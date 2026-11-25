// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The migration paths between role layouts (`.kiro/specs/kinesis-
// independent-layers/` task 14; Requirements 11.1, 11.6, 11.7, 13.1-13.3,
// 15.4 and 15.7). Each path runs in both directions while a producer
// writes and two consumers read without pause: one polling GetRecords with
// iterators it carries across every step, one holding SubscribeToShard
// (EFO) streams and subscribing again when one ends. After every path:
//
// - every acknowledged record was read exactly once by both consumers, in
//   each shard's order, and nothing was read that was not written;
// - each shard's sequence numbers only ever rose;
// - iterators issued before a step (TRIM_HORIZON and LATEST) still work
//   after it, on the next layout's front end, and LATEST never shows a
//   record acknowledged before it was issued;
// - every KCL lease taken at one step is still held, and still cannot be
//   taken by anyone else, at every later step.
//
// The paths: the gateway role split off and folded back (with a drain and
// a front-end restart along the way); the front-end role likewise; the
// data role evacuated to data-only nodes and back; segments moved from
// local stores to segment-node volumes and back by replica replacement;
// and the whole way from co-located to the four-way split and back,
// stopping and reversing in the middle. The in-place store move path
// waits for task 13's store move.
//
// The data layer is one Raft group played by hand, as the stream state
// machine's segment_layer suite plays it: an entry is acknowledged once a
// majority of replicas has applied it and passed its barrier. A replica
// moves the way the placement operators move one: a learner on the new
// node copies the sealed segments while writes go on, then, behind a short
// fence, restores the leader's snapshot (fetching the active segment's
// prefix from its peers), picks up what sealed meanwhile, joins as a voter
// and the old replica leaves. Moving the leader's replica hands leadership
// on. Front ends and gateways are the real ones over the real internal
// transport (kinesis_layouts.hpp, kinesis_gateway_layouts.hpp).

#define BOOST_TEST_MODULE kinesis_migration_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_lease_api.hpp>
#include <kythira/kinesis/kinesis_service.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>

#include "kinesis_cluster_handle.hpp"
#include "kinesis_gateway_layouts.hpp"

#include <raft/aws_eventstream.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/remote_segment_store.hpp>
#include <raft/segment_volume_service.hpp>

#include <boost/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kin = kythira::kinesis;
namespace kt = kythira::kinesis::test;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace es = kythira::aws_eventstream;
namespace https = kythira::https;
namespace json = boost::json;

using namespace std::chrono_literals;

namespace {

constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_stream = "orders";
constexpr int k_shards = 3;

struct temp_dir {
    std::filesystem::path _path;
    temp_dir() {
        static std::atomic<int> counter{0};
        _path = std::filesystem::temp_directory_path() /
                ("kinesis_migration_test." + std::to_string(::getpid()) + "." +
                 std::to_string(++counter));
        std::filesystem::remove_all(_path);
        std::filesystem::create_directories(_path);
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

// Small segments, so records roll many of them and every move has sealed
// segments to copy and an active one to fence. Every replica, local or on
// a volume, must use the same bounds or their files stop matching.
auto store_options() -> kythira::record_segment_store_options {
    return {
        ._data_dir = {},
        ._max_segment_bytes = 400,
        ._max_segment_age_ms = 0,
        ._max_record_bytes = 4096,
        ._index_interval_bytes = 64,
        ._barriers_enabled = false,
    };
}

struct allow_all {
    auto authenticate(const sv4::request&, const sv4::service_rules&) -> az::authn_result {
        az::principal_context p;
        p.account = std::string(k_account);
        p.arn = "arn:aws:iam::" + std::string(k_account) + ":user/alice";
        return p;
    }
    auto authorize(const az::principal_context&, const az::authz_request&) -> az::authz_decision {
        az::authz_decision d;
        d.allowed = true;
        return d;
    }
};

/// What every front end of the cluster shares: the iterator key and
/// limits high enough that the test's own pace is the only one.
auto service_config() -> kin::kinesis_service_config {
    kin::kinesis_service_config c;
    c._iterator_keys._keys.push_back({._id = 3, ._secret = "the cluster's iterator key, shared"});
    c._throughput._read_calls_per_s = 1e9;
    c._throughput._iterator_calls_per_s = 1e9;
    c._throughput._read_bytes_per_s = 1e12;
    c._control_plane._rates.clear();
    c._subscription_heartbeat = 200ms;
    c._subscription_poll = 5ms;
    c._subscription_recheck = 50ms;
    return c;
}

// ---- the data layer ---------------------------------------------------------

enum class store_kind : std::uint8_t {
    local,
    volume
};

/// Where one replica lives: its node, and whether its segments are on the
/// node's disk or in a volume on a segment node.
struct placement {
    std::string _node;
    store_kind _store = store_kind::local;
};

/// One segment node: volumes behind the volume API, reached in process.
struct segment_node {
    temp_dir _dir;
    kythira::segment_volume_service _service{
        kythira::segment_volume_service_options{.data_dir = _dir._path, .store = store_options()}};

    auto transport() -> kythira::segment_volume_transport {
        return [this](std::vector<std::byte> req) -> std::optional<std::vector<std::byte>> {
            return _service.handle(req);
        };
    }
};

/// One Raft group's replicas, moved between nodes while it serves.
/// Thread-safe: every proposal, read and membership step runs under one
/// lock, as entries apply in log order on every replica.
class replicated_data_layer {
public:
    using sm_type = kin::stream_state_machine<std::uint64_t>;

    explicit replicated_data_layer(const std::vector<placement>& initial) {
        for (const auto& p : initial) {
            _voters.push_back(make_replica(p));
        }
    }

    auto propose(const std::string& /*key*/, std::vector<std::byte> command,
                 kin::admission /*mode*/ = kin::admission::none)
        -> std::optional<kin::apply_result> {
        const std::scoped_lock lock(_mutex);
        return commit_locked(std::move(command));
    }

    auto read(const std::string& /*key*/, const kin::stream_reader& f) -> bool {
        const std::scoped_lock lock(_mutex);
        f(*_voters.front()->_sm);
        return true;
    }

    [[nodiscard]] auto now_ms() const -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    auto transact(std::vector<kin::txn_write> writes) -> kin::transact_outcome {
        const std::scoped_lock lock(_mutex);
        for (auto& w : writes) {
            if (!commit_locked(std::move(w._command))) {
                return kin::transact_outcome::unknown;
            }
        }
        return kin::transact_outcome::committed;
    }

    [[nodiscard]] auto group_of(const std::string& /*key*/) const -> std::optional<std::uint64_t> {
        return 0;
    }
    [[nodiscard]] auto leads(const std::string& /*key*/) const -> bool { return true; }

    /// Moves the replica on `from` to `to` while proposals and reads go on.
    void move(const std::string& from, const placement& to) {
        auto learner = make_replica(to);
        // The sealed segments, copied with writes going on: they never
        // change once sealed.
        std::vector<kythira::segment_store*> peers;
        {
            const std::scoped_lock lock(_mutex);
            for (const auto& v : _voters) {
                peers.push_back(v->_store.get());
            }
        }
        copy_sealed(*learner, peers);

        // The fence: the leader's snapshot (the active segment's prefix is
        // fetched from the peers), the segments sealed since, then the
        // learner joins and the old replica leaves.
        const auto fenced = std::chrono::steady_clock::now();
        const std::scoped_lock lock(_mutex);
        const auto it =
            std::ranges::find_if(_voters, [&](const auto& v) { return v->_node == from; });
        if (it == _voters.end()) {
            throw std::invalid_argument("no replica on " + from);
        }
        learner->_sm->restore_from_snapshot(_voters.front()->_sm->get_state(), _log.size());
        copy_sealed(*learner, peers);
        _retired.push_back(std::move(*it));
        _voters.erase(it);
        _voters.push_back(std::move(learner));
        _longest_fence = std::max(_longest_fence, std::chrono::steady_clock::now() - fenced);
        ++_moves;
    }

    /// Where the replicas are now, leader first.
    [[nodiscard]] auto placements() const -> std::vector<placement> {
        const std::scoped_lock lock(_mutex);
        std::vector<placement> out;
        for (const auto& v : _voters) {
            out.push_back({v->_node, v->_kind});
        }
        return out;
    }

    /// Every replica holds the same state and the same files.
    [[nodiscard]] auto replicas_agree() const -> std::optional<std::string> {
        const std::scoped_lock lock(_mutex);
        const auto& leader = *_voters.front();
        const auto state = leader._sm->get_state();
        for (const auto& v : _voters) {
            if (v->_sm->get_state() != state) {
                return v->_node + "'s state differs from " + leader._node + "'s";
            }
            for (const auto& stream : leader._store->streams()) {
                if (v->_store->local_segments(stream).back() !=
                    leader._store->local_segments(stream).back()) {
                    return v->_node + "'s active segment of " + stream + " differs";
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto moves() const -> int {
        const std::scoped_lock lock(_mutex);
        return _moves;
    }

    [[nodiscard]] auto longest_fence() const -> std::chrono::steady_clock::duration {
        const std::scoped_lock lock(_mutex);
        return _longest_fence;
    }

    [[nodiscard]] auto volumes() const -> std::size_t {
        std::size_t n = 0;
        for (const auto& [name, node] : _segment_nodes) {
            n += node->_service.volumes().size();
        }
        return n;
    }

private:
    struct replica {
        std::string _node;
        store_kind _kind = store_kind::local;
        std::unique_ptr<temp_dir> _dir;
        std::unique_ptr<kythira::segment_store> _store;
        std::unique_ptr<sm_type> _sm;
    };

    // An entry is acknowledged once a majority applied it and passed the
    // barrier; the answer is the leader's.
    auto commit_locked(std::vector<std::byte> command) -> std::optional<kin::apply_result> {
        _log.push_back(std::move(command));
        std::optional<kin::apply_result> answer;
        std::size_t durable = 0;
        for (const auto& v : _voters) {
            auto out = v->_sm->apply(_log.back(), _log.size());
            v->_store->barrier();
            ++durable;
            if (!answer) {
                answer = kin::decode_result(out);
            }
        }
        if (durable * 2 <= _voters.size()) {
            return std::nullopt;
        }
        return answer;
    }

    // `peers` stay alive: replicas that left are kept in `_retired`.
    static void copy_sealed(replica& r, const std::vector<kythira::segment_store*>& peers) {
        std::vector<std::string> names;
        for (std::size_t i = 0; i < peers.size(); ++i) {
            names.push_back(std::to_string(i));
        }
        const auto transport = [&peers](const std::string& peer, const std::string& stream,
                                        std::uint64_t first, std::uint64_t length) {
            return peers.at(std::stoul(peer))->read_segment_bytes(stream, first, length);
        };
        for (const auto& stream : peers.front()->streams()) {
            for (const auto& d : peers.front()->local_segments(stream)) {
                if (d._sealed && !r._store->has_segment(d) &&
                    !r._store->fetch_segment(d, names, transport)) {
                    throw kythira::record_segment_error("no peer had " + d._stream);
                }
            }
        }
    }

    auto make_replica(const placement& p) -> std::unique_ptr<replica> {
        auto r = std::make_unique<replica>();
        r->_node = p._node;
        r->_kind = p._store;
        if (p._store == store_kind::local) {
            r->_dir = std::make_unique<temp_dir>();
            auto o = store_options();
            o._data_dir = r->_dir->_path;
            r->_store = std::make_unique<kythira::record_segment_store>(o);
        } else {
            // A volume on the node's own segment node, at the first epoch:
            // a replacement replica is a new volume, never a reused one.
            auto& seg = _segment_nodes["s-" + p._node];
            if (!seg) {
                seg = std::make_unique<segment_node>();
            }
            const auto volume = "kinesis-" + p._node + "-" + std::to_string(++_volume_ids);
            seg->_service.assign(volume, 1);
            r->_store =
                std::make_unique<kythira::remote_segment_store>(seg->transport(), volume, 1);
        }
        // Sealed segments are fetched on read when missing; called with the
        // lock held (reads and the fence), so the voters are stable.
        auto* self = r.get();
        r->_sm = std::make_unique<sm_type>(
            r->_store.get(), [this, self](const kythira::record_segment_descriptor& d) {
                std::vector<kythira::segment_store*> peers;
                for (const auto& v : _voters) {
                    if (v.get() != self) {
                        peers.push_back(v->_store.get());
                    }
                }
                std::vector<std::string> names;
                for (std::size_t i = 0; i < peers.size(); ++i) {
                    names.push_back(std::to_string(i));
                }
                if (!self->_store->fetch_segment(
                        d, names,
                        [&peers](const std::string& peer, const std::string& stream,
                                 std::uint64_t first, std::uint64_t length) {
                            return peers.at(std::stoul(peer))
                                ->read_segment_bytes(stream, first, length);
                        })) {
                    throw kythira::record_segment_error("fetch failed for " + d._stream);
                }
            });
        return r;
    }

    mutable std::mutex _mutex;
    std::vector<std::vector<std::byte>> _log;
    std::map<std::string, std::unique_ptr<segment_node>> _segment_nodes;
    std::vector<std::unique_ptr<replica>> _voters;
    std::vector<std::unique_ptr<replica>> _retired;
    std::chrono::steady_clock::duration _longest_fence{};
    int _moves = 0;
    int _volume_ids = 0;
};

static_assert(kin::stream_cluster<replicated_data_layer>);

// ---- front ends and gateways ------------------------------------------------

auto request(std::string_view op, const json::value& body) -> kin::front_end_request {
    kin::front_end_request r;
    r._method = "POST";
    r._path = "/";
    r._body = json::serialize(body);
    r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                  {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}};
    return r;
}

/// One event of a SubscribeToShard stream.
struct pulled_event {
    std::string _message_type;  // "event" or "exception"
    std::string _type;
    json::object _payload;
};

auto parse_event(const std::string& bytes) -> pulled_event {
    const auto m = es::decode({reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()});
    pulled_event e;
    e._message_type = std::string(m.string_header(":message-type").value_or(""));
    e._type = std::string(
        m.string_header(e._message_type == "exception" ? ":exception-type" : ":event-type")
            .value_or(""));
    if (!m.payload.empty()) {
        const std::string body(reinterpret_cast<const char*>(m.payload.data()), m.payload.size());
        if (auto v = json::parse(body); v.is_object()) {
            e._payload = std::move(v.as_object());
        }
    }
    return e;
}

/// An open SubscribeToShard stream, from a front end or through a gateway.
struct subscription {
    subscription() = default;
    subscription(const subscription&) = delete;
    auto operator=(const subscription&) -> subscription& = delete;
    subscription(subscription&&) = delete;
    auto operator=(subscription&&) -> subscription& = delete;
    virtual ~subscription() = default;

    /// The next event within about `wait`: nullopt with `ended` false when
    /// none came, nullopt with `ended` true once the stream is over.
    virtual auto next(std::chrono::milliseconds wait, bool& ended)
        -> std::optional<pulled_event> = 0;
    virtual void cancel() = 0;
};

struct front_end_subscription final : subscription {
    std::shared_ptr<kin::event_source> _events;
    explicit front_end_subscription(std::shared_ptr<kin::event_source> e) : _events(std::move(e)) {}
    ~front_end_subscription() override { cancel(); }
    auto next(std::chrono::milliseconds wait, bool& ended) -> std::optional<pulled_event> override {
        auto p = _events->next(wait);
        if (!p._message.empty()) {
            return parse_event(p._message);
        }
        ended = p._done;
        return std::nullopt;
    }
    void cancel() override { _events->cancel(); }
};

struct gateway_subscription final : subscription {
    https::streaming_response _stream;
    bool _open = true;
    explicit gateway_subscription(https::streaming_response s) : _stream(std::move(s)) {}
    ~gateway_subscription() override { cancel(); }
    auto next(std::chrono::milliseconds wait, bool& ended) -> std::optional<pulled_event> override {
        const auto until = std::chrono::steady_clock::now() + wait;
        while (_open && std::chrono::steady_clock::now() < until) {
            std::string chunk;
            _open = _stream.next(chunk);
            if (!chunk.empty()) {
                return parse_event(chunk);
            }
        }
        ended = !_open;
        return std::nullopt;
    }
    void cancel() override { _stream.cancel(); }
};

/// Where clients send their calls: a front end's own listener, or a
/// gateway in front of one.
struct endpoint {
    endpoint() = default;
    endpoint(const endpoint&) = delete;
    auto operator=(const endpoint&) -> endpoint& = delete;
    endpoint(endpoint&&) = delete;
    auto operator=(endpoint&&) -> endpoint& = delete;
    virtual ~endpoint() = default;

    virtual auto handle(const kin::front_end_request& r) -> aj::http_response = 0;
    virtual auto lease_handle(const kin::front_end_request& r) -> aj::http_response = 0;
    /// The SubscribeToShard call; a refusal or failure as nullptr.
    virtual auto subscribe(const kin::front_end_request& r) -> std::unique_ptr<subscription> = 0;
    [[nodiscard]] virtual auto name() const -> std::string = 0;

    auto call(std::string_view op, const json::value& body) -> aj::http_response {
        return handle(request(op, body));
    }

    auto ok(std::string_view op, const json::value& body) -> json::object {
        const auto r = call(op, body);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, name() + " " + std::string(op) + ": " + r.body);
        return json::parse(r.body).as_object();
    }

    auto lease(std::string method, std::string path, std::string body = {},
               std::vector<std::pair<std::string, std::string>> headers = {}) -> aj::http_response {
        kin::front_end_request r;
        r._method = std::move(method);
        r._path = std::move(path);
        r._body = std::move(body);
        r._headers = std::move(headers);
        return lease_handle(r);
    }
};

/// One front end in `kind`'s layout over the data layer: its own service,
/// Lease API and front end.
struct front_end_node final : endpoint {
    kt::layered_access layer;
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    kin::kinesis_service<kin::data_access> service;
    kin::lease_api<kin::data_access, allow_all> leases;

    front_end_node(const kt::cluster_handle& data, kt::layout_kind kind)
        : layer(data, kind),
          service(layer.get(), service_config()),
          leases(layer.get(), auth, kin::front_end_config{}) {
        service.register_with(fe);
    }

    auto handle(const kin::front_end_request& r) -> aj::http_response override {
        return fe.handle(r);
    }
    auto lease_handle(const kin::front_end_request& r) -> aj::http_response override {
        return leases.handle(r);
    }
    auto subscribe(const kin::front_end_request& r) -> std::unique_ptr<subscription> override {
        auto reply = fe.handle_streaming(r);
        if (reply._response.status != 200U || !reply._events) {
            return nullptr;
        }
        return std::make_unique<front_end_subscription>(std::move(reply._events));
    }
    [[nodiscard]] auto name() const -> std::string override {
        return std::string(kt::layout_name(layer.kind()));
    }
};

/// A gateway without a front end before `target`'s front end, which serves
/// it over the front-end API as a node with the `front_end` role does.
struct gateway_node final : endpoint {
    front_end_node& target;
    kt::loopback_front_end<kin::front_end<allow_all>> served;
    allow_all auth;
    kt::gateway_apart<allow_all> gateway;

    explicit gateway_node(front_end_node& f)
        : target(f),
          served(f.fe, [&f](const kin::authenticated_call& c) { return f.leases.execute(c); }),
          gateway(auth, {served.address()}) {}

    auto handle(const kin::front_end_request& r) -> aj::http_response override {
        return gateway.handle(r);
    }
    auto lease_handle(const kin::front_end_request& r) -> aj::http_response override {
        return gateway.handle(r);
    }
    auto subscribe(const kin::front_end_request& r) -> std::unique_ptr<subscription> override {
        auto s = gateway.node().stream(kt::to_https(r), {});
        if (!s || s->head.result_int() != 200U) {
            return nullptr;
        }
        return std::make_unique<gateway_subscription>(std::move(*s));
    }
    [[nodiscard]] auto name() const -> std::string override {
        return "gateway -> " + target.name();
    }
};

auto str(const json::value& v) -> std::string {
    return std::string(v.as_string());
}

/// Kinesis sequence numbers are decimal strings of growing length.
auto seq_less(const std::string& a, const std::string& b) -> bool {
    return a.size() != b.size() ? a.size() < b.size() : a < b;
}

auto decode_data(const json::value& d) -> std::string {
    return kin::service_detail::base64_decode(d.as_string()).value_or("<undecodable>");
}

// ---- traffic ----------------------------------------------------------------

struct read_record {
    std::string _seq;
    std::string _data;
};

/// The sequence numbers one consumer read from `shard`, in order.
auto sequences_of(const std::map<std::string, std::vector<read_record>>& got,
                  const std::string& shard) -> std::vector<std::string> {
    std::vector<std::string> out;
    if (const auto it = got.find(shard); it != got.end()) {
        for (const auto& r : it->second) {
            out.push_back(r._seq);
        }
    }
    return out;
}

/// A producer and two consumers that never stop for a step: each call goes
/// to wherever the client is pointed now, as a load balancer's target set
/// changes under real clients.
class traffic {
public:
    traffic(endpoint& first, std::vector<std::string> shards, std::string consumer_arn)
        : _at(&first), _shards(std::move(shards)), _consumer(std::move(consumer_arn)) {
        for (const auto& s : _shards) {
            _iterators[s] = str(first
                                    .ok("GetShardIterator", {{"StreamName", k_stream},
                                                             {"ShardId", s},
                                                             {"ShardIteratorType", "TRIM_HORIZON"}})
                                    .at("ShardIterator"));
        }
        _threads.emplace_back([this] { produce(); });
        _threads.emplace_back([this] { poll(); });
        _threads.emplace_back([this] { push(); });
    }

    traffic(const traffic&) = delete;
    auto operator=(const traffic&) -> traffic& = delete;
    traffic(traffic&&) = delete;
    auto operator=(traffic&&) -> traffic& = delete;
    ~traffic() { stop(); }

    void point_at(endpoint& e) { _at.store(&e); }
    [[nodiscard]] auto at() const -> endpoint& { return *_at.load(); }

    /// Waits until `records` more have been acknowledged and both consumers
    /// have read at least that far behind, so each step happens with
    /// records in flight both ways.
    void advance(std::size_t records = 24) {
        const auto target = acked_count() + records;
        const auto until = std::chrono::steady_clock::now() + 30s;
        while (std::chrono::steady_clock::now() < until) {
            if (acked_count() >= target && polled_count() + records >= target &&
                pushed_count() + records >= target) {
                return;
            }
            std::this_thread::sleep_for(5ms);
        }
        note("traffic stalled at " + std::to_string(acked_count()) + " acknowledged, " +
             std::to_string(polled_count()) + " polled, " + std::to_string(pushed_count()) +
             " pushed");
    }

    /// Stops the producer, waits for both consumers to read everything it
    /// was acknowledged, then stops them.
    void drain() {
        _producing.store(false);
        // The call in flight finishes first, or its records would be
        // acknowledged after the count the consumers are held to.
        while (!_produced.load()) {
            std::this_thread::sleep_for(1ms);
        }
        const auto target = acked_count();
        const auto until = std::chrono::steady_clock::now() + 30s;
        while (std::chrono::steady_clock::now() < until &&
               (polled_count() < target || pushed_count() < target)) {
            std::this_thread::sleep_for(5ms);
        }
        if (polled_count() < target || pushed_count() < target) {
            note("consumers stalled: " + std::to_string(target) + " acknowledged, " +
                 std::to_string(polled_count()) + " polled, " + std::to_string(pushed_count()) +
                 " pushed");
        }
        // Give a late duplicate the time to show itself.
        std::this_thread::sleep_for(100ms);
        stop();
    }

    void stop() {
        _producing.store(false);
        _running.store(false);
        for (auto& t : _threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        _threads.clear();
    }

    /// The highest acknowledged sequence number of each shard so far.
    [[nodiscard]] auto acked_tips() const -> std::map<std::string, std::string> {
        const std::scoped_lock lock(_mutex);
        std::map<std::string, std::string> out;
        for (const auto& [shard, seqs] : _acked) {
            if (!seqs.empty()) {
                out[shard] = seqs.back();
            }
        }
        return out;
    }

    // After `stop`: what happened.
    [[nodiscard]] auto acked() const -> const std::map<std::string, std::vector<std::string>>& {
        return _acked;
    }
    [[nodiscard]] auto acked_data() const -> const std::set<std::string>& { return _acked_data; }
    [[nodiscard]] auto maybe_data() const -> const std::set<std::string>& { return _maybe_data; }
    [[nodiscard]] auto polled() const -> const std::map<std::string, std::vector<read_record>>& {
        return _polled;
    }
    [[nodiscard]] auto pushed() const -> const std::map<std::string, std::vector<read_record>>& {
        return _pushed;
    }
    [[nodiscard]] auto problems() const -> const std::vector<std::string>& { return _problems; }
    [[nodiscard]] auto failed_puts() const -> int { return _failed_puts.load(); }
    [[nodiscard]] auto failed_reads() const -> int { return _failed_reads.load(); }
    [[nodiscard]] auto subscriptions() const -> int { return _subscriptions.load(); }

private:
    void note(std::string problem) {
        const std::scoped_lock lock(_mutex);
        _problems.push_back(std::move(problem));
    }

    [[nodiscard]] auto acked_count() const -> std::size_t {
        const std::scoped_lock lock(_mutex);
        return _acked_data.size();
    }
    [[nodiscard]] auto polled_count() const -> std::size_t {
        const std::scoped_lock lock(_mutex);
        std::size_t n = 0;
        for (const auto& [s, r] : _polled) {
            n += r.size();
        }
        return n;
    }
    [[nodiscard]] auto pushed_count() const -> std::size_t {
        const std::scoped_lock lock(_mutex);
        std::size_t n = 0;
        for (const auto& [s, r] : _pushed) {
            n += r.size();
        }
        return n;
    }

    // PutRecords of four records at a time. A call that failed, or a record
    // it reports failed, may or may not have been written: it is never sent
    // again, so it may show up at most once.
    void produce() {
        int next = 0;
        while (_producing.load()) {
            try {
                produce_one(next);
            } catch (const std::exception& e) {
                note(std::string("producer: ") + e.what());
            }
            std::this_thread::sleep_for(2ms);
        }
        _produced.store(true);
    }

    void produce_one(int& next) {
        json::array recs;
        std::vector<std::string> data;
        for (int i = 0; i < 4; ++i) {
            data.push_back("record-" + std::to_string(next++));
            recs.push_back({{"PartitionKey", "pk-" + std::to_string(next)},
                            {"Data", kin::service_detail::base64_encode(data.back())}});
        }
        auto& e = at();
        const auto r = e.call("PutRecords", {{"StreamName", k_stream}, {"Records", recs}});
        const std::scoped_lock lock(_mutex);
        if (r.status != 200U) {
            ++_failed_puts;
            _maybe_data.insert(data.begin(), data.end());
        } else {
            const auto put = json::parse(r.body).as_object();
            const auto& results = put.at("Records").as_array();
            for (std::size_t i = 0; i < results.size(); ++i) {
                const auto& rec = results[i].as_object();
                if (rec.contains("ErrorCode")) {
                    _maybe_data.insert(data[i]);
                    continue;
                }
                auto& seqs = _acked[str(rec.at("ShardId"))];
                const auto seq = str(rec.at("SequenceNumber"));
                if (!seqs.empty() && !seq_less(seqs.back(), seq)) {
                    _problems.push_back("acknowledged " + seq + " after " + seqs.back() + " via " +
                                        e.name());
                }
                seqs.push_back(seq);
                _acked_data.insert(data[i]);
            }
        }
    }

    // GetRecords on every shard with the iterators it carries from layout
    // to layout; a failed call is retried with the same iterator.
    void poll() {
        while (_running.load()) {
            try {
                if (!poll_once()) {
                    std::this_thread::sleep_for(5ms);
                }
            } catch (const std::exception& e) {
                note(std::string("GetRecords consumer: ") + e.what());
            }
        }
    }

    auto poll_once() -> bool {
        bool any = false;
        for (const auto& shard : _shards) {
            auto& e = at();
            const auto r =
                e.call("GetRecords", {{"ShardIterator", _iterators[shard]}, {"Limit", 25}});
            if (r.status != 200U) {
                ++_failed_reads;
                continue;
            }
            const auto got = json::parse(r.body).as_object();
            const std::scoped_lock lock(_mutex);
            for (const auto& rec : got.at("Records").as_array()) {
                _polled[shard].push_back(
                    {str(rec.at("SequenceNumber")), decode_data(rec.at("Data"))});
                any = true;
            }
            _iterators[shard] = str(got.at("NextShardIterator"));
        }
        return any;
    }

    // One SubscribeToShard stream per shard. When a stream ends (its front
    // end restarted, its gateway drained) or the client is pointed
    // elsewhere, it subscribes again after the last record it was given,
    // as the KCL does.
    void push() {
        std::map<std::string, open_stream> streams;
        while (_running.load()) {
            try {
                push_once(streams);
            } catch (const std::exception& e) {
                note(std::string("SubscribeToShard consumer: ") + e.what());
            }
        }
    }

    struct open_stream {
        endpoint* _via = nullptr;
        std::unique_ptr<subscription> _sub;
        std::optional<std::string> _after;
    };

    void push_once(std::map<std::string, open_stream>& streams) {
        for (const auto& shard : _shards) {
            auto& s = streams[shard];
            auto* e = &at();
            if (s._sub && s._via != e) {
                s._sub->cancel();
                s._sub.reset();
            }
            if (!s._sub) {
                json::object position{{"Type", "TRIM_HORIZON"}};
                if (s._after) {
                    position = {{"Type", "AFTER_SEQUENCE_NUMBER"}, {"SequenceNumber", *s._after}};
                }
                s._sub =
                    e->subscribe(request("SubscribeToShard", {{"ConsumerARN", _consumer},
                                                              {"ShardId", shard},
                                                              {"StartingPosition", position}}));
                s._via = e;
                ++_subscriptions;
                if (!s._sub) {
                    std::this_thread::sleep_for(10ms);
                    continue;
                }
            }
            bool ended = false;
            auto ev = s._sub->next(10ms, ended);
            if (ended) {
                s._sub.reset();
                continue;
            }
            if (!ev || ev->_message_type != "event" || ev->_type != "SubscribeToShardEvent") {
                continue;
            }
            const std::scoped_lock lock(_mutex);
            for (const auto& rec : ev->_payload.at("Records").as_array()) {
                const auto& o = rec.as_object();
                _pushed[shard].push_back({str(o.at("SequenceNumber")), decode_data(o.at("Data"))});
                s._after = str(o.at("SequenceNumber"));
            }
        }
    }

    std::atomic<endpoint*> _at;
    std::vector<std::string> _shards;
    std::string _consumer;
    std::map<std::string, std::string> _iterators;  // the polling thread's

    mutable std::mutex _mutex;
    std::map<std::string, std::vector<std::string>> _acked;
    std::set<std::string> _acked_data;
    std::set<std::string> _maybe_data;
    std::map<std::string, std::vector<read_record>> _polled;
    std::map<std::string, std::vector<read_record>> _pushed;
    std::vector<std::string> _problems;

    std::atomic<bool> _producing{true};
    std::atomic<bool> _produced{false};
    std::atomic<bool> _running{true};
    std::atomic<int> _failed_puts{0};
    std::atomic<int> _failed_reads{0};
    std::atomic<int> _subscriptions{0};
    std::vector<std::thread> _threads;
};

// ---- the rig ----------------------------------------------------------------

/// Where the client stands: a front end's layout, reached directly or
/// through a gateway apart from it.
struct stop {
    kt::layout_kind _kind = kt::layout_kind::co_located;
    bool _via_gateway = false;
};

auto describe(const stop& s) -> std::string {
    return (s._via_gateway ? std::string("gateway -> ") : std::string()) +
           std::string(kt::layout_name(s._kind));
}

const std::vector<std::pair<std::string, std::string>> k_create{{"if-none-match", "*"}};

/// A data layer, the front ends and gateways clients are moved between, and
/// the traffic that never stops while they move.
class rig {
public:
    rig(const std::vector<placement>& replicas, const stop& first)
        : _data(replicas), _handle(kt::cluster_handle::of(_data)) {
        auto& e = open(first);
        e.ok("CreateStream", {{"StreamName", k_stream}, {"ShardCount", k_shards}});
        const auto listed = e.ok("ListShards", {{"StreamName", k_stream}});
        for (const auto& s : listed.at("Shards").as_array()) {
            _shards.push_back(str(s.at("ShardId")));
        }
        const auto arn = str(e.ok("DescribeStreamSummary", {{"StreamName", k_stream}})
                                 .at("StreamDescriptionSummary")
                                 .at("StreamARN"));
        const auto consumer =
            str(e.ok("RegisterStreamConsumer", {{"StreamARN", arn}, {"ConsumerName", "kcl-app"}})
                    .at("Consumer")
                    .at("ConsumerARN"));
        _now = &e;
        take_lease();
        _traffic = std::make_unique<traffic>(e, _shards, consumer);
        _traffic->advance();
    }

    rig(const rig&) = delete;
    auto operator=(const rig&) -> rig& = delete;
    rig(rig&&) = delete;
    auto operator=(rig&&) -> rig& = delete;
    ~rig() {
        if (_traffic) {
            _traffic->stop();
        }
    }

    [[nodiscard]] auto data() -> replicated_data_layer& { return _data; }

    /// Moves the clients to `next`, checking iterators issued on the old
    /// endpoint work on the new one and every lease still holds. The old
    /// endpoint goes as its role would: a gateway drains (ending its event
    /// streams retryably), a front end stops being sent calls.
    void move_clients(const stop& next) {
        BOOST_TEST_CONTEXT("to " << describe(next)) {
            auto& old_at = *_now;
            const auto before = issue_iterators(old_at);
            auto& e = open(next);
            _traffic->point_at(e);
            _now = &e;
            if (auto* g = dynamic_cast<gateway_node*>(&old_at); g != nullptr) {
                g->gateway.node().begin_drain();
            }
            check_iterators(before);
            take_lease();
            _traffic->advance();
        }
    }

    /// Moves the replica on `from` to `to` with the clients where they are.
    void move_replica(const std::string& from, const placement& to) {
        BOOST_TEST_CONTEXT("replica " << from << " to " << to._node) {
            const auto before = issue_iterators(*_now);
            _data.move(from, to);
            check_iterators(before);
            _traffic->advance();
        }
    }

    /// Moves every replica, one at a time, to `to` in order.
    void move_replicas(const std::vector<placement>& to) {
        const auto from = _data.placements();
        BOOST_REQUIRE_EQUAL(from.size(), to.size());
        for (std::size_t i = 0; i < to.size(); ++i) {
            move_replica(from[i]._node, to[i]);
        }
        take_lease();
    }

    /// The front end behind the clients' gateway restarts on its port, as a
    /// rolling restart does: in-flight calls fail, event streams end.
    void restart_front_end() {
        auto* g = dynamic_cast<gateway_node*>(_now);
        BOOST_REQUIRE_MESSAGE(g != nullptr, "the clients are not behind a gateway");
        g->served.restart();
        _traffic->advance();
    }

    /// Stops the traffic and checks everything the header promises.
    void finish() {
        _traffic->drain();
        const auto& t = *_traffic;
        for (const auto& p : t.problems()) {
            BOOST_ERROR(p);
        }
        // What the stream holds now, read back whole from a fresh iterator.
        std::map<std::string, std::vector<read_record>> stored;
        for (const auto& shard : _shards) {
            auto it = str(_now->ok("GetShardIterator", {{"StreamName", k_stream},
                                                        {"ShardId", shard},
                                                        {"ShardIteratorType", "TRIM_HORIZON"}})
                              .at("ShardIterator"));
            for (int page = 0; page < 10'000; ++page) {
                const auto r = _now->ok("GetRecords", {{"ShardIterator", it}, {"Limit", 1000}});
                for (const auto& rec : r.at("Records").as_array()) {
                    stored[shard].push_back(
                        {str(rec.at("SequenceNumber")), decode_data(rec.at("Data"))});
                }
                it = str(r.at("NextShardIterator"));
                if (r.at("Records").as_array().empty()) {
                    break;
                }
            }
        }
        std::size_t total = 0;
        std::set<std::string> seen;
        for (const auto& [shard, recs] : stored) {
            BOOST_TEST_CONTEXT(shard) {
                for (std::size_t i = 0; i < recs.size(); ++i) {
                    if (i > 0) {
                        BOOST_TEST(seq_less(recs[i - 1]._seq, recs[i]._seq),
                                   recs[i - 1]._seq << " then " << recs[i]._seq);
                    }
                    BOOST_TEST(seen.insert(recs[i]._data).second, recs[i]._data << " twice");
                    BOOST_TEST((t.acked_data().contains(recs[i]._data) ||
                                t.maybe_data().contains(recs[i]._data)),
                               recs[i]._data << " was never written");
                }
                // Every acknowledged record, in the order acknowledged.
                std::vector<std::string> seqs;
                for (const auto& r : recs) {
                    seqs.push_back(r._seq);
                }
                std::vector<std::string> acked;
                if (const auto a = t.acked().find(shard); a != t.acked().end()) {
                    acked = a->second;
                }
                BOOST_TEST(std::ranges::includes(seqs, acked, seq_less),
                           "acknowledged records lost");
                // Both consumers read exactly what is stored, once, in order.
                const auto polled = sequences_of(t.polled(), shard);
                BOOST_TEST(polled == seqs,
                           "GetRecords read " << polled.size() << " of " << seqs.size());
                const auto pushed = sequences_of(t.pushed(), shard);
                BOOST_TEST(pushed == seqs,
                           "SubscribeToShard read " << pushed.size() << " of " << seqs.size());
                total += recs.size();
            }
        }
        for (const auto& d : t.acked_data()) {
            BOOST_TEST(seen.contains(d), d << " acknowledged but not stored");
        }
        BOOST_TEST(total >= t.acked_data().size());
        // Every lease still held, by its owner, and refused to anyone else.
        check_leases();
        const auto disagree = _data.replicas_agree();
        BOOST_TEST(!disagree.has_value(), disagree.value_or(""));
        BOOST_TEST_MESSAGE(
            "acknowledged "
            << t.acked_data().size() << ", ambiguous " << t.maybe_data().size() << " ("
            << t.failed_puts() << " failed calls), " << t.failed_reads() << " failed reads, "
            << t.subscriptions() << " subscriptions, " << _data.moves()
            << " replica moves, longest fence "
            << std::chrono::duration_cast<std::chrono::microseconds>(_data.longest_fence()).count()
            << " us");
    }

private:
    struct issued {
        std::map<std::string, std::string> _trim_horizon;
        std::map<std::string, std::string> _latest;
        std::map<std::string, std::string> _tips;  // acknowledged before LATEST
    };

    auto open(const stop& s) -> endpoint& {
        _front_ends.push_back(std::make_unique<front_end_node>(_handle, s._kind));
        if (!s._via_gateway) {
            return *_front_ends.back();
        }
        _gateways.push_back(std::make_unique<gateway_node>(*_front_ends.back()));
        return *_gateways.back();
    }

    auto issue_iterators(endpoint& e) -> issued {
        issued out;
        out._tips = _traffic->acked_tips();
        for (const auto& shard : _shards) {
            for (const auto* type : {"TRIM_HORIZON", "LATEST"}) {
                const auto r = e.call(
                    "GetShardIterator",
                    {{"StreamName", k_stream}, {"ShardId", shard}, {"ShardIteratorType", type}});
                BOOST_REQUIRE_MESSAGE(r.status == 200U, e.name() + " GetShardIterator: " + r.body);
                const auto it = str(json::parse(r.body).at("ShardIterator"));
                (std::string_view(type) == "LATEST" ? out._latest : out._trim_horizon)[shard] = it;
            }
        }
        return out;
    }

    // Each iterator issued before the step answers on the endpoint after
    // it: TRIM_HORIZON from the first record, LATEST with nothing that was
    // acknowledged before it was issued.
    void check_iterators(const issued& before) {
        for (const auto& shard : _shards) {
            const auto r = _now->call(
                "GetRecords", {{"ShardIterator", before._trim_horizon.at(shard)}, {"Limit", 1}});
            BOOST_TEST(r.status == 200U, shard << " TRIM_HORIZON from before: " << r.body);
            const auto l = _now->call(
                "GetRecords", {{"ShardIterator", before._latest.at(shard)}, {"Limit", 100}});
            BOOST_TEST(l.status == 200U, shard << " LATEST from before: " << l.body);
            if (l.status != 200U) {
                continue;
            }
            const auto tip = before._tips.find(shard);
            if (tip == before._tips.end()) {
                continue;
            }
            const auto got = json::parse(l.body);
            for (const auto& rec : got.at("Records").as_array()) {
                const auto seq = str(rec.at("SequenceNumber"));
                BOOST_TEST(seq_less(tip->second, seq),
                           "LATEST issued after " << tip->second << " returned " << seq);
            }
        }
    }

    // A KCL worker takes one more shard lease at each step.
    void take_lease() {
        const auto n = _leases++;
        const auto path = "/v1/leases/kcl-app/lease-" + std::to_string(n);
        const auto r = _now->lease(
            "PUT", path, R"({"leaseOwner":"worker-)" + std::to_string(n) + R"("})", k_create);
        BOOST_TEST(r.status == 200U, _now->name() << " PUT " << path << ": " << r.body);
        check_leases();
    }

    void check_leases() {
        for (int j = 0; j < _leases; ++j) {
            const auto path = "/v1/leases/kcl-app/lease-" + std::to_string(j);
            const auto r = _now->lease("GET", path);
            BOOST_REQUIRE_MESSAGE(r.status == 200U, _now->name() + " GET " + path + ": " + r.body);
            BOOST_TEST(str(json::parse(r.body).at("lease").at("leaseOwner")) ==
                       "worker-" + std::to_string(j));
            BOOST_TEST(
                _now->lease("PUT", path, R"({"leaseOwner":"thief"})", k_create).status == 412U,
                path << " taken twice");
        }
    }

    replicated_data_layer _data;
    kt::cluster_handle _handle;
    std::vector<std::unique_ptr<front_end_node>> _front_ends;
    std::vector<std::unique_ptr<gateway_node>> _gateways;
    endpoint* _now = nullptr;
    std::vector<std::string> _shards;
    int _leases = 0;
    std::unique_ptr<traffic> _traffic;
};

auto on(std::initializer_list<const char*> nodes, store_kind kind = store_kind::local)
    -> std::vector<placement> {
    std::vector<placement> out;
    for (const auto* n : nodes) {
        out.push_back({n, kind});
    }
    return out;
}

// Co-located nodes hold replicas and serve; data-only nodes hold replicas
// alone; the v nodes keep theirs in volumes on segment nodes.
const auto k_colocated = on({"n1", "n2", "n3"});
const auto k_data_only = on({"d1", "d2", "d3"});
const auto k_on_volumes = on({"v1", "v2", "v3"}, store_kind::volume);

using kt::layout_kind;
constexpr stop k_direct{layout_kind::co_located, false};
constexpr stop k_gateway_co{layout_kind::co_located, true};
constexpr stop k_front_end_apart{layout_kind::front_end_apart, false};
constexpr stop k_gateway_apart{layout_kind::front_end_apart, true};

}  // namespace

// ---- one role at a time -----------------------------------------------------

// The gateway role split off a co-located node and folded back: clients
// move onto a gateway, its front end restarts under them, and they move
// back off as the gateway drains.
BOOST_AUTO_TEST_CASE(the_gateway_role_splits_off_and_folds_back) {
    rig r(k_colocated, k_direct);
    r.move_clients(k_gateway_co);
    r.restart_front_end();
    r.move_clients(k_direct);
    r.finish();
}

BOOST_AUTO_TEST_CASE(the_gateway_role_folds_in_and_splits_off_again) {
    rig r(k_colocated, k_gateway_co);
    r.restart_front_end();
    r.move_clients(k_direct);
    r.move_clients(k_gateway_co);
    r.restart_front_end();
    r.finish();
}

// The front-end role split off: clients move from a co-located node's front
// end to one with no replica, which reaches the data layer over the wire,
// and back.
BOOST_AUTO_TEST_CASE(the_front_end_role_splits_off_and_folds_back) {
    rig r(k_colocated, k_direct);
    r.move_clients(k_front_end_apart);
    r.move_clients(k_direct);
    r.finish();
}

BOOST_AUTO_TEST_CASE(the_front_end_role_folds_in_and_splits_off_again) {
    rig r(k_colocated, k_front_end_apart);
    r.move_clients(k_direct);
    r.move_clients(k_front_end_apart);
    r.finish();
}

// The data role evacuated: the clients' front end stops holding data, each
// replica moves from a co-located node to a data-only node, and the way
// back moves them home before the front end serves from its replica again.
BOOST_AUTO_TEST_CASE(the_data_role_is_evacuated_to_data_only_nodes_and_back) {
    rig r(k_colocated, k_direct);
    r.move_clients(k_front_end_apart);
    r.move_replicas(k_data_only);
    r.move_replicas(k_colocated);
    r.move_clients(k_direct);
    r.finish();
}

BOOST_AUTO_TEST_CASE(the_data_role_comes_back_to_co_located_nodes_and_leaves_again) {
    rig r(k_data_only, k_front_end_apart);
    r.move_replicas(k_colocated);
    r.move_clients(k_direct);
    r.move_clients(k_front_end_apart);
    r.move_replicas(k_data_only);
    r.finish();
}

// Segments moved from each data node's disk to volumes on segment nodes by
// replacing each replica with one whose store is a volume, and back.
BOOST_AUTO_TEST_CASE(segments_move_to_volumes_and_back_by_replica_replacement) {
    rig r(k_data_only, k_front_end_apart);
    r.move_replicas(k_on_volumes);
    BOOST_TEST(r.data().volumes() == 3U);
    r.move_replicas(k_data_only);
    r.finish();
}

BOOST_AUTO_TEST_CASE(segments_move_off_volumes_and_back_by_replica_replacement) {
    rig r(k_on_volumes, k_gateway_apart);
    r.move_replicas(k_data_only);
    r.move_replicas(on({"v4", "v5", "v6"}, store_kind::volume));
    BOOST_TEST(r.data().volumes() == 6U);
    r.finish();
}

// ---- the whole way ----------------------------------------------------------

namespace {

// The layouts from co-located to the four-way split, one role at a time.
// Stage 0: every role on the n nodes. 1: gateway apart. 2: front end apart.
// 3: data on data-only nodes. 4: segments in volumes on segment nodes.
void go(rig& r, int from, int to) {
    const auto step = [&r](int stage, bool forward) {
        switch (stage) {
            case 1:
                r.move_clients(forward ? k_gateway_co : k_direct);
                break;
            case 2:
                r.move_clients(forward ? k_gateway_apart : k_gateway_co);
                break;
            case 3:
                r.move_replicas(forward ? k_data_only : k_colocated);
                break;
            case 4:
                r.move_replicas(forward ? k_on_volumes : k_data_only);
                break;
            default:
                BOOST_FAIL("no stage " << stage);
        }
    };
    for (int s = from + 1; s <= to; ++s) {
        BOOST_TEST_CONTEXT("stage " << s - 1 << " -> " << s) {
            step(s, true);
        }
    }
    for (int s = from; s > to; --s) {
        BOOST_TEST_CONTEXT("stage " << s << " -> " << s - 1) {
            step(s, false);
        }
    }
}

}  // namespace

// Co-located to the four-way split and back, stopping half way and
// reversing before going on.
BOOST_AUTO_TEST_CASE(co_located_to_four_way_split_and_back_reversing_half_way) {
    rig r(k_colocated, k_direct);
    go(r, 0, 2);
    go(r, 2, 1);
    go(r, 1, 4);
    go(r, 4, 0);
    r.finish();
}

BOOST_AUTO_TEST_CASE(four_way_split_to_co_located_and_back_reversing_half_way) {
    rig r(k_on_volumes, k_gateway_apart);
    go(r, 4, 2);
    go(r, 2, 3);
    go(r, 3, 0);
    go(r, 0, 4);
    r.finish();
}
