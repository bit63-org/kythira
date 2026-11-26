// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_data_api.hpp
/// @brief The data-layer API and the front end's remote and hybrid data
///        access over it (`.kiro/specs/kinesis-independent-layers/` task 6,
///        design "Data-layer API on the existing internal listener",
///        Requirements 3.2, 5.1-5.6).
///
/// A front end that holds no replica of a group asks a data node the same
/// named queries `local_data_access` answers in-process (task 2,
/// `kinesis_data_access.hpp`). Six routes on a data node's internal
/// listener carry them, beside the `v1` gateway-to-gateway routes:
///
///   POST /_kythira/kinesis/v2/propose    route, key, admission, command
///   POST /_kythira/kinesis/v2/transact   writes -> outcome
///   POST /_kythira/kinesis/v2/catalog    route, query, arguments
///   POST /_kythira/kinesis/v2/shard      route, key -> shard state
///   POST /_kythira/kinesis/v2/read       route, key, from, limits -> records
///   POST /_kythira/kinesis/v2/routes     key range -> routes, addresses
///
/// Every body starts with a version byte; integers and text use the
/// catalog codec (`kinesis_catalog.hpp`), records their own encodings.
///
/// ## Writes
///
/// `propose` is proposed on the data node that receives it, never forwarded
/// on (Requirement 5.2): a node that does not lead the key's group answers
/// 409 with its leader hint, and the front end corrects its route cache
/// and tries the leader. Only answers that say nothing was proposed (409,
/// 404, 421 and a refused connection) are retried; a 503 means the command
/// may still commit, so the front end answers it as today's timeouts are
/// answered, and the client retries. Retrying is bounded by
/// `remote_data_options::_attempts`.
///
/// `transact` runs the tier-1 coordinator on whichever data node takes it:
/// every data node is a Raft member and already sends transaction ops to
/// the leaders of the groups involved.
///
/// ## Reads
///
/// Catalog, shard and record reads go to a replica of the owning group,
/// nearest first (`route_cache::read_targets`), and are answered from that
/// replica as `local_data_access` answers them: the same staleness a
/// co-located node's replica read has today, which the handlers already
/// wait out where it matters (their own writes). The Lease API needs no
/// read route: every lease read is a proposal, so it is linearizable over
/// `propose` (Requirement 5.3).
///
/// `read` answers records as stored: sealed for an encrypted stream, so
/// keys and plaintext stay on the front end (Requirement 5.4). A data node
/// caps a read at `k_max_read_records` and `k_max_read_bytes`, the most
/// any GetRecords may ask for today (Requirement 5.5).
///
/// ## Routes
///
/// Keyed requests carry the group and epoch the front end routed them by.
/// A data node whose map is newer answers 421 with the current route
/// (`check_route`'s stale case) and the front end retries with it; a node
/// that holds no replica of the group answers 404 and the front end tries
/// the next replica. A node that cannot answer at all (no read point, no
/// apply in time) answers 503 and the next replica is tried.
///
/// ## Who may call
///
/// `serve_data_api` takes the listener's verdict on the caller, as the KMS
/// catalog API does: the gateway admits a request signed with the cluster's
/// forward secret over the path and body (what co-located nodes share
/// today), or one from a caller presenting a layer identity with the
/// `front_end` or `data` role when the node checks identities.
///
/// ## The three accesses
///
/// - `remote_data_access`: every query over the API, through a
///   `route_cache` seeded with data-node addresses (`KINESIS_DATA_NODES`).
/// - `hybrid_data_access<Cluster>`: a front end on a data node. Per call, a
///   key whose group this node holds a replica of is answered locally
///   (the local branch is task 2's code, Requirement 1.2); any other goes
///   remote.
/// - `local_data_access<Cluster>`: task 2, unchanged.

#include <kythira/kinesis/kinesis_catalog.hpp>
#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_data_access.hpp>
#include <kythira/kinesis/kinesis_forward.hpp>
#include <kythira/kinesis/kinesis_records.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>
#include <kythira/kinesis/kinesis_throttle.hpp>

#include <raft/host_node_id.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/route_cache.hpp>
#include <raft/shard_types.hpp>

#include <boost/beast/http.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis {

namespace data_api {

inline constexpr std::string_view k_prefix = "/_kythira/kinesis/v2/";
inline constexpr std::string_view k_propose_path = "/_kythira/kinesis/v2/propose";
inline constexpr std::string_view k_transact_path = "/_kythira/kinesis/v2/transact";
inline constexpr std::string_view k_catalog_path = "/_kythira/kinesis/v2/catalog";
inline constexpr std::string_view k_shard_path = "/_kythira/kinesis/v2/shard";
inline constexpr std::string_view k_read_path = "/_kythira/kinesis/v2/read";
inline constexpr std::string_view k_routes_path = "/_kythira/kinesis/v2/routes";
inline constexpr std::uint8_t k_version = 1;

/// The most a `read` returns: GetRecords' record limit, and the relaxed
/// profile's byte limit (`kinesis_limits::_relaxed_get_records_bytes`).
inline constexpr std::size_t k_max_read_records = 10'000;
inline constexpr std::uint64_t k_max_read_bytes = std::uint64_t{64} * 1024 * 1024;

/// Answers that carry their meaning in the status.
inline constexpr unsigned k_ok = 200;
inline constexpr unsigned k_malformed = 400;
inline constexpr unsigned k_refused = 403;
/// No replica of the group here (or no route for the key).
inline constexpr unsigned k_no_replica = 404;
/// Not the leader; the body names the leader when known.
inline constexpr unsigned k_not_leader = 409;
/// The caller's route is stale; the body is the current one.
inline constexpr unsigned k_stale_route = 421;
/// Not answered now (or, for a write, the outcome is unknown).
inline constexpr unsigned k_unavailable = 503;

[[nodiscard]] inline auto is_data_api_path(std::string_view target) -> bool {
    return target.starts_with(k_prefix);
}

/// What a signed request's `x-kythira-forward` covers: path and body, so a
/// signature for one route cannot be replayed on another.
[[nodiscard]] inline auto signed_text(std::string_view path, std::string_view body) -> std::string {
    std::string out(path);
    out.push_back('\n');
    out.append(body);
    return out;
}

/// The catalog queries `catalog` carries, one per `data_access` query.
enum class catalog_query : std::uint8_t {
    find_stream = 1,
    list_streams = 2,
    streams = 3,
    find_channel = 4,
    find_channel_by_id = 5,
    list_channels = 6,
};

}  // namespace data_api

/// A route as the API carries it: group ids as the host's, node ids as
/// text (`host_node_id_text`), so the front end needs no host types.
using data_route = shard_descriptor<std::uint64_t, std::string, std::string>;
using data_route_cache = route_cache<std::uint64_t, std::string, std::string>;

/// The group and epoch a keyed request was routed by.
struct route_ref {
    std::uint64_t _group = 0;
    shard_epoch _epoch{};
};

/// The data node's side of a keyed request's route check.
struct route_verdict {
    route_check_kind _kind = route_check_kind::current;
    /// For `stale`: the route that owns the key now.
    std::optional<data_route> _route;
};

/// A proposal made on this data node only.
struct data_node_proposal {
    enum class kind : std::uint8_t {
        committed,
        not_leader,
        no_replica,
        failed
    };
    kind _kind = kind::failed;
    std::optional<apply_result> _result;
    std::optional<std::string> _leader;
};

/// What a data node serves the API from. Every member must be set.
struct data_api_deps {
    /// The queries and transactions, answered from this node's replicas.
    data_access* _local = nullptr;
    /// Proposes on this node only (`raft_stream_cluster::propose_here`).
    std::function<data_node_proposal(const std::string& key, const std::vector<std::byte>& command,
                                     admission mode)>
        _propose_here;
    /// The route check for a keyed request (`check_route`); a request
    /// without a route is checked only for a replica.
    std::function<route_verdict(const std::string& key, const std::optional<route_ref>& route)>
        _check;
    /// The `routes` answer for a range, with each named node's address.
    std::function<data_route_cache::routes_reply(const shard_range<std::string>& range)> _routes;
};

struct data_api_answer {
    unsigned _status = data_api::k_ok;
    std::string _body;
};

namespace data_api_detail {

[[nodiscard]] inline auto to_string(const std::vector<std::byte>& b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

[[nodiscard]] inline auto to_bytes(std::string_view s) -> std::span<const std::byte> {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

inline void put_opt_str(codec::writer& w, const std::optional<std::string>& s) {
    w.u8(s ? 1 : 0);
    if (s) {
        w.str(*s);
    }
}

[[nodiscard]] inline auto get_opt_str(codec::reader& r) -> std::optional<std::string> {
    if (!r.boolean()) {
        return std::nullopt;
    }
    return r.str();
}

inline void put_strs(codec::writer& w, const std::vector<std::string>& v) {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const auto& s : v) {
        w.str(s);
    }
}

[[nodiscard]] inline auto get_strs(codec::reader& r) -> std::vector<std::string> {
    const auto n = r.u32();
    if (n > r.remaining() / 4) {
        throw kinesis_codec_error("kinesis data api: string count past the body");
    }
    std::vector<std::string> out;
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(r.str());
    }
    return out;
}

inline void put_route(codec::writer& w, const data_route& d) {
    w.u64(d._group_id);
    put_opt_str(w, d._range._start);
    put_opt_str(w, d._range._end);
    w.u64(d._epoch._version).u64(d._epoch._conf_version);
    put_strs(w, d._voters);
    put_strs(w, d._learners);
    put_opt_str(w, d._leader_hint);
}

[[nodiscard]] inline auto get_route(codec::reader& r) -> data_route {
    data_route d;
    d._group_id = r.u64();
    d._range._start = get_opt_str(r);
    d._range._end = get_opt_str(r);
    d._epoch._version = r.u64();
    d._epoch._conf_version = r.u64();
    d._voters = get_strs(r);
    d._learners = get_strs(r);
    d._leader_hint = get_opt_str(r);
    return d;
}

inline void put_route_ref(codec::writer& w, const std::optional<route_ref>& ref) {
    w.u8(ref ? 1 : 0);
    if (ref) {
        w.u64(ref->_group).u64(ref->_epoch._version).u64(ref->_epoch._conf_version);
    }
}

[[nodiscard]] inline auto get_route_ref(codec::reader& r) -> std::optional<route_ref> {
    if (!r.boolean()) {
        return std::nullopt;
    }
    route_ref ref;
    ref._group = r.u64();
    ref._epoch._version = r.u64();
    ref._epoch._conf_version = r.u64();
    return ref;
}

inline void put_shard_state(codec::writer& w, const shard_state& s) {
    w.u64(s._last_counter).i64(s._last_arrival_ms).u8(s._open ? 1 : 0);
    w.u64(s._trim_before).u64(s._retained_bytes).u64(s._records);
    w.u32(static_cast<std::uint32_t>(s._sealed.size()));
    for (const auto& d : s._sealed) {
        w.bytes(encode_segment_descriptor(d));
    }
    w.u32(static_cast<std::uint32_t>(s._tiered.size()));
    for (const auto t : s._tiered) {
        w.u64(t);
    }
}

[[nodiscard]] inline auto get_shard_state(codec::reader& r) -> shard_state {
    shard_state s;
    s._last_counter = r.u64();
    s._last_arrival_ms = r.i64();
    s._open = r.boolean();
    s._trim_before = r.u64();
    s._retained_bytes = r.u64();
    s._records = r.u64();
    const auto sealed = r.u32();
    if (sealed > r.remaining() / 4) {
        throw kinesis_codec_error("kinesis data api: segment count past the body");
    }
    for (std::uint32_t i = 0; i < sealed; ++i) {
        const auto blob = r.bytes();
        std::span<const std::byte> in(blob);
        auto d = decode_segment_descriptor(in);
        if (!d || !in.empty()) {
            throw kinesis_codec_error("kinesis data api: bad segment descriptor");
        }
        s._sealed.push_back(std::move(*d));
    }
    const auto tiered = r.u32();
    if (tiered > r.remaining() / 8) {
        throw kinesis_codec_error("kinesis data api: tiered count past the body");
    }
    for (std::uint32_t i = 0; i < tiered; ++i) {
        s._tiered.push_back(r.u64());
    }
    return s;
}

inline void put_streams(codec::writer& w, const std::vector<stream_record>& v) {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const auto& s : v) {
        encode(w, s);
    }
}

[[nodiscard]] inline auto get_streams(codec::reader& r) -> std::vector<stream_record> {
    const auto n = r.u32();
    std::vector<stream_record> out;
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(decode_stream_record(r));
    }
    return out;
}

inline void put_channels(codec::writer& w, const std::vector<channel_record>& v) {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const auto& c : v) {
        encode(w, c);
    }
}

[[nodiscard]] inline auto get_channels(codec::reader& r) -> std::vector<channel_record> {
    const auto n = r.u32();
    std::vector<channel_record> out;
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(decode_channel_record(r));
    }
    return out;
}

/// A request body's reader, past its version byte.
[[nodiscard]] inline auto open_body(std::string_view body) -> codec::reader {
    codec::reader r(to_bytes(body));
    if (r.u8() != data_api::k_version) {
        throw kinesis_codec_error("kinesis data api: unknown version");
    }
    return r;
}

[[nodiscard]] inline auto writer_v() -> codec::writer {
    codec::writer w;
    w.u8(data_api::k_version);
    return w;
}

[[nodiscard]] inline auto ok(codec::writer& w) -> data_api_answer {
    return {data_api::k_ok, to_string(w.take())};
}

[[nodiscard]] inline auto status(unsigned code, std::string_view why) -> data_api_answer {
    return {code, std::string(why)};
}

[[nodiscard]] inline auto stale(const data_route& current) -> data_api_answer {
    auto w = writer_v();
    put_route(w, current);
    return {data_api::k_stale_route, to_string(w.take())};
}

/// The route check's answer, or nothing when the request may be served.
[[nodiscard]] inline auto refuse_route(const data_api_deps& deps, const std::string& key,
                                       const std::optional<route_ref>& ref)
    -> std::optional<data_api_answer> {
    const auto v = deps._check(key, ref);
    switch (v._kind) {
        case route_check_kind::current:
            return std::nullopt;
        case route_check_kind::stale:
            if (v._route) {
                return stale(*v._route);
            }
            return status(data_api::k_no_replica, "no route for the key");
        case route_check_kind::unknown_group:
            return status(data_api::k_no_replica, "no such group here");
    }
    return status(data_api::k_no_replica, "no such group here");
}

[[nodiscard]] inline auto serve_propose(const data_api_deps& deps, std::string_view body)
    -> data_api_answer {
    auto r = open_body(body);
    const auto ref = get_route_ref(r);
    const auto key = r.str();
    const auto mode = r.enumeration<admission>(static_cast<std::uint8_t>(admission::shard_limits));
    const auto command = r.bytes();
    r.expect_end("propose");
    if (auto refused = refuse_route(deps, key, ref)) {
        return std::move(*refused);
    }
    const auto p = deps._propose_here(key, command, mode);
    switch (p._kind) {
        case data_node_proposal::kind::committed: {
            if (!p._result) {
                return status(data_api::k_unavailable, "not committed here");
            }
            auto w = writer_v();
            w.bytes(encode_result(*p._result));
            return ok(w);
        }
        case data_node_proposal::kind::not_leader: {
            auto w = writer_v();
            put_opt_str(w, p._leader);
            return {data_api::k_not_leader, to_string(w.take())};
        }
        case data_node_proposal::kind::no_replica:
            return status(data_api::k_no_replica, "no replica of the group here");
        case data_node_proposal::kind::failed:
            break;
    }
    return status(data_api::k_unavailable, "not committed here");
}

[[nodiscard]] inline auto serve_transact(const data_api_deps& deps, std::string_view body)
    -> data_api_answer {
    auto r = open_body(body);
    const auto n = r.u32();
    if (n == 0 || n > r.remaining() / 8) {
        throw kinesis_codec_error("kinesis data api: bad write count");
    }
    std::vector<txn_write> writes;
    writes.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        txn_write wr;
        wr._key = r.str();
        wr._command = r.bytes();
        writes.push_back(std::move(wr));
    }
    r.expect_end("transact");
    const auto outcome = deps._local->transact(std::move(writes));
    auto w = writer_v();
    w.u8(static_cast<std::uint8_t>(outcome));
    return ok(w);
}

template<typename T>
[[nodiscard]] auto answer_or_unavailable(const data_result<T>& got, auto&& put) -> data_api_answer {
    if (!got) {
        return status(data_api::k_no_replica, "no replica of the group here");
    }
    auto w = writer_v();
    put(w, *got);
    return ok(w);
}

[[nodiscard]] inline auto serve_catalog(const data_api_deps& deps, std::string_view body)
    -> data_api_answer {
    using data_api::catalog_query;
    auto r = open_body(body);
    const auto ref = get_route_ref(r);
    const auto q =
        r.enumeration<catalog_query>(static_cast<std::uint8_t>(catalog_query::list_channels));
    if (auto refused = refuse_route(deps, next_id_key(), ref)) {
        return std::move(*refused);
    }
    auto& d = *deps._local;
    const auto put_opt_stream = [](codec::writer& w, const std::optional<stream_record>& s) {
        w.u8(s ? 1 : 0);
        if (s) {
            encode(w, *s);
        }
    };
    const auto put_opt_channel = [](codec::writer& w, const std::optional<channel_record>& c) {
        w.u8(c ? 1 : 0);
        if (c) {
            encode(w, *c);
        }
    };
    switch (q) {
        case catalog_query::find_stream: {
            const auto account = r.str();
            const auto name = r.str();
            r.expect_end("catalog");
            return answer_or_unavailable(d.find_stream(account, name), put_opt_stream);
        }
        case catalog_query::list_streams: {
            const auto account = r.str();
            const auto after = r.str();
            const auto limit = r.u64();
            r.expect_end("catalog");
            return answer_or_unavailable(d.list_streams(account, after, limit), put_streams);
        }
        case catalog_query::streams: {
            const auto n = r.u32();
            if (n > r.remaining()) {
                throw kinesis_codec_error("kinesis data api: bad status count");
            }
            stream_status_filter filter;
            for (std::uint32_t i = 0; i < n; ++i) {
                filter.push_back(r.enumeration<stream_status>(
                    static_cast<std::uint8_t>(stream_status::deleting)));
            }
            r.expect_end("catalog");
            return answer_or_unavailable(d.streams(filter), put_streams);
        }
        case catalog_query::find_channel: {
            const auto account = r.str();
            const auto name = r.str();
            r.expect_end("catalog");
            return answer_or_unavailable(d.find_channel(account, name), put_opt_channel);
        }
        case catalog_query::find_channel_by_id: {
            const auto account = r.str();
            const auto id = r.u64();
            r.expect_end("catalog");
            return answer_or_unavailable(d.find_channel_by_id(account, id), put_opt_channel);
        }
        case catalog_query::list_channels: {
            const auto account = r.str();
            const auto after = r.str();
            const auto limit = r.u64();
            r.expect_end("catalog");
            return answer_or_unavailable(d.list_channels(account, after, limit), put_channels);
        }
    }
    throw kinesis_codec_error("kinesis data api: unknown catalog query");
}

[[nodiscard]] inline auto serve_shard(const data_api_deps& deps, std::string_view body)
    -> data_api_answer {
    auto r = open_body(body);
    const auto ref = get_route_ref(r);
    const auto key = r.str();
    r.expect_end("shard");
    if (auto refused = refuse_route(deps, key, ref)) {
        return std::move(*refused);
    }
    return answer_or_unavailable(deps._local->shard(key),
                                 [](codec::writer& w, const std::optional<shard_state>& s) {
                                     w.u8(s ? 1 : 0);
                                     if (s) {
                                         put_shard_state(w, *s);
                                     }
                                 });
}

[[nodiscard]] inline auto serve_read(const data_api_deps& deps, std::string_view body)
    -> data_api_answer {
    auto r = open_body(body);
    const auto ref = get_route_ref(r);
    const auto key = r.str();
    const auto from = r.u64();
    const auto min_ts = r.i64();
    const segment_read_limits limits{
        ._max_records = static_cast<std::size_t>(
            std::min<std::uint64_t>(r.u64(), data_api::k_max_read_records)),
        ._max_bytes = std::min(r.u64(), data_api::k_max_read_bytes)};
    r.expect_end("read");
    if (auto refused = refuse_route(deps, key, ref)) {
        return std::move(*refused);
    }
    std::optional<data_result<shard_records>> got;
    try {
        got.emplace(deps._local->read_records(key, from, min_ts, limits));
    } catch (const std::exception&) {
        // A record failing its CRC: this replica cannot serve the read.
        return status(data_api::k_unavailable, "the replica could not read the shard");
    }
    return answer_or_unavailable(*got, [](codec::writer& w, const shard_records& s) {
        w.u8(s._found ? 1 : 0).i64(s._last_arrival_ms);
        w.u64(s._read._next_counter).u8(s._read._caught_up ? 1 : 0).u8(s._read._missing ? 1 : 0);
        w.u32(static_cast<std::uint32_t>(s._read._records.size()));
        for (const auto& rec : s._read._records) {
            w.u64(rec._seq).i64(rec._timestamp_ms).bytes(rec._data);
        }
    });
}

[[nodiscard]] inline auto serve_routes(const data_api_deps& deps, std::string_view body)
    -> data_api_answer {
    auto r = open_body(body);
    shard_range<std::string> range;
    range._start = get_opt_str(r);
    range._end = get_opt_str(r);
    r.expect_end("routes");
    const auto reply = deps._routes(range);
    auto w = writer_v();
    w.u32(static_cast<std::uint32_t>(reply.routes.size()));
    for (const auto& d : reply.routes) {
        put_route(w, d);
    }
    w.u32(static_cast<std::uint32_t>(reply.addresses.size()));
    for (const auto& [node, address] : reply.addresses) {
        w.str(node).str(address);
    }
    return ok(w);
}

}  // namespace data_api_detail

/// Answers a data-layer API request, or nothing when `target` is not one.
/// `allowed` is the listener's verdict on the caller.
[[nodiscard]] inline auto serve_data_api(const data_api_deps& deps, bool allowed,
                                         std::string_view method, std::string_view target,
                                         std::string_view body) -> std::optional<data_api_answer> {
    using namespace data_api_detail;  // NOLINT(google-build-using-namespace)
    if (!data_api::is_data_api_path(target)) {
        return std::nullopt;
    }
    if (!allowed) {
        return status(data_api::k_refused, "not a Kinesis front end or data node");
    }
    if (method != "POST") {
        return status(data_api::k_malformed, "malformed data-layer request");
    }
    try {
        if (target == data_api::k_propose_path) {
            return serve_propose(deps, body);
        }
        if (target == data_api::k_transact_path) {
            return serve_transact(deps, body);
        }
        if (target == data_api::k_catalog_path) {
            return serve_catalog(deps, body);
        }
        if (target == data_api::k_shard_path) {
            return serve_shard(deps, body);
        }
        if (target == data_api::k_read_path) {
            return serve_read(deps, body);
        }
        if (target == data_api::k_routes_path) {
            return serve_routes(deps, body);
        }
    } catch (const kinesis_codec_error&) {
        return status(data_api::k_malformed, "malformed data-layer request");
    } catch (const std::exception&) {
        return status(data_api::k_unavailable, "data-layer request failed");
    }
    return status(data_api::k_malformed, "unknown data-layer route");
}

// ---------------------------------------------------------------------------
// The front end's side
// ---------------------------------------------------------------------------

/// One POST to a data node at `address` ("host:port"): status and body, or
/// nothing when it could not be reached.
using data_transport = std::function<std::optional<std::pair<unsigned, std::string>>(
    const std::string& address, std::string_view target, std::string body)>;

struct remote_data_options {
    /// Rounds of route correction a call may take (not leader, stale route,
    /// no replica) before it gives up as unreachable.
    int _attempts = 4;
    route_cache_options _routes{};
    /// The clock arrival and creation times are stamped with; empty is
    /// this node's wall clock. Tests that drive a data node's clock hand
    /// the same one here, as NTP keeps every real layer's in step.
    std::function<std::int64_t()> _clock;
    /// Told, for every keyed call that ends without an answer, what each
    /// target answered on the way (`node@address: status reason`, in
    /// order), so an operator sees where the data layer stopped taking
    /// calls. Empty is silent.
    std::function<void(std::string_view)> _on_failure;
};

struct remote_data_stats {
    std::uint64_t _calls = 0;
    std::uint64_t _not_leader = 0;
    std::uint64_t _stale_route = 0;
    std::uint64_t _no_replica = 0;
    std::uint64_t _unreachable = 0;
};

/// `data_access` over the data-layer API: what a front end without the
/// `data` role serves the whole API over (task 7, `KINESIS_DATA_NODES`).
/// Thread-safe.
class remote_data_access final : public data_access {
public:
    /// @param seeds data-node addresses ("host:port", names resolved at
    ///        use) asked for routes when no known node answers.
    remote_data_access(std::vector<std::string> seeds, data_transport transport,
                       remote_data_options options = {})
        : _transport(std::move(transport)),
          _options(options),
          _routes(
              std::move(seeds),
              [this](const std::string& address, const shard_range<std::string>& range) {
                  return fetch_routes(address, range);
              },
              options._routes) {
        if (!_transport) {
            throw std::invalid_argument("remote_data_access: no transport");
        }
    }

    auto propose(const std::string& key, std::vector<std::byte> command, admission mode)
        -> std::optional<apply_result> override {
        const auto body = keyed(key, data_api::k_propose_path, true,
                                [&](codec::writer& w, const std::optional<route_ref>& ref) {
                                    data_api_detail::put_route_ref(w, ref);
                                    w.str(key).u8(static_cast<std::uint8_t>(mode)).bytes(command);
                                });
        if (!body) {
            return std::nullopt;
        }
        try {
            auto r = data_api_detail::open_body(*body);
            const auto bytes = r.bytes();
            r.expect_end("propose answer");
            return decode_result(bytes);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    [[nodiscard]] auto can_transact() const -> bool override { return true; }

    auto transact(std::vector<txn_write> writes) -> transact_outcome override {
        if (writes.empty()) {
            return transact_outcome::committed;
        }
        auto w = data_api_detail::writer_v();
        w.u32(static_cast<std::uint32_t>(writes.size()));
        for (const auto& wr : writes) {
            w.str(wr._key).bytes(wr._command);
        }
        const auto body = data_api_detail::to_string(w.take());
        // Any data node coordinates; try the first write's group's
        // replicas, then the seeds. Only a refused connection is tried
        // elsewhere: any other failure may have committed.
        const auto targets = addresses_for(writes.front()._key, true);
        for (const auto& [node, address] : targets) {
            const auto res = call(address, data_api::k_transact_path, body);
            if (!res) {
                if (node) {
                    _routes.on_connection_failure(*node);
                }
                continue;
            }
            if (res->first != data_api::k_ok) {
                return transact_outcome::unknown;
            }
            try {
                auto r = data_api_detail::open_body(res->second);
                const auto o = r.enumeration<transact_outcome>(
                    static_cast<std::uint8_t>(transact_outcome::unknown));
                r.expect_end("transact answer");
                return o;
            } catch (const std::exception&) {
                return transact_outcome::unknown;
            }
        }
        return transact_outcome::aborted;  // nobody took it: nothing applied
    }

    [[nodiscard]] auto group_of(const std::string& key) -> std::optional<std::uint64_t> override {
        if (auto r = _routes.ensure(key)) {
            return r->_group_id;
        }
        return std::nullopt;
    }

    /// A front end leads nothing.
    [[nodiscard]] auto leads(const std::string& /*key*/) -> bool override { return false; }

    /// This node's wall clock, as `raft_stream_cluster::now_ms` is every
    /// co-located node's: every layer runs NTP.
    [[nodiscard]] auto now_ms() -> std::int64_t override {
        if (_options._clock) {
            return _options._clock();
        }
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    [[nodiscard]] auto find_stream(std::string_view account, std::string_view name)
        -> data_result<std::optional<stream_record>> override {
        return catalog<std::optional<stream_record>>(
            data_api::catalog_query::find_stream,
            [&](codec::writer& w) { w.str(account).str(name); },
            [](codec::reader& r) -> std::optional<stream_record> {
                if (!r.boolean()) {
                    return std::nullopt;
                }
                return decode_stream_record(r);
            });
    }

    [[nodiscard]] auto list_streams(std::string_view account, std::string_view start_after,
                                    std::size_t limit)
        -> data_result<std::vector<stream_record>> override {
        return catalog<std::vector<stream_record>>(
            data_api::catalog_query::list_streams,
            [&](codec::writer& w) { w.str(account).str(start_after).u64(limit); },
            [](codec::reader& r) { return data_api_detail::get_streams(r); });
    }

    [[nodiscard]] auto streams(const stream_status_filter& filter)
        -> data_result<std::vector<stream_record>> override {
        return catalog<std::vector<stream_record>>(
            data_api::catalog_query::streams,
            [&](codec::writer& w) {
                w.u32(static_cast<std::uint32_t>(filter.size()));
                for (const auto s : filter) {
                    w.u8(static_cast<std::uint8_t>(s));
                }
            },
            [](codec::reader& r) { return data_api_detail::get_streams(r); });
    }

    [[nodiscard]] auto find_channel(std::string_view account, std::string_view name)
        -> data_result<std::optional<channel_record>> override {
        return catalog<std::optional<channel_record>>(
            data_api::catalog_query::find_channel,
            [&](codec::writer& w) { w.str(account).str(name); }, opt_channel);
    }

    [[nodiscard]] auto find_channel_by_id(std::string_view account, std::uint64_t id)
        -> data_result<std::optional<channel_record>> override {
        return catalog<std::optional<channel_record>>(
            data_api::catalog_query::find_channel_by_id,
            [&](codec::writer& w) { w.str(account).u64(id); }, opt_channel);
    }

    [[nodiscard]] auto list_channels(std::string_view account, std::string_view start_after,
                                     std::size_t limit)
        -> data_result<std::vector<channel_record>> override {
        return catalog<std::vector<channel_record>>(
            data_api::catalog_query::list_channels,
            [&](codec::writer& w) { w.str(account).str(start_after).u64(limit); },
            [](codec::reader& r) { return data_api_detail::get_channels(r); });
    }

    [[nodiscard]] auto shard(const std::string& key)
        -> data_result<std::optional<shard_state>> override {
        const auto body = keyed(key, data_api::k_shard_path, false,
                                [&](codec::writer& w, const std::optional<route_ref>& ref) {
                                    data_api_detail::put_route_ref(w, ref);
                                    w.str(key);
                                });
        if (!body) {
            return data_error::unreachable;
        }
        try {
            auto r = data_api_detail::open_body(*body);
            std::optional<shard_state> out;
            if (r.boolean()) {
                out = data_api_detail::get_shard_state(r);
            }
            r.expect_end("shard answer");
            return out;
        } catch (const std::exception&) {
            return data_error::unreachable;
        }
    }

    [[nodiscard]] auto read_records(const std::string& key, std::uint64_t from,
                                    std::int64_t min_timestamp_ms,
                                    const segment_read_limits& limits)
        -> data_result<shard_records> override {
        const auto body = keyed(key, data_api::k_read_path, false,
                                [&](codec::writer& w, const std::optional<route_ref>& ref) {
                                    data_api_detail::put_route_ref(w, ref);
                                    w.str(key).u64(from).i64(min_timestamp_ms);
                                    w.u64(limits._max_records).u64(limits._max_bytes);
                                });
        if (!body) {
            return data_error::unreachable;
        }
        try {
            auto r = data_api_detail::open_body(*body);
            shard_records out;
            out._found = r.boolean();
            out._last_arrival_ms = r.i64();
            out._read._next_counter = r.u64();
            out._read._caught_up = r.boolean();
            out._read._missing = r.boolean();
            const auto n = r.u32();
            if (n > r.remaining() / 20) {
                throw kinesis_codec_error("kinesis data api: record count past the body");
            }
            out._read._records.reserve(n);
            for (std::uint32_t i = 0; i < n; ++i) {
                segment_record rec;
                rec._seq = r.u64();
                rec._timestamp_ms = r.i64();
                rec._data = r.bytes();
                out._read._records.push_back(std::move(rec));
            }
            r.expect_end("read answer");
            return out;
        } catch (const std::exception&) {
            return data_error::unreachable;
        }
    }

    /// A front end keeps no segments.
    [[nodiscard]] auto local_bytes(const std::string& /*key*/) -> std::uint64_t override {
        return 0;
    }

    [[nodiscard]] auto routes() -> data_route_cache& { return _routes; }

    [[nodiscard]] auto stats() const -> remote_data_stats {
        const std::lock_guard lock(_stats_mutex);
        return _stats;
    }

private:
    data_transport _transport;
    remote_data_options _options;
    data_route_cache _routes;
    mutable std::mutex _stats_mutex;
    remote_data_stats _stats;

    static auto opt_channel(codec::reader& r) -> std::optional<channel_record> {
        if (!r.boolean()) {
            return std::nullopt;
        }
        return decode_channel_record(r);
    }

    template<typename F> void count(F&& f) {
        const std::lock_guard lock(_stats_mutex);
        f(_stats);
    }

    auto call(const std::string& address, std::string_view target, std::string body)
        -> std::optional<std::pair<unsigned, std::string>> {
        count([](remote_data_stats& s) { ++s._calls; });
        try {
            return _transport(address, target, std::move(body));
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    auto fetch_routes(const std::string& address, const shard_range<std::string>& range)
        -> std::optional<data_route_cache::routes_reply> {
        auto w = data_api_detail::writer_v();
        data_api_detail::put_opt_str(w, range._start);
        data_api_detail::put_opt_str(w, range._end);
        const auto res =
            call(address, data_api::k_routes_path, data_api_detail::to_string(w.take()));
        if (!res || res->first != data_api::k_ok) {
            return std::nullopt;
        }
        try {
            auto r = data_api_detail::open_body(res->second);
            data_route_cache::routes_reply reply;
            const auto n = r.u32();
            for (std::uint32_t i = 0; i < n; ++i) {
                reply.routes.push_back(data_api_detail::get_route(r));
            }
            const auto m = r.u32();
            for (std::uint32_t i = 0; i < m; ++i) {
                auto node = r.str();
                reply.addresses.emplace_back(std::move(node), r.str());
            }
            r.expect_end("routes answer");
            return reply;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    /// Where to send a call for `key`, in order: the route's targets with
    /// their addresses, or, with no route, the seeds (node unknown).
    auto addresses_for(const std::string& key, bool write)
        -> std::vector<std::pair<std::optional<std::string>, std::string>> {
        std::vector<std::pair<std::optional<std::string>, std::string>> out;
        if (_routes.ensure(key)) {
            for (const auto& node :
                 write ? _routes.write_targets(key) : _routes.read_targets(key)) {
                if (auto a = _routes.address_of(node)) {
                    out.emplace_back(node, std::move(*a));
                }
            }
        }
        return out;
    }

    /// One keyed call: built with the route it is sent by, sent to the
    /// route's targets in order, its route corrected on every answer that
    /// says nothing was done. The 200 body, or nothing.
    template<typename Build>
    auto keyed(const std::string& key, std::string_view target, bool write, Build&& build)
        -> std::optional<std::string> {
        std::string trail;
        const auto note = [&](const std::string& node, const std::string& address,
                              std::string_view what) {
            if (!_options._on_failure) {
                return;
            }
            trail += trail.empty() ? "" : "; ";
            trail += node + "@" + address + ": ";
            trail += what.substr(0, 160);
        };
        const auto give_up = [&](std::string_view why) -> std::optional<std::string> {
            if (_options._on_failure) {
                std::string line = std::string(target) + " for key " + key + " " +
                                   std::string(why) + " [" + trail + "]";
                _options._on_failure(line);
            }
            return std::nullopt;
        };
        for (int attempt = 0; attempt < _options._attempts; ++attempt) {
            const auto route = _routes.ensure(key);
            if (!route) {
                note("-", "-", "no route");
                break;
            }
            const route_ref ref{._group = route->_group_id, ._epoch = route->_epoch};
            auto w = data_api_detail::writer_v();
            build(w, std::optional{ref});
            const auto body = data_api_detail::to_string(w.take());
            bool reroute = false;
            for (const auto& node :
                 write ? _routes.write_targets(key) : _routes.read_targets(key)) {
                const auto address = _routes.address_of(node);
                if (!address) {
                    note(node, "-", "no address");
                    continue;
                }
                const auto res = call(*address, target, body);
                if (!res) {
                    note(node, *address, "unreachable");
                    _routes.on_connection_failure(node);
                    continue;
                }
                const auto& [code, answer] = *res;
                if (code == data_api::k_ok) {
                    return answer;
                }
                if (_options._on_failure) {
                    const bool text =
                        code != data_api::k_not_leader && code != data_api::k_stale_route;
                    note(node, *address,
                         std::to_string(code) + (text ? " " + answer : std::string()));
                }
                if (code == data_api::k_not_leader) {
                    count([](remote_data_stats& s) { ++s._not_leader; });
                    std::optional<std::string> hint;
                    try {
                        auto r = data_api_detail::open_body(answer);
                        hint = data_api_detail::get_opt_str(r);
                    } catch (const std::exception&) {
                        hint.reset();
                    }
                    if (_options._on_failure) {
                        trail += " hint=" + hint.value_or("none");
                    }
                    _routes.on_not_leader(route->_group_id, hint);
                    reroute = true;
                    break;
                }
                if (code == data_api::k_stale_route) {
                    count([](remote_data_stats& s) { ++s._stale_route; });
                    try {
                        auto r = data_api_detail::open_body(answer);
                        const auto current = data_api_detail::get_route(r);
                        if (_options._on_failure) {
                            trail += " epoch=" + std::to_string(current._epoch._version) + "." +
                                     std::to_string(current._epoch._conf_version) + " voters=";
                            for (const auto& v : current._voters) {
                                trail += v + ",";
                            }
                            trail += " leader=" + current._leader_hint.value_or("none");
                        }
                        _routes.on_stale_epoch(current);
                    } catch (const std::exception&) {
                        _routes.on_unknown_group(route->_group_id);
                    }
                    reroute = true;
                    break;
                }
                if (code == data_api::k_no_replica) {
                    // This node has no replica: the next one may.
                    count([](remote_data_stats& s) { ++s._no_replica; });
                    continue;
                }
                if (write) {
                    // 503 on a write: it may still commit. Never retried.
                    return give_up("may have committed");
                }
                // A read the node could not answer now: try the next.
            }
            if (!reroute) {
                // Every target failed or had no replica: ask for the routes
                // again before the next round.
                _routes.on_unknown_group(route->_group_id);
            }
        }
        count([](remote_data_stats& s) { ++s._unreachable; });
        return give_up("found no replica to answer it");
    }

    template<typename T, typename Args, typename Parse>
    auto catalog(data_api::catalog_query q, Args&& args, Parse&& parse) -> data_result<T> {
        const auto key = next_id_key();
        const auto body = keyed(key, data_api::k_catalog_path, false,
                                [&](codec::writer& w, const std::optional<route_ref>& ref) {
                                    data_api_detail::put_route_ref(w, ref);
                                    w.u8(static_cast<std::uint8_t>(q));
                                    args(w);
                                });
        if (!body) {
            return data_error::unreachable;
        }
        try {
            auto r = data_api_detail::open_body(*body);
            T out = parse(r);
            r.expect_end("catalog answer");
            return out;
        } catch (const std::exception&) {
            return data_error::unreachable;
        }
    }
};

/// A front end on a data node: each call goes to this node's replica when
/// it holds one of the key's group, otherwise over the API. A co-located
/// node that holds every group never leaves the local branch.
template<stream_cluster Cluster> class hybrid_data_access final : public data_access {
public:
    hybrid_data_access(local_data_access<Cluster>& local, data_access& remote)
        : _local(local), _remote(remote) {}

    auto propose(const std::string& key, std::vector<std::byte> command, admission mode)
        -> std::optional<apply_result> override {
        return pick(key).propose(key, std::move(command), mode);
    }

    /// A data node coordinates transactions itself.
    [[nodiscard]] auto can_transact() const -> bool override {
        return _local.can_transact() || _remote.can_transact();
    }

    auto transact(std::vector<txn_write> writes) -> transact_outcome override {
        if (_local.can_transact()) {
            return _local.transact(std::move(writes));
        }
        return _remote.transact(std::move(writes));
    }

    [[nodiscard]] auto group_of(const std::string& key) -> std::optional<std::uint64_t> override {
        return pick(key).group_of(key);
    }

    [[nodiscard]] auto leads(const std::string& key) -> bool override { return _local.leads(key); }

    [[nodiscard]] auto now_ms() -> std::int64_t override { return _local.now_ms(); }

    [[nodiscard]] auto find_stream(std::string_view account, std::string_view name)
        -> data_result<std::optional<stream_record>> override {
        return catalog().find_stream(account, name);
    }

    [[nodiscard]] auto list_streams(std::string_view account, std::string_view start_after,
                                    std::size_t limit)
        -> data_result<std::vector<stream_record>> override {
        return catalog().list_streams(account, start_after, limit);
    }

    [[nodiscard]] auto streams(const stream_status_filter& filter)
        -> data_result<std::vector<stream_record>> override {
        return catalog().streams(filter);
    }

    [[nodiscard]] auto find_channel(std::string_view account, std::string_view name)
        -> data_result<std::optional<channel_record>> override {
        return catalog().find_channel(account, name);
    }

    [[nodiscard]] auto find_channel_by_id(std::string_view account, std::uint64_t id)
        -> data_result<std::optional<channel_record>> override {
        return catalog().find_channel_by_id(account, id);
    }

    [[nodiscard]] auto list_channels(std::string_view account, std::string_view start_after,
                                     std::size_t limit)
        -> data_result<std::vector<channel_record>> override {
        return catalog().list_channels(account, start_after, limit);
    }

    [[nodiscard]] auto shard(const std::string& key)
        -> data_result<std::optional<shard_state>> override {
        return pick(key).shard(key);
    }

    [[nodiscard]] auto read_records(const std::string& key, std::uint64_t from,
                                    std::int64_t min_timestamp_ms,
                                    const segment_read_limits& limits)
        -> data_result<shard_records> override {
        return pick(key).read_records(key, from, min_timestamp_ms, limits);
    }

    [[nodiscard]] auto local_bytes(const std::string& key) -> std::uint64_t override {
        return _local.local_bytes(key);
    }

private:
    local_data_access<Cluster>& _local;
    data_access& _remote;

    auto pick(const std::string& key) -> data_access& {
        return _local.holds(key) ? static_cast<data_access&>(_local) : _remote;
    }

    auto catalog() -> data_access& { return pick(next_id_key()); }
};

// ---------------------------------------------------------------------------
// Composition helpers
// ---------------------------------------------------------------------------

/// The front end's transport over the internal listener: each request is
/// signed with the cluster's forward secret over its path and body.
/// `Client` has `peer_client::request`'s shape.
template<typename Client>
[[nodiscard]] auto make_http_data_transport(
    const Client& client, std::string secret,
    std::function<std::chrono::system_clock::time_point()> clock = [] {
        return std::chrono::system_clock::now();
    }) -> data_transport {
    return [&client, secret = std::move(secret), clock = std::move(clock)](
               const std::string& address, std::string_view target,
               std::string body) -> std::optional<std::pair<unsigned, std::string>> {
        const auto signature = forward::sign(secret, data_api::signed_text(target, body), clock());
        const auto res = client.request(address, boost::beast::http::verb::post, target,
                                        {{std::string(forward::k_header), signature},
                                         {"Content-Type", "application/octet-stream"}},
                                        std::move(body));
        if (!res) {
            return std::nullopt;
        }
        return std::pair{res->_status, std::move(res->_body)};
    };
}

/// The deps a data node serves the API with, over its `multi_raft` host,
/// its `raft_stream_cluster` and the `local_data_access` over that cluster.
/// `address_of` names where each node's internal listener is (the node
/// itself included). All must outlive the deps.
template<typename Host, typename RaftCluster, typename Local>
[[nodiscard]] auto data_api_deps_over(
    Host& host, RaftCluster& cluster, Local& local,
    std::function<std::optional<std::string>(const typename Host::node_id_type&)> address_of)
    -> data_api_deps {
    using node_type = typename Host::node_id_type;
    const auto text = [](const node_type& n) { return host_node_id_text(n); };
    // A row as this node knows it now. The routing map keeps the replica
    // set a group was created with: membership changes (a replica
    // evacuated to a node that joined) move only the Raft configuration.
    // A front end routed by the map would never try a joined leader and
    // keep trying a replica that left, so every row this node holds a
    // replica of takes its voters and learners from that replica. A joint
    // configuration is in transit: the map's set stays until it lands.
    // The leader hint stays this node when it leads, as before: a
    // follower's last-known leader may be stale, and a not-leader answer
    // names the leader anyway.
    const auto current = [&host](auto row) {
        auto* n = host.group_node(row._group_id);
        if (n == nullptr) {
            return row;
        }
        if (const auto m = n->current_membership(); !m.joint && !m.voters.empty()) {
            row._voters = m.voters;
            row._learners = m.learners;
        }
        if (n->is_leader()) {
            row._leader_hint = host.node_id();
        }
        return row;
    };
    const auto to_route = [text](const auto& d) {
        data_route out;
        out._group_id = static_cast<std::uint64_t>(d._group_id);
        out._range = d._range;
        out._epoch = d._epoch;
        for (const auto& v : d._voters) {
            out._voters.push_back(text(v));
        }
        for (const auto& l : d._learners) {
            out._learners.push_back(text(l));
        }
        if (d._leader_hint) {
            out._leader_hint = text(*d._leader_hint);
        }
        return out;
    };
    data_api_deps deps;
    deps._local = &local;
    deps._propose_here = [&cluster, text](const std::string& key,
                                          const std::vector<std::byte>& command, admission mode) {
        const auto r = cluster.propose_here(key, command, mode);
        data_node_proposal out;
        out._result = r._result;
        if (r._leader) {
            out._leader = text(*r._leader);
        }
        using here = typename RaftCluster::here_kind;
        switch (r._kind) {
            case here::committed:
                out._kind = data_node_proposal::kind::committed;
                break;
            case here::not_leader:
                out._kind = data_node_proposal::kind::not_leader;
                break;
            case here::no_replica:
                out._kind = data_node_proposal::kind::no_replica;
                break;
            case here::failed:
                out._kind = data_node_proposal::kind::failed;
                break;
        }
        return out;
    };
    deps._check = [&host, to_route, current](const std::string& key,
                                             const std::optional<route_ref>& ref) {
        route_verdict v;
        const auto d = host.resolve(key);
        if (!d) {
            v._kind = route_check_kind::unknown_group;
            return v;
        }
        if (ref && (static_cast<std::uint64_t>(d->_group_id) != ref->_group ||
                    ref->_epoch._version < d->_epoch._version ||
                    ref->_epoch._conf_version < d->_epoch._conf_version)) {
            v._kind = route_check_kind::stale;
            v._route = to_route(current(*d));
        }
        return v;
    };
    deps._routes = [&host, to_route, text, current,
                    address_of = std::move(address_of)](const shard_range<std::string>& range) {
        data_route_cache::routes_reply reply;
        const auto map = host.shard_map_snapshot();
        std::vector<typename std::remove_cvref_t<decltype(map)>::descriptor_type> rows;
        for (const auto& row : routes_answer(map, range)) {
            rows.push_back(current(row));
        }
        std::vector<node_type> named;
        for (const auto& row : rows) {
            reply.routes.push_back(to_route(row));
            for (const auto& n : row._voters) {
                named.push_back(n);
            }
            for (const auto& n : row._learners) {
                named.push_back(n);
            }
        }
        std::ranges::sort(named);
        named.erase(std::unique(named.begin(), named.end()), named.end());
        for (const auto& n : named) {
            if (auto a = address_of(n)) {
                reply.addresses.emplace_back(text(n), std::move(*a));
            }
        }
        return reply;
    };
    return deps;
}

}  // namespace kythira::kinesis
