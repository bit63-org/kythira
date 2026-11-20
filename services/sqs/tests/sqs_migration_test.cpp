// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Migration paths (`.kiro/specs/sqs-compatible-queues/` task 11,
// Requirements 12.1-12.3 and 13.3): whole in-process nodes moving between
// layouts under standard and FIFO producers and consumers. Every path runs
// both ways and checks Requirement 12.3 at the end: no acknowledged
// message lost, FIFO order and deduplication kept, a visibility timeout
// started before the move ending on time after it, and a receipt handle
// issued before the move still deleting its message after it.

#define BOOST_TEST_MODULE sqs_migration_test

#include <boost/test/unit_test.hpp>

#include "sqs_module_harness.hpp"

#include <kythira/sqs/sqs_evacuate.hpp>
#include <kythira/sqs/sqs_forward.hpp>

#include <atomic>
#include <future>
#include <mutex>
#include <set>

namespace {

constexpr std::string_view k_forward_secret = "forwarding-secret-0123456789";

/// A signed admin call (`sqs_evacuate.hpp`) to the node on `port`.
auto admin_call(std::uint16_t port, std::string_view path, const std::string& body,
                std::chrono::seconds timeout = std::chrono::seconds(120))
    -> http::response<http::string_body> {
    boost::asio::io_context io;
    boost::beast::tcp_stream stream(io);
    stream.expires_after(timeout);
    stream.connect(
        boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    http::request<http::string_body> req{http::verb::post, std::string(path), 11};
    req.set(http::field::host, "localhost");
    req.set(http::field::content_type, "application/json");
    req.set(std::string(kythira::sqs::forward::k_header),
            kythira::sqs::forward::sign(k_forward_secret, body, std::chrono::system_clock::now()));
    req.body() = body;
    req.prepare_payload();
    http::write(stream, req);
    boost::beast::flat_buffer buf;
    http::response<http::string_body> res;
    http::read(stream, buf, res);
    return res;
}

/// Up to eight nodes on one host. 1-3 found the group with every role;
/// 4-6 join it as data-only learners (`SQS_JOIN`); 7 and 8 run stateless
/// layers.
class cluster {
public:
    static constexpr int k_max = 8;

    cluster()
        : _raft(kythira::testing::free_port_block(k_max)),
          _api(kythira::testing::free_port_block(k_max)) {}

    [[nodiscard]] auto raft_port(int id) const -> std::uint16_t {
        return static_cast<std::uint16_t>(_raft + id - 1);
    }
    [[nodiscard]] auto api_port(int id) const -> std::uint16_t {
        return static_cast<std::uint16_t>(_api + id - 1);
    }
    [[nodiscard]] auto api_url(int id) const -> std::string {
        return "http://127.0.0.1:" + std::to_string(api_port(id));
    }

    /// Starts nodes `ids` together (founders must start together to elect).
    void start(const std::vector<int>& ids, bool join, const std::string& roles = "",
               const env_map& extra = {}) {
        std::vector<std::thread> starting;
        for (const int id : ids) {
            auto env = base_env(_dir, std::to_string(id), raft_port(id), api_port(id));
            // Founders know each other, joiners know every data node, and a
            // node without the data role only itself (it runs no group).
            const bool stateless = !roles.empty() && roles.find("data") == std::string::npos;
            const int known = join ? 6 : 3;
            std::string peers;
            std::string endpoints;
            for (int i = 1; i <= known; ++i) {
                const auto sep = std::string(i == 1 ? "" : ",") + std::to_string(i);
                peers += sep + "=127.0.0.1:" + std::to_string(raft_port(i));
                endpoints += sep + "=" + api_url(i);
            }
            if (stateless) {
                env["KYTHIRA_NODE_PEERS"] =
                    std::to_string(id) + "=127.0.0.1:" + std::to_string(raft_port(id));
            } else {
                env["KYTHIRA_NODE_PEERS"] = peers;
                env["SQS_PEER_ENDPOINTS"] = endpoints;
            }
            env["SQS_COMPAT"] = "delete-cooldown=0,purge-cooldown=0";
            if (join) {
                env["SQS_JOIN"] = "on";
            }
            if (!roles.empty()) {
                env["KYTHIRA_SQS_ROLES"] = roles;
            }
            for (const auto& [k, v] : extra) {
                env[k] = v;
            }
            starting.emplace_back([this, id, env, stateless] {
                auto n = std::make_unique<node>(env);
                const std::lock_guard lock(_mutex);
                _nodes[id] = std::move(n);
                if (stateless) {
                    _data.erase(id);
                } else {
                    _data.insert(id);
                }
            });
        }
        for (auto& t : starting) {
            t.join();
        }
    }

    auto at(int id) -> node& { return *_nodes.at(id); }

    /// Stops node `id` (a drain first: parked long polls answer empty).
    void stop(int id) {
        std::unique_ptr<node> n;
        {
            const std::lock_guard lock(_mutex);
            n = std::move(_nodes.at(id));
            _nodes.erase(id);
            _data.erase(id);
        }
        n->stop();
    }

    /// Removes a stopped node's data directory (a retired replica).
    void wipe(int id) { std::filesystem::remove_all(_dir.path / std::to_string(id)); }

    /// The data endpoints `ids`, for SQS_DATA_ENDPOINTS.
    [[nodiscard]] auto urls(const std::vector<int>& ids) const -> std::string {
        std::string out;
        for (const int id : ids) {
            out += (out.empty() ? "" : ",") + api_url(id);
        }
        return out;
    }

    /// Tells every running data node where node `id` listens.
    void announce(int id) {
        const auto body = kythira::sqs::encode_peer(
            {std::to_string(id), "http://127.0.0.1:" + std::to_string(raft_port(id)), api_url(id)});
        for (const int n : _data) {
            const auto r = admin_call(api_port(n), kythira::sqs::k_admin_peer_path, body);
            BOOST_TEST_REQUIRE(r.result_int() == 200U, r.body());
        }
    }

    /// Evacuates `from` to `to` through node `via`; the steps taken.
    auto evacuate(int via, int from, int to) -> std::vector<std::string> {
        const auto r =
            admin_call(api_port(via), kythira::sqs::k_admin_evacuate_path,
                       kythira::sqs::encode_evacuate({std::to_string(from), std::to_string(to)}));
        BOOST_TEST_REQUIRE(r.result_int() == 200U, r.body());
        std::vector<std::string> steps;
        const auto answer = body_of(r);
        for (const auto& s : answer.at("steps").as_array()) {
            steps.emplace_back(s.as_string());
        }
        return steps;
    }

private:
    temp_dir _dir;
    std::uint16_t _raft;
    std::uint16_t _api;
    std::mutex _mutex;
    std::map<int, std::unique_ptr<node>> _nodes;
    /// The running nodes with the data role.
    std::set<int> _data;
};

auto queue_url(node& n, const std::string& name, const json::object& attributes = {})
    -> std::string {
    json::object in{{"QueueName", name}};
    if (!attributes.empty()) {
        in["Attributes"] = attributes;
    }
    const auto r = n.call_until_ok("CreateQueue", in);
    BOOST_TEST_REQUIRE(r.result_int() == 200U, r.body());
    return std::string(body_of(r).at("QueueUrl").as_string());
}

/// A standard and a FIFO producer and a consumer for each, through one
/// node, recording what was acknowledged and what came back.
class load {
public:
    load(node& n, std::string standard, std::string fifo)
        : _target(&n), _standard(std::move(standard)), _fifo(std::move(fifo)) {
        _threads.emplace_back([this] { produce_standard(); });
        _threads.emplace_back([this] { produce_fifo(); });
        _threads.emplace_back([this] { consume(_standard, _got_standard); });
        _threads.emplace_back([this] { consume(_fifo, _got_fifo); });
    }
    ~load() { stop(); }
    load(const load&) = delete;
    auto operator=(const load&) -> load& = delete;
    load(load&&) = delete;
    auto operator=(load&&) -> load& = delete;

    /// Stops producing, drains both queues, stops consuming.
    void stop() {
        if (_threads.empty()) {
            return;
        }
        _producing = false;
        _threads[0].join();
        _threads[1].join();
        const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        while (std::chrono::steady_clock::now() < end && !drained()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        _consuming = false;
        _threads[2].join();
        _threads[3].join();
        _threads.clear();
    }

    /// Requirement 12.3's message checks.
    void check() {
        const std::lock_guard lock(_mutex);
        BOOST_TEST_MESSAGE("standard: " << _acked_standard.size() << " acknowledged, "
                                        << _got_standard.size()
                                        << " received; FIFO: " << _acked_fifo << " acknowledged, "
                                        << _got_fifo.size() << " received");
        BOOST_TEST(_acked_standard.size() > 20U);
        BOOST_TEST(_acked_fifo > 20U);
        const std::set<std::string> got(_got_standard.begin(), _got_standard.end());
        std::size_t lost = 0;
        for (const auto& b : _acked_standard) {
            lost += got.contains(b) ? 0 : 1;
        }
        BOOST_TEST(lost == 0U);
        // FIFO: every acknowledged message once, in the order sent.
        BOOST_TEST_REQUIRE(_got_fifo.size() >= _acked_fifo);
        for (std::size_t i = 0; i < _got_fifo.size(); ++i) {
            BOOST_TEST_INFO("FIFO message " << i);
            BOOST_TEST(_got_fifo[i] == "f-" + std::to_string(i));
        }
    }

    /// Sends every later call to `n` (the clients' endpoint changing).
    void retarget(node& n) { _target.store(&n); }

    [[nodiscard]] auto progress() -> std::size_t {
        const std::lock_guard lock(_mutex);
        return _acked_standard.size() + _acked_fifo;
    }

private:
    /// Where the clients send: moved when a node is about to go.
    std::atomic<node*> _target;
    std::string _standard;
    std::string _fifo;
    std::atomic<bool> _producing{true};
    std::atomic<bool> _consuming{true};
    std::mutex _mutex;
    std::vector<std::string> _acked_standard;
    std::size_t _acked_fifo = 0;
    std::vector<std::string> _got_standard;
    std::vector<std::string> _got_fifo;
    std::atomic<std::size_t> _sent_fifo{0};
    std::vector<std::thread> _threads;

    /// One call to the current target; a connection the target drops (it
    /// is stopping) is an ordinary failure the client retries.
    auto call(std::string_view op, const json::object& in) -> http::response<http::string_body> {
        try {
            return _target.load()->call(op, in);
        } catch (const std::exception&) {
            return http::response<http::string_body>{http::status::service_unavailable, 11};
        }
    }

    void produce_standard() {
        for (std::size_t i = 0; _producing; ++i) {
            const auto body = "s-" + std::to_string(i);
            const auto r = call("SendMessage", {{"QueueUrl", _standard}, {"MessageBody", body}});
            if (r.result_int() == 200U) {
                const std::lock_guard lock(_mutex);
                _acked_standard.push_back(body);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    /// Each message is retried with its deduplication id until it is
    /// acknowledged, so the order sent is the order acknowledged.
    void produce_fifo() {
        for (std::size_t i = 0; _producing; ++i) {
            const auto body = "f-" + std::to_string(i);
            for (;;) {
                const auto r = call("SendMessage", {{"QueueUrl", _fifo},
                                                    {"MessageBody", body},
                                                    {"MessageGroupId", "g"},
                                                    {"MessageDeduplicationId", body}});
                if (r.result_int() == 200U) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            {
                const std::lock_guard lock(_mutex);
                ++_acked_fifo;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    void consume(const std::string& url, std::vector<std::string>& got) {
        while (_consuming) {
            const auto r =
                call("ReceiveMessage",
                     {{"QueueUrl", url}, {"MaxNumberOfMessages", 10}, {"WaitTimeSeconds", 1}});
            if (r.result_int() != 200U) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            const auto o = body_of(r);
            const auto* ms = o.if_contains("Messages");
            if (ms == nullptr) {
                continue;
            }
            for (const auto& m : ms->as_array()) {
                {
                    const std::lock_guard lock(_mutex);
                    got.emplace_back(m.at("Body").as_string());
                }
                // A handle stays good across every step, so a delete that
                // meets an election is simply retried.
                const json::object del{{"QueueUrl", url}, {"ReceiptHandle", m.at("ReceiptHandle")}};
                const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(20);
                while (call("DeleteMessage", del).result_int() != 200U &&
                       std::chrono::steady_clock::now() < end) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
            }
        }
    }

    auto drained() -> bool {
        const std::lock_guard lock(_mutex);
        if (_got_fifo.size() < _acked_fifo) {
            return false;
        }
        const std::set<std::string> got(_got_standard.begin(), _got_standard.end());
        return std::all_of(_acked_standard.begin(), _acked_standard.end(),
                           [&got](const std::string& b) { return got.contains(b); });
    }
};

/// A message received before a move: its handle and visibility deadline
/// must survive the move.
struct held_message {
    std::string _url;
    std::string _handle;
    std::chrono::steady_clock::time_point _visible_at;
};

auto hold(node& n, const std::string& url, const std::string& body, int visibility_seconds)
    -> held_message {
    BOOST_TEST_REQUIRE(
        n.call_until_ok("SendMessage", {{"QueueUrl", url}, {"MessageBody", body}}).result_int() ==
        200U);
    const auto r = n.call_until_ok("ReceiveMessage",
                                   {{"QueueUrl", url}, {"VisibilityTimeout", visibility_seconds}});
    const auto o = body_of(r);
    BOOST_TEST_REQUIRE(o.contains("Messages"), r.body());
    const auto& m = o.at("Messages").as_array().at(0);
    BOOST_TEST_REQUIRE(m.at("Body").as_string() == body);
    return {url, std::string(m.at("ReceiptHandle").as_string()),
            std::chrono::steady_clock::now() + std::chrono::seconds(visibility_seconds)};
}

/// Messages visible in `url` now (a receive with no wait and a zero
/// visibility timeout, so nothing is hidden by looking).
auto visible(node& n, const std::string& url) -> std::size_t {
    const auto r =
        n.call_until_ok("ReceiveMessage",
                        {{"QueueUrl", url}, {"MaxNumberOfMessages", 10}, {"VisibilityTimeout", 0}});
    const auto o = body_of(r);
    const auto* ms = o.if_contains("Messages");
    return ms == nullptr ? 0 : ms->as_array().size();
}

/// The receipt-handle and visibility checks of Requirement 12.3.
void check_held(node& n, const held_message& deleted, const held_message& timed) {
    const auto r = n.call_until_ok(
        "DeleteMessage", {{"QueueUrl", deleted._url}, {"ReceiptHandle", deleted._handle}});
    BOOST_TEST(r.result_int() == 200U, r.body());
    BOOST_TEST(visible(n, deleted._url) == 0U);
    // Not visible before its deadline (a second of margin for the clock
    // the deadline was stamped with), visible within a few seconds after.
    if (std::chrono::steady_clock::now() + std::chrono::seconds(1) < timed._visible_at) {
        BOOST_TEST(visible(n, timed._url) == 0U);
    }
    std::this_thread::sleep_until(timed._visible_at + std::chrono::seconds(1));
    const auto end = timed._visible_at + std::chrono::seconds(5);
    std::size_t seen = 0;
    while (seen == 0 && std::chrono::steady_clock::now() < end) {
        seen = visible(n, timed._url);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    BOOST_TEST(seen == 1U);
}

/// Waits until the load has made `more` further acknowledgements.
void let_run(load& l, std::size_t more) {
    const auto want = l.progress() + more;
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (l.progress() < want && std::chrono::steady_clock::now() < end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    BOOST_TEST(l.progress() >= want);
}

/// Moves the clients to `to`, then stops `from` with a long poll parked on
/// it, which must be answered, empty, not dropped. A front end ends it at
/// once (Requirement 12.1's drain); a gateway without one waits for the
/// front end's answer, so its poll asks for less.
void move_clients_and_stop(cluster& c, load& l, int from, int to, const std::string& url,
                           int wait_seconds = 20) {
    auto parked = std::async(std::launch::async, [&c, from, url, wait_seconds] {
        return c.at(from).call("ReceiveMessage",
                               {{"QueueUrl", url}, {"WaitTimeSeconds", wait_seconds}});
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    l.retarget(c.at(to));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const auto stopping = std::chrono::steady_clock::now();
    c.stop(from);
    const auto r = parked.get();
    BOOST_TEST(r.result_int() == 200U, r.body());
    BOOST_TEST(!body_of(r).contains("Messages"), r.body());
    // Well before the 20 s the poll asked for.
    BOOST_TEST((std::chrono::steady_clock::now() - stopping < std::chrono::seconds(10)));
}

}  // namespace

BOOST_AUTO_TEST_SUITE(sqs_migration)

// The data role: every replica of three co-located nodes evacuated to
// three data-only nodes, then back, under load through a co-located node
// that keeps serving the API throughout (from its replica, then from the
// data nodes, then from its replica again).
BOOST_AUTO_TEST_CASE(the_data_role_moves_to_data_nodes_and_back) {
    cluster c;
    c.start({1, 2, 3}, false);
    auto& api = c.at(2);
    const auto standard = queue_url(api, "std");
    const auto fifo = queue_url(api, "q.fifo", {{"FifoQueue", "true"}});
    const auto deleted_q = queue_url(api, "held");
    const auto timed_q = queue_url(api, "timed");
    c.start({4, 5, 6}, true, "data");
    for (const int id : {4, 5, 6}) {
        c.announce(id);
    }

    load l(api, standard, fifo);
    let_run(l, 20);
    const auto deleted = hold(api, deleted_q, "held across", 600);
    const auto timed = hold(api, timed_q, "timed across", 12);
    for (const auto& [from, to] : std::vector<std::pair<int, int>>{{1, 4}, {2, 5}, {3, 6}}) {
        const auto steps = c.evacuate(2, from, to);
        BOOST_TEST_MESSAGE("evacuated " << from << " to " << to << " in " << steps.size()
                                        << " steps");
        BOOST_TEST(steps.size() >= 3U);
        let_run(l, 10);
    }
    // Only the data nodes hold replicas now; the co-located nodes still
    // serve every call.
    check_held(api, deleted, timed);
    const auto deleted2 = hold(api, queue_url(api, "held2"), "held back", 600);
    const auto timed2 = hold(api, queue_url(api, "timed2"), "timed back", 12);
    for (const auto& [from, to] : std::vector<std::pair<int, int>>{{4, 1}, {5, 2}, {6, 3}}) {
        c.evacuate(5, from, to);
        let_run(l, 10);
    }
    check_held(api, deleted2, timed2);
    l.stop();
    l.check();
}

// An evacuation stopped midway (the new node added and promoted, the old
// one still voting) and reversed: the reversal is the same call from the
// far end, and the group ends where it began.
BOOST_AUTO_TEST_CASE(an_evacuation_reverses_from_midway) {
    cluster c;
    c.start({1, 2, 3}, false);
    auto& api = c.at(1);
    const auto standard = queue_url(api, "std");
    const auto fifo = queue_url(api, "q.fifo", {{"FifoQueue", "true"}});
    c.start({4}, true, "data");
    c.announce(4);
    load l(api, standard, fifo);
    let_run(l, 20);
    const auto deleted = hold(api, queue_url(api, "held"), "held", 600);
    const auto timed = hold(api, queue_url(api, "timed"), "timed", 12);

    // Single steps on whichever node leads, until two changes are made.
    const auto step_on = [&c](int id) {
        const auto r = admin_call(c.api_port(id), kythira::sqs::k_admin_step_path,
                                  kythira::sqs::encode_evacuate({"3", "4"}));
        BOOST_TEST_REQUIRE(r.result_int() == 200U, r.body());
        return kythira::sqs::decode_step(r.body()).value_or(kythira::sqs::step_result{});
    };
    std::vector<std::string> made;
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (made.size() < 2 && std::chrono::steady_clock::now() < end) {
        for (const int id : {1, 2, 3}) {
            const auto r = step_on(id);
            if (r._kind == kythira::sqs::step_kind::progressed) {
                made.push_back(r._what);
            }
            if (r._kind != kythira::sqs::step_kind::not_leader) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    BOOST_TEST_REQUIRE(made.size() == 2U);
    BOOST_TEST(made[0].find("learner") != std::string::npos);
    BOOST_TEST(made[1].find("promoting") != std::string::npos);
    let_run(l, 10);

    const auto back = c.evacuate(2, 4, 3);
    BOOST_TEST(!back.empty());
    let_run(l, 10);
    // 4 holds nothing now: a second reversal has nothing to do.
    BOOST_TEST(c.evacuate(1, 4, 3).empty());
    check_held(api, deleted, timed);
    l.stop();
    l.check();
}

// A data node that restarts after the group has moved on from the members
// its KYTHIRA_NODE_PEERS names still reaches the ones announced to it
// since: `peer` is kept in its data directory.
BOOST_AUTO_TEST_CASE(announced_peers_survive_a_restart) {
    cluster c;
    c.start({1, 2, 3}, false);
    // Each joiner's configuration names only the founders and itself; the
    // others reach it by announcement alone.
    const auto only_founders_and = [&c](int id) {
        std::string peers;
        std::string endpoints;
        for (const int i : {1, 2, 3, id}) {
            const auto sep = std::string(peers.empty() ? "" : ",") + std::to_string(i);
            peers += sep + "=127.0.0.1:" + std::to_string(c.raft_port(i));
            endpoints += sep + "=" + c.api_url(i);
        }
        return env_map{{"KYTHIRA_NODE_PEERS", peers},
                       {"SQS_PEER_ENDPOINTS", endpoints},
                       {"SQS_EVACUATE_TIMEOUT_MS", "20000"}};
    };
    for (const int id : {4, 5, 6}) {
        c.start({id}, true, "data", only_founders_and(id));
    }
    for (const int id : {4, 5, 6}) {
        c.announce(id);
    }
    for (const auto& [from, to] : std::vector<std::pair<int, int>>{{1, 4}, {2, 5}, {3, 6}}) {
        c.evacuate(5, from, to);
    }
    for (const int id : {1, 2, 3}) {
        c.stop(id);
    }
    // Node 4 comes back knowing, from its configuration, only nodes that
    // have gone. An evacuation call through it must find the leader among
    // 5 and 6 (4 itself does not lead after a restart while they run).
    c.stop(4);
    c.start({4}, true, "data", only_founders_and(4));
    BOOST_TEST(c.evacuate(4, 3, 6).empty());
}

// The front-end role split off onto its own node and folded back: clients
// move to a front end without the data role, and back to a co-located
// node when it stops with a long poll parked on it.
BOOST_AUTO_TEST_CASE(the_front_end_role_splits_off_and_folds_back) {
    cluster c;
    c.start({1, 2, 3}, false);
    auto& home = c.at(1);
    const auto standard = queue_url(home, "std");
    const auto fifo = queue_url(home, "q.fifo", {{"FifoQueue", "true"}});
    const auto idle = queue_url(home, "idle");
    const auto deleted = hold(home, queue_url(home, "held"), "held", 600);
    const auto timed = hold(home, queue_url(home, "timed"), "timed", 15);
    load l(home, standard, fifo);
    let_run(l, 20);

    c.start({7}, false, "gateway,front_end", {{"SQS_DATA_ENDPOINTS", c.urls({1, 2, 3})}});
    l.retarget(c.at(7));
    let_run(l, 30);
    // Back: the split-off front end drains with a poll parked on it.
    move_clients_and_stop(c, l, 7, 1, idle);
    let_run(l, 20);
    // And off again, then the co-located node 2 takes the clients while
    // node 7 goes for good.
    c.start({7}, false, "gateway,front_end", {{"SQS_DATA_ENDPOINTS", c.urls({1, 2, 3})}});
    l.retarget(c.at(7));
    let_run(l, 20);
    move_clients_and_stop(c, l, 7, 2, idle);
    let_run(l, 10);
    check_held(c.at(2), deleted, timed);
    l.stop();
    l.check();
}

// The gateway role split off and folded back: clients move to a gateway
// that hands their requests to the co-located nodes' front ends, then
// back when it stops.
BOOST_AUTO_TEST_CASE(the_gateway_role_splits_off_and_folds_back) {
    cluster c;
    c.start({1, 2, 3}, false);
    auto& home = c.at(1);
    const auto standard = queue_url(home, "std");
    const auto fifo = queue_url(home, "q.fifo", {{"FifoQueue", "true"}});
    const auto idle = queue_url(home, "idle");
    const auto deleted = hold(home, queue_url(home, "held"), "held", 600);
    const auto timed = hold(home, queue_url(home, "timed"), "timed", 15);
    load l(home, standard, fifo);
    let_run(l, 20);

    for (int round = 0; round < 2; ++round) {
        c.start({8}, false, "gateway", {{"SQS_FRONT_END_ENDPOINTS", c.urls({1, 2, 3})}});
        l.retarget(c.at(8));
        let_run(l, 30);
        move_clients_and_stop(c, l, 8, 1, idle, 4);
        let_run(l, 20);
    }
    check_held(home, deleted, timed);
    l.stop();
    l.check();
}

// The whole path: three co-located nodes to a gateway, a front end and
// three data nodes, stopped and reversed midway, then all the way and all
// the way back. Node 3 is restarted without the data role once its replica
// has gone, and rejoins with it on the way back.
BOOST_AUTO_TEST_CASE(the_whole_path_to_split_and_back_reversing_midway) {
    cluster c;
    c.start({1, 2, 3}, false);
    auto& home = c.at(1);
    const auto standard = queue_url(home, "std");
    const auto fifo = queue_url(home, "q.fifo", {{"FifoQueue", "true"}});
    const auto idle = queue_url(home, "idle");
    const auto deleted = hold(home, queue_url(home, "held"), "held", 600);
    const auto timed = hold(home, queue_url(home, "timed"), "timed", 25);
    load l(home, standard, fifo);
    let_run(l, 20);

    // Data nodes, a front end over every data node, a gateway over it.
    c.start({4, 5, 6}, true, "data");
    for (const int id : {4, 5, 6}) {
        c.announce(id);
    }
    const auto data = c.urls({1, 2, 3, 4, 5, 6});
    c.start({7}, false, "front_end", {{"SQS_DATA_ENDPOINTS", data}});
    c.start({8}, false, "gateway", {{"SQS_FRONT_END_ENDPOINTS", c.urls({7})}});
    l.retarget(c.at(8));
    let_run(l, 20);

    // Midway: two replicas moved, then the operator reverses.
    c.evacuate(1, 1, 4);
    c.evacuate(1, 2, 5);
    let_run(l, 10);
    c.evacuate(1, 5, 2);
    c.evacuate(1, 4, 1);
    let_run(l, 10);

    // All the way: every replica on the data nodes, node 3 restarted
    // without the data role (its retired replica removed first).
    for (const auto& [from, to] : std::vector<std::pair<int, int>>{{1, 4}, {2, 5}, {3, 6}}) {
        c.evacuate(1, from, to);
        let_run(l, 10);
    }
    c.stop(3);
    c.wipe(3);
    c.start({3}, false, "gateway,front_end", {{"SQS_DATA_ENDPOINTS", c.urls({4, 5, 6})}});
    let_run(l, 10);

    // All the way back: node 3 rejoins with every role, the replicas
    // return, the clients return to node 1, and the split nodes go.
    c.stop(3);
    c.wipe(3);
    c.start({3}, true);
    c.announce(3);
    for (const auto& [from, to] : std::vector<std::pair<int, int>>{{4, 1}, {5, 2}, {6, 3}}) {
        c.evacuate(1, from, to);
        let_run(l, 10);
    }
    move_clients_and_stop(c, l, 8, 1, idle, 4);
    c.stop(7);
    for (const int id : {4, 5, 6}) {
        c.stop(id);
    }
    let_run(l, 20);
    check_held(home, deleted, timed);
    l.stop();
    l.check();
}

BOOST_AUTO_TEST_SUITE_END()
