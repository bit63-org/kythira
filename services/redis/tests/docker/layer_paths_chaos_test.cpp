// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE layer_paths_chaos_test
#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include "os_faults.hpp"

#include <kythira/redis/resp_protocol.hpp>
#include <test_ports.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

// The full layer migration path in containers
// (.kiro/specs/redis-general-data-types/ task 20, Requirement 24.3).
// services/redis/docker/layer-paths-compose.yml has six redis_gateway_node
// slots. The test walks one cluster from co-located (lp-1..lp-3 run every
// layer) to a three-way split (gateway on lp-1, front ends on lp-2 and
// lp-3, data on lp-4..lp-6) and back, under a write workload, and kills one
// node of each layer on the way:
//
//   * a **data node** (lp-2 while it holds replicas) is killed for good and
//     its replicas are evacuated off it while it is down;
//   * the **gateway** (lp-1 once it is the only one) is killed and started
//     again;
//   * a **front end** (lp-2 once it is one) is killed and started again.
//
// After each step the workload must have moved on, and every write it made
// so far must hold: an acknowledged SET, SETEX, MSET or MULTI reads back
// whole, an unacknowledged one reads back whole or not at all, and every
// deadline is intact.
//
// The in-process test (services/redis/tests/redis_layer_paths_test.cpp)
// walks the same path with every intermediate layout; this one is the real
// daemons, the real network and real process deaths. The workload covers
// the commands that have shipped; tasks 3, 6, 7, 9 and 12 add theirs.

using namespace std::chrono_literals;
namespace os = docker_chaos::os;

namespace {

constexpr int k_slots = 6;
constexpr long k_ttl = 3600;

std::string compose_file() {
    const char* env = std::getenv("KYTHIRA_LAYER_PATHS_COMPOSE_FILE");
    if ((env != nullptr) && (*env != 0)) {
        return env;
    }
    return "services/redis/docker/layer-paths-compose.yml";
}

std::vector<std::string> compose_cmd(std::initializer_list<std::string> args) {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", compose_file()});
    cmd.insert(cmd.end(), args);
    return cmd;
}

std::string service(int id) {
    return "lp-" + std::to_string(id);
}
std::string container(int id) {
    return "layer-paths-" + std::to_string(id);
}
std::string gateway_of(int id) {
    return service(id) + ":6379";
}

/// The loopback ports the slots publish, picked once per run.
std::array<std::uint16_t, k_slots + 1> g_ports{};

std::uint16_t port(int id) {
    return g_ports.at(static_cast<std::size_t>(id));
}

int dial(std::uint16_t p, std::chrono::seconds wait) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    timeval tv{.tv_sec = static_cast<time_t>(wait.count()), .tv_usec = 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(p);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

class resp_client {
public:
    explicit resp_client(std::uint16_t p, std::chrono::seconds wait = std::chrono::seconds{10})
        : _fd(dial(p, wait)) {
        if (_fd < 0) {
            throw std::runtime_error("connect to 127.0.0.1:" + std::to_string(p) + " refused");
        }
        if (call({"AUTH", "ops", "ops-secret"}) != "+OK\r\n") {
            throw std::runtime_error("AUTH refused");
        }
    }
    ~resp_client() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
    resp_client(const resp_client&) = delete;
    resp_client& operator=(const resp_client&) = delete;
    resp_client(resp_client&&) = delete;
    resp_client& operator=(resp_client&&) = delete;

    std::string call(const std::vector<std::string>& argv) {
        std::string out = "*" + std::to_string(argv.size()) + "\r\n";
        for (const auto& a : argv) {
            out += "$" + std::to_string(a.size()) + "\r\n" + a + "\r\n";
        }
        for (std::size_t sent = 0; sent < out.size();) {
            auto n = ::send(_fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
            if (n <= 0) {
                throw std::runtime_error("send failed");
            }
            sent += static_cast<std::size_t>(n);
        }
        std::size_t len = 0;
        while ((len = kythira::resp_reply_length(_buffer)) == 0) {
            std::array<char, 65536> chunk{};
            auto n = ::recv(_fd, chunk.data(), chunk.size(), 0);
            if (n <= 0) {
                throw std::runtime_error("connection closed or timed out waiting for a reply");
            }
            _buffer.append(chunk.data(), static_cast<std::size_t>(n));
        }
        auto reply = _buffer.substr(0, len);
        _buffer.erase(0, len);
        return reply;
    }

private:
    int _fd{-1};
    std::string _buffer;
};

std::string bulk(const std::string& v) {
    return "$" + std::to_string(v.size()) + "\r\n" + v + "\r\n";
}

std::string first_line(const std::string& r) {
    return r.substr(0, r.find('\r'));
}

/// The nodes clients may connect to: those running the gateway layer.
class entries {
public:
    void set(std::vector<int> ids) {
        std::lock_guard lock(_mu);
        _ids = std::move(ids);
    }
    std::vector<int> get() {
        std::lock_guard lock(_mu);
        return _ids;
    }

private:
    std::mutex _mu;
    std::vector<int> _ids;
};

// ── the workload and its ledger (the in-process test's, over the network) ──

struct ledger {
    enum class kind : std::uint8_t {
        set,
        mset,
        multi,
        setex
    };
    struct op {
        kind _kind;
        bool _acked = false;
    };
    std::mutex _mu;
    std::map<std::uint64_t, op> _ops;
    std::atomic<std::uint64_t> _next{0};
    std::atomic<std::uint64_t> _acked{0};
    std::atomic<std::uint64_t> _unacked{0};
    std::atomic<std::uint64_t> _reconnects{0};

    void record(std::uint64_t seq, kind k, bool acked) {
        std::lock_guard lock(_mu);
        _ops[seq] = op{k, acked};
        (acked ? _acked : _unacked).fetch_add(1);
    }
};

// "a/..." is the first shard, "z/..." the second (KYTHIRA_SHARD_CUTS=m).
std::string side(std::uint64_t seq) {
    return seq % 2 == 0 ? "a/" : "z/";
}
std::string set_key(std::uint64_t seq) {
    return side(seq) + "s/" + std::to_string(seq);
}
std::string setex_key(std::uint64_t seq) {
    return side(seq) + "d/" + std::to_string(seq);
}
std::string value(std::uint64_t seq) {
    return "v" + std::to_string(seq);
}
std::array<std::string, 2> mset_keys(std::uint64_t seq) {
    return {"a/p/" + std::to_string(seq), "z/p/" + std::to_string(seq)};
}
std::array<std::string, 3> multi_keys(std::uint64_t seq) {
    return {"a/t/" + std::to_string(seq), "z/t/" + std::to_string(seq),
            "z/t/ttl/" + std::to_string(seq)};
}

class workload {
public:
    workload(entries& e, ledger& l, std::size_t workers) : _entries(e), _ledger(l) {
        for (std::size_t w = 0; w < workers; ++w) {
            _threads.emplace_back([this, w] { run(w); });
        }
    }
    ~workload() { stop(); }
    workload(const workload&) = delete;
    workload& operator=(const workload&) = delete;
    workload(workload&&) = delete;
    workload& operator=(workload&&) = delete;

    void stop() {
        _stop = true;
        for (auto& t : _threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

private:
    void run(std::size_t w) {
        std::size_t turn = w;
        while (!_stop.load()) {
            const auto ids = _entries.get();
            if (ids.empty()) {
                std::this_thread::sleep_for(100ms);
                continue;
            }
            std::unique_ptr<resp_client> client;
            try {
                client = std::make_unique<resp_client>(port(ids[turn++ % ids.size()]));
            } catch (const std::exception&) {
                std::this_thread::sleep_for(200ms);
                continue;
            }
            _ledger._reconnects.fetch_add(1);
            // A bounded run per connection, so every entry gets traffic as
            // the layout changes.
            for (int i = 0; i < 200 && !_stop.load(); ++i) {
                if (!one(*client, _ledger._next.fetch_add(1))) {
                    std::this_thread::sleep_for(100ms);
                    break;
                }
            }
        }
    }

    bool one(resp_client& c, std::uint64_t seq) {
        const auto k = static_cast<ledger::kind>(seq % 4);
        try {
            switch (k) {
                case ledger::kind::set:
                    _ledger.record(seq, k, c.call({"SET", set_key(seq), value(seq)}) == "+OK\r\n");
                    break;
                case ledger::kind::setex:
                    _ledger.record(seq, k,
                                   c.call({"SETEX", setex_key(seq), std::to_string(k_ttl),
                                           value(seq)}) == "+OK\r\n");
                    break;
                case ledger::kind::mset: {
                    const auto keys = mset_keys(seq);
                    _ledger.record(
                        seq, k,
                        c.call({"MSET", keys[0], value(seq), keys[1], value(seq)}) == "+OK\r\n");
                    break;
                }
                case ledger::kind::multi: {
                    const auto keys = multi_keys(seq);
                    if (c.call({"MULTI"}) != "+OK\r\n") {
                        _ledger.record(seq, k, false);
                        return false;
                    }
                    (void)c.call({"SET", keys[0], value(seq)});
                    (void)c.call({"SET", keys[1], value(seq)});
                    (void)c.call({"SETEX", keys[2], std::to_string(k_ttl), value(seq)});
                    const auto r = c.call({"EXEC"});
                    _ledger.record(seq, k, r == "*3\r\n+OK\r\n+OK\r\n+OK\r\n");
                    if (r.front() == '-') {
                        return false;  // the connection's MULTI state is unknown
                    }
                    break;
                }
            }
        } catch (const std::exception&) {
            _ledger.record(seq, k, false);
            return false;
        }
        return true;
    }

    entries& _entries;
    ledger& _ledger;
    std::vector<std::thread> _threads;
    std::atomic<bool> _stop{false};
};

constexpr const char* k_nil = "(nil)";

/// Reads back what the workload did, retrying what a moving layout may
/// answer for a moment. Its connections read at read_committed_wait where
/// the build has it, so a transaction whose coordinator died mid-commit is
/// resolved by the read instead of skipped (multi-raft-transactions 5.3).
class checker {
public:
    explicit checker(entries& e) : _entries(e) {}

    std::vector<std::string> mget(const std::vector<std::string>& keys) {
        std::vector<std::string> argv{"MGET"};
        argv.insert(argv.end(), keys.begin(), keys.end());
        const auto r = call(argv);
        std::vector<std::string> out;
        if (r.empty() || r.front() != '*') {
            out.push_back(first_line(r));
            return out;
        }
        std::size_t pos = r.find("\r\n") + 2;
        while (pos < r.size()) {
            const auto eol = r.find("\r\n", pos);
            const auto head = r.substr(pos, eol - pos);
            pos = eol + 2;
            if (head == "$-1" || head == "_") {
                out.push_back(k_nil);
                continue;
            }
            const auto len = std::stoul(head.substr(1));
            out.push_back(r.substr(pos, len));
            pos += len + 2;
        }
        return out;
    }

    long ttl(const std::string& key) {
        const auto r = call({"TTL", key});
        return r.front() == ':' ? std::stol(r.substr(1)) : -100;
    }

    /// Every check over everything the workload did so far; the failures,
    /// one line each.
    std::vector<std::string> verify(ledger& l) {
        std::map<std::uint64_t, ledger::op> ops;
        {
            std::lock_guard lock(l._mu);
            ops = l._ops;
        }
        std::vector<std::string> bad;
        // Single keys in batches of one MGET each.
        std::vector<std::pair<std::uint64_t, ledger::op>> singles;
        auto flush = [&] {
            if (singles.empty()) {
                return;
            }
            std::vector<std::string> keys;
            for (const auto& [seq, op] : singles) {
                keys.push_back(op._kind == ledger::kind::set ? set_key(seq) : setex_key(seq));
            }
            const auto got = mget(keys);
            if (got.size() != keys.size()) {
                bad.push_back("MGET of " + std::to_string(keys.size()) +
                              " keys: " + (got.empty() ? std::string{} : got.front()));
                singles.clear();
                return;
            }
            for (std::size_t i = 0; i < keys.size(); ++i) {
                const auto& [seq, op] = singles[i];
                const auto v = value(seq);
                if (op._acked && got[i] != v) {
                    bad.push_back("lost " + keys[i] + ": " + got[i]);
                } else if (!op._acked && got[i] != v && got[i] != k_nil) {
                    bad.push_back("wrong " + keys[i] + ": " + got[i]);
                }
                // Deadlines on a sample, one TTL each.
                if (op._kind == ledger::kind::setex && got[i] == v && seq % 16 == 3) {
                    const auto t = ttl(keys[i]);
                    if (t <= 0 || t > k_ttl) {
                        bad.push_back("deadline of " + keys[i] + ": " + std::to_string(t));
                    }
                }
            }
            singles.clear();
        };
        for (const auto& [seq, op] : ops) {
            if (bad.size() > 10) {
                break;
            }
            const auto v = value(seq);
            switch (op._kind) {
                case ledger::kind::set:
                case ledger::kind::setex:
                    singles.emplace_back(seq, op);
                    // The gateway takes at most 64 array elements a command
                    // (resp_limits), MGET's name included.
                    if (singles.size() >= 48) {
                        flush();
                    }
                    break;
                case ledger::kind::mset: {
                    const auto keys = mset_keys(seq);
                    const auto got = mget({keys[0], keys[1]});
                    const bool both = got == std::vector<std::string>{v, v};
                    const bool neither = got == std::vector<std::string>{k_nil, k_nil};
                    if (op._acked ? !both : !(both || neither)) {
                        bad.push_back("MSET " + std::to_string(seq) + " acked " +
                                      std::to_string(op._acked) + ": " + join(got));
                    }
                    break;
                }
                case ledger::kind::multi: {
                    const auto keys = multi_keys(seq);
                    const auto got = mget({keys[0], keys[1], keys[2]});
                    const bool all = got == std::vector<std::string>{v, v, v};
                    const bool none = got == std::vector<std::string>{k_nil, k_nil, k_nil};
                    if (op._acked ? !all : !(all || none)) {
                        bad.push_back("MULTI " + std::to_string(seq) + " acked " +
                                      std::to_string(op._acked) + ": " + join(got));
                    }
                    if (all && seq % 16 == 3) {
                        const auto t = ttl(keys[2]);
                        if (t <= 0 || t > k_ttl) {
                            bad.push_back("deadline of " + keys[2] + ": " + std::to_string(t));
                        }
                    }
                    break;
                }
            }
        }
        flush();
        return bad;
    }

private:
    static std::string join(const std::vector<std::string>& v) {
        std::string out;
        for (const auto& e : v) {
            out += (out.empty() ? "" : " / ") + e;
        }
        return out;
    }

    std::string call(const std::vector<std::string>& argv) {
        std::string r;
        for (int attempt = 0; attempt < 60; ++attempt) {
            try {
                if (!_client) {
                    const auto ids = _entries.get();
                    if (ids.empty()) {
                        throw std::runtime_error("no node serves clients");
                    }
                    _client = std::make_unique<resp_client>(
                        port(ids[static_cast<std::size_t>(attempt) % ids.size()]));
                    // Builds without it answer an error; their default
                    // isolation is what the reads get then.
                    (void)_client->call({"KYTHIRA.ISOLATION", "read_committed_wait"});
                }
                r = _client->call(argv);
                const bool retry = r.rfind("-TRYAGAIN", 0) == 0 || r.rfind("-LOADING", 0) == 0 ||
                                   (r.front() == '-' && (r.find("retry") != std::string::npos ||
                                                         r.find("timed out") != std::string::npos ||
                                                         r.find("leader") != std::string::npos));
                if (!retry) {
                    return r;
                }
            } catch (const std::exception& e) {
                _client.reset();
                r = std::string("-ERR ") + e.what();
            }
            std::this_thread::sleep_for(250ms);
        }
        return r;
    }

    entries& _entries;
    std::unique_ptr<resp_client> _client;
};

// ── the cluster ──

std::string everyone_peers() {
    std::string out;
    for (int id = 1; id <= k_slots; ++id) {
        out += (out.empty() ? "" : ",") + std::to_string(id) + "=http://" + service(id) + ":7000";
    }
    return out;
}

std::string list_gateways(std::initializer_list<int> ids) {
    std::string out;
    for (const auto id : ids) {
        out += (out.empty() ? "" : ",") + gateway_of(id);
    }
    return out;
}

/// What one of lp-1..lp-3 runs: the LPn_* variables the compose file reads.
struct layout {
    std::string _roles = "gateway,front_end,data";
    bool _join = false;
    std::string _data_nodes;
    std::string _front_ends;
};

void export_layout(int id, const layout& l) {
    const auto prefix = "LP" + std::to_string(id) + "_";
    ::setenv((prefix + "ROLES").c_str(), l._roles.c_str(), 1);
    ::setenv((prefix + "JOIN").c_str(), l._join ? "true" : "false", 1);
    ::setenv((prefix + "DATA_NODES").c_str(), l._data_nodes.c_str(), 1);
    ::setenv((prefix + "FRONT_ENDS").c_str(), l._front_ends.c_str(), 1);
    // A joining node founds nothing, so it only needs every address; a
    // founder founds over lp-1..lp-3.
    if (l._join) {
        ::setenv((prefix + "PEERS").c_str(), everyone_peers().c_str(), 1);
    } else {
        ::unsetenv((prefix + "PEERS").c_str());
    }
}

/// Each node's log lines about layers, evacuation, membership changes and
/// failures (the Raft info lines would bury them), the last `lines` each.
std::string node_logs(std::size_t lines = 150) {
    static const std::array<const char*, 9> k_marks{"evacuat", "learner", "leadership",
                                                    "redis:",  "ERROR",   "WARN",
                                                    "joining", "drain",   "membership"};
    std::string all;
    for (int id = 1; id <= k_slots; ++id) {
        const auto r = os::real_exec(os::container_logs_all_cmd(container(id)));
        std::vector<std::string> kept;
        std::size_t start = 0;
        const auto& text = r.out;
        while (start < text.size()) {
            const auto eol = std::min(text.find('\n', start), text.size());
            const auto line = text.substr(start, eol - start);
            if (std::any_of(k_marks.begin(), k_marks.end(),
                            [&](const char* m) { return line.find(m) != std::string::npos; })) {
                kept.push_back(line);
            }
            start = eol + 1;
        }
        if (kept.empty()) {
            continue;
        }
        all += "── " + container(id) + " ──\n";
        for (auto i = kept.size() > lines ? kept.size() - lines : 0; i < kept.size(); ++i) {
            all += kept[i] + "\n";
        }
    }
    return all;
}

/// True once `pred` holds, polling until `timeout`.
bool await(const std::function<bool()>& pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(500ms);
    }
    return pred();
}

/// One call on a fresh connection to `id`, or the error as a reply.
/// `wait` bounds each read; a reply that needs other nodes first (START
/// asks every data node) takes a longer one.
std::string on(int id, const std::vector<std::string>& argv,
               std::chrono::seconds wait = std::chrono::seconds{10}) {
    try {
        resp_client c(port(id), wait);
        return c.call(argv);
    } catch (const std::exception& e) {
        return std::string("-ERR ") + e.what();
    }
}

/// A gateway answers, and a write through it commits on both shards.
bool serves(int id) {
    const auto r = on(id, {"MSET", "a/ready", "1", "z/ready", "1"});
    return r == "+OK\r\n";
}

void recreate(int id, const layout& l) {
    export_layout(id, l);
    os::checked_exec(os::real_exec,
                     compose_cmd({"up", "-d", "--force-recreate", "--no-deps", service(id)}));
}

/// Starts a joining data node and waits until it answers, so the START
/// that targets it reaches it: a data node that misses the job and later
/// leads a group holds STATUS short of done until START runs again.
void start_joiner(int id) {
    os::checked_exec(os::real_exec, compose_cmd({"up", "-d", "--no-deps", service(id)}));
    BOOST_REQUIRE_MESSAGE(await([id] { return on(id, {"PING"}) == "+PONG\r\n"; }, 60s),
                          service(id) << " does not answer: " << first_line(on(id, {"PING"})));
}

void remove_node(int id) {
    os::try_exec(os::real_exec, compose_cmd({"rm", "-s", "-f", service(id)}));
}

/// A fresh co-located cluster on lp-1..lp-3.
struct LayerPathsFixture {
    LayerPathsFixture() {
        for (int id = 1; id <= k_slots; ++id) {
            if (g_ports.at(static_cast<std::size_t>(id)) == 0) {
                g_ports.at(static_cast<std::size_t>(id)) = kythira::testing::free_port();
            }
            ::setenv(("KYTHIRA_LP_PORT_" + std::to_string(id)).c_str(),
                     std::to_string(port(id)).c_str(), 1);
        }
        for (int id = 1; id <= 3; ++id) {
            export_layout(id, layout{});
        }
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        os::checked_exec(os::real_exec,
                         compose_cmd({"up", "-d", service(1), service(2), service(3)}));
        if (!await([] { return serves(1) && serves(2) && serves(3); }, 120s)) {
            BOOST_TEST_MESSAGE(node_logs());
            os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
            BOOST_FAIL("co-located cluster did not serve within 120 s");
        }
    }
    ~LayerPathsFixture() {
        // Before the cluster goes: a failed case's node logs.
        const auto& tc = boost::unit_test::framework::current_test_case();
        if (!boost::unit_test::results_collector.results(tc.p_id).passed()) {
            std::cerr << "── node logs after " << tc.full_name() << " failed ──\n" << node_logs();
        }
        try {
            os::real_exec(compose_cmd({"down", "-v", "--remove-orphans"}));
        } catch (...) {
        }
    }
    LayerPathsFixture(const LayerPathsFixture&) = delete;
    LayerPathsFixture& operator=(const LayerPathsFixture&) = delete;
    LayerPathsFixture(LayerPathsFixture&&) = delete;
    LayerPathsFixture& operator=(LayerPathsFixture&&) = delete;
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(full_path_both_ways_killing_one_node_per_layer, LayerPathsFixture,
                        *boost::unit_test::timeout(1500)) {
    entries e;
    e.set({1, 2, 3});
    ledger l;
    checker check(e);
    workload work(e, l, 3);

    auto step = [&](const std::string& name, const std::function<void()>& body) {
        BOOST_TEST_MESSAGE("step: " << name);
        const auto before = l._acked.load();
        body();
        BOOST_REQUIRE_MESSAGE(await([&] { return l._acked.load() > before + 20; }, 90s),
                              name << ": no writes were acknowledged");
        const auto bad = check.verify(l);
        for (const auto& b : bad) {
            BOOST_ERROR(name << ": " << b);
        }
        BOOST_REQUIRE_MESSAGE(bad.empty(), name);
        BOOST_TEST_MESSAGE("  " << l._acked.load() << " acknowledged, " << l._unacked.load()
                                << " not");
    };
    // KYTHIRA.EVACUATE through `admin`, a node running gateway and data.
    auto evacuate = [&](int admin, int from, int to) {
        const std::vector<std::string> start_argv{
            "KYTHIRA.EVACUATE", "START",   std::to_string(from), "TO",
            std::to_string(to), "ADDRESS", std::to_string(to),   "http://" + service(to) + ":7000",
            gateway_of(to)};
        // START on a node without data is relayed to a data node, which
        // asks every other data node before it answers.
        const auto start = on(admin, start_argv, 60s);
        BOOST_REQUIRE_MESSAGE(start == "+OK\r\n",
                              "START " << from << " TO " << to << ": " << first_line(start));
        std::string status;
        const auto began = std::chrono::steady_clock::now();
        auto next_report = began + 30s;
        auto next_start = began + 20s;
        const bool done = await(
            [&] {
                status = on(admin, {"KYTHIRA.EVACUATE", "STATUS"});
                const auto now = std::chrono::steady_clock::now();
                if (now >= next_report) {
                    next_report += 30s;
                    BOOST_TEST_MESSAGE("  evacuating " << from << " to " << to << ": " << status);
                }
                // The runbook's answer to a data node that missed the job
                // (it did not answer when START fanned out, here because
                // a peer still remembered the joining node's name as
                // unresolvable) and since took leadership of a group: run
                // the same START again.
                if (now >= next_start && status.find(bulk("done 1")) == std::string::npos) {
                    next_start += 20s;
                    BOOST_TEST_MESSAGE("  START " << from << " TO " << to << " again: "
                                                  << first_line(on(admin, start_argv, 60s)));
                }
                // The first line, exactly: each node's own line ends in
                // "done 0" or "done 1" too.
                return status.find(bulk("done 1")) != std::string::npos;
            },
            180s);
        BOOST_REQUIRE_MESSAGE(
            done, "evacuation of " << from << " to " << to << " did not finish: " << status);
        BOOST_TEST_MESSAGE("  evacuated " << from << " to " << to << " in "
                                          << std::chrono::duration_cast<std::chrono::seconds>(
                                                 std::chrono::steady_clock::now() - began)
                                                 .count()
                                          << " s");
    };
    auto cancel = [&](int admin) {
        BOOST_REQUIRE_EQUAL(on(admin, {"KYTHIRA.EVACUATE", "CANCEL"}, 60s), "+OK\r\n");
    };
    auto release = [&](int evacuee) {
        const auto r = on(evacuee, {"KYTHIRA.EVACUATE", "RELEASE"});
        BOOST_REQUIRE_MESSAGE(r == "+OK\r\n", "RELEASE on " << evacuee << ": " << first_line(r));
    };
    auto require_serves = [&](int id) {
        BOOST_REQUIRE_MESSAGE(await([&] { return serves(id); }, 90s),
                              service(id) << " does not serve: "
                                          << first_line(on(id, {"MSET", "a/x", "1", "z/x", "1"})));
    };

    step("co-located baseline", [] {});

    step("data leaves lp-1 (evacuated to lp-4)", [&] {
        start_joiner(4);
        evacuate(2, 1, 4);
        release(1);
        cancel(2);
        recreate(1, layout{._roles = "gateway,front_end", ._data_nodes = list_gateways({2, 3, 4})});
        require_serves(1);
    });

    step("data node lp-2 killed and evacuated to lp-5 while down", [&] {
        e.set({1, 3});
        os::checked_exec(os::real_exec, os::docker_kill_cmd(container(2)));
        start_joiner(5);
        evacuate(3, 2, 5);
        cancel(3);
        // lp-2 comes back as a new, empty node without data.
        recreate(2, layout{._roles = "gateway,front_end", ._data_nodes = list_gateways({3, 4, 5})});
        require_serves(2);
        e.set({1, 2, 3});
    });

    step("data leaves lp-3 (evacuated to lp-6): gateway and front end apart from data", [&] {
        start_joiner(6);
        evacuate(3, 3, 6);
        release(3);
        cancel(3);
        e.set({1, 2});
        recreate(3, layout{._roles = "gateway,front_end", ._data_nodes = list_gateways({4, 5, 6})});
        require_serves(3);
        e.set({1, 2, 3});
    });

    const auto front_end_only =
        layout{._roles = "front_end", ._data_nodes = list_gateways({4, 5, 6})};
    const auto gateway_only = layout{._roles = "gateway", ._front_ends = list_gateways({2, 3})};
    const auto gateway_front_end =
        layout{._roles = "gateway,front_end", ._data_nodes = list_gateways({4, 5, 6})};

    step("gateway split off: three-way", [&] {
        e.set({1});
        recreate(2, front_end_only);
        recreate(3, front_end_only);
        recreate(1, gateway_only);
        require_serves(1);
    });

    step("the gateway killed and started again", [&] {
        os::checked_exec(os::real_exec, os::docker_kill_cmd(container(1)));
        std::this_thread::sleep_for(3s);
        os::checked_exec(os::real_exec, os::docker_start_cmd(container(1)));
        require_serves(1);
    });

    step("a front end killed and started again", [&] {
        os::checked_exec(os::real_exec, os::docker_kill_cmd(container(2)));
        std::this_thread::sleep_for(5s);
        os::checked_exec(os::real_exec, os::docker_start_cmd(container(2)));
        require_serves(1);
    });

    step("gateway merged back", [&] {
        recreate(2, gateway_front_end);
        recreate(3, gateway_front_end);
        require_serves(2);
        require_serves(3);
        e.set({2, 3});
        recreate(1, gateway_front_end);
        require_serves(1);
        e.set({1, 2, 3});
    });

    // Back to co-located: each of lp-1..lp-3 joins the data layer empty and
    // takes a data node's replicas, and that data node leaves.
    const auto all_joining = layout{._join = true};
    // Each START runs on a gateway that reaches data holding the groups
    // (lp-1 without data passes it to its data nodes): the joining node
    // holds nothing yet, so it knows no voter count.
    for (const auto& [back, from, admin] :
         std::vector<std::tuple<int, int, int>>{{3, 6, 1}, {2, 5, 3}, {1, 4, 3}}) {
        step("data merged back on " + service(back) + " (evacuated from " + service(from) + ")",
             [&, back = back, from = from, admin = admin] {
                 auto rest = e.get();
                 rest.erase(std::remove(rest.begin(), rest.end(), back), rest.end());
                 e.set(rest);
                 // A joining node holds no replica and, having `data`,
                 // attaches no remote path either, so it serves clients
                 // only once the evacuation has brought it every group;
                 // it stays out of the rotation until then.
                 recreate(back, all_joining);
                 BOOST_REQUIRE(await([&] { return on(back, {"PING"}) == "+PONG\r\n"; }, 60s));
                 evacuate(admin, from, back);
                 cancel(admin);
                 require_serves(back);
                 remove_node(from);
                 e.set({1, 2, 3});
             });
    }

    work.stop();
    const auto bad = check.verify(l);
    for (const auto& b : bad) {
        BOOST_ERROR("final: " << b);
    }
    BOOST_TEST_MESSAGE("acknowledged " << l._acked.load() << ", not acknowledged "
                                       << l._unacked.load() << ", connections "
                                       << l._reconnects.load());
    BOOST_CHECK_GT(l._acked.load(), 0U);
}
