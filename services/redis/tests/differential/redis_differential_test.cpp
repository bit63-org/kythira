// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE redis_differential_test
#include <boost/test/unit_test.hpp>

#include "os_faults.hpp"
#include "redis_differential.hpp"
#include "test_ports.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// The differential suite in containers (.kiro/specs/redis-general-data-types/
// Requirement 23.2; the task 14 scaffold). services/redis/docker/differential/
// compose.yml runs one Redis 7.2, one Valkey 8 and a three-node Kythira
// gateway cluster. For every seed and both protocols this test sends the same
// generated stream to all of them in lockstep, one command at a time, and
// compares each Kythira reply with the references (redis_differential.hpp
// says what counts as a match). It writes:
//
//   $KYTHIRA_DIFF_OUT/difference-table.md   every row where any two disagree
//   $KYTHIRA_DIFF_OUT/recs/<server>-seed<N>.json   what each server answered
//
// and fails if a Kythira reply differs from both references with no rule to
// cover it.
//
// Environment (all optional):
//   KYTHIRA_DIFF_COMPOSE_FILE      the compose file (default: the one above)
//   KYTHIRA_DIFF_KYTHIRA_SERVICES  space-separated Kythira service names
//                                  (default "kv1 kv2 kv3"); empty runs the
//                                  references alone, to regenerate recs/
//   KYTHIRA_DIFF_SEEDS             space-separated seeds (default "1 2 3")
//   KYTHIRA_DIFF_LENGTH            commands per stream (default 400)
//   KYTHIRA_DIFF_OUT               output directory (default
//                                  ./redis-differential-out)
//   KYTHIRA_DIFF_KEEP_UP           non-empty: leave the containers running
//
// Every service publishes its RESP port on a loopback port chosen here with
// tests/test_ports.hpp and handed to compose as KYTHIRA_DIFF_PORT_<SERVICE>
// (upper case, '-' as '_'), so nothing is hardcoded and two runs on one host
// do not collide. Containers address each other by service name (CLAUDE.md).

using namespace std::chrono_literals;
namespace os = docker_chaos::os;
namespace diff = kythira::redis_diff;
namespace fs = std::filesystem;

namespace {

auto env_or(const char* name, std::string fallback) -> std::string {
    const char* v = std::getenv(name);
    return v != nullptr ? std::string(v) : std::move(fallback);
}

auto split_words(const std::string& s) -> std::vector<std::string> {
    std::istringstream in(s);
    std::vector<std::string> out;
    for (std::string w; in >> w;) {
        out.push_back(w);
    }
    return out;
}

auto compose_file() -> std::string {
    return env_or("KYTHIRA_DIFF_COMPOSE_FILE", "services/redis/docker/differential/compose.yml");
}

auto compose_cmd(std::vector<std::string> args) -> std::vector<std::string> {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", compose_file()});
    cmd.insert(cmd.end(), args.begin(), args.end());
    return cmd;
}

auto port_variable(const std::string& service) -> std::string {
    std::string v = "KYTHIRA_DIFF_PORT_";
    for (char c : service) {
        v += c == '-' ? '_' : static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return v;
}

auto today() -> std::string {
    const auto t = std::time(nullptr);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char buf[16];
    std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
    return buf;
}

// ── a blocking RESP client over the harness's own parser ────────────────────

class resp_client {
public:
    explicit resp_client(std::uint16_t port) : _fd(::socket(AF_INET, SOCK_STREAM, 0)) {
        if (_fd < 0) {
            throw std::runtime_error("socket() failed");
        }
        timeval tv{.tv_sec = 10, .tv_usec = 0};
        ::setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        int one = 1;
        ::setsockopt(_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (::connect(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
            ::close(_fd);
            throw std::runtime_error("connect to 127.0.0.1:" + std::to_string(port) + " refused");
        }
    }
    ~resp_client() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
    resp_client(const resp_client&) = delete;
    resp_client& operator=(const resp_client&) = delete;

    /// Sends one command and returns the raw bytes of its reply.
    auto call_raw(const std::vector<std::string>& argv) -> std::string {
        const auto out = diff::encode_command(argv);
        for (std::size_t sent = 0; sent < out.size();) {
            auto n = ::send(_fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
            if (n <= 0) {
                throw std::runtime_error("send failed");
            }
            sent += static_cast<std::size_t>(n);
        }
        for (;;) {
            std::size_t pos = 0;
            if (diff::parse_reply(_buffer, pos)) {
                auto raw = _buffer.substr(0, pos);
                _buffer.erase(0, pos);
                return raw;
            }
            char chunk[4096];
            auto n = ::recv(_fd, chunk, sizeof chunk, 0);
            if (n <= 0) {
                throw std::runtime_error("connection closed or timed out awaiting a reply");
            }
            _buffer.append(chunk, static_cast<std::size_t>(n));
        }
    }
    auto call(const std::vector<std::string>& argv) -> diff::reply {
        return diff::parse_one(call_raw(argv));
    }

private:
    int _fd;
    std::string _buffer;
};

/// A reply Kythira gives while a shard has no leader yet or a forward is
/// refused for a moment. Retried outside MULTI; never a conformance result.
auto transient(const diff::reply& r) -> bool {
    if (r.kind != diff::reply_kind::error) {
        return false;
    }
    return r.text.find(", retry") != std::string::npos || r.text.rfind("LOADING", 0) == 0 ||
           r.text.rfind("TRYAGAIN", 0) == 0 || r.text.rfind("CLUSTERDOWN", 0) == 0;
}

struct endpoint {
    std::string service;
    std::string server;  // "redis", "valkey", "kythira"
    std::uint16_t port = 0;
};

class stack {
public:
    stack(std::vector<std::string> kythira_services) : _kythira(std::move(kythira_services)) {
        std::vector<std::string> all{"redis", "valkey"};
        all.insert(all.end(), _kythira.begin(), _kythira.end());
        for (const auto& s : all) {
            const auto port = kythira::testing::free_port();
            ::setenv(port_variable(s).c_str(), std::to_string(port).c_str(), 1);
            _endpoints.push_back(endpoint{s, s == "redis" || s == "valkey" ? s : "kythira", port});
        }
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        auto up = compose_cmd({"up", "-d"});
        up.insert(up.end(), all.begin(), all.end());
        os::checked_exec(os::real_exec, up);
    }
    ~stack() {
        if (!env_or("KYTHIRA_DIFF_KEEP_UP", "").empty()) {
            return;
        }
        os::real_exec(compose_cmd({"down", "-v", "--remove-orphans"}));
    }
    stack(const stack&) = delete;
    stack& operator=(const stack&) = delete;

    [[nodiscard]] auto endpoints() const -> const std::vector<endpoint>& { return _endpoints; }
    [[nodiscard]] auto find(const std::string& service) const -> const endpoint& {
        for (const auto& e : _endpoints) {
            if (e.service == service) {
                return e;
            }
        }
        throw std::runtime_error("no endpoint " + service);
    }
    [[nodiscard]] auto kythira() const -> const std::vector<std::string>& { return _kythira; }

    [[nodiscard]] auto logs() const -> std::string {
        std::string all;
        for (const auto& e : _endpoints) {
            all += "── " + e.service + " ──\n" +
                   os::real_exec(compose_cmd({"logs", "--tail", "200", e.service})).out;
        }
        return all;
    }

private:
    std::vector<std::string> _kythira;
    std::vector<endpoint> _endpoints;
};

/// Opens a connection and switches it to `protocol`, authenticating as the
/// `ops` user every server is given (compose.yml, acl.txt).
auto open_session(const endpoint& e, int protocol) -> std::unique_ptr<resp_client> {
    auto c = std::make_unique<resp_client>(e.port);
    auto hello = c->call({"HELLO", std::to_string(protocol), "AUTH", "ops", "ops-secret"});
    if (hello.kind == diff::reply_kind::error) {
        throw std::runtime_error(e.service + ": HELLO refused: " + hello.text);
    }
    return c;
}

/// Waits until a server answers, and for Kythira until a write lands on
/// both shards (keys below and above the "e" cut).
void wait_ready(const endpoint& e, std::chrono::seconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    std::string last;
    while (std::chrono::steady_clock::now() < deadline) {
        try {
            auto c = open_session(e, 2);
            bool ok = true;
            for (const auto* k : {"a:probe", "h:probe"}) {
                auto r = c->call({"SET", k, "1"});
                if (r.kind != diff::reply_kind::simple) {
                    last = diff::display(r);
                    ok = false;
                    break;
                }
                c->call({"DEL", k});
            }
            if (ok) {
                return;
            }
        } catch (const std::exception& ex) {
            last = ex.what();
        }
        std::this_thread::sleep_for(500ms);
    }
    throw std::runtime_error(e.service + " not ready: " + last);
}

auto server_version(const endpoint& e) -> std::string {
    auto c = open_session(e, 3);
    auto hello = c->call({"HELLO", "3"});
    for (std::size_t i = 0; i + 1 < hello.items.size(); i += 2) {
        if (hello.items[i].text == "version") {
            return hello.items[i + 1].text;
        }
    }
    return "unknown";
}

struct run_result {
    std::vector<diff::difference_row> rows;
    std::size_t compared = 0;
    std::size_t same = 0;
    std::map<std::string, std::size_t> allowed;  // rule id -> count
    std::size_t differs = 0;
    std::size_t refs_differ = 0;
};

}  // namespace

BOOST_AUTO_TEST_CASE(differential_against_reference_servers) {
    const auto kythira_services =
        split_words(env_or("KYTHIRA_DIFF_KYTHIRA_SERVICES", "kv1 kv2 kv3"));
    std::vector<std::uint64_t> seeds;
    for (const auto& w : split_words(env_or("KYTHIRA_DIFF_SEEDS", "1 2 3"))) {
        seeds.push_back(std::stoull(w));
    }
    const auto length = std::stoull(env_or("KYTHIRA_DIFF_LENGTH", "400"));
    const fs::path out_dir = env_or("KYTHIRA_DIFF_OUT", "redis-differential-out");
    fs::create_directories(out_dir / "recs");

    stack s(kythira_services);
    try {
        for (const auto& e : s.endpoints()) {
            wait_ready(e, e.server == "kythira" ? 120s : 60s);
        }
    } catch (...) {
        std::cerr << s.logs();
        throw;
    }

    const auto& redis = s.find("redis");
    const auto& valkey = s.find("valkey");
    const std::map<std::string, std::string> versions{
        {"redis", server_version(redis)},
        {"valkey", server_version(valkey)},
        {"kythira", kythira_services.empty() ? "" : server_version(s.find(kythira_services[0]))},
    };
    BOOST_TEST_MESSAGE("Redis " << versions.at("redis") << ", Valkey " << versions.at("valkey")
                                << ", Kythira " << versions.at("kythira"));

    run_result result;
    for (const auto seed : seeds) {
        diff::generator_options opt;
        opt.length = length;
        opt.tag = "s" + std::to_string(seed);
        const auto stream = diff::generate(seed, opt);

        std::map<std::string, diff::recording> recs;
        for (const auto* server : {"redis", "valkey", "kythira"}) {
            if (std::string(server) == "kythira" && kythira_services.empty()) {
                continue;
            }
            auto& r = recs[server];
            r.server = server;
            r.version = versions.at(server);
            r.date = today();
            r.seed = seed;
            r.length = length;
            for (const auto& c : stream) {
                r.entries.push_back({c.argv, c.shape, {}, {}});
            }
        }

        for (const int protocol : {2, 3}) {
            // Kythira streams rotate over the gateways so forwarding to a
            // shard's leader is exercised from every node.
            std::optional<endpoint> k;
            if (!kythira_services.empty()) {
                k = s.find(kythira_services[(seed + protocol) % kythira_services.size()]);
            }
            auto rc = open_session(redis, protocol);
            auto vc = open_session(valkey, protocol);
            auto kc = k ? open_session(*k, protocol) : nullptr;
            // Each stream starts from an empty key space. Kythira refuses
            // FLUSHALL by default (D6), so every key the generator can name is
            // deleted one by one, on every server alike.
            for (std::size_t i = 0; i < opt.key_space; ++i) {
                const std::vector<std::string> del{
                    "DEL", std::string(1, static_cast<char>('a' + i)) + ":" + opt.tag};
                rc->call(del);
                vc->call(del);
                if (kc) {
                    for (int attempt = 0; attempt < 20 && transient(kc->call(del)); ++attempt) {
                        std::this_thread::sleep_for(250ms);
                    }
                }
            }

            bool in_multi = false;
            for (std::size_t i = 0; i < stream.size(); ++i) {
                const auto& c = stream[i];
                const auto name = diff::detail::upper(c.argv.front());
                auto rraw = rc->call_raw(c.argv);
                auto vraw = vc->call_raw(c.argv);
                std::string kraw;
                if (kc) {
                    kraw = kc->call_raw(c.argv);
                    for (int attempt = 0;
                         attempt < 20 && !in_multi && transient(diff::parse_one(kraw)); ++attempt) {
                        std::this_thread::sleep_for(250ms);
                        kraw = kc->call_raw(c.argv);
                    }
                }
                // MULTI state follows the reference's view of the stream.
                const auto rr = diff::parse_one(rraw);
                if (name == "MULTI" && rr.kind == diff::reply_kind::simple) {
                    in_multi = true;
                } else if ((name == "EXEC" || name == "DISCARD") && in_multi) {
                    in_multi = false;
                }

                auto field = [&](diff::recording& r) -> std::string& {
                    return protocol == 2 ? r.entries[i].resp2 : r.entries[i].resp3;
                };
                field(recs["redis"]) = rraw;
                field(recs["valkey"]) = vraw;
                if (kc) {
                    field(recs["kythira"]) = kraw;
                }

                const auto vr = diff::parse_one(vraw);
                const bool refs_agree = rr == vr;
                diff::difference_row row{seed, protocol, i, c.argv, rr, vr, std::nullopt, ""};
                if (!refs_agree) {
                    ++result.refs_differ;
                    row.note = "refs differ";
                }
                if (kc) {
                    const auto kr = diff::parse_one(kraw);
                    row.kythira = kr;
                    ++result.compared;
                    const auto v = diff::classify(c, rr, vr, kr);
                    switch (v.result) {
                        case diff::outcome::same:
                            ++result.same;
                            break;
                        case diff::outcome::allowed:
                            ++result.allowed[v.rule];
                            row.note = v.rule;
                            break;
                        case diff::outcome::differs:
                            ++result.differs;
                            row.note = "DIFFERS";
                            break;
                    }
                    if (v.result == diff::outcome::same && refs_agree) {
                        continue;
                    }
                } else if (refs_agree) {
                    continue;
                }
                result.rows.push_back(std::move(row));
            }
        }

        for (const auto& [server, rec] : recs) {
            std::ofstream(out_dir / "recs" / (server + "-seed" + std::to_string(seed) + ".json"))
                << diff::serialize(rec);
        }
    }

    std::ostringstream summary;
    summary << "# Redis differential run\n\n"
            << "Redis " << versions.at("redis") << ", Valkey " << versions.at("valkey")
            << ", Kythira " << versions.at("kythira") << "; seeds";
    for (auto seed : seeds) {
        summary << ' ' << seed;
    }
    summary << ", " << length << " commands each, RESP2 and RESP3.\n\n"
            << "- Kythira replies compared: " << result.compared << "\n"
            << "- equal to a reference: " << result.same << "\n";
    for (const auto& [rule, n] : result.allowed) {
        summary << "- allowed by " << rule << ": " << n << "\n";
    }
    summary << "- **differs: " << result.differs << "**\n"
            << "- rows where Redis and Valkey disagree: " << result.refs_differ << "\n\n";
    std::ofstream(out_dir / "difference-table.md")
        << summary.str() << diff::render_difference_table(result.rows);
    BOOST_TEST_MESSAGE(summary.str());
    for (const auto& row : result.rows) {
        if (row.note == "DIFFERS") {
            BOOST_TEST_MESSAGE("DIFFERS " << diff::render_difference_table({row}).substr(
                                   diff::render_difference_table({}).size()));
        }
    }
    BOOST_TEST(result.differs == 0U, "Kythira differs from both references "
                                         << result.differs << " times; see "
                                         << (out_dir / "difference-table.md").string());
}
