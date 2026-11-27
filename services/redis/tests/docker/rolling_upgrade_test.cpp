// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file rolling_upgrade_test.cpp
/// @brief The format-gate rolling upgrade in containers
///        (.kiro/specs/redis-general-data-types/ Requirement 23.5).
///
/// services/redis/docker/rolling-upgrade-compose.yml runs three
/// engine-storage nodes. They start on kythira-engine-chaos:old,
/// redis_gateway_node built from the last commit before the format gate,
/// and are recreated one at a time on kythira-engine-chaos:dev, this tree's
/// build, keeping each node's volume:
///
///   1. All old: strings work; HSET is an unknown command.
///   2. One node new: it reports level 3, refuses typed commands with the
///      gate error, and KYTHIRA.FORMAT UPGRADE 3 is refused naming the two
///      old nodes; the mixed cluster still serves the old data from every
///      node.
///   3. All new: UPGRADE 3 passes, typed commands work through every node,
///      and the strings written by the old build are intact.
///   4. One node back on the old build after the gate: it does not come
///      back into service, and says why in its log (doc/redis-gateway.md,
///      "Format level and the rolling upgrade"); the other two keep serving.
///
/// Run by docker-redis-rolling-upgrade-tests, which builds both images.
/// Each node publishes RESP on a loopback port picked with
/// tests/test_ports.hpp; containers address each other by service name and
/// the runtime comes from container_runtime() (CLAUDE.md).

#define BOOST_TEST_MODULE redis_rolling_upgrade_test
#include <boost/test/unit_test.hpp>

#include "os_faults.hpp"
#include "test_ports.hpp"

#include "redis_differential.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
namespace os = docker_chaos::os;
namespace diff = kythira::redis_diff;

namespace {

constexpr std::size_t k_nodes = 3;
constexpr const char* k_old_image = "kythira-engine-chaos:old";
constexpr const char* k_new_image = "kythira-engine-chaos:dev";

auto env_or(const char* name, std::string fallback) -> std::string {
    const char* v = std::getenv(name);
    return v != nullptr && *v != 0 ? std::string(v) : std::move(fallback);
}

auto compose_file() -> std::string {
    return env_or("KYTHIRA_UPGRADE_COMPOSE_FILE",
                  "services/redis/docker/rolling-upgrade-compose.yml");
}

auto compose_cmd(std::vector<std::string> args) -> std::vector<std::string> {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", compose_file()});
    cmd.insert(cmd.end(), args.begin(), args.end());
    return cmd;
}

auto service(std::size_t i) -> std::string {
    return "upgrade-" + std::to_string(i + 1);
}

class resp_client {
public:
    explicit resp_client(std::uint16_t port) : _fd(::socket(AF_INET, SOCK_STREAM, 0)) {
        if (_fd < 0) {
            throw std::runtime_error("socket() failed");
        }
        timeval tv{.tv_sec = 15, .tv_usec = 0};
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
        if (call({"AUTH", "ops", "ops-secret"}) != "+OK\r\n") {
            ::close(_fd);
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

    auto call(const std::vector<std::string>& argv) -> std::string {
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
            std::array<char, 4096> chunk{};
            auto n = ::recv(_fd, chunk.data(), chunk.size(), 0);
            if (n <= 0) {
                throw std::runtime_error("connection closed or timed out awaiting a reply");
            }
            _buffer.append(chunk.data(), static_cast<std::size_t>(n));
        }
    }

private:
    int _fd;
    std::string _buffer;
};

auto bulk(const std::string& v) -> std::string {
    return "$" + std::to_string(v.size()) + "\r\n" + v + "\r\n";
}

class cluster {
public:
    cluster() {
        for (std::size_t i = 0; i < k_nodes; ++i) {
            _ports[i] = kythira::testing::free_port();
            set_env("KYTHIRA_UPGRADE_PORT_" + std::to_string(i + 1), std::to_string(_ports[i]));
            set_image(i, k_old_image);
        }
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        os::checked_exec(os::real_exec, compose_cmd({"up", "-d"}));
    }
    ~cluster() {
        if (!env_or("KYTHIRA_UPGRADE_KEEP_UP", "").empty()) {
            return;
        }
        try {
            os::real_exec(compose_cmd({"down", "-v", "--remove-orphans"}));
        } catch (...) {
        }
    }
    cluster(const cluster&) = delete;
    cluster& operator=(const cluster&) = delete;
    cluster(cluster&&) = delete;
    cluster& operator=(cluster&&) = delete;

    [[nodiscard]] auto port(std::size_t i) const -> std::uint16_t { return _ports[i]; }

    /// Recreates node `i` on `image`, keeping its volume: one step of a
    /// rolling upgrade (or a downgrade).
    void roll(std::size_t i, const char* image) {
        BOOST_TEST_MESSAGE("recreate " << service(i) << " on " << image);
        set_image(i, image);
        os::checked_exec(os::real_exec, compose_cmd({"up", "-d", "--no-deps", service(i)}));
    }

    /// A SET and GET on both shards through each of `nodes` answers.
    [[nodiscard]] auto wait_serving(std::vector<std::size_t> nodes, std::chrono::seconds budget)
        -> bool {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            bool all = true;
            for (const auto i : nodes) {
                try {
                    resp_client c(_ports[i]);
                    for (const auto* k : {"a/probe", "z/probe"}) {
                        if (c.call({"SET", k, "1"}) != "+OK\r\n" ||
                            c.call({"GET", k}) != bulk("1")) {
                            all = false;
                        }
                    }
                } catch (const std::exception& e) {
                    _last = e.what();
                    all = false;
                }
                if (!all) {
                    break;
                }
            }
            if (all) {
                return true;
            }
            std::this_thread::sleep_for(1s);
        }
        return false;
    }

    /// One command through node `i`, retried while a shard settles.
    auto call(std::size_t i, const std::vector<std::string>& argv) -> std::string {
        std::string reply;
        for (int attempt = 0; attempt < 30; ++attempt) {
            try {
                resp_client c(_ports[i]);
                reply = c.call(argv);
                if (reply.find(", retry") == std::string::npos) {
                    return reply;
                }
            } catch (const std::exception& e) {
                reply = e.what();
            }
            std::this_thread::sleep_for(500ms);
        }
        return reply;
    }

    [[nodiscard]] auto logs(std::size_t i) const -> std::string {
        return os::real_exec(compose_cmd({"logs", "--no-color", service(i)})).out;
    }

    [[nodiscard]] auto last_error() const -> const std::string& { return _last; }

private:
    static void set_env(const std::string& name, const std::string& value) {
        ::setenv(name.c_str(), value.c_str(), 1);
    }
    static void set_image(std::size_t i, const char* image) {
        set_env("KYTHIRA_UPGRADE_IMAGE_" + std::to_string(i + 1), image);
    }

    std::array<std::uint16_t, k_nodes> _ports{};
    std::string _last;
};

/// What a pre-gate binary says when it meets data written after the gate:
/// the engine store's meta record grew at the gate, the log holds format
/// 0x03 records, and a binary with format levels (but below the level)
/// names the level it needs. Any of them, never silence.
auto refusal_in(const std::string& log) -> bool {
    return log.find("meta record has the wrong size") != std::string::npos ||
           log.find("unknown redis kv command format version 3") != std::string::npos ||
           log.find("needs Redis format level") != std::string::npos;
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_rolling_upgrade_through_the_format_gate, *boost::unit_test::timeout(1500)) {
    if (env_or("KYTHIRA_DOCKER_INTEGRATION_TESTS", "").empty()) {
        BOOST_TEST_MESSAGE("KYTHIRA_DOCKER_INTEGRATION_TESTS is not set; skipping");
        return;
    }
    cluster c;
    BOOST_REQUIRE_MESSAGE(c.wait_serving({0, 1, 2}, 180s),
                          "the old cluster never served: " << c.last_error());

    // 1. All old.
    BOOST_REQUIRE_EQUAL(c.call(0, {"SET", "a/old", "before"}), "+OK\r\n");
    BOOST_REQUIRE_EQUAL(c.call(1, {"SET", "z/old", "before"}), "+OK\r\n");
    BOOST_CHECK(c.call(2, {"HSET", "a/h", "f", "v"}).rfind("-ERR unknown command", 0) == 0);

    // 2. One node on the new build.
    c.roll(0, k_new_image);
    BOOST_REQUIRE_MESSAGE(c.wait_serving({0, 1, 2}, 180s),
                          "the mixed cluster never served: " << c.last_error());
    BOOST_CHECK_EQUAL(c.call(0, {"KYTHIRA.FORMAT", "LEVEL"}), ":3\r\n");
    BOOST_CHECK_EQUAL(c.call(0, {"HSET", "a/h", "f", "v"}),
                      "-ERR this cluster has not enabled typed values yet (KYTHIRA.FORMAT)\r\n");
    const auto refused = c.call(0, {"KYTHIRA.FORMAT", "UPGRADE", "3"});
    BOOST_TEST_INFO(refused);
    BOOST_CHECK(refused.rfind("-ERR KYTHIRA.FORMAT cannot reach level 3", 0) == 0);
    BOOST_CHECK(refused.find("2 (no answer)") != std::string::npos);
    BOOST_CHECK(refused.find("3 (no answer)") != std::string::npos);
    for (std::size_t i = 0; i < k_nodes; ++i) {
        BOOST_CHECK_EQUAL(c.call(i, {"GET", "a/old"}), bulk("before"));
        BOOST_CHECK_EQUAL(c.call(i, {"GET", "z/old"}), bulk("before"));
    }
    BOOST_CHECK_EQUAL(c.call(1, {"SET", "a/mixed", "written-by-old"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(c.call(0, {"GET", "a/mixed"}), bulk("written-by-old"));

    // 3. The rest of the cluster, then the gate.
    c.roll(1, k_new_image);
    BOOST_REQUIRE_MESSAGE(c.wait_serving({0, 1, 2}, 180s), c.last_error());
    c.roll(2, k_new_image);
    BOOST_REQUIRE_MESSAGE(c.wait_serving({0, 1, 2}, 180s), c.last_error());
    BOOST_REQUIRE_EQUAL(c.call(1, {"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(c.call(1, {"HSET", "a/h", "f", "v"}), ":1\r\n");
    BOOST_CHECK_EQUAL(c.call(2, {"RPUSH", "z/l", "x", "y"}), ":2\r\n");
    for (std::size_t i = 0; i < k_nodes; ++i) {
        BOOST_CHECK_EQUAL(c.call(i, {"HGET", "a/h", "f"}), bulk("v"));
        BOOST_CHECK_EQUAL(c.call(i, {"LINDEX", "z/l", "-1"}), bulk("y"));
        BOOST_CHECK_EQUAL(c.call(i, {"GET", "a/old"}), bulk("before"));
        BOOST_CHECK_EQUAL(c.call(i, {"GET", "a/mixed"}), bulk("written-by-old"));
    }

    // 4. A node rolled back to the old build after the gate.
    c.roll(2, k_old_image);
    BOOST_CHECK_EQUAL(c.call(0, {"HSET", "a/h", "g", "w"}), ":1\r\n");
    std::string log;
    for (int attempt = 0; attempt < 60 && !refusal_in(log); ++attempt) {
        std::this_thread::sleep_for(1s);
        log = c.logs(2);
    }
    BOOST_TEST_INFO(log.substr(log.size() > 4000 ? log.size() - 4000 : 0));
    BOOST_CHECK_MESSAGE(refusal_in(log), "the old build on gated data did not say why it stopped");
    // It never serves the gated data, and the other two carry on.
    BOOST_CHECK(!c.wait_serving({2}, 10s));
    BOOST_CHECK(c.wait_serving({0, 1}, 60s));
    BOOST_CHECK_EQUAL(c.call(1, {"HGET", "a/h", "g"}), bulk("w"));
}
