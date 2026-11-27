// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file client_suites_test.cpp
/// @brief redis-py's, go-redis's and ioredis's own tests against a Kythira
///        cluster in containers (.kiro/specs/redis-general-data-types/
///        Requirement 23.3).
///
/// services/redis/docker/clients/compose.yml runs three gateways. Once a
/// write lands on both shards this test raises the format gate (typed
/// commands need it), then runs the client image once
/// (`run --rm clients`), which runs each library's selected tests
/// (services/redis/docker/clients/{redis-py,go-redis,ioredis}.txt) and
/// exits non-zero if any fails. The client output is the test's message,
/// so a failure shows which library test broke, and each suite's JUnit
/// report is written to $KYTHIRA_CLIENTS_OUT (default
/// /tmp/kythira-redis-clients-out).
///
/// Run by docker-redis-client-suites-tests, which builds both images. kv1
/// publishes RESP on a loopback port picked with tests/test_ports.hpp, for
/// the readiness probe and the gate; containers address each other by
/// service name and the runtime comes from container_runtime() (CLAUDE.md).
/// Skips unless KYTHIRA_DOCKER_INTEGRATION_TESTS is set.

#define BOOST_TEST_MODULE redis_client_suites_test
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
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
namespace os = docker_chaos::os;
namespace diff = kythira::redis_diff;

namespace {

auto env_or(const char* name, std::string fallback) -> std::string {
    const char* v = std::getenv(name);
    return v != nullptr && *v != 0 ? std::string(v) : std::move(fallback);
}

auto compose_cmd(std::vector<std::string> args) -> std::vector<std::string> {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", env_or("KYTHIRA_CLIENTS_COMPOSE_FILE",
                                        "services/redis/docker/clients/compose.yml")});
    cmd.insert(cmd.end(), args.begin(), args.end());
    return cmd;
}

/// One authenticated connection to kv1's published port.
class resp_client {
public:
    explicit resp_client(std::uint16_t port) : _fd(::socket(AF_INET, SOCK_STREAM, 0)) {
        if (_fd < 0) {
            throw std::runtime_error("socket() failed");
        }
        timeval tv{.tv_sec = 30, .tv_usec = 0};
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

class cluster {
public:
    cluster() : _port(kythira::testing::free_port()) {
        ::setenv("KYTHIRA_CLIENTS_PORT_KV1", std::to_string(_port).c_str(), 1);
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        os::checked_exec(os::real_exec, compose_cmd({"up", "-d", "kv1", "kv2", "kv3"}));
    }
    ~cluster() {
        if (!env_or("KYTHIRA_CLIENTS_KEEP_UP", "").empty()) {
            return;
        }
        try {
            os::real_exec(compose_cmd({"--profile", "clients", "down", "-v", "--remove-orphans"}));
        } catch (...) {
        }
    }
    cluster(const cluster&) = delete;
    cluster& operator=(const cluster&) = delete;
    cluster(cluster&&) = delete;
    cluster& operator=(cluster&&) = delete;

    /// A write lands on both shards (keys below and above the "e" cut).
    [[nodiscard]] auto wait_serving(std::chrono::seconds budget) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            try {
                resp_client c(_port);
                if (c.call({"SET", "a:probe", "1"}) == "+OK\r\n" &&
                    c.call({"SET", "z:probe", "1"}) == "+OK\r\n") {
                    c.call({"DEL", "a:probe", "z:probe"});
                    return true;
                }
            } catch (const std::exception& e) {
                _last = e.what();
            }
            std::this_thread::sleep_for(1s);
        }
        return false;
    }

    /// One command through kv1, retried while a shard settles.
    auto call(const std::vector<std::string>& argv) -> std::string {
        std::string reply;
        for (int attempt = 0; attempt < 60; ++attempt) {
            try {
                resp_client c(_port);
                reply = c.call(argv);
                if (!reply.starts_with('-')) {
                    return reply;
                }
            } catch (const std::exception& e) {
                reply = e.what();
            }
            std::this_thread::sleep_for(500ms);
        }
        return reply;
    }

    [[nodiscard]] auto logs() const -> std::string {
        return os::real_exec(compose_cmd({"logs", "--no-color", "--tail", "100"})).out;
    }
    [[nodiscard]] auto last_error() const -> const std::string& { return _last; }

private:
    std::uint16_t _port;
    std::string _last;
};

}  // namespace

BOOST_AUTO_TEST_CASE(client_library_suites_pass, *boost::unit_test::timeout(3600)) {
    if (env_or("KYTHIRA_DOCKER_INTEGRATION_TESTS", "").empty()) {
        BOOST_TEST_MESSAGE("KYTHIRA_DOCKER_INTEGRATION_TESTS is not set; skipping");
        return;
    }
    cluster c;
    BOOST_REQUIRE_MESSAGE(c.wait_serving(180s), "the cluster never served: " << c.last_error()
                                                                             << "\n"
                                                                             << c.logs());
    BOOST_REQUIRE_EQUAL(c.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");

    // The suites' JUnit reports land here (compose.yml mounts it at /out).
    const auto out =
        std::filesystem::absolute(env_or("KYTHIRA_CLIENTS_OUT", "/tmp/kythira-redis-clients-out"));
    std::filesystem::create_directories(out);
    ::setenv("KYTHIRA_CLIENTS_OUT", out.c_str(), 1);
    const auto run =
        os::real_exec(compose_cmd({"--profile", "clients", "run", "--rm", "-T", "clients"}));
    BOOST_TEST_MESSAGE(run.out);
    BOOST_CHECK_MESSAGE(run.code == 0, "a client library test failed (exit "
                                           << run.code << "); its output is above\n"
                                           << c.logs());
}
