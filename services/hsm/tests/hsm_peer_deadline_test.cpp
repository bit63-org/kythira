// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The blocking HTTPS clients keep their deadline on every step
// (include/raft/beast_deadline.hpp). A synchronous Beast connect,
// handshake, write or read ignores `tcp_stream::expires_after()`, so a
// member forwarding to a peer that had just been restarted under rootless
// Podman (its old address answering nothing) waited out the kernel's SYN
// retries, about 127 s, and a peer that accepted but never answered held
// the read forever. The HSM chaos job in containers failed on binds that
// took 42 s and 137 s against a 7 s forward deadline.
//
// Two listeners stand in for those peers without root or a black-holed
// route: one whose accept queue is full, so the kernel drops every further
// SYN and the dial hangs, and one that completes the TCP handshake but
// never reads or writes.

#define BOOST_TEST_MODULE hsm_peer_deadline_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_pki.hpp"

#include <raft/https_peer_client.hpp>
#include <raft/mtls_https_client.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using clock_type = std::chrono::steady_clock;

/// The client's deadline, and how long a call may take with it: the
/// deadline plus slack for a loaded runner, far below the minutes a
/// blocking call waited.
constexpr auto k_deadline = 500ms;
constexpr auto k_bound = 4s;

/// A loopback TCP socket that listens and never accepts. With `fill`, its
/// accept queue is filled first, so the kernel drops later SYNs and a dial
/// to it hangs; without, a dial completes and nothing is ever answered.
class silent_listener {
public:
    explicit silent_listener(bool fill) : _fd(::socket(AF_INET, SOCK_STREAM, 0)) {
        BOOST_REQUIRE(_fd >= 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;  // the kernel picks a free port
        BOOST_REQUIRE(::bind(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0);
        BOOST_REQUIRE(::listen(_fd, fill ? 0 : 16) == 0);
        socklen_t len = sizeof addr;
        BOOST_REQUIRE(::getsockname(_fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
        _port = ntohs(addr.sin_port);
        if (fill) {
            // A backlog of 0 admits one finished connection; two more
            // dials make sure the queue is full whatever the kernel
            // rounds it to, and leave the SYN queue pending.
            for (int i = 0; i < 3; ++i) {
                const int c = ::socket(AF_INET, SOCK_STREAM, 0);
                BOOST_REQUIRE(c >= 0);
                (void)::fcntl(c, F_SETFL, O_NONBLOCK);
                (void)::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
                _fillers.push_back(c);
            }
            std::this_thread::sleep_for(100ms);
        }
    }
    ~silent_listener() {
        for (const int c : _fillers) {
            ::close(c);
        }
        ::close(_fd);
    }
    silent_listener(const silent_listener&) = delete;
    auto operator=(const silent_listener&) -> silent_listener& = delete;
    silent_listener(silent_listener&&) = delete;
    auto operator=(silent_listener&&) -> silent_listener& = delete;

    [[nodiscard]] auto host_port() const -> std::string {
        return "127.0.0.1:" + std::to_string(_port);
    }

private:
    int _fd = -1;
    unsigned short _port = 0;
    std::vector<int> _fillers;
};

auto elapsed_since(clock_type::time_point start) -> std::chrono::milliseconds {
    return std::chrono::duration_cast<std::chrono::milliseconds>(clock_type::now() - start);
}

/// One mtls::client request to `l`: it must fail, within the bound.
void expect_mtls_gives_up(const silent_listener& l, bool tls,
                          const kythira::hsm::test::test_pki::files& cert,
                          const std::string& ca_path) {
    kythira::mtls::client_config cfg;
    cfg.cert_path = cert.cert;
    cfg.key_path = cert.key;
    cfg.ca_path = ca_path;
    cfg.plaintext = !tls;
    cfg.timeout = k_deadline;
    const kythira::mtls::client client(cfg);
    const auto start = clock_type::now();
    const auto answer = client.request("POST", (tls ? "https://" : "http://") + l.host_port(),
                                       "/v1/peer/propose", "body", "text/plain", "test");
    const auto took = elapsed_since(start);
    BOOST_TEST_INFO("tls=" << tls << " took " << took.count() << " ms");
    BOOST_TEST(!answer.has_value());
    BOOST_TEST(took < k_bound);
}

/// One https_peer::peer_client request to `l`: it must fail, within the
/// bound.
void expect_peer_client_gives_up(const silent_listener& l, bool tls, const std::string& ca_path) {
    kythira::https_peer::peer_client_config cfg;
    cfg._tls = tls;
    cfg._ca_path = ca_path;
    cfg._timeout = k_deadline;
    const kythira::https_peer::peer_client client(cfg);
    const auto start = clock_type::now();
    const auto answer = client.request(l.host_port(), boost::beast::http::verb::get, "/health", {});
    const auto took = elapsed_since(start);
    BOOST_TEST_INFO("tls=" << tls << " took " << took.count() << " ms");
    BOOST_TEST(!answer.has_value());
    BOOST_TEST(took < k_bound);
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_dial_nothing_answers_ends_at_the_deadline) {
    kythira::hsm::test::test_pki pki;
    const auto cert = pki.issue("node-1", "DNS:localhost,IP:127.0.0.1");
    for (const bool tls : {false, true}) {
        const silent_listener l(true);
        expect_mtls_gives_up(l, tls, cert, pki.ca_path());
    }
    for (const bool tls : {false, true}) {
        const silent_listener l(true);
        expect_peer_client_gives_up(l, tls, pki.ca_path());
    }
}

BOOST_AUTO_TEST_CASE(a_peer_that_never_answers_ends_at_the_deadline) {
    kythira::hsm::test::test_pki pki;
    const auto cert = pki.issue("node-1", "DNS:localhost,IP:127.0.0.1");
    for (const bool tls : {false, true}) {
        const silent_listener l(false);
        expect_mtls_gives_up(l, tls, cert, pki.ca_path());  // handshake or read
    }
    for (const bool tls : {false, true}) {
        const silent_listener l(false);
        expect_peer_client_gives_up(l, tls, pki.ca_path());
    }
}
