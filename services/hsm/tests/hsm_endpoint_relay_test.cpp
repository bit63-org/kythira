// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The HSM's endpoint relay (.kiro/specs/hsm-independent-layers/ task 4,
// Requirement 6), first against plain TCP backends that say who they are,
// then in front of two crypto nodes' mutual TLS wire servers:
//
//  - each connection is pinned to one backend, new ones going to the one
//    with the fewest;
//  - an unhealthy backend gets none, and its pinned connections are closed;
//    a backend that fails closes its client's connection;
//  - a draining backend keeps its connections and gets no new ones, and
//    with no backend left a client is closed at once;
//  - the relay never terminates TLS: the crypto node sees the client's own
//    certificate, and the client checks the crypto node's;
//  - when a crypto node goes away, the client reconnects through the relay,
//    logs in again on the other one and keeps using its key.

#define BOOST_TEST_MODULE hsm_endpoint_relay_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_node.hpp"
#include "hsm_test_pki.hpp"

#include <kythira/hsm/endpoint_relay.hpp>
#include <kythira/hsm/wire_client.hpp>
#include <kythira/hsm/wire_server.hpp>

#include <raft/net_bind.hpp>

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace hsm = kythira::hsm;
using namespace kythira::hsm::test;  // NOLINT(google-build-using-namespace)

namespace {

/// A TCP server on loopback that writes its name to every connection,
/// then echoes what it reads, and can drop every connection at once.
class named_backend {
public:
    explicit named_backend(std::string name) : _name(std::move(name)) {
        const auto eps = kythira::net_bind::resolve_bind_addresses("127.0.0.1", "test backend");
        _fd = kythira::net_bind::open_listeners(eps, 0, "test backend").front();
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        ::getsockname(_fd, reinterpret_cast<sockaddr*>(&addr), &len);
        _port = ntohs(addr.sin_port);
        _thread = std::thread([this] { serve(); });
    }

    named_backend(const named_backend&) = delete;
    auto operator=(const named_backend&) -> named_backend& = delete;
    named_backend(named_backend&&) = delete;
    auto operator=(named_backend&&) -> named_backend& = delete;

    ~named_backend() {
        _stop = true;
        ::shutdown(_fd, SHUT_RDWR);
        drop_all();
        if (_thread.joinable()) {
            _thread.join();
        }
        for (auto& t : _conns) {
            t.join();
        }
        ::close(_fd);
    }

    [[nodiscard]] auto backend() const -> hsm::relay_backend { return {"127.0.0.1", _port}; }

    /// Close every connection this backend holds (a crash, as clients see it).
    auto drop_all() -> void {
        const std::lock_guard lock(_mutex);
        for (const int fd : _fds) {
            ::shutdown(fd, SHUT_RDWR);
        }
    }

private:
    auto serve() -> void {
        while (!_stop) {
            const int c = ::accept(_fd, nullptr, nullptr);
            if (c < 0) {
                return;
            }
            const std::lock_guard lock(_mutex);
            _fds.push_back(c);
            _conns.emplace_back([this, c] {
                (void)::send(c, _name.data(), _name.size(), MSG_NOSIGNAL);
                std::array<char, 256> buf{};
                for (;;) {
                    const auto n = ::recv(c, buf.data(), buf.size(), 0);
                    if (n <= 0) {
                        break;
                    }
                    (void)::send(c, buf.data(), static_cast<std::size_t>(n), MSG_NOSIGNAL);
                }
                ::close(c);
            });
        }
    }

    std::string _name;
    int _fd = -1;
    std::uint16_t _port = 0;
    std::atomic<bool> _stop{false};
    std::thread _thread;
    std::mutex _mutex;
    std::vector<int> _fds;
    std::vector<std::thread> _conns;
};

/// A client of the relay: connects and reads the backend's name.
struct client {
    int fd = -1;
    std::string backend;

    explicit client(std::uint16_t port) {
        fd = kythira::net_bind::connect_to("127.0.0.1", port, std::chrono::seconds{2});
        BOOST_REQUIRE(fd >= 0);
        backend = read_some();
    }
    client(const client&) = delete;
    auto operator=(const client&) -> client& = delete;
    client(client&&) = delete;
    auto operator=(client&&) -> client& = delete;
    ~client() { ::close(fd); }

    /// What arrives within two seconds; empty on EOF or a timeout.
    [[nodiscard]] auto read_some() const -> std::string {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 2000) <= 0) {
            return {};
        }
        std::array<char, 256> buf{};
        const auto n = ::recv(fd, buf.data(), buf.size(), 0);
        return n <= 0 ? std::string() : std::string(buf.data(), static_cast<std::size_t>(n));
    }

    /// True when the relay has closed this connection.
    [[nodiscard]] auto closed() const -> bool {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 2000) <= 0) {
            return false;
        }
        std::array<char, 16> buf{};
        return ::recv(fd, buf.data(), buf.size(), 0) <= 0;
    }

    [[nodiscard]] auto echo(const std::string& s) const -> std::string {
        (void)::send(fd, s.data(), s.size(), MSG_NOSIGNAL);
        return read_some();
    }
};

auto config(const std::vector<hsm::relay_backend>& backends) -> hsm::endpoint_relay_config {
    hsm::endpoint_relay_config cfg;
    cfg.bind_address = "127.0.0.1";
    cfg.port = 0;
    cfg.backends = backends;
    cfg.probe_interval = std::chrono::milliseconds{50};
    return cfg;
}

auto await(const std::function<bool()>& p) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline) {
        if (p()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return p();
}

auto non_owning(hsm::session_layer& layer) -> std::shared_ptr<hsm::session_layer> {
    return {&layer, [](hsm::session_layer*) {}};
}

}  // namespace

BOOST_AUTO_TEST_CASE(connections_are_pinned_and_spread_by_fewest_connections) {
    named_backend a("A");
    named_backend b("B");
    hsm::endpoint_relay relay(config({a.backend(), b.backend()}));
    relay.start();
    std::vector<std::unique_ptr<client>> clients;
    for (int i = 0; i < 4; ++i) {
        clients.push_back(std::make_unique<client>(relay.port()));
    }
    int on_a = 0;
    for (const auto& c : clients) {
        BOOST_TEST((c->backend == "A" || c->backend == "B"));
        on_a += c->backend == "A" ? 1 : 0;
        // Bytes go both ways, always to the same backend.
        BOOST_TEST(c->echo("ping") == "ping");
    }
    BOOST_TEST(on_a == 2);
    BOOST_TEST(relay.active(0) == 2U);
    BOOST_TEST(relay.active(1) == 2U);
    // A closed connection frees its slot: the next one goes there.
    const auto freed = clients.front()->backend;
    clients.erase(clients.begin());
    BOOST_REQUIRE(await([&] { return relay.active(freed == "A" ? 0 : 1) == 1U; }));
    client next(relay.port());
    BOOST_TEST(next.backend == freed);
    BOOST_TEST(relay.stats().accepted == 5U);
    BOOST_TEST(relay.stats().bytes_to_backends >= 16U);
}

BOOST_AUTO_TEST_CASE(an_unhealthy_backend_gets_nothing_and_loses_its_connections) {
    named_backend a("A");
    named_backend b("B");
    std::atomic<bool> a_healthy{true};
    auto cfg = config({a.backend(), b.backend()});
    cfg.healthy = [&](const hsm::relay_backend& be) {
        return be.port != a.backend().port || a_healthy.load();
    };
    hsm::endpoint_relay relay(cfg);
    relay.start();
    client first(relay.port());
    client second(relay.port());
    const auto& on_a = first.backend == "A" ? first : second;
    const auto& on_b = first.backend == "A" ? second : first;
    BOOST_REQUIRE(on_a.backend == "A");
    // A seals: its pinned connection is closed so the client reconnects,
    // and every new connection goes to B.
    a_healthy = false;
    BOOST_TEST(on_a.closed());
    BOOST_TEST(relay.stats().closed_unhealthy == 1U);
    BOOST_TEST(on_b.echo("still") == "still");
    for (int i = 0; i < 3; ++i) {
        client c(relay.port());
        BOOST_TEST(c.backend == "B");
    }
    a_healthy = true;
    BOOST_REQUIRE(await([&] { return relay.healthy(0); }));
    client back(relay.port());
    BOOST_TEST(back.backend == "A");  // fewest connections again
}

BOOST_AUTO_TEST_CASE(a_failed_backend_closes_its_clients_and_a_dead_one_is_skipped) {
    auto a = std::make_unique<named_backend>("A");
    named_backend b("B");
    hsm::endpoint_relay relay(config({a->backend(), b.backend()}));
    relay.start();
    client first(relay.port());
    client second(relay.port());
    const auto& on_a = first.backend == "A" ? first : second;
    a->drop_all();
    BOOST_TEST(on_a.closed());
    // Gone altogether: a connection to it fails, so the relay tries B.
    a.reset();
    for (int i = 0; i < 3; ++i) {
        client c(relay.port());
        BOOST_TEST(c.backend == "B");
    }
}

BOOST_AUTO_TEST_CASE(draining_keeps_connections_and_stops_new_ones) {
    named_backend a("A");
    named_backend b("B");
    hsm::endpoint_relay relay(config({a.backend(), b.backend()}));
    relay.start();
    client first(relay.port());
    const auto drained = first.backend == "A" ? 0U : 1U;
    relay.drain_backend(drained);
    for (int i = 0; i < 3; ++i) {
        client c(relay.port());
        BOOST_TEST(c.backend != first.backend);
    }
    BOOST_TEST(first.echo("kept") == "kept");
    // With every backend draining, a client is closed at once.
    relay.drain_backend(1 - drained);
    client none(relay.port());
    BOOST_TEST(none.backend.empty());
    BOOST_TEST(relay.stats().refused == 1U);
    // Draining the relay waits for the last connection to end.
    BOOST_TEST(!relay.drain(std::chrono::milliseconds{100}));
    ::shutdown(first.fd, SHUT_RDWR);
    BOOST_TEST(relay.drain(std::chrono::seconds{5}));
}

BOOST_AUTO_TEST_CASE(tls_passes_through_and_clients_reconnect_to_the_other_crypto_node) {
    // Two crypto nodes' wire servers over one store, as two crypto nodes
    // over one store layer would be; each with its own certificate.
    node n;
    test_pki pki;
    const auto server_files = pki.issue("crypto", "DNS:localhost,IP:127.0.0.1");
    const auto app = pki.issue("app", "URI:spiffe://test/app");
    BOOST_REQUIRE(n.propose_catalog(hsm::make_bind_command("spiffe://test/app", k_token)) ==
                  CKR_OK);
    auto serve = [&] {
        hsm::wire_server_config cfg;
        cfg.tls_port = 0;
        cfg.bind_address = "127.0.0.1";
        cfg.cert_path = server_files.cert;
        cfg.key_path = server_files.key;
        cfg.ca_path = pki.ca_path();
        auto s = std::make_unique<hsm::wire_server>(non_owning(n.layer), cfg);
        s->start();
        return s;
    };
    auto first = serve();
    auto second = serve();
    hsm::endpoint_relay relay(
        config({{"127.0.0.1", first->tls_port()}, {"127.0.0.1", second->tls_port()}}));
    relay.start();

    hsm::wire::tls_client_config tc;
    tc.host = "127.0.0.1";
    tc.port = relay.port();
    tc.cert_path = app.cert;
    tc.key_path = app.key;
    tc.ca_path = pki.ca_path();
    // The client checks the crypto node's certificate through the relay,
    // and the crypto node sees the client's own identity: the relay
    // terminated nothing.
    hsm::wire_client c(hsm::wire::connection::tls(tc, std::chrono::seconds{5}));
    BOOST_TEST(c.hello()->identity == "spiffe://test/app");
    auto s = c.open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    BOOST_REQUIRE(s.has_value());
    BOOST_REQUIRE(rv(c.login(*s, CKU_USER, k_user_pin)) == CKR_OK);
    hsm::attribute_map pub;
    pub.set_bool(CKA_TOKEN, true);
    pub.set_bytes(CKA_EC_PARAMS, k_p256);
    pub.set_bool(CKA_VERIFY, true);
    hsm::attribute_map priv;
    priv.set_bool(CKA_TOKEN, true);
    priv.set_bool(CKA_SIGN, true);
    const CK_MECHANISM gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    const auto pair = c.generate_key_pair(*s, gen, pub, priv);
    BOOST_REQUIRE(pair.has_value());
    const CK_MECHANISM ecdsa{CKM_ECDSA_SHA256, nullptr, 0};
    const std::vector<std::uint8_t> msg = {'h', 'i'};
    BOOST_REQUIRE(c.sign_init(*s, ecdsa, pair->second).has_value());
    BOOST_REQUIRE(c.sign(*s, msg).has_value());
    const auto pinned = relay.active(0) == 1U ? 0U : 1U;
    BOOST_REQUIRE(relay.active(pinned) == 1U);
    BOOST_TEST(relay.stats().bytes_to_clients > 0U);

    // The pinned crypto node goes away. The client's next exchange fails
    // (the library's cue to reconnect), and a new connection through the
    // relay reaches the other node, where it logs in and signs again.
    (pinned == 0 ? first : second).reset();
    BOOST_TEST(rv(c.get_slot_list()) == CKR_DEVICE_ERROR);
    BOOST_TEST(c.transport_failed());
    hsm::wire_client again(hsm::wire::connection::tls(tc, std::chrono::seconds{5}));
    BOOST_TEST(again.hello()->identity == "spiffe://test/app");
    BOOST_TEST(relay.active(1 - pinned) == 1U);
    auto s2 = again.open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    BOOST_REQUIRE(s2.has_value());
    const auto login = rv(again.login(*s2, CKU_USER, k_user_pin));
    BOOST_TEST((login == CKR_OK || login == CKR_USER_ALREADY_LOGGED_IN));
    BOOST_REQUIRE(again.sign_init(*s2, ecdsa, pair->second).has_value());
    BOOST_TEST(again.sign(*s2, msg).has_value());
}
