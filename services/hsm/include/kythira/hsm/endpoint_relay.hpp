// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The HSM's endpoint layer (.kiro/specs/hsm-independent-layers/ task 4,
// Requirement 6): a layer-4 relay in front of the crypto nodes' client
// listeners.
//
// Sessions belong to the connection that opened them (virtual HSM design,
// "Sessions are node-local"), so an endpoint node cannot answer PKCS#11
// itself without the crypto layer's state. It relays each client TCP
// connection whole to one crypto node instead, and never terminates the
// client's TLS: the client's certificate, its PINs and any key bytes in a
// C_UnwrapKey or C_CreateObject stay inside the TLS stream between the
// client and the crypto node, and the crypto node sees the client's own
// certificate as its identity (Requirement 6.1). The relay holds no key, no
// certificate and no share, so a compromised endpoint node exposes traffic
// metadata only.
//
//  - Placement. Each new connection goes to a crypto node that the health
//    check last found healthy (unsealed and answering) and that is not
//    draining, preferring the one with the fewest relayed connections, and
//    stays pinned to it for its life (Requirement 6.2). A crypto node that
//    refuses the connection is marked unhealthy until the next check and
//    the next one is tried. With none left the client's connection is
//    closed at once.
//  - Failure. When either side closes or fails, both are closed. A crypto
//    node the health check finds unhealthy (sealed, or not answering) has
//    its pinned connections closed too, by default: libkythira_pkcs11
//    reconnects and logs its sessions in again, as after any failover
//    (Requirement 6.3), and the new connection is placed on a healthy node.
//  - Drain. drain_backend() stops new placements on one crypto node and
//    leaves its connections alone, so an operator can take it out of
//    service as clients finish; drain() stops accepting altogether and
//    waits for the relayed connections to end.
//
// Unix-socket clients always talk to a crypto role in their own node
// (Requirement 6.4); this relay is TCP only. Any layer-4 load balancer may
// stand in for it (Requirement 6.5); what this one adds is health-aware
// pinning and drain.
//
// Each relayed connection has a thread, as each wire_server connection
// does: a PKCS#11 client holds its connection for its whole life.

#include <raft/net_bind.hpp>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::hsm {

/// A crypto node's client listener.
struct relay_backend {
    std::string host;
    std::uint16_t port = 9444;
};

struct endpoint_relay_config {
    /// Where clients connect; port 0 picks one (port() says which).
    std::string bind_address{"0.0.0.0"};
    std::uint16_t port{9444};
    std::vector<relay_backend> backends;
    /// Whether a crypto node is unsealed and answering. The module asks
    /// the node's status route; nothing means every backend is healthy
    /// unless a connection to it fails.
    std::function<bool(const relay_backend&)> healthy;
    /// Pause between health checks.
    std::chrono::milliseconds probe_interval{1000};
    /// The budget of one connection to a crypto node.
    std::chrono::milliseconds connect_timeout{2000};
    std::size_t max_connections{1024};
    /// Close a crypto node's pinned connections once it turns unhealthy.
    bool close_on_unhealthy{true};
};

struct endpoint_relay_stats {
    std::uint64_t accepted = 0;
    /// Connections closed at once: no healthy crypto node, or too many.
    std::uint64_t refused = 0;
    /// Connections closed because their crypto node turned unhealthy.
    std::uint64_t closed_unhealthy = 0;
    std::uint64_t bytes_to_backends = 0;
    std::uint64_t bytes_to_clients = 0;
};

class endpoint_relay {
public:
    explicit endpoint_relay(endpoint_relay_config config)
        : _cfg(std::move(config)), _state(_cfg.backends.size()) {
        if (_cfg.backends.empty()) {
            throw std::invalid_argument("endpoint_relay: no crypto nodes to relay to");
        }
    }

    endpoint_relay(const endpoint_relay&) = delete;
    auto operator=(const endpoint_relay&) -> endpoint_relay& = delete;
    endpoint_relay(endpoint_relay&&) = delete;
    auto operator=(endpoint_relay&&) -> endpoint_relay& = delete;

    ~endpoint_relay() { stop(); }

    /// Bind, run one health check, and start accepting.
    auto start() -> void {
        const std::lock_guard run(_run_mutex);
        if (_running) {
            return;
        }
        const auto endpoints =
            net_bind::resolve_bind_addresses(_cfg.bind_address, "hsm endpoint relay");
        _listeners = net_bind::open_listeners(endpoints, _cfg.port, "hsm endpoint relay");
        _port = bound_port(_listeners.front());
        if (::pipe(_wake.data()) != 0) {
            close_listeners();
            throw std::runtime_error("hsm endpoint relay: pipe()");
        }
        probe_now();
        _running = true;
        _accepting = true;
        _acceptor = std::thread([this] { accept_loop(); });
        _prober = std::thread([this] { probe_loop(); });
    }

    /// Stop accepting, close every relayed connection, and wait for them.
    auto stop() -> void {
        {
            const std::lock_guard run(_run_mutex);
            if (!_running) {
                return;
            }
            _running = false;
            _accepting = false;
        }
        wake();
        _probe_cv.notify_all();
        if (_acceptor.joinable()) {
            _acceptor.join();
        }
        if (_prober.joinable()) {
            _prober.join();
        }
        close_listeners();
        {
            const std::lock_guard lock(_mutex);
            for (auto& [id, c] : _conns) {
                ::shutdown(c.client, SHUT_RDWR);
                ::shutdown(c.backend, SHUT_RDWR);
            }
        }
        std::unique_lock lock(_mutex);
        _idle_cv.wait(lock, [this] { return _conns.empty(); });
        lock.unlock();
        for (auto fd : _wake) {
            if (fd >= 0) {
                ::close(fd);
            }
        }
        _wake = {-1, -1};
    }

    /// Stop accepting and wait up to `timeout` for the relayed connections
    /// to end on their own; true when they all did.
    auto drain(std::chrono::milliseconds timeout) -> bool {
        _accepting = false;
        wake();
        std::unique_lock lock(_mutex);
        return _idle_cv.wait_for(lock, timeout, [this] { return _conns.empty(); });
    }

    /// Stop (or resume) placing new connections on backend `index`; its
    /// relayed connections are left alone.
    auto drain_backend(std::size_t index, bool draining = true) -> void {
        const std::lock_guard lock(_mutex);
        _state.at(index).draining = draining;
    }

    /// Run the health check now (the prober does every probe_interval).
    auto probe_now() -> void {
        std::vector<bool> results;
        results.reserve(_cfg.backends.size());
        for (const auto& b : _cfg.backends) {
            bool ok = true;
            if (_cfg.healthy) {
                try {
                    ok = _cfg.healthy(b);
                } catch (const std::exception&) {
                    ok = false;
                }
            }
            results.push_back(ok);
        }
        const std::lock_guard lock(_mutex);
        for (std::size_t i = 0; i < results.size(); ++i) {
            const bool was = _state[i].healthy;
            _state[i].healthy = results[i];
            if (was && !results[i] && _cfg.close_on_unhealthy) {
                for (auto& [id, c] : _conns) {
                    if (c.backend_index == i && !c.closing) {
                        c.closing = true;
                        ++_stats.closed_unhealthy;
                        ::shutdown(c.client, SHUT_RDWR);
                        ::shutdown(c.backend, SHUT_RDWR);
                    }
                }
            }
        }
    }

    [[nodiscard]] auto port() const -> std::uint16_t { return _port; }

    /// Connections relayed to backend `index` now.
    [[nodiscard]] auto active(std::size_t index) const -> std::size_t {
        const std::lock_guard lock(_mutex);
        return _state.at(index).active;
    }

    [[nodiscard]] auto healthy(std::size_t index) const -> bool {
        const std::lock_guard lock(_mutex);
        return _state.at(index).healthy;
    }

    [[nodiscard]] auto stats() const -> endpoint_relay_stats {
        const std::lock_guard lock(_mutex);
        auto out = _stats;
        out.bytes_to_backends = _up.load(std::memory_order_relaxed);
        out.bytes_to_clients = _down.load(std::memory_order_relaxed);
        return out;
    }

private:
    struct backend_state {
        bool healthy = true;
        bool draining = false;
        std::size_t active = 0;
    };

    struct relayed {
        int client = -1;
        int backend = -1;
        std::size_t backend_index = 0;
        bool closing = false;
    };

    static auto bound_port(int fd) -> std::uint16_t {
        sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
        return ntohs(addr.ss_family == AF_INET6
                         ? reinterpret_cast<const sockaddr_in6&>(addr).sin6_port
                         : reinterpret_cast<const sockaddr_in&>(addr).sin_port);
    }

    auto close_listeners() -> void {
        for (const int fd : _listeners) {
            ::close(fd);
        }
        _listeners.clear();
    }

    auto wake() const -> void {
        if (_wake[1] >= 0) {
            const char b = 0;
            [[maybe_unused]] const auto n = ::write(_wake[1], &b, 1);
        }
    }

    auto accept_loop() -> void {
        std::vector<pollfd> fds;
        for (const int fd : _listeners) {
            fds.push_back({fd, POLLIN, 0});
        }
        fds.push_back({_wake[0], POLLIN, 0});
        while (_accepting) {
            for (auto& p : fds) {
                p.revents = 0;
            }
            if (::poll(fds.data(), fds.size(), -1) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return;
            }
            if (!_accepting) {
                return;
            }
            for (std::size_t i = 0; i + 1 < fds.size(); ++i) {
                if ((fds[i].revents & POLLIN) == 0) {
                    continue;
                }
                const int client = ::accept(fds[i].fd, nullptr, nullptr);
                if (client >= 0) {
                    place(client);
                }
            }
        }
    }

    /// The backend for a new connection: healthy, not draining, fewest
    /// connections; the round-robin cursor breaks ties. Nothing when none.
    auto choose(const std::vector<bool>& tried) -> std::optional<std::size_t> {
        std::optional<std::size_t> best;
        const auto n = _state.size();
        for (std::size_t k = 0; k < n; ++k) {
            const auto i = (_cursor + k) % n;
            const auto& s = _state[i];
            if (!s.healthy || s.draining || tried[i]) {
                continue;
            }
            if (!best || s.active < _state[*best].active) {
                best = i;
            }
        }
        if (best) {
            _cursor = (*best + 1) % n;
        }
        return best;
    }

    auto place(int client) -> void {
        int one = 1;
        ::setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        std::vector<bool> tried(_state.size(), false);
        for (;;) {
            std::optional<std::size_t> pick;
            {
                const std::lock_guard lock(_mutex);
                if (_conns.size() >= _cfg.max_connections) {
                    ++_stats.refused;
                    ::close(client);
                    return;
                }
                pick = choose(tried);
                if (!pick) {
                    ++_stats.refused;
                    ::close(client);
                    return;
                }
            }
            tried[*pick] = true;
            const auto& b = _cfg.backends[*pick];
            const int backend = net_bind::connect_to(b.host, b.port, _cfg.connect_timeout);
            if (backend < 0) {
                const std::lock_guard lock(_mutex);
                _state[*pick].healthy = false;  // until the next health check
                continue;
            }
            // connect_to leaves send and receive timeouts set; the relay
            // waits in poll() for as long as the client keeps the
            // connection, so clear them.
            timeval none{};
            ::setsockopt(backend, SOL_SOCKET, SO_SNDTIMEO, &none, sizeof(none));
            ::setsockopt(backend, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof(none));
            ::setsockopt(backend, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            std::uint64_t id = 0;
            {
                const std::lock_guard lock(_mutex);
                id = ++_next_id;
                _conns[id] = relayed{client, backend, *pick, false};
                ++_state[*pick].active;
                ++_stats.accepted;
            }
            std::thread([this, id, client, backend] { relay(id, client, backend); }).detach();
            return;
        }
    }

    /// Copies bytes both ways until either side closes or fails.
    auto relay(std::uint64_t id, int client, int backend) -> void {
        std::array<char, 16384> buf{};
        std::array<pollfd, 2> fds{{{client, POLLIN, 0}, {backend, POLLIN, 0}}};
        for (bool open = true; open;) {
            fds[0].revents = fds[1].revents = 0;
            if (::poll(fds.data(), fds.size(), -1) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            for (std::size_t i = 0; i < 2 && open; ++i) {
                if (fds[i].revents == 0) {
                    continue;
                }
                const int from = fds[i].fd;
                const int to = i == 0 ? backend : client;
                const auto n = ::recv(from, buf.data(), buf.size(), 0);
                if (n <= 0) {
                    open = false;
                    break;
                }
                if (!send_all(to, buf.data(), static_cast<std::size_t>(n))) {
                    open = false;
                    break;
                }
                (i == 0 ? _up : _down)
                    .fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
            }
        }
        const std::lock_guard lock(_mutex);
        const auto it = _conns.find(id);
        if (it != _conns.end()) {
            --_state[it->second.backend_index].active;
            _conns.erase(it);
        }
        ::close(client);
        ::close(backend);
        if (_conns.empty()) {
            _idle_cv.notify_all();
        }
    }

    static auto send_all(int fd, const char* data, std::size_t size) -> bool {
        while (size > 0) {
            const auto n = ::send(fd, data, size, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n <= 0) {
                return false;
            }
            data += n;
            size -= static_cast<std::size_t>(n);
        }
        return true;
    }

    auto probe_loop() -> void {
        std::unique_lock lock(_run_mutex);
        while (_running) {
            _probe_cv.wait_for(lock, _cfg.probe_interval, [this] { return !_running; });
            if (!_running) {
                return;
            }
            lock.unlock();
            probe_now();
            lock.lock();
        }
    }

    endpoint_relay_config _cfg;

    mutable std::mutex _mutex;
    std::vector<backend_state> _state;
    std::map<std::uint64_t, relayed> _conns;
    std::uint64_t _next_id = 0;
    std::size_t _cursor = 0;
    endpoint_relay_stats _stats;
    std::atomic<std::uint64_t> _up{0};
    std::atomic<std::uint64_t> _down{0};
    std::condition_variable _idle_cv;

    std::mutex _run_mutex;
    std::condition_variable _probe_cv;
    bool _running = false;
    std::atomic<bool> _accepting{false};
    std::vector<int> _listeners;
    std::array<int, 2> _wake{-1, -1};
    std::uint16_t _port = 0;
    std::thread _acceptor;
    std::thread _prober;
};

}  // namespace kythira::hsm
