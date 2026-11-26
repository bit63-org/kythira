// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_gateway_impl.hpp
/// @brief Definitions for redis_gateway (redis_gateway.hpp): the gateway
///        layer. The front end it extends is in redis_front_end_impl.hpp.

#include <raft/asio_listeners.hpp>
#include <kythira/redis/redis_front_end_impl.hpp>
#include <kythira/redis/redis_gateway.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <exception>
#include <map>
#include <set>
#include <span>
#include <sstream>
#include <system_error>
#include <thread>
#include <tuple>

namespace kythira {

// ─────────────────────────────────────────────────────────────────────────────
// connection
// ─────────────────────────────────────────────────────────────────────────────
/// One accepted socket, plaintext or TLS. Lives on an Asio strand for its
/// socket operations; command execution happens on the gateway's worker
/// pool, never on an I/O thread (see the threading note in redis_gateway.hpp).
template<typename Host, typename Logger, typename Metrics>
class redis_gateway<Host, Logger, Metrics>::connection
    : public std::enable_shared_from_this<redis_gateway<Host, Logger, Metrics>::connection> {
public:
    using tcp = boost::asio::ip::tcp;
    using ssl_stream = boost::asio::ssl::stream<tcp::socket>;

    connection(redis_gateway& gw, tcp::socket socket,
               std::shared_ptr<boost::asio::ssl::context> ssl_ctx)
        : _gw(gw), _strand(boost::asio::make_strand(gw._io)), _idle_timer(_strand) {
        boost::system::error_code ec;
        (void)socket.set_option(tcp::no_delay(true), ec);
        auto remote = socket.remote_endpoint(ec);
        if (!ec) {
            _session._rate_key = redis_auth_limiter::rate_key(remote.address());
            _session._source = remote.address().to_string() + ":" + std::to_string(remote.port());
        } else {
            _session._source = "unknown";
            _session._rate_key = "unknown";
        }
        if (ssl_ctx) {
            _ssl.emplace(std::move(socket), *ssl_ctx);
            _ssl_ctx = std::move(ssl_ctx);
        } else {
            _plain.emplace(std::move(socket));
        }
        _session._parser = resp_parser(gw._config._parser_limits);
        _session._conn_id = gw._next_conn_id.fetch_add(1);
        if (gw._config._allow_anonymous && gw._acl.empty()) {
            _session._identity = redis_identity{"anonymous", redis_role::admin, {""}};
        }
        _authenticated.store(_session._identity.has_value());
    }

    auto start() -> void {
        auto self = this->shared_from_this();
        boost::asio::post(_strand, [self] {
            if (self->_ssl) {
                self->do_handshake();
            } else {
                self->arm_idle();
                self->do_read();
            }
        });
    }

    /// Close from any thread; the work happens on the strand.
    auto close() -> void {
        auto self = this->shared_from_this();
        boost::asio::post(_strand, [self] { self->do_close(); });
    }

    [[nodiscard]] auto source() const -> const std::string& { return _session._source; }

    /// Nothing received is left to run or to send: no queued command, no
    /// worker on it, no reply bytes waiting. drain() waits for this.
    [[nodiscard]] auto idle() -> bool {
        std::lock_guard<std::mutex> lock(_mutex);
        return _closed || (_queue.empty() && !_busy && _out.empty() && _writing_bytes == 0);
    }

private:
    auto lowest() -> tcp::socket& { return _ssl ? _ssl->next_layer() : *_plain; }

    auto do_handshake() -> void {
        auto self = this->shared_from_this();
        arm_idle();
        _ssl->async_handshake(
            boost::asio::ssl::stream_base::server, [self](const boost::system::error_code& ec) {
                if (ec) {
                    self->_gw._logger.log(
                        log_level::debug, "redis gateway: tls handshake failed",
                        {{"source", self->_session._source}, {"error", ec.message()}});
                    self->do_close();
                    return;
                }
                self->map_client_certificate();
                self->do_read();
            });
    }

    /// mTLS: a verified client certificate's subject may name an ACL user, in
    /// which case the connection is authenticated before its first command.
    auto map_client_certificate() -> void {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        X509* cert = SSL_get1_peer_certificate(_ssl->native_handle());
#else
        X509* cert = SSL_get_peer_certificate(_ssl->native_handle());
#endif
        if (cert == nullptr) {
            return;
        }
        // Another node's layer identity (Requirement 19.1): the session is
        // internal, with that node's roles.
        if (_gw.accept_layer_identity(_session, cert)) {
            X509_free(cert);
            _authenticated.store(true);
            return;
        }
        std::string subject;
        if (BIO* bio = BIO_new(BIO_s_mem())) {
            X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_RFC2253);
            char* data = nullptr;
            long len = BIO_get_mem_data(bio, &data);
            if (len > 0 && data != nullptr) {
                subject.assign(data, static_cast<std::size_t>(len));
            }
            BIO_free(bio);
        }
        X509_free(cert);
        if (subject.empty()) {
            return;
        }
        if (auto id = _gw._acl.authenticate_certificate(subject)) {
            if (id->_user == _gw._config._internal_user) {
                if (auto refused = _gw.internal_auth_refusal(_session)) {
                    _gw.audit(_session, "TLS", "internal user's certificate refused");
                    return;
                }
                _session._peer_roles = _gw._config._insecure_plaintext
                                           ? k_redis_all_roles
                                           : layers::role_set{layers::role::data};
            }
            _session._identity = std::move(id);
            _session._internal = _session._identity->_user == _gw._config._internal_user;
            _authenticated.store(true);
            _gw.audit(_session, "TLS", "certificate accepted");
        } else {
            _gw.audit(_session, "TLS", "certificate subject not mapped");
        }
    }

    /// Strand only. One timer serves two deadlines: the idle timeout, pushed
    /// back by every read, and the expiry of a credential a verifier
    /// accepted (`_deadline_ns`), which nothing pushes back. It is armed for
    /// whichever comes first.
    auto arm_idle() -> void {
        using namespace std::chrono;
        std::optional<steady_clock::duration> wait;
        if (_gw._config._idle_timeout.count() > 0) {
            wait = _gw._config._idle_timeout;
        }
        bool for_deadline = false;
        if (auto d = _deadline_ns.load(); d != 0) {
            auto left =
                system_clock::time_point(duration_cast<system_clock::duration>(nanoseconds(d))) -
                system_clock::now();
            auto left_steady = std::max(steady_clock::duration::zero(),
                                        duration_cast<steady_clock::duration>(left));
            if (!wait || left_steady < *wait) {
                wait = left_steady;
                for_deadline = true;
            }
        }
        if (!wait) {
            _idle_timer.cancel();
            return;
        }
        auto self = this->shared_from_this();
        _idle_timer.expires_after(*wait);
        _idle_timer.async_wait([self, for_deadline](const boost::system::error_code& ec) {
            if (ec) {
                return;  // cancelled: activity, a new deadline, or close
            }
            if (for_deadline) {
                auto d = self->_deadline_ns.load();
                if (d == 0 || system_clock::now() <
                                  system_clock::time_point(
                                      duration_cast<system_clock::duration>(nanoseconds(d)))) {
                    // RESET or a new AUTH moved the deadline since: re-arm.
                    self->arm_idle();
                    return;
                }
                ++self->_gw._stats._credential_expiries;
                self->_gw._logger.log(log_level::info, "redis gateway: credential expired",
                                      {{"source", self->_session._source}});
                self->do_close();
                return;
            }
            self->_gw._logger.log(log_level::debug, "redis gateway: idle timeout",
                                  {{"source", self->_session._source}});
            self->do_close();
        });
    }

    auto do_read() -> void {
        if (_closed || _read_pending) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(_mutex);
            if (_parse_held) {
                // A pre-auth command is executing; the worker resumes us.
                return;
            }
            if (_queue.size() >= _gw._config._max_inflight_per_connection) {
                // Backpressure: leave the bytes in the kernel until the worker
                // has drained the queue; it re-posts do_read when it has.
                _paused = true;
                return;
            }
        }
        _read_pending = true;
        auto self = this->shared_from_this();
        auto handler = [self](const boost::system::error_code& ec, std::size_t n) {
            self->_read_pending = false;
            self->on_read(ec, n);
        };
        if (_ssl) {
            _ssl->async_read_some(boost::asio::buffer(_read_buffer),
                                  boost::asio::bind_executor(_strand, handler));
        } else {
            _plain->async_read_some(boost::asio::buffer(_read_buffer),
                                    boost::asio::bind_executor(_strand, handler));
        }
    }

    auto on_read(const boost::system::error_code& ec, std::size_t n) -> void {
        if (ec || _closed) {
            do_close();
            return;
        }
        arm_idle();
        _gw._stats._bytes_in += n;
        try {
            _session._parser.feed(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(_read_buffer.data()), n));
        } catch (const resp_protocol_error& e) {
            protocol_error(e);
            return;
        }
        if (drain_parser()) {
            kick();
            do_read();
        }
    }

    /// Redis closes on a protocol error; so do we, after saying why.
    auto protocol_error(const resp_protocol_error& e) -> void {
        queue_reply(_session._writer.error(std::string("ERR Protocol error: ") + e.what()));
        _session._closing = true;
        _close_after_flush = true;
        flush();
    }

    /// Strand only. Parse and queue what the parser holds. Before AUTH
    /// succeeds the parser runs under the small pre-auth limits and yields
    /// one command at a time: the next is not parsed (nor more bytes read)
    /// until the worker has executed this one, so a pipelined `AUTH` + large
    /// `SET` is parsed under the limits that apply once AUTH has run, as in
    /// Redis, which executes each command before parsing the next. Returns
    /// false after a protocol error.
    auto drain_parser() -> bool {
        bool authenticated = _authenticated.load();
        _session._parser.set_limits(authenticated
                                        ? _gw._config._parser_limits
                                        : resp_pre_auth_limits(_gw._config._parser_limits));
        try {
            while (true) {
                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    if (_parse_held) {
                        break;
                    }
                }
                auto cmd = _session._parser.next();
                if (!cmd.has_value()) {
                    break;
                }
                enqueue(std::move(*cmd), !authenticated);
            }
        } catch (const resp_protocol_error& e) {
            protocol_error(e);
            return false;
        }
        return true;
    }

    auto enqueue(resp_command cmd, bool hold) -> void {
        std::lock_guard<std::mutex> lock(_mutex);
        queued_command q;
        q._bytes = 0;
        for (const auto& a : cmd._argv) {
            q._bytes += a.size();
        }
        // Total in-flight memory bound (Requirement 13.5): shed with a
        // retryable error rather than queue past the budget. The reply
        // is queued in order so pipelining stays intact.
        auto before = _gw._inflight_bytes.fetch_add(q._bytes);
        if (before + q._bytes > _gw._config._max_inflight_bytes) {
            _gw._inflight_bytes.fetch_sub(q._bytes);
            q._bytes = 0;
            q._prebuilt =
                _session._writer.error("TRYAGAIN gateway is over its in-flight budget, retry");
            ++_gw._stats._shed;
        } else {
            q._cmd = std::move(cmd);
        }
        _queue.push_back(std::move(q));
        _parse_held = hold;
    }

    /// Bytes queued for the socket past which commands stop executing.
    /// Caller holds `_mutex`.
    [[nodiscard]] auto output_full_locked() const -> bool {
        auto limit = _authenticated.load() ? _gw._config._max_output_buffer_bytes
                                           : _gw._config._pre_auth_output_buffer_bytes;
        return _out.size() + _writing_bytes >= limit;
    }

    /// Hand the queue to a worker unless one already has it.
    auto kick() -> void {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            if (_busy || _queue.empty()) {
                return;
            }
            _busy = true;
        }
        auto self = this->shared_from_this();
        boost::asio::post(*_gw._workers, [self] { self->process(); });
    }

    /// Worker-pool job: execute queued commands in order until the queue is
    /// empty (or the client has stopped reading its replies), then hand the
    /// connection back to the I/O side.
    auto process() -> void {
        while (true) {
            queued_command q;
            bool stop = false;
            bool resume_read = false;
            bool resume_parse = false;
            {
                std::lock_guard<std::mutex> lock(_mutex);
                bool closing = _session._closing || _closed;
                bool blocked = !closing && !_queue.empty() && output_full_locked();
                if (_queue.empty() || closing || blocked) {
                    // Output backpressure: leave the queue as it is; the
                    // write completion kicks us once the client catches up.
                    // Until then a full queue keeps reads paused too.
                    _busy = false;
                    if (blocked && !_output_blocked) {
                        ++_gw._stats._output_stalls;
                    }
                    _output_blocked = blocked;
                    stop = true;
                    if (!closing && !blocked) {
                        resume_read = _paused;
                        _paused = false;
                        resume_parse = _parse_held;
                        _parse_held = false;
                    }
                } else {
                    q = std::move(_queue.front());
                    _queue.pop_front();
                    if (_paused && _queue.size() < _gw._config._max_inflight_per_connection) {
                        _paused = false;
                        resume_read = true;
                    }
                }
            }
            if (resume_read || resume_parse) {
                auto self = this->shared_from_this();
                boost::asio::post(_strand, [self, resume_parse] {
                    if (resume_parse && !self->drain_parser()) {
                        return;
                    }
                    self->kick();
                    self->do_read();
                });
            }
            if (stop) {
                return;
            }
            if (q._bytes != 0) {
                _gw._inflight_bytes.fetch_sub(q._bytes);
            }
            std::string reply;
            if (!q._prebuilt.empty()) {
                reply = std::move(q._prebuilt);
            } else {
                try {
                    reply = _gw.execute(_session, q._cmd);
                } catch (const std::exception& e) {
                    _gw._logger.log(log_level::error, "redis gateway: command failed",
                                    {{"error", e.what()}});
                    reply = _session._writer.error("ERR internal error");
                }
            }
            // AUTH, HELLO ... AUTH and RESET change this; the strand reads it
            // to pick parser limits only once this command has finished.
            _authenticated.store(_session._identity.has_value());
            // The same for a verifier's credential expiry: the strand re-arms
            // its timer for the new deadline.
            const std::int64_t deadline =
                _session._expires ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        _session._expires->time_since_epoch())
                                        .count()
                                  : 0;
            if (_deadline_ns.exchange(deadline) != deadline) {
                auto self = this->shared_from_this();
                boost::asio::post(_strand, [self] {
                    if (!self->_closed) {
                        self->arm_idle();
                    }
                });
            }
            if (!reply.empty()) {
                queue_reply(reply);
            }
            if (_session._closing) {
                _close_after_flush = true;
            }
            flush();
        }
    }

    auto queue_reply(std::string bytes) -> void {
        std::lock_guard<std::mutex> lock(_mutex);
        _out += bytes;
    }

    auto flush() -> void {
        auto self = this->shared_from_this();
        boost::asio::post(_strand, [self] { self->do_write(); });
    }

    auto do_write() -> void {
        if (_closed || _writing) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _writing_buffer.swap(_out);
            _out.clear();
            _writing_bytes = _writing_buffer.size();
        }
        if (_writing_buffer.empty()) {
            if (_close_after_flush) {
                do_close();
            }
            return;
        }
        _writing = true;
        auto self = this->shared_from_this();
        auto handler = [self](const boost::system::error_code& ec, std::size_t n) {
            self->_writing = false;
            self->_gw._stats._bytes_out += n;
            self->_writing_buffer.clear();
            bool unblocked = false;
            {
                std::lock_guard<std::mutex> lock(self->_mutex);
                self->_writing_bytes = 0;
                if (self->_output_blocked && !self->output_full_locked()) {
                    self->_output_blocked = false;
                    unblocked = true;
                }
            }
            if (ec) {
                self->do_close();
                return;
            }
            if (unblocked) {
                self->kick();
            }
            self->do_write();
        };
        if (_ssl) {
            boost::asio::async_write(*_ssl, boost::asio::buffer(_writing_buffer),
                                     boost::asio::bind_executor(_strand, handler));
        } else {
            boost::asio::async_write(*_plain, boost::asio::buffer(_writing_buffer),
                                     boost::asio::bind_executor(_strand, handler));
        }
    }

    auto do_close() -> void {
        if (_closed) {
            return;
        }
        _closed = true;
        boost::system::error_code ec;
        _idle_timer.cancel();
        if (_ssl) {
            (void)_ssl->next_layer().shutdown(tcp::socket::shutdown_both, ec);
            (void)_ssl->next_layer().close(ec);
        } else {
            (void)_plain->shutdown(tcp::socket::shutdown_both, ec);
            (void)_plain->close(ec);
        }
        std::size_t dropped = 0;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            for (const auto& q : _queue) {
                dropped += q._bytes;
            }
            _queue.clear();
        }
        if (dropped != 0) {
            _gw._inflight_bytes.fetch_sub(dropped);
        }
        --_gw._stats._connections_current;
        _gw.unregister_connection(this);
    }

    redis_gateway& _gw;
    boost::asio::strand<boost::asio::io_context::executor_type> _strand;
    std::optional<tcp::socket> _plain;
    std::optional<ssl_stream> _ssl;
    std::shared_ptr<boost::asio::ssl::context> _ssl_ctx;
    boost::asio::steady_timer _idle_timer;
    std::array<char, 64 * 1024> _read_buffer{};
    session _session;

    std::mutex _mutex;
    std::deque<queued_command> _queue;
    std::string _out;
    std::string _writing_buffer;
    /// Size of `_writing_buffer` while a write is in flight, readable under
    /// `_mutex` (the buffer itself belongs to the strand).
    std::size_t _writing_bytes = 0;
    bool _busy = false;
    bool _paused = false;
    /// The worker stopped because `_out` is over its cap.
    bool _output_blocked = false;
    /// Pre-auth: a parsed command is queued or executing; parse and read
    /// nothing more until it has run.
    bool _parse_held = false;
    /// Mirrors `_session._identity.has_value()` for the strand, which must
    /// not read the session while a worker executes against it.
    std::atomic<bool> _authenticated{false};
    /// Mirrors `_session._expires` for the strand's timer, as nanoseconds
    /// since the system clock's epoch; 0 when there is none.
    std::atomic<std::int64_t> _deadline_ns{0};
    bool _writing = false;
    bool _read_pending = false;
    bool _close_after_flush = false;
    std::atomic<bool> _closed{false};
};

// ─────────────────────────────────────────────────────────────────────────────
// lifecycle
// ─────────────────────────────────────────────────────────────────────────────

template<typename Host, typename Logger, typename Metrics>
redis_gateway<Host, Logger, Metrics>::redis_gateway(Host& host, redis_acl& acl, Logger& logger,
                                                    Metrics& metrics, redis_gateway_config config,
                                                    endpoint_resolver resolver)
    : front_end(host, acl, logger, metrics, std::move(config), std::move(resolver)),
      _auth_limiter(_config._auth_failure_limit, _config._auth_failure_window,
                    _config._max_concurrent_auth != 0
                        ? _config._max_concurrent_auth
                        : std::max<std::size_t>(1, _config._worker_threads / 2)) {}

template<typename Host, typename Logger, typename Metrics>
redis_gateway<Host, Logger, Metrics>::~redis_gateway() {
    stop();
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::start() -> void {
    if (_running.exchange(true)) {
        return;
    }
    if (!is_plain_redis_version(_config._redis_compat_version)) {
        // Requirement 1.5 (redis-general-data-types): clients parse this
        // field, and a suffix or a missing part breaks their parsers.
        _running = false;
        throw std::runtime_error("redis gateway: the Redis compatibility version '" +
                                 _config._redis_compat_version +
                                 "' is not a plain major.minor.patch (e.g. 7.0.0)");
    }
    if (auto why = this->layer_refusal()) {
        _running = false;
        throw std::runtime_error(*why);
    }
    if (_config._transactions) {
        // Requirement 11.1: refused unless the build wrapped the KV state
        // machine; Requirement 10.2: a level the build cannot give is an
        // error at startup, never a silent downgrade.
        if constexpr (!k_transactional) {
            _running = false;
            throw std::runtime_error(
                "redis gateway: --transactions on needs a build with the transaction adapter "
                "(CONFIG_REDIS_GATEWAY_TRANSACTIONS=y)");
        } else {
            const auto offered = coordinator_type::offered_isolations();
            if (std::find(offered.begin(), offered.end(), _config._txn_isolation) ==
                offered.end()) {
                _running = false;
                throw isolation_unsupported_exception(_config._txn_isolation, offered);
            }
            // The host's resolver reaches a primary this host does not lead
            // through the same forward link the coordinator uses.
            _data.host().set_txn_forwarder([this](const std::vector<std::string>& keys,
                                                  const std::vector<std::byte>& envelope,
                                                  std::chrono::milliseconds timeout) {
                return txn_send(keys, envelope, timeout);
            });
            if constexpr (k_snapshot) {
                // Under mvcc::on every plain write needs a commit timestamp;
                // a host that does not lead the oracle asks its leader's
                // gateway for one.
                _data.host().set_timestamp_forwarder(
                    [this](std::size_t n, std::chrono::milliseconds timeout) {
                        return txn_allocate_timestamps(n, timeout);
                    });
            }
        }
    }
    if (_acl.empty()) {
        if (!_config._allow_anonymous) {
            _running = false;
            throw std::runtime_error(
                "redis gateway: the ACL has no users and --allow-anonymous is not set; refusing "
                "to start an open cache");
        }
        _logger.log(log_level::warning,
                    "redis gateway: ACL is empty and --allow-anonymous is set; every connection is "
                    "admin with "
                    "access to every key");
    }
    if (_config._forwarding && _config._internal_secret.empty() &&
        redis_roles_colocated(_config._layer_roles)) {
        _logger.log(log_level::warning,
                    "redis gateway: forwarding is on but no internal secret is configured; "
                    "commands for a shard "
                    "led elsewhere will be answered with a retry error instead of forwarded");
    } else if (_config._forwarding && !_config._forward_tls &&
               !_config._allow_plaintext_forwarding && !_config._insecure_plaintext) {
        // Requirement 12.5: the internal identity is a read/write-everything
        // credential; it never crosses the network in the clear by default.
        _logger.log(log_level::warning,
                    "redis gateway: forwarding is on but neither TLS forwarding nor plaintext "
                    "forwarding is enabled; refusing to send the internal secret unencrypted, so "
                    "commands for a shard led elsewhere will be answered with a retry error");
    } else if (_config._forwarding && !_config._forward_tls) {
        _logger.log(log_level::warning,
                    "redis gateway: PLAINTEXT forwarding; the internal secret and forwarded "
                    "commands cross the network unencrypted");
    }
    _started_at = std::chrono::steady_clock::now();
    _io.restart();
    _work.emplace(boost::asio::make_work_guard(_io));
    _workers.emplace(std::max<std::size_t>(1, _config._worker_threads));

    auto bind = [&](const std::string& spec) {
        auto [host, port] = redis_gateway_detail::parse_listen(spec);
        return kythira::net_bind::open_asio_acceptors(_io, host.empty() ? "0.0.0.0" : host, port,
                                                      "redis gateway");
    };

    try {
        if (_config._forward_tls &&
            (!_config._internal_secret.empty() || !redis_roles_colocated(_config._layer_roles))) {
            const bool own_cert =
                !_config._forward_tls_cert_path.empty() || !_config._forward_tls_key_path.empty();
            const auto& cert = own_cert ? _config._forward_tls_cert_path : _config._tls_cert_path;
            {
                std::lock_guard<std::mutex> lock(_tls_mutex);
                _forward_ssl_ctx =
                    std::make_shared<boost::asio::ssl::context>(build_forward_ssl_context());
                this->_forward_tls_files._stamps = front_end::stamp_files(
                    {cert, own_cert ? _config._forward_tls_key_path : _config._tls_key_path,
                     _config._forward_tls_ca_path.empty() ? _config._tls_ca_path
                                                          : _config._forward_tls_ca_path});
                this->_forward_tls_files._checked = std::chrono::steady_clock::now();
                this->_own_identity =
                    redis_gateway_detail::identity_in_file(cert, _config._layer_cluster);
            }
            _logger.log(
                log_level::info, "redis gateway: forwarding over TLS",
                {{"ca", _config._forward_tls_ca_path.empty() ? _config._tls_ca_path
                                                             : _config._forward_tls_ca_path}});
        }
        if (!_config._listen.empty()) {
            _acceptors = bind(_config._listen);
            _port = _acceptors.front()->local_endpoint().port();
            // Requirement 12.6: a plaintext listener is announced once, loudly.
            _logger.log(log_level::warning,
                        "redis gateway: PLAINTEXT listener; AUTH secrets and values cross the "
                        "network unencrypted",
                        {{"listen", _config._listen}, {"port", std::to_string(_port)}});
        }
        if (!_config._tls_listen.empty()) {
            {
                std::lock_guard<std::mutex> lock(_tls_mutex);
                _ssl_ctx = std::make_shared<boost::asio::ssl::context>(build_ssl_context());
                _server_tls_files._stamps = front_end::stamp_files(
                    {_config._tls_cert_path, _config._tls_key_path, _config._tls_ca_path});
                _server_tls_files._checked = std::chrono::steady_clock::now();
            }
            _tls_acceptors = bind(_config._tls_listen);
            _tls_port = _tls_acceptors.front()->local_endpoint().port();
            _logger.log(log_level::info, "redis gateway: TLS listener",
                        {{"listen", _config._tls_listen},
                         {"port", std::to_string(_tls_port)},
                         {"client_cert", _config._require_client_cert ? "required" : "optional"}});
        }
    } catch (...) {
        _work.reset();
        _workers->join();
        _workers.reset();
        _acceptors.clear();
        _tls_acceptors.clear();
        {
            std::lock_guard<std::mutex> lock(_tls_mutex);
            _forward_ssl_ctx.reset();
        }
        _running = false;
        throw;
    }

    for (const auto& acceptor : _acceptors) {
        accept_loop(acceptor, false);
    }
    for (const auto& acceptor : _tls_acceptors) {
        accept_loop(acceptor, true);
    }
    for (std::size_t i = 0; i < std::max<std::size_t>(1, _config._io_threads); ++i) {
        _io_threads.emplace_back([this] { _io.run(); });
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::stop() -> void {
    if (!_running.exchange(false)) {
        return;
    }
    if constexpr (k_transactional) {
        if (_config._transactions) {
            _data.host().set_txn_forwarder({});
        }
    }
    boost::system::error_code ec;
    for (const auto& acceptor : _acceptors) {
        (void)acceptor->close(ec);
    }
    for (const auto& acceptor : _tls_acceptors) {
        (void)acceptor->close(ec);
    }
    std::vector<std::shared_ptr<connection>> live;
    {
        std::lock_guard<std::mutex> lock(_connections_mutex);
        for (auto& [ptr, weak] : _connections) {
            if (auto c = weak.lock()) {
                live.push_back(std::move(c));
            }
        }
    }
    for (auto& c : live) {
        c->close();
    }
    live.clear();
    // Workers first: a job mid-command holds its connection alive and may
    // post to the strand; once every job has returned the I/O side can wind
    // down knowing nothing will post to it again.
    if (_workers) {
        _workers->join();
        _workers.reset();
    }
    _work.reset();
    _io.stop();
    for (auto& t : _io_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    _io_threads.clear();
    _acceptors.clear();
    _tls_acceptors.clear();
    {
        std::lock_guard<std::mutex> lock(_connections_mutex);
        _connections.clear();
    }
    {
        std::lock_guard<std::mutex> lock(_forward_mutex);
        _forward_pools.clear();
    }
    {
        std::lock_guard<std::mutex> lock(_tls_mutex);
        _forward_ssl_ctx.reset();
        _ssl_ctx.reset();
        this->_own_identity.reset();
    }
    _port = 0;
    _tls_port = 0;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::build_ssl_context() -> boost::asio::ssl::context {
    namespace ssl = boost::asio::ssl;
    ssl::context ctx(ssl::context::tls_server);
    // TLS 1.2 floor, 1.3 preferred (Requirement 12.1).
    ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                    ssl::context::no_sslv3 | ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1 |
                    ssl::context::single_dh_use);
    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_2_VERSION);
    if (_config._tls_cert_path.empty() || _config._tls_key_path.empty()) {
        throw std::runtime_error("redis gateway: TLS listener needs both a certificate and a key");
    }
    ctx.use_certificate_chain_file(_config._tls_cert_path);
    ctx.use_private_key_file(_config._tls_key_path, ssl::context::pem);
    if (!_config._tls_ca_path.empty()) {
        ctx.load_verify_file(_config._tls_ca_path);
    }
    if (_config._require_client_cert) {
        ctx.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
    } else if (!_config._tls_ca_path.empty()) {
        ctx.set_verify_mode(ssl::verify_peer);
    } else {
        ctx.set_verify_mode(ssl::verify_none);
    }
    return ctx;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::accept_loop(
    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor, bool tls) -> void {
    auto& a = *acceptor;
    a.async_accept([this, acceptor = std::move(acceptor), tls](
                       const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
        if (ec) {
            if (ec != boost::asio::error::operation_aborted && _running.load()) {
                _logger.log(log_level::warning, "redis gateway: accept failed",
                            {{"error", ec.message()}});
                accept_loop(acceptor, tls);
            }
            return;
        }
        if (_stats._connections_current.load() >= _config._max_clients) {
            // Requirement 13.1: say why before closing.
            ++_stats._connections_rejected;
            boost::system::error_code ignored;
            (void)socket.non_blocking(true, ignored);
            static constexpr std::string_view reply = "-ERR max number of clients reached\r\n";
            socket.write_some(boost::asio::buffer(reply.data(), reply.size()), ignored);
            (void)socket.close(ignored);
            emit("redis.connections.rejected", "accept");
        } else {
            ++_stats._connections_accepted;
            ++_stats._connections_current;
            auto conn = std::make_shared<connection>(*this, std::move(socket),
                                                     tls ? server_tls_context() : nullptr);
            register_connection(conn);
            emit("redis.connections.accepted", "accept");
            conn->start();
        }
        if (_running.load()) {
            accept_loop(acceptor, tls);
        }
    });
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::register_connection(const std::shared_ptr<connection>& c)
    -> void {
    std::lock_guard<std::mutex> lock(_connections_mutex);
    _connections.emplace(c.get(), c);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::unregister_connection(connection* c) -> void {
    std::lock_guard<std::mutex> lock(_connections_mutex);
    _connections.erase(c);
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::execute_for_test(
    const resp_command& cmd, const std::optional<redis_identity>& identity, bool internal)
    -> std::string {
    session s;
    s._identity = identity;
    s._internal = internal;
    s._source = "test";
    s._rate_key = "test";
    return execute(s, cmd);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::execute(session& s, const resp_command& cmd)
    -> std::string {
    if (cmd._argv.empty()) {
        return {};
    }
    ++_stats._commands;
    const auto upper = resp_to_upper(cmd._argv[0]);
    const auto started = std::chrono::steady_clock::now();
    if (_config._log_commands) {
        // AUTH/HELLO arguments are secrets: never in a trace (Requirement 11.4).
        bool redact = upper == "AUTH" || upper == "HELLO";
        std::string args;
        for (std::size_t i = 1; i < cmd._argv.size() && i < 4; ++i) {
            args += redact ? " <redacted>" : " " + cmd._argv[i].substr(0, 64);
        }
        _logger.log(log_level::debug, "redis command",
                    {{"source", s._source}, {"command", upper}, {"args", args}});
    }
    auto arity = [&](std::size_t min, std::size_t max) -> std::optional<std::string> {
        if (cmd._argv.size() < min || cmd._argv.size() > max) {
            std::string lower = cmd._argv[0];
            for (auto& c : lower) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            return s._writer.error("ERR wrong number of arguments for '" + lower + "' command");
        }
        return std::nullopt;
    };
    auto finish = [&](std::string reply) {
        emit_duration("redis.command.latency", upper, std::chrono::steady_clock::now() - started);
        return reply;
    };

    // Pre-authentication surface: AUTH, HELLO, QUIT, RESET and nothing else.
    if (upper == "QUIT") {
        s._closing = true;
        return finish(s._writer.simple_string("OK"));
    }
    if (upper == "RESET") {
        s._in_multi = false;
        s._multi_failed = false;
        s._queued.clear();
        s._isolation.reset();
        s._identity.reset();
        s._internal = false;
        s._peer_roles.reset();
        s._expires.reset();
        s._writer.set_version(2);
        s._client_name.clear();
        if (_config._allow_anonymous && _acl.empty()) {
            s._identity = redis_identity{"anonymous", redis_role::admin, {""}};
        }
        return finish(s._writer.simple_string("RESET"));
    }
    if (upper == "AUTH") {
        return finish(handle_auth(s, cmd));
    }
    if (upper == "HELLO") {
        return finish(handle_hello(s, cmd));
    }
    if (s._expires && std::chrono::system_clock::now() >= *s._expires) {
        // The credential a verifier accepted has lapsed. The idle timer
        // closes a quiet connection at the deadline; this catches a command
        // that arrives first. The client must reconnect and AUTH afresh.
        ++_stats._credential_expiries;
        audit(s, upper, "credential expired");
        s._identity.reset();
        s._expires.reset();
        s._closing = true;
        return finish(s._writer.error("NOAUTH credential expired"));
    }
    if (!s._identity) {
        return finish(s._writer.error("NOAUTH Authentication required."));
    }

    if (upper == "CLIENT") {
        return finish(handle_client(s, cmd));
    }
    if (s._internal) {
        if (auto refused = this->peer_role_refusal(s, upper)) {
            return finish(std::move(*refused));
        }
        if (upper == "KYTHIRA.CALL") {
            return finish(this->handle_call(s, cmd));
        }
        if (this->remote_front_ends()) {
            return finish(s._writer.error("ERR this node runs no front end (KYTHIRA_REDIS_ROLES=" +
                                          _config._layer_roles.to_string() + ")"));
        }
        return finish(this->execute_command(s, upper, cmd));
    }
    if (upper == "KYTHIRA.CALL") {
        return finish(this->handle_call(s, cmd));  // refused: not a peer
    }
    if (this->serves_no_clients() && upper != "PING") {
        // A node without a gateway serves other nodes' calls and the
        // commands they forward, never clients (tasks 16, 17): its listener
        // is only the internal listener.
        return finish(s._writer.error("ERR this node runs no gateway (KYTHIRA_REDIS_ROLES=" +
                                      _config._layer_roles.to_string() +
                                      "); connect to a gateway"));
    }
    if (this->remote_front_ends()) {
        return finish(call_front_end(s, upper, cmd));
    }
    return finish(this->execute_command(s, upper, cmd));
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::admit_auth(session& s) -> std::optional<std::string> {
    // Admission is decided, and the attempt charged, before the KDF runs.
    switch (_auth_limiter.begin(s._rate_key)) {
        case redis_auth_limiter::verdict::allowed:
            return std::nullopt;
        case redis_auth_limiter::verdict::rate_limited:
            ++_stats._auth_failures;
            emit("redis.auth.failures", "AUTH");
            audit(s, "AUTH", "rate limited");
            return s._writer.error(
                "ERR too many authentication failures from this address, retry later");
        case redis_auth_limiter::verdict::busy:
            break;
    }
    ++_stats._auth_busy;
    emit("redis.auth.busy", "AUTH");
    audit(s, "AUTH", "too many concurrent attempts");
    return s._writer.error("ERR too many concurrent authentication attempts, retry later");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::handle_auth(session& s, const resp_command& cmd)
    -> std::string {
    if (cmd._argv.size() != 2 && cmd._argv.size() != 3) {
        return s._writer.error("ERR wrong number of arguments for 'auth' command");
    }
    // `AUTH password` is the pre-ACL form; it authenticates the `default` user.
    std::string user = cmd._argv.size() == 3 ? cmd._argv[1] : "default";
    const auto& secret = cmd._argv.back();
    if (_config._credential_verifier && _config._credential_verifier_users &&
        _config._credential_verifier_users(user)) {
        return auth_with_verifier(s, user, secret);
    }
    if (auto refused = admit_auth(s)) {
        return std::move(*refused);
    }
    std::optional<redis_identity> id;
    try {
        id = _acl.authenticate(user, secret);
    } catch (...) {
        _auth_limiter.finish(s._rate_key, false);
        throw;
    }
    _auth_limiter.finish(s._rate_key, id.has_value());
    if (!id) {
        ++_stats._auth_failures;
        emit("redis.auth.failures", "AUTH");
        audit(s, "AUTH", "rejected user '" + user + "'");
        // Identical for unknown user and wrong password (Requirement 10.4).
        return s._writer.error("WRONGPASS invalid username-password pair or user is disabled.");
    }
    if (id->_user == _config._internal_user) {
        if (auto refused = internal_auth_refusal(s)) {
            return std::move(*refused);
        }
        // A layer identity already says which roles the caller has; the
        // secret alone implies `data`, so it can never make an
        // authenticated call (design "Internal protocol") unless the node
        // runs insecure plaintext, where it stands in for every role.
        if (!s._peer_roles) {
            s._peer_roles = _config._insecure_plaintext ? k_redis_all_roles
                                                        : layers::role_set{layers::role::data};
        }
    }
    s._identity = std::move(id);
    s._internal = s._identity->_user == _config._internal_user;
    s._expires.reset();
    audit(s, "AUTH", "accepted");
    return s._writer.simple_string("OK");
}

/// The credential verifier's half of AUTH (design "Authentication seam").
/// It runs on the worker that executes the connection's commands, never on
/// the I/O strand, so a verifier that answers slowly holds this connection
/// (and one auth slot) and nothing else. Admission, the failure budget and
/// the reply to a refused credential are the password path's.
template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::auth_with_verifier(session& s, const std::string& user,
                                                              const std::string& credential)
    -> std::string {
    const auto wrongpass = [&](const std::string& why) {
        ++_stats._auth_failures;
        emit("redis.auth.failures", "AUTH");
        audit(s, "AUTH", "rejected user '" + user + "': " + why);
        return s._writer.error("WRONGPASS invalid username-password pair or user is disabled.");
    };
    if (auto refused = admit_auth(s)) {
        return std::move(*refused);
    }
    // The ACL still decides who the user is and what it may do. The internal
    // user is never vouched for from outside: forwarded links authenticate
    // with its secret (IAM Requirement 13.7).
    auto id = _acl.identity_of(user);
    if (!id || user == _config._internal_user) {
        _auth_limiter.finish(s._rate_key, false);
        return wrongpass("not an enabled ACL user");
    }
    credential_result result;
    try {
        auto f = _config._credential_verifier(
            credential_request{"redis", user, credential, s._rate_key});
        if (!f.wait(_config._command_timeout)) {
            // The verifier's delay, not the client's guess: refund it.
            _auth_limiter.finish(s._rate_key, true);
            audit(s, "AUTH", "credential verifier timed out");
            return s._writer.error("ERR authentication timed out, retry later");
        }
        result = std::move(f).get();
    } catch (...) {
        _auth_limiter.finish(s._rate_key, false);
        throw;
    }
    if (const auto* denied = std::get_if<credential_denied>(&result)) {
        // An `auth=both` user may still be sending its password: try it in
        // the same admission slot, after the cheap verifier said no.
        if (_acl.auth_mode_of(user) == redis_auth_mode::both) {
            std::optional<redis_identity> by_password;
            try {
                by_password = _acl.authenticate(user, credential);
            } catch (...) {
                _auth_limiter.finish(s._rate_key, false);
                throw;
            }
            if (by_password) {
                _auth_limiter.finish(s._rate_key, true);
                s._identity = std::move(by_password);
                s._internal = false;
                s._expires.reset();
                audit(s, "AUTH", "accepted by password");
                return s._writer.simple_string("OK");
            }
        }
        _auth_limiter.finish(s._rate_key, false);
        return wrongpass(denied->reason);
    }
    auto& accepted = std::get<credential_accepted>(result);
    if (accepted.expires <= std::chrono::system_clock::now()) {
        _auth_limiter.finish(s._rate_key, false);
        return wrongpass("credential already expired");
    }
    _auth_limiter.finish(s._rate_key, true);
    s._identity = std::move(id);
    s._internal = false;
    s._expires = accepted.expires;
    audit(s, "AUTH", "accepted by credential verifier as '" + accepted.principal + "'");
    return s._writer.simple_string("OK");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::handle_hello(session& s, const resp_command& cmd)
    -> std::string {
    // HELLO [protover [AUTH username password] [SETNAME clientname]]
    int version = s._writer.version();
    std::size_t i = 1;
    if (cmd._argv.size() > 1) {
        const auto& v = cmd._argv[1];
        if (v == "2") {
            version = 2;
        } else if (v == "3") {
            version = 3;
        } else {
            return s._writer.error("NOPROTO unsupported protocol version");
        }
        i = 2;
    }
    std::optional<std::pair<std::string, std::string>> auth;
    std::optional<std::string> setname;
    while (i < cmd._argv.size()) {
        auto opt = resp_to_upper(cmd._argv[i]);
        if (opt == "AUTH" && i + 2 < cmd._argv.size()) {
            auth = std::make_pair(cmd._argv[i + 1], cmd._argv[i + 2]);
            i += 3;
        } else if (opt == "SETNAME" && i + 1 < cmd._argv.size()) {
            setname = cmd._argv[i + 1];
            i += 2;
        } else {
            return s._writer.error("ERR Syntax error in HELLO option '" + cmd._argv[i] + "'");
        }
    }
    if (auth) {
        resp_command a;
        a._argv = {"AUTH", auth->first, auth->second};
        auto reply = handle_auth(s, a);
        if (reply.rfind('-', 0) == 0) {
            return reply;
        }
    }
    if (!s._identity) {
        return s._writer.error("NOAUTH Authentication required.");
    }
    if (setname) {
        s._client_name = *setname;
    }
    s._writer.set_version(version);
    resp_writer& w = s._writer;
    return w.map({{"server", w.bulk("kythira")},
                  {"version", w.bulk(_config._redis_compat_version)},
                  {"kythira_version", w.bulk(_config._kythira_version)},
                  {"proto", w.integer(version)},
                  {"id", w.integer(0)},
                  {"mode", w.bulk(server_mode())},
                  {"role", w.bulk("master")},
                  {"modules", w.array({})}});
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::handle_client(session& s, const resp_command& cmd)
    -> std::string {
    if (auto e = authorize(s, "CLIENT", {})) {
        return *e;
    }
    if (cmd._argv.size() < 2) {
        return s._writer.error("ERR wrong number of arguments for 'client' command");
    }
    auto sub = resp_to_upper(cmd._argv[1]);
    if (sub == "SETINFO") {
        if (cmd._argv.size() != 4) {
            return s._writer.error("ERR wrong number of arguments for 'client|setinfo' command");
        }
        auto attr = resp_to_upper(cmd._argv[2]);
        if (attr == "LIB-NAME") {
            s._lib_name = cmd._argv[3];
        } else if (attr == "LIB-VER") {
            s._lib_version = cmd._argv[3];
        } else {
            return s._writer.error("ERR Unrecognized option '" + cmd._argv[2] + "'");
        }
        return s._writer.simple_string("OK");
    }
    if (sub == "SETNAME") {
        if (cmd._argv.size() != 3) {
            return s._writer.error("ERR wrong number of arguments for 'client|setname' command");
        }
        s._client_name = cmd._argv[2];
        return s._writer.simple_string("OK");
    }
    if (sub == "GETNAME") {
        return s._client_name.empty() ? s._writer.null() : s._writer.bulk(s._client_name);
    }
    if (sub == "ID") {
        return s._writer.integer(0);
    }
    return s._writer.error("ERR unknown subcommand '" + cmd._argv[1] + "'. Try CLIENT HELP.");
}

// ─────────────────────────────────────────────────────────────────────────────
// layers: identities, remote front ends, rotation, drain (task 17)
// ─────────────────────────────────────────────────────────────────────────────

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::internal_auth_refusal(const session& s)
    -> std::optional<std::string> {
    if (_config._insecure_plaintext) {
        return std::nullopt;
    }
    std::string why;
    if (s._peer_roles && !redis_roles_colocated(*s._peer_roles)) {
        why = "the caller's layer identity names roles=" + s._peer_roles->to_string() +
              ", and the internal secret is accepted only between co-located nodes";
    } else if (!redis_roles_colocated(_config._layer_roles)) {
        why =
            "this node is not co-located (KYTHIRA_REDIS_ROLES=" + _config._layer_roles.to_string() +
            "); other nodes call it with their layer identity, never the internal secret";
    } else {
        return std::nullopt;
    }
    // Requirement 19.3.
    ++_stats._auth_failures;
    emit("redis.auth.failures", "AUTH");
    audit(const_cast<session&>(s), "AUTH", "internal secret refused: " + why);
    return s._writer.error("NOPERM " + why);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::accept_layer_identity(session& s, X509* cert) -> bool {
    auto id =
        layers::find_identity(layers::certificate_uri_sans(cert), "redis", _config._layer_cluster);
    if (!id) {
        return false;
    }
    // A peer's commands run with the internal user's scope, as a co-located
    // peer's do after AUTH; its roles decide which internal commands it may
    // send (peer_role_refusal).
    auto acl_id = _acl.identity_of(_config._internal_user);
    s._identity = acl_id ? std::move(*acl_id)
                         : redis_identity{_config._internal_user, redis_role::read_write, {""}};
    s._internal = true;
    s._peer_roles = id->roles;
    audit(s, "TLS", "layer identity " + id->to_uri());
    return true;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::server_tls_context()
    -> std::shared_ptr<boost::asio::ssl::context> {
    std::lock_guard<std::mutex> lock(_tls_mutex);
    const auto now = std::chrono::steady_clock::now();
    if (!_ssl_ctx || now - _server_tls_files._checked < _config._tls_reload_interval) {
        return _ssl_ctx;
    }
    _server_tls_files._checked = now;
    auto stamps = front_end::stamp_files(
        {_config._tls_cert_path, _config._tls_key_path, _config._tls_ca_path});
    if (stamps == _server_tls_files._stamps) {
        return _ssl_ctx;
    }
    // Requirement 19.5: connections accepted from now on present the new
    // certificate and trust the new CA; open ones keep their session.
    try {
        _ssl_ctx = std::make_shared<boost::asio::ssl::context>(build_ssl_context());
        _server_tls_files._stamps = std::move(stamps);
        _logger.log(log_level::info, "redis gateway: listener certificate reloaded", {});
    } catch (const std::exception& e) {
        _logger.log(log_level::warning, "redis gateway: listener certificate reload failed",
                    {{"error", e.what()}});
    }
    return _ssl_ctx;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::drain() -> void {
    if (!_running.load()) {
        return;
    }
    boost::system::error_code ec;
    for (const auto& acceptor : _acceptors) {
        (void)acceptor->close(ec);
    }
    for (const auto& acceptor : _tls_acceptors) {
        (void)acceptor->close(ec);
    }
    _logger.log(log_level::info, "redis gateway: draining",
                {{"timeout_ms", std::to_string(_config._drain_timeout.count())}});
    const auto deadline = std::chrono::steady_clock::now() + _config._drain_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        std::vector<std::shared_ptr<connection>> live;
        {
            std::lock_guard<std::mutex> lock(_connections_mutex);
            for (auto& [ptr, weak] : _connections) {
                if (auto c = weak.lock()) {
                    live.push_back(std::move(c));
                }
            }
        }
        if (std::all_of(live.begin(), live.end(), [](const auto& c) { return c->idle(); })) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    stop();
}

namespace redis_gateway_detail {

/// FNV-1a: stable across processes and builds, unlike std::hash, so a
/// connection's front end does not depend on which gateway binary runs.
inline auto fnv1a(std::string_view bytes, std::uint64_t h = 1469598103934665603ULL)
    -> std::uint64_t {
    for (const char c : bytes) {
        h ^= static_cast<unsigned char>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

/// The payload of one RESP bulk string reply, or nullopt for anything else.
inline auto bulk_payload(std::string_view reply) -> std::optional<std::string_view> {
    if (reply.size() < 4 || reply.front() != '$') {
        return std::nullopt;
    }
    const auto eol = reply.find("\r\n");
    if (eol == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t n = 0;
    const auto* first = reply.data() + 1;
    const auto* last = reply.data() + eol;
    const auto [end, ec] = std::from_chars(first, last, n);
    if (ec != std::errc{} || end != last || reply.size() != eol + 2 + n + 2 ||
        reply.substr(eol + 2 + n) != "\r\n") {
        return std::nullopt;
    }
    return reply.substr(eol + 2, n);
}

}  // namespace redis_gateway_detail

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::mark_front_end_down(const std::string& endpoint)
    -> void {
    std::lock_guard<std::mutex> lock(_front_end_mutex);
    // Long enough that the connections pinned to it move on together, short
    // enough that a restarted front end gets new connections soon.
    _front_end_down[endpoint] = std::chrono::steady_clock::now() +
                                std::max(std::chrono::milliseconds{1000}, _config._command_timeout);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::pick_front_end(const session& s)
    -> std::optional<std::string> {
    std::vector<std::string> live;
    {
        std::lock_guard<std::mutex> lock(_front_end_mutex);
        const auto now = std::chrono::steady_clock::now();
        for (const auto& fe : _config._front_ends) {
            auto it = _front_end_down.find(fe);
            if (it == _front_end_down.end() || it->second <= now) {
                live.push_back(fe);
            }
        }
    }
    if (live.empty()) {
        // Every front end failed lately: try them anyway rather than refuse.
        live = _config._front_ends;
    }
    if (live.empty()) {
        return std::nullopt;
    }
    if (!s._pinned.empty() && std::find(live.begin(), live.end(), s._pinned) != live.end()) {
        return s._pinned;
    }
    // Rendezvous hashing: a connection keeps its front end while that one
    // lives, and only the connections of a front end that leaves move.
    const auto id = std::to_string(s._conn_id);
    std::string best;
    std::uint64_t best_score = 0;
    for (const auto& fe : live) {
        const auto score = redis_gateway_detail::fnv1a(fe, redis_gateway_detail::fnv1a(id));
        if (best.empty() || score > best_score) {
            best = fe;
            best_score = score;
        }
    }
    return best;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_gateway<Host, Logger, Metrics>::call_front_end(session& s, std::string_view upper,
                                                          const resp_command& cmd) -> std::string {
    redis_call_wire::call_state state;
    state.user = s._identity->_user;
    state.resp_version = static_cast<std::uint8_t>(s._writer.version());
    if (s._isolation) {
        state.isolation = static_cast<std::uint8_t>(*s._isolation);
    }
    state.in_multi = s._in_multi;
    state.multi_failed = s._multi_failed;
    state.watch_ts = s._watch_ts;
    state.watched.assign(s._watched.begin(), s._watched.end());
    if (upper == "EXEC") {
        // The queue travels whole, once, with EXEC (design "Connection
        // state on a split gateway").
        for (const auto& q : s._queued) {
            state.queued.push_back(q._argv);
        }
    }
    std::vector<std::string> argv;
    argv.reserve(cmd._argv.size() + 2);
    argv.emplace_back("KYTHIRA.CALL");
    argv.push_back(redis_call_wire::encode_state(state));
    argv.insert(argv.end(), cmd._argv.begin(), cmd._argv.end());

    for (std::size_t attempt = 0; attempt < std::max<std::size_t>(1, _config._front_ends.size());
         ++attempt) {
        auto fe = pick_front_end(s);
        if (!fe) {
            break;
        }
        if (s._pinned != *fe) {
            if (!s._pinned.empty()) {
                ++_stats._front_end_repins;
                emit("redis.front_end.repins", upper);
            }
            s._pinned = *fe;
        }
        ++_stats._front_end_calls;
        emit("redis.front_end.calls", upper);
        // The front end bounds each step of the command by the command
        // timeout, and a transaction takes several: give it room, so a slow
        // answer is not mistaken for a lost front end.
        auto r = this->exchange(argv, *fe, _config._command_timeout * 3);
        using kind = typename front_end::exchange_result::kind;
        if (r._kind == kind::not_sent) {
            // Nothing left this gateway: another front end may run it.
            _logger.log(log_level::warning, "redis gateway: front end unreachable",
                        {{"front_end", *fe}, {"error", r._error}});
            // Still the pin, so the move to the next one counts as a re-pin.
            mark_front_end_down(*fe);
            continue;
        }
        if (r._kind == kind::lost) {
            // The front end may have run it: never replay (Requirement
            // 17.2). The connection moves on at its next command.
            _logger.log(log_level::warning, "redis gateway: front end lost mid-call",
                        {{"front_end", *fe}, {"error", r._error}});
            mark_front_end_down(*fe);
            ++_stats._front_end_lost;
            if (s._in_multi) {
                s._multi_failed = true;
            }
            return s._writer.error("ERR outcome unknown, front end lost; it may have applied");
        }
        if (!r._reply.empty() && r._reply.front() == '-') {
            return std::move(r._reply);  // the front end refused the call itself
        }
        const auto payload = redis_gateway_detail::bulk_payload(r._reply);
        auto answer = payload ? redis_call_wire::decode_answer(*payload) : std::nullopt;
        if (!answer) {
            _logger.log(log_level::warning, "redis gateway: malformed answer from front end",
                        {{"front_end", *fe}});
            return s._writer.error("ERR malformed answer from front end " + *fe);
        }
        if (answer->state.isolation) {
            s._isolation = static_cast<txn_isolation>(*answer->state.isolation);
        } else {
            s._isolation.reset();
        }
        s._in_multi = answer->state.in_multi;
        s._multi_failed = answer->state.multi_failed;
        s._watch_ts = answer->state.watch_ts;
        s._watched =
            std::set<std::string>(answer->state.watched.begin(), answer->state.watched.end());
        if (answer->queued) {
            s._queued.push_back(cmd);
        }
        if (!s._in_multi) {
            s._queued.clear();
        }
        return std::move(answer->reply);
    }
    return s._writer.error("TRYAGAIN no front end reachable, retry");
}

}  // namespace kythira
