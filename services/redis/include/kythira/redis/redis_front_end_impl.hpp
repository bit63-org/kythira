// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_front_end_impl.hpp
/// @brief Definitions for redis_front_end (redis_gateway.hpp): the front-end
///        layer, everything a command does past the gateway's
///        authentication (.kiro/specs/redis-general-data-types/ task 15).

#include <raft/asio_listeners.hpp>
#include <kythira/redis/redis_gateway.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <span>
#include <sstream>
#include <system_error>
#include <thread>
#include <tuple>

namespace kythira {

namespace redis_gateway_detail {

inline auto parse_listen(const std::string& spec) -> std::pair<std::string, std::uint16_t> {
    auto colon = spec.rfind(':');
    if (colon == std::string::npos) {
        throw std::invalid_argument("listen address must be host:port, got '" + spec + "'");
    }
    auto host = spec.substr(0, colon);
    auto port_text = spec.substr(colon + 1);
    if (!host.empty() && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    int port = std::stoi(port_text);
    if (port < 0 || port > 65535) {
        throw std::invalid_argument("listen port out of range: " + port_text);
    }
    return {host, static_cast<std::uint16_t>(port)};
}

inline auto to_bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    if (!s.empty()) {
        std::memcpy(out.data(), s.data(), s.size());
    }
    return out;
}

inline auto to_string(const std::vector<std::byte>& b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

/// One reply from a peer gateway, as far as `KYTHIRA.TXN` needs: a bulk
/// string (the payload), a null, or an error (its text, without the `-`).
struct peer_reply {
    enum class kind : std::uint8_t {
        bulk,
        null,
        error,
        other
    } _kind{kind::other};
    std::string _body;
};

inline auto parse_peer_reply(const std::string& reply) -> peer_reply {
    if (reply.empty()) {
        return {};
    }
    const auto crlf = reply.find("\r\n");
    if (crlf == std::string::npos) {
        return {};
    }
    if (reply[0] == '-') {
        return {peer_reply::kind::error, reply.substr(1, crlf - 1)};
    }
    if (reply[0] == '_' || reply.rfind("$-1", 0) == 0) {
        return {peer_reply::kind::null, {}};
    }
    if (reply[0] == '$') {
        const auto len = std::stoull(reply.substr(1, crlf - 1));
        if (reply.size() < crlf + 2 + len) {
            return {};
        }
        return {peer_reply::kind::bulk, reply.substr(crlf + 2, len)};
    }
    return {};
}

/// A peer gateway refused a transaction op because its shard no longer owns
/// every key: the coordinator should re-partition and resend.
class txn_moved_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

inline auto put_u32(std::string& out, std::uint32_t v) -> void {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((v >> shift) & 0xFFU));
    }
}

inline auto put_u64(std::string& out, std::uint64_t v) -> void {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((v >> shift) & 0xFFU));
    }
}

/// Reads the encoding `encode_txn_read` writes; throws on a short buffer.
class txn_read_cursor {
public:
    explicit txn_read_cursor(std::string_view in) : _in(in) {}
    auto u8() -> std::uint8_t { return static_cast<std::uint8_t>(take(1)[0]); }
    auto u32() -> std::uint32_t { return static_cast<std::uint32_t>(be(take(4))); }
    auto u64() -> std::uint64_t { return be(take(8)); }
    auto str() -> std::string { return std::string(take(u32())); }
    [[nodiscard]] auto empty() const -> bool { return _in.empty(); }
    [[nodiscard]] auto peek() const -> std::uint8_t {
        return _in.empty() ? 0 : static_cast<std::uint8_t>(_in[0]);
    }
    /// Everything not read yet; the cursor is then empty.
    auto rest() -> std::string_view { return take(_in.size()); }

private:
    auto take(std::size_t n) -> std::string_view {
        if (_in.size() < n) {
            throw std::runtime_error("truncated KYTHIRA.TXN READ reply");
        }
        auto out = _in.substr(0, n);
        _in.remove_prefix(n);
        return out;
    }
    static auto be(std::string_view b) -> std::uint64_t {
        std::uint64_t v = 0;
        for (char c : b) {
            v = (v << 8) | static_cast<unsigned char>(c);
        }
        return v;
    }
    std::string_view _in;
};

/// The `KYTHIRA.TXN TS` reply body: the range's first timestamp and count.
inline auto encode_timestamp_range(const timestamp_range& r) -> std::string {
    std::string out;
    put_u64(out, r._first);
    put_u64(out, r._count);
    return out;
}

inline auto decode_timestamp_range(std::string_view in) -> timestamp_range {
    txn_read_cursor c(in);
    timestamp_range r;
    r._first = c.u64();
    r._count = c.u64();
    return r;
}

/// A peer's `KYTHIRA.TXN READAT` refusal below its shard's safe point:
/// `KYTHIRA.TOOOLD <start_ts> <safe_point>`.
inline constexpr std::string_view k_too_old_prefix = "KYTHIRA.TOOOLD ";

inline auto parse_too_old(std::string_view body) -> std::optional<snapshot_too_old_exception> {
    if (body.rfind(k_too_old_prefix, 0) != 0) {
        return std::nullopt;
    }
    body.remove_prefix(k_too_old_prefix.size());
    std::uint64_t start = 0;
    std::uint64_t safe = 0;
    const auto space = body.find(' ');
    if (space == std::string_view::npos) {
        return std::nullopt;
    }
    auto r1 = std::from_chars(body.data(), body.data() + space, start);
    auto r2 = std::from_chars(body.data() + space + 1, body.data() + body.size(), safe);
    if (r1.ec != std::errc{} || r2.ec != std::errc{}) {
        return std::nullopt;
    }
    return snapshot_too_old_exception(start, safe);
}

/// Marks the typed extension of a `KYTHIRA.TXN READ` reply.
inline constexpr char k_txn_read_typed = 'T';

/// The `KYTHIRA.TXN READ` reply body: the committed value and any intent,
/// then, for a live key, the typed extension: `'T'`, `u64` deadline, `u8`
/// type, and for a collection its body (redis_kv_state_machine.hpp's
/// `put_collection_body`). A collection's committed value is empty bytes,
/// so a decoder from before the extension, which ignores what follows the
/// fields it knows, still sees the key as present.
inline auto encode_txn_read(const txn_read_result<std::string>& r,
                            const redis_kv_value_entry* entry = nullptr) -> std::string {
    std::string out;
    out.push_back(static_cast<char>(r._value.has_value() ? 1 : 0));
    if (r._value) {
        put_u32(out, static_cast<std::uint32_t>(r._value->size()));
        out += to_string(*r._value);
    }
    out.push_back(static_cast<char>(r._intent.has_value() ? 1 : 0));
    if (r._intent) {
        put_u64(out, r._intent->_txn._hi);
        put_u64(out, r._intent->_txn._lo);
        put_u32(out, static_cast<std::uint32_t>(r._intent->_primary.size()));
        out += r._intent->_primary;
        put_u64(out, r._intent->_deadline_ms);
        // Tier 2: the holder's start timestamp, after the tier-1 fields so a
        // tier-1 decoder, which ignores what follows, still reads the rest.
        put_u64(out, r._intent->_start_ts);
    }
    if (entry != nullptr && r._value) {
        out.push_back(k_txn_read_typed);
        put_u64(out, entry->_expire_at_ms);
        const auto type = redis_entry_type(*entry);
        out.push_back(static_cast<char>(type));
        if (type != redis_value_type::string) {
            std::vector<std::byte> body;
            redis_kv_detail::put_collection_body(body, *entry);
            out.append(reinterpret_cast<const char*>(body.data()), body.size());
        }
    }
    return out;
}

inline auto decode_txn_read(std::string_view in) -> txn_typed_read {
    txn_read_cursor c(in);
    txn_typed_read out;
    auto& r = out._read;
    if (c.u8() != 0) {
        r._value = to_bytes(c.str());
    }
    if (c.u8() != 0) {
        intent_view<std::string> v;
        v._txn._hi = c.u64();
        v._txn._lo = c.u64();
        v._primary = c.str();
        v._deadline_ms = c.u64();
        if (!c.empty()) {
            v._start_ts = c.u64();
        }
        r._intent = std::move(v);
    }
    if (r._value && c.peek() == static_cast<std::uint8_t>(k_txn_read_typed)) {
        (void)c.u8();
        auto e = std::make_shared<redis_kv_value_entry>();
        e->_expire_at_ms = c.u64();
        const auto tag = c.u8();
        if (tag == static_cast<std::uint8_t>(redis_value_type::string)) {
            e->_value = *r._value;
        } else {
            const auto rest = c.rest();
            redis_kv_detail::reader body(std::as_bytes(std::span(rest.data(), rest.size())));
            redis_kv_detail::read_collection_body(body, tag, *e);
        }
        out._entry = std::move(e);
    }
    return out;
}

}  // namespace redis_gateway_detail

template<typename Host, typename Logger, typename Metrics>
redis_front_end<Host, Logger, Metrics>::redis_front_end(Host& host, redis_acl& acl, Logger& logger,
                                                        Metrics& metrics,
                                                        redis_gateway_config config,
                                                        endpoint_resolver resolver)
    : _data(host),
      _acl(acl),
      _logger(logger),
      _metrics(metrics),
      _config(std::move(config)),
      _resolver(std::move(resolver)) {
    // A front end without the data layer reaches it over KYTHIRA.DATA on
    // the forward link (task 16). Its host holds no groups, so every call
    // goes remote; a node with `data` never attaches one.
    if (!_config._layer_roles.has(layers::role::data) && !_config._data_nodes.empty()) {
        typename decltype(_data)::remote_type::options opts;
        opts.timeout = _config._command_timeout;
        _data.attach_remote(
            _config._data_nodes,
            [this](const std::string& address, const std::vector<std::string>& argv) {
                return data_call(address, argv);
            },
            opts);
    }
}

namespace redis_gateway_detail {

/// The layer identity in a PEM certificate file for `cluster`, if any.
inline auto identity_in_file(const std::string& path, std::string_view cluster)
    -> std::optional<layers::identity> {
    if (path.empty()) {
        return std::nullopt;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return layers::identity_in_pem(pem, "redis", cluster);
}

}  // namespace redis_gateway_detail

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::layer_refusal() const -> std::optional<std::string> {
    const auto& roles = _config._layer_roles;
    const auto named = "redis gateway: KYTHIRA_REDIS_ROLES=" + roles.to_string() + ": ";
    if (roles.has(layers::role::front_end) && !roles.has(layers::role::data)) {
        if (_config._data_nodes.empty()) {
            return named +
                   "a front end without the data layer needs the data nodes to reach "
                   "(KYTHIRA_REDIS_DATA_NODES)";
        }
        if constexpr (!decltype(_data)::k_remote_reads) {
            return named +
                   "the disk-backed store keeps a value's chunks on its data nodes, so a front "
                   "end without the data layer cannot read them; run the in-memory or engine "
                   "store";
        }
    }
    if (roles.has(layers::role::gateway) && !roles.has(layers::role::front_end) &&
        _config._front_ends.empty() && _config._front_ends_dns.empty() &&
        _config._membership_voters.empty() && !_config._membership_local) {
        return named +
               "a gateway without the front end needs the front ends to call "
               "(KYTHIRA_REDIS_FRONT_ENDS, KYTHIRA_REDIS_FRONT_ENDS_DNS or the layer membership "
               "group, KYTHIRA_REDIS_MEMBERSHIP)";
    }
    if (redis_roles_colocated(roles)) {
        return std::nullopt;
    }
    if (_config._insecure_plaintext) {
        if (_config._internal_secret.empty()) {
            return named +
                   "with KYTHIRA_NODE_INSECURE_PLAINTEXT=1 the nodes authenticate each other with "
                   "the internal secret, which is not set";
        }
        return std::nullopt;
    }
    // Requirement 19.4: calls between nodes of different role sets carry
    // layer identities over mutual TLS.
    const std::string insecure =
        "; or set KYTHIRA_NODE_INSECURE_PLAINTEXT=1 on an isolated network";
    if (!_config._forward_tls) {
        return named +
               "a node that is not co-located calls the other layers over mutual TLS with layer "
               "identities, and forwarding TLS is off" +
               insecure;
    }
    if ((roles.has(layers::role::front_end) || roles.has(layers::role::data)) &&
        (_config._tls_listen.empty() || _config._tls_ca_path.empty())) {
        return named +
               "other layers call this node on its TLS listener, which needs a CA to verify "
               "their certificates against (KYTHIRA_REDIS_TLS_LISTEN, KYTHIRA_REDIS_TLS_CA)" +
               insecure;
    }
    const bool own_cert =
        !_config._forward_tls_cert_path.empty() || !_config._forward_tls_key_path.empty();
    const auto id = redis_gateway_detail::identity_in_file(
        own_cert ? _config._forward_tls_cert_path : _config._tls_cert_path, _config._layer_cluster);
    if (!id) {
        return named + "the forwarding client certificate carries no layer identity: it needs " +
               "the URI SAN kythira://redis/" + _config._layer_cluster +
               "/<node id>?roles=" + roles.to_string() + insecure;
    }
    if (id->roles != roles) {
        return named + "the layer identity " + id->to_uri() + " names other roles than the node " +
               "runs";
    }
    return std::nullopt;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::can_call_peers() const -> bool {
    if (!_config._forward_tls && !_config._allow_plaintext_forwarding &&
        !_config._insecure_plaintext) {
        return false;
    }
    std::lock_guard<std::mutex> lock(_tls_mutex);
    return !_config._internal_secret.empty() || (_config._forward_tls && _own_identity);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::own_identity() const
    -> std::optional<layers::identity> {
    std::lock_guard<std::mutex> lock(_tls_mutex);
    return _own_identity;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::stamp_files(const std::vector<std::string>& paths)
    -> std::vector<std::pair<std::string, std::string>> {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& p : paths) {
        if (p.empty()) {
            continue;
        }
        std::error_code ec;
        const auto when = std::filesystem::last_write_time(p, ec);
        const auto size = ec ? 0 : std::filesystem::file_size(p, ec);
        out.emplace_back(
            p, ec ? std::string("missing")
                  : std::to_string(when.time_since_epoch().count()) + "/" + std::to_string(size));
    }
    return out;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::forward_tls_context()
    -> std::shared_ptr<boost::asio::ssl::context> {
    std::unique_lock<std::mutex> lock(_tls_mutex);
    if (!_forward_ssl_ctx) {
        return nullptr;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now - _forward_tls_files._checked < _config._tls_reload_interval) {
        return _forward_ssl_ctx;
    }
    _forward_tls_files._checked = now;
    const bool own_cert =
        !_config._forward_tls_cert_path.empty() || !_config._forward_tls_key_path.empty();
    const auto& cert = own_cert ? _config._forward_tls_cert_path : _config._tls_cert_path;
    const auto& key = own_cert ? _config._forward_tls_key_path : _config._tls_key_path;
    const auto& ca =
        _config._forward_tls_ca_path.empty() ? _config._tls_ca_path : _config._forward_tls_ca_path;
    auto stamps = stamp_files({cert, key, ca});
    if (stamps == _forward_tls_files._stamps) {
        return _forward_ssl_ctx;
    }
    // Requirement 19.5: new connections use the new files; connections
    // already open finish on the old ones, so the idle pool is dropped.
    try {
        auto rebuilt = std::make_shared<boost::asio::ssl::context>(build_forward_ssl_context());
        _forward_ssl_ctx = std::move(rebuilt);
        _forward_tls_files._stamps = std::move(stamps);
        _own_identity = redis_gateway_detail::identity_in_file(cert, _config._layer_cluster);
    } catch (const std::exception& e) {
        // A half-written pair (certificate before key) fails here; the old
        // context stays until the next check sees both.
        _logger.log(log_level::warning, "redis gateway: forwarding certificate reload failed",
                    {{"error", e.what()}});
        return _forward_ssl_ctx;
    }
    auto ctx = _forward_ssl_ctx;
    lock.unlock();
    {
        std::lock_guard<std::mutex> pools(_forward_mutex);
        _forward_pools.clear();
    }
    _logger.log(log_level::info, "redis gateway: forwarding certificate reloaded", {});
    return ctx;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::build_forward_ssl_context()
    -> boost::asio::ssl::context {
    namespace ssl = boost::asio::ssl;
    ssl::context ctx(ssl::context::tls_client);
    // The same TLS 1.2 floor as the listener (Requirement 12.2).
    ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                    ssl::context::no_sslv3 | ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);
    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_2_VERSION);
    const auto& ca =
        _config._forward_tls_ca_path.empty() ? _config._tls_ca_path : _config._forward_tls_ca_path;
    if (ca.empty()) {
        // Without a CA the only options are trusting every certificate or
        // none; the first hands the secret to whoever answers.
        throw std::runtime_error(
            "redis gateway: forwarding over TLS needs a CA to verify peer gateways against");
    }
    ctx.load_verify_file(ca);
    ctx.set_verify_mode(ssl::verify_peer);
    const bool own_cert =
        !_config._forward_tls_cert_path.empty() || !_config._forward_tls_key_path.empty();
    const auto& cert = own_cert ? _config._forward_tls_cert_path : _config._tls_cert_path;
    const auto& key = own_cert ? _config._forward_tls_key_path : _config._tls_key_path;
    if (cert.empty() != key.empty()) {
        throw std::runtime_error(
            "redis gateway: the forwarding client certificate needs both a certificate and a key");
    }
    if (!cert.empty()) {
        ctx.use_certificate_chain_file(cert);
        ctx.use_private_key_file(key, ssl::context::pem);
    }
    return ctx;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::now_ms() -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::is_expired(const entry_type& e) const -> bool {
    return e._expire_at_ms != 0 && e._expire_at_ms <= now_ms();
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::emit(std::string_view name, std::string_view command,
                                                  std::int64_t count) -> void {
    std::lock_guard<std::mutex> lock(_metrics_mutex);
    _metrics.set_metric_name(name);
    _metrics.add_dimension("command", command);
    _metrics.add_count(count);
    _metrics.emit();
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::emit_duration(std::string_view name,
                                                           std::string_view command,
                                                           std::chrono::nanoseconds d) -> void {
    std::lock_guard<std::mutex> lock(_metrics_mutex);
    _metrics.set_metric_name(name);
    _metrics.add_dimension("command", command);
    _metrics.add_duration(d);
    _metrics.emit();
}

/// Audit stream: who, from where, what, and why — never a secret or a value.
/// Tagged `stream=audit` so a log sink can route it separately (Requirement 11.5).
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::audit(session& s, std::string_view command,
                                                   std::string_view outcome) -> void {
    _logger.log(log_level::info, "redis audit",
                {{"stream", "audit"},
                 {"identity", s._identity ? std::string_view(s._identity->_user) : "unknown"},
                 {"source", s._source},
                 {"command", command},
                 {"reason", outcome}});
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::authorize(session& s, std::string_view upper,
                                                       const std::vector<std::string_view>& keys,
                                                       std::optional<unsigned> access)
    -> std::optional<std::string> {
    if (!s._identity) {
        return s._writer.error("NOAUTH Authentication required.");
    }
    switch (redis_acl::authorize(*s._identity, upper, keys, access)) {
        case acl_decision::allow:
            return std::nullopt;
        case acl_decision::deny_command:
            ++_stats._authz_denials;
            emit("redis.authz.denied", upper);
            audit(s, upper, "command denied");
            return s._writer.error("NOPERM User " + s._identity->_user +
                                   " has no permissions to run the '" + std::string(upper) +
                                   "' command");
        case acl_decision::deny_key:
            ++_stats._authz_denials;
            emit("redis.authz.denied", upper);
            audit(s, upper, "key out of scope");
            return s._writer.error("NOPERM No permissions to access a key");
    }
    return s._writer.error("NOPERM denied");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::touch_lru(group_id_type group, const std::string& key)
    -> void {
    if (auto* node = _data.local_replica(group); node != nullptr && !node->is_leader()) {
        // A follower keeps no LRU of its own; the read is queued for the
        // leader's (Requirement 6.2), and only when something will send it.
        if (!_cache_hooks._advisory) {
            return;
        }
        std::lock_guard<std::mutex> lock(_lru_mutex);
        auto& queued = _remote_touches[group];
        if (queued.size() >= max_queued_touches && !queued.contains(key)) {
            ++_stats._touches_dropped;
            return;
        }
        queued.insert(key);
        return;
    }
    std::lock_guard<std::mutex> lock(_lru_mutex);
    auto& lru = _lru[group];
    auto it = lru._index.find(key);
    if (it != lru._index.end()) {
        lru._order.splice(lru._order.begin(), lru._order, it->second);
        return;
    }
    lru._order.push_front(key);
    lru._index.emplace(key, lru._order.begin());
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::note_access(const std::string& key) -> void {
    if (auto desc = _data.route(key)) {
        touch_lru(desc->group_id(), key);
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::note_removed(const std::string& key) -> void {
    if (auto desc = _data.route(key)) {
        forget_lru(desc->group_id(), key);
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::forget_lru(group_id_type group, const std::string& key)
    -> void {
    std::lock_guard<std::mutex> lock(_lru_mutex);
    auto g = _lru.find(group);
    if (g == _lru.end()) {
        return;
    }
    auto it = g->second._index.find(key);
    if (it != g->second._index.end()) {
        g->second._order.erase(it->second);
        g->second._index.erase(it);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// routing
// ─────────────────────────────────────────────────────────────────────────────

/// Find the local replica for `key`. On failure fills `error_reply` (an
/// encoded error) and, when a leader elsewhere is known, `forward_to`.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::locate(const std::string& key,
                                                    std::string& error_reply,
                                                    std::optional<node_id_type>& forward_to)
    -> group_node_type* {
    redis_data_status status{};
    auto* node = _data.replica_for(key, status, forward_to);
    if (node == nullptr) {
        error_reply = data_error(status);
    }
    return node;
}

/// The wire error for a data-layer outcome other than `ok`. The same text
/// for RESP2 and RESP3, so no session writer is needed.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::data_error(redis_data_status status) -> std::string {
    resp_writer w;
    switch (status) {
        case redis_data_status::loading:
            return w.error("LOADING Kythira is loading the dataset in memory");
        case redis_data_status::unrouted:
            return w.error("ERR no shard owns this key");
        case redis_data_status::not_replicated:
            return w.error("ERR value not yet replicated here, retry");
        case redis_data_status::ok:
        case redis_data_status::no_leader:
        case redis_data_status::barrier_failed:
            break;
    }
    return w.error("ERR shard has no reachable leader, retry");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::submit(
    session& s, const std::string& key, const std::vector<std::byte>& command,
    std::string& error_reply, std::optional<node_id_type>& forward_to,
    std::vector<std::byte>* result, const std::vector<std::string>* keys, bool* moved) -> bool {
    // A key a transaction holds refuses plain writes. The gateway finishes
    // that transaction if its time is up, then tries once more
    // (multi-raft-transactions design "Error Handling").
    std::exception_ptr failure;
    for (int attempt = 0; !failure; ++attempt) {
        try {
            auto future = keys != nullptr
                              ? _data.propose_keys(*keys, command, _config._command_timeout)
                              : _data.propose(key, command, _config._command_timeout);
            if (!future.wait(_config._command_timeout)) {
                error_reply = s._writer.error("ERR timeout submitting to shard, retry");
                return false;
            }
            auto applied = std::move(future).get();
            if (result != nullptr) {
                *result = std::move(applied);
            }
            return true;
        } catch (const key_locked_exception<std::string>& e) {
            if (attempt == 0 && resolve_lock(e.key(), e.holder(), e.primary())) {
                continue;
            }
            error_reply = s._writer.error("ERR key is locked by transaction " +
                                          e.holder().to_string() + ", retry");
            return false;
        } catch (...) {
            failure = std::current_exception();
        }
    }
    try {
        std::rethrow_exception(failure);
    } catch (const shard_not_leader_exception<group_id_type, node_id_type>& e) {
        forward_to = e.leader_hint();
        error_reply = s._writer.error("ERR shard has no reachable leader, retry");
        return false;
    } catch (const unrouted_key_exception<std::string>&) {
        error_reply = s._writer.error("ERR no shard owns this key");
        return false;
    } catch (const shard_epoch_mismatch_exception<group_id_type, std::string, node_id_type>& e) {
        // A key of a multi-key entry is no longer in the group it was
        // planned for; take the routes the refusal carried.
        (void)_data.learn_routes(e.current_descriptors());
        if (moved != nullptr) {
            *moved = true;
        }
        error_reply = s._writer.error("ERR shard layout changed, retry");
        return false;
    } catch (const std::exception& e) {
        _logger.log(log_level::debug, "redis gateway: submit failed", {{"error", e.what()}});
        error_reply = s._writer.error("ERR shard has no reachable leader, retry");
        return false;
    }
}

/// Local read under the configured consistency, through the data layer
/// (redis_data_access.hpp, which says why it never serialises the shard).
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::read_local(session& s, const std::string& key)
    -> read_result {
    read_result r;
    if constexpr (!k_string_only_store) {
        if (s._txn_view != nullptr) {
            // Inside a transaction: what it reads, with its own writes.
            r._entry = s._txn_view->find(key);
            return r;
        }
    }
    if (_data.remote_for(key)) {
        // No replica here: the data node runs the barrier and the lookup,
        // and answers with the entry's bytes (KYTHIRA.DATA READ).
        auto mode = redis_data_wire::read_mode::leader;
        if (_config._read_consistency == redis_read_consistency::any_replica) {
            mode = redis_data_wire::read_mode::any_replica;
        } else if (_config._read_consistency == redis_read_consistency::linearizable) {
            mode = redis_data_wire::read_mode::linearizable;
        }
        auto outcome = _data.read_remote(key, mode, _config._command_timeout);
        if (outcome._status != redis_data_status::ok) {
            r._error = data_error(outcome._status);
            return r;
        }
        r._entry = std::move(outcome._entry);
        r._context = std::move(outcome._context);
        return r;
    }
    auto read = [&](auto&& barrier) {
        return _data.read(key, _config._read_consistency == redis_read_consistency::any_replica,
                          std::forward<decltype(barrier)>(barrier));
    };
    auto outcome = _config._read_consistency == redis_read_consistency::linearizable
                       // A committed no-op proves this leader's applied state includes
                       // every write that preceded the read. A sweep naming the key
                       // with deadline 0 is that no-op: apply() only deletes on an exact
                       // deadline match and 0 never matches, so nothing changes, and
                       // the key routes it.
                       ? read([&] {
                             auto sweep =
                                 encode_redis_kv_command(redis_kv_sweep_command{{{key, 0}}});
                             return submit(s, key, sweep, r._error, r._forward_to);
                         })
                       : read(nullptr);
    if (outcome._status == redis_data_status::barrier_failed) {
        return r;  // submit() filled the error and the hint
    }
    if (outcome._status != redis_data_status::ok) {
        r._forward_to = outcome._leader;
        r._error = data_error(outcome._status);
        return r;
    }
    r._entry = std::move(outcome._entry);
    r._context = std::move(outcome._context);
    return r;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::forward_endpoint(const node_id_type& to)
    -> std::optional<std::string> {
    if (_resolver) {
        if (auto endpoint = _resolver(to)) {
            return endpoint;
        }
    }
    // A front end without data knows the data nodes from their routes.
    return _data.address_of(to);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::forward_socket(
    const std::string& endpoint, std::chrono::steady_clock::time_point deadline)
    -> std::unique_ptr<redis_forward_link> {
    std::shared_ptr<forward_pool> pool;
    {
        std::lock_guard<std::mutex> lock(_forward_mutex);
        auto& slot = _forward_pools[endpoint];
        if (!slot) {
            slot = std::make_shared<forward_pool>();
        }
        pool = slot;
    }
    {
        std::lock_guard<std::mutex> lock(pool->_mutex);
        while (!pool->_idle.empty()) {
            auto sock = std::move(pool->_idle.back());
            pool->_idle.pop_back();
            // A peer that restarted closed this socket while it sat idle;
            // a request written to it would be lost, and an authenticated
            // call could not tell that from one that ran.
            if (sock->looks_closed()) {
                continue;
            }
            sock->set_deadline(deadline);
            return sock;
        }
    }
    auto [host, port] = redis_gateway_detail::parse_listen(endpoint);
    // TLS whenever it is configured; forward() never gets here without TLS
    // unless plaintext forwarding was explicitly allowed (Requirement 12.5).
    auto sock = std::make_unique<redis_forward_link>(forward_tls_context());
    sock->set_deadline(deadline);
    sock->connect(host, port);

    // Between co-located nodes the internal secret authenticates the link
    // (or under insecure plaintext). Any other node presents its layer
    // identity in the TLS handshake and sends no secret, which the peer
    // would refuse (Requirement 19.3). Either way the peer never forwards a
    // command that arrives on this connection (one hop, Requirement 9.4).
    if (_config._internal_secret.empty() ||
        (!redis_roles_colocated(_config._layer_roles) && !_config._insecure_plaintext)) {
        if (!sock->is_tls() || !own_identity()) {
            throw std::runtime_error("no way to authenticate to peer " + endpoint +
                                     ": no internal secret and no layer identity");
        }
        return sock;
    }
    resp_writer w;
    auto auth =
        w.array({w.bulk("AUTH"), w.bulk(_config._internal_user), w.bulk(_config._internal_secret)});
    sock->write(boost::asio::buffer(auth));
    std::string buf;
    std::array<char, 512> chunk{};
    while (resp_reply_length(buf) == 0) {
        if (buf.size() > 64u * 1024u) {
            throw std::runtime_error("oversized AUTH reply from peer gateway");
        }
        auto n = sock->read_some(boost::asio::buffer(chunk));
        buf.append(chunk.data(), n);
    }
    if (buf.rfind("+OK", 0) != 0) {
        throw std::runtime_error("internal AUTH rejected by peer gateway: " +
                                 buf.substr(0, buf.size() - 2));
    }
    return sock;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::return_forward_socket(
    const std::string& endpoint, std::unique_ptr<redis_forward_link> sock) -> void {
    if (!sock->healthy()) {
        return;
    }
    std::lock_guard<std::mutex> lock(_forward_mutex);
    auto it = _forward_pools.find(endpoint);
    if (it == _forward_pools.end()) {
        return;
    }
    std::lock_guard<std::mutex> plock(it->second->_mutex);
    if (it->second->_idle.size() < 16) {
        it->second->_idle.push_back(std::move(sock));
    }
}

/// Relay `cmd` to the gateway on node `to` and return its reply, or nullopt
/// if forwarding is off, the session is itself internal, or the peer could
/// not be reached — the caller then answers with the retry error it already
/// has.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::forward(session& s, const resp_command& cmd,
                                                     const node_id_type& to)
    -> std::optional<std::string> {
    // A front end without data never hands a whole command to another
    // node: it reaches the data layer only through KYTHIRA.DATA and
    // KYTHIRA.TXN (task 16), so the command logic stays on the front end.
    if (!_config._forwarding || s._internal || _data.remote() != nullptr) {
        return std::nullopt;
    }
    auto reply = forward_argv(cmd._argv, to, resp_to_upper(cmd._argv[0]));
    // The internal hop speaks RESP2; a RESP3 client expects `_` for every
    // null, nested ones included. Shapes RESP2 flattens (maps, sets) are
    // restored by the handlers that know them.
    if (reply && s._writer.version() >= 3 &&
        (reply->find("$-1\r\n") != std::string::npos ||
         reply->find("*-1\r\n") != std::string::npos)) {
        if (auto tree = parse_resp2_reply(*reply)) {
            *reply = render_redis_reply(*tree, s._writer.version());
        }
    }
    return reply;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::forward_argv(const std::vector<std::string>& argv,
                                                          const node_id_type& to,
                                                          std::string_view what)
    -> std::optional<std::string> {
    if (!_running.load() || !can_call_peers()) {
        return std::nullopt;
    }
    auto endpoint = forward_endpoint(to);
    if (!endpoint) {
        return std::nullopt;
    }
    return forward_to_endpoint(argv, *endpoint, what);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::data_call(const std::string& endpoint,
                                                       const std::vector<std::string>& argv)
    -> std::optional<std::string> {
    if (!_running.load() || !can_call_peers()) {
        return std::nullopt;
    }
    return forward_to_endpoint(argv, endpoint, "KYTHIRA.DATA");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::forward_to_endpoint(
    const std::vector<std::string>& argv, const std::string& endpoint, std::string_view what)
    -> std::optional<std::string> {
    ++_stats._forwards;
    emit("redis.forwards", what);
    auto r = exchange(argv, endpoint);
    if (r._kind == exchange_result::kind::answered) {
        return std::move(r._reply);
    }
    ++_stats._forward_failures;
    _logger.log(log_level::warning, "redis gateway: forward failed",
                {{"endpoint", endpoint}, {"error", r._error}});
    return std::nullopt;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::exchange(const std::vector<std::string>& argv,
                                                      const std::string& endpoint,
                                                      std::chrono::milliseconds budget_ms)
    -> exchange_result {
    exchange_result out;
    bool sent = false;
    try {
        // One budget for the whole exchange, connect and AUTH included, so a
        // peer that stalls surfaces as the retry error, never a hang
        // (Requirement 13.4). A zero timeout meant "none" for the old
        // socket options; keep that meaning with a day-long budget.
        const auto timeout = budget_ms.count() > 0 ? budget_ms : _config._command_timeout;
        const auto budget = timeout.count() > 0
                                ? std::chrono::steady_clock::duration{timeout}
                                : std::chrono::steady_clock::duration{std::chrono::hours{24}};
        auto sock = forward_socket(endpoint, std::chrono::steady_clock::now() + budget);
        resp_writer w;
        std::vector<std::string> parts;
        parts.reserve(argv.size());
        for (const auto& a : argv) {
            parts.push_back(w.bulk(a));
        }
        auto wire = w.array(parts);
        // From here the peer may have the request: a failure is no longer
        // "never sent". A write that fails part way leaves the peer a
        // truncated command, which it never runs, but the write call cannot
        // say how much arrived, so it counts as sent too.
        sent = true;
        sock->write(boost::asio::buffer(wire));
        std::string buf;
        std::array<char, 16 * 1024> chunk{};
        std::size_t len = 0;
        // A peer's reply is never larger than the largest request this
        // gateway itself accepts; past that, give up on the peer.
        resp_reply_limits limits;
        limits._max_bulk_len = _config._parser_limits._max_bulk_len;
        while ((len = resp_reply_length(buf, limits)) == 0) {
            if (buf.size() > _config._parser_limits._max_buffered_bytes) {
                throw std::runtime_error("oversized reply from peer gateway");
            }
            auto n = sock->read_some(boost::asio::buffer(chunk));
            buf.append(chunk.data(), n);
        }
        return_forward_socket(endpoint, std::move(sock));
        buf.resize(len);
        out._kind = exchange_result::kind::answered;
        out._reply = std::move(buf);
    } catch (const std::exception& e) {
        out._kind = sent ? exchange_result::kind::lost : exchange_result::kind::not_sent;
        out._error = e.what();
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// dispatch
// ─────────────────────────────────────────────────────────────────────────────

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::execute_command(session& s, std::string_view upper,
                                                             const resp_command& cmd)
    -> std::string {
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

    // The data-layer API (task 16), on internal sessions, whatever the
    // transaction settings: a front end without a replica sends every
    // proposal for a group through it.
    if (upper == "KYTHIRA.DATA") {
        return handle_data(s, cmd);
    }

    if (s._txn_view != nullptr) {
        // EXEC evaluating its queue: every write is an `exec` record the
        // view takes, so the plain SET/SETEX/DEL paths and the
        // transaction surface step aside.
        if (upper == "MSET" || upper == "MGET") {
            return txn_view_mset_mget(s, upper, cmd);
        }
    } else if (_config._transactions) {
        if (s._in_multi && upper != "EXEC" && upper != "DISCARD" && upper != "MULTI") {
            return queue_in_multi(s, upper, cmd);
        }
        // Multi-key DEL plans as one record per group once the typed-values
        // gate is up (Requirement 6.1); before it, a transaction as before.
        const bool planned_del = (upper == "DEL" || upper == "UNLINK") && cmd._argv.size() > 2 &&
                                 typed_ready(cmd._argv[1]);
        if (!planned_del && is_txn_command(upper, cmd)) {
            return execute_txn_command(s, upper, cmd);
        }
    }

    if (upper == "PING") {
        if (auto e = arity(1, 2)) {
            return *e;
        }
        if (auto e = authorize(s, upper, {})) {
            return *e;
        }
        return cmd._argv.size() == 2 ? s._writer.bulk(cmd._argv[1])
                                     : s._writer.simple_string("PONG");
    }
    if (upper == "ECHO") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        if (auto e = authorize(s, upper, {})) {
            return *e;
        }
        return s._writer.bulk(cmd._argv[1]);
    }
    if (upper == "SELECT") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        if (auto e = authorize(s, upper, {})) {
            return *e;
        }
        return cmd._argv[1] == "0" ? s._writer.simple_string("OK")
                                   : s._writer.error("ERR DB index is out of range");
    }
    if (upper == "GET") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        return handle_get(s, cmd);
    }
    if (upper == "EXISTS") {
        if (auto e = arity(2, std::numeric_limits<std::size_t>::max())) {
            return *e;
        }
        if (cmd._argv.size() > 2) {
            // Each key read where it lives, at the connection's isolation
            // (Requirement 6.4): no transaction needed.
            return handle_key_read(s, upper, cmd);
        }
        return handle_exists(s, cmd);
    }
    if (upper == "STRLEN") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        return handle_strlen(s, cmd);
    }
    if (upper == "GETRANGE") {
        if (auto e = arity(4, 4)) {
            return *e;
        }
        return handle_getrange(s, cmd);
    }
    if (upper == "TTL") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        return handle_ttl(s, cmd);
    }
    if (upper == "SET") {
        if (auto e = arity(3, std::numeric_limits<std::size_t>::max())) {
            return *e;
        }
        if (cmd._argv.size() > 3 || s._txn_view != nullptr || mutable_exec(s, cmd._argv[1])) {
            return handle_string_write(s, upper, cmd);
        }
        return handle_set(s, cmd, false);
    }
    if (upper == "SETNX" || upper == "GETSET" || upper == "INCRBY" || upper == "DECRBY" ||
        upper == "APPEND" || upper == "INCRBYFLOAT") {
        if (auto e = arity(3, 3)) {
            return *e;
        }
        return handle_string_write(s, upper, cmd);
    }
    if (upper == "INCR" || upper == "DECR" || upper == "GETDEL") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        return handle_string_write(s, upper, cmd);
    }
    if (upper == "PSETEX" || upper == "SETRANGE") {
        if (auto e = arity(4, 4)) {
            return *e;
        }
        return handle_string_write(s, upper, cmd);
    }
    if (upper == "GETEX") {
        if (auto e = arity(2, 4)) {
            return *e;
        }
        return handle_string_write(s, upper, cmd);
    }
    if (upper == "EXPIRE" || upper == "PEXPIRE" || upper == "EXPIREAT" || upper == "PEXPIREAT") {
        if (auto e = arity(3, std::numeric_limits<std::size_t>::max())) {
            return *e;
        }
        return handle_string_write(s, upper, cmd);
    }
    if (upper == "PERSIST") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        return handle_string_write(s, upper, cmd);
    }
    if (upper == "TYPE" || upper == "PTTL" || upper == "EXPIRETIME" || upper == "PEXPIRETIME") {
        if (auto e = arity(2, 2)) {
            return *e;
        }
        return handle_key_read(s, upper, cmd);
    }
    if (upper == "TOUCH") {
        if (auto e = arity(2, std::numeric_limits<std::size_t>::max())) {
            return *e;
        }
        return handle_key_read(s, upper, cmd);
    }
    if (upper == "OBJECT") {
        if (auto e = arity(2, std::numeric_limits<std::size_t>::max())) {
            return *e;
        }
        return handle_key_read(s, upper, cmd);
    }
    if (upper == "UNLINK" || upper == "DEL") {
        if ((s._txn_view != nullptr && cmd._argv.size() >= 2) ||
            (cmd._argv.size() > 2 && typed_ready(cmd._argv[1]))) {
            return handle_multi_key_write(s, upper, cmd);
        }
        if (auto e = arity(2, 2)) {
            return *e;
        }
        return handle_del(s, cmd);
    }
    if (upper == "RENAME" || upper == "RENAMENX") {
        if (auto e = arity(3, 3)) {
            return *e;
        }
        return handle_multi_key_write(s, upper, cmd);
    }
    if (upper == "COPY") {
        if (auto e = arity(3, std::numeric_limits<std::size_t>::max())) {
            return *e;
        }
        return handle_multi_key_write(s, upper, cmd);
    }
    if (upper == "MSETNX") {
        if (cmd._argv.size() < 3 || cmd._argv.size() % 2 == 0) {
            return s._writer.error("ERR wrong number of arguments for 'msetnx' command");
        }
        return handle_multi_key_write(s, upper, cmd);
    }
    if (upper == "SETEX") {
        if (auto e = arity(4, 4)) {
            return *e;
        }
        if (s._txn_view != nullptr || mutable_exec(s, cmd._argv[1])) {
            return handle_string_write(s, upper, cmd);
        }
        return handle_set(s, cmd, true);
    }
    if (const auto* info = find_redis_command(upper);
        info != nullptr &&
        (info->group == "hash" || info->group == "set" || info->group == "list") &&
        info->status == redis_command_status::shipped) {
        const auto argc = static_cast<std::ptrdiff_t>(cmd._argv.size());
        const bool pairs = upper == "HSET" || upper == "HMSET";
        if ((info->arity > 0 && argc != info->arity) || (info->arity < 0 && argc < -info->arity) ||
            (pairs && argc % 2 != 0) || (upper == "HRANDFIELD" && argc > 4) ||
            ((upper == "SPOP" || upper == "SRANDMEMBER" || upper == "LPOP" || upper == "RPOP") &&
             argc > 3)) {
            return *arity(std::numeric_limits<std::size_t>::max(), 0);
        }
        return handle_collection(s, *info, cmd);
    }
    if (upper == "INFO") {
        if (auto e = authorize(s, upper, {})) {
            return *e;
        }
        return handle_info(s);
    }
    if (upper == "DBSIZE") {
        if (auto e = authorize(s, upper, {})) {
            return *e;
        }
        return handle_dbsize(s);
    }
    if (upper == "COMMAND") {
        return handle_command(s, cmd);
    }
    if (upper == "KYTHIRA.ADVISE") {
        return handle_advise(s, cmd);
    }
    if (upper == "KYTHIRA.INSTALL") {
        // An exec record id a transaction's commit applies
        // (redis_install_exec.hpp), never a command anyone sends.
        audit(s, "KYTHIRA.INSTALL", "record-only command from a client");
        return s._writer.error("NOPERM KYTHIRA.INSTALL is internal to the gateways");
    }
    if (upper == "KYTHIRA.FORMAT") {
        return handle_format(s, cmd);
    }
    if (upper == "KYTHIRA.EXEC") {
        return handle_internal_exec(s, cmd);
    }

    // Requirement 1.8: unknown commands are an error, not a disconnect.
    std::string args;
    for (std::size_t i = 1; i < cmd._argv.size(); ++i) {
        args += "'" + cmd._argv[i].substr(0, 32) + "' ";
    }
    return s._writer.error("ERR unknown command '" + cmd._argv[0] +
                           "', with args beginning with: " + args);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_get(session& s, const resp_command& cmd)
    -> std::string {
    const auto& key = cmd._argv[1];
    if (auto e = authorize(s, "GET", {key})) {
        return *e;
    }
    auto r = read_local(s, key);
    if (!r._error.empty()) {
        if (r._forward_to) {
            if (auto reply = forward(s, cmd, *r._forward_to)) {
                return *reply;
            }
        }
        return r._error;
    }
    if (!r._entry || is_expired(*r._entry)) {
        ++_stats._misses;
        emit("redis.misses", "GET");
        return s._writer.null();
    }
    if (auto typed = redis_collection_read(r._entry.get(), redis_command_id::get, {}, now_ms())) {
        return render_redis_reply(*typed, s._writer.version());
    }
    auto bytes = value_access::read(r._context, *r._entry);
    if (!bytes) {
        // A chunk vanished or failed its hash after the lookup.
        ++_stats._misses;
        emit("redis.misses", "GET");
        return s._writer.null();
    }
    ++_stats._hits;
    emit("redis.hits", "GET");
    if (auto desc = _data.route(key)) {
        touch_lru(desc->group_id(), key);
    }
    return s._writer.bulk(bytes->view());
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_exists(session& s, const resp_command& cmd)
    -> std::string {
    const auto& key = cmd._argv[1];
    if (auto e = authorize(s, "EXISTS", {key})) {
        return *e;
    }
    auto r = read_local(s, key);
    if (!r._error.empty()) {
        if (r._forward_to) {
            if (auto reply = forward(s, cmd, *r._forward_to)) {
                return *reply;
            }
        }
        return r._error;
    }
    bool present = r._entry && !is_expired(*r._entry);
    emit(present ? "redis.hits" : "redis.misses", "EXISTS");
    return s._writer.integer(present ? 1 : 0);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_strlen(session& s, const resp_command& cmd)
    -> std::string {
    const auto& key = cmd._argv[1];
    if (auto e = authorize(s, "STRLEN", {key})) {
        return *e;
    }
    auto r = read_local(s, key);
    if (!r._error.empty()) {
        if (r._forward_to) {
            if (auto reply = forward(s, cmd, *r._forward_to)) {
                return *reply;
            }
        }
        return r._error;
    }
    bool present = r._entry && !is_expired(*r._entry);
    if (auto typed =
            redis_collection_read(r._entry.get(), redis_command_id::strlen, {}, now_ms())) {
        return render_redis_reply(*typed, s._writer.version());
    }
    return s._writer.integer(present ? static_cast<std::int64_t>(value_access::size(*r._entry))
                                     : 0);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_getrange(session& s, const resp_command& cmd)
    -> std::string {
    const auto& key = cmd._argv[1];
    if (auto e = authorize(s, "GETRANGE", {key})) {
        return *e;
    }
    std::int64_t start = 0;
    std::int64_t end = 0;
    try {
        std::size_t used = 0;
        start = std::stoll(cmd._argv[2], &used);
        if (used != cmd._argv[2].size()) {
            throw std::invalid_argument("start");
        }
        end = std::stoll(cmd._argv[3], &used);
        if (used != cmd._argv[3].size()) {
            throw std::invalid_argument("end");
        }
    } catch (const std::exception&) {
        return s._writer.error("ERR value is not an integer or out of range");
    }
    auto r = read_local(s, key);
    if (!r._error.empty()) {
        if (r._forward_to) {
            if (auto reply = forward(s, cmd, *r._forward_to)) {
                return *reply;
            }
        }
        return r._error;
    }
    if (!r._entry || is_expired(*r._entry)) {
        return s._writer.bulk("");
    }
    if (auto typed =
            redis_collection_read(r._entry.get(), redis_command_id::getrange,
                                  std::span<const std::string>(cmd._argv).subspan(2), now_ms())) {
        return render_redis_reply(*typed, s._writer.version());
    }
    // Redis 7 (getrangeCommand): negative indexes count from the end, both
    // ends are inclusive, and out-of-range bounds clamp to the string
    // rather than error, so `0 -100` on a short string is its first byte.
    if (start < 0 && end < 0 && start > end) {
        return s._writer.bulk("");
    }
    const auto len = static_cast<std::int64_t>(value_access::size(*r._entry));
    if (start < 0) {
        start = std::max<std::int64_t>(0, len + start);
    }
    if (end < 0) {
        end = std::max<std::int64_t>(0, len + end);
    }
    if (end >= len) {
        end = len - 1;
    }
    if (len == 0 || start > end || start >= len) {
        return s._writer.bulk("");
    }
    auto bytes = value_access::read(r._context, *r._entry);
    if (!bytes) {
        return s._writer.bulk("");
    }
    auto span = bytes->view().subspan(static_cast<std::size_t>(start),
                                      static_cast<std::size_t>(end - start + 1));
    return s._writer.bulk(span);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_ttl(session& s, const resp_command& cmd)
    -> std::string {
    const auto& key = cmd._argv[1];
    if (auto e = authorize(s, "TTL", {key})) {
        return *e;
    }
    auto r = read_local(s, key);
    if (!r._error.empty()) {
        if (r._forward_to) {
            if (auto reply = forward(s, cmd, *r._forward_to)) {
                return *reply;
            }
        }
        return r._error;
    }
    if (!r._entry || is_expired(*r._entry)) {
        return s._writer.integer(-2);
    }
    if (r._entry->_expire_at_ms == 0) {
        return s._writer.integer(-1);
    }
    auto remaining_ms = r._entry->_expire_at_ms - now_ms();
    return s._writer.integer(static_cast<std::int64_t>((remaining_ms + 999) / 1000));
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_set(session& s, const resp_command& cmd,
                                                        bool with_expiry) -> std::string {
    const auto& key = cmd._argv[1];
    const auto& value = cmd._argv.back();
    const char* name = with_expiry ? "SETEX" : "SET";
    if (auto e = authorize(s, name, {key})) {
        return *e;
    }
    std::int64_t seconds = 0;
    if (with_expiry) {
        try {
            std::size_t used = 0;
            seconds = std::stoll(cmd._argv[2], &used);
            if (used != cmd._argv[2].size()) {
                throw std::invalid_argument("seconds");
            }
        } catch (const std::exception&) {
            return s._writer.error("ERR value is not an integer or out of range");
        }
        if (seconds <= 0) {
            return s._writer.error("ERR invalid expire time in 'setex' command");
        }
    }
    if (value.size() > _config._max_value_bytes) {
        ++_stats._oversize_rejections;
        emit("redis.oversize_rejections", name);
        return s._writer.error("ERR value exceeds the configured maximum of " +
                               std::to_string(_config._max_value_bytes) + " bytes");
    }

    std::string error;
    std::optional<node_id_type> forward_to;
    // No replica here (a front end without data, task 16): the checks below
    // read the data node's leader, and the entry goes over KYTHIRA.DATA.
    const bool remote = _data.remote_for(key);
    group_node_type* node = nullptr;
    if (!remote) {
        node = locate(key, error, forward_to);
        if (node != nullptr && !node->is_leader()) {
            forward_to = node->known_leader();
            error = s._writer.error("ERR shard has no reachable leader, retry");
            node = nullptr;
        }
        if (node == nullptr) {
            if (forward_to) {
                if (auto reply = forward(s, cmd, *forward_to)) {
                    return *reply;
                }
            }
            return error;
        }

        // The space hooks belong to the disk-backed store, which a front end
        // without data cannot run.
        if (auto refused = space_refusal(key)) {
            ++_stats._space_refusals;
            emit("redis.space_refusals", name);
            return s._writer.error("ERR " + *refused + ", retry later");
        }
    }

    if (_config._immutable_values && !redis_acl::key_is_mutable(*s._identity, key)) {
        // sccache keys are content hashes, so a rewrite is either the same
        // bytes (sccache rewriting its `.sccache_check` probe) or a bug
        // somewhere. The first is a free no-op; the second is refused.
        // Checked against a caught-up leader's state only; see read_local().
        std::optional<entry_handle> looked_up;
        if (remote) {
            auto outcome = _data.read_remote(key, redis_data_wire::read_mode::leader,
                                             _config._command_timeout);
            if (outcome._status != redis_data_status::ok) {
                return data_error(outcome._status);
            }
            looked_up = std::move(outcome._entry);
        } else {
            looked_up = node->with_leader_state_machine(
                [&key](auto& sm) { return redis_gateway_detail::kv_of(sm).lookup(key); });
        }
        if (!looked_up) {
            return s._writer.error("ERR shard has no reachable leader, retry");
        }
        const auto& existing = *looked_up;
        if (existing && !is_expired(*existing)) {
            if (value_access::equals(*existing, std::as_bytes(std::span(value)))) {
                return s._writer.simple_string("OK");
            }
            ++_stats._value_conflicts;
            emit("redis.value_conflicts", name);
            return s._writer.error("ERR value conflict for an existing key");
        }
    }

    redis_kv_set_command set;
    set._key = key;
    set._value.resize(value.size());
    if (!value.empty()) {
        std::memcpy(set._value.data(), value.data(), value.size());
    }
    // The deadline is resolved here, on the leader, so the log entry carries
    // an absolute time and every replica agrees on it (Requirement 6.1).
    set._expire_at_ms = with_expiry ? now_ms() + static_cast<std::uint64_t>(seconds) * 1000u : 0;
    auto encoded = encode_redis_kv_command(set);
    if (!submit(s, key, encoded, error, forward_to)) {
        if (forward_to) {
            if (auto reply = forward(s, cmd, *forward_to)) {
                return *reply;
            }
        }
        return error;
    }
    ++_stats._writes;
    emit("redis.writes", name);
    emit("redis.bytes_written", name, static_cast<std::int64_t>(value.size()));
    if (auto desc = _data.route(key)) {
        touch_lru(desc->group_id(), key);
    }
    return s._writer.simple_string("OK");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_del(session& s, const resp_command& cmd)
    -> std::string {
    const auto& key = cmd._argv[1];
    if (auto e = authorize(s, "DEL", {key})) {
        return *e;
    }
    std::string error;
    std::optional<node_id_type> forward_to;
    std::optional<entry_handle> looked_up;
    if (_data.remote_for(key)) {
        // From the leader on the data node, which has caught up, as below.
        auto outcome =
            _data.read_remote(key, redis_data_wire::read_mode::leader, _config._command_timeout);
        if (outcome._status != redis_data_status::ok) {
            return data_error(outcome._status);
        }
        looked_up = std::move(outcome._entry);
    } else {
        auto* node = locate(key, error, forward_to);
        if (node != nullptr && !node->is_leader()) {
            forward_to = node->known_leader();
            error = s._writer.error("ERR shard has no reachable leader, retry");
            node = nullptr;
        }
        if (node == nullptr) {
            if (forward_to) {
                if (auto reply = forward(s, cmd, *forward_to)) {
                    return *reply;
                }
            }
            return error;
        }
        // On a leader that has not caught up, "no such key" could be a key an
        // earlier leader acknowledged, and answering 0 would skip the delete.
        looked_up = node->with_leader_state_machine(
            [&key](auto& sm) { return redis_gateway_detail::kv_of(sm).lookup(key); });
    }
    if (!looked_up) {
        return s._writer.error("ERR shard has no reachable leader, retry");
    }
    const auto& existing = *looked_up;
    if (!existing) {
        return s._writer.integer(0);
    }
    bool live = !is_expired(*existing);
    auto encoded = encode_redis_kv_command(redis_kv_del_command{key});
    if (!submit(s, key, encoded, error, forward_to)) {
        if (forward_to) {
            if (auto reply = forward(s, cmd, *forward_to)) {
                return *reply;
            }
        }
        return error;
    }
    ++_stats._deletes;
    emit("redis.deletes", "DEL");
    if (auto desc = _data.route(key)) {
        forget_lru(desc->group_id(), key);
    }
    return s._writer.integer(live ? 1 : 0);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_dbsize(session& s) -> std::string {
    std::size_t keys = 0;
    for (const auto& g : _data.local_groups()) {
        if (auto* node = _data.local_replica(g)) {
            keys += node->with_state_machine(
                [](auto& sm) { return redis_gateway_detail::kv_of(sm).approximate_key_count(); });
        }
    }
    return s._writer.integer(static_cast<std::int64_t>(keys));
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_info(session& s) -> std::string {
    std::size_t keys = 0;
    std::size_t expiring = 0;
    std::size_t bytes = 0;
    std::size_t shards = 0;
    std::size_t led = 0;
    for (const auto& g : _data.local_groups()) {
        if (auto* node = _data.local_replica(g)) {
            ++shards;
            if (node->is_leader()) {
                ++led;
            }
            auto [k, e, b] = node->with_state_machine([](auto& sm) {
                return std::tuple{redis_gateway_detail::kv_of(sm).approximate_key_count(),
                                  redis_gateway_detail::kv_of(sm).expiring_key_count(),
                                  redis_gateway_detail::kv_of(sm).approximate_size_bytes()};
            });
            keys += k;
            expiring += e;
            bytes += b;
        }
    }
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - _started_at);
    std::ostringstream out;
    out << "# Server\r\n"
        << "redis_version:" << _config._redis_compat_version << "\r\n"
        << "server_name:kythira\r\n"
        << "kythira_version:" << _config._kythira_version << "\r\n"
        << "kythira_gateway:1\r\n"
        << "kythira_format_level:" << reported_format_level() << "\r\n"
        << "redis_mode:" << server_mode() << "\r\n"
        << "uptime_in_seconds:" << uptime.count() << "\r\n"
        << "kythira_roles:" << _config._layer_roles.to_string() << "\r\n"
        << "kythira_membership:" << membership_mode_name() << "\r\n"
        << "kythira_member_drain:" << layers::to_string(_member_drain.load()) << "\r\n"
        << "kythira_front_end_index:" << _config._front_end_index << "\r\n"
        << "kythira_front_end_calls_served:" << _stats._front_end_calls_served.load() << "\r\n"
        << "\r\n# Clients\r\n"
        << "connected_clients:" << _stats._connections_current.load() << "\r\n"
        << "maxclients:" << _config._max_clients << "\r\n"
        << "rejected_connections:" << _stats._connections_rejected.load() << "\r\n"
        << "\r\n# Memory\r\n"
        << "used_memory_dataset:" << bytes << "\r\n"
        << "\r\n# Keyspace\r\n"
        << "local_shards:" << shards << "\r\n"
        << "local_shards_led:" << led << "\r\n"
        << "db0:keys=" << keys << ",expires=" << expiring << ",avg_ttl=0\r\n"
        << "\r\n# Stats\r\n"
        << "total_commands_processed:" << _stats._commands.load() << "\r\n"
        << "total_connections_received:" << _stats._connections_accepted.load() << "\r\n"
        << "total_net_input_bytes:" << _stats._bytes_in.load() << "\r\n"
        << "total_net_output_bytes:" << _stats._bytes_out.load() << "\r\n"
        << "keyspace_hits:" << _stats._hits.load() << "\r\n"
        << "keyspace_misses:" << _stats._misses.load() << "\r\n"
        << "evicted_keys:" << _stats._evictions.load() << "\r\n"
        << "expired_keys:" << _stats._expirations.load() << "\r\n"
        << "kythira_writes:" << _stats._writes.load() << "\r\n"
        << "kythira_deletes:" << _stats._deletes.load() << "\r\n"
        << "kythira_value_conflicts:" << _stats._value_conflicts.load() << "\r\n"
        << "kythira_oversize_rejections:" << _stats._oversize_rejections.load() << "\r\n"
        << "kythira_auth_failures:" << _stats._auth_failures.load() << "\r\n"
        << "kythira_auth_busy:" << _stats._auth_busy.load() << "\r\n"
        << "kythira_authz_denials:" << _stats._authz_denials.load() << "\r\n"
        << "kythira_forwards:" << _stats._forwards.load() << "\r\n"
        << "kythira_forward_failures:" << _stats._forward_failures.load() << "\r\n"
        << "kythira_shed:" << _stats._shed.load() << "\r\n"
        << "kythira_output_stalls:" << _stats._output_stalls.load() << "\r\n";
    if (_cache_hooks._advisory || _cache_hooks._write_refusal) {
        out << "kythira_space_refusals:" << _stats._space_refusals.load() << "\r\n"
            << "kythira_advisories_sent:" << _stats._advisories_sent.load() << "\r\n"
            << "kythira_advisory_failures:" << _stats._advisory_failures.load() << "\r\n"
            << "kythira_advisories_received:" << _stats._advisories_received.load() << "\r\n"
            << "kythira_touches_dropped:" << _stats._touches_dropped.load() << "\r\n";
    }
    if (_cache_hooks._info) {
        out << "\r\n" << _cache_hooks._info();
    }
    return s._writer.bulk(out.str());
}

/// `COMMAND`, `COMMAND COUNT|LIST|INFO [name...]|DOCS [name...]`, answered
/// from the command registry (redis-general-data-types Requirement 1.3):
/// exactly the commands this node accepts, which are the registry's shipped
/// ones less the transaction commands when transactions are off.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_command(session& s, const resp_command& cmd)
    -> std::string {
    if (auto e = authorize(s, "COMMAND", {})) {
        return *e;
    }
    const auto accepted = [this](const redis_command_info& c) {
        if (c.status != redis_command_status::shipped) {
            return false;
        }
        const bool txn = c.name == "MULTI" || c.name == "EXEC" || c.name == "DISCARD" ||
                         c.name == "WATCH" || c.name == "UNWATCH" ||
                         c.name == "KYTHIRA.ISOLATION" || c.name == "KYTHIRA.TXN";
        return !txn || _config._transactions;
    };
    const auto lower = [](std::string_view n) {
        std::string out(n);
        for (auto& ch : out) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return out;
    };
    const auto& w = s._writer;
    const auto info = [&](const redis_command_info& c) {
        static constexpr std::array<std::string_view, 14> flag_names = {
            "write",       "readonly",   "denyoom",      "admin",   "noscript",
            "loading",     "stale",      "skip_slowlog", "fast",    "no_auth",
            "movablekeys", "allow_busy", "no_multi",     "blocking"};
        static constexpr std::array<std::string_view, 14> category_names = {
            "@keyspace", "@read",      "@write",      "@set",        "@list",
            "@hash",     "@string",    "@admin",      "@fast",       "@slow",
            "@blocking", "@dangerous", "@connection", "@transaction"};
        std::vector<std::string> flags;
        for (std::size_t i = 0; i < flag_names.size(); ++i) {
            if ((c.flags & (1U << i)) != 0U) {
                flags.push_back(w.simple_string(flag_names[i]));
            }
        }
        std::vector<std::string> categories;
        for (std::size_t i = 0; i < category_names.size(); ++i) {
            if ((c.acl_categories & (1U << i)) != 0U) {
                categories.push_back(w.simple_string(category_names[i]));
            }
        }
        std::vector<std::string> key_specs;
        if (c.first_key > 0) {
            // One key specification from the legacy triple; its flags follow
            // the command's access (RO/ACCESS for reads, RW/UPDATE otherwise).
            const bool ro = (c.flags & redis_command_flag::readonly) != 0U;
            const auto last = c.last_key < 0 ? -1 : c.last_key - c.first_key;
            key_specs.push_back(w.map(
                {{"flags", w.array({w.simple_string(ro ? "RO" : "RW"),
                                    w.simple_string(ro ? "ACCESS" : "UPDATE")})},
                 {"begin_search", w.map({{"type", w.bulk("index")},
                                         {"spec", w.map({{"index", w.integer(c.first_key)}})}})},
                 {"find_keys", w.map({{"type", w.bulk("range")},
                                      {"spec", w.map({{"lastkey", w.integer(last)},
                                                      {"keystep", w.integer(c.step)},
                                                      {"limit", w.integer(0)}})}})}}));
        }
        return w.array({w.bulk(lower(c.name)), w.integer(c.arity), w.array(flags),
                        w.integer(c.first_key), w.integer(c.last_key), w.integer(c.step),
                        w.array(categories), w.array({}), w.array(key_specs), w.array({})});
    };
    const auto docs = [&](const redis_command_info& c) {
        return w.map({{"since", w.bulk(c.since)}, {"group", w.bulk(c.group)}});
    };
    std::vector<const redis_command_info*> all;
    for (const auto& c : k_redis_commands) {
        if (accepted(c)) {
            all.push_back(&c);
        }
    }
    const auto lookup = [&](const std::string& name) -> const redis_command_info* {
        const auto* c = find_redis_command(resp_to_upper(name));
        return c != nullptr && accepted(*c) ? c : nullptr;
    };
    if (cmd._argv.size() >= 2) {
        auto sub = resp_to_upper(cmd._argv[1]);
        if (sub == "COUNT" && cmd._argv.size() == 2) {
            return w.integer(static_cast<std::int64_t>(all.size()));
        }
        if (sub == "LIST" && cmd._argv.size() == 2) {
            std::vector<std::string> out;
            for (const auto* c : all) {
                out.push_back(w.bulk(lower(c->name)));
            }
            return w.array(out);
        }
        if (sub == "INFO") {
            std::vector<std::string> out;
            if (cmd._argv.size() == 2) {
                for (const auto* c : all) {
                    out.push_back(info(*c));
                }
            }
            for (std::size_t i = 2; i < cmd._argv.size(); ++i) {
                const auto* c = lookup(cmd._argv[i]);
                out.push_back(c != nullptr ? info(*c) : w.null_array());
            }
            return w.array(out);
        }
        if (sub == "DOCS") {
            std::vector<std::pair<std::string, std::string>> out;
            if (cmd._argv.size() == 2) {
                for (const auto* c : all) {
                    out.emplace_back(lower(c->name), docs(*c));
                }
            }
            for (std::size_t i = 2; i < cmd._argv.size(); ++i) {
                if (const auto* c = lookup(cmd._argv[i])) {
                    out.emplace_back(lower(c->name), docs(*c));
                }
            }
            return w.map(out);
        }
        return w.error("ERR unknown subcommand '" + cmd._argv[1] + "'. Try COMMAND HELP.");
    }
    std::vector<std::string> out;
    for (const auto* c : all) {
        out.push_back(info(*c));
    }
    return w.array(out);
}

// ─────────────────────────────────────────────────────────────────────────────
// transactions (.kiro/specs/multi-raft-transactions/ task 9)
// ─────────────────────────────────────────────────────────────────────────────

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::resolve(const std::string& key)
    -> std::optional<group_id_type> {
    if (auto desc = _front_end._data.route(key)) {
        return desc->group_id();
    }
    return std::nullopt;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::send(
    const std::vector<std::string>& keys, const std::vector<std::byte>& envelope,
    std::chrono::milliseconds timeout) -> send_future {
    promise_default<std::vector<std::byte>> promise;
    auto result = promise.getFuture();
    try {
        promise.setValue(_front_end.txn_send(keys, envelope, timeout));
    } catch (...) {
        promise.setException(std::current_exception());
    }
    return result;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::refresh(std::exception_ptr error) -> bool {
    try {
        std::rethrow_exception(std::move(error));
    } catch (const shard_epoch_mismatch_exception<group_id_type, std::string, node_id_type>& e) {
        std::ignore = _front_end._data.learn_routes(e.current_descriptors());
        return true;
    } catch (const redis_gateway_detail::txn_moved_error&) {
        // The peer's host knows the new tiling and this one will learn it
        // from its own routing; give it a moment before re-partitioning.
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
        return true;
    } catch (...) {
        return false;
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::read(const std::string& key,
                                                              std::chrono::milliseconds timeout)
    -> txn_read_result<std::string> {
    return keep(key, _front_end.txn_read(key, timeout));
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::keep(
    const std::string& key, redis_gateway_detail::txn_typed_read r)
    -> txn_read_result<std::string> {
    _entries.insert_or_assign(key, std::move(r._entry));
    return std::move(r._read);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::entry_of(const std::string& key) const
    -> std::shared_ptr<const redis_kv_value_entry> {
    auto it = _entries.find(key);
    return it == _entries.end() ? nullptr : it->second;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::now_ms() const -> std::uint64_t {
    return _front_end._data.txn_now_ms();
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::allocate_timestamps(
    std::size_t n, std::chrono::milliseconds timeout) -> timestamp_range
requires k_snapshot
{
    return _front_end.txn_allocate_timestamps(n, timeout);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_client::read_at(const std::string& key,
                                                                 std::uint64_t ts,
                                                                 std::chrono::milliseconds timeout)
    -> txn_read_result<std::string>
requires k_snapshot
{
    return keep(key, _front_end.txn_read_at(key, ts, timeout));
}

/// The host's oracle when it leads the oracle group, else the leader's
/// gateway over `KYTHIRA.TXN TS`, which serves it from its own host and
/// never forwards again. Also the host's timestamp forwarder, so a plain
/// write on a node that does not lead the oracle gets its commit timestamp.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_allocate_timestamps(
    std::size_t n, std::chrono::milliseconds timeout) -> timestamp_range {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto left = [&deadline] {
        return std::max(std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now()),
                        std::chrono::milliseconds{1});
    };
    std::string last = "no reachable timestamp oracle";
    for (;;) {
        std::optional<node_id_type> hint;
        if (auto* remote = _data.remote(); remote != nullptr) {
            // A front end without data holds no replica of the oracle group,
            // and the group has no key to route by: ask the data nodes in
            // turn, and the oracle's leader answers (task 16).
            for (const auto& address : remote->data_addresses()) {
                auto reply = data_call(address, {"KYTHIRA.TXN", "TS", std::to_string(n)});
                if (!reply) {
                    continue;
                }
                auto parsed = redis_gateway_detail::parse_peer_reply(*reply);
                if (parsed._kind == redis_gateway_detail::peer_reply::kind::bulk) {
                    return redis_gateway_detail::decode_timestamp_range(parsed._body);
                }
                last = parsed._body;
            }
        } else {
            try {
                return _data.allocate_timestamps(n, left()).get();
            } catch (const shard_not_leader_exception<group_id_type, node_id_type>& e) {
                hint = e.leader_hint();
            } catch (const timestamp_oracle_unavailable_exception& e) {
                last = e.what();
            }
        }
        if (hint && *hint != _data.self()) {
            if (auto reply =
                    forward_argv({"KYTHIRA.TXN", "TS", std::to_string(n)}, *hint, "KYTHIRA.TXN")) {
                auto parsed = redis_gateway_detail::parse_peer_reply(*reply);
                using kind = redis_gateway_detail::peer_reply::kind;
                if (parsed._kind == kind::bulk) {
                    return redis_gateway_detail::decode_timestamp_range(parsed._body);
                }
                if (parsed._kind != kind::error ||
                    parsed._body.find("retry") == std::string::npos) {
                    throw timestamp_oracle_unavailable_exception(
                        "peer gateway refused a timestamp request: " + parsed._body);
                }
                last = parsed._body;
            }
        }
        if (!_running.load() || std::chrono::steady_clock::now() >= deadline) {
            throw timestamp_oracle_unavailable_exception("redis gateway: " + last);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_read_at_local(const std::string& key,
                                                               std::uint64_t ts,
                                                               std::chrono::milliseconds timeout)
    -> std::optional<redis_gateway_detail::txn_typed_read> {
    if constexpr (!k_snapshot) {
        return std::nullopt;
    } else {
        auto desc = _data.route(key);
        if (!desc) {
            return std::nullopt;
        }
        const auto group = desc->group_id();
        if (auto* node = _data.local_replica(group); node == nullptr || !node->is_leader()) {
            return std::nullopt;
        }
        try {
            // Every entry committed before the read began is applied here
            // when this returns, so a commit at or below `ts` shows as a
            // version or as its intent (Requirement 8.5). Through the host,
            // which holds the group alive for the round.
            (void)_data.read_barrier(key, timeout).get();
            auto looked = _data.with_local_state_machine(
                group,
                [&](state_machine_type& sm, const auto& d)
                    -> std::optional<
                        std::pair<entry_handle, std::optional<intent_view<std::string>>>> {
                    if (!d._range.contains(key)) {
                        return std::nullopt;  // a split or merge moved it
                    }
                    if (ts < sm.safe_point()) {
                        // Versions this read needs may be gone.
                        throw snapshot_too_old_exception(ts, sm.safe_point());
                    }
                    return std::pair{sm.inner().read_at(key, ts), sm.intent_on(key)};
                });
            if (!looked || !*looked) {
                return std::nullopt;
            }
            auto& [entry, intent] = **looked;
            redis_gateway_detail::txn_typed_read out;
            out._read._intent = std::move(intent);
            // As a plain GET: a version whose TTL has run out is a miss.
            if (entry && !is_expired(*entry)) {
                const auto view = value_access::read({}, *entry)->view();
                out._read._value = std::vector<std::byte>(view.begin(), view.end());
                out._entry = entry;
            }
            return out;
        } catch (const snapshot_too_old_exception&) {
            throw;
        } catch (const std::exception&) {
            // Lost leadership mid-read: the caller finds the new leader.
            return std::nullopt;
        }
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_read_at(const std::string& key, std::uint64_t ts,
                                                         std::chrono::milliseconds timeout)
    -> redis_gateway_detail::txn_typed_read {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto left = [&deadline] {
        return std::max(std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now()),
                        std::chrono::milliseconds{1});
    };
    std::string last = "no reachable leader for the key's shard";
    for (;;) {
        if (auto local = txn_read_at_local(key, ts, left())) {
            return std::move(*local);
        }
        if (auto to = txn_leader_of(key); to && *to != _data.self()) {
            if (auto reply = forward_argv({"KYTHIRA.TXN", "READAT", std::to_string(ts), key}, *to,
                                          "KYTHIRA.TXN")) {
                auto parsed = redis_gateway_detail::parse_peer_reply(*reply);
                using kind = redis_gateway_detail::peer_reply::kind;
                if (parsed._kind == kind::bulk) {
                    return redis_gateway_detail::decode_txn_read(parsed._body);
                }
                if (parsed._kind == kind::error) {
                    if (auto too_old = redis_gateway_detail::parse_too_old(parsed._body)) {
                        throw *too_old;
                    }
                }
                if (parsed._kind != kind::error ||
                    parsed._body.find("retry") == std::string::npos) {
                    throw std::runtime_error("peer gateway refused a transaction read: " +
                                             parsed._body);
                }
                last = parsed._body;
            }
        }
        if (!_running.load() || std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("redis gateway: " + last);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_leader_of(const std::string& key)
    -> std::optional<node_id_type> {
    return _data.leader_of(key);
}

/// Local leader first; otherwise the leader's gateway over the forward link,
/// which runs the op on its own host and never forwards it again. A peer
/// that answers with the retry error (it lost leadership on the way) is
/// asked again after a pause, until the timeout.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_send(const std::vector<std::string>& keys,
                                                      const std::vector<std::byte>& envelope,
                                                      std::chrono::milliseconds timeout)
    -> std::vector<std::byte> {
    if constexpr (!k_transactional) {
        throw std::logic_error("redis gateway: transactions need a transactional host");
    } else {
        if (keys.empty()) {
            throw std::invalid_argument("redis gateway: a transaction op names no key");
        }
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        auto left = [&deadline] {
            return std::max(std::chrono::duration_cast<std::chrono::milliseconds>(
                                deadline - std::chrono::steady_clock::now()),
                            std::chrono::milliseconds{1});
        };
        std::string last = "no reachable leader for the shard";
        for (;;) {
            if (!_running.load()) {
                throw std::runtime_error("redis gateway: stopping");
            }
            std::optional<node_id_type> hint;
            try {
                auto f = _data.propose_txn(keys, envelope, left());
                if (!f.wait(left())) {
                    throw std::runtime_error("redis gateway: transaction op timed out");
                }
                return std::move(f).get();
            } catch (const shard_not_leader_exception<group_id_type, node_id_type>& e) {
                hint = e.leader_hint();
            } catch (const unknown_shard_exception<group_id_type>&) {
                // No replica here: ask whoever the routing row names.
            }
            auto to = hint ? hint : txn_leader_of(keys.front());
            if (to && *to != _data.self()) {
                std::vector<std::string> argv{"KYTHIRA.TXN", "SEND",
                                              redis_gateway_detail::to_string(envelope)};
                argv.insert(argv.end(), keys.begin(), keys.end());
                if (auto reply = forward_argv(argv, *to, "KYTHIRA.TXN")) {
                    auto parsed = redis_gateway_detail::parse_peer_reply(*reply);
                    using kind = redis_gateway_detail::peer_reply::kind;
                    if (parsed._kind == kind::bulk) {
                        return redis_gateway_detail::to_bytes(parsed._body);
                    }
                    if (parsed._kind == kind::error &&
                        parsed._body.rfind("KYTHIRA.MOVED", 0) == 0) {
                        throw redis_gateway_detail::txn_moved_error(parsed._body);
                    }
                    if (parsed._kind != kind::error ||
                        parsed._body.find("retry") == std::string::npos) {
                        throw std::runtime_error("peer gateway refused a transaction op: " +
                                                 parsed._body);
                    }
                    last = parsed._body;
                }
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("redis gateway: " + last);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_read_local(const std::string& key)
    -> std::optional<redis_gateway_detail::txn_typed_read> {
    if constexpr (!k_transactional) {
        return std::nullopt;
    } else {
        auto desc = _data.route(key);
        if (!desc) {
            return std::nullopt;
        }
        auto* node = _data.local_replica(desc->group_id());
        if (node == nullptr || !node->is_leader()) {
            return std::nullopt;
        }
        // A caught-up leader only, as read_local(): a new leader's state may
        // not hold every write its predecessor acknowledged.
        // The entry, its read context and any intent under the node lock;
        // the bytes after it, as read_local() does.
        auto looked = node->with_leader_state_machine([&](auto& sm) {
            return std::tuple{redis_gateway_detail::kv_of(sm).lookup(key),
                              value_access::context_of(sm), sm.intent_on(key)};
        });
        if (!looked) {
            return std::nullopt;
        }
        auto& [entry, context, intent] = *looked;
        redis_gateway_detail::txn_typed_read out;
        out._read._intent = std::move(intent);
        // A leader whose node lacks the bytes answers a miss, as a plain
        // GET on it does (read_local()).
        if (entry && !is_expired(*entry) && value_access::servable(*entry)) {
            if (auto bytes = value_access::read(context, *entry)) {
                const auto view = bytes->view();
                out._read._value = std::vector<std::byte>(view.begin(), view.end());
                if constexpr (!k_string_only_store) {
                    out._entry = entry;
                }
            }
        }
        return out;
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_read(const std::string& key,
                                                      std::chrono::milliseconds timeout)
    -> redis_gateway_detail::txn_typed_read {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::string last = "no reachable leader for the key's shard";
    for (;;) {
        if (auto local = txn_read_local(key)) {
            return std::move(*local);
        }
        if (auto to = txn_leader_of(key); to && *to != _data.self()) {
            if (auto reply = forward_argv({"KYTHIRA.TXN", "READ", key}, *to, "KYTHIRA.TXN")) {
                auto parsed = redis_gateway_detail::parse_peer_reply(*reply);
                using kind = redis_gateway_detail::peer_reply::kind;
                if (parsed._kind == kind::bulk) {
                    return redis_gateway_detail::decode_txn_read(parsed._body);
                }
                if (parsed._kind != kind::error ||
                    parsed._body.find("retry") == std::string::npos) {
                    throw std::runtime_error("peer gateway refused a transaction read: " +
                                             parsed._body);
                }
                last = parsed._body;
            }
        }
        if (!_running.load() || std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("redis gateway: " + last);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::resolve_lock(const std::string& key,
                                                          const txn_id& holder,
                                                          const std::string& primary) -> bool {
    if constexpr (!k_transactional) {
        return false;
    } else {
        try {
            txn_client client(*this);
            coordinator_type coordinator(client, txn_options{.timeout = _config._command_timeout});
            const auto status =
                coordinator.resolve_intent(key, intent_view<std::string>{holder, primary, 0});
            if (status == txn_record_status::pending) {
                return false;
            }
            ++_stats._txn_lock_resolves;
            emit("redis.txn.lock_resolves", "resolve");
            return true;
        } catch (const std::exception& e) {
            _logger.log(log_level::debug, "redis gateway: resolving a lock failed",
                        {{"txn", holder.to_string()}, {"error", e.what()}});
            return false;
        }
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::is_txn_command(std::string_view upper,
                                                            const resp_command& cmd) const -> bool {
    return upper == "MSET" || upper == "MGET" || upper == "MULTI" || upper == "EXEC" ||
           upper == "DISCARD" || upper == "WATCH" || upper == "UNWATCH" ||
           upper == "KYTHIRA.ISOLATION" || upper == "KYTHIRA.TXN" ||
           (upper == "DEL" && cmd._argv.size() > 2);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::isolation_of(const session& s) const -> txn_isolation {
    return s._isolation.value_or(_config._txn_isolation);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::make_options(const session& s) const -> txn_options {
    txn_options o;
    o.isolation = isolation_of(s);
    o.lock_ttl = _config._txn_lock_ttl;
    if (_config._command_timeout.count() > 0) {
        o.timeout = _config._command_timeout;
    }
    o.max_retries = _config._txn_max_retries;
    return o;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::set_command(const std::string& key,
                                                         std::string_view value,
                                                         std::uint64_t expire_at_ms) const
    -> std::vector<std::byte> {
    redis_kv_set_command set;
    set._key = key;
    set._value = redis_gateway_detail::to_bytes(value);
    set._expire_at_ms = expire_at_ms;
    return encode_redis_kv_command(set);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::outcome_error(session& s,
                                                           const txn_outcome<std::string>& outcome)
    -> std::string {
    switch (outcome._kind) {
        case txn_outcome_kind::committed:
            ++_stats._txn_committed;
            emit("redis.txn.committed", to_string(isolation_of(s)));
            return {};
        case txn_outcome_kind::aborted: {
            ++_stats._txn_aborted;
            emit("redis.txn.aborted", to_string(isolation_of(s)));
            std::string why;
            switch (outcome._reason) {
                case txn_abort_reason::write_conflict:
                    why = "write conflict" + (outcome._conflict_key
                                                  ? " on '" + *outcome._conflict_key + "'"
                                                  : std::string{});
                    break;
                case txn_abort_reason::expired:
                    why = "its locks expired before the commit point";
                    break;
                case txn_abort_reason::unroutable:
                    why = "a key is owned by no shard";
                    break;
                case txn_abort_reason::snapshot_too_old:
                    why = "its snapshot is older than a shard's safe point";
                    break;
                case txn_abort_reason::read_conflict:
                    why = "a key it read changed after it started" +
                          (outcome._conflict_key ? " ('" + *outcome._conflict_key + "')"
                                                 : std::string{});
                    break;
                default:
                    why = "a shard did not prepare" +
                          (outcome._detail.empty() ? std::string{} : " (" + outcome._detail + ")");
                    break;
            }
            return s._writer.error("ERR transaction aborted: " + why + "; nothing applied, retry");
        }
        case txn_outcome_kind::unknown:
            ++_stats._txn_unknown;
            emit("redis.txn.unknown", to_string(isolation_of(s)));
            // Never a retry hint: the writes may have applied.
            return s._writer.error("ERR transaction " + outcome._txn.to_string() +
                                   " outcome unknown; it may have applied (" + outcome._detail +
                                   ")");
    }
    return s._writer.error("ERR transaction outcome unrecognised");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::execute_txn_command(session& s, std::string_view upper,
                                                                 const resp_command& cmd)
    -> std::string {
    auto wrong_args = [&] {
        std::string lower = cmd._argv[0];
        for (auto& c : lower) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return s._writer.error("ERR wrong number of arguments for '" + lower + "' command");
    };
    if (upper == "KYTHIRA.TXN") {
        return handle_internal_txn(s, cmd);
    }
    if (upper == "WATCH" || upper == "UNWATCH") {
        // Requirement 11.4: only under mvcc::on, which needs the timestamp
        // oracle of tier 2 and the read validation of tier 3.
        if constexpr (k_snapshot) {
            return handle_watch(s, cmd);
        } else {
            return s._writer.error("ERR " + std::string(upper) +
                                   " needs a build with mvcc::on (multi-version transactions)");
        }
    }
    if (upper == "MULTI") {
        if (cmd._argv.size() != 1) {
            return wrong_args();
        }
        if (auto e = authorize(s, "MULTI", {})) {
            return *e;
        }
        if (s._in_multi) {
            return s._writer.error("ERR MULTI calls can not be nested");
        }
        s._in_multi = true;
        s._multi_failed = false;
        s._queued.clear();
        return s._writer.simple_string("OK");
    }
    if (upper == "DISCARD") {
        if (!s._in_multi) {
            return s._writer.error("ERR DISCARD without MULTI");
        }
        s._in_multi = false;
        s._multi_failed = false;
        s._queued.clear();
        s._watched.clear();  // as Redis: DISCARD unwatches
        s._watch_ts = 0;
        return s._writer.simple_string("OK");
    }
    if (upper == "EXEC") {
        if (!s._in_multi) {
            return s._writer.error("ERR EXEC without MULTI");
        }
        s._in_multi = false;
        if (s._multi_failed) {
            s._multi_failed = false;
            s._queued.clear();
            s._watched.clear();
            s._watch_ts = 0;
            return s._writer.error("EXECABORT Transaction discarded because of previous errors.");
        }
        return handle_exec(s);
    }
    if (upper == "KYTHIRA.ISOLATION") {
        if (cmd._argv.size() > 2) {
            return wrong_args();
        }
        return handle_isolation(s, cmd);
    }
    if (upper == "MSET") {
        if (cmd._argv.size() < 3 || cmd._argv.size() % 2 == 0) {
            return wrong_args();
        }
        return handle_mset(s, cmd);
    }
    if (upper == "MGET") {
        if (cmd._argv.size() < 2) {
            return wrong_args();
        }
        return handle_mget(s, cmd);
    }
    return handle_multi_del(s, cmd);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_isolation(session& s, const resp_command& cmd)
    -> std::string {
    if (auto e = authorize(s, "KYTHIRA.ISOLATION", {})) {
        return *e;
    }
    if (cmd._argv.size() == 1) {
        return s._writer.bulk(to_string(isolation_of(s)));
    }
    auto level = parse_txn_isolation(cmd._argv[1]);
    if (!level) {
        return s._writer.error("ERR unknown isolation level '" + cmd._argv[1] + "'");
    }
    const auto offered = coordinator_type::offered_isolations();
    if (std::find(offered.begin(), offered.end(), *level) == offered.end()) {
        return s._writer.error(std::string("ERR ") +
                               isolation_unsupported_exception(*level, offered).what());
    }
    s._isolation = level;
    return s._writer.simple_string("OK");
}

/// `WATCH key [key ...]` and `UNWATCH` on the snapshot build (task 16).
///
/// The first `WATCH` takes an oracle timestamp; the next `EXEC` runs as a
/// serializable transaction started there, with every watched key in its
/// read set, so it commits only if none of them has a version newer than
/// that timestamp (and none is held by another transaction) when it
/// prepares. A later `WATCH` adds keys under the same timestamp, which is
/// stricter than Redis (a change between the two `WATCH`es also counts).
/// The reads queued in the `MULTI` are at that timestamp too, and an
/// `EXEC` with no writes is a read-only transaction: it commits without a
/// prepare, its reads one consistent snapshot as of the `WATCH`.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_watch(session& s, const resp_command& cmd)
    -> std::string {
    const auto upper = resp_to_upper(cmd._argv[0]);
    if (upper == "UNWATCH") {
        if (cmd._argv.size() != 1) {
            return s._writer.error("ERR wrong number of arguments for 'unwatch' command");
        }
        if (auto e = authorize(s, "UNWATCH", {})) {
            return *e;
        }
        s._watched.clear();
        s._watch_ts = 0;
        return s._writer.simple_string("OK");
    }
    if (cmd._argv.size() < 2) {
        return s._writer.error("ERR wrong number of arguments for 'watch' command");
    }
    std::vector<std::string_view> keys(cmd._argv.begin() + 1, cmd._argv.end());
    if (auto e = authorize(s, "WATCH", keys)) {
        return *e;
    }
    if (s._watch_ts == 0) {
        try {
            s._watch_ts = txn_allocate_timestamps(1, _config._command_timeout)._first;
        } catch (const std::exception& e) {
            return s._writer.error(std::string("ERR WATCH could not take a timestamp: ") +
                                   e.what() + ", retry");
        }
    }
    for (std::size_t i = 1; i < cmd._argv.size(); ++i) {
        s._watched.insert(cmd._argv[i]);
    }
    return s._writer.simple_string("OK");
}

/// One `MSET`: every pair in one transaction, all or none (Requirement 11.1).
/// Under `_immutable_values` a key already holding the same bytes is left
/// out of the write, and one holding other bytes refuses the whole command,
/// as `SET` refuses it.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_mset(session& s, const resp_command& cmd)
    -> std::string {
    if constexpr (!k_transactional) {
        return s._writer.error("ERR transactions are not built in");
    } else {
        std::vector<std::string_view> keys;
        for (std::size_t i = 1; i < cmd._argv.size(); i += 2) {
            keys.emplace_back(cmd._argv[i]);
        }
        if (auto e = authorize(s, "MSET", keys)) {
            return *e;
        }
        for (std::size_t i = 2; i < cmd._argv.size(); i += 2) {
            if (cmd._argv[i].size() > _config._max_value_bytes) {
                ++_stats._oversize_rejections;
                emit("redis.oversize_rejections", "MSET");
                return s._writer.error("ERR value exceeds the configured maximum of " +
                                       std::to_string(_config._max_value_bytes) + " bytes");
            }
        }
        try {
            txn_client client(*this);
            coordinator_type coordinator(client);
            coordinator.begin(make_options(s));
            // A repeated key: the last value wins, as in Redis.
            std::map<std::string, std::string_view> pairs;
            for (std::size_t i = 1; i < cmd._argv.size(); i += 2) {
                pairs.insert_or_assign(cmd._argv[i], cmd._argv[i + 1]);
            }
            std::size_t bytes = 0;
            for (const auto& [key, value] : pairs) {
                if (_config._immutable_values && !redis_acl::key_is_mutable(*s._identity, key)) {
                    if (auto existing = coordinator.get(key)) {
                        if (redis_gateway_detail::to_string(*existing) == value) {
                            continue;
                        }
                        coordinator.rollback();
                        ++_stats._value_conflicts;
                        emit("redis.value_conflicts", "MSET");
                        return s._writer.error("ERR value conflict for an existing key");
                    }
                }
                coordinator.put(key, set_command(key, value, 0));
                bytes += value.size();
            }
            auto outcome = coordinator.commit();
            if (auto e = outcome_error(s, outcome); !e.empty()) {
                return e;
            }
            _stats._writes += pairs.size();
            emit("redis.writes", "MSET", static_cast<std::int64_t>(pairs.size()));
            emit("redis.bytes_written", "MSET", static_cast<std::int64_t>(bytes));
            return s._writer.simple_string("OK");
        } catch (const std::exception& e) {
            return s._writer.error(std::string("ERR transaction failed: ") + e.what() + ", retry");
        }
    }
}

/// `MGET`: a read-only transaction. Each key is read at the connection's
/// isolation; under the tier-1 levels that is per key, not one snapshot.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_mget(session& s, const resp_command& cmd)
    -> std::string {
    if constexpr (!k_transactional) {
        return s._writer.error("ERR transactions are not built in");
    } else {
        std::vector<std::string_view> keys(cmd._argv.begin() + 1, cmd._argv.end());
        if (auto e = authorize(s, "MGET", keys)) {
            return *e;
        }
        try {
            txn_client client(*this);
            coordinator_type coordinator(client);
            coordinator.begin(make_options(s));
            std::vector<std::string> out;
            out.reserve(keys.size());
            for (std::size_t i = 1; i < cmd._argv.size(); ++i) {
                auto value = coordinator.get(cmd._argv[i]);
                if (value) {
                    ++_stats._hits;
                    out.push_back(s._writer.bulk(std::span<const std::byte>(*value)));
                } else {
                    ++_stats._misses;
                    out.push_back(s._writer.null());
                }
            }
            coordinator.rollback();
            return s._writer.array(out);
        } catch (const std::exception& e) {
            return s._writer.error(std::string("ERR transaction failed: ") + e.what() + ", retry");
        }
    }
}

/// Multi-key `DEL`: one transaction deleting every key that was present
/// when read, and the count of those, as Redis replies.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_multi_del(session& s, const resp_command& cmd)
    -> std::string {
    if constexpr (!k_transactional) {
        return s._writer.error("ERR transactions are not built in");
    } else {
        std::vector<std::string_view> keys(cmd._argv.begin() + 1, cmd._argv.end());
        if (auto e = authorize(s, "DEL", keys)) {
            return *e;
        }
        try {
            txn_client client(*this);
            coordinator_type coordinator(client);
            coordinator.begin(make_options(s));
            std::set<std::string> present;
            for (std::size_t i = 1; i < cmd._argv.size(); ++i) {
                const auto& key = cmd._argv[i];
                if (!present.contains(key) && coordinator.get(key).has_value()) {
                    present.insert(key);
                    coordinator.put(key, encode_redis_kv_command(redis_kv_del_command{key}));
                }
            }
            auto outcome = coordinator.commit();
            if (auto e = outcome_error(s, outcome); !e.empty()) {
                return e;
            }
            _stats._deletes += present.size();
            emit("redis.deletes", "DEL", static_cast<std::int64_t>(present.size()));
            for (const auto& key : present) {
                if (auto desc = _data.route(key)) {
                    forget_lru(desc->group_id(), key);
                }
            }
            return s._writer.integer(static_cast<std::int64_t>(present.size()));
        } catch (const std::exception& e) {
            return s._writer.error(std::string("ERR transaction failed: ") + e.what() + ", retry");
        }
    }
}

/// Inside `MULTI`: check and queue. A refused command dooms the `EXEC`
/// (EXECABORT), as in Redis: one `EXEC` cannot run (a server, connection
/// or keyspace-wide command), a wrong argument count, or a refused
/// authorization. Every other error is that command's element of the
/// `EXEC` reply, as Redis reports a runtime error (task 11).
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::queue_in_multi(session& s, std::string_view upper,
                                                            const resp_command& cmd)
    -> std::string {
    auto refuse = [&](std::string reply) {
        s._multi_failed = true;
        return reply;
    };
    const auto* info = find_redis_command(upper);
    const bool keyed_group =
        info != nullptr && (info->group == "string" || info->group == "generic" ||
                            info->group == "hash" || info->group == "set" || info->group == "list");
    const bool queueable =
        keyed_group && info->status == redis_command_status::shipped &&
        (info->flags & redis_command_flag::no_multi) == 0 &&
        (info->flags & redis_command_flag::blocking) == 0 &&
        (info->first_key > 0 || (info->flags & redis_command_flag::movablekeys) != 0) &&
        !k_string_only_store;
    if (!queueable) {
        return refuse(s._writer.error("ERR " + std::string(upper) +
                                      " is not supported inside MULTI on this gateway"));
    }
    const auto argc = static_cast<std::ptrdiff_t>(cmd._argv.size());
    const bool arity_ok =
        (info->arity > 0 && argc == info->arity) || (info->arity < 0 && argc >= -info->arity);
    if (!arity_ok || (upper == "MSET" && argc % 2 == 0)) {
        std::string lower = cmd._argv[0];
        for (auto& c : lower) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return refuse(s._writer.error("ERR wrong number of arguments for '" + lower + "' command"));
    }
    // The registry's key positions; a command with movable keys has its
    // keys checked when EXEC runs it, as that command's error.
    std::vector<std::string_view> keys;
    if (info->first_key > 0) {
        const auto first = std::ptrdiff_t{info->first_key};
        const auto last_key = std::ptrdiff_t{info->last_key};
        const std::ptrdiff_t last = last_key < 0 ? argc + last_key : last_key;
        const std::ptrdiff_t step = std::max<std::ptrdiff_t>(std::ptrdiff_t{info->step}, 1);
        for (std::ptrdiff_t i = first; i <= last && i < argc; i += step) {
            keys.emplace_back(cmd._argv[static_cast<std::size_t>(i)]);
        }
    }
    if (auto e = authorize(s, upper, keys)) {
        return refuse(*e);
    }
    s._queued.push_back(cmd);
    return s._writer.simple_string("QUEUED");
}

/// `EXEC`: the queued commands as one transaction (task 11, design
/// Component 5). Each runs through its usual handler against the
/// transaction's view: reads see what the transaction read with its own
/// earlier writes on top, as a Redis `MULTI` does, and writes are `exec`
/// records the same appliers `apply()` runs evaluate against the view, so
/// each reply is known before the commit. The commit then installs each
/// changed key's resulting value (redis_txn_view.hpp); if it does not
/// commit, `EXEC` answers with that error instead of the array, and
/// nothing applied. A command's own error (a value conflict under
/// `_immutable_values`, `WRONGTYPE`, a syntax error) is its element and
/// writes nothing, the way Redis reports a runtime error inside `EXEC`.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_exec(session& s) -> std::string {
    auto queued = std::move(s._queued);
    s._queued.clear();
    // EXEC unwatches whatever its outcome, as in Redis.
    const auto watched = std::exchange(s._watched, {});
    const auto watch_ts = std::exchange(s._watch_ts, 0);
    if constexpr (!k_transactional || k_string_only_store) {
        return s._writer.error("ERR transactions are not built in");
    } else {
        try {
            txn_client client(*this);
            coordinator_type coordinator(client);
            auto options = make_options(s);
            if (!watched.empty()) {
                // The whole EXEC runs as a serializable transaction that
                // started at the first WATCH: its reads are at that point,
                // and its commit fails validation if a watched key changed
                // since (task 16). Not retried: the watch is what failed.
                options.isolation = txn_isolation::serializable;
                options.start_ts = watch_ts;
                options.max_retries = 0;
            }
            coordinator.begin(options);
            for (const auto& key : watched) {
                coordinator.watch(key);
            }
            auto view = make_txn_view(coordinator, client);
            std::vector<std::string> replies;
            replies.reserve(queued.size());
            s._txn_view = &view;
            try {
                for (const auto& cmd : queued) {
                    replies.push_back(execute_command(s, resp_to_upper(cmd._argv[0]), cmd));
                    if (auto failed = view.failure()) {
                        // A read the transaction could not make: a reply
                        // built around it is not the transaction's.
                        std::rethrow_exception(failed);
                    }
                }
            } catch (...) {
                s._txn_view = nullptr;
                throw;
            }
            s._txn_view = nullptr;
            if (auto refused = stage_txn_writes(s, coordinator, view)) {
                coordinator.rollback();
                return *refused;
            }
            auto outcome = coordinator.commit();
            // A watched key that changed fails one of two ways: read
            // validation (`read_conflict`), or, when the MULTI also writes
            // that key, first-committer-wins finding a version newer than
            // the WATCH (`write_conflict` with no holder). Both mean what
            // Redis means by a null array: a watched key changed, nothing
            // applied. A conflict with a live holder is not this: that is
            // a lock, already retried, and keeps its error.
            const bool watched_changed =
                outcome._reason == txn_abort_reason::read_conflict ||
                (outcome._reason == txn_abort_reason::write_conflict &&
                 !outcome._holder.has_value() && outcome._conflict_key.has_value() &&
                 watched.contains(*outcome._conflict_key));
            if (!watched.empty() && outcome._kind == txn_outcome_kind::aborted && watched_changed) {
                ++_stats._txn_aborted;
                emit("redis.txn.aborted", "watch");
                return s._writer.null_array();
            }
            if (auto e = outcome_error(s, outcome); !e.empty()) {
                return e;
            }
            for (const auto& [key, entry] : view.writes()) {
                if (entry) {
                    ++_stats._writes;
                } else {
                    ++_stats._deletes;
                }
                if (auto desc = _data.route(key)) {
                    if (entry) {
                        touch_lru(desc->group_id(), key);
                    } else {
                        forget_lru(desc->group_id(), key);
                    }
                }
            }
            return s._writer.array(replies);
        } catch (const std::exception& e) {
            return s._writer.error(std::string("ERR transaction failed: ") + e.what() + ", retry");
        }
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::make_txn_view(coordinator_type& coordinator,
                                                           txn_client& client) -> redis_txn_view {
    return redis_txn_view([&coordinator, &client](const std::string& key) {
        auto value = coordinator.get(key);
        if (!value) {
            return redis_txn_view::entry_handle{};
        }
        if (auto entry = client.entry_of(key)) {
            return entry;
        }
        // A shard that answered without the typed extension: a string
        // whose deadline that gateway does not say.
        auto entry = std::make_shared<redis_kv_value_entry>();
        entry->_value = std::move(*value);
        return redis_txn_view::entry_handle{std::move(entry)};
    });
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::stage_txn_writes(session& s,
                                                              coordinator_type& coordinator,
                                                              const redis_txn_view& view)
    -> std::optional<std::string> {
    const auto now = now_ms();
    for (const auto& [key, entry] : view.writes()) {
        if (entry && redis_entry_type(*entry) != redis_value_type::string) {
            // A collection commits as `KYTHIRA.INSTALL`, an `exec` record
            // only a group past the gate applies. A group with no replica
            // here is checked by the commands that made the collection.
            if (auto refused = format_refusal(s, key, k_redis_typed_values_level)) {
                return refused;
            }
        }
        coordinator.put(key, redis_txn_write_record(key, entry, now));
    }
    return std::nullopt;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_view_exec(session& s, std::string_view name,
                                                           const std::string& key,
                                                           redis_command_id id,
                                                           const std::vector<std::string>& args,
                                                           const std::string& mutable_bits)
    -> std::string {
    const auto t = now_ms();
    const auto record = make_redis_exec_record(key, static_cast<std::uint16_t>(id), args, t,
                                               _config._immutable_values, mutable_bits);
    auto reply = apply_redis_exec(*s._txn_view, record, t);
    if (!reply) {
        return s._writer.error("ERR unknown command id " +
                               std::to_string(static_cast<unsigned>(id)));
    }
    if (reply->is_error() && reply->_text.rfind("ERR value conflict", 0) == 0) {
        ++_stats._value_conflicts;
        emit("redis.value_conflicts", name);
    }
    return render_redis_reply(*reply, s._writer.version());
}

/// `MSET` and `MGET` against a transaction's view. `MSET` under
/// `_immutable_values` refuses the whole command when a key outside the
/// user's mutable prefixes holds other bytes, as outside a transaction.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::txn_view_mset_mget(session& s, std::string_view upper,
                                                                const resp_command& cmd)
    -> std::string {
    auto& view = *s._txn_view;
    const auto t = now_ms();
    const auto live = [&](const redis_txn_view::entry_handle& e) {
        return e && (e->_expire_at_ms == 0 || e->_expire_at_ms > t);
    };
    if (upper == "MGET") {
        std::vector<std::string> out;
        for (std::size_t i = 1; i < cmd._argv.size(); ++i) {
            auto e = view.find(cmd._argv[i]);
            // As Redis: a key holding another type reads as nil.
            if (live(e) && redis_entry_type(*e) == redis_value_type::string) {
                out.push_back(s._writer.bulk(std::span<const std::byte>(e->_value)));
            } else {
                out.push_back(s._writer.null());
            }
        }
        return s._writer.array(out);
    }
    if (cmd._argv.size() < 3 || cmd._argv.size() % 2 == 0) {
        return s._writer.error("ERR wrong number of arguments for 'mset' command");
    }
    for (std::size_t i = 2; i < cmd._argv.size(); i += 2) {
        if (cmd._argv[i].size() > _config._max_value_bytes) {
            ++_stats._oversize_rejections;
            return s._writer.error("ERR value exceeds the configured maximum of " +
                                   std::to_string(_config._max_value_bytes) + " bytes");
        }
    }
    if (_config._immutable_values) {
        for (std::size_t i = 1; i < cmd._argv.size(); i += 2) {
            const auto& key = cmd._argv[i];
            if (redis_acl::key_is_mutable(*s._identity, key)) {
                continue;
            }
            auto e = view.find(key);
            if (live(e) && (redis_entry_type(*e) != redis_value_type::string ||
                            redis_gateway_detail::to_string(e->_value) != cmd._argv[i + 1])) {
                ++_stats._value_conflicts;
                return s._writer.error("ERR value conflict for an existing key");
            }
        }
    }
    for (std::size_t i = 1; i < cmd._argv.size(); i += 2) {
        view.put(cmd._argv[i], redis_gateway_detail::to_bytes(cmd._argv[i + 1]), 0);
    }
    return s._writer.simple_string("OK");
}

/// `KYTHIRA.TXN SEND <envelope> <key>...` and `KYTHIRA.TXN READ <key>`: the
/// coordinator's hop to a shard leader's gateway (Requirement 11.5). Only on
/// a connection authenticated as the internal identity, and never forwarded
/// again: a gateway that does not lead the shard answers with the retry
/// error and the sender asks again.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_internal_txn(session& s,
                                                                 const resp_command& cmd)
    -> std::string {
    if (!s._internal) {
        audit(s, "KYTHIRA.TXN", "internal command from a client");
        return s._writer.error("NOPERM KYTHIRA.TXN is internal to the gateways");
    }
    if (cmd._argv.size() < 3) {
        return s._writer.error("ERR wrong number of arguments for 'kythira.txn' command");
    }
    const auto sub = resp_to_upper(cmd._argv[1]);
    if constexpr (!k_transactional) {
        return s._writer.error("ERR transactions are not built in");
    } else {
        if (sub == "READ") {
            if (cmd._argv.size() != 3) {
                return s._writer.error("ERR wrong number of arguments for 'kythira.txn' command");
            }
            auto local = txn_read_local(cmd._argv[2]);
            if (!local) {
                return s._writer.error("ERR shard has no reachable leader, retry");
            }
            return s._writer.bulk(
                redis_gateway_detail::encode_txn_read(local->_read, local->_entry.get()));
        }
        if (sub == "TS") {
            // Tier 2: timestamps from this host's oracle, never forwarded.
            std::size_t n = 0;
            const auto& arg = cmd._argv[2];
            if (cmd._argv.size() != 3 ||
                std::from_chars(arg.data(), arg.data() + arg.size(), n).ec != std::errc{} ||
                n == 0) {
                return s._writer.error("ERR wrong arguments for 'kythira.txn ts'");
            }
            try {
                auto range = _data.allocate_timestamps(n, _config._command_timeout).get();
                return s._writer.bulk(redis_gateway_detail::encode_timestamp_range(range));
            } catch (const shard_not_leader_exception<group_id_type, node_id_type>&) {
                return s._writer.error("ERR not the timestamp oracle's leader, retry");
            } catch (const std::exception& e) {
                return s._writer.error(std::string("ERR timestamp oracle: ") + e.what() +
                                       ", retry");
            }
        }
        if (sub == "READAT") {
            // Tier 2: `READAT <ts> <key>`, on this replica only.
            std::uint64_t ts = 0;
            const auto& arg = cmd._argv[2];
            if (cmd._argv.size() != 4 ||
                std::from_chars(arg.data(), arg.data() + arg.size(), ts).ec != std::errc{}) {
                return s._writer.error("ERR wrong arguments for 'kythira.txn readat'");
            }
            try {
                auto local = txn_read_at_local(cmd._argv[3], ts, _config._command_timeout);
                if (!local) {
                    return s._writer.error("ERR shard has no reachable leader, retry");
                }
                return s._writer.bulk(
                    redis_gateway_detail::encode_txn_read(local->_read, local->_entry.get()));
            } catch (const snapshot_too_old_exception& e) {
                return s._writer.error(std::string(redis_gateway_detail::k_too_old_prefix) +
                                       std::to_string(e.start_ts()) + " " +
                                       std::to_string(e.safe_point()));
            }
        }
        if (sub == "SEND") {
            if (cmd._argv.size() < 4) {
                return s._writer.error("ERR wrong number of arguments for 'kythira.txn' command");
            }
            std::vector<std::string> keys(cmd._argv.begin() + 3, cmd._argv.end());
            try {
                auto f = _data.propose_txn(keys, redis_gateway_detail::to_bytes(cmd._argv[2]),
                                           _config._command_timeout);
                if (!f.wait(_config._command_timeout)) {
                    return s._writer.error("ERR timeout submitting to shard, retry");
                }
                return s._writer.bulk(std::span<const std::byte>(std::move(f).get()));
            } catch (
                const shard_epoch_mismatch_exception<group_id_type, std::string, node_id_type>& e) {
                return s._writer.error(std::string("KYTHIRA.MOVED ") + e.what());
            } catch (const shard_not_leader_exception<group_id_type, node_id_type>&) {
                return s._writer.error("ERR shard has no reachable leader, retry");
            } catch (const unknown_shard_exception<group_id_type>&) {
                return s._writer.error("ERR shard has no reachable leader, retry");
            } catch (const std::exception& e) {
                return s._writer.error(std::string("ERR transaction op failed: ") + e.what());
            }
        }
        return s._writer.error("ERR unknown KYTHIRA.TXN subcommand '" + cmd._argv[1] + "'");
    }
}

/// `KYTHIRA.DATA ROUTE <key>`, `ROUTES <range>` and `PROPOSE <group>
/// <version> <conf_version> <entry>`: the data-layer API of a node with a
/// replica (Requirement 18.4). Only on a connection authenticated as the
/// internal identity. A refusal is answered, never forwarded (Requirement
/// 18.3): the caller makes every hop. Each answer is a bulk string in
/// redis_data_wire.hpp's encoding; a RESP error means the call itself was
/// malformed.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::peer_role_refusal(session& s, std::string_view upper)
    -> std::optional<std::string> {
    if (!s._internal) {
        return std::nullopt;
    }
    // Requirement 19.2: authenticated calls need `gateway`; the data-layer
    // API, transaction messages and whole commands a co-located peer
    // forwards need `front_end` or `data`. A session the internal secret
    // authenticated has the roles the secret implies.
    const auto roles = s._peer_roles.value_or(layers::role_set{layers::role::data});
    if (upper == "KYTHIRA.MEMBERS") {
        return std::nullopt;  // every member announces itself (task 18)
    }
    const auto needed = upper == "KYTHIRA.CALL"
                            ? layers::role_set{layers::role::gateway}
                            : layers::role_set{layers::role::front_end, layers::role::data};
    if (roles.intersects(needed)) {
        return std::nullopt;
    }
    audit(s, upper, "caller's layer roles " + roles.to_string() + " lack " + needed.to_string());
    return s._writer.error("NOPERM a caller with the layer roles " + roles.to_string() +
                           " may not send " + std::string(upper) + " (it needs " +
                           needed.to_string() + ")");
}

/// `KYTHIRA.CALL <state> <command> <arg>...` (task 17): the gateway holds
/// the connection, the front end runs one command as that connection and
/// keeps nothing, so the next call can go to any front end.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_call(session& s, const resp_command& cmd)
    -> std::string {
    if (!s._internal) {
        audit(s, "KYTHIRA.CALL", "internal command from a client");
        return s._writer.error("NOPERM KYTHIRA.CALL is internal to the gateways");
    }
    if (!_config._layer_roles.has(layers::role::front_end)) {
        return s._writer.error("ERR this node runs no front end (KYTHIRA_REDIS_ROLES=" +
                               _config._layer_roles.to_string() + ")");
    }
    if (cmd._argv.size() < 3) {
        return s._writer.error("ERR wrong number of arguments for 'kythira.call' command");
    }
    auto state = redis_call_wire::decode_state(cmd._argv[1]);
    if (!state || (state->isolation && *state->isolation > 3)) {
        return s._writer.error("ERR malformed connection state for 'kythira.call'");
    }
    session c;
    c._writer.set_version(state->resp_version);
    // The front end's own ACL decides the user's role and key scopes; the
    // gateway only vouches for who authenticated.
    c._identity = _acl.identity_of(state->user);
    if (!c._identity && _acl.empty() && _config._allow_anonymous && state->user == "anonymous") {
        c._identity = redis_identity{"anonymous", redis_role::admin, {""}};
    }
    if (!c._identity || state->user == _config._internal_user) {
        audit(s, "KYTHIRA.CALL", "unknown or disabled user '" + state->user + "'");
        return s._writer.error("NOAUTH the connection's user is not an enabled ACL user here");
    }
    c._source = s._source + " (call)";
    c._rate_key = s._rate_key;
    if (state->isolation) {
        c._isolation = static_cast<txn_isolation>(*state->isolation);
    }
    c._in_multi = state->in_multi;
    c._multi_failed = state->multi_failed;
    c._watch_ts = state->watch_ts;
    c._watched.insert(state->watched.begin(), state->watched.end());
    for (auto& argv : state->queued) {
        c._queued.push_back(resp_command{std::move(argv)});
    }
    const auto queued_before = c._queued.size();
    resp_command inner;
    inner._argv.assign(cmd._argv.begin() + 2, cmd._argv.end());
    const auto upper = resp_to_upper(inner._argv[0]);

    redis_call_wire::call_answer answer;
    // A draining front end counts its calls, so it reports itself drained
    // only once none is running (task 18).
    ++_stats._calls_in_flight;
    ++_stats._front_end_calls_served;
    try {
        answer.reply = execute_command(c, upper, inner);
    } catch (...) {
        --_stats._calls_in_flight;
        throw;
    }
    --_stats._calls_in_flight;
    answer.queued = c._queued.size() > queued_before;
    answer.state.user = state->user;
    answer.state.resp_version = static_cast<std::uint8_t>(c._writer.version());
    if (c._isolation) {
        answer.state.isolation = static_cast<std::uint8_t>(*c._isolation);
    }
    answer.state.in_multi = c._in_multi;
    answer.state.multi_failed = c._multi_failed;
    answer.state.watch_ts = c._watch_ts;
    answer.state.watched.assign(c._watched.begin(), c._watched.end());
    return s._writer.bulk(redis_call_wire::encode_answer(answer));
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_data(session& s, const resp_command& cmd)
    -> std::string {
    if (!s._internal) {
        audit(s, "KYTHIRA.DATA", "internal command from a client");
        return s._writer.error("NOPERM KYTHIRA.DATA is internal to the gateways");
    }
    if (cmd._argv.size() < 3) {
        return s._writer.error("ERR wrong number of arguments for 'kythira.data' command");
    }
    if (!_data.running()) {
        return s._writer.error("LOADING Kythira is loading the dataset in memory");
    }
    const auto sub = resp_to_upper(cmd._argv[1]);
    if (sub == "ROUTE" || sub == "ROUTES") {
        if (cmd._argv.size() != 3) {
            return s._writer.error("ERR wrong number of arguments for 'kythira.data' command");
        }
        if (sub == "ROUTE") {
            return s._writer.bulk(
                redis_data_wire::encode_routes(data_routes_payload(_data.route_row(cmd._argv[2]))));
        }
        auto range = redis_data_wire::decode_range(cmd._argv[2]);
        if (!range) {
            return s._writer.error("ERR malformed range for 'kythira.data routes'");
        }
        return s._writer.bulk(
            redis_data_wire::encode_routes(data_routes_payload(_data.routes(*range))));
    }
    if (sub == "PROPOSE") {
        if (cmd._argv.size() != 6) {
            return s._writer.error("ERR wrong number of arguments for 'kythira.data' command");
        }
        return s._writer.bulk(data_propose(cmd));
    }
    if (sub == "READ") {
        if (cmd._argv.size() != 4) {
            return s._writer.error("ERR wrong number of arguments for 'kythira.data' command");
        }
        auto mode = redis_data_wire::parse_read_mode(resp_to_upper(cmd._argv[2]));
        if (!mode) {
            return s._writer.error("ERR unknown read mode for 'kythira.data read'");
        }
        return s._writer.bulk(data_read(*mode, cmd._argv[3]));
    }
    return s._writer.error("ERR unknown KYTHIRA.DATA subcommand '" + cmd._argv[1] + "'");
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::data_routes_payload(
    std::vector<typename Host::descriptor_type> routes)
    -> redis_data_wire::routes_payload<group_id_type, node_id_type> {
    redis_data_wire::routes_payload<group_id_type, node_id_type> out;
    std::set<node_id_type> seen;
    auto add = [&](const node_id_type& n) {
        if (!seen.insert(n).second) {
            return;
        }
        if (auto endpoint = forward_endpoint(n)) {
            out.addresses.emplace_back(n, std::move(*endpoint));
        }
    };
    for (const auto& d : routes) {
        for (const auto& v : d._voters) {
            add(v);
        }
        for (const auto& l : d._learners) {
            add(l);
        }
        if (d._leader_hint) {
            add(*d._leader_hint);
        }
    }
    out.routes = std::move(routes);
    return out;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::data_propose(const resp_command& cmd) -> std::string {
    using redis_data_wire::propose_status;
    std::uint64_t group = 0;
    shard_epoch epoch{};
    auto number = [](const std::string& a, std::uint64_t& v) {
        return std::from_chars(a.data(), a.data() + a.size(), v).ec == std::errc{};
    };
    if (!number(cmd._argv[2], group) || !number(cmd._argv[3], epoch._version) ||
        !number(cmd._argv[4], epoch._conf_version)) {
        return redis_data_wire::encode_propose_status(propose_status::failed,
                                                      "malformed group or epoch");
    }
    const auto group_id = static_cast<group_id_type>(group);
    // A refusal that only says "not now" (a split or merge in flight, this
    // replica's epoch behind the caller's): name this node as the leader to
    // ask again, after the caller's pause.
    auto again = [this] {
        return redis_data_wire::encode_propose_not_leader(
            std::optional<node_id_type>{_data.self()});
    };
    try {
        auto f = _data.propose_to(group_id, epoch, redis_gateway_detail::to_bytes(cmd._argv[5]),
                                  _config._command_timeout);
        if (!f.wait(_config._command_timeout)) {
            return redis_data_wire::encode_propose_status(propose_status::timeout);
        }
        const auto result = std::move(f).get();
        return redis_data_wire::encode_propose_ok(
            std::string_view(reinterpret_cast<const char*>(result.data()), result.size()));
    } catch (const shard_epoch_mismatch_exception<group_id_type, std::string, node_id_type>& e) {
        return redis_data_wire::encode_propose_stale(data_routes_payload(e.current_descriptors()));
    } catch (const cross_shard_command_exception<group_id_type, std::string>& e) {
        // The entry's key left the group (a split the caller has not seen).
        auto routes = _data.route_row(e.key());
        if (routes.empty()) {
            return redis_data_wire::encode_propose_status(propose_status::unrouted);
        }
        return redis_data_wire::encode_propose_stale(data_routes_payload(std::move(routes)));
    } catch (const shard_not_leader_exception<group_id_type, node_id_type>& e) {
        return redis_data_wire::encode_propose_not_leader(e.leader_hint());
    } catch (const unknown_shard_exception<group_id_type>&) {
        return redis_data_wire::encode_propose_status(propose_status::unknown_group);
    } catch (const unrouted_key_exception<std::string>&) {
        return redis_data_wire::encode_propose_status(propose_status::unrouted);
    } catch (const key_locked_exception<std::string>& e) {
        return redis_data_wire::encode_propose_locked(e.key(), e.holder(), e.primary());
    } catch (const shard_busy_exception<group_id_type>&) {
        return again();
    } catch (const shard_merging_exception<group_id_type>&) {
        return again();
    } catch (const shard_epoch_ahead_exception<group_id_type>&) {
        return again();
    } catch (const std::exception& e) {
        return redis_data_wire::encode_propose_status(propose_status::failed, e.what());
    }
}

/// A read on this node's own replica, never another node's (Requirement
/// 18.3): the front end that asked makes every hop. The same lookup a
/// co-located `GET` makes (redis_data_access.hpp), so the reply bytes match
/// whichever layout serves them (Requirement 18.6). The deadline travels
/// with the value: the front end decides expiry on its clock, as a
/// co-located node does on its own.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::data_read(redis_data_wire::read_mode mode,
                                                       const std::string& key) -> std::string {
    using redis_data_wire::read_status;
    auto& local = _data.local();
    auto read = [&](auto&& barrier) {
        return local.read(key, mode == redis_data_wire::read_mode::any_replica,
                          std::forward<decltype(barrier)>(barrier));
    };
    auto outcome =
        mode == redis_data_wire::read_mode::linearizable
            // read_local()'s no-op: a sweep naming the key with deadline 0.
            ? read([&] {
                  try {
                      auto f = local.propose(
                          key, encode_redis_kv_command(redis_kv_sweep_command{{{key, 0}}}),
                          _config._command_timeout);
                      if (!f.wait(_config._command_timeout)) {
                          return false;
                      }
                      (void)std::move(f).get();
                      return true;
                  } catch (const std::exception&) {
                      return false;
                  }
              })
            : read(nullptr);
    switch (outcome._status) {
        case redis_data_status::ok:
            break;
        case redis_data_status::loading:
            return redis_data_wire::encode_read_status(read_status::loading);
        case redis_data_status::unrouted:
            return redis_data_wire::encode_read_status(read_status::unrouted);
        case redis_data_status::barrier_failed:
            return redis_data_wire::encode_read_status(read_status::barrier_failed);
        case redis_data_status::not_replicated:
            return redis_data_wire::encode_read_elsewhere(read_status::not_replicated,
                                                          outcome._leader);
        case redis_data_status::no_leader:
            return redis_data_wire::encode_read_elsewhere(read_status::not_leader, outcome._leader);
    }
    if (!outcome._entry) {
        return redis_data_wire::encode_read_miss();
    }
    auto bytes = value_access::read(outcome._context, *outcome._entry);
    if (!bytes) {
        return redis_data_wire::encode_read_miss();  // as read_local(): unvouched bytes
    }
    const auto view = bytes->view();
    return redis_data_wire::encode_read_value(
        outcome._entry->_expire_at_ms,
        std::string_view(reinterpret_cast<const char*>(view.data()), view.size()));
}

// ─────────────────────────────────────────────────────────────────────────────
// maintenance: expiry sweep and eviction
// ─────────────────────────────────────────────────────────────────────────────

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::run_maintenance() -> std::size_t {
    if (!_data.running()) {
        return 0;
    }
    std::size_t proposals = 0;
    const auto now = now_ms();
    for (const auto& group : _data.local_groups()) {
        auto* node = _data.local_replica(group);
        if (node == nullptr || !node->is_leader()) {
            // Followers keep no LRU: theirs would be stale on promotion anyway.
            std::lock_guard<std::mutex> lock(_lru_mutex);
            _lru.erase(group);
            continue;
        }
        auto desc = _data.local_route(group);
        if (!desc) {
            continue;
        }

        // Expiry: a bounded batch per tick, never the whole backlog at once.
        auto expired = node->with_state_machine([&](auto& sm) {
            auto out = redis_gateway_detail::kv_of(sm).collect_expired(now, _config._sweep_batch);
            if constexpr (k_transactional) {
                // A key a transaction holds is the transaction's to finish;
                // a sweep naming it would be refused whole.
                std::erase_if(out,
                              [&sm](const auto& e) { return sm.intent_on(e._key).has_value(); });
            }
            return out;
        });
        if (!expired.empty()) {
            redis_kv_sweep_command sweep;
            sweep._entries = std::move(expired);
            auto count = sweep._entries.size();
            try {
                auto f = _data.propose_to(group, desc->epoch(), encode_redis_kv_command(sweep),
                                          _config._command_timeout);
                if (f.wait(_config._command_timeout)) {
                    (void)std::move(f).get();
                    _stats._expirations += count;
                    emit("redis.expirations", "sweep", static_cast<std::int64_t>(count));
                    ++proposals;
                    for (const auto& e : sweep._entries) {
                        forget_lru(group, e._key);
                    }
                }
            } catch (const std::exception& e) {
                _logger.log(log_level::debug, "redis gateway: sweep proposal failed",
                            {{"error", e.what()}});
            }
        }

        // Eviction: only when the shard is over its budget. Over-budget is a
        // metric and a log line; it is never a reason to refuse a write.
        auto [bytes, key_count] = node->with_state_machine([](auto& sm) {
            return std::pair{redis_gateway_detail::kv_of(sm).approximate_size_bytes(),
                             redis_gateway_detail::kv_of(sm).approximate_key_count()};
        });
        // The node disk budget (Requirement 6.1): bytes the fullest voter of
        // this shard holds over it, to be freed from this shard.
        const std::uint64_t excess =
            _cache_hooks._excess_bytes ? _cache_hooks._excess_bytes(group, desc->voters()) : 0;
        if ((bytes <= _config._max_shard_bytes && excess == 0) || key_count == 0) {
            continue;
        }
        ++_stats._over_budget_ticks;
        emit("redis.shard_over_budget", "evict");
        _logger.log(log_level::warning, "redis gateway: shard over budget, evicting",
                    {{"group", std::to_string(group)},
                     {"bytes", std::to_string(bytes)},
                     {"budget", std::to_string(_config._max_shard_bytes)},
                     {"disk_excess", std::to_string(excess)}});

        std::vector<std::string> victims;
        {
            std::lock_guard<std::mutex> lock(_lru_mutex);
            auto& lru = _lru[group];
            if (lru._order.empty()) {
                // Fresh leadership: seed from the shard itself so eviction can
                // proceed. Key order is arbitrary as an LRU, which is fine —
                // any order beats refusing to evict.
                node->with_state_machine([&](auto& sm) {
                    redis_gateway_detail::kv_of(sm).for_each_key(
                        [&](const std::string& key, const entry_type&) {
                            lru._order.push_back(key);
                            lru._index.emplace(key, std::prev(lru._order.end()));
                        });
                });
            }
            // Walk from the least recently read end. Against the shard budget
            // every key counts its full size. Against the disk excess a key
            // counts only the bytes evicting it frees on disk: a key whose
            // chunks are still pending (a fresh write, inside the orphan
            // grace) or shared frees nothing, so it is passed over rather
            // than evicted for no gain. Without this a burst of writes over
            // the budget would empty the shard and free nothing. The walk is
            // capped so a shard of pinned keys costs a bounded scan per tick.
            std::size_t freed = 0;
            std::uint64_t disk_freed = 0;
            std::size_t scanned = 0;
            const std::size_t max_scan = _config._sweep_batch * evict_scan_factor;
            auto it = lru._order.end();
            while (it != lru._order.begin() && victims.size() < _config._sweep_batch &&
                   scanned < max_scan) {
                const bool shard_over = freed < bytes && bytes - freed > _config._max_shard_bytes;
                if (!shard_over && disk_freed >= excess) {
                    break;
                }
                --it;
                ++scanned;
                const std::string key = *it;
                auto [size, reclaim] = node->with_state_machine([&key](auto& sm) {
                    auto& kv = redis_gateway_detail::kv_of(sm);
                    auto entry = kv.lookup(key);
                    const std::uint64_t sz = key.size() + (entry ? value_access::size(*entry) : 0);
                    if constexpr (requires { kv.reclaimable_bytes(key); }) {
                        return std::pair<std::uint64_t, std::uint64_t>{sz,
                                                                       kv.reclaimable_bytes(key)};
                    } else {
                        return std::pair<std::uint64_t, std::uint64_t>{sz, sz};
                    }
                });
                if (!shard_over && reclaim == 0) {
                    continue;
                }
                freed += size;
                disk_freed += reclaim;
                victims.push_back(key);
                lru._index.erase(key);
                it = lru._order.erase(it);
            }
        }
        if constexpr (k_transactional) {
            node->with_state_machine([&](auto& sm) {
                std::erase_if(victims, [&sm](const std::string& key) {
                    return sm.intent_on(key).has_value();
                });
            });
        }
        if (victims.empty()) {
            continue;
        }
        try {
            auto count = victims.size();
            auto f = _data.propose_to(
                group, desc->epoch(),
                encode_redis_kv_command(redis_kv_evict_command{std::move(victims)}),
                _config._command_timeout);
            if (f.wait(_config._command_timeout)) {
                (void)std::move(f).get();
                _stats._evictions += count;
                emit("redis.evictions", "evict", static_cast<std::int64_t>(count));
                ++proposals;
            }
        } catch (const std::exception& e) {
            _logger.log(log_level::debug, "redis gateway: evict proposal failed",
                        {{"error", e.what()}});
        }
    }
    send_advisories();
    return proposals;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::space_refusal(const std::string& key)
    -> std::optional<std::string> {
    if (!_cache_hooks._write_refusal) {
        return std::nullopt;
    }
    auto desc = _data.route(key);
    if (!desc) {
        return std::nullopt;
    }
    return _cache_hooks._write_refusal(desc->group_id(), desc->voters());
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::send_advisories() -> void {
    if (!_cache_hooks._advisory || !_running.load() || _config._internal_secret.empty() ||
        (!_config._forward_tls && !_config._allow_plaintext_forwarding)) {
        return;
    }
    // Every leader of a shard this node follows hears from it, with the
    // reads it served for that leader's shards.
    std::map<node_id_type, std::vector<std::pair<group_id_type, std::vector<std::string>>>> batches;
    std::map<group_id_type, std::set<std::string>> queued;
    {
        std::lock_guard<std::mutex> lock(_lru_mutex);
        queued.swap(_remote_touches);
    }
    for (const auto& group : _data.local_groups()) {
        auto* node = _data.local_replica(group);
        if (node == nullptr || node->is_leader()) {
            continue;
        }
        auto leader = node->known_leader();
        if (!leader || *leader == _data.self()) {
            continue;
        }
        auto& batch = batches[*leader];
        auto it = queued.find(group);
        if (it != queued.end() && !it->second.empty()) {
            batch.emplace_back(group,
                               std::vector<std::string>(it->second.begin(), it->second.end()));
        }
    }
    if (batches.empty()) {
        return;
    }
    const auto payload = _cache_hooks._advisory();
    const auto budget = _config._command_timeout.count() > 0
                            ? std::chrono::steady_clock::duration{_config._command_timeout}
                            : std::chrono::steady_clock::duration{std::chrono::seconds{5}};
    for (auto& [leader, groups] : batches) {
        auto endpoint = forward_endpoint(leader);
        if (!endpoint) {
            continue;
        }
        resp_writer w;
        std::vector<std::string> parts{w.bulk("KYTHIRA.ADVISE"), w.bulk(payload)};
        for (auto& [group, keys] : groups) {
            const auto blob = encode_redis_kv_command(redis_kv_touch_command{std::move(keys)});
            parts.push_back(w.bulk(std::to_string(group)));
            parts.push_back(
                w.bulk(std::string_view(reinterpret_cast<const char*>(blob.data()), blob.size())));
        }
        try {
            auto sock = forward_socket(*endpoint, std::chrono::steady_clock::now() + budget);
            auto wire = w.array(parts);
            sock->write(boost::asio::buffer(wire));
            std::string buf;
            std::array<char, 512> chunk{};
            std::size_t len = 0;
            while ((len = resp_reply_length(buf)) == 0) {
                if (buf.size() > 64u * 1024u) {
                    throw std::runtime_error("oversized advisory reply");
                }
                auto n = sock->read_some(boost::asio::buffer(chunk));
                buf.append(chunk.data(), n);
            }
            if (buf.rfind("+OK", 0) != 0) {
                throw std::runtime_error("advisory refused: " + buf.substr(0, len));
            }
            return_forward_socket(*endpoint, std::move(sock));
            ++_stats._advisories_sent;
        } catch (const std::exception& e) {
            ++_stats._advisory_failures;
            _logger.log(log_level::debug, "redis gateway: advisory failed",
                        {{"endpoint", *endpoint}, {"error", e.what()}});
        }
    }
}

/// `KYTHIRA.ADVISE <payload> [<group> <touch>]...` from a peer gateway: the
/// reads it served for shards this node leads, and its cache hooks'
/// payload. Internal connections only.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_advise(session& s, const resp_command& cmd)
    -> std::string {
    if (!s._internal) {
        ++_stats._authz_denials;
        return s._writer.error("NOPERM KYTHIRA.ADVISE is for peer gateways only");
    }
    if (cmd._argv.size() < 2 || cmd._argv.size() % 2 != 0) {
        return s._writer.error("ERR wrong number of arguments for 'kythira.advise' command");
    }
    ++_stats._advisories_received;
    for (std::size_t i = 2; i + 1 < cmd._argv.size(); i += 2) {
        group_id_type group{};
        try {
            std::size_t used = 0;
            group = static_cast<group_id_type>(std::stoull(cmd._argv[i], &used));
            if (used != cmd._argv[i].size()) {
                continue;
            }
        } catch (const std::exception&) {
            continue;
        }
        auto* node = _data.local_replica(group);
        if (node == nullptr || !node->is_leader()) {
            continue;
        }
        const auto& blob = cmd._argv[i + 1];
        std::vector<std::string> keys;
        try {
            auto decoded = decode_redis_kv_command(std::as_bytes(std::span(blob)));
            if (auto* touch = std::get_if<redis_kv_touch_command>(&decoded)) {
                keys = std::move(touch->_keys);
            }
        } catch (const std::exception&) {
            continue;
        }
        for (const auto& key : keys) {
            // Only keys the shard still holds: a deleted key must not come
            // back into the LRU as a victim that frees nothing.
            auto entry = node->with_state_machine(
                [&key](auto& sm) { return redis_gateway_detail::kv_of(sm).lookup(key); });
            if (entry) {
                touch_lru(group, key);
            }
        }
    }
    if (_cache_hooks._on_advisory) {
        _cache_hooks._on_advisory(cmd._argv[1]);
    }
    return s._writer.simple_string("OK");
}

// ── format level and gate (redis-general-data-types task 2) ─────────────────

namespace redis_gateway_detail {
template<typename Id> auto describe_id(const Id& id) -> std::string {
    if constexpr (requires { std::to_string(id); }) {
        return std::to_string(id);
    } else if constexpr (requires(std::ostream& os) { os << id; }) {
        std::ostringstream out;
        out << id;
        return out.str();
    } else {
        return "?";
    }
}
}  // namespace redis_gateway_detail

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::call_peer(const node_id_type& node,
                                                       const std::vector<std::string>& argv)
    -> std::optional<std::string> {
    if (_config._internal_secret.empty() ||
        (!_config._forward_tls && !_config._allow_plaintext_forwarding)) {
        return std::nullopt;
    }
    auto endpoint = forward_endpoint(node);
    if (!endpoint) {
        return std::nullopt;
    }
    const auto budget = _config._command_timeout.count() > 0
                            ? std::chrono::steady_clock::duration{_config._command_timeout}
                            : std::chrono::steady_clock::duration{std::chrono::seconds{5}};
    try {
        auto sock = forward_socket(*endpoint, std::chrono::steady_clock::now() + budget);
        resp_writer w;
        std::vector<std::string> parts;
        parts.reserve(argv.size());
        for (const auto& a : argv) {
            parts.push_back(w.bulk(a));
        }
        auto wire = w.array(parts);
        sock->write(boost::asio::buffer(wire));
        std::string buf;
        std::array<char, 512> chunk{};
        std::size_t len = 0;
        while ((len = resp_reply_length(buf)) == 0) {
            if (buf.size() > 64U * 1024U) {
                throw std::runtime_error("oversized reply from peer gateway");
            }
            auto n = sock->read_some(boost::asio::buffer(chunk));
            buf.append(chunk.data(), n);
        }
        buf.resize(len);
        return_forward_socket(*endpoint, std::move(sock));
        return buf;
    } catch (const std::exception& e) {
        _logger.log(log_level::debug, "redis gateway: peer call failed",
                    {{"endpoint", *endpoint},
                     {"command", argv.empty() ? "" : argv[0]},
                     {"error", e.what()}});
        return std::nullopt;
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::peer_format_level(const node_id_type& node)
    -> std::optional<std::uint16_t> {
    auto reply = call_peer(node, {"KYTHIRA.FORMAT", "LEVEL"});
    if (!reply || reply->size() < 4 || (*reply)[0] != ':') {
        return std::nullopt;
    }
    try {
        std::size_t used = 0;
        const auto body = reply->substr(1, reply->size() - 3);
        const auto v = std::stoul(body, &used);
        if (used != body.size() || v > 0xFFFFU) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(v);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::group_format_level(const std::string& key)
    -> std::optional<std::uint16_t> {
    if constexpr (k_node_format_level < k_redis_typed_values_level) {
        (void)key;
        return k_redis_base_format_level;
    } else {
        redis_data_status status{};
        std::optional<node_id_type> leader;
        auto* node = _data.replica_for(key, status, leader);
        if (node == nullptr) {
            return std::nullopt;
        }
        return node->with_state_machine(
            [](auto& sm) { return redis_gateway_detail::kv_of(sm).format_level(); });
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::format_refusal(session& s, const std::string& key,
                                                            std::uint16_t level)
    -> std::optional<std::string> {
    if constexpr (k_string_only_store) {
        (void)key;
        (void)level;
        return s._writer.error(std::string(k_redis_string_only_store_error));
    }
    auto have = group_format_level(key);
    if (have && *have < level) {
        return s._writer.error(std::string(k_redis_format_gate_error));
    }
    return std::nullopt;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::mutable_exec(const session& s, const std::string& key)
    -> bool {
    if (!_config._immutable_values || !s._identity ||
        !redis_acl::key_is_mutable(*s._identity, key)) {
        return false;
    }
    return typed_ready(key);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::typed_ready(const std::string& key) -> bool {
    const auto have = group_format_level(key);
    return !have || *have >= k_redis_typed_values_level;
}

/// The `KYTHIRA.FORMAT STATUS` reply, encoded as RESP2 bulk text: this
/// node's level, then each local replica's gate.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::format_status_text() -> std::string {
    std::ostringstream out;
    out << "node_level:" << reported_format_level() << "\r\n"
        << "binary_level:" << k_redis_format_level << "\r\n";
    for (const auto& g : _data.local_groups()) {
        auto* node = _data.local_replica(g);
        if (node == nullptr) {
            continue;
        }
        std::uint16_t level = 0;
        if constexpr (k_node_format_level >= k_redis_typed_values_level) {
            level = node->with_state_machine(
                [](auto& sm) { return redis_gateway_detail::kv_of(sm).format_level(); });
        }
        out << "group:" << redis_gateway_detail::describe_id(g)
            << ":gate=" << (level == 0 ? k_redis_base_format_level : level) << "\r\n";
    }
    resp_writer w;
    return w.bulk(out.str());
}

/// `KYTHIRA.FORMAT STATUS`: this node's level and each local group's gate.
/// `KYTHIRA.FORMAT LEVEL`: this node's level, as an integer (what peers ask).
/// `KYTHIRA.FORMAT UPGRADE <level>`: see `format_upgrade`.
/// `KYTHIRA.FORMAT GATE <level> <key>`: internal only; propose the gate to
/// `key`'s group from here, its leader.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_format(session& s, const resp_command& cmd)
    -> std::string {
    if (cmd._argv.size() < 2) {
        return s._writer.error("ERR wrong number of arguments for 'kythira.format' command");
    }
    const auto sub = resp_to_upper(cmd._argv[1]);
    const bool internal_hop = s._internal && (sub == "LEVEL" || sub == "GATE" || sub == "STATUS");
    if (!internal_hop) {
        if (auto e = authorize(s, "KYTHIRA.FORMAT", {})) {
            return *e;
        }
    }
    auto parse_level = [](const std::string& text) -> std::optional<std::uint16_t> {
        if (text.empty() || text.size() > 5 ||
            !std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) {
            return std::nullopt;
        }
        const auto v = std::stoul(text);
        return v <= 0xFFFFU ? std::optional<std::uint16_t>(static_cast<std::uint16_t>(v))
                            : std::nullopt;
    };
    if (sub == "LEVEL" && cmd._argv.size() == 2) {
        return s._writer.integer(reported_format_level());
    }
    if (sub == "STATUS" && cmd._argv.size() == 2) {
        return format_status_text();
    }
    if (sub == "UPGRADE" && cmd._argv.size() == 3) {
        auto level = parse_level(cmd._argv[2]);
        if (!level) {
            return s._writer.error("ERR KYTHIRA.FORMAT UPGRADE needs a format level");
        }
        return format_upgrade(s, *level);
    }
    if (sub == "GATE" && cmd._argv.size() == 4) {
        if (!s._internal) {
            ++_stats._authz_denials;
            return s._writer.error("NOPERM KYTHIRA.FORMAT GATE is for peer gateways only");
        }
        auto level = parse_level(cmd._argv[2]);
        if (!level || *level > reported_format_level()) {
            return s._writer.error("ERR KYTHIRA.FORMAT GATE above this node's format level");
        }
        const auto entry =
            encode_redis_kv_command(redis_kv_format_gate_command{cmd._argv[3], *level});
        try {
            auto future = _data.propose(cmd._argv[3], entry, _config._command_timeout);
            if (!future.wait(_config._command_timeout)) {
                return s._writer.error("ERR timeout proposing the format gate");
            }
            (void)std::move(future).get();
            return s._writer.simple_string("OK");
        } catch (const std::exception& e) {
            return s._writer.error(std::string("ERR format gate not applied: ") + e.what());
        }
    }
    return s._writer.error(
        "ERR unknown subcommand or wrong number of arguments for "
        "'KYTHIRA.FORMAT'. Try STATUS, LEVEL or UPGRADE <level>");
}

/// Design Component 8: refuse unless every node holding a replica of any
/// group reports at least `level`, naming the ones that do not; then propose
/// `format_gate{level}` to every group, from here when this node leads it
/// and through its leader otherwise, until each applies. Groups a split made
/// meanwhile inherit the gate through `split_state`; the walk is repeated
/// until it finds no group it has not gated. Safe to repeat: a gate at or
/// below a group's level changes nothing.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::format_upgrade(session& s, std::uint16_t level)
    -> std::string {
    if (level < k_redis_typed_values_level || level > k_redis_format_level) {
        return s._writer.error("ERR KYTHIRA.FORMAT UPGRADE level must be between " +
                               std::to_string(k_redis_typed_values_level) + " and " +
                               std::to_string(k_redis_format_level));
    }
    auto routes = _data.all_routes();
    if (routes.empty()) {
        return s._writer.error("ERR KYTHIRA.FORMAT routing is still loading, retry");
    }
    // 1. Every node with a replica of any group, and this one.
    std::set<node_id_type> nodes{_data.self()};
    for (const auto& r : routes) {
        nodes.insert(r.voters().begin(), r.voters().end());
        nodes.insert(r.learners().begin(), r.learners().end());
    }
    std::vector<std::string> behind;
    for (const auto& n : nodes) {
        const auto have =
            n == _data.self() ? std::optional(reported_format_level()) : peer_format_level(n);
        if (!have) {
            behind.push_back(redis_gateway_detail::describe_id(n) + " (no answer)");
        } else if (*have < level) {
            behind.push_back(redis_gateway_detail::describe_id(n) + " (level " +
                             std::to_string(*have) + ")");
        }
    }
    if (!behind.empty()) {
        std::string names;
        for (const auto& b : behind) {
            names += (names.empty() ? "" : ", ") + b;
        }
        return s._writer.error("ERR KYTHIRA.FORMAT cannot reach level " + std::to_string(level) +
                               ": nodes below it: " + names);
    }
    // 2. Gate every group.
    std::set<group_id_type> gated;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::max(_config._command_timeout * 4, std::chrono::milliseconds{1000});
    for (int pass = 0; pass < 8; ++pass) {
        if (pass > 0) {
            routes = _data.all_routes();
        }
        bool any_new = false;
        for (const auto& r : routes) {
            if (gated.contains(r.group_id())) {
                continue;
            }
            any_new = true;
            const std::string key = r.range()._start.value_or(std::string{});
            const auto entry = encode_redis_kv_command(redis_kv_format_gate_command{key, level});
            std::optional<node_id_type> to;
            while (std::chrono::steady_clock::now() < deadline) {
                try {
                    auto future = _data.propose(key, entry, _config._command_timeout);
                    if (future.wait(_config._command_timeout)) {
                        (void)std::move(future).get();
                        gated.insert(r.group_id());
                        break;
                    }
                } catch (const shard_not_leader_exception<group_id_type, node_id_type>& e) {
                    to = e.leader_hint();
                } catch (const std::exception&) {
                    to.reset();
                }
                if (!to) {
                    to = _data.leader_of(key);
                }
                if (to && *to != _data.self()) {
                    auto reply =
                        call_peer(*to, {"KYTHIRA.FORMAT", "GATE", std::to_string(level), key});
                    if (reply && reply->rfind("+OK", 0) == 0) {
                        gated.insert(r.group_id());
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
                to.reset();
            }
            if (!gated.contains(r.group_id())) {
                return s._writer.error("ERR KYTHIRA.FORMAT could not gate group " +
                                       redis_gateway_detail::describe_id(r.group_id()) +
                                       "; the gate is idempotent, retry");
            }
        }
        if (!any_new) {
            break;
        }
    }
    // 3. Until every replica has applied it, a node whose replica of a
    // group lags would still refuse typed commands for that group; wait
    // (within the same budget) until every node reports every group it
    // holds at the level, so OK means typed values work everywhere.
    const auto all_at_level = [level](std::string_view status) {
        std::size_t pos = 0;
        while ((pos = status.find("gate=", pos)) != std::string_view::npos) {
            pos += 5;
            std::uint16_t have = 0;
            const auto end = status.find_first_not_of("0123456789", pos);
            const auto digits = status.substr(pos, end - pos);
            if (std::from_chars(digits.data(), digits.data() + digits.size(), have).ec !=
                    std::errc{} ||
                have < level) {
                return false;
            }
        }
        return true;
    };
    std::set<node_id_type> waiting = nodes;
    while (!waiting.empty() && std::chrono::steady_clock::now() < deadline) {
        for (auto it = waiting.begin(); it != waiting.end();) {
            std::optional<std::string> status;
            if (*it == _data.self()) {
                status = format_status_text();
            } else {
                status = call_peer(*it, {"KYTHIRA.FORMAT", "STATUS"});
            }
            if (status && status->starts_with('$') && all_at_level(*status)) {
                it = waiting.erase(it);
            } else {
                ++it;
            }
        }
        if (!waiting.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
    }
    if (!waiting.empty()) {
        // The gate is committed in every group; the laggards apply it as
        // they catch up.
        _logger.log(log_level::warning, "redis gateway: format gate not yet applied everywhere",
                    {{"level", std::to_string(level)}, {"nodes", std::to_string(waiting.size())}});
    }
    _logger.log(log_level::info, "redis gateway: format gate applied",
                {{"level", std::to_string(level)}, {"groups", std::to_string(gated.size())}});
    return s._writer.simple_string("OK");
}

// ── tier 1 strings (redis-general-data-types task 3) ────────────────────────

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::propose_exec(
    session& s, const resp_command& cmd, const std::string& key, redis_command_id id,
    std::vector<std::string> args, bool may_grow, std::optional<std::string> mutable_bits,
    int replans) -> std::string {
    const auto name = resp_to_upper(cmd._argv[0]);
    const auto keys = redis_exec_keys(id, args);
    // Requirement 5: whether each key is in one of the user's mutable
    // prefixes. apply() decides against the stored value.
    std::string bits;
    if (mutable_bits) {
        bits = *mutable_bits;
    } else {
        for (const auto& k : keys) {
            bits += s._identity && redis_acl::key_is_mutable(*s._identity, k) ? '1' : '0';
        }
    }
    if (s._txn_view != nullptr) {
        return txn_view_exec(s, name, key, id, args, bits);
    }
    // The hop to a leader elsewhere carries the record, not the command.
    resp_command hop;
    hop._argv = {"KYTHIRA.EXEC", std::to_string(static_cast<unsigned>(id)), bits,
                 may_grow ? "1" : "0"};
    hop._argv.insert(hop._argv.end(), args.begin(), args.end());
    // Plan (Component 5): every key in one group, or a cross-group write.
    if (keys.size() > 1) {
        std::optional<group_id_type> group;
        bool split = false;
        for (const auto& k : keys) {
            auto desc = _data.route(k);
            if (!desc) {
                return s._writer.error("ERR no shard owns this key");
            }
            if (group && *group != desc->group_id()) {
                split = true;
            }
            group = desc->group_id();
        }
        if (split) {
            return cross_group_exec(s, id, args, bits);
        }
    }
    std::string error;
    std::optional<node_id_type> forward_to;
    auto* node = locate(key, error, forward_to);
    if (node != nullptr && !node->is_leader()) {
        forward_to = node->known_leader();
        error = s._writer.error("ERR shard has no reachable leader, retry");
        node = nullptr;
    }
    if (node == nullptr) {
        if (forward_to) {
            if (auto reply = forward(s, hop, *forward_to)) {
                return *reply;
            }
        }
        return error;
    }
    if (auto refused = format_refusal(s, key, k_redis_typed_values_level)) {
        return *refused;
    }
    if (may_grow) {
        if (auto refused = space_refusal(key)) {
            ++_stats._space_refusals;
            emit("redis.space_refusals", name);
            return s._writer.error("ERR " + *refused + ", retry later");
        }
    }
    const auto exec = make_redis_exec_record(key, static_cast<std::uint16_t>(id), args, now_ms(),
                                             _config._immutable_values, bits);
    const auto encoded = encode_redis_kv_command(exec);
    std::vector<std::byte> result;
    bool moved = false;
    if (!submit(s, key, encoded, error, forward_to, &result, keys.size() > 1 ? &keys : nullptr,
                &moved)) {
        if (moved && replans < 3) {
            // A split moved a key between routing and submission
            // (Requirement 6.5): the routes are learnt, so plan again.
            return propose_exec(s, cmd, key, id, std::move(args), may_grow, bits, replans + 1);
        }
        if (forward_to) {
            if (auto reply = forward(s, hop, *forward_to)) {
                return *reply;
            }
        }
        return error;
    }
    if (result.size() == 1 &&
        result[0] == static_cast<std::byte>(redis_v3_apply_status::refused_before_gate)) {
        return s._writer.error(std::string(k_redis_format_gate_error));
    }
    redis_reply reply;
    try {
        reply = decode_redis_reply(result);
    } catch (const redis_reply_error& e) {
        _logger.log(log_level::error, "redis gateway: undecodable exec reply",
                    {{"command", name}, {"error", e.what()}});
        return s._writer.error("ERR internal error decoding the reply");
    }
    if (reply.is_error()) {
        if (reply._text.rfind("ERR value conflict", 0) == 0) {
            ++_stats._value_conflicts;
            emit("redis.value_conflicts", name);
        }
    } else {
        ++_stats._writes;
        emit("redis.writes", name);
        if (auto desc = _data.route(key)) {
            if (id == redis_command_id::getdel) {
                forget_lru(desc->group_id(), key);
            } else {
                touch_lru(desc->group_id(), key);
            }
        }
    }
    return render_redis_reply(reply, s._writer.version());
}

namespace redis_gateway_detail {
/// A positive expiry in `unit_ms` units from `text`, as an absolute ms
/// deadline from `now`; `nullopt` when not a positive integer or when it
/// overflows (Redis: "invalid expire time").
inline auto absolute_deadline(std::string_view text, std::uint64_t unit_ms, bool absolute,
                              std::uint64_t now) -> std::optional<std::uint64_t> {
    const auto v = redis_string_detail::parse_int64(text);
    if (!v || *v <= 0) {
        return std::nullopt;
    }
    const auto u = static_cast<std::uint64_t>(*v);
    if (u > std::numeric_limits<std::uint64_t>::max() / unit_ms / 2) {
        return std::nullopt;
    }
    const auto ms = u * unit_ms;
    if (absolute) {
        return ms;
    }
    if (ms > std::numeric_limits<std::uint64_t>::max() / 2 - now) {
        return std::nullopt;
    }
    return now + ms;
}
}  // namespace redis_gateway_detail

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_internal_exec(session& s,
                                                                  const resp_command& cmd)
    -> std::string {
    if (!s._internal) {
        audit(s, "KYTHIRA.EXEC", "internal command from a client");
        return s._writer.error("NOPERM KYTHIRA.EXEC is internal to the gateways");
    }
    const auto& a = cmd._argv;
    if (a.size() < 5 || a[2].empty() || a[2].find_first_not_of("01") != std::string::npos ||
        (a[3] != "0" && a[3] != "1")) {
        return s._writer.error("ERR syntax error");
    }
    const auto id = redis_string_detail::parse_u64(a[1]);
    if (!id || *id > 0xFFFFU) {
        return s._writer.error("ERR syntax error");
    }
    const auto command = static_cast<redis_command_id>(*id);
    const auto* info = find_redis_command(command);
    if (info == nullptr || info->status != redis_command_status::shipped) {
        return s._writer.error("ERR unknown command id " + a[1]);
    }
    std::vector<std::string> args(a.begin() + 4, a.end());
    const auto keys = redis_exec_keys(command, args);
    if (keys.empty()) {
        return s._writer.error("ERR syntax error");
    }
    const auto& key = keys.front();
    return propose_exec(s, cmd, key, command, std::move(args), a[3] == "1", a[2]);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_string_write(session& s, std::string_view upper,
                                                                 const resp_command& cmd)
    -> std::string {
    const auto& a = cmd._argv;
    const auto& key = a[1];
    if (auto e = authorize(s, upper, {key})) {
        return *e;
    }
    std::string lower(upper);
    for (auto& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    const auto syntax = [&] { return s._writer.error("ERR syntax error"); };
    const auto bad_expire = [&] {
        return s._writer.error("ERR invalid expire time in '" + lower + "' command");
    };
    const auto oversize = [&](std::size_t n) -> std::optional<std::string> {
        if (n > _config._max_value_bytes) {
            ++_stats._oversize_rejections;
            emit("redis.oversize_rejections", upper);
            return s._writer.error("ERR value exceeds the configured maximum of " +
                                   std::to_string(_config._max_value_bytes) + " bytes");
        }
        return std::nullopt;
    };
    const auto max_bytes = std::to_string(_config._max_value_bytes);
    using redis_gateway_detail::absolute_deadline;

    if (upper == "SET") {
        bool nx = false;
        bool xx = false;
        bool get = false;
        bool keepttl = false;
        std::optional<std::uint64_t> pxat;
        bool expiry_given = false;
        for (std::size_t i = 3; i < a.size(); ++i) {
            const auto opt = resp_to_upper(a[i]);
            if (opt == "NX" && !xx) {
                nx = true;
            } else if (opt == "XX" && !nx) {
                xx = true;
            } else if (opt == "GET") {
                get = true;
            } else if (opt == "KEEPTTL" && !expiry_given) {
                keepttl = true;
            } else if ((opt == "EX" || opt == "PX" || opt == "EXAT" || opt == "PXAT") && !keepttl &&
                       !expiry_given && i + 1 < a.size()) {
                expiry_given = true;
                const bool seconds = opt == "EX" || opt == "EXAT";
                const bool absolute = opt == "EXAT" || opt == "PXAT";
                pxat = absolute_deadline(a[++i], seconds ? 1000 : 1, absolute, now_ms());
                if (!pxat) {
                    return bad_expire();
                }
            } else {
                return syntax();
            }
        }
        if (get) {
            if (auto e =
                    authorize(s, upper, {key}, redis_key_access::read | redis_key_access::write)) {
                return *e;
            }
        }
        if (auto e = oversize(a[2].size())) {
            return *e;
        }
        std::vector<std::string> args{key, a[2]};
        if (nx) {
            args.emplace_back("NX");
        }
        if (xx) {
            args.emplace_back("XX");
        }
        if (get) {
            args.emplace_back("GET");
        }
        if (pxat) {
            args.emplace_back("PXAT");
            args.push_back(std::to_string(*pxat));
        } else if (keepttl) {
            args.emplace_back("KEEPTTL");
        }
        return propose_exec(s, cmd, key, redis_command_id::set, std::move(args), true);
    }
    if (upper == "SETNX") {
        if (auto e = oversize(a[2].size())) {
            return *e;
        }
        return propose_exec(s, cmd, key, redis_command_id::setnx, {key, a[2]}, true);
    }
    if (upper == "GETSET") {
        if (auto e = oversize(a[2].size())) {
            return *e;
        }
        return propose_exec(s, cmd, key, redis_command_id::set, {key, a[2], "GET"}, true);
    }
    if (upper == "SETEX") {
        const auto pxat = absolute_deadline(a[2], 1000, false, now_ms());
        if (!pxat) {
            return bad_expire();
        }
        if (auto e = oversize(a[3].size())) {
            return *e;
        }
        return propose_exec(s, cmd, key, redis_command_id::set,
                            {key, a[3], "PXAT", std::to_string(*pxat)}, true);
    }
    if (upper == "PSETEX") {
        const auto pxat = absolute_deadline(a[2], 1, false, now_ms());
        if (!pxat) {
            return bad_expire();
        }
        if (auto e = oversize(a[3].size())) {
            return *e;
        }
        return propose_exec(s, cmd, key, redis_command_id::set,
                            {key, a[3], "PXAT", std::to_string(*pxat)}, true);
    }
    if (upper == "INCR" || upper == "DECR" || upper == "INCRBY" || upper == "DECRBY") {
        std::int64_t delta = upper == "DECR" ? -1 : 1;
        if (upper == "INCRBY" || upper == "DECRBY") {
            const auto v = redis_string_detail::parse_int64(a[2]);
            if (!v) {
                return s._writer.error("ERR value is not an integer or out of range");
            }
            if (upper == "DECRBY") {
                if (*v == std::numeric_limits<std::int64_t>::min()) {
                    return s._writer.error("ERR decrement would overflow");
                }
                delta = -*v;
            } else {
                delta = *v;
            }
        }
        return propose_exec(s, cmd, key, redis_command_id::incrby, {key, std::to_string(delta)},
                            true);
    }
    if (upper == "INCRBYFLOAT") {
        const auto incr = parse_redis_float128(a[2]);
        if (!incr || !is_finite_redis_float128(*incr)) {
            return s._writer.error(incr ? "ERR increment would produce NaN or Infinity"
                                        : "ERR value is not a valid float");
        }
        return propose_exec(s, cmd, key, redis_command_id::incrbyfloat, {key, a[2]}, true);
    }
    if (upper == "GETDEL") {
        return propose_exec(s, cmd, key, redis_command_id::getdel, {key}, false);
    }
    if (upper == "GETEX") {
        std::vector<std::string> args{key};
        if (a.size() >= 3) {
            const auto opt = resp_to_upper(a[2]);
            if (opt == "PERSIST" && a.size() == 3) {
                args.emplace_back("PERSIST");
            } else if ((opt == "EX" || opt == "PX" || opt == "EXAT" || opt == "PXAT") &&
                       a.size() == 4) {
                const bool seconds = opt == "EX" || opt == "EXAT";
                const bool absolute = opt == "EXAT" || opt == "PXAT";
                const auto pxat = absolute_deadline(a[3], seconds ? 1000 : 1, absolute, now_ms());
                if (!pxat) {
                    return bad_expire();
                }
                args.emplace_back("PXAT");
                args.push_back(std::to_string(*pxat));
            } else {
                return syntax();
            }
        }
        return propose_exec(s, cmd, key, redis_command_id::getex, std::move(args), false);
    }
    if (upper == "APPEND") {
        if (auto e = oversize(a[2].size())) {
            return *e;
        }
        return propose_exec(s, cmd, key, redis_command_id::append, {key, a[2], max_bytes}, true);
    }
    if (upper == "EXPIRE" || upper == "PEXPIRE" || upper == "EXPIREAT" || upper == "PEXPIREAT") {
        // Redis order: options, then the integer, then overflow.
        unsigned flags = 0;
        std::vector<std::string> names;
        for (std::size_t i = 3; i < a.size(); ++i) {
            const auto f = redis_expiry_detail::parse_expire_flag(a[i]);
            if (!f) {
                return s._writer.error("ERR Unsupported option " + a[i]);
            }
            flags |= *f;
            names.push_back(resp_to_upper(a[i]));
        }
        if (const auto conflict = redis_expiry_detail::expire_flags_conflict(flags);
            !conflict.empty()) {
            return s._writer.error(std::string(conflict));
        }
        const auto v = redis_string_detail::parse_int64(a[2]);
        if (!v) {
            return s._writer.error("ERR value is not an integer or out of range");
        }
        constexpr auto k_max = std::numeric_limits<std::int64_t>::max();
        constexpr auto k_min = std::numeric_limits<std::int64_t>::min();
        auto when = *v;
        if (upper == "EXPIRE" || upper == "EXPIREAT") {
            if (when > k_max / 1000 || when < k_min / 1000) {
                return bad_expire();
            }
            when *= 1000;
        }
        if (upper == "EXPIRE" || upper == "PEXPIRE") {
            const auto now = static_cast<std::int64_t>(now_ms());
            if (when > k_max - now) {
                return bad_expire();
            }
            when += now;
        }
        std::vector<std::string> args{key, std::to_string(when)};
        args.insert(args.end(), names.begin(), names.end());
        return propose_exec(s, cmd, key, redis_command_id::pexpireat, std::move(args), false);
    }
    if (upper == "PERSIST") {
        return propose_exec(s, cmd, key, redis_command_id::persist, {key}, false);
    }
    if (upper == "SETRANGE") {
        const auto offset = redis_string_detail::parse_int64(a[2]);
        if (!offset) {
            return s._writer.error("ERR value is not an integer or out of range");
        }
        if (*offset < 0) {
            return s._writer.error("ERR offset is out of range");
        }
        if (static_cast<std::uint64_t>(*offset) + a[3].size() >
            std::min<std::uint64_t>(_config._max_value_bytes, k_redis_max_string_bytes)) {
            return s._writer.error(std::string(redis_string_detail::k_too_big));
        }
        return propose_exec(s, cmd, key, redis_command_id::setrange,
                            {key, std::to_string(*offset), a[3], max_bytes}, true);
    }
    return syntax();
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_multi_key_write(session& s,
                                                                    std::string_view upper,
                                                                    const resp_command& cmd)
    -> std::string {
    const auto& a = cmd._argv;
    std::vector<std::string> args;
    redis_command_id id{};
    bool may_grow = false;
    if (upper == "DEL" || upper == "UNLINK") {
        id = upper == "DEL" ? redis_command_id::del : redis_command_id::unlink;
        args.assign(a.begin() + 1, a.end());
    } else if (upper == "RENAME" || upper == "RENAMENX") {
        id = upper == "RENAME" ? redis_command_id::rename : redis_command_id::renamenx;
        args = {a[1], a[2]};
    } else if (upper == "COPY") {
        id = redis_command_id::copy;
        args = {a[1], a[2]};
        may_grow = true;
        bool replace = false;
        for (std::size_t i = 3; i < a.size(); ++i) {
            const auto opt = resp_to_upper(a[i]);
            if (opt == "REPLACE") {
                replace = true;
            } else if (opt == "DB" && i + 1 < a.size()) {
                // One database (D-numbered limitation of the spec).
                const auto db = redis_string_detail::parse_int64(a[++i]);
                if (!db) {
                    return s._writer.error("ERR value is not an integer or out of range");
                }
                if (*db != 0) {
                    return s._writer.error("ERR DB index is out of range");
                }
            } else {
                return s._writer.error("ERR syntax error");
            }
        }
        if (replace) {
            args.emplace_back("REPLACE");
        }
    } else if (upper == "MSETNX") {
        id = redis_command_id::msetnx;
        args.assign(a.begin() + 1, a.end());
        may_grow = true;
        for (std::size_t i = 1; i < args.size(); i += 2) {
            if (args[i].size() > _config._max_value_bytes) {
                ++_stats._oversize_rejections;
                emit("redis.oversize_rejections", upper);
                return s._writer.error("ERR value exceeds the configured maximum of " +
                                       std::to_string(_config._max_value_bytes) + " bytes");
            }
        }
    } else {
        return s._writer.error("ERR syntax error");
    }
    // Views into the command's own arguments, which outlive the call.
    std::vector<std::string_view> key_views;
    for (const auto pos : redis_exec_key_positions(id, args)) {
        key_views.emplace_back(a[pos + 1]);
    }
    if (auto e = authorize(s, upper, key_views)) {
        return *e;
    }
    const auto first = args[0];
    return propose_exec(s, cmd, first, id, std::move(args), may_grow);
}

/// A multi-key write across groups (Requirement 6.2): one transaction at
/// the connection's isolation. The record is evaluated against the
/// transaction's view by the appliers `apply()` runs, so every command,
/// a collection's included, crosses groups the same way (task 11); the
/// commit installs each changed key's resulting value.
template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::cross_group_exec(session& s, redis_command_id id,
                                                              const std::vector<std::string>& args,
                                                              const std::string& mutable_bits)
    -> std::string {
    if constexpr (!k_transactional || k_string_only_store) {
        return s._writer.error("CROSSSLOT Keys in request don't hash to the same slot");
    } else {
        if (!_config._transactions) {
            return s._writer.error("CROSSSLOT Keys in request don't hash to the same slot");
        }
        const auto keys = redis_exec_keys(id, args);
        if (keys.empty()) {
            return s._writer.error("ERR syntax error");
        }
        try {
            txn_client client(*this);
            coordinator_type coordinator(client);
            coordinator.begin(make_options(s));
            auto view = make_txn_view(coordinator, client);
            const auto t = now_ms();
            const auto record =
                make_redis_exec_record(keys.front(), static_cast<std::uint16_t>(id), args, t,
                                       _config._immutable_values, mutable_bits);
            std::optional<redis_reply> reply;
            try {
                reply = apply_redis_exec(view, record, t);
            } catch (...) {
                if (auto failed = view.failure()) {
                    std::rethrow_exception(failed);
                }
                throw;
            }
            if (!reply) {
                coordinator.rollback();
                return s._writer.error("ERR syntax error");
            }
            if (reply->is_error() || view.writes().empty()) {
                coordinator.rollback();
                if (reply->is_error() && reply->_text.rfind("ERR value conflict", 0) == 0) {
                    ++_stats._value_conflicts;
                    emit("redis.value_conflicts", "exec");
                }
                return render_redis_reply(*reply, s._writer.version());
            }
            if (auto refused = stage_txn_writes(s, coordinator, view)) {
                coordinator.rollback();
                return *refused;
            }
            auto outcome = coordinator.commit();
            if (auto e = outcome_error(s, outcome); !e.empty()) {
                return e;
            }
            ++_stats._writes;
            for (const auto& [key, entry] : view.writes()) {
                if (auto desc = _data.route(key)) {
                    if (entry) {
                        touch_lru(desc->group_id(), key);
                    } else {
                        forget_lru(desc->group_id(), key);
                    }
                }
            }
            return render_redis_reply(*reply, s._writer.version());
        } catch (const std::exception& e) {
            return s._writer.error(std::string("ERR transaction failed: ") + e.what() + ", retry");
        }
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_key_read(session& s, std::string_view upper,
                                                             const resp_command& cmd)
    -> std::string {
    std::vector<std::string_view> keys;
    std::size_t first = 1;
    if (upper == "OBJECT") {
        const auto sub = resp_to_upper(cmd._argv[1]);
        if (sub != "ENCODING" || cmd._argv.size() != 3) {
            return s._writer.error("ERR unknown subcommand or wrong number of arguments for '" +
                                   cmd._argv[1] + "'. Try OBJECT HELP.");
        }
        first = 2;
    }
    for (std::size_t i = first; i < cmd._argv.size(); ++i) {
        keys.emplace_back(cmd._argv[i]);
    }
    if (auto e = authorize(s, upper, keys)) {
        return *e;
    }
    std::int64_t touched = 0;
    for (std::size_t i = first; i < cmd._argv.size(); ++i) {
        const auto& key = cmd._argv[i];
        auto r = read_local(s, key);
        if (!r._error.empty()) {
            if (r._forward_to && cmd._argv.size() == first + 1) {
                if (auto reply = forward(s, cmd, *r._forward_to)) {
                    return *reply;
                }
            } else if (r._forward_to && (upper == "TOUCH" || upper == "EXISTS")) {
                // One key of several: ask its node about that key alone.
                resp_command one{{std::string(upper), key}};
                const auto reply = forward(s, one, *r._forward_to);
                if (reply && *reply == ":1\r\n") {
                    ++touched;
                    continue;
                }
                if (reply && *reply == ":0\r\n") {
                    continue;
                }
            }
            return r._error;
        }
        const bool present = r._entry && !is_expired(*r._entry);
        if (upper == "PTTL" || upper == "EXPIRETIME" || upper == "PEXPIRETIME") {
            const auto id = upper == "PTTL"         ? redis_command_id::pttl
                            : upper == "EXPIRETIME" ? redis_command_id::expiretime
                                                    : redis_command_id::pexpiretime;
            const auto reply = redis_expiry_read_reply(
                id, present, present ? r._entry->_expire_at_ms : 0, now_ms());
            return render_redis_reply(*reply, s._writer.version());
        }
        if (upper == "TYPE" || upper == "OBJECT") {
            const std::vector<std::string> encoding{"ENCODING"};
            if (auto typed = redis_collection_read(
                    r._entry.get(),
                    upper == "TYPE" ? redis_command_id::type : redis_command_id::object, encoding,
                    now_ms())) {
                return render_redis_reply(*typed, s._writer.version());
            }
        }
        if (upper == "TYPE") {
            return s._writer.simple_string(present ? "string" : "none");
        }
        if (upper == "OBJECT") {
            if (!present) {
                return s._writer.null();
            }
            // D16: the encoding Redis would choose for these bytes.
            const auto size = value_access::size(*r._entry);
            if (size <= 20) {
                auto bytes = value_access::read(r._context, *r._entry);
                if (bytes) {
                    const auto view = bytes->view();
                    const std::string_view text(reinterpret_cast<const char*>(view.data()),
                                                view.size());
                    if (redis_string_detail::parse_int64(text)) {
                        return s._writer.bulk("int");
                    }
                }
            }
            return s._writer.bulk(size <= 44 ? "embstr" : "raw");
        }
        touched += present ? 1 : 0;
        if (present && upper == "TOUCH") {
            if (auto desc = _data.route(key)) {
                touch_lru(desc->group_id(), key);
            }
        }
    }
    return s._writer.integer(touched);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_collection(session& s,
                                                               const redis_command_info& info,
                                                               const resp_command& cmd)
    -> std::string {
    const auto id = static_cast<redis_command_id>(info.id);
    const auto& a = cmd._argv;
    const auto& key = a[1];
    const std::string upper(info.name);
    const auto max_bytes = std::to_string(_config._max_collection_bytes);
    const auto max_count = std::to_string(_config._max_collection_elements);

    if (auto reply = handle_list_command(s, info, cmd)) {
        return *reply;
    }
    // Commands naming several keys.
    switch (id) {
        case redis_command_id::sinter:
        case redis_command_id::sunion:
        case redis_command_id::sdiff:
        case redis_command_id::sintercard:
            return handle_set_algebra(s, id, cmd);
        case redis_command_id::smove: {
            if (auto e = authorize(s, upper, {a[1], a[2]})) {
                return *e;
            }
            return propose_exec(s, cmd, a[1], id, {a[1], a[2], max_bytes, max_count, a[3]}, true);
        }
        case redis_command_id::sinterstore:
        case redis_command_id::sunionstore:
        case redis_command_id::sdiffstore: {
            std::vector<std::string_view> sources(a.begin() + 2, a.end());
            if (auto e = authorize(s, upper, {a[1]}, redis_key_access::write)) {
                return *e;
            }
            if (auto e = authorize(s, upper, sources, redis_key_access::read)) {
                return *e;
            }
            std::vector<std::string> args{a[1], max_bytes, max_count};
            args.insert(args.end(), a.begin() + 2, a.end());
            return propose_exec(s, cmd, a[1], id, std::move(args), true);
        }
        default:
            break;
    }
    if (auto e = authorize(s, upper, {key})) {
        return *e;
    }
    if (id == redis_command_id::spop) {
        return handle_spop(s, cmd);
    }
    if (id == redis_command_id::sadd) {
        std::vector<std::string> args{key, max_bytes, max_count};
        args.insert(args.end(), a.begin() + 2, a.end());
        return propose_exec(s, cmd, key, id, std::move(args), true);
    }
    if (id == redis_command_id::srem) {
        std::vector<std::string> args(a.begin() + 1, a.end());
        return propose_exec(s, cmd, key, id, std::move(args), false);
    }
    if (redis_hash_detail::is_hash_write(id)) {
        std::vector<std::string> args{key};
        if (id != redis_command_id::hdel) {
            args.push_back(std::to_string(_config._max_collection_bytes));
            args.push_back(std::to_string(_config._max_collection_elements));
        }
        if (id == redis_command_id::hincrby && !redis_string_detail::parse_int64(a[3])) {
            return s._writer.error("ERR value is not an integer or out of range");
        }
        if (id == redis_command_id::hincrbyfloat && !parse_redis_float128(a[3])) {
            return s._writer.error("ERR value is not a valid float");
        }
        args.insert(args.end(), a.begin() + 2, a.end());
        return propose_exec(s, cmd, key, id, std::move(args), id != redis_command_id::hdel);
    }

    // A read: arguments the data side expects already valid.
    std::vector<std::string> args(a.begin() + 2, a.end());
    if (id == redis_command_id::lindex || id == redis_command_id::lrange) {
        for (const auto& v : args) {
            if (!redis_string_detail::parse_int64(v)) {
                return s._writer.error("ERR value is not an integer or out of range");
            }
        }
    }
    if (id == redis_command_id::lpos) {
        // LPOS key element [RANK r] [COUNT n] [MAXLEN m], in normal form
        // `element rank count maxlen with-count`.
        std::string rank = "1";
        std::string count = "0";
        std::string maxlen = "0";
        bool with_count = false;
        for (std::size_t i = 1; i < args.size(); i += 2) {
            const auto opt = resp_to_upper(args[i]);
            if (i + 1 >= args.size() || (opt != "RANK" && opt != "COUNT" && opt != "MAXLEN")) {
                return s._writer.error("ERR syntax error");
            }
            const auto v = redis_string_detail::parse_int64(args[i + 1]);
            if (!v) {
                return s._writer.error("ERR value is not an integer or out of range");
            }
            if (opt == "RANK") {
                if (*v == 0) {
                    return s._writer.error(
                        "ERR RANK can't be zero: use 1 to start from the first match, 2 from the "
                        "second ... or use negative to start from the end of the list");
                }
                if (*v == std::numeric_limits<std::int64_t>::min()) {
                    return s._writer.error("ERR value is out of range");
                }
                rank = args[i + 1];
            } else if (opt == "COUNT") {
                if (*v < 0) {
                    return s._writer.error("ERR COUNT can't be negative");
                }
                count = args[i + 1];
                with_count = true;
            } else {
                if (*v < 0) {
                    return s._writer.error("ERR MAXLEN can't be negative");
                }
                maxlen = args[i + 1];
            }
        }
        args = {args[0], rank, count, maxlen, with_count ? "1" : "0"};
    }
    if (id == redis_command_id::srandmember && !args.empty() &&
        !redis_string_detail::parse_int64(args[0])) {
        return s._writer.error("ERR value is not an integer or out of range");
    }
    if (id == redis_command_id::hrandfield && !args.empty()) {
        if (!redis_string_detail::parse_int64(args[0])) {
            return s._writer.error("ERR value is not an integer or out of range");
        }
        if (args.size() == 2) {
            if (resp_to_upper(args[1]) != "WITHVALUES") {
                return s._writer.error("ERR syntax error");
            }
            args[1] = "WITHVALUES";
        }
    }
    if (auto refused = format_refusal(s, key, k_redis_typed_values_level)) {
        return *refused;
    }
    auto r = read_local(s, key);
    if (!r._error.empty()) {
        if (r._forward_to) {
            if (auto reply = forward(s, cmd, *r._forward_to)) {
                if (s._writer.version() < 3) {
                    return *reply;
                }
                // The internal hop answers in RESP2; give a RESP3 client the
                // shapes it expects (Redis's own RESP2 downgrade, undone).
                auto tree = parse_resp2_reply(*reply);
                if (!tree) {
                    return *reply;
                }
                if (id == redis_command_id::hgetall && tree->_kind == redis_reply_kind::array) {
                    tree = redis_reply::map(std::move(tree->_elements));
                } else if (id == redis_command_id::smembers &&
                           tree->_kind == redis_reply_kind::array) {
                    tree = redis_reply::set(std::move(tree->_elements));
                } else if (id == redis_command_id::hrandfield && args.size() == 2 &&
                           tree->_kind == redis_reply_kind::array) {
                    std::vector<redis_reply> pairs;
                    for (std::size_t i = 0; i + 1 < tree->_elements.size(); i += 2) {
                        pairs.push_back(redis_reply::array(
                            {std::move(tree->_elements[i]), std::move(tree->_elements[i + 1])}));
                    }
                    tree = redis_reply::array(std::move(pairs));
                }
                return render_redis_reply(*tree, s._writer.version());
            }
        }
        return r._error;
    }
    if constexpr (requires(const entry_type& e) {
                      e._value;
                      e._expire_at_ms;
                  }) {
        // The handle keeps the entry, and its immutable hash, alive: the
        // reply is built here, after the lock (Requirement 10.2).
        auto reply = evaluate_redis_read(r._entry.get(), id, args, now_ms());
        if (!reply) {
            return s._writer.error("ERR unknown command id " + std::to_string(info.id));
        }
        if (id == redis_command_id::hrandfield && args.size() == 2 && s._writer.version() < 3) {
            *reply = redis_flatten_pairs(std::move(*reply));
        }
        return render_redis_reply(*reply, s._writer.version());
    } else {
        return s._writer.error(std::string(k_redis_string_only_store_error));
    }
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_spop(session& s, const resp_command& cmd)
    -> std::string {
    const auto& key = cmd._argv[1];
    std::optional<std::int64_t> count;
    if (cmd._argv.size() == 3) {
        count = redis_string_detail::parse_int64(cmd._argv[2]);
        if (!count || *count < 0) {
            return s._writer.error("ERR value is out of range, must be positive");
        }
    }
    if (auto refused = format_refusal(s, key, k_redis_typed_values_level)) {
        return *refused;
    }
    const auto empty_reply = [&] { return count ? s._writer.array({}) : s._writer.null(); };
    if (count && *count == 0) {
        return empty_reply();
    }
    // Pick distinct members from the set as this node, or the leader, sees
    // it; apply() removes only those still there, so a stale pick costs a
    // smaller pop, never a wrong one.
    const std::vector<std::string> pick_args{std::to_string(count.value_or(1))};
    std::optional<redis_reply> picked;
    auto r = read_local(s, key);
    if (r._error.empty()) {
        if constexpr (requires(const entry_type& e) {
                          e._value;
                          e._expire_at_ms;
                      }) {
            picked = evaluate_redis_read(r._entry.get(), redis_command_id::srandmember, pick_args,
                                         now_ms());
        } else {
            return s._writer.error(std::string(k_redis_string_only_store_error));
        }
    } else if (r._forward_to) {
        if (auto reply =
                forward_argv({"SRANDMEMBER", key, pick_args[0]}, *r._forward_to, "SRANDMEMBER")) {
            picked = parse_resp2_reply(*reply);
        }
    }
    if (!picked) {
        return r._error.empty() ? s._writer.error("ERR shard has no reachable leader, retry")
                                : r._error;
    }
    if (picked->is_error()) {
        return render_redis_reply(*picked, s._writer.version());
    }
    std::vector<std::string> args{key, count ? "1" : "0"};
    for (auto& m : picked->_elements) {
        args.push_back(std::move(m._text));
    }
    if (args.size() == 2) {
        return empty_reply();
    }
    return propose_exec(s, cmd, key, redis_command_id::spop, std::move(args), false);
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::set_members_of(session& s, const std::string& key)
    -> std::variant<std::vector<std::string>, std::string> {
    auto r = read_local(s, key);
    if (r._error.empty()) {
        if (!r._entry || is_expired(*r._entry)) {
            return std::vector<std::string>{};
        }
        if constexpr (requires(const entry_type& e) { e._set; }) {
            if (r._entry->_type == redis_value_type::set) {
                std::vector<std::string> out;
                out.reserve(r._entry->_set->size());
                r._entry->_set->for_each([&](const std::string& m) { out.push_back(m); });
                return out;
            }
        }
        return s._writer.error(std::string(k_redis_wrongtype));
    }
    if (!r._forward_to) {
        return r._error;
    }
    auto reply = forward_argv({"SMEMBERS", key}, *r._forward_to, "SMEMBERS");
    if (!reply) {
        return r._error;
    }
    auto tree = parse_resp2_reply(*reply);
    if (!tree || tree->_kind != redis_reply_kind::array) {
        return tree && tree->is_error() ? *reply : r._error;
    }
    std::vector<std::string> out;
    out.reserve(tree->_elements.size());
    for (auto& m : tree->_elements) {
        out.push_back(std::move(m._text));
    }
    return out;
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_set_algebra(session& s, redis_command_id id,
                                                                const resp_command& cmd)
    -> std::string {
    const auto& a = cmd._argv;
    std::size_t first = 1;
    std::size_t last = a.size();
    std::size_t limit = 0;
    if (id == redis_command_id::sintercard) {
        const auto n = redis_string_detail::parse_int64(a[1]);
        if (!n || *n <= 0) {
            return s._writer.error("ERR numkeys should be greater than 0");
        }
        if (static_cast<std::uint64_t>(*n) > a.size() - 2) {
            return s._writer.error("ERR Number of keys can't be greater than number of args");
        }
        first = 2;
        last = 2 + static_cast<std::size_t>(*n);
        for (std::size_t i = last; i < a.size(); i += 2) {
            if (resp_to_upper(a[i]) != "LIMIT" || i + 1 >= a.size()) {
                return s._writer.error("ERR syntax error");
            }
            const auto v = redis_string_detail::parse_int64(a[i + 1]);
            if (!v) {
                return s._writer.error("ERR value is not an integer or out of range");
            }
            if (*v < 0) {
                return s._writer.error("ERR LIMIT can't be negative");
            }
            limit = static_cast<std::size_t>(*v);
        }
    }
    std::vector<std::string_view> keys(a.begin() + static_cast<std::ptrdiff_t>(first),
                                       a.begin() + static_cast<std::ptrdiff_t>(last));
    if (auto e = authorize(s, resp_to_upper(a[0]), keys, redis_key_access::read)) {
        return *e;
    }
    if (auto refused = format_refusal(s, a[first], k_redis_typed_values_level)) {
        return *refused;
    }
    // Each key read where it lives, at the connection's consistency, as a
    // multi-key EXISTS (Requirement 6.4).
    std::vector<redis_set> sets;
    sets.reserve(keys.size());
    for (const auto key : keys) {
        auto members = set_members_of(s, std::string(key));
        if (auto* error = std::get_if<std::string>(&members)) {
            return *error;
        }
        sets.push_back(
            redis_set::from_sorted(std::get<std::vector<std::string>>(std::move(members))));
    }
    std::vector<const redis_set*> views;
    for (const auto& set : sets) {
        views.push_back(&set);
    }
    auto result = redis_set_detail::combine(id, views, limit);
    if (id == redis_command_id::sintercard) {
        return s._writer.integer(static_cast<std::int64_t>(result.size()));
    }
    std::vector<redis_reply> out;
    out.reserve(result.size());
    for (auto& m : result) {
        out.push_back(redis_reply::bulk(std::move(m)));
    }
    return render_redis_reply(redis_reply::set(std::move(out)), s._writer.version());
}

template<typename Host, typename Logger, typename Metrics>
auto redis_front_end<Host, Logger, Metrics>::handle_list_command(session& s,
                                                                 const redis_command_info& info,
                                                                 const resp_command& cmd)
    -> std::optional<std::string> {
    const auto id = static_cast<redis_command_id>(info.id);
    if (!redis_list_detail::is_list_write(id) && id != redis_command_id::rpoplpush) {
        return std::nullopt;
    }
    const auto& a = cmd._argv;
    const std::string upper(info.name);
    const auto max_bytes = std::to_string(_config._max_collection_bytes);
    const auto max_count = std::to_string(_config._max_collection_elements);
    const auto not_integer = [&] {
        return s._writer.error("ERR value is not an integer or out of range");
    };
    const auto side = [](const std::string& v) -> std::optional<std::string> {
        auto u = resp_to_upper(v);
        return u == "LEFT" || u == "RIGHT" ? std::optional(u) : std::nullopt;
    };
    using redis_string_detail::parse_int64;

    if (id == redis_command_id::lmove || id == redis_command_id::rpoplpush) {
        if (auto e =
                authorize(s, upper, {a[1]}, redis_key_access::read | redis_key_access::write)) {
            return e;
        }
        if (auto e = authorize(s, upper, {a[2]}, redis_key_access::write)) {
            return e;
        }
        std::string from = "RIGHT";
        std::string to = "LEFT";
        if (id == redis_command_id::lmove) {
            const auto f = side(a[3]);
            const auto t = side(a[4]);
            if (!f || !t) {
                return s._writer.error("ERR syntax error");
            }
            from = *f;
            to = *t;
        }
        return propose_exec(s, cmd, a[1], redis_command_id::lmove,
                            {a[1], a[2], from, to, max_bytes, max_count}, true);
    }
    if (id == redis_command_id::lmpop) {
        const auto n = parse_int64(a[1]);
        if (!n) {
            return not_integer();
        }
        if (*n <= 0) {
            return s._writer.error("ERR numkeys should be greater than 0");
        }
        const auto numkeys = static_cast<std::size_t>(*n);
        if (a.size() < numkeys + 3) {
            return s._writer.error("ERR syntax error");
        }
        const auto dir = side(a[numkeys + 2]);
        if (!dir) {
            return s._writer.error("ERR syntax error");
        }
        std::string count = "1";
        if (a.size() == numkeys + 5 && resp_to_upper(a[numkeys + 3]) == "COUNT") {
            const auto c = parse_int64(a[numkeys + 4]);
            if (!c || *c <= 0) {
                return s._writer.error("ERR count should be greater than 0");
            }
            count = a[numkeys + 4];
        } else if (a.size() != numkeys + 3) {
            return s._writer.error("ERR syntax error");
        }
        std::vector<std::string_view> keys(a.begin() + 2,
                                           a.begin() + 2 + static_cast<std::ptrdiff_t>(numkeys));
        if (auto e = authorize(s, upper, keys, redis_key_access::read | redis_key_access::write)) {
            return e;
        }
        std::vector<std::string> args{a[1]};
        args.insert(args.end(), keys.begin(), keys.end());
        args.push_back(*dir);
        args.push_back(count);
        return propose_exec(s, cmd, a[2], id, std::move(args), false);
    }

    const auto& key = a[1];
    if (auto e = authorize(s, upper, {key})) {
        return e;
    }
    switch (id) {
        case redis_command_id::lpush:
        case redis_command_id::rpush:
        case redis_command_id::lpushx:
        case redis_command_id::rpushx: {
            std::vector<std::string> args{key, max_bytes, max_count};
            args.insert(args.end(), a.begin() + 2, a.end());
            return propose_exec(s, cmd, key, id, std::move(args), true);
        }
        case redis_command_id::lpop:
        case redis_command_id::rpop: {
            if (a.size() == 3) {
                const auto c = parse_int64(a[2]);
                if (!c || *c < 0) {
                    return s._writer.error("ERR value is out of range, must be positive");
                }
                return propose_exec(s, cmd, key, id, {key, "1", a[2]}, false);
            }
            return propose_exec(s, cmd, key, id, {key, "0", "1"}, false);
        }
        case redis_command_id::lset:
            if (!parse_int64(a[2])) {
                return not_integer();
            }
            return propose_exec(s, cmd, key, id, {key, a[2], a[3], max_bytes}, true);
        case redis_command_id::linsert: {
            const auto where = resp_to_upper(a[2]);
            if (where != "BEFORE" && where != "AFTER") {
                return s._writer.error("ERR syntax error");
            }
            return propose_exec(s, cmd, key, id, {key, where, a[3], a[4], max_bytes, max_count},
                                true);
        }
        case redis_command_id::lrem:
            if (!parse_int64(a[2])) {
                return not_integer();
            }
            return propose_exec(s, cmd, key, id, {key, a[2], a[3]}, false);
        case redis_command_id::ltrim:
            if (!parse_int64(a[2]) || !parse_int64(a[3])) {
                return not_integer();
            }
            return propose_exec(s, cmd, key, id, {key, a[2], a[3]}, false);
        default:
            return std::nullopt;
    }
}

}  // namespace kythira
