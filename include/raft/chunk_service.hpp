// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file chunk_service.hpp
/// @brief Chunk reads and writes between nodes: the blob layer's wire
///        (.kiro/specs/s3-compatible-storage/ task 2, design "Layers";
///        Requirements 10.1, 10.2, 10.5 and 15.1).
///
/// The S3 front end cuts an object into content-addressed chunks, writes each
/// to the nodes its placement names, waits for a write quorum of durable
/// copies and only then commits a manifest naming them. The chunk may be on
/// this node (`local_chunk_access`, a function call into the `chunk_store`)
/// or on another (`remote_chunk_access`, one HTTPS request to that node's
/// `chunk_service`). Both satisfy `chunk_access`, so placement, quorum and
/// repair code is written once and a co-located node never touches the
/// network for its own copy.
///
/// **Wire.** One route family on the node's internal listener, raw bytes,
/// no encoding:
///
/// | Request | Answer |
/// |---|---|
/// | `PUT /_kythira/chunks/v1/<64 hex>`, body = the chunk | 201 stored now, 200 already held;
/// durable either way | | `GET /_kythira/chunks/v1/<64 hex>` | 200 with the bytes, 404 not held |
///
/// Errors: 400 the body does not hash to the name (or the name is not 64
/// hex digits), 413 larger than the store's largest chunk, 403 the caller
/// may not use the route, 405 another method, 500 the copy here is corrupt
/// (its bytes no longer hash to its name), 503 the store could not read or
/// write (I/O error, disk full). A 400 or 413 would fail on every node, so
/// the writer gives up; anything else, or no answer, means "try another
/// copy".
///
/// **Durability.** A write is answered only once the chunk is fsynced,
/// directory entry included, whether this call stored it or found it
/// already there (`chunk_store::ensure_durable`): the front end counts the
/// answer towards its write quorum, and Requirement 10.2 forbids a manifest
/// naming a chunk that is nowhere.
///
/// **Verification.** Content addressing makes every copy checkable
/// (Requirement 10.5). The server refuses a body that does not hash to its
/// name and never serves bytes that do not; the client hashes what it
/// receives too, so a copy damaged on the way is reported as corrupt, not
/// returned. A node drops a corrupt copy of its own as it finds it, so
/// the caller can read another copy and repair this one by writing it.
///
/// **Who may call.** The server asks `authorize` about every request. The
/// daemon passes a check on the connection's verified client certificate:
/// today any certificate from the cluster CA (`require_verified_client`);
/// once layer identity lands (kinesis-independent-layers task 3), the
/// front-end and blob roles only. A chunk name is not a secret, so the route
/// must never be open to object-API clients.
///
/// **Sizes.** Chunks are whole bodies in memory on both sides. The server's
/// listener must accept bodies of `chunk_store_options::_max_chunk_bytes`
/// (`https::server_config::max_body_bytes`), and the client's
/// `mtls::client_config::max_body_bytes` must be at least that for reads.
/// `remote_chunk_access` checks the second at construction.

#include <raft/beast_https_server.hpp>
#include <raft/chunk_store.hpp>
#include <raft/mtls_https_client.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira {

/// Path prefix of the chunk routes; the chunk's name follows it.
inline constexpr std::string_view chunk_service_prefix = "/_kythira/chunks/v1/";

/// The outcome of writing one copy of a chunk.
enum class chunk_write_result : std::uint8_t {
    /// This call stored it; it is durable.
    created,
    /// It was already held; it is durable now.
    present,
    /// The chunk itself is wrong (bytes that do not hash to the name, or too
    /// large). Every node would refuse it, so do not try another.
    refused,
    /// This copy could not be written (I/O error, disk full, the node is
    /// down or refused the caller). Try another node.
    unavailable,
};

/// What reading one copy of a chunk found.
enum class chunk_read_status : std::uint8_t {
    found,
    /// Not held here.
    missing,
    /// Held, but the bytes do not hash to the name: read another copy and
    /// repair this one.
    corrupt,
    /// The copy could not be read (I/O error, the node is down or refused
    /// the caller).
    unavailable,
};

struct chunk_read_result {
    chunk_read_status _status = chunk_read_status::unavailable;
    /// The chunk's bytes when `_status` is `found`, else empty.
    std::vector<std::byte> _bytes;
};

/// Whether a write counts towards the write quorum.
[[nodiscard]] constexpr auto is_durable(chunk_write_result r) noexcept -> bool {
    return r == chunk_write_result::created || r == chunk_write_result::present;
}

/// One node's copy of chunks: on this node or across the internal transport.
template<typename A>
concept chunk_access = requires(A& a, const chunk_sha& sha, std::span<const std::byte> bytes) {
    { a.write(sha, bytes) } -> std::same_as<chunk_write_result>;
    { a.read(sha) } -> std::same_as<chunk_read_result>;
};

/// The chunks in this node's own store, by function call.
class local_chunk_access {
public:
    explicit local_chunk_access(chunk_store& store) : _store(&store) {}

    /// Hash-check, store durably, and say whether this call created it.
    auto write(const chunk_sha& sha, std::span<const std::byte> bytes) -> chunk_write_result {
        if (bytes.size() > _store->options()._max_chunk_bytes || sha256_of(bytes) != sha) {
            return chunk_write_result::refused;
        }
        try {
            if (_store->put_verified(sha, bytes, chunk_durability::now)) {
                return chunk_write_result::created;
            }
            // Held already, perhaps not yet on disk.
            if (_store->ensure_durable(sha)) {
                return chunk_write_result::present;
            }
            // Removed between the two calls (a sweep): store it again.
            return _store->put_verified(sha, bytes, chunk_durability::now)
                       ? chunk_write_result::created
                       : chunk_write_result::unavailable;
        } catch (const std::exception&) {
            return chunk_write_result::unavailable;
        }
    }

    /// The bytes, hash-checked. A copy whose bytes no longer match is
    /// `corrupt`, never returned, and is dropped from the store as it is
    /// found: until then the store counts it as held, so the repair write
    /// that follows would be answered `present` and keep the bad bytes
    /// (`chunk_store::drop_if_corrupt`).
    auto read(const chunk_sha& sha) -> chunk_read_result {
        try {
            if (auto bytes = _store->read(sha)) {
                return {chunk_read_status::found, std::move(*bytes)};
            }
            // `read` gives nothing for both an absent chunk and a bad one.
            if (!_store->contains(sha)) {
                return {chunk_read_status::missing, {}};
            }
            _store->drop_if_corrupt(sha);
            return {chunk_read_status::corrupt, {}};
        } catch (const std::exception&) {
            return {chunk_read_status::unavailable, {}};
        }
    }

    [[nodiscard]] auto store() const noexcept -> chunk_store& { return *_store; }

private:
    chunk_store* _store;
};

/// Serves `chunk_service_prefix` routes from this node's store. Mount it on
/// the internal listener's handler: `handle` answers requests under the
/// prefix and returns nothing for any other target, so the daemon can try
/// its other routes.
class chunk_service {
public:
    /// May this connection use the chunk routes?
    using authorize_fn = std::function<bool(const https::request_context&)>;

    chunk_service(chunk_store& store, authorize_fn authorize)
        : _local(store), _authorize(std::move(authorize)) {
        if (!_authorize) {
            throw std::invalid_argument("chunk_service: an authorize check is required");
        }
    }

    /// The check the daemon uses until layer identity lands: a TLS
    /// connection with a client certificate that verified against the
    /// cluster CA.
    [[nodiscard]] static auto require_verified_client() -> authorize_fn {
        return [](const https::request_context& ctx) { return ctx.tls && ctx.client_verified; };
    }

    /// Whether `target` is one of this service's routes.
    [[nodiscard]] static auto owns(std::string_view target) noexcept -> bool {
        return target.starts_with(chunk_service_prefix);
    }

    [[nodiscard]] auto handle(const https::request& req, const https::request_context& ctx)
        -> std::optional<https::response> {
        namespace http = boost::beast::http;
        const std::string_view target{req.target().data(), req.target().size()};
        if (!owns(target)) {
            return std::nullopt;
        }
        if (!_authorize(ctx)) {
            return reply(req, http::status::forbidden, "chunk routes need a cluster identity");
        }
        const auto sha = chunk_sha_from_hex(target.substr(chunk_service_prefix.size()));
        if (!sha) {
            return reply(req, http::status::bad_request, "not a chunk name");
        }
        switch (req.method()) {
            case http::verb::put:
                return put(req, *sha);
            case http::verb::get:
                return get(req, *sha);
            default: {
                auto res = reply(req, http::status::method_not_allowed, "PUT or GET");
                res.set(http::field::allow, "GET, PUT");
                return res;
            }
        }
    }

    /// `handle` as an `https::handler` for a listener that serves nothing
    /// else (404 for other targets).
    [[nodiscard]] auto as_handler() -> https::handler {
        return [this](const https::request& req, const https::request_context& ctx) {
            if (auto res = handle(req, ctx)) {
                return std::move(*res);
            }
            return reply(req, boost::beast::http::status::not_found, "no such route");
        };
    }

private:
    auto put(const https::request& req, const chunk_sha& sha) -> https::response {
        namespace http = boost::beast::http;
        const auto& body = req.body();
        const std::span<const std::byte> bytes{reinterpret_cast<const std::byte*>(body.data()),
                                               body.size()};
        if (bytes.size() > _local.store().options()._max_chunk_bytes) {
            return reply(req, http::status::payload_too_large, "larger than the largest chunk");
        }
        if (sha256_of(bytes) != sha) {
            return reply(req, http::status::bad_request, "body does not hash to the chunk name");
        }
        switch (_local.write(sha, bytes)) {
            case chunk_write_result::created:
                return reply(req, http::status::created, {});
            case chunk_write_result::present:
                return reply(req, http::status::ok, {});
            case chunk_write_result::refused:
                return reply(req, http::status::bad_request, "chunk refused");
            case chunk_write_result::unavailable:
                break;
        }
        return reply(req, http::status::service_unavailable, "chunk store unavailable");
    }

    auto get(const https::request& req, const chunk_sha& sha) -> https::response {
        namespace http = boost::beast::http;
        auto r = _local.read(sha);
        switch (r._status) {
            case chunk_read_status::found: {
                https::response res{http::status::ok, req.version()};
                res.set(http::field::content_type, "application/octet-stream");
                res.body().assign(reinterpret_cast<const char*>(r._bytes.data()), r._bytes.size());
                res.keep_alive(req.keep_alive());
                res.prepare_payload();
                return res;
            }
            case chunk_read_status::missing:
                return reply(req, http::status::not_found, "chunk not held");
            case chunk_read_status::corrupt:
                return reply(req, http::status::internal_server_error, "chunk corrupt");
            case chunk_read_status::unavailable:
                break;
        }
        return reply(req, http::status::service_unavailable, "chunk store unavailable");
    }

    static auto reply(const https::request& req, boost::beast::http::status status,
                      std::string_view text) -> https::response {
        namespace http = boost::beast::http;
        https::response res{status, req.version()};
        res.set(http::field::content_type, "text/plain");
        res.body() = std::string(text);
        res.keep_alive(req.keep_alive());
        res.prepare_payload();
        return res;
    }

    local_chunk_access _local;
    authorize_fn _authorize;
};

/// Another node's chunks, through its `chunk_service`. One blocking HTTPS
/// request per call (mtls_https_client.hpp); the connection carries this
/// node's certificate, which the server's `authorize` checks.
class remote_chunk_access {
public:
    /// `base_url` is the node's internal listener, "https://host:port".
    /// `max_chunk_bytes` is the largest chunk the caller will read; the
    /// client must accept a body that large.
    remote_chunk_access(mtls::client_config config, std::string base_url,
                        std::size_t max_chunk_bytes = chunk_store_options{}._max_chunk_bytes)
        : _client(check(std::move(config), max_chunk_bytes)), _base_url(std::move(base_url)) {}

    auto write(const chunk_sha& sha, std::span<const std::byte> bytes) -> chunk_write_result {
        auto res =
            _client.request("PUT", _base_url, target(sha),
                            std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()),
                            "application/octet-stream", user_agent);
        if (!res) {
            return chunk_write_result::unavailable;
        }
        switch (res->first) {
            case 201:
                return chunk_write_result::created;
            case 200:
                return chunk_write_result::present;
            case 400:
            case 413:
                return chunk_write_result::refused;
            default:
                return chunk_write_result::unavailable;
        }
    }

    auto read(const chunk_sha& sha) -> chunk_read_result {
        auto res = _client.request("GET", _base_url, target(sha), {}, "application/octet-stream",
                                   user_agent);
        if (!res) {
            return {chunk_read_status::unavailable, {}};
        }
        switch (res->first) {
            case 200: {
                const auto& body = res->second;
                std::vector<std::byte> bytes(body.size());
                if (!body.empty()) {
                    std::memcpy(bytes.data(), body.data(), body.size());
                }
                if (sha256_of(bytes) != sha) {
                    return {chunk_read_status::corrupt, {}};
                }
                return {chunk_read_status::found, std::move(bytes)};
            }
            case 404:
                return {chunk_read_status::missing, {}};
            case 500:
                return {chunk_read_status::corrupt, {}};
            default:
                return {chunk_read_status::unavailable, {}};
        }
    }

    [[nodiscard]] auto base_url() const noexcept -> const std::string& { return _base_url; }

private:
    static constexpr std::string_view user_agent = "kythira-chunk-client/1";

    static auto check(mtls::client_config config, std::size_t max_chunk_bytes)
        -> mtls::client_config {
        if (config.max_body_bytes < max_chunk_bytes) {
            throw std::invalid_argument(
                "remote_chunk_access: client max_body_bytes is below the largest chunk");
        }
        return config;
    }

    [[nodiscard]] static auto target(const chunk_sha& sha) -> std::string {
        return std::string(chunk_service_prefix) + to_hex(sha);
    }

    mtls::client _client;
    std::string _base_url;
};

static_assert(chunk_access<local_chunk_access>);
static_assert(chunk_access<remote_chunk_access>);

}  // namespace kythira
