// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file chunk_service_test.cpp
/// @brief Chunk reads and writes between nodes (`chunk_service.hpp`;
///        .kiro/specs/s3-compatible-storage/ task 2, Requirements 10.1,
///        10.2 and 10.5): the local access, the server's routes, and the
///        remote access over mutual TLS against a real listener, including
///        corrupt copies, refused chunks, unauthorised callers and a node
///        that is down.

#define BOOST_TEST_MODULE chunk_service_test
#include <boost/test/unit_test.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/certificate_authority.hpp>
#include <raft/chunk_service.hpp>
#include <raft/chunk_store.hpp>
#include <raft/mtls_https_client.hpp>
#include <raft/private_file.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

namespace fs = std::filesystem;
namespace http = boost::beast::http;
using kythira::chunk_read_status;
using kythira::chunk_service;
using kythira::chunk_sha;
using kythira::chunk_store;
using kythira::chunk_store_options;
using kythira::chunk_write_result;
using kythira::local_chunk_access;
using kythira::remote_chunk_access;
using kythira::sha256_of;

/// Small enough that the "too large" cases are cheap, large enough that a
/// chunk can be loose (over the pack threshold) or packed.
constexpr std::size_t max_chunk = std::size_t{256} * 1024;
constexpr std::size_t pack_threshold = std::size_t{4} * 1024;

struct temp_dir {
    fs::path _path;
    temp_dir() {
        static std::atomic<int> counter{0};
        _path = fs::temp_directory_path() / ("kythira_chunk_service_" + std::to_string(::getpid()) +
                                             "_" + std::to_string(counter.fetch_add(1)));
        fs::remove_all(_path);
        fs::create_directories(_path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(_path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

auto options_for(const fs::path& dir) -> chunk_store_options {
    chunk_store_options o;
    o._data_dir = dir;
    o._pack_threshold_bytes = pack_threshold;
    o._max_chunk_bytes = max_chunk;
    return o;
}

auto make_bytes(std::size_t size, std::uint32_t seed) -> std::vector<std::byte> {
    std::vector<std::byte> out(size);
    std::uint32_t x = seed * 2654435761U + 1;
    for (auto& b : out) {
        x ^= x << 13U;
        x ^= x >> 17U;
        x ^= x << 5U;
        b = static_cast<std::byte>(x);
    }
    for (std::size_t i = 0; i < 4 && i < size; ++i) {
        out[i] = static_cast<std::byte>(seed >> (8U * i));
    }
    return out;
}

/// Flip one byte of a loose chunk's file.
void corrupt_loose(const chunk_store& store, const chunk_sha& sha) {
    std::fstream f(store.loose_path(sha), std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(100);
    f.put('\x55');
}

/// A cluster CA, a node certificate for the server, one for a calling
/// node, and one from a CA the server does not trust.
struct pki {
    fs::path dir;
    std::string ca_path;
    std::string server_cert;
    std::string server_key;
    std::string node_cert;
    std::string node_key;
    std::string stranger_cert;
    std::string stranger_key;

    pki() {
        dir = raft::make_private_temp_directory(fs::temp_directory_path(), "chunk-service-test-");
        raft::testing::certificate_authority ca;
        raft::testing::certificate_authority other;
        auto write = [&](const std::string& name, const std::string& pem) {
            const auto p = (dir / name).string();
            raft::write_private_file(p, pem);
            return p;
        };
        ca_path = write("ca.pem", ca.root_certificate_pem());
        raft::testing::leaf_certificate_options server;
        server.subject.common_name = "localhost";
        server.dns_names = {"localhost"};
        server.ip_addresses = {"127.0.0.1"};
        auto s = ca.issue(server);
        server_cert = write("server.pem", s.chain_pem);
        server_key = write("server.key", s.private_key_pem);

        raft::testing::leaf_certificate_options node;
        node.subject.common_name = "node-2";
        node.uri_names = {"spiffe://kythira/node/2"};
        node.server_auth = false;
        node.client_auth = true;
        auto n = ca.issue(node);
        node_cert = write("node.pem", n.chain_pem);
        node_key = write("node.key", n.private_key_pem);

        auto x = other.issue(node);
        stranger_cert = write("stranger.pem", x.chain_pem);
        stranger_key = write("stranger.key", x.private_key_pem);
    }
    ~pki() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    pki(const pki&) = delete;
    auto operator=(const pki&) -> pki& = delete;
    pki(pki&&) = delete;
    auto operator=(pki&&) -> pki& = delete;
};

/// One blob node: a store, its chunk service, and the internal listener.
struct node {
    temp_dir dir;
    chunk_store store;
    chunk_service service;
    kythira::https::server server;

    explicit node(const pki& p)
        : store(options_for(dir._path)),
          service(store, chunk_service::require_verified_client()),
          server(config_for(p), service.as_handler()) {
        server.start();
    }

    static auto config_for(const pki& p) -> kythira::https::server_config {
        kythira::https::server_config cfg;
        cfg.bind_address = "127.0.0.1";
        cfg.tls_cert_path = p.server_cert;
        cfg.tls_key_path = p.server_key;
        cfg.client_ca_path = p.ca_path;
        // Room for the largest chunk and then some, so an oversized chunk
        // reaches the service and gets its 413.
        cfg.max_body_bytes = 4 * max_chunk;
        return cfg;
    }

    [[nodiscard]] auto url() const -> std::string {
        return "https://localhost:" + std::to_string(server.port());
    }
};

auto client_config(const pki& p) -> kythira::mtls::client_config {
    kythira::mtls::client_config c;
    c.cert_path = p.node_cert;
    c.key_path = p.node_key;
    c.ca_path = p.ca_path;
    c.timeout = std::chrono::milliseconds{5000};
    c.max_body_bytes = 2 * max_chunk;
    return c;
}

auto remote_for(const pki& p, const node& n) -> remote_chunk_access {
    return {client_config(p), n.url(), max_chunk};
}

}  // namespace

// ---- local access -----------------------------------------------------------

BOOST_AUTO_TEST_CASE(local_write_is_created_then_present_and_reads_back) {
    temp_dir dir;
    chunk_store store(options_for(dir._path));
    local_chunk_access local(store);
    for (const std::size_t size : {std::size_t{100}, std::size_t{64} * 1024}) {
        const auto bytes = make_bytes(size, static_cast<std::uint32_t>(size));
        const auto sha = sha256_of(bytes);
        BOOST_TEST((local.read(sha)._status == chunk_read_status::missing));
        BOOST_TEST((local.write(sha, bytes) == chunk_write_result::created));
        BOOST_TEST((local.write(sha, bytes) == chunk_write_result::present));
        auto r = local.read(sha);
        BOOST_TEST((r._status == chunk_read_status::found));
        BOOST_TEST((r._bytes == bytes));
    }
}

BOOST_AUTO_TEST_CASE(local_write_refuses_bytes_that_do_not_match_or_do_not_fit) {
    temp_dir dir;
    chunk_store store(options_for(dir._path));
    local_chunk_access local(store);
    const auto bytes = make_bytes(1000, 1);
    const auto other = make_bytes(1000, 2);
    BOOST_TEST((local.write(sha256_of(other), bytes) == chunk_write_result::refused));
    const auto huge = make_bytes(max_chunk + 1, 3);
    BOOST_TEST((local.write(sha256_of(huge), huge) == chunk_write_result::refused));
    BOOST_TEST(!store.contains(sha256_of(other)));
    BOOST_TEST(!store.contains(sha256_of(huge)));
}

BOOST_AUTO_TEST_CASE(local_read_reports_a_corrupt_copy_and_never_returns_it) {
    temp_dir dir;
    chunk_store store(options_for(dir._path));
    local_chunk_access local(store);
    const auto bytes = make_bytes(32 * 1024, 4);
    const auto sha = sha256_of(bytes);
    BOOST_TEST((local.write(sha, bytes) == chunk_write_result::created));
    corrupt_loose(store, sha);
    auto r = local.read(sha);
    BOOST_TEST((r._status == chunk_read_status::corrupt));
    BOOST_TEST(r._bytes.empty());
    // The bad copy is gone, so a repair write stores the good bytes.
    BOOST_TEST(!store.contains(sha));
    BOOST_TEST((local.write(sha, bytes) == chunk_write_result::created));
    BOOST_TEST((local.read(sha)._status == chunk_read_status::found));
}

// A deferred put leaves a chunk staged (loose) or in an unflushed pack; a
// later write of the same bytes must not be answered before it is on disk.
BOOST_AUTO_TEST_CASE(ensure_durable_covers_chunks_another_writer_deferred) {
    temp_dir dir;
    chunk_store store(options_for(dir._path));
    const auto small = make_bytes(200, 5);
    const auto large = make_bytes(32 * 1024, 6);
    BOOST_TEST(store.put(sha256_of(small), small, kythira::chunk_durability::deferred));
    BOOST_TEST(store.put(sha256_of(large), large, kythira::chunk_durability::deferred));
    BOOST_TEST(store.ensure_durable(sha256_of(small)));
    BOOST_TEST(store.ensure_durable(sha256_of(large)));
    // After ensure_durable the loose chunk has its final name.
    BOOST_TEST(fs::exists(store.loose_path(sha256_of(large))));
    BOOST_TEST(!store.ensure_durable(sha256_of(make_bytes(10, 7))));

    local_chunk_access local(store);
    const auto again = make_bytes(48 * 1024, 8);
    BOOST_TEST(store.put(sha256_of(again), again, kythira::chunk_durability::deferred));
    BOOST_TEST((local.write(sha256_of(again), again) == chunk_write_result::present));
    BOOST_TEST(fs::exists(store.loose_path(sha256_of(again))));
}

// ---- the server's routes ----------------------------------------------------

BOOST_AUTO_TEST_CASE(service_ignores_other_targets_and_checks_name_method_and_caller) {
    temp_dir dir;
    chunk_store store(options_for(dir._path));
    chunk_service service(store, chunk_service::require_verified_client());
    kythira::https::request_context trusted;
    trusted.tls = true;
    trusted.client_verified = true;
    const auto sha_hex = kythira::to_hex(sha256_of(make_bytes(10, 9)));

    kythira::https::request other{http::verb::get, "/_kythira/kinesis/v1/propose", 11};
    BOOST_TEST(!service.handle(other, trusted).has_value());

    kythira::https::request bad_name{http::verb::get, "/_kythira/chunks/v1/xyz", 11};
    BOOST_TEST(service.handle(bad_name, trusted)->result_int() == 400U);

    kythira::https::request del{http::verb::delete_, "/_kythira/chunks/v1/" + sha_hex, 11};
    auto res = service.handle(del, trusted);
    BOOST_TEST(res->result_int() == 405U);
    BOOST_TEST(std::string((*res)[http::field::allow]) == "GET, PUT");

    kythira::https::request get{http::verb::get, "/_kythira/chunks/v1/" + sha_hex, 11};
    kythira::https::request_context plaintext;  // no TLS, no certificate
    BOOST_TEST(service.handle(get, plaintext)->result_int() == 403U);
    kythira::https::request_context unverified;
    unverified.tls = true;
    BOOST_TEST(service.handle(get, unverified)->result_int() == 403U);
    BOOST_TEST(service.handle(get, trusted)->result_int() == 404U);

    BOOST_CHECK_THROW(chunk_service(store, {}), std::invalid_argument);
}

// ---- remote access over mutual TLS ------------------------------------------

BOOST_AUTO_TEST_CASE(remote_write_and_read_round_trip_loose_and_packed_chunks) {
    pki p;
    node n(p);
    auto remote = remote_for(p, n);
    for (const std::size_t size : {std::size_t{0}, std::size_t{300}, max_chunk}) {
        const auto bytes = make_bytes(size, 100 + static_cast<std::uint32_t>(size));
        const auto sha = sha256_of(bytes);
        BOOST_TEST((remote.read(sha)._status == chunk_read_status::missing));
        BOOST_TEST((remote.write(sha, bytes) == chunk_write_result::created));
        BOOST_TEST((remote.write(sha, bytes) == chunk_write_result::present));
        BOOST_TEST(n.store.contains(sha));
        auto r = remote.read(sha);
        BOOST_TEST((r._status == chunk_read_status::found));
        BOOST_TEST((r._bytes == bytes));
    }
}

BOOST_AUTO_TEST_CASE(remote_write_refuses_a_wrong_or_oversized_chunk) {
    pki p;
    node n(p);
    auto remote = remote_for(p, n);
    const auto bytes = make_bytes(5000, 11);
    const auto wrong = sha256_of(make_bytes(5000, 12));
    BOOST_TEST((remote.write(wrong, bytes) == chunk_write_result::refused));
    BOOST_TEST(!n.store.contains(wrong));
    const auto huge = make_bytes(max_chunk + 1, 13);
    BOOST_TEST((remote.write(sha256_of(huge), huge) == chunk_write_result::refused));
    BOOST_TEST(!n.store.contains(sha256_of(huge)));

    // The raw answers behind those.
    kythira::mtls::client raw(client_config(p));
    auto res = raw.request("PUT", n.url(), "/_kythira/chunks/v1/" + kythira::to_hex(wrong),
                           std::string(5000, 'x'), "application/octet-stream", "test");
    BOOST_REQUIRE(res.has_value());
    BOOST_TEST(res->first == 400U);
    res = raw.request("PUT", n.url(), "/_kythira/chunks/v1/" + kythira::to_hex(sha256_of(huge)),
                      std::string(max_chunk + 1, 'x'), "application/octet-stream", "test");
    BOOST_REQUIRE(res.has_value());
    BOOST_TEST(res->first == 413U);
}

BOOST_AUTO_TEST_CASE(remote_read_of_a_corrupt_copy_is_corrupt_not_bytes) {
    pki p;
    node n(p);
    auto remote = remote_for(p, n);
    const auto bytes = make_bytes(64 * 1024, 14);
    const auto sha = sha256_of(bytes);
    BOOST_TEST((remote.write(sha, bytes) == chunk_write_result::created));
    corrupt_loose(n.store, sha);
    auto r = remote.read(sha);
    BOOST_TEST((r._status == chunk_read_status::corrupt));
    BOOST_TEST(r._bytes.empty());

    // The server dropped the bad copy as it found it; a repair writes the
    // good bytes again.
    BOOST_TEST(!n.store.contains(sha));
    BOOST_TEST((remote.write(sha, bytes) == chunk_write_result::created));
    BOOST_TEST((remote.read(sha)._status == chunk_read_status::found));
}

BOOST_AUTO_TEST_CASE(callers_without_a_cluster_certificate_get_nothing) {
    pki p;
    node n(p);
    const auto bytes = make_bytes(100, 15);
    const auto sha = sha256_of(bytes);

    // No certificate: the handshake succeeds, the service says 403.
    auto anonymous = client_config(p);
    anonymous.client_certificate = false;
    remote_chunk_access anon(anonymous, n.url(), max_chunk);
    BOOST_TEST((anon.write(sha, bytes) == chunk_write_result::unavailable));
    BOOST_TEST((anon.read(sha)._status == chunk_read_status::unavailable));
    kythira::mtls::client raw(anonymous);
    auto res = raw.request("GET", n.url(), "/_kythira/chunks/v1/" + kythira::to_hex(sha), {},
                           "application/octet-stream", "test");
    BOOST_REQUIRE(res.has_value());
    BOOST_TEST(res->first == 403U);

    // A certificate from another CA fails the handshake.
    auto stranger = client_config(p);
    stranger.cert_path = p.stranger_cert;
    stranger.key_path = p.stranger_key;
    remote_chunk_access strange(stranger, n.url(), max_chunk);
    BOOST_TEST((strange.write(sha, bytes) == chunk_write_result::unavailable));
    BOOST_TEST(!n.store.contains(sha));
}

BOOST_AUTO_TEST_CASE(a_node_that_is_down_is_unavailable) {
    pki p;
    std::string url;
    {
        node n(p);
        url = n.url();
    }
    auto cfg = client_config(p);
    cfg.timeout = std::chrono::milliseconds{2000};
    remote_chunk_access remote(cfg, url, max_chunk);
    const auto bytes = make_bytes(100, 16);
    BOOST_TEST((remote.write(sha256_of(bytes), bytes) == chunk_write_result::unavailable));
    BOOST_TEST((remote.read(sha256_of(bytes))._status == chunk_read_status::unavailable));
}

BOOST_AUTO_TEST_CASE(a_client_that_cannot_hold_the_largest_chunk_is_refused) {
    pki p;
    auto cfg = client_config(p);
    cfg.max_body_bytes = max_chunk - 1;
    BOOST_CHECK_THROW(remote_chunk_access(cfg, "https://localhost:1", max_chunk),
                      std::invalid_argument);
}
