// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_gateway_integration_test.cpp
/// @brief Three in-process `multi_raft` hosts, each with a `redis_gateway` on
///        a real TCP port, driven by a hand-rolled RESP client
///        (.kiro/specs/redis-compatible-kv/ tasks 5-9 and 11).
///
/// The TLS cases mint a throwaway CA and certificates per test with OpenSSL,
/// so they need no fixtures on disk and no network beyond loopback.
///
/// The client is deliberately not a Redis library: it sends exactly the bytes
/// the test names and compares exactly the bytes that come back, so a reply
/// that redis-rs would tolerate but the spec forbids still fails. The real
/// sccache acceptance lives under services/redis/tests/docker/.
///
/// Built twice (Requirement 2.7 of .kiro/specs/disk-backed-build-cache/):
/// as `redis_gateway_integration_test` over `redis_kv_state_machine`, and
/// through redis_gateway_disk_store_integration_test.cpp, which defines
/// `KYTHIRA_GATEWAY_TEST_DISK_STORE`, as
/// `redis_gateway_disk_store_integration_test` over
/// `cache_kv_state_machine`, each host with its own chunk store under a
/// per-process temporary directory. Every case runs unchanged over both.
///
/// Built a third time through redis_gateway_engine_store_integration_test.cpp,
/// which defines `KYTHIRA_GATEWAY_TEST_ENGINE_STORE`, over the persistent
/// `persistent_kv_state_machine` with one `memory_kv_engine` per host
/// (.kiro/specs/persistent-state-machine/ task 7, Requirement 9.1).

#define BOOST_TEST_MODULE redis_gateway_integration_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"
#include "redis_golden_bytes.hpp"
#include "scratch_dir.hpp"
#include "test_ports.hpp"

#include <raft/bounded_resolver.hpp>
#include <raft/console_logger.hpp>
#include <raft/credential_verifier.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>
#include <kythira/redis/redis_call_wire.hpp>
#include <kythira/redis/redis_gateway_impl.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <kythira/redis/redis_remote_data_access.hpp>
#if defined(KYTHIRA_GATEWAY_TEST_DISK_STORE)
#include <kythira/redis/cache_chunk_fetcher.hpp>
#include <kythira/redis/cache_kv_state_machine.hpp>
#endif
#if defined(KYTHIRA_GATEWAY_TEST_ENGINE_STORE)
#include <raft/memory_kv_engine.hpp>
#include <kythira/redis/persistent_kv_state_machine.hpp>
#endif

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("redis_gateway_integration_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

using kythira::hibernation_mode;
using kythira::k_redis_base_format_level;
using kythira::k_redis_format_level;
using kythira::k_redis_typed_values_level;
using kythira::multi_raft;
using kythira::multi_raft_config;
using kythira::redis_acl;
using kythira::redis_gateway;
using kythira::redis_gateway_config;
using kythira::redis_read_consistency;
using kythira::resp_reply_length;
using kythira::shard_descriptor;
using kythira::shard_epoch;
using kythira::shard_range;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using key_type = std::string;
using group_id_type = std::uint64_t;
using node_id_t = std::uint64_t;

struct host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = std::uint64_t;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using network_client_type = fabric_client;
    using network_server_type = fabric_server;

    using persistence_engine_type =
        kythira::memory_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
#if defined(KYTHIRA_GATEWAY_TEST_DISK_STORE)
    using state_machine_type = kythira::cache_kv_state_machine<log_index_type>;
#elif defined(KYTHIRA_GATEWAY_TEST_ENGINE_STORE)
    using state_machine_type =
        kythira::persistent_kv_state_machine<kythira::memory_kv_engine, log_index_type>;
#else
    using state_machine_type = kythira::redis_kv_state_machine<log_index_type>;
#endif

    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type, group_id_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type, group_id_type>;
    using append_entries_request_type =
        kythira::append_entries_request<node_id_type, term_id_type, log_index_type, log_entry_type,
                                        group_id_type>;
    using append_entries_response_type =
        kythira::append_entries_response<term_id_type, log_index_type, group_id_type>;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type,
                                          group_id_type>;
    using install_snapshot_response_type =
        kythira::install_snapshot_response<term_id_type, group_id_type>;
};

using host_type = multi_raft<host_types, key_type, group_id_type>;
using config_type = multi_raft_config<host_types, key_type, group_id_type>;
using descriptor_type = shard_descriptor<group_id_type, key_type, node_id_t>;
using gateway_type = redis_gateway<host_type, kythira::console_logger, kythira::noop_metrics>;

#if defined(KYTHIRA_GATEWAY_TEST_DISK_STORE)
/// Every chunk store this process makes lives under one directory, removed
/// when the process exits.
auto disk_store_root() -> const std::filesystem::path& {
    struct root {
        std::filesystem::path _path = kythira::testing::fast_scratch_root() /
                                      ("kythira-gw-disk-" + std::to_string(::getpid()));
        root() {
            std::filesystem::remove_all(_path);
            std::filesystem::create_directories(_path);
        }
        ~root() {
            std::error_code ec;
            std::filesystem::remove_all(_path, ec);
        }
    };
    static const root r;
    return r._path;
}
#endif

/// Give a host its state machines. The in-memory machine needs nothing; the
/// disk-backed one gets one chunk store per host, shared by its groups, as
/// a real node has.
auto with_state_machines(config_type& cfg) -> void {
#if defined(KYTHIRA_GATEWAY_TEST_DISK_STORE)
    static std::atomic<std::uint64_t> next{0};
    auto dir = disk_store_root() / ("host-" + std::to_string(next.fetch_add(1)));
    kythira::cache_chunk_store_options opts;
    opts._data_dir = dir;
    // A node owns its store and the counts over it; the aliasing pointer
    // keeps both alive for as long as any replica holds the counts.
    struct node_store {
        explicit node_store(kythira::cache_chunk_store_options o)
            : _store(std::move(o)), _refs(_store) {}
        kythira::cache_chunk_store _store;
        kythira::chunk_refcounts _refs;
    };
    auto owner = std::make_shared<node_store>(std::move(opts));
    std::shared_ptr<kythira::chunk_refcounts> refs(owner, &owner->_refs);
    cfg.state_machine_factory = [refs](const group_id_type&) {
        return host_types::state_machine_type(refs);
    };
#elif defined(KYTHIRA_GATEWAY_TEST_ENGINE_STORE)
    // One engine per host, shared by its groups, as a real node has.
    cfg.state_engine = std::make_shared<kythira::memory_kv_engine>();
#else
    (void)cfg;
#endif
}

constexpr std::size_t k_node_count = 3;
constexpr std::size_t k_shard_count = 2;
constexpr std::uint32_t k_kdf_iters = 1000;
/// Every `sccache/...` key sorts above the "m" cut, so it lives in shard 2.
/// Tests that inspect a shard's node directly must look there, not in shard 1.
constexpr group_id_type k_sccache_group = 2;

auto range_of(std::optional<key_type> start, std::optional<key_type> end) -> shard_range<key_type> {
    return shard_range<key_type>{._start = std::move(start), ._end = std::move(end)};
}

/// Two shards split at "m", every one replicated on all three nodes.
auto static_shards() -> std::vector<descriptor_type> {
    const std::vector<node_id_t> voters{1, 2, 3};
    return {
        descriptor_type{._group_id = 1,
                        ._range = range_of(std::nullopt, key_type{"m"}),
                        ._epoch = shard_epoch{},
                        ._voters = voters},
        descriptor_type{._group_id = 2,
                        ._range = range_of(key_type{"m"}, std::nullopt),
                        ._epoch = shard_epoch{},
                        ._voters = voters},
    };
}

auto acl_text() -> std::string {
    return "user farm " + redis_acl::hash_secret("farm-secret", k_kdf_iters) +
           " read_write sccache/\n" + "user reader " +
           redis_acl::hash_secret("reader-secret", k_kdf_iters) + " read_only sccache/\n" +
           "user ops " + redis_acl::hash_secret("ops-secret", k_kdf_iters) + " admin *\n" +
           "user kythira-internal " + redis_acl::hash_secret("internal-secret", k_kdf_iters) +
           " read_write *\n" +
           // Task 9: client certificates map to users by subject.
           "user certfarm " + redis_acl::hash_secret("certfarm-secret", k_kdf_iters) +
           " read_write sccache/ cert=CN=farm\n" +
           "user gone disabled read_write sccache/ cert=CN=gone\n" +
           // IAM task 21: an IAM-only user (no password, still enabled) and
           // one that takes either.
           "user iamfarm disabled read_write sccache/ auth=iam\n" + "user bothfarm " +
           redis_acl::hash_secret("both-secret", k_kdf_iters) + " read_write sccache/ auth=both\n" +
           // redis-general-data-types task 5: a user whose counters may change.
           "user counter " + redis_acl::hash_secret("counter-secret", k_kdf_iters) +
           " read_write sccache/ mutable~sccache/counters/*\n";
}

// ── a throwaway PKI for the TLS cases ────────────────────────────────────────

using pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

auto make_key() -> pkey_ptr {
    pkey_ptr key(EVP_EC_gen("P-256"), &EVP_PKEY_free);
    if (!key) {
        throw std::runtime_error("EVP_EC_gen failed");
    }
    return key;
}

/// A certificate for `cn` signed by `issuer` (self-signed when null). A CA
/// gets the CA basic constraint; a leaf gets server and client key usage and
/// `san` (an OpenSSL subjectAltName value, e.g. "IP:127.0.0.1") if non-empty.
/// `uris` adds URI SANs (layer identities, whose role lists hold commas the
/// OpenSSL value syntax would split); with them `san` may only be
/// "IP:127.0.0.1" or empty.
auto make_cert(const std::string& cn, EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key, bool ca,
               const std::string& san, const std::vector<std::string>& uris = {}) -> x509_ptr {
    static std::atomic<long> serial{1};
    x509_ptr cert(X509_new(), &X509_free);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial++);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400);
    X509_set_pubkey(cert.get(), key);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert.get(), issuer != nullptr ? X509_get_subject_name(issuer) : name);
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer != nullptr ? issuer : cert.get(), cert.get(), nullptr, nullptr, 0);
    auto add = [&](int nid, const std::string& value) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
        if (ext == nullptr) {
            throw std::runtime_error("bad certificate extension " + value);
        }
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    };
    if (ca) {
        add(NID_basic_constraints, "critical,CA:TRUE");
        add(NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add(NID_basic_constraints, "critical,CA:FALSE");
        add(NID_ext_key_usage, "serverAuth,clientAuth");
        if (!uris.empty()) {
            GENERAL_NAMES* names = sk_GENERAL_NAME_new_null();
            if (san == "IP:127.0.0.1") {
                GENERAL_NAME* ip = GENERAL_NAME_new();
                GENERAL_NAME_set0_value(ip, GEN_IPADD, a2i_IPADDRESS("127.0.0.1"));
                sk_GENERAL_NAME_push(names, ip);
            } else if (!san.empty()) {
                throw std::runtime_error("make_cert: uris go with IP:127.0.0.1 only");
            }
            for (const auto& uri : uris) {
                GENERAL_NAME* g = GENERAL_NAME_new();
                ASN1_IA5STRING* text = ASN1_IA5STRING_new();
                ASN1_STRING_set(text, uri.data(), static_cast<int>(uri.size()));
                GENERAL_NAME_set0_value(g, GEN_URI, text);
                sk_GENERAL_NAME_push(names, g);
            }
            X509_add1_ext_i2d(cert.get(), NID_subject_alt_name, names, 0, X509V3_ADD_DEFAULT);
            GENERAL_NAMES_free(names);
        } else if (!san.empty()) {
            add(NID_subject_alt_name, san);
        }
    }
    if (X509_sign(cert.get(), issuer_key != nullptr ? issuer_key : key, EVP_sha256()) == 0) {
        throw std::runtime_error("X509_sign failed");
    }
    return cert;
}

/// PEM files under a private temporary directory, removed on destruction:
/// `ca` and `rogue-ca`, and leaves signed by `ca` — `node` (SAN IP 127.0.0.1,
/// what every gateway presents), `wrong-host` (SAN DNS kv.invalid only), and
/// client certificates `farm`, `gone` and `stranger`.
class test_pki {
public:
    test_pki() : _ca_key(make_key()), _ca(nullptr, &X509_free) {
        static std::atomic<int> counter{0};
        _dir =
            std::filesystem::temp_directory_path() /
            ("kythira-redis-tls-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
        std::filesystem::create_directories(_dir);
        _ca = make_cert("kythira test CA", _ca_key.get(), nullptr, nullptr, true, "");
        auto& ca = _ca;
        auto& ca_key = _ca_key;
        write("ca", ca.get(), ca_key.get());
        auto rogue_key = make_key();
        auto rogue = make_cert("rogue CA", rogue_key.get(), nullptr, nullptr, true, "");
        write("rogue-ca", rogue.get(), rogue_key.get());
        auto leaf = [&](const std::string& file, const std::string& cn, const std::string& san) {
            auto key = make_key();
            auto cert = make_cert(cn, key.get(), ca.get(), ca_key.get(), false, san);
            write(file, cert.get(), key.get());
        };
        leaf("node", "kythira-redis-node", "IP:127.0.0.1");
        leaf("wrong-host", "kythira-redis-node", "DNS:kv.invalid");
        leaf("farm", "farm", "");
        leaf("gone", "gone", "");
        leaf("stranger", "stranger", "");
    }
    ~test_pki() {
        std::error_code ec;
        std::filesystem::remove_all(_dir, ec);
    }
    test_pki(const test_pki&) = delete;
    auto operator=(const test_pki&) -> test_pki& = delete;

    [[nodiscard]] auto cert(const std::string& name) const -> std::string {
        return (_dir / (name + ".crt")).string();
    }
    [[nodiscard]] auto key(const std::string& name) const -> std::string {
        return (_dir / (name + ".key")).string();
    }

    /// A leaf for 127.0.0.1 carrying the layer identity
    /// `kythira://redis/<cluster>/<node>?roles=<roles>` (task 17), written
    /// as `file` (overwriting it: a rotation).
    auto layer_leaf(const std::string& file, const std::string& node, const std::string& roles,
                    const std::string& cluster = "test") -> void {
        auto key = make_key();
        auto cert = make_cert("kythira-redis-" + node, key.get(), _ca.get(), _ca_key.get(), false,
                              "IP:127.0.0.1",
                              {"kythira://redis/" + cluster + "/" + node + "?roles=" + roles});
        write(file, cert.get(), key.get());
    }

private:
    auto write(const std::string& name, X509* cert, EVP_PKEY* key) -> void {
        BIO* c = BIO_new_file(this->cert(name).c_str(), "w");
        BIO* k = BIO_new_file(this->key(name).c_str(), "w");
        bool ok = c != nullptr && k != nullptr && PEM_write_bio_X509(c, cert) == 1 &&
                  PEM_write_bio_PrivateKey(k, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
        BIO_free(c);
        BIO_free(k);
        if (!ok) {
            throw std::runtime_error("cannot write PEM files for " + name);
        }
    }

    std::filesystem::path _dir;
    pkey_ptr _ca_key;
    x509_ptr _ca;
};

/// Gateways with an mTLS listener presenting `leaf`, forwarding over TLS.
auto tls_config(const test_pki& pki, const std::string& leaf = "node") -> redis_gateway_config {
    redis_gateway_config cfg;
    cfg._tls_listen = "127.0.0.1:0";
    cfg._tls_cert_path = pki.cert(leaf);
    cfg._tls_key_path = pki.key(leaf);
    cfg._tls_ca_path = pki.cert("ca");
    cfg._require_client_cert = true;
    cfg._forward_tls = true;
    return cfg;
}

/// A TLS client context trusting the test CA, presenting `leaf` if given.
auto client_tls(const test_pki& pki, const std::string& leaf = "")
    -> std::shared_ptr<boost::asio::ssl::context> {
    namespace ssl = boost::asio::ssl;
    auto ctx = std::make_shared<ssl::context>(ssl::context::tls_client);
    ctx->load_verify_file(pki.cert("ca"));
    ctx->set_verify_mode(ssl::verify_peer);
    if (!leaf.empty()) {
        ctx->use_certificate_chain_file(pki.cert(leaf));
        ctx->use_private_key_file(pki.key(leaf), ssl::context::pem);
    }
    return ctx;
}

// ── a minimal RESP client ────────────────────────────────────────────────────

class resp_client {
public:
    /// Plaintext, or TLS when `tls` is given; a TLS client checks that the
    /// server certificate names 127.0.0.1.
    explicit resp_client(std::uint16_t port,
                         std::shared_ptr<boost::asio::ssl::context> tls = nullptr)
        : _tls_ctx(std::move(tls)) {
        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), port);
        if (_tls_ctx) {
            _tls.emplace(_io, *_tls_ctx);
            _tls->next_layer().connect(ep);
            _tls->next_layer().set_option(boost::asio::ip::tcp::no_delay(true));
            X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(_tls->native_handle()), "127.0.0.1");
            _tls->handshake(boost::asio::ssl::stream_base::client);
        } else {
            _plain.emplace(_io);
            _plain->connect(ep);
            _plain->set_option(boost::asio::ip::tcp::no_delay(true));
        }
    }

    static auto encode(const std::vector<std::string>& argv) -> std::string {
        std::string out = "*" + std::to_string(argv.size()) + "\r\n";
        for (const auto& a : argv) {
            out += "$" + std::to_string(a.size()) + "\r\n" + a + "\r\n";
        }
        return out;
    }

    auto send_raw(const std::string& bytes) -> void {
        if (_tls) {
            boost::asio::write(*_tls, boost::asio::buffer(bytes));
        } else {
            boost::asio::write(*_plain, boost::asio::buffer(bytes));
        }
    }

    /// Send one command and return its raw reply.
    auto call(const std::vector<std::string>& argv) -> std::string {
        send_raw(encode(argv));
        return read_reply();
    }

    auto read_reply() -> std::string {
        std::size_t len = 0;
        while ((len = resp_reply_length(_buffer)) == 0) {
            std::array<char, 65536> chunk{};
            boost::system::error_code ec;
            auto n = read_some(boost::asio::buffer(chunk), ec);
            if (ec) {
                throw std::runtime_error("connection closed: " + ec.message());
            }
            _buffer.append(chunk.data(), n);
        }
        auto reply = _buffer.substr(0, len);
        _buffer.erase(0, len);
        return reply;
    }

    /// True once the peer has closed the connection (EOF on read).
    auto wait_closed() -> bool {
        std::array<char, 16> chunk{};
        boost::system::error_code ec;
        while (true) {
            auto n = read_some(boost::asio::buffer(chunk), ec);
            if (ec == boost::asio::error::eof) {
                return true;
            }
            if (ec) {
                return true;
            }
            _buffer.append(chunk.data(), n);
        }
    }

    auto auth(const std::string& user, const std::string& secret) -> std::string {
        return call({"AUTH", user, secret});
    }

    /// The serial number of the certificate the TLS server presented.
    auto peer_serial() -> long {
        X509* cert = SSL_get1_peer_certificate(_tls->native_handle());
        const long serial = cert != nullptr ? ASN1_INTEGER_get(X509_get_serialNumber(cert)) : -1;
        X509_free(cert);
        return serial;
    }

private:
    auto read_some(boost::asio::mutable_buffer into, boost::system::error_code& ec) -> std::size_t {
        return _tls ? _tls->read_some(into, ec) : _plain->read_some(into, ec);
    }

    boost::asio::io_context _io;
    std::shared_ptr<boost::asio::ssl::context> _tls_ctx;
    std::optional<boost::asio::ip::tcp::socket> _plain;
    std::optional<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> _tls;
    std::string _buffer;
};

/// Every reply the gateway gives when a shard's leader cannot be reached.
auto is_retry_error(const std::string& reply) -> bool {
    return reply.rfind("-ERR ", 0) == 0 && reply.find("retry") != std::string::npos;
}

auto bulk(const std::string& s) -> std::string {
    return "$" + std::to_string(s.size()) + "\r\n" + s + "\r\n";
}

// ── a three-node cluster with a gateway per node ─────────────────────────────

class cluster {
public:
    /// `plaintext_forwarding` opts the gateways into forwarding over
    /// plaintext loopback, which every case not about forwarding security
    /// relies on; it has no effect once `base._forward_tls` is set.
    /// Runs on each gateway after it is built and before it starts: where
    /// a case installs cache hooks.
    using gateway_setup = std::function<void(node_id_t, gateway_type&)>;

    /// Adjusts one node's gateway configuration before it is built: where a
    /// case makes one node differ from the others.
    using config_tweak = std::function<void(node_id_t, redis_gateway_config&)>;

    explicit cluster(redis_gateway_config base = {}, bool plaintext_forwarding = true,
                     const gateway_setup& setup = {}, const config_tweak& tweak = {}) {
        _acl.reload(acl_text());
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            _hosts.push_back(std::make_unique<host_type>(make_config(id)));
            for (const auto& shard : static_shards()) {
                _hosts.back()->create_group(shard);
            }
        }
        for (auto& h : _hosts) {
            h->start();
        }
        for (std::size_t i = 0; i < _hosts.size(); ++i) {
            auto cfg = base;
            cfg._listen = "127.0.0.1:0";
            cfg._internal_secret = "internal-secret";
            cfg._io_threads = 1;
            cfg._worker_threads = 4;
            cfg._command_timeout = std::chrono::milliseconds{3000};
            cfg._allow_plaintext_forwarding =
                base._allow_plaintext_forwarding || plaintext_forwarding;
            const node_id_t from = static_cast<node_id_t>(i + 1);
            if (tweak) {
                tweak(from, cfg);
            }
            auto resolver = [this, from](const node_id_t& to) -> std::optional<std::string> {
                if (auto endpoint = endpoint_override(from, to)) {
                    return endpoint;
                }
                auto target = route(from, to);
                if (target < 1 || target > _gateways.size() || !_gateways[target - 1]) {
                    return std::nullopt;
                }
                const auto& gw = *_gateways[target - 1];
                return "127.0.0.1:" +
                       std::to_string(gw.config()._forward_tls ? gw.tls_port() : gw.port());
            };
            _gateways.push_back(
                std::make_unique<gateway_type>(*_hosts[i], _acl, _logger, _metrics, cfg, resolver));
            if (setup) {
                setup(from, *_gateways.back());
            }
        }
        for (auto& g : _gateways) {
            g->start();
        }
        _running = true;
        for (std::size_t i = 0; i < _hosts.size(); ++i) {
            _drivers.emplace_back([this, i] { drive(i); });
        }
    }

    ~cluster() {
        _running = false;
        for (auto& g : _front_ends) {
            g->stop();
        }
        for (auto& h : _front_end_hosts) {
            h->stop();
        }
        for (auto& t : _drivers) {
            if (t.joinable()) {
                t.join();
            }
        }
        for (auto& g : _gateways) {
            g->stop();
        }
        for (auto& h : _hosts) {
            h->stop();
        }
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;

    [[nodiscard]] auto host(node_id_t id) -> host_type& { return *_hosts.at(id - 1); }
    [[nodiscard]] auto gateway(node_id_t id) -> gateway_type& { return *_gateways.at(id - 1); }
    [[nodiscard]] auto port(node_id_t id) -> std::uint16_t { return _gateways.at(id - 1)->port(); }
    [[nodiscard]] auto tls_port(node_id_t id) -> std::uint16_t {
        return _gateways.at(id - 1)->tls_port();
    }

    /// Make node `from`'s gateway resolve node `to` to node `target`'s
    /// gateway: a stale or poisoned routing map.
    auto poison_route(node_id_t from, node_id_t to, node_id_t target) -> void {
        std::lock_guard<std::mutex> lock(_routes_mutex);
        _routes[{from, to}] = target;
    }
    /// Make node `from`'s gateway resolve node `to` to an arbitrary endpoint.
    auto override_endpoint(node_id_t from, node_id_t to, std::string endpoint) -> void {
        std::lock_guard<std::mutex> lock(_routes_mutex);
        _endpoint_overrides[{from, to}] = std::move(endpoint);
    }
    auto heal_routes() -> void {
        std::lock_guard<std::mutex> lock(_routes_mutex);
        _routes.clear();
        _endpoint_overrides.clear();
    }

    /// Crash node `id`: its Raft traffic is dropped, its host stops ticking
    /// and its gateway closes its listeners and connections.
    auto kill(node_id_t id) -> void {
        _alive[id - 1] = false;
        _fabric.kill(id);
        if (_drivers[id - 1].joinable()) {
            _drivers[id - 1].join();
        }
        _gateways[id - 1]->stop();
    }

    [[nodiscard]] auto leader_of(group_id_type group) -> node_id_t {
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            if (!_alive[id - 1]) {
                continue;  // a crashed node still believes it leads
            }
            auto* n = _hosts[id - 1]->group_node(group);
            if (n != nullptr && n->is_leader()) {
                return id;
            }
        }
        return 0;
    }

    [[nodiscard]] auto a_follower_of(group_id_type group) -> node_id_t {
        auto leader = leader_of(group);
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            if (id != leader && _alive[id - 1]) {
                return id;
            }
        }
        return 0;
    }

    auto await_all_leaders(std::chrono::milliseconds budget) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            bool all = true;
            for (group_id_type g = 1; g <= k_shard_count; ++g) {
                if (leader_of(g) == 0) {
                    all = false;
                    break;
                }
            }
            if (all) {
                // Let the leaders' no-op entries commit so the first write does
                // not race the term's first heartbeat.
                std::this_thread::sleep_for(std::chrono::milliseconds{200});
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        return false;
    }

    /// A node without the data layer (.kiro/specs/redis-general-data-types/
    /// task 16): its host is in no group, and its gateway reaches the data
    /// layer over `KYTHIRA.DATA` at every cluster node's gateway. It knows
    /// no peer endpoint of its own, so every address comes from the routes.
    auto add_front_end(redis_gateway_config cfg = {}) -> gateway_type& {
        const auto id = static_cast<node_id_t>(k_node_count + 1 + _front_end_hosts.size());
        _front_end_hosts.push_back(std::make_unique<host_type>(make_config(id)));
        _front_end_hosts.back()->start();
        cfg._listen = "127.0.0.1:0";
        if (cfg._internal_secret.empty()) {
            cfg._internal_secret = "internal-secret";
        }
        cfg._io_threads = 1;
        cfg._worker_threads = 4;
        cfg._command_timeout = std::chrono::milliseconds{3000};
        cfg._allow_plaintext_forwarding = true;
        // No layer identities in these cases: the secret stands in.
        cfg._insecure_plaintext = true;
        cfg._layer_roles = {kythira::layers::role::gateway, kythira::layers::role::front_end};
        if (cfg._data_nodes.empty()) {
            for (node_id_t n = 1; n <= k_node_count; ++n) {
                cfg._data_nodes.push_back("127.0.0.1:" + std::to_string(port(n)));
            }
        }
        _front_ends.push_back(std::make_unique<gateway_type>(
            *_front_end_hosts.back(), _acl, _logger, _metrics, cfg,
            [](const node_id_t&) -> std::optional<std::string> { return std::nullopt; }));
        _front_ends.back()->start();
        return *_front_ends.back();
    }

    /// A gateway without the front end (task 17): its host is in no group,
    /// and every command goes to one of the cluster nodes' front ends as
    /// `KYTHIRA.CALL`. By default it calls all three, on their TLS
    /// listeners when `cfg._forward_tls` is set; the case brings the
    /// credentials (a layer identity, or insecure plaintext and the secret).
    auto add_gateway(redis_gateway_config cfg) -> gateway_type& {
        const auto id = static_cast<node_id_t>(k_node_count + 1 + _front_end_hosts.size());
        _front_end_hosts.push_back(std::make_unique<host_type>(make_config(id)));
        _front_end_hosts.back()->start();
        cfg._listen = "127.0.0.1:0";
        cfg._io_threads = 1;
        cfg._worker_threads = 4;
        cfg._command_timeout = std::chrono::milliseconds{3000};
        cfg._layer_roles = {kythira::layers::role::gateway};
        if (cfg._front_ends.empty() && cfg._front_ends_dns.empty() &&
            cfg._membership_voters.empty() && !cfg._membership_local) {
            for (node_id_t n = 1; n <= k_node_count; ++n) {
                cfg._front_ends.push_back("127.0.0.1:" +
                                          std::to_string(cfg._forward_tls ? tls_port(n) : port(n)));
            }
        }
        _front_ends.push_back(std::make_unique<gateway_type>(
            *_front_end_hosts.back(), _acl, _logger, _metrics, cfg,
            [](const node_id_t&) -> std::optional<std::string> { return std::nullopt; }));
        _front_ends.back()->start();
        return *_front_ends.back();
    }

    /// Run the gateway's maintenance on the leader of `group` right now.
    auto maintain(group_id_type group) -> std::size_t {
        auto leader = leader_of(group);
        if (leader == 0) {
            return 0;
        }
        return _gateways[leader - 1]->run_maintenance();
    }

private:
    auto make_config(node_id_t id) -> config_type {
        config_type cfg{
            .node_id = id,
            .network_client = fabric_client{_fabric, id},
            .network_server = fabric_server{_fabric, id},
            .store_factory =
                [](const group_id_type&) { return host_types::persistence_engine_type{}; },
        };
        cfg.config._election_timeout_min = std::chrono::milliseconds{500};
        cfg.config._election_timeout_max = std::chrono::milliseconds{1000};
        cfg.config._heartbeat_interval = std::chrono::milliseconds{50};
        cfg.hibernation = hibernation_mode::off;
        cfg.executor_stripes = 2;
        cfg.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
        with_state_machines(cfg);
        return cfg;
    }

    auto endpoint_override(node_id_t from, node_id_t to) -> std::optional<std::string> {
        std::lock_guard<std::mutex> lock(_routes_mutex);
        auto it = _endpoint_overrides.find({from, to});
        if (it == _endpoint_overrides.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    auto route(node_id_t from, node_id_t to) -> node_id_t {
        std::lock_guard<std::mutex> lock(_routes_mutex);
        auto it = _routes.find({from, to});
        return it == _routes.end() ? to : it->second;
    }

    auto drive(std::size_t index) -> void {
        while (_running.load() && _alive[index].load()) {
            _hosts[index]->tick();
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
    }

    message_fabric _fabric{8};
    redis_acl _acl;
    kythira::console_logger _logger{kythira::log_level::warning};
    kythira::noop_metrics _metrics;
    std::vector<std::unique_ptr<host_type>> _hosts;
    std::vector<std::unique_ptr<gateway_type>> _gateways;
    std::vector<std::unique_ptr<host_type>> _front_end_hosts;
    std::vector<std::unique_ptr<gateway_type>> _front_ends;
    std::vector<std::thread> _drivers;
    std::atomic<bool> _running{false};
    std::array<std::atomic<bool>, k_node_count> _alive{true, true, true};
    std::mutex _routes_mutex;
    std::map<std::pair<node_id_t, node_id_t>, node_id_t> _routes;
    std::map<std::pair<node_id_t, node_id_t>, std::string> _endpoint_overrides;
};

/// Accepts connections on loopback and never answers: a peer gateway that
/// hung after accept().
class silent_peer {
public:
    silent_peer() : _acceptor(_io, {boost::asio::ip::make_address("127.0.0.1"), 0}) {
        _thread = std::thread([this] {
            while (!_stopping.load()) {
                boost::system::error_code ec;
                auto sock = _acceptor.accept(ec);
                if (ec) {
                    return;
                }
                ++_accepted;
                _held.push_back(std::move(sock));
            }
        });
    }
    ~silent_peer() {
        _stopping = true;
        boost::system::error_code ec;
        (void)_acceptor.cancel(ec);
        // accept() may not wake on cancel; a connection does wake it.
        boost::asio::ip::tcp::socket wake(_io);
        (void)wake.connect(_acceptor.local_endpoint(), ec);
        (void)_acceptor.close(ec);
        _thread.join();
    }
    silent_peer(const silent_peer&) = delete;
    auto operator=(const silent_peer&) -> silent_peer& = delete;

    [[nodiscard]] auto endpoint() const -> std::string {
        return "127.0.0.1:" + std::to_string(_acceptor.local_endpoint().port());
    }
    [[nodiscard]] auto accepted() const -> int { return _accepted.load(); }

private:
    boost::asio::io_context _io;
    boost::asio::ip::tcp::acceptor _acceptor;
    std::vector<boost::asio::ip::tcp::socket> _held;
    std::atomic<bool> _stopping{false};
    std::atomic<int> _accepted{0};
    std::thread _thread;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(redis_gateway)

BOOST_AUTO_TEST_CASE(sccache_handshake_pipeline_and_round_trip, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto leader = c.leader_of(2);
    resp_client client(c.port(leader));

    // redis-rs opens with this exact pipeline; the replies must come back in
    // order as one stream (Requirement 1.2, 1.5).
    client.send_raw(resp_client::encode({"AUTH", "farm", "farm-secret"}) +
                    resp_client::encode({"SELECT", "0"}) +
                    resp_client::encode({"CLIENT", "SETINFO", "LIB-NAME", "redis-rs"}) +
                    resp_client::encode({"CLIENT", "SETINFO", "LIB-VER", "0.25.0"}));
    BOOST_CHECK_EQUAL(client.read_reply(), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.read_reply(), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.read_reply(), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.read_reply(), "+OK\r\n");

    BOOST_CHECK_EQUAL(client.call({"PING"}), "+PONG\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/missing"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/obj1", "object-bytes"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/obj1"}), bulk("object-bytes"));
    BOOST_CHECK_EQUAL(client.call({"EXISTS", "sccache/obj1"}), ":1\r\n");
    BOOST_CHECK_EQUAL(client.call({"STRLEN", "sccache/obj1"}), ":12\r\n");
    BOOST_CHECK_EQUAL(client.call({"GETRANGE", "sccache/obj1", "0", "5"}), bulk("object"));
    BOOST_CHECK_EQUAL(client.call({"GETRANGE", "sccache/obj1", "-5", "-1"}), bulk("bytes"));
    BOOST_CHECK_EQUAL(client.call({"TTL", "sccache/obj1"}), ":-1\r\n");
    BOOST_CHECK_EQUAL(client.call({"DEL", "sccache/obj1"}), ":1\r\n");
    BOOST_CHECK_EQUAL(client.call({"DEL", "sccache/obj1"}), ":0\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/obj1"}), "$-1\r\n");

    // Binary-safe: values may contain CRLF and NULs (Requirement 1.3).
    std::string binary("a\r\n\0b\xff", 6);
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/bin", binary}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/bin"}), bulk(binary));

    BOOST_CHECK_EQUAL(client.call({"SELECT", "1"}), "-ERR DB index is out of range\r\n");
    BOOST_CHECK_EQUAL(client.call({"ECHO", "hi"}), bulk("hi"));
    BOOST_CHECK_EQUAL(client.call({"GET"}), "-ERR wrong number of arguments for 'get' command\r\n");
    auto unknown = client.call({"FLUSHALL"});
    BOOST_CHECK(unknown.rfind("-ERR unknown command 'FLUSHALL'", 0) == 0);
    // ...and the connection is still usable afterwards (Requirement 1.8).
    BOOST_CHECK_EQUAL(client.call({"PING"}), "+PONG\r\n");
    BOOST_CHECK_EQUAL(client.call({"QUIT"}), "+OK\r\n");
    BOOST_CHECK(client.wait_closed());
}

BOOST_AUTO_TEST_CASE(hello_3_switches_the_reply_encoding, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(1)));

    BOOST_CHECK_EQUAL(client.call({"HELLO", "4"}), "-NOPROTO unsupported protocol version\r\n");
    auto hello = client.call({"HELLO", "3", "AUTH", "farm", "farm-secret", "SETNAME", "t"});
    BOOST_CHECK(hello.rfind('%', 0) == 0);
    BOOST_CHECK(hello.find("$6\r\nserver\r\n$7\r\nkythira\r\n") != std::string::npos);
    BOOST_CHECK(hello.find("$5\r\nproto\r\n:3\r\n") != std::string::npos);
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/none"}), "_\r\n");
    BOOST_CHECK_EQUAL(client.call({"CLIENT", "GETNAME"}), bulk("t"));

    BOOST_CHECK_EQUAL(client.call({"RESET"}), "+RESET\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/none"}), "-NOAUTH Authentication required.\r\n");
    auto hello2 = client.call({"HELLO", "2", "AUTH", "farm", "farm-secret"});
    BOOST_CHECK(hello2.rfind('*', 0) == 0);
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/none"}), "$-1\r\n");
}

BOOST_AUTO_TEST_CASE(authentication_and_authorization, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._auth_failure_limit = 3;
    // Short enough to wait out below, long enough that the four failures and
    // the reconnect check comfortably land inside one window.
    cfg._auth_failure_window = std::chrono::seconds{3};
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto port = c.port(c.leader_of(1));

    {
        resp_client client(port);
        BOOST_CHECK_EQUAL(client.call({"GET", "sccache/x"}),
                          "-NOAUTH Authentication required.\r\n");
        BOOST_CHECK_EQUAL(client.call({"PING"}), "-NOAUTH Authentication required.\r\n");
        const std::string wrongpass =
            "-WRONGPASS invalid username-password pair or user is disabled.\r\n";
        BOOST_CHECK_EQUAL(client.auth("farm", "nope"), wrongpass);
        BOOST_CHECK_EQUAL(client.auth("ghost", "nope"), wrongpass);
        BOOST_CHECK_EQUAL(client.call({"AUTH", "nope"}), wrongpass);  // "default" user
        // Fourth failure from this source inside the window is refused
        // without running the KDF.
        auto limited = client.auth("farm", "farm-secret");
        BOOST_CHECK(limited.rfind("-ERR too many authentication failures", 0) == 0);
        BOOST_CHECK_GE(c.gateway(c.leader_of(1)).stats()._auth_failures.load(), 4u);
    }
    {
        // The limit is per source ADDRESS, not per connection: reconnecting
        // (a fresh source port) must not reset it, or a password guesser just
        // opens one connection per attempt.
        resp_client reconnect(port);
        auto limited = reconnect.auth("farm", "farm-secret");
        BOOST_CHECK(limited.rfind("-ERR too many authentication failures", 0) == 0);
    }
    // Once the window lapses the address may authenticate again.
    std::this_thread::sleep_for(cfg._auth_failure_window + std::chrono::milliseconds{500});
    {
        resp_client reader(port);
        BOOST_CHECK_EQUAL(reader.auth("reader", "reader-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(reader.call({"GET", "sccache/x"}), "$-1\r\n");
        BOOST_CHECK_EQUAL(reader.call({"SET", "sccache/x", "v"}),
                          "-NOPERM User reader has no permissions to run the 'SET' command\r\n");
        BOOST_CHECK_EQUAL(reader.call({"DEL", "sccache/x"}),
                          "-NOPERM User reader has no permissions to run the 'DEL' command\r\n");
        BOOST_CHECK_EQUAL(reader.call({"INFO"}),
                          "-NOPERM User reader has no permissions to run the 'INFO' command\r\n");
        BOOST_CHECK_EQUAL(reader.call({"GET", "other/x"}),
                          "-NOPERM No permissions to access a key\r\n");

        resp_client farm(port);
        BOOST_CHECK_EQUAL(farm.auth("farm", "farm-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(farm.call({"SET", "other/x", "v"}),
                          "-NOPERM No permissions to access a key\r\n");
        BOOST_CHECK_EQUAL(farm.call({"SET", "sccache/x", "v"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(farm.call({"INFO"}),
                          "-NOPERM User farm has no permissions to run the 'INFO' command\r\n");

        // DBSIZE counts this node's replicas, so ask the node that led the
        // SET rather than one that may not have applied it yet.
        resp_client ops(c.port(c.leader_of(k_sccache_group)));
        BOOST_CHECK_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
        auto info = ops.call({"INFO"});
        BOOST_CHECK(info.find("kythira_gateway:1") != std::string::npos);
        // redis-general-data-types Requirement 16.7: a node that sets no
        // roles reports all three.
        BOOST_CHECK(info.find("kythira_roles:gateway,front_end,data\r\n") != std::string::npos);
        BOOST_CHECK(info.find("kythira_authz_denials:") != std::string::npos);
        BOOST_CHECK_EQUAL(ops.call({"DBSIZE"}), ":1\r\n");
        // COMMAND answers from the registry: its shipped commands, less the
        // transaction commands this cluster (transactions off) refuses.
        const auto shipped = std::ranges::count_if(kythira::k_redis_commands, [](const auto& cmd) {
            return cmd.status == kythira::redis_command_status::shipped && cmd.name != "MULTI" &&
                   cmd.name != "EXEC" && cmd.name != "DISCARD" && cmd.name != "WATCH" &&
                   cmd.name != "UNWATCH" && cmd.name != "KYTHIRA.ISOLATION" &&
                   cmd.name != "KYTHIRA.TXN";
        });
        BOOST_CHECK_EQUAL(ops.call({"COMMAND", "COUNT"}), ":" + std::to_string(shipped) + "\r\n");
        BOOST_CHECK(ops.call({"COMMAND", "INFO", "incr", "nosuch"})
                        .starts_with("*2\r\n*10\r\n$4\r\nincr\r\n:2\r\n"));
    }
}

BOOST_AUTO_TEST_CASE(any_node_answers_any_key_by_forwarding, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));

    // Talk only to a follower of shard 2 and write a shard-2 key: the write
    // must be forwarded to the leader's gateway and the read served the same
    // way (Requirements 9.1-9.3).
    auto follower = c.a_follower_of(2);
    BOOST_REQUIRE_NE(follower, 0u);
    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/zzz", "far away"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/zzz"}), bulk("far away"));
    BOOST_CHECK_EQUAL(client.call({"EXISTS", "sccache/zzz"}), ":1\r\n");
    BOOST_CHECK_EQUAL(client.call({"TTL", "sccache/zzz"}), ":-1\r\n");
    BOOST_CHECK_GE(c.gateway(follower).stats()._forwards.load(), 4u);
    BOOST_CHECK_EQUAL(c.gateway(follower).stats()._forward_failures.load(), 0u);

    // The leader's own view agrees.
    resp_client direct(c.port(c.leader_of(2)));
    BOOST_REQUIRE_EQUAL(direct.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(direct.call({"GET", "sccache/zzz"}), bulk("far away"));
    BOOST_CHECK_EQUAL(client.call({"DEL", "sccache/zzz"}), ":1\r\n");
    BOOST_CHECK_EQUAL(direct.call({"GET", "sccache/zzz"}), "$-1\r\n");

    // A RESP3 client forwarding through a RESP2 internal hop still gets `_`.
    resp_client v3(c.port(follower));
    auto hello = v3.call({"HELLO", "3", "AUTH", "farm", "farm-secret"});
    BOOST_REQUIRE(hello.rfind('%', 0) == 0);
    BOOST_CHECK_EQUAL(v3.call({"GET", "sccache/zzz"}), "_\r\n");
}

BOOST_AUTO_TEST_CASE(forwarding_off_answers_with_a_retry_error, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._forwarding = false;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto follower = c.a_follower_of(k_sccache_group);
    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/aaa", "v"}),
                      "-ERR shard has no reachable leader, retry\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/aaa"}),
                      "-ERR shard has no reachable leader, retry\r\n");
}

BOOST_AUTO_TEST_CASE(any_replica_reads_serve_locally, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._read_consistency = redis_read_consistency::any_replica;
    cfg._forwarding = false;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client leader(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(leader.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(leader.call({"SET", "sccache/aaa", "replicated"}), "+OK\r\n");

    resp_client follower(c.port(c.a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(follower.auth("farm", "farm-secret"), "+OK\r\n");
    // Replication is asynchronous from the client's point of view; poll.
    std::string got;
    for (int i = 0; i < 100 && got != bulk("replicated"); ++i) {
        got = follower.call({"GET", "sccache/aaa"});
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    BOOST_CHECK_EQUAL(got, bulk("replicated"));
    BOOST_CHECK_EQUAL(c.gateway(c.a_follower_of(k_sccache_group)).stats()._forwards.load(), 0u);
}

#if defined(KYTHIRA_GATEWAY_TEST_DISK_STORE)
// Design Component 3, "Missing chunks on read": a replica whose `has_all`
// bit is clear (the fetcher has not brought every chunk yet) does not serve
// the value. A follower hands the read to the leader; a leader answers a
// miss rather than wait.
BOOST_AUTO_TEST_CASE(a_value_whose_chunks_are_not_here_is_not_served_here,
                     *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._read_consistency = redis_read_consistency::any_replica;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader_id = c.leader_of(k_sccache_group);
    const auto follower_id = c.a_follower_of(k_sccache_group);
    BOOST_REQUIRE_NE(follower_id, 0u);
    resp_client leader(c.port(leader_id));
    BOOST_REQUIRE_EQUAL(leader.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(leader.call({"SET", "sccache/far", "fetched elsewhere"}), "+OK\r\n");

    // Mark the entry unservable on one node, as a restore that named chunks
    // the store lacks would. Returns whether the node held the key.
    auto clear_has_all = [&](node_id_t id) {
        return c.host(id).group_node(k_sccache_group)->with_state_machine([](auto& sm) {
            auto m = sm.lookup("sccache/far");
            if (m) {
                m->set_has_all(false);
            }
            return static_cast<bool>(m);
        });
    };
    bool held = false;
    for (int i = 0; i < 100 && !(held = clear_has_all(follower_id)); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    BOOST_REQUIRE(held);

    resp_client follower(c.port(follower_id));
    BOOST_REQUIRE_EQUAL(follower.auth("farm", "farm-secret"), "+OK\r\n");
    const auto forwards_before = c.gateway(follower_id).stats()._forwards.load();
    BOOST_CHECK_EQUAL(follower.call({"GET", "sccache/far"}), bulk("fetched elsewhere"));
    BOOST_CHECK_EQUAL(follower.call({"STRLEN", "sccache/far"}), ":17\r\n");
    BOOST_CHECK_GE(c.gateway(follower_id).stats()._forwards.load(), forwards_before + 2);

    // The leader itself still fetching: a miss, consistently across reads.
    BOOST_REQUIRE(clear_has_all(leader_id));
    BOOST_CHECK_EQUAL(leader.call({"GET", "sccache/far"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(leader.call({"EXISTS", "sccache/far"}), ":0\r\n");
    BOOST_CHECK_EQUAL(leader.call({"TTL", "sccache/far"}), ":-2\r\n");
}

// Task 5's acceptance at the gateway: a follower that lost a chunk forwards
// reads of its key to the leader until the fetcher brings the chunk back
// from a peer, then serves them itself (Requirements 4.3 and 4.4).
BOOST_AUTO_TEST_CASE(a_fetch_moves_reads_from_forwarded_to_local, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._read_consistency = redis_read_consistency::any_replica;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader_id = c.leader_of(k_sccache_group);
    const auto follower_id = c.a_follower_of(k_sccache_group);
    BOOST_REQUIRE_NE(follower_id, 0u);
    resp_client leader(c.port(leader_id));
    BOOST_REQUIRE_EQUAL(leader.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(leader.call({"SET", "sccache/fetch", "from a peer"}), "+OK\r\n");

    auto* follower_node = c.host(follower_id).group_node(k_sccache_group);
    auto* leader_node = c.host(leader_id).group_node(k_sccache_group);
    auto look = [](auto* node) {
        return node->with_state_machine(
            [](auto& sm) { return std::pair{sm.lookup("sccache/fetch"), sm.refcounts()}; });
    };
    for (int i = 0; i < 100 && !look(follower_node).first; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    auto [manifest, refs] = look(follower_node);
    BOOST_REQUIRE(manifest);
    const auto sha = manifest->chunks().front();
    // Lose the chunk on the follower, as a disk swap or a restore would.
    BOOST_REQUIRE(refs->store().remove(sha));
    follower_node->with_state_machine([](auto& sm) { return sm.refresh_has_all(); });
    BOOST_REQUIRE(!manifest->has_all());

    resp_client follower(c.port(follower_id));
    BOOST_REQUIRE_EQUAL(follower.auth("farm", "farm-secret"), "+OK\r\n");
    // A follower that does not know a leader has nowhere to forward and
    // answers a miss. On a loaded CI runner a heartbeat can be late enough
    // for the follower to start a pre-vote and forget its leader, so wait
    // until it knows one again. A miss with no forward is what CI run
    // 41350889106 saw; the log was too long to keep the election lines,
    // and this is the only path that answers that way on a follower.
    auto knows_leader = [&] {
        return !follower_node->is_leader() && follower_node->known_leader();
    };
    for (int i = 0; i < 500 && !knows_leader(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    BOOST_REQUIRE(knows_leader());
    auto forwards = c.gateway(follower_id).stats()._forwards.load();
    std::string reply;
    for (int i = 0; i < 50; ++i) {
        reply = follower.call({"GET", "sccache/fetch"});
        if (reply == bulk("from a peer")) {
            break;
        }
        // The follower lost its leader again between the check and the
        // read: try again once it has had a moment to hear from one.
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    BOOST_CHECK_EQUAL(reply, bulk("from a peer"));
    BOOST_CHECK_GE(c.gateway(follower_id).stats()._forwards.load(), forwards + 1);

    auto leader_refs = look(leader_node).second;
    kythira::cache_chunk_fetcher<node_id_t> fetcher(
        refs, [leader_id](const group_id_type&) { return std::vector<node_id_t>{leader_id}; },
        [leader_refs](const node_id_t&, const kythira::chunk_sha& want) {
            return leader_refs->store().read(want);
        },
        [follower_node](const group_id_type&) {
            follower_node->with_state_machine([](auto& sm) { return sm.refresh_has_all(); });
        });
    fetcher.want(k_sccache_group, {sha});
    BOOST_REQUIRE(fetcher.run_once());
    BOOST_CHECK_EQUAL(fetcher.stats()._fetched.load(), 1u);
    BOOST_CHECK(manifest->has_all());

    forwards = c.gateway(follower_id).stats()._forwards.load();
    BOOST_CHECK_EQUAL(follower.call({"GET", "sccache/fetch"}), bulk("from a peer"));
    BOOST_CHECK_EQUAL(c.gateway(follower_id).stats()._forwards.load(), forwards);
}
#endif

BOOST_AUTO_TEST_CASE(linearizable_reads_go_through_the_log, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._read_consistency = redis_read_consistency::linearizable;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/aaa", "v1"}), "+OK\r\n");
    auto before =
        c.host(c.leader_of(k_sccache_group)).group_node(k_sccache_group)->last_applied_index();
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/aaa"}), bulk("v1"));
    BOOST_CHECK_GT(
        c.host(c.leader_of(k_sccache_group)).group_node(k_sccache_group)->last_applied_index(),
        before);
}

BOOST_AUTO_TEST_CASE(setex_expires_and_the_sweep_removes_it, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");

    BOOST_CHECK_EQUAL(client.call({"SETEX", "sccache/ttl", "0", "v"}),
                      "-ERR invalid expire time in 'setex' command\r\n");
    BOOST_CHECK_EQUAL(client.call({"SETEX", "sccache/ttl", "-5", "v"}),
                      "-ERR invalid expire time in 'setex' command\r\n");
    BOOST_CHECK_EQUAL(client.call({"SETEX", "sccache/ttl", "abc", "v"}),
                      "-ERR value is not an integer or out of range\r\n");
    BOOST_CHECK_EQUAL(client.call({"SETEX", "sccache/ttl", "1", "v"}), "+OK\r\n");
    auto ttl = client.call({"TTL", "sccache/ttl"});
    BOOST_CHECK(ttl == ":1\r\n" || ttl == ":0\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/ttl"}), bulk("v"));
    BOOST_CHECK_EQUAL(client.call({"SETEX", "sccache/keep", "1000", "k"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/forever", "f"}), "+OK\r\n");

    std::this_thread::sleep_for(std::chrono::milliseconds{1200});
    // Expired for readers immediately, before any sweep (Requirement 6.2).
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/ttl"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(client.call({"EXISTS", "sccache/ttl"}), ":0\r\n");
    BOOST_CHECK_EQUAL(client.call({"TTL", "sccache/ttl"}), ":-2\r\n");
    // Rewriting an expired key is not a conflict.
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/ttl", "v2"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"DEL", "sccache/ttl"}), ":1\r\n");
    BOOST_CHECK_EQUAL(client.call({"SETEX", "sccache/ttl", "1", "v3"}), "+OK\r\n");
    std::this_thread::sleep_for(std::chrono::milliseconds{1200});

    // The sweep removes it from the store on every replica.
    auto proposals = c.maintain(k_sccache_group);
    BOOST_CHECK_GE(proposals, 1u);
    auto count_on = [&](node_id_t id) {
        return c.host(id).group_node(k_sccache_group)->with_state_machine([](auto& sm) {
            return sm.approximate_key_count();
        });
    };
    for (int i = 0; i < 100 && (count_on(1) != 2 || count_on(2) != 2 || count_on(3) != 2); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    BOOST_CHECK_EQUAL(count_on(1), 2u);
    BOOST_CHECK_EQUAL(count_on(2), 2u);
    BOOST_CHECK_EQUAL(count_on(3), 2u);
    BOOST_CHECK_GE(c.gateway(c.leader_of(k_sccache_group)).stats()._expirations.load(), 1u);
    // Nothing to sweep now: the maintenance pass is a no-op.
    BOOST_CHECK_EQUAL(c.maintain(k_sccache_group), 0u);
}

BOOST_AUTO_TEST_CASE(immutable_values_and_size_limit, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._max_value_bytes = 64;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");

    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/k", "one"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/k", "one"}), "+OK\r\n");  // identical: no-op
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/k", "two"}),
                      "-ERR value conflict for an existing key\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/k"}), bulk("one"));
    BOOST_CHECK_EQUAL(c.gateway(c.leader_of(k_sccache_group)).stats()._value_conflicts.load(), 1u);

    std::string big(65, 'x');
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/big", big}),
                      "-ERR value exceeds the configured maximum of 64 bytes\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/big"}), "$-1\r\n");
    std::string fits(64, 'x');
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/big", fits}), "+OK\r\n");
}

BOOST_AUTO_TEST_CASE(eviction_when_a_shard_is_over_budget, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._max_shard_bytes = 400;
    cfg._sweep_batch = 2;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");

    // Ten 50-byte values: well past 400 bytes. Writes are never refused.
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK_EQUAL(
            client.call({"SET", "sccache/e" + std::to_string(i), std::string(50, 'v')}), "+OK\r\n");
    }
    // Reads keep e9 hot so it survives; the LRU tail goes first.
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/e0"}), bulk(std::string(50, 'v')));

    auto bytes_on_leader = [&] {
        return c.host(c.leader_of(k_sccache_group))
            .group_node(k_sccache_group)
            ->with_state_machine([](auto& sm) { return sm.approximate_size_bytes(); });
    };
    std::size_t passes = 0;
    while (bytes_on_leader() > 400 && passes < 20) {
        BOOST_CHECK_GE(c.maintain(k_sccache_group), 1u);
        ++passes;
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    BOOST_CHECK_LE(bytes_on_leader(), 400u);
    BOOST_CHECK_GE(c.gateway(c.leader_of(k_sccache_group)).stats()._evictions.load(), 1u);
    BOOST_CHECK_GE(c.gateway(c.leader_of(k_sccache_group)).stats()._over_budget_ticks.load(), 1u);
    // The most recently read key survived.
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/e0"}), bulk(std::string(50, 'v')));
    BOOST_CHECK_EQUAL(client.call({"EXISTS", "sccache/e1"}), ":0\r\n");
}

BOOST_AUTO_TEST_CASE(protocol_errors_close_and_limits_hold, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._max_clients = 2;
    cfg._parser_limits._max_bulk_len = 1024;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto port = c.port(c.leader_of(1));

    {
        resp_client bad(port);
        bad.send_raw("*1\r\n$2000\r\n");
        auto reply = bad.read_reply();
        BOOST_CHECK(reply.rfind("-ERR Protocol error:", 0) == 0);
        BOOST_CHECK(bad.wait_closed());
    }
    {
        resp_client bad(port);
        bad.send_raw("*1\r\n$abc\r\n");
        BOOST_CHECK(bad.read_reply().rfind("-ERR Protocol error:", 0) == 0);
        BOOST_CHECK(bad.wait_closed());
    }
    {
        resp_client first(port);
        resp_client second(port);
        BOOST_CHECK_EQUAL(first.auth("farm", "farm-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(second.auth("farm", "farm-secret"), "+OK\r\n");
        resp_client third(port);
        BOOST_CHECK_EQUAL(third.read_reply(), "-ERR max number of clients reached\r\n");
        BOOST_CHECK(third.wait_closed());
        BOOST_CHECK_GE(c.gateway(c.leader_of(1)).stats()._connections_rejected.load(), 1u);
    }
    // Slots are released on close.
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    resp_client again(port);
    BOOST_CHECK_EQUAL(again.auth("farm", "farm-secret"), "+OK\r\n");

    // Inline commands work too (redis-cli style).
    again.send_raw("PING\r\n");
    BOOST_CHECK_EQUAL(again.read_reply(), "+PONG\r\n");
}

// Vulnerability audit 2026-10-02 H3: before AUTH the parser runs under
// Redis's unauthenticated limits, one command at a time, so a stranger cannot
// park a 32 MiB argument per connection, yet a client that pipelines AUTH and
// a large SET in one write still gets both executed.
BOOST_AUTO_TEST_CASE(pre_auth_limits_and_pipelined_auth, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto port = c.port(c.leader_of(k_sccache_group));
    {
        resp_client bad(port);
        bad.send_raw("*2\r\n$4\r\nAUTH\r\n$20000\r\n");
        BOOST_CHECK_EQUAL(bad.read_reply(), "-ERR Protocol error: invalid bulk length\r\n");
        BOOST_CHECK(bad.wait_closed());
    }
    {
        resp_client bad(port);
        bad.send_raw("*11\r\n");
        BOOST_CHECK_EQUAL(bad.read_reply(), "-ERR Protocol error: invalid multibulk length\r\n");
        BOOST_CHECK(bad.wait_closed());
    }
    {
        const std::string value(100000, 'p');
        resp_client client(port);
        client.send_raw(resp_client::encode({"AUTH", "farm", "farm-secret"}) +
                        resp_client::encode({"SET", "sccache/pipelined", value}) +
                        resp_client::encode({"GET", "sccache/pipelined"}));
        BOOST_CHECK_EQUAL(client.read_reply(), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.read_reply(), "+OK\r\n");
        BOOST_CHECK(client.read_reply() == bulk(value));
    }
}

// Audit M8: a client that stops reading its replies stalls its own commands
// once its output buffer is full, instead of growing it without bound, and
// gets every reply, in order, once it reads again.
BOOST_AUTO_TEST_CASE(slow_reader_stalls_instead_of_buffering, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._max_output_buffer_bytes = 1024u * 1024u;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto leader = c.leader_of(k_sccache_group);
    resp_client client(c.port(leader));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    const std::string value(512u * 1024u, 'r');
    BOOST_REQUIRE_EQUAL(client.call({"SET", "sccache/slow", value}), "+OK\r\n");

    // ~50 MiB of replies, far beyond the socket buffers and the 1 MiB cap.
    constexpr int k_gets = 100;
    std::string batch;
    for (int i = 0; i < k_gets; ++i) {
        batch += resp_client::encode({"GET", "sccache/slow"});
    }
    client.send_raw(batch);
    const auto& stats = c.gateway(leader).stats();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
    while (stats._output_stalls.load() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    BOOST_CHECK_GE(stats._output_stalls.load(), 1u);
    const auto expected = bulk(value);
    for (int i = 0; i < k_gets; ++i) {
        BOOST_REQUIRE(client.read_reply() == expected);
    }
    BOOST_CHECK_EQUAL(client.call({"PING"}), "+PONG\r\n");
}

BOOST_AUTO_TEST_CASE(pipelined_writes_keep_order, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    std::string batch;
    constexpr int n = 50;
    for (int i = 0; i < n; ++i) {
        batch += resp_client::encode({"SET", "sccache/p" + std::to_string(i), std::to_string(i)});
        batch += resp_client::encode({"GET", "sccache/p" + std::to_string(i)});
    }
    client.send_raw(batch);
    for (int i = 0; i < n; ++i) {
        BOOST_CHECK_EQUAL(client.read_reply(), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.read_reply(), bulk(std::to_string(i)));
    }
}

BOOST_AUTO_TEST_CASE(empty_acl_refuses_to_start_unless_anonymous, *boost::unit_test::timeout(60)) {
    // No cluster needed: this is a start()-time check. A dummy host is
    // enough because start() never touches it.
    message_fabric fabric{2};
    config_type cfg{
        .node_id = 1,
        .network_client = fabric_client{fabric, 1},
        .network_server = fabric_server{fabric, 1},
        .store_factory = [](const group_id_type&) { return host_types::persistence_engine_type{}; },
    };
    cfg.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
    with_state_machines(cfg);
    host_type host(std::move(cfg));
    redis_acl acl;
    kythira::console_logger logger{kythira::log_level::error};
    kythira::noop_metrics metrics;
    redis_gateway_config gcfg;
    gcfg._listen = "127.0.0.1:0";
    {
        gateway_type gw(host, acl, logger, metrics, gcfg, nullptr);
        BOOST_CHECK_THROW(gw.start(), std::runtime_error);
        BOOST_CHECK(!gw.is_running());
    }
    gcfg._allow_anonymous = true;
    gateway_type gw(host, acl, logger, metrics, gcfg, nullptr);
    BOOST_CHECK_NO_THROW(gw.start());
    BOOST_CHECK(gw.is_running());
    BOOST_CHECK_NE(gw.port(), 0);
    resp_client client(gw.port());
    // Anonymous connections are admin; the host is not running, so a key
    // command reports LOADING rather than NOAUTH.
    BOOST_CHECK_EQUAL(client.call({"PING"}), "+PONG\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "x"}),
                      "-LOADING Kythira is loading the dataset in memory\r\n");
    gw.stop();
    BOOST_CHECK(!gw.is_running());
}

// ── task 8: forwarding failure modes ─────────────────────────────────────────

BOOST_AUTO_TEST_CASE(killing_a_shard_leader_gives_a_retry_error_then_recovers,
                     *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto old_leader = c.leader_of(k_sccache_group);
    const auto survivor = c.a_follower_of(k_sccache_group);
    BOOST_REQUIRE_NE(survivor, 0u);
    resp_client client(c.port(survivor));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_REQUIRE_EQUAL(client.call({"SET", "sccache/survives", "v"}), "+OK\r\n");

    c.kill(old_leader);

    // The survivor still names the dead node as leader (or no leader at all)
    // until an election completes; either way the client is told to retry,
    // promptly, rather than left hanging on a gateway that is gone.
    const auto started = std::chrono::steady_clock::now();
    const auto first = client.call({"GET", "sccache/survives"});
    BOOST_CHECK_MESSAGE(is_retry_error(first), "first reply after the kill: " << first);
    BOOST_CHECK_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds{5});

    // Then the shard elects a new leader among the survivors and the same
    // single endpoint answers again, with the committed value intact.
    bool recovered = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
    while (!recovered && std::chrono::steady_clock::now() < deadline) {
        auto reply = client.call({"GET", "sccache/survives"});
        if (reply == bulk("v")) {
            recovered = true;
            break;
        }
        BOOST_REQUIRE_MESSAGE(is_retry_error(reply), "unexpected reply during failover: " << reply);
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    BOOST_REQUIRE(recovered);
    const auto new_leader = c.leader_of(k_sccache_group);
    BOOST_CHECK_NE(new_leader, 0u);
    BOOST_CHECK_NE(new_leader, old_leader);
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/after", "w"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/after"}), bulk("w"));
}

BOOST_AUTO_TEST_CASE(a_poisoned_routing_map_does_not_loop, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader = c.leader_of(k_sccache_group);
    node_id_t f = 0;
    node_id_t g = 0;
    for (node_id_t id = 1; id <= k_node_count; ++id) {
        if (id != leader) {
            (f == 0 ? f : g) = id;
        }
    }
    BOOST_REQUIRE(f != 0 && g != 0);
    // Both followers believe the other one is the leader's gateway, the
    // shape that would bounce a command between them forever without the
    // one-hop rule (Requirement 13.3).
    c.poison_route(f, leader, g);
    c.poison_route(g, leader, f);

    resp_client client(c.port(f));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    const auto f_before = c.gateway(f).stats()._forwards.load();
    const auto g_before = c.gateway(g).stats()._forwards.load();
    BOOST_CHECK(is_retry_error(client.call({"SET", "sccache/poison", "v"})));
    BOOST_CHECK(is_retry_error(client.call({"GET", "sccache/poison"})));
    // Exactly one hop per command: f forwarded each once, and g, which got
    // them on an internal connection, forwarded nothing.
    BOOST_CHECK_EQUAL(c.gateway(f).stats()._forwards.load() - f_before, 2u);
    BOOST_CHECK_EQUAL(c.gateway(g).stats()._forwards.load() - g_before, 0u);

    // A map that points a gateway at itself is the degenerate loop.
    c.heal_routes();
    c.poison_route(f, leader, f);
    BOOST_CHECK(is_retry_error(client.call({"GET", "sccache/poison"})));
    BOOST_CHECK_EQUAL(c.gateway(f).stats()._forwards.load() - f_before, 3u);

    c.heal_routes();
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/poison", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/poison"}), bulk("v"));
}

// Requirement 13.4. The old SO_RCVTIMEO deadline never fired, because Asio
// answers the EAGAIN it causes by polling with no timeout, so this case hung
// a worker forever.
BOOST_AUTO_TEST_CASE(a_peer_that_never_answers_costs_one_command_timeout,
                     *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader = c.leader_of(k_sccache_group);
    const auto follower = c.a_follower_of(k_sccache_group);
    silent_peer peer;
    c.override_endpoint(follower, leader, peer.endpoint());

    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    const auto failures_before = c.gateway(follower).stats()._forward_failures.load();
    const auto started = std::chrono::steady_clock::now();
    BOOST_CHECK(is_retry_error(client.call({"GET", "sccache/hung"})));
    const auto took = std::chrono::steady_clock::now() - started;
    BOOST_CHECK_GE(peer.accepted(), 1);
    BOOST_CHECK_EQUAL(c.gateway(follower).stats()._forward_failures.load() - failures_before, 1u);
    // The fixture's command timeout is 3 s.
    BOOST_CHECK_GE(took, std::chrono::milliseconds{2500});
    BOOST_CHECK_LT(took, std::chrono::seconds{10});

    c.heal_routes();
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/hung"}), "$-1\r\n");
}

BOOST_AUTO_TEST_CASE(a_forward_dials_the_address_the_peer_was_last_seen_at,
                     *boost::unit_test::timeout(120)) {
    // Under rootless Podman a restarted gateway sits at an address its name
    // does not give for a while (bounded_resolver.hpp). The forward link
    // must then dial where the peer's Raft traffic was last seen from, as
    // redis_gateway_node learns it: a name DNS has never answered for, with
    // the leader's gateway port learned against it, still forwards.
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader = c.leader_of(k_sccache_group);
    const auto follower = c.a_follower_of(k_sccache_group);
    const std::string name = "kythira-gateway-" + std::to_string(c.port(leader)) + ".invalid";
    const auto port = c.port(leader);
    c.override_endpoint(follower, leader, name + ":" + std::to_string(port));

    sockaddr_storage seen_from{};
    auto& in4 = reinterpret_cast<sockaddr_in&>(seen_from);
    in4.sin_family = AF_INET;
    in4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    in4.sin_port = htons(40000);  // the ephemeral port an RPC came from
    auto hint =
        kythira::net_resolve::address_from(seen_from, sizeof(sockaddr_in), port, SOCK_STREAM);
    BOOST_REQUIRE(hint.has_value());
    kythira::net_resolve::learn(name, std::to_string(port), SOCK_STREAM, *hint);

    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    const auto failures_before = c.gateway(follower).stats()._forward_failures.load();
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/seen", "there"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/seen"}), bulk("there"));
    BOOST_CHECK_EQUAL(c.gateway(follower).stats()._forward_failures.load(), failures_before);
    c.heal_routes();
}

// ── Requirement 12.5 / task 9: forwarding and listener security ─────────────

BOOST_AUTO_TEST_CASE(forwarding_without_tls_or_the_plaintext_opt_in_sends_nothing,
                     *boost::unit_test::timeout(120)) {
    cluster c({}, false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto follower = c.a_follower_of(k_sccache_group);
    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(is_retry_error(client.call({"SET", "sccache/clear", "v"})));
    BOOST_CHECK(is_retry_error(client.call({"GET", "sccache/clear"})));
    // No forward was even attempted, so the internal secret never left.
    BOOST_CHECK_EQUAL(c.gateway(follower).stats()._forwards.load(), 0u);
}

BOOST_AUTO_TEST_CASE(forwarding_crosses_mutual_tls, *boost::unit_test::timeout(120)) {
    test_pki pki;
    cluster c(tls_config(pki), false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    BOOST_REQUIRE_NE(c.tls_port(1), 0);
    // The client speaks plaintext to a follower; the follower forwards to
    // the leader's mTLS listener, the only endpoint the resolver hands out.
    // That listener refuses a connection without a client certificate, so a
    // reply proves the hop was TLS with the node certificate presented.
    const auto follower = c.a_follower_of(k_sccache_group);
    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/tls", "sealed"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "sccache/tls"}), bulk("sealed"));
    BOOST_CHECK_GE(c.gateway(follower).stats()._forwards.load(), 2u);
    BOOST_CHECK_EQUAL(c.gateway(follower).stats()._forward_failures.load(), 0u);
}

BOOST_AUTO_TEST_CASE(forwarding_refuses_a_peer_the_ca_does_not_vouch_for,
                     *boost::unit_test::timeout(120)) {
    test_pki pki;
    auto cfg = tls_config(pki);
    cfg._forward_tls_ca_path = pki.cert("rogue-ca");
    cluster c(cfg, false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto follower = c.a_follower_of(k_sccache_group);
    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(is_retry_error(client.call({"GET", "sccache/tls"})));
    BOOST_CHECK_GE(c.gateway(follower).stats()._forward_failures.load(), 1u);
}

BOOST_AUTO_TEST_CASE(forwarding_refuses_a_certificate_for_another_host,
                     *boost::unit_test::timeout(120)) {
    test_pki pki;
    // Every gateway presents a certificate the CA signed, but for
    // kv.invalid, while the resolver dials 127.0.0.1.
    cluster c(tls_config(pki, "wrong-host"), false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto follower = c.a_follower_of(k_sccache_group);
    resp_client client(c.port(follower));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(is_retry_error(client.call({"GET", "sccache/tls"})));
    BOOST_CHECK_GE(c.gateway(follower).stats()._forward_failures.load(), 1u);
}

BOOST_AUTO_TEST_CASE(mtls_listener_maps_client_certificates_to_users,
                     *boost::unit_test::timeout(120)) {
    test_pki pki;
    cluster c(tls_config(pki), false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto port = c.tls_port(c.leader_of(k_sccache_group));

    // No certificate: the handshake, or the first exchange after it under
    // TLS 1.3, fails.
    bool refused = false;
    try {
        resp_client anonymous(port, client_tls(pki));
        anonymous.call({"PING"});
    } catch (const std::exception&) {
        refused = true;
    }
    BOOST_CHECK(refused);

    // A certificate whose subject maps to a user authenticates without
    // AUTH, and is held to that user's key prefixes.
    resp_client farm(port, client_tls(pki, "farm"));
    BOOST_CHECK_EQUAL(farm.call({"SET", "sccache/mtls", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(farm.call({"GET", "sccache/mtls"}), bulk("v"));
    BOOST_CHECK(farm.call({"SET", "other/mtls", "v"}).rfind("-NOPERM", 0) == 0);

    // A certificate for a disabled user establishes nobody.
    resp_client gone(port, client_tls(pki, "gone"));
    BOOST_CHECK_EQUAL(gone.call({"GET", "sccache/mtls"}), "-NOAUTH Authentication required.\r\n");

    // A valid certificate no user claims gets the same, and AUTH still works.
    resp_client stranger(port, client_tls(pki, "stranger"));
    BOOST_CHECK_EQUAL(stranger.call({"GET", "sccache/mtls"}),
                      "-NOAUTH Authentication required.\r\n");
    BOOST_REQUIRE_EQUAL(stranger.auth("reader", "reader-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(stranger.call({"GET", "sccache/mtls"}), bulk("v"));
}

BOOST_AUTO_TEST_CASE(multi_key_commands_keep_todays_behaviour_without_transactions,
                     *boost::unit_test::timeout(120)) {
    // multi-raft-transactions Requirement 11.2: with transactions off, the
    // multi-key surface is exactly what it was before task 9.
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(client.auth("ops", "ops-secret"), "+OK\r\n");
    for (const auto& name : {"MSET", "MGET", "MULTI", "EXEC", "DISCARD", "WATCH",
                             "KYTHIRA.ISOLATION", "KYTHIRA.TXN"}) {
        auto reply = client.call({name, "sccache/a", "1"});
        BOOST_CHECK_MESSAGE(reply.rfind(std::string("-ERR unknown command '") + name, 0) == 0,
                            name << ": " << reply);
    }
    BOOST_CHECK_EQUAL(client.call({"DEL", "sccache/a", "sccache/b"}),
                      "-ERR wrong number of arguments for 'del' command\r\n");
    // ...and the single-key commands still work.
    BOOST_CHECK_EQUAL(client.call({"SET", "sccache/a", "1"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"DEL", "sccache/a"}), ":1\r\n");
}

BOOST_AUTO_TEST_CASE(transactions_need_a_transactional_host, *boost::unit_test::timeout(60)) {
    // Requirement 11.1: an unwrapped KV state machine has no lock table, so
    // `--transactions on` is refused at start rather than half-working.
    static_assert(!gateway_type::k_transactional);
    redis_acl acl;
    acl.reload(acl_text());
    message_fabric fabric{1};
    config_type cfg{
        .node_id = 1,
        .network_client = fabric_client{fabric, 1},
        .network_server = fabric_server{fabric, 1},
        .store_factory = [](const group_id_type&) { return host_types::persistence_engine_type{}; },
    };
    host_type host(std::move(cfg));
    kythira::console_logger logger{kythira::log_level::error};
    kythira::noop_metrics metrics;
    redis_gateway_config gw_cfg;
    gw_cfg._listen = "127.0.0.1:0";
    gw_cfg._transactions = true;
    gateway_type gateway(host, acl, logger, metrics, gw_cfg, nullptr);
    BOOST_CHECK_EXCEPTION(gateway.start(), std::runtime_error, [](const std::runtime_error& e) {
        return std::string(e.what()).find("transaction adapter") != std::string::npos;
    });
    BOOST_CHECK(!gateway.is_running());
}

BOOST_AUTO_TEST_CASE(tls_forwarding_without_a_ca_refuses_to_start, *boost::unit_test::timeout(60)) {
    message_fabric fabric{2};
    config_type cfg{
        .node_id = 1,
        .network_client = fabric_client{fabric, 1},
        .network_server = fabric_server{fabric, 1},
        .store_factory = [](const group_id_type&) { return host_types::persistence_engine_type{}; },
    };
    cfg.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
    with_state_machines(cfg);
    host_type host(std::move(cfg));
    redis_acl acl;
    acl.reload(acl_text());
    kythira::console_logger logger{kythira::log_level::error};
    kythira::noop_metrics metrics;
    redis_gateway_config gcfg;
    gcfg._listen = "127.0.0.1:0";
    gcfg._internal_secret = "internal-secret";
    gcfg._forward_tls = true;
    gateway_type gw(host, acl, logger, metrics, gcfg, nullptr);
    BOOST_CHECK_THROW(gw.start(), std::runtime_error);
    BOOST_CHECK(!gw.is_running());
}

// ── cache hooks (.kiro/specs/disk-backed-build-cache/ task 7) ──────────────

/// What the hooks below saw, shared by the three gateways.
struct hook_log {
    std::mutex _mu;
    std::vector<std::string> _payloads;
    std::atomic<bool> _refuse{false};
    std::atomic<std::uint64_t> _excess{0};

    auto payloads() -> std::vector<std::string> {
        const std::lock_guard lock(_mu);
        return _payloads;
    }
};

auto hooks_into(const std::shared_ptr<hook_log>& log) -> cluster::gateway_setup {
    return [log](node_id_t id, gateway_type& gw) {
        gateway_type::cache_hooks h;
        h._advisory = [id] { return "node-" + std::to_string(id); };
        h._on_advisory = [log](std::string_view payload) {
            const std::lock_guard lock(log->_mu);
            log->_payloads.emplace_back(payload);
        };
        h._write_refusal = [log](const group_id_type&,
                                 const std::vector<node_id_t>&) -> std::optional<std::string> {
            if (log->_refuse.load()) {
                return std::string("node 3 has 0 bytes free, below the floor of 1");
            }
            return std::nullopt;
        };
        h._excess_bytes = [log](const group_id_type&, const std::vector<node_id_t>&) {
            return log->_excess.load();
        };
        gw.set_cache_hooks(std::move(h));
    };
}

// Requirement 6.2: a read a follower serves moves the key to the front of
// the leader's LRU, so the disk budget evicts what nobody reads.
BOOST_AUTO_TEST_CASE(follower_reads_reach_the_leaders_lru, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._read_consistency = redis_read_consistency::any_replica;
    auto log = std::make_shared<hook_log>();
    cluster c(cfg, true, hooks_into(log));
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader_id = c.leader_of(k_sccache_group);
    const auto follower_id = c.a_follower_of(k_sccache_group);
    resp_client leader(c.port(leader_id));
    BOOST_REQUIRE_EQUAL(leader.auth("farm", "farm-secret"), "+OK\r\n");
    // Written oldest first: "old" is the LRU's tail.
    BOOST_CHECK_EQUAL(leader.call({"SET", "sccache/old", "o"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(leader.call({"SET", "sccache/new", "n"}), "+OK\r\n");

    resp_client follower(c.port(follower_id));
    BOOST_REQUIRE_EQUAL(follower.auth("farm", "farm-secret"), "+OK\r\n");
    std::string got;
    for (int i = 0; i < 100 && got != bulk("o"); ++i) {
        got = follower.call({"GET", "sccache/old"});
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    BOOST_REQUIRE_EQUAL(got, bulk("o"));

    // The follower's maintenance sends the read and its payload.
    const auto received = c.gateway(leader_id).stats()._advisories_received.load();
    (void)c.gateway(follower_id).run_maintenance();
    BOOST_CHECK_GE(c.gateway(follower_id).stats()._advisories_sent.load(), 1U);
    BOOST_CHECK_GT(c.gateway(leader_id).stats()._advisories_received.load(), received);
    const auto payloads = log->payloads();
    BOOST_CHECK(std::find(payloads.begin(), payloads.end(),
                          "node-" + std::to_string(follower_id)) != payloads.end());

    // One byte over the budget evicts one key: the tail, now "new".
    log->_excess = 1;
    BOOST_CHECK_GE(c.maintain(k_sccache_group), 1U);
    log->_excess = 0;
    BOOST_CHECK_EQUAL(leader.call({"GET", "sccache/new"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(leader.call({"GET", "sccache/old"}), bulk("o"));
    BOOST_CHECK_EQUAL(c.gateway(leader_id).stats()._evictions.load(), 1U);
}

// Requirement 6.6: below a floor anywhere in the shard, SET is refused with
// a retryable error, on the leader and through a follower's forward; DEL
// still frees space and reads still work.
BOOST_AUTO_TEST_CASE(a_space_refusal_stops_set_but_not_del, *boost::unit_test::timeout(120)) {
    auto log = std::make_shared<hook_log>();
    cluster c({}, true, hooks_into(log));
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader_id = c.leader_of(k_sccache_group);
    resp_client leader(c.port(leader_id));
    BOOST_REQUIRE_EQUAL(leader.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(leader.call({"SET", "sccache/kept", "k"}), "+OK\r\n");

    log->_refuse = true;
    const auto refused = leader.call({"SET", "sccache/more", "m"});
    BOOST_CHECK(is_retry_error(refused));
    BOOST_CHECK(refused.find("bytes free") != std::string::npos);
    resp_client follower(c.port(c.a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(follower.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(is_retry_error(follower.call({"SET", "sccache/more", "m"})));
    BOOST_CHECK_GE(c.gateway(leader_id).stats()._space_refusals.load(), 2U);
    BOOST_CHECK_EQUAL(leader.call({"GET", "sccache/kept"}), bulk("k"));
    BOOST_CHECK_EQUAL(leader.call({"DEL", "sccache/kept"}), ":1\r\n");

    log->_refuse = false;
    BOOST_CHECK_EQUAL(leader.call({"SET", "sccache/more", "m"}), "+OK\r\n");
    resp_client ops(c.port(leader_id));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    const auto info = ops.call({"INFO"});
    BOOST_CHECK(info.find("kythira_space_refusals:") != std::string::npos);
}

// Kythira names itself as Kythira and reports a plain Redis compatibility
// level that clients can parse (redis-general-data-types Requirement
// 1.5-1.6): `server`/`server_name` kythira, `kythira_version` the build's,
// `version`/`redis_version` a bare major.minor.patch, and `standalone`
// unless the Cluster compatibility mode is on.
BOOST_AUTO_TEST_CASE(hello_and_info_identify_kythira, *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._kythira_version = "9.8.7+gabc1234";
    cfg._redis_compat_version = "7.2.4";
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));

    resp_client ops(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    const auto hello = ops.call({"HELLO", "2"});
    BOOST_CHECK(hello.find("$6\r\nserver\r\n$7\r\nkythira\r\n") != std::string::npos);
    BOOST_CHECK(hello.find("$7\r\nversion\r\n$5\r\n7.2.4\r\n") != std::string::npos);
    BOOST_CHECK(hello.find("$15\r\nkythira_version\r\n$14\r\n9.8.7+gabc1234\r\n") !=
                std::string::npos);
    BOOST_CHECK(hello.find("$4\r\nmode\r\n$10\r\nstandalone\r\n") != std::string::npos);
    BOOST_CHECK(hello.find("cluster") == std::string::npos);

    const auto info = ops.call({"INFO"});
    BOOST_CHECK(info.find("\r\nredis_version:7.2.4\r\n") != std::string::npos);
    BOOST_CHECK(info.find("\r\nserver_name:kythira\r\n") != std::string::npos);
    BOOST_CHECK(info.find("\r\nkythira_version:9.8.7+gabc1234\r\n") != std::string::npos);
    BOOST_CHECK(info.find("\r\nredis_mode:standalone\r\n") != std::string::npos);
    BOOST_CHECK(info.find("-kythira") == std::string::npos);
}

// The Cluster compatibility mode (phase 2) is the only thing that makes the
// gateway report `cluster`; the flag is wired now so the mode string has one
// source.
BOOST_AUTO_TEST_CASE(cluster_mode_only_with_the_compatibility_mode,
                     *boost::unit_test::timeout(120)) {
    redis_gateway_config cfg;
    cfg._cluster_compat_mode = true;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client ops(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_CHECK(ops.call({"HELLO", "2"}).find("$4\r\nmode\r\n$7\r\ncluster\r\n") !=
                std::string::npos);
    BOOST_CHECK(ops.call({"INFO"}).find("\r\nredis_mode:cluster\r\n") != std::string::npos);
}

// A compatibility level with a vendor suffix, or not three numbers, would
// break clients' version parsers, so the gateway refuses to start with one.
BOOST_AUTO_TEST_CASE(a_suffixed_compat_version_is_refused_at_start,
                     *boost::unit_test::timeout(60)) {
    BOOST_CHECK(kythira::is_plain_redis_version("7.0.0"));
    BOOST_CHECK(kythira::is_plain_redis_version("10.12.345"));
    for (const char* bad : {"7.0.0-kythira", "7.0", "7..0", ".7.0.0", "7.0.0.", "7.0.0.1", "v7.0.0",
                            "7.0.x", "", " 7.0.0"}) {
        BOOST_CHECK_MESSAGE(!kythira::is_plain_redis_version(bad), bad);
    }

    message_fabric fabric{2};
    config_type cfg{
        .node_id = 1,
        .network_client = fabric_client{fabric, 1},
        .network_server = fabric_server{fabric, 1},
        .store_factory = [](const group_id_type&) { return host_types::persistence_engine_type{}; },
    };
    cfg.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
    with_state_machines(cfg);
    host_type host(std::move(cfg));
    redis_acl acl;
    acl.reload(acl_text());
    kythira::console_logger logger{kythira::log_level::error};
    kythira::noop_metrics metrics;
    redis_gateway_config gcfg;
    gcfg._listen = "127.0.0.1:0";
    gcfg._redis_compat_version = "7.0.0-kythira";
    gateway_type gw(host, acl, logger, metrics, gcfg, nullptr);
    BOOST_CHECK_EXCEPTION(gw.start(), std::runtime_error, [](const std::runtime_error& e) {
        return std::string(e.what()).find("major.minor.patch") != std::string::npos;
    });
    BOOST_CHECK(!gw.is_running());
}

// The reply bytes of every command the default build supports, including its
// errors, pinned before the gateway moves into services/redis/
// (.kiro/specs/redis-gateway-module/ task 1). The script avoids replies that
// depend on the clock or the cluster's history (TTL of an expiring key, INFO,
// DBSIZE after writes). The disk-store variant runs the same script against
// the same file: the store must not change a single reply byte.
// Regenerate with KYTHIRA_UPDATE_GOLDENS=1; a change is a wire change.
BOOST_AUTO_TEST_CASE(resp_replies_match_the_golden_file, *boost::unit_test::timeout(120)) {
    // HELLO carries kythira_version, which is the build's git describe by
    // default; pin it so the file does not change with every commit.
    redis_gateway_config pinned;
    pinned._kythira_version = "0.1.0+golden";
    cluster c(pinned);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto port = c.port(c.leader_of(k_sccache_group));
    using kythira::testing::golden::escape;

    std::string out =
        "# RESP replies of redis_gateway_node, default build (redis-gateway-module\n"
        "# task 1). One `>` line per command sent, one `<` line per reply, escaped.\n"
        "# Regenerate with KYTHIRA_UPDATE_GOLDENS=1; a change here is a wire change.\n";
    auto record = [&](resp_client& client, const std::string& who,
                      const std::vector<std::string>& argv) {
        std::string line = "> " + who;
        for (const auto& a : argv) {
            line += " " + escape(a);
        }
        out += line + "\n< " + escape(client.call(argv)) + "\n";
    };

    resp_client farm(port);
    out += "## before AUTH\n";
    record(farm, "farm", {"GET", "sccache/x"});
    record(farm, "farm", {"PING"});
    record(farm, "farm", {"AUTH"});
    record(farm, "farm", {"AUTH", "farm", "wrong-secret"});
    record(farm, "farm", {"AUTH", "nobody", "farm-secret"});
    record(farm, "farm", {"AUTH", "gone", "anything"});
    record(farm, "farm", {"HELLO", "4"});
    record(farm, "farm", {"HELLO", "x"});
    record(farm, "farm", {"AUTH", "farm", "farm-secret"});

    out += "## connection commands\n";
    record(farm, "farm", {"PING"});
    record(farm, "farm", {"PING", "hello"});
    record(farm, "farm", {"PING", "a", "b"});
    record(farm, "farm", {"ping"});
    record(farm, "farm", {"ECHO", "hi"});
    record(farm, "farm", {"ECHO"});
    record(farm, "farm", {"SELECT", "0"});
    record(farm, "farm", {"SELECT", "1"});
    record(farm, "farm", {"SELECT"});
    record(farm, "farm", {"CLIENT", "GETNAME"});
    record(farm, "farm", {"CLIENT", "SETNAME", "golden"});
    record(farm, "farm", {"CLIENT", "GETNAME"});
    record(farm, "farm", {"CLIENT", "SETINFO", "LIB-NAME", "redis-rs"});
    record(farm, "farm", {"CLIENT", "SETINFO", "LIB-VER", "0.25.0"});
    record(farm, "farm", {"CLIENT", "SETINFO", "BOGUS", "1"});
    record(farm, "farm", {"CLIENT", "NOSUCH"});
    record(farm, "farm", {"CLIENT"});
    record(farm, "farm", {"COMMAND", "COUNT"});
    record(farm, "farm", {"COMMAND", "LIST"});
    record(farm, "farm", {"COMMAND", "DOCS"});
    record(farm, "farm", {"COMMAND", "INFO", "get"});
    record(farm, "farm", {"COMMAND"});
    record(farm, "farm", {"FLUSHALL"});
    record(farm, "farm", {"FLUSHALL", "ASYNC"});
    record(farm, "farm", {"KYTHIRA.ADVISE", "node-9;0,0,0"});
    record(farm, "farm", {"INFO"});
    record(farm, "farm", {"DBSIZE"});

    out += "## data commands\n";
    record(farm, "farm", {"GET", "sccache/missing"});
    record(farm, "farm", {"GET"});
    record(farm, "farm", {"GET", "a", "b"});
    record(farm, "farm", {"SET", "sccache/obj1", "object-bytes"});
    record(farm, "farm", {"SET", "sccache/obj1", "other-bytes"});
    record(farm, "farm", {"SET", "sccache/obj1"});
    record(farm, "farm", {"SET", "sccache/obj1", "v", "EX", "10"});
    record(farm, "farm", {"GET", "sccache/obj1"});
    record(farm, "farm", {"get", "sccache/obj1"});
    record(farm, "farm", {"EXISTS", "sccache/obj1"});
    record(farm, "farm", {"EXISTS", "sccache/missing"});
    record(farm, "farm", {"EXISTS"});
    record(farm, "farm", {"STRLEN", "sccache/obj1"});
    record(farm, "farm", {"STRLEN", "sccache/missing"});
    record(farm, "farm", {"GETRANGE", "sccache/obj1", "0", "5"});
    record(farm, "farm", {"GETRANGE", "sccache/obj1", "-5", "-1"});
    record(farm, "farm", {"GETRANGE", "sccache/obj1", "5", "1"});
    record(farm, "farm", {"GETRANGE", "sccache/obj1", "0", "1000"});
    record(farm, "farm", {"GETRANGE", "sccache/missing", "0", "1"});
    record(farm, "farm", {"GETRANGE", "sccache/obj1", "a", "b"});
    record(farm, "farm", {"GETRANGE", "sccache/obj1", "0"});
    record(farm, "farm", {"TTL", "sccache/obj1"});
    record(farm, "farm", {"TTL", "sccache/missing"});
    record(farm, "farm", {"TTL"});
    record(farm, "farm", {"SETEX", "sccache/exp", "100", "v"});
    record(farm, "farm", {"SETEX", "sccache/exp2", "0", "v"});
    record(farm, "farm", {"SETEX", "sccache/exp2", "-1", "v"});
    record(farm, "farm", {"SETEX", "sccache/exp2", "abc", "v"});
    record(farm, "farm", {"SETEX", "sccache/exp2", "100"});
    record(farm, "farm", {"GET", "sccache/exp"});
    record(farm, "farm", {"SET", "sccache/bin", std::string("a\r\n\0b\xff", 6)});
    record(farm, "farm", {"GET", "sccache/bin"});
    record(farm, "farm", {"SET", "sccache/empty", ""});
    record(farm, "farm", {"GET", "sccache/empty"});
    record(farm, "farm", {"STRLEN", "sccache/empty"});
    record(farm, "farm", {"DEL", "sccache/obj1"});
    record(farm, "farm", {"DEL", "sccache/obj1"});
    record(farm, "farm", {"DEL"});
    record(farm, "farm", {"GET", "sccache/obj1"});
    record(farm, "farm", {"GET", "other/key"});
    record(farm, "farm", {"SET", "other/key", "v"});
    record(farm, "farm", {"DEL", "other/key"});
    record(farm, "farm", {"MSET", "sccache/a", "1", "sccache/b", "2"});
    record(farm, "farm", {"MGET", "sccache/a", "sccache/b"});
    record(farm, "farm", {"MULTI"});
    record(farm, "farm", {"EXEC"});
    record(farm, "farm", {"DISCARD"});
    record(farm, "farm", {"WATCH", "sccache/a"});
    record(farm, "farm", {"UNWATCH"});

    out += "## roles\n";
    resp_client reader(port);
    record(reader, "reader", {"AUTH", "reader", "reader-secret"});
    record(reader, "reader", {"GET", "sccache/bin"});
    record(reader, "reader", {"SET", "sccache/r", "v"});
    record(reader, "reader", {"SETEX", "sccache/r", "10", "v"});
    record(reader, "reader", {"DEL", "sccache/bin"});
    record(reader, "reader", {"DBSIZE"});
    resp_client ops(port);
    record(ops, "ops", {"AUTH", "ops", "ops-secret"});
    record(ops, "ops", {"GET", "anything/at/all"});
    record(ops, "ops", {"SET", "ops/key", "v"});
    record(ops, "ops", {"DEL", "ops/key"});

    out += "## RESP3 and RESET\n";
    resp_client v3(port);
    record(v3, "v3", {"HELLO", "3", "AUTH", "farm", "farm-secret", "SETNAME", "three"});
    record(v3, "v3", {"GET", "sccache/none"});
    record(v3, "v3", {"GET", "sccache/bin"});
    record(v3, "v3", {"EXISTS", "sccache/bin"});
    record(v3, "v3", {"CLIENT", "GETNAME"});
    record(v3, "v3", {"PING"});
    record(v3, "v3", {"SELECT", "1"});
    record(v3, "v3", {"COMMAND", "COUNT"});
    record(v3, "v3", {"HELLO"});
    record(v3, "v3", {"HELLO", "2"});
    record(v3, "v3", {"GET", "sccache/none"});
    record(v3, "v3", {"RESET"});
    record(v3, "v3", {"GET", "sccache/none"});
    record(v3, "v3", {"HELLO", "2", "AUTH", "farm", "wrong"});
    record(v3, "v3", {"QUIT"});
    BOOST_CHECK(v3.wait_closed());

    kythira::testing::golden::check_golden("resp_replies.txt", out);
}

// ── format level and gate (redis-general-data-types task 2) ─────────────────

namespace {
/// Every local group's gate level from `KYTHIRA.FORMAT STATUS`.
auto gate_levels(resp_client& ops) -> std::vector<std::string> {
    const auto status = ops.call({"KYTHIRA.FORMAT", "STATUS"});
    std::vector<std::string> out;
    for (std::size_t at = status.find("group:"); at != std::string::npos;
         at = status.find("group:", at + 1)) {
        const auto eq = status.find(":gate=", at);
        const auto end = status.find("\r\n", eq);
        out.push_back(status.substr(eq + 6, end - eq - 6));
    }
    return out;
}
}  // namespace

// Requirement 14.3: one node still on an older binary (it reports level 2)
// blocks the gate, and the refusal names it; nothing is gated.
BOOST_AUTO_TEST_CASE(one_old_level_node_blocks_the_format_gate, *boost::unit_test::timeout(120)) {
    cluster c({}, true, {}, [](node_id_t id, redis_gateway_config& cfg) {
        if (id == 3) {
            cfg._reported_format_level = k_redis_base_format_level;
        }
    });
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client ops(c.port(1));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    const auto refused = ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"});
    BOOST_TEST_INFO(refused);
    BOOST_CHECK(refused.rfind("-ERR KYTHIRA.FORMAT cannot reach level 3", 0) == 0);
    BOOST_CHECK(refused.find("3 (level 2)") != std::string::npos);
    BOOST_CHECK_EQUAL(ops.call({"KYTHIRA.FORMAT", "LEVEL"}),
                      ":" + std::to_string(gateway_type::k_node_format_level) + "\r\n");
    for (node_id_t id = 1; id <= 3; ++id) {
        resp_client each(c.port(id));
        BOOST_REQUIRE_EQUAL(each.auth("ops", "ops-secret"), "+OK\r\n");
        for (const auto& level : gate_levels(each)) {
            BOOST_CHECK_EQUAL(level, "2");
        }
    }
    resp_client old(c.port(3));
    BOOST_REQUIRE_EQUAL(old.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_CHECK(old.call({"INFO"}).find("\r\nkythira_format_level:2\r\n") != std::string::npos);
}

// With every node at the binary's level, UPGRADE gates every group on every
// replica, from whichever node it is sent to (it proposes through each
// group's leader); repeating it changes nothing. A store that does not read
// the newer formats yet reports level 2 and is always refused.
BOOST_AUTO_TEST_CASE(the_format_gate_reaches_every_group, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto follower = c.a_follower_of(k_sccache_group);
    resp_client ops(c.port(follower));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    if constexpr (gateway_type::k_node_format_level < k_redis_typed_values_level) {
        BOOST_CHECK(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}).find("(level 2)") !=
                    std::string::npos);
        return;
    }
    BOOST_CHECK_EQUAL(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    for (node_id_t id = 1; id <= 3; ++id) {
        resp_client each(c.port(id));
        BOOST_REQUIRE_EQUAL(each.auth("ops", "ops-secret"), "+OK\r\n");
        std::vector<std::string> levels;
        for (int i = 0; i < 100; ++i) {
            levels = gate_levels(each);
            if (!levels.empty() &&
                std::ranges::all_of(levels, [](const auto& l) { return l == "3"; })) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        BOOST_CHECK_EQUAL(levels.size(), 2U);
        for (const auto& level : levels) {
            BOOST_CHECK_EQUAL(level, "3");
        }
    }
    BOOST_CHECK_EQUAL(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    // Plain commands keep working after the gate.
    resp_client farm(c.port(follower));
    BOOST_REQUIRE_EQUAL(farm.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(farm.call({"SET", "sccache/after-gate", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(farm.call({"GET", "sccache/after-gate"}), bulk("v"));
}

// KYTHIRA.FORMAT is an admin command; the gate hop is for peers only, and
// levels outside what the binary knows are refused.
BOOST_AUTO_TEST_CASE(kythira_format_is_admin_only, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client farm(c.port(1));
    BOOST_REQUIRE_EQUAL(farm.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(farm.call({"KYTHIRA.FORMAT", "STATUS"}).rfind("-NOPERM", 0) == 0);
    BOOST_CHECK(farm.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}).rfind("-NOPERM", 0) == 0);
    resp_client ops(c.port(1));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_CHECK(ops.call({"KYTHIRA.FORMAT", "GATE", "3", "a"}).rfind("-NOPERM", 0) == 0);
    BOOST_CHECK(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "4"}).rfind("-ERR", 0) == 0);
    BOOST_CHECK(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "2"}).rfind("-ERR", 0) == 0);
    BOOST_CHECK(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "x"}).rfind("-ERR", 0) == 0);
    BOOST_CHECK(ops.call({"KYTHIRA.FORMAT"}).rfind("-ERR wrong number", 0) == 0);
    const auto status = ops.call({"KYTHIRA.FORMAT", "STATUS"});
    BOOST_CHECK(status.find("binary_level:" + std::to_string(k_redis_format_level)) !=
                std::string::npos);
}

// ── tier 1 strings (redis-general-data-types task 3) ────────────────────────

namespace {
/// A cluster with mutable values and the format gate passed.
auto typed_cluster(redis_gateway_config cfg = {}) -> std::unique_ptr<cluster> {
    cfg._immutable_values = false;
    auto c = std::make_unique<cluster>(cfg);
    BOOST_REQUIRE(c->await_all_leaders(std::chrono::seconds{20}));
    resp_client ops(c->port(1));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    return c;
}
}  // namespace

// Before the gate the new commands answer the gate error; plain SET, GET
// and DEL keep working (Requirement 14.3).
BOOST_AUTO_TEST_CASE(string_commands_wait_for_the_format_gate, *boost::unit_test::timeout(120)) {
    if constexpr (gateway_type::k_node_format_level < k_redis_typed_values_level) {
        return;
    }
    redis_gateway_config cfg;
    cfg._immutable_values = false;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client farm(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(farm.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(farm.call({"INCR", "sccache/n"}),
                      "-ERR this cluster has not enabled typed values yet (KYTHIRA.FORMAT)\r\n");
    BOOST_CHECK_EQUAL(farm.call({"SET", "sccache/k", "v"}), "+OK\r\n");
    resp_client ops(c.port(1));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(farm.call({"INCR", "sccache/n"}), ":1\r\n");
}

// Replies match Redis 7.2 byte for byte, sent to a follower so each write
// is forwarded to its leader and decided in apply().
BOOST_AUTO_TEST_CASE(tier_one_string_commands, *boost::unit_test::timeout(120)) {
    if constexpr (gateway_type::k_node_format_level < k_redis_typed_values_level) {
        return;
    }
    auto c = typed_cluster();
    resp_client r(c->port(c->a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(r.auth("farm", "farm-secret"), "+OK\r\n");
    const auto call = [&](const std::vector<std::string>& argv) { return r.call(argv); };

    // INCR family
    BOOST_CHECK_EQUAL(call({"INCR", "sccache/n"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"INCRBY", "sccache/n", "41"}), ":42\r\n");
    BOOST_CHECK_EQUAL(call({"DECR", "sccache/n"}), ":41\r\n");
    BOOST_CHECK_EQUAL(call({"DECRBY", "sccache/n", "-9"}), ":50\r\n");
    BOOST_CHECK_EQUAL(call({"GET", "sccache/n"}), bulk("50"));
    BOOST_CHECK_EQUAL(call({"INCRBY", "sccache/n", "x"}),
                      "-ERR value is not an integer or out of range\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/big", "9223372036854775807"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"INCR", "sccache/big"}),
                      "-ERR increment or decrement would overflow\r\n");
    BOOST_CHECK_EQUAL(call({"DECRBY", "sccache/n", "-9223372036854775808"}),
                      "-ERR decrement would overflow\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/s", "abc"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"INCR", "sccache/s"}),
                      "-ERR value is not an integer or out of range\r\n");

    // INCRBYFLOAT in binary128 (D1)
    BOOST_CHECK_EQUAL(call({"INCRBYFLOAT", "sccache/f", "10.5"}), bulk("10.5"));
    BOOST_CHECK_EQUAL(call({"INCRBYFLOAT", "sccache/f", "0.1"}), bulk("10.6"));
    BOOST_CHECK_EQUAL(call({"INCRBYFLOAT", "sccache/f", "-5.0e3"}), bulk("-4989.4"));
    BOOST_CHECK_EQUAL(call({"INCRBYFLOAT", "sccache/f", "x"}),
                      "-ERR value is not a valid float\r\n");
    BOOST_CHECK_EQUAL(call({"INCRBYFLOAT", "sccache/f", "inf"}),
                      "-ERR increment would produce NaN or Infinity\r\n");
    BOOST_CHECK_EQUAL(call({"INCRBYFLOAT", "sccache/s", "1"}),
                      "-ERR value is not a valid float\r\n");

    // SET options
    BOOST_CHECK_EQUAL(call({"SET", "sccache/s", "x", "NX"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/s", "x", "XX", "GET"}), bulk("abc"));
    BOOST_CHECK_EQUAL(call({"SET", "sccache/new", "y", "XX"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/new", "y", "nx", "px", "60000"}), "+OK\r\n");
    const auto pttl = call({"TTL", "sccache/new"});
    BOOST_CHECK(pttl == ":60\r\n" || pttl == ":59\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/new", "z", "KEEPTTL"}), "+OK\r\n");
    const auto kept = call({"TTL", "sccache/new"});
    BOOST_CHECK(kept == ":60\r\n" || kept == ":59\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/new", "z", "NX", "XX"}), "-ERR syntax error\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/new", "z", "EX", "0"}),
                      "-ERR invalid expire time in 'set' command\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/new", "z", "EX", "10", "KEEPTTL"}),
                      "-ERR syntax error\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/gone", "z", "PXAT", "1"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"GET", "sccache/gone"}), "$-1\r\n");

    // SETNX, GETSET, PSETEX, GETDEL, GETEX
    BOOST_CHECK_EQUAL(call({"SETNX", "sccache/nx", "1"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"SETNX", "sccache/nx", "2"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"GETSET", "sccache/nx", "3"}), bulk("1"));
    BOOST_CHECK_EQUAL(call({"GETSET", "sccache/fresh", "3"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(call({"PSETEX", "sccache/ps", "100000", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"PSETEX", "sccache/ps", "0", "v"}),
                      "-ERR invalid expire time in 'psetex' command\r\n");
    BOOST_CHECK_EQUAL(call({"GETEX", "sccache/ps", "PERSIST"}), bulk("v"));
    BOOST_CHECK_EQUAL(call({"TTL", "sccache/ps"}), ":-1\r\n");
    BOOST_CHECK_EQUAL(call({"GETEX", "sccache/ps", "EX", "100"}), bulk("v"));
    BOOST_CHECK_EQUAL(call({"TTL", "sccache/ps"}), ":100\r\n");
    BOOST_CHECK_EQUAL(call({"GETEX", "sccache/ps", "BOGUS"}), "-ERR syntax error\r\n");
    BOOST_CHECK_EQUAL(call({"GETDEL", "sccache/ps"}), bulk("v"));
    BOOST_CHECK_EQUAL(call({"GETDEL", "sccache/ps"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(call({"GETEX", "sccache/ps"}), "$-1\r\n");

    // APPEND, SETRANGE, GETRANGE (G2)
    BOOST_CHECK_EQUAL(call({"APPEND", "sccache/a", "Hello"}), ":5\r\n");
    BOOST_CHECK_EQUAL(call({"APPEND", "sccache/a", " World"}), ":11\r\n");
    BOOST_CHECK_EQUAL(call({"SETRANGE", "sccache/a", "6", "Redis"}), ":11\r\n");
    BOOST_CHECK_EQUAL(call({"GET", "sccache/a"}), bulk("Hello Redis"));
    BOOST_CHECK_EQUAL(call({"SETRANGE", "sccache/pad", "3", "x"}), ":4\r\n");
    BOOST_CHECK_EQUAL(call({"GET", "sccache/pad"}), bulk(std::string("\0\0\0x", 4)));
    BOOST_CHECK_EQUAL(call({"SETRANGE", "sccache/pad", "-1", "x"}),
                      "-ERR offset is out of range\r\n");
    BOOST_CHECK_EQUAL(call({"SETRANGE", "sccache/none", "5", ""}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"GETRANGE", "sccache/a", "0", "-100"}), bulk("H"));
    BOOST_CHECK_EQUAL(call({"GETRANGE", "sccache/a", "-3", "-5"}), bulk(""));
    BOOST_CHECK_EQUAL(call({"GETRANGE", "sccache/a", "-5", "-1"}), bulk("Redis"));

    // TYPE, TOUCH, OBJECT ENCODING, UNLINK
    BOOST_CHECK_EQUAL(call({"TYPE", "sccache/a"}), "+string\r\n");
    BOOST_CHECK_EQUAL(call({"TYPE", "sccache/missing"}), "+none\r\n");
    BOOST_CHECK_EQUAL(call({"TOUCH", "sccache/a", "sccache/missing"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"OBJECT", "ENCODING", "sccache/n"}), bulk("int"));
    BOOST_CHECK_EQUAL(call({"OBJECT", "ENCODING", "sccache/a"}), bulk("embstr"));
    BOOST_CHECK_EQUAL(call({"OBJECT", "ENCODING", "sccache/missing"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(call({"UNLINK", "sccache/a"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"UNLINK", "sccache/a"}), ":0\r\n");

    // RESP3 renders the same replies with its own null.
    BOOST_REQUIRE(call({"HELLO", "3"}).starts_with('%'));
    BOOST_CHECK_EQUAL(call({"GETDEL", "sccache/a"}), "_\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/nx", "4", "GET"}), bulk("3"));
}

// The immutable-value rule (D11) holds for the new commands: creating a key
// works, changing a live value is refused and counted.
BOOST_AUTO_TEST_CASE(immutable_values_refuse_string_mutations, *boost::unit_test::timeout(120)) {
    if constexpr (gateway_type::k_node_format_level < k_redis_typed_values_level) {
        return;
    }
    cluster c;  // _immutable_values on, as by default
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client ops(c.port(1));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    resp_client r(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(r.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"INCR", "sccache/n"}), ":1\r\n");
    BOOST_CHECK_EQUAL(r.call({"INCR", "sccache/n"}), "-ERR value conflict for an existing key\r\n");
    BOOST_CHECK_EQUAL(r.call({"APPEND", "sccache/n", "x"}),
                      "-ERR value conflict for an existing key\r\n");
    BOOST_CHECK_EQUAL(r.call({"SET", "sccache/n", "1", "XX", "GET"}), bulk("1"));
    // Requirement 5.2: the deadline and the key itself are protected too.
    BOOST_CHECK_EQUAL(r.call({"EXPIRE", "sccache/n", "100"}),
                      "-ERR value conflict for an existing key\r\n");
    BOOST_CHECK_EQUAL(r.call({"GETDEL", "sccache/n"}),
                      "-ERR value conflict for an existing key\r\n");
    BOOST_CHECK_EQUAL(r.call({"DEL", "sccache/n"}), ":1\r\n");
    BOOST_CHECK_GE(c.gateway(c.leader_of(k_sccache_group)).stats()._value_conflicts.load(), 2U);

    // A user's mutable prefix may change, through exec records and plain SET.
    resp_client m(c.port(c.a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(m.auth("counter", "counter-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(m.call({"INCR", "sccache/counters/a"}), ":1\r\n");
    BOOST_CHECK_EQUAL(m.call({"INCR", "sccache/counters/a"}), ":2\r\n");
    BOOST_CHECK_EQUAL(m.call({"SET", "sccache/counters/a", "7"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(m.call({"EXPIRE", "sccache/counters/a", "100"}), ":1\r\n");
    BOOST_CHECK_EQUAL(m.call({"GETDEL", "sccache/counters/a"}), bulk("7"));
    BOOST_CHECK_EQUAL(m.call({"SET", "sccache/plain", "1"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(m.call({"SET", "sccache/plain", "2"}),
                      "-ERR value conflict for an existing key\r\n");
    // The same prefix is not mutable for a user without it.
    BOOST_CHECK_EQUAL(r.call({"SET", "sccache/counters/b", "1"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"INCR", "sccache/counters/b"}),
                      "-ERR value conflict for an existing key\r\n");
}

// Task 6: multi-key commands. Keys in one group make one record; this
// build has no transactions, so keys in two groups answer -CROSSSLOT and
// change nothing (Requirement 6.3). Sent to a follower: the record hops.
BOOST_AUTO_TEST_CASE(multi_key_commands, *boost::unit_test::timeout(120)) {
    if constexpr (gateway_type::k_node_format_level < k_redis_typed_values_level) {
        return;
    }
    auto c = typed_cluster();
    resp_client r(c->port(c->a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(r.auth("ops", "ops-secret"), "+OK\r\n");
    const auto call = [&](const std::vector<std::string>& argv) { return r.call(argv); };
    const std::string crossslot = "-CROSSSLOT Keys in request don't hash to the same slot\r\n";

    BOOST_CHECK_EQUAL(call({"MSETNX", "sccache/a", "1", "sccache/b", "2"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"MSETNX", "sccache/b", "x", "sccache/c", "3"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"EXISTS", "sccache/a", "sccache/b", "sccache/c", "a/x"}), ":2\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/t", "v", "PX", "100000"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"RENAME", "sccache/t", "sccache/u"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"GET", "sccache/u"}), bulk("v"));
    BOOST_CHECK(call({"PTTL", "sccache/u"}) != ":-1\r\n");
    BOOST_CHECK_EQUAL(call({"RENAME", "sccache/t", "sccache/u"}), "-ERR no such key\r\n");
    BOOST_CHECK_EQUAL(call({"RENAMENX", "sccache/u", "sccache/a"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"COPY", "sccache/u", "sccache/a"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"COPY", "sccache/u", "sccache/a", "DB", "0", "REPLACE"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"COPY", "sccache/u", "sccache/a", "DB", "1"}),
                      "-ERR DB index is out of range\r\n");
    BOOST_CHECK_EQUAL(call({"GET", "sccache/a"}), bulk("v"));
    BOOST_CHECK_EQUAL(call({"DEL", "sccache/a", "sccache/b", "sccache/zz"}), ":2\r\n");
    BOOST_CHECK_EQUAL(call({"UNLINK", "sccache/u", "sccache/a"}), ":1\r\n");

    // Across the "m" cut: refused, nothing changed.
    BOOST_CHECK_EQUAL(call({"SET", "a/x", "1"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"RENAME", "a/x", "sccache/x"}), crossslot);
    BOOST_CHECK_EQUAL(call({"MSETNX", "a/y", "1", "sccache/y", "2"}), crossslot);
    BOOST_CHECK_EQUAL(call({"DEL", "a/x", "sccache/c"}), crossslot);
    BOOST_CHECK_EQUAL(call({"GET", "a/x"}), bulk("1"));
    BOOST_CHECK_EQUAL(call({"EXISTS", "a/y", "sccache/y", "sccache/x"}), ":0\r\n");
    BOOST_CHECK(call({"MSETNX", "a", "1", "b"}).starts_with("-ERR wrong number of arguments"));
}

// Requirement 5.4: the rule is decided in apply(), so writers racing to
// create one key cannot both pass: exactly one INCR creates it and every
// other one finds it existing. In a mutable prefix every INCR counts.
BOOST_AUTO_TEST_CASE(racing_writers_under_the_immutable_rule, *boost::unit_test::timeout(180)) {
    if constexpr (gateway_type::k_node_format_level < k_redis_typed_values_level) {
        return;
    }
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    {
        resp_client ops(c.port(1));
        BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
        BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    }
    constexpr int k_writers = 8;
    const auto race = [&](const std::string& user, const std::string& secret,
                          const std::string& key) {
        // Log in first, one at a time (the AUTH limiter counts concurrent
        // attempts per address), spread over every node: followers forward.
        std::vector<std::unique_ptr<resp_client>> clients;
        for (int i = 0; i < k_writers; ++i) {
            clients.push_back(
                std::make_unique<resp_client>(c.port(static_cast<node_id_t>(1 + (i % 3)))));
            BOOST_REQUIRE_EQUAL(clients.back()->auth(user, secret), "+OK\r\n");
        }
        std::vector<std::string> replies(k_writers);
        std::vector<std::thread> threads;
        std::atomic<int> ready{0};
        for (int i = 0; i < k_writers; ++i) {
            threads.emplace_back([&, i] {
                ready.fetch_add(1);
                while (ready.load() < k_writers) {
                    std::this_thread::yield();
                }
                // A forward the leader could not take is refused before
                // anything is proposed, and says to retry.
                auto& reply = replies[static_cast<std::size_t>(i)];
                for (int attempt = 0; attempt < 50; ++attempt) {
                    reply = clients[static_cast<std::size_t>(i)]->call({"INCR", key});
                    if (reply != "-ERR shard has no reachable leader, retry\r\n") {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{20});
                }
            });
        }
        for (auto& t : threads) {
            t.join();
        }
        return replies;
    };
    const auto fixed = race("farm", "farm-secret", "sccache/race");
    BOOST_CHECK_EQUAL(std::ranges::count(fixed, std::string(":1\r\n")), 1);
    BOOST_CHECK_EQUAL(
        std::ranges::count(fixed, std::string("-ERR value conflict for an existing key\r\n")),
        k_writers - 1);
    auto counted = race("counter", "counter-secret", "sccache/counters/race");
    std::ranges::sort(counted);
    std::vector<std::string> expected;
    for (int i = 1; i <= k_writers; ++i) {
        expected.push_back(":" + std::to_string(i) + "\r\n");
    }
    std::ranges::sort(expected);
    std::string got;
    for (const auto& r : counted) {
        got += r;
    }
    BOOST_CHECK_MESSAGE(counted == expected, "replies: " << got);
}

// Task 4: the expiry family through the front end, from a follower so the
// writes forward and the reads may answer locally or forward.
BOOST_AUTO_TEST_CASE(expiry_family, *boost::unit_test::timeout(120)) {
    if constexpr (gateway_type::k_node_format_level < k_redis_typed_values_level) {
        return;
    }
    auto c = typed_cluster();
    resp_client r(c->port(c->a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(r.auth("farm", "farm-secret"), "+OK\r\n");
    const auto call = [&](const std::vector<std::string>& argv) { return r.call(argv); };
    const auto integer = [](const std::string& reply) {
        BOOST_REQUIRE(reply.starts_with(':'));
        return std::stoll(reply.substr(1));
    };

    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "100"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"PTTL", "sccache/x"}), ":-2\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/x", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"PTTL", "sccache/x"}), ":-1\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRETIME", "sccache/x"}), ":-1\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "100", "XX"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "100", "nx"}), ":1\r\n");
    const auto pttl = integer(call({"PTTL", "sccache/x"}));
    BOOST_CHECK(pttl > 90'000 && pttl <= 100'000);
    BOOST_CHECK_EQUAL(call({"PEXPIRE", "sccache/x", "50000", "GT"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"PEXPIRE", "sccache/x", "50000", "LT"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIREAT", "sccache/x", "4102444800"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRETIME", "sccache/x"}), ":4102444800\r\n");
    BOOST_CHECK_EQUAL(call({"PEXPIREAT", "sccache/x", "4102444800123"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"PEXPIRETIME", "sccache/x"}), ":4102444800123\r\n");
    BOOST_CHECK_EQUAL(call({"PERSIST", "sccache/x"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"PERSIST", "sccache/x"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"TTL", "sccache/x"}), ":-1\r\n");

    // A deadline already past deletes the key and answers 1.
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "-1"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"EXISTS", "sccache/x"}), ":0\r\n");
    BOOST_CHECK_EQUAL(call({"SET", "sccache/x", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(call({"PEXPIREAT", "sccache/x", "1"}), ":1\r\n");
    BOOST_CHECK_EQUAL(call({"GET", "sccache/x"}), "$-1\r\n");

    // Refusals the front end answers without a proposal.
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "10", "NX", "GT"}),
                      "-ERR NX and XX, GT or LT options at the same time are not compatible\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "10", "GT", "LT"}),
                      "-ERR GT and LT options at the same time are not compatible\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "10", "SOON"}),
                      "-ERR Unsupported option SOON\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "ten"}),
                      "-ERR value is not an integer or out of range\r\n");
    BOOST_CHECK_EQUAL(call({"EXPIRE", "sccache/x", "9223372036854775807"}),
                      "-ERR invalid expire time in 'expire' command\r\n");
    BOOST_CHECK_EQUAL(call({"PEXPIRE", "sccache/x", "9223372036854775807"}),
                      "-ERR invalid expire time in 'pexpire' command\r\n");
    BOOST_CHECK(call({"PERSIST"}).starts_with("-ERR wrong number of arguments"));
    BOOST_CHECK(call({"PTTL", "a", "b"}).starts_with("-ERR wrong number of arguments"));

    // The read-only role may read deadlines but not change them.
    resp_client ro(c->port(c->a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(ro.auth("reader", "reader-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(ro.call({"PTTL", "sccache/x"}), ":-2\r\n");
    BOOST_CHECK(ro.call({"PERSIST", "sccache/x"}).starts_with("-NOPERM"));
}

BOOST_AUTO_TEST_CASE(only_peer_gateways_may_advise, *boost::unit_test::timeout(120)) {
    auto log = std::make_shared<hook_log>();
    cluster c({}, true, hooks_into(log));
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(client.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ADVISE", "node-9;0,0,0"}).rfind("-NOPERM", 0), 0U);
    BOOST_CHECK(log->payloads().empty());
}

// ── the authentication seam (redis-gateway-module task 6) ───────────────────

/// A credential verifier the test drives by the credential it is handed:
/// "good" is accepted for an hour, "short" for 1.5 s, "stale" with an expiry
/// already past, "slow" only when the test calls `release_slow()`, "never"
/// not at all, and anything else is denied.
struct test_verifier {
    using result_promise = kythira::promise_default<kythira::credential_result>;

    std::mutex _mu;
    std::vector<std::unique_ptr<result_promise>> _pending;
    std::unique_ptr<result_promise> _slow;
    std::vector<std::string> _users_asked;

    auto verify(const kythira::credential_request& r)
        -> kythira::future_default<kythira::credential_result> {
        using clock = std::chrono::system_clock;
        const std::lock_guard lock(_mu);
        _users_asked.emplace_back(r.user);
        auto p = std::make_unique<result_promise>();
        auto f = p->getFuture();
        const std::string cred(r.credential);
        if (cred == "good") {
            p->setValue(kythira::credential_accepted{"principal-good",
                                                     clock::now() + std::chrono::hours{1}});
        } else if (cred == "short") {
            p->setValue(kythira::credential_accepted{
                "principal-short", clock::now() + std::chrono::milliseconds{1500}});
        } else if (cred == "stale") {
            p->setValue(kythira::credential_accepted{"principal-stale",
                                                     clock::now() - std::chrono::seconds{1}});
        } else if (cred == "slow") {
            _slow = std::move(p);
            return f;
        } else if (cred == "never") {
            _pending.push_back(std::move(p));
            return f;
        } else {
            p->setValue(kythira::credential_denied{"test verifier: unknown credential"});
        }
        return f;
    }

    auto slow_asked() -> bool {
        const std::lock_guard lock(_mu);
        return _slow != nullptr;
    }

    auto release_slow() -> bool {
        const std::lock_guard lock(_mu);
        if (!_slow) {
            return false;
        }
        _slow->setValue(kythira::credential_accepted{
            "principal-slow", std::chrono::system_clock::now() + std::chrono::hours{1}});
        _slow.reset();
        return true;
    }

    auto users_asked() -> std::vector<std::string> {
        const std::lock_guard lock(_mu);
        return _users_asked;
    }
};
static_assert(kythira::credential_verifier<test_verifier>);

BOOST_AUTO_TEST_CASE(a_credential_verifier_vouches_only_for_selected_users,
                     *boost::unit_test::timeout(120)) {
    test_verifier verifier;
    redis_gateway_config cfg;
    cfg._credential_verifier = kythira::erase_credential_verifier(verifier);
    // What IAM task 21's `auth=` attribute will decide; "reader" stays on
    // its password.
    cfg._credential_verifier_users = [](std::string_view user) {
        return user == "farm" || user == "kythira-internal" || user == "ghost";
    };
    // Short enough that "never" times out inside the test.
    cfg._command_timeout = std::chrono::milliseconds{3000};
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto port = c.port(c.leader_of(k_sccache_group));
    auto& gw = c.gateway(c.leader_of(k_sccache_group));
    const std::string wrongpass =
        "-WRONGPASS invalid username-password pair or user is disabled.\r\n";

    // A selected user is the verifier's to vouch for, and only the
    // verifier's: its ACL password no longer works.
    {
        resp_client farm(port);
        BOOST_CHECK_EQUAL(farm.auth("farm", "farm-secret"), wrongpass);
        BOOST_CHECK_EQUAL(farm.auth("farm", "nope"), wrongpass);
        BOOST_CHECK_EQUAL(farm.auth("farm", "stale"), wrongpass);
        BOOST_CHECK_EQUAL(farm.auth("farm", "good"), "+OK\r\n");
        // Once in, the ACL user's role and key prefixes apply.
        BOOST_CHECK_EQUAL(farm.call({"SET", "sccache/seam", "v"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(farm.call({"SET", "other/seam", "v"}),
                          "-NOPERM No permissions to access a key\r\n");
        BOOST_CHECK_EQUAL(farm.call({"INFO"}),
                          "-NOPERM User farm has no permissions to run the 'INFO' command\r\n");
    }
    // HELLO ... AUTH takes the same path.
    {
        resp_client farm(port);
        auto hello = farm.call({"HELLO", "3", "AUTH", "farm", "good"});
        BOOST_CHECK_EQUAL(hello.rfind("%8\r\n", 0), 0U);
        BOOST_CHECK_EQUAL(farm.call({"GET", "sccache/seam"}), bulk("v"));
    }
    // The internal user is never vouched for from outside, and a user the
    // ACL does not have is refused before the verifier is asked.
    {
        resp_client other(port);
        const auto asked_before = verifier.users_asked().size();
        BOOST_CHECK_EQUAL(other.auth("kythira-internal", "good"), wrongpass);
        BOOST_CHECK_EQUAL(other.auth("ghost", "good"), wrongpass);
        BOOST_CHECK_EQUAL(verifier.users_asked().size(), asked_before);
    }
    // A user the predicate does not select authenticates as before.
    {
        resp_client reader(port);
        BOOST_CHECK_EQUAL(reader.auth("reader", "good"), wrongpass);
        BOOST_CHECK_EQUAL(reader.auth("reader", "reader-secret"), "+OK\r\n");
    }
    for (const auto& u : verifier.users_asked()) {
        BOOST_CHECK_EQUAL(u, "farm");
    }

    // A verifier that is slow to answer holds its own connection and no
    // other: while one AUTH waits, another client authenticates and is
    // served.
    {
        resp_client slow(port);
        slow.send_raw(resp_client::encode({"AUTH", "farm", "slow"}));
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        while (!verifier.slow_asked()) {
            BOOST_REQUIRE(std::chrono::steady_clock::now() < deadline);
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        resp_client reader(port);
        BOOST_CHECK_EQUAL(reader.auth("reader", "reader-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(reader.call({"GET", "sccache/seam"}), bulk("v"));
        BOOST_REQUIRE(verifier.release_slow());
        BOOST_CHECK_EQUAL(slow.read_reply(), "+OK\r\n");
        BOOST_CHECK_EQUAL(slow.call({"GET", "sccache/seam"}), bulk("v"));
    }
    // One that never answers costs the command timeout and a retryable
    // error, not the connection.
    {
        resp_client never(port);
        BOOST_CHECK_EQUAL(never.auth("farm", "never"),
                          "-ERR authentication timed out, retry later\r\n");
        BOOST_CHECK_EQUAL(never.auth("farm", "good"), "+OK\r\n");
    }
    // The credential's expiry closes the connection, even a busy one.
    {
        resp_client brief(port);
        const auto expired_before = gw.stats()._credential_expiries.load();
        BOOST_CHECK_EQUAL(brief.auth("farm", "short"), "+OK\r\n");
        BOOST_CHECK_EQUAL(brief.call({"GET", "sccache/seam"}), bulk("v"));
        auto start = std::chrono::steady_clock::now();
        BOOST_CHECK(brief.wait_closed());
        auto waited = std::chrono::steady_clock::now() - start;
        BOOST_CHECK_LT(waited, std::chrono::seconds{10});
        BOOST_CHECK_GT(gw.stats()._credential_expiries.load(), expired_before);
    }
    // A password AUTH clears a verifier's deadline: the connection outlives it.
    {
        resp_client back(port);
        BOOST_CHECK_EQUAL(back.auth("farm", "short"), "+OK\r\n");
        BOOST_CHECK_EQUAL(back.auth("reader", "reader-secret"), "+OK\r\n");
        std::this_thread::sleep_for(std::chrono::milliseconds{2500});
        BOOST_CHECK_EQUAL(back.call({"GET", "sccache/seam"}), bulk("v"));
    }
}

// IAM task 21: the composition root selects the verifier's users from the
// ACL's `auth=` attribute. An `auth=iam` user logs in only through the
// verifier; an `auth=both` user through the verifier or, when the verifier
// refuses, its password.
BOOST_AUTO_TEST_CASE(auth_attribute_selects_the_verifier_and_both_falls_back_to_the_password,
                     *boost::unit_test::timeout(120)) {
    test_verifier verifier;
    redis_gateway_config cfg;
    cfg._credential_verifier = kythira::erase_credential_verifier(verifier);
    auto modes = std::make_shared<redis_acl>();
    modes->reload(acl_text());
    cfg._credential_verifier_users = [modes](std::string_view user) {
        const auto mode = modes->auth_mode_of(user);
        return mode == kythira::redis_auth_mode::iam || mode == kythira::redis_auth_mode::both;
    };
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto port = c.port(c.leader_of(k_sccache_group));
    const std::string wrongpass =
        "-WRONGPASS invalid username-password pair or user is disabled.\r\n";
    {
        resp_client iam(port);
        BOOST_CHECK_EQUAL(iam.auth("iamfarm", "nope"), wrongpass);
        BOOST_CHECK_EQUAL(iam.auth("iamfarm", "good"), "+OK\r\n");
        BOOST_CHECK_EQUAL(iam.call({"SET", "sccache/iam", "v"}), "+OK\r\n");
    }
    {
        resp_client both(port);
        BOOST_CHECK_EQUAL(both.auth("bothfarm", "good"), "+OK\r\n");
        BOOST_CHECK_EQUAL(both.auth("bothfarm", "both-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(both.call({"GET", "sccache/iam"}), bulk("v"));
        BOOST_CHECK_EQUAL(both.auth("bothfarm", "wrong"), wrongpass);
    }
    // A password user is not the verifier's.
    {
        resp_client farm(port);
        const auto asked_before = verifier.users_asked().size();
        BOOST_CHECK_EQUAL(farm.auth("farm", "farm-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(verifier.users_asked().size(), asked_before);
    }
}

// IAM task 22 (Requirements 13.5, 13.7, 3.8): a verifier's deadline is
// extended by re-AUTH on the open connection; refused tokens spend the
// source's failure budget like wrong passwords; and the forward links an
// IAM user's commands travel over still authenticate as the internal user
// with its secret, never through the verifier.
BOOST_AUTO_TEST_CASE(reauth_extends_a_verified_connection_and_denials_spend_the_budget,
                     *boost::unit_test::timeout(120)) {
    test_verifier verifier;
    redis_gateway_config cfg;
    cfg._credential_verifier = kythira::erase_credential_verifier(verifier);
    auto modes = std::make_shared<redis_acl>();
    modes->reload(acl_text());
    cfg._credential_verifier_users = [modes](std::string_view user) {
        const auto mode = modes->auth_mode_of(user);
        return mode == kythira::redis_auth_mode::iam || mode == kythira::redis_auth_mode::both;
    };
    cfg._auth_failure_limit = 3;
    cfg._auth_failure_window = std::chrono::seconds{3};
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));

    // Re-AUTH with a fresh credential moves the deadline: "short" lapses
    // in 1.5 s, but the connection that re-AUTHs with "good" outlives it.
    auto follower = c.a_follower_of(2);
    BOOST_REQUIRE_NE(follower, 0u);
    auto& gw = c.gateway(follower);
    {
        resp_client iam(c.port(follower));
        const auto expired_before = gw.stats()._credential_expiries.load();
        BOOST_REQUIRE_EQUAL(iam.auth("iamfarm", "short"), "+OK\r\n");
        BOOST_REQUIRE_EQUAL(iam.auth("iamfarm", "good"), "+OK\r\n");
        std::this_thread::sleep_for(std::chrono::milliseconds{2500});
        // A shard-2 key from a shard-2 follower: forwarded to the leader's
        // gateway over the internal link.
        const auto forwards_before = gw.stats()._forwards.load();
        BOOST_CHECK_EQUAL(iam.call({"SET", "sccache/zzz-iam", "v"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(iam.call({"GET", "sccache/zzz-iam"}), bulk("v"));
        BOOST_CHECK_GT(gw.stats()._forwards.load(), forwards_before);
        BOOST_CHECK_EQUAL(gw.stats()._forward_failures.load(), 0u);
        BOOST_CHECK_EQUAL(gw.stats()._credential_expiries.load(), expired_before);
        // The forward link never asked the verifier: only the IAM user did.
        for (const auto& u : verifier.users_asked()) {
            BOOST_CHECK_EQUAL(u, "iamfarm");
        }
    }
    // Without the re-AUTH the same credential closes the connection.
    {
        resp_client brief(c.port(follower));
        BOOST_REQUIRE_EQUAL(brief.auth("iamfarm", "short"), "+OK\r\n");
        BOOST_CHECK(brief.wait_closed());
    }

    // Three refused tokens from one address use up its budget: the fourth
    // AUTH is refused before the verifier is asked, even with a good token
    // and on a fresh connection.
    const auto leader_port = c.port(c.leader_of(k_sccache_group));
    const std::string wrongpass =
        "-WRONGPASS invalid username-password pair or user is disabled.\r\n";
    {
        resp_client guess(leader_port);
        BOOST_CHECK_EQUAL(guess.auth("iamfarm", "forged-1"), wrongpass);
        BOOST_CHECK_EQUAL(guess.auth("iamfarm", "forged-2"), wrongpass);
        BOOST_CHECK_EQUAL(guess.auth("bothfarm", "forged-3"), wrongpass);
        const auto asked_before = verifier.users_asked().size();
        resp_client again(leader_port);
        auto limited = again.auth("iamfarm", "good");
        BOOST_CHECK(limited.rfind("-ERR too many authentication failures", 0) == 0);
        BOOST_CHECK_EQUAL(verifier.users_asked().size(), asked_before);
    }
    std::this_thread::sleep_for(cfg._auth_failure_window + std::chrono::milliseconds{500});
    {
        resp_client later(leader_port);
        BOOST_CHECK_EQUAL(later.auth("iamfarm", "good"), "+OK\r\n");
    }
}

BOOST_AUTO_TEST_SUITE_END()

// The co-located latency and throughput measurement of
// .kiro/specs/redis-general-data-types/ Requirement 24.4: the layer work must
// not slow a node that runs every layer. Disabled, as it asserts nothing and
// takes about a minute; run it by name on the build before and after a
// change, alternating, and compare (doc/redis-layers.md has the baseline):
//   redis_gateway_integration_test --run_test=colocated_measurement
// Per round and per entry node (the shard's leader, then a follower, which
// forwards): sequential 1 KiB SET and GET latency over 2000 keys, then the
// ops/s of 8 clients doing 25% SET for 3 s.
namespace {
auto pct(std::vector<double> v, double p) -> double {
    std::sort(v.begin(), v.end());
    return v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))];
}
}  // namespace
BOOST_AUTO_TEST_CASE(colocated_measurement,
                     *boost::unit_test::disabled() * boost::unit_test::timeout(600)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader = c.leader_of(k_sccache_group);
    const auto follower = c.a_follower_of(k_sccache_group);
    for (int round = 0; round < 3; ++round) {
        for (auto [id, where] : {std::pair{leader, "leader"}, std::pair{follower, "follower"}}) {
            const std::string value(1024, 'v');
            {
                resp_client k(c.port(id));
                BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
                std::vector<double> set_us, get_us;
                for (int i = 0; i < 2000; ++i) {
                    const auto key =
                        "sccache/m" + std::to_string(round) + where + std::to_string(i);
                    auto t0 = std::chrono::steady_clock::now();
                    BOOST_REQUIRE_EQUAL(k.call({"SET", key, value}), "+OK\r\n");
                    auto t1 = std::chrono::steady_clock::now();
                    (void)k.call({"GET", key});
                    auto t2 = std::chrono::steady_clock::now();
                    set_us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
                    get_us.push_back(std::chrono::duration<double, std::micro>(t2 - t1).count());
                }
                std::printf(
                    "MEASURE round=%d via=%s SET p50=%.0fus p99=%.0fus GET p50=%.0fus p99=%.0fus\n",
                    round, where, pct(set_us, .5), pct(set_us, .99), pct(get_us, .5),
                    pct(get_us, .99));
            }
            std::atomic<bool> stop{false};
            std::atomic<std::uint64_t> ops{0};
            std::vector<std::thread> ts;
            for (int t = 0; t < 8; ++t) {
                ts.emplace_back([&, t] {
                    resp_client k(c.port(id));
                    (void)k.auth("farm", "farm-secret");
                    std::uint64_t n = 0;
                    while (!stop.load()) {
                        const auto key =
                            "sccache/t" + std::to_string(t) + "/" + std::to_string(n % 512);
                        if (n % 4 == 0) {
                            (void)k.call({"SET", key, value});
                        } else {
                            (void)k.call({"GET", key});
                        }
                        ++n;
                    }
                    ops += n;
                });
            }
            std::this_thread::sleep_for(std::chrono::seconds{3});
            stop = true;
            for (auto& t : ts) {
                t.join();
            }
            std::printf("MEASURE round=%d via=%s 8 clients 25%% SET: %.0f ops/s\n", round, where,
                        static_cast<double>(ops.load()) / 3.0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The data-layer API (.kiro/specs/redis-general-data-types/ task 16): a
// node's routes and proposals over `KYTHIRA.DATA`, as a front end with no
// replica of the key's group reaches them.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

auto set_entry(const std::string& key, const std::string& value) -> std::vector<std::byte> {
    kythira::redis_kv_set_command set;
    set._key = key;
    set._value.resize(value.size());
    std::memcpy(set._value.data(), value.data(), value.size());
    return kythira::encode_redis_kv_command(set);
}

auto propose_answer(const std::optional<std::string>& reply)
    -> std::optional<kythira::redis_data_wire::propose_outcome<group_id_type, node_id_t>> {
    if (!reply) {
        return std::nullopt;
    }
    auto answer = kythira::parse_redis_peer_answer(*reply);
    if (answer._kind != kythira::redis_peer_answer::kind::bulk) {
        return std::nullopt;
    }
    return kythira::redis_data_wire::decode_propose<group_id_type, node_id_t>(answer._text);
}

}  // namespace

BOOST_AUTO_TEST_CASE(remote_data_access_routes_and_proposes_over_kythira_data,
                     *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader = c.leader_of(k_sccache_group);
    const auto follower = c.a_follower_of(k_sccache_group);
    BOOST_REQUIRE(leader != 0 && follower != 0);
    auto address = [&](node_id_t id) { return "127.0.0.1:" + std::to_string(c.port(id)); };
    // The forward link of the follower's gateway stands in for a front end
    // with no data: every call below crosses it to a data node.
    auto& link = c.gateway(follower);
    kythira::redis_remote_data_access<group_id_type, node_id_t> remote(
        {address(follower)}, [&link](const std::string& to, const std::vector<std::string>& argv) {
            return link.data_call(to, argv);
        });

    // Routes come from the seed, with the leader its replica knows and an
    // address for every voter.
    const std::string key = "sccache/remote";
    auto route = remote.route(key);
    BOOST_REQUIRE(route.has_value());
    BOOST_CHECK_EQUAL(route->_group_id, k_sccache_group);
    BOOST_CHECK(route->_leader_hint == std::optional<node_id_t>{leader});
    for (node_id_t id = 1; id <= k_node_count; ++id) {
        BOOST_CHECK(remote.cache().address_of(id) == std::optional<std::string>{address(id)});
    }

    // A proposal reaches the leader and applies; a client reads it back.
    (void)remote.propose(key, set_entry(key, "v1"), std::chrono::seconds{3});
    resp_client client(c.port(leader));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", key}), "$2\r\nv1\r\n");

    // A wrong leader hint costs one refusal that names the real leader.
    remote.cache().on_not_leader(k_sccache_group, follower);
    (void)remote.propose(key, set_entry(key, "v2"), std::chrono::seconds{3});
    BOOST_CHECK_EQUAL(client.call({"GET", key}), "$2\r\nv2\r\n");
    BOOST_CHECK_GE(remote.cache().stats().not_leader, 2u);
    BOOST_CHECK(remote.leader_of(key) == std::optional<node_id_t>{leader});

    // The refusals themselves, straight off the wire. A follower answers
    // with the leader and never forwards (Requirement 18.3).
    const auto entry = set_entry(key, "v3");
    const std::string entry_text(reinterpret_cast<const char*>(entry.data()), entry.size());
    auto propose_to = [&](node_id_t at, group_id_type group, std::uint64_t version) {
        return propose_answer(link.data_call(
            address(at), {"KYTHIRA.DATA", "PROPOSE", std::to_string(group), std::to_string(version),
                          std::to_string(route->_epoch._conf_version), entry_text}));
    };
    using kythira::redis_data_wire::propose_status;
    auto refused = propose_to(follower, k_sccache_group, route->_epoch._version);
    BOOST_REQUIRE(refused.has_value());
    BOOST_CHECK(refused->status == propose_status::not_leader);
    BOOST_CHECK(refused->leader == std::optional<node_id_t>{leader});
    BOOST_CHECK_EQUAL(client.call({"GET", key}), "$2\r\nv2\r\n");

    // An epoch the group is not at gets the current route back.
    auto stale = propose_to(leader, k_sccache_group, route->_epoch._version + 5);
    BOOST_REQUIRE(stale.has_value());
    BOOST_CHECK(stale->status == propose_status::stale_route);
    BOOST_REQUIRE_EQUAL(stale->routes.routes.size(), 1u);
    BOOST_CHECK(stale->routes.routes[0]._epoch == route->_epoch);
    BOOST_CHECK(!stale->routes.addresses.empty());

    // A group nobody has.
    auto unknown = propose_to(leader, 99, 0);
    BOOST_REQUIRE(unknown.has_value());
    BOOST_CHECK(unknown->status == propose_status::unknown_group);

    // The entry's key is outside the named group: the route that owns it.
    auto elsewhere = propose_to(leader, 1, 0);
    BOOST_REQUIRE(elsewhere.has_value());
    BOOST_CHECK(elsewhere->status == propose_status::stale_route ||
                elsewhere->status == propose_status::not_leader);

    // ROUTE for one key, and malformed calls.
    auto one = kythira::parse_redis_peer_answer(
        *link.data_call(address(leader), {"KYTHIRA.DATA", "ROUTE", "a"}));
    BOOST_REQUIRE(one._kind == kythira::redis_peer_answer::kind::bulk);
    auto rows = kythira::redis_data_wire::decode_routes<group_id_type, node_id_t>(one._text);
    BOOST_REQUIRE(rows.has_value());
    BOOST_REQUIRE_EQUAL(rows->routes.size(), 1u);
    BOOST_CHECK_EQUAL(rows->routes[0]._group_id, 1u);
    BOOST_CHECK(link.data_call(address(leader), {"KYTHIRA.DATA", "ROUTES", "\xff"})
                    ->rfind("-ERR malformed range", 0) == 0);
    BOOST_CHECK(link.data_call(address(leader), {"KYTHIRA.DATA", "NOPE", "x"})
                    ->rfind("-ERR unknown KYTHIRA.DATA subcommand", 0) == 0);

    // Never from a client, whatever its role.
    resp_client ops(c.port(leader));
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_CHECK(ops.call({"KYTHIRA.DATA", "ROUTE", key}).rfind("-NOPERM", 0) == 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Front ends without data (.kiro/specs/redis-general-data-types/ task 16,
// Requirements 18.1-18.6): a node whose host holds no group serves every
// command through `KYTHIRA.DATA READ|PROPOSE` and the `KYTHIRA.TXN` hop, with
// the bytes a co-located node gives.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

/// The same commands, in order, on two nodes (each on its own keys): every
/// reply byte-for-byte (Requirement 18.6).
[[maybe_unused]] void check_same_replies(resp_client& a, resp_client& b, const std::string& tag) {
    const std::vector<std::vector<std::string>> script{
        {"SET", tag + "/a", "alpha"},
        {"GET", tag + "/a"},
        {"EXISTS", tag + "/a"},
        {"STRLEN", tag + "/a"},
        {"GETRANGE", tag + "/a", "1", "3"},
        {"TTL", tag + "/a"},
        {"SETEX", tag + "/b", "100", "beta"},
        {"GET", tag + "/b"},
        {"GET", tag + "/missing"},
        {"EXISTS", tag + "/missing"},
        {"TTL", tag + "/missing"},
        {"DEL", tag + "/a"},
        {"DEL", tag + "/a"},
        {"GET", tag + "/a"},
    };
    for (const auto& argv : script) {
        auto left = argv;
        auto right = argv;
        for (std::size_t i = 1; i < argv.size(); ++i) {
            if (argv[i].rfind(tag, 0) == 0) {
                left[i] = "x" + argv[i];
                right[i] = "y" + argv[i];
            }
        }
        BOOST_TEST_CONTEXT(argv[0] << " " << argv[1]) {
            BOOST_CHECK_EQUAL(a.call(left), b.call(right));
        }
    }
}

}  // namespace

// The disk-backed store keeps a value's chunks on its data nodes, which a
// front end without data cannot read, so it refuses to start (see the next
// case); these run on the in-memory and engine stores.
#if !defined(KYTHIRA_GATEWAY_TEST_DISK_STORE)
BOOST_AUTO_TEST_CASE(front_end_without_data_serves_commands_from_the_data_nodes,
                     *boost::unit_test::timeout(180)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto& fe = c.add_front_end();

    resp_client remote(fe.port());
    BOOST_REQUIRE_EQUAL(remote.auth("farm", "farm-secret"), "+OK\r\n");
    resp_client local(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(local.auth("farm", "farm-secret"), "+OK\r\n");

    // Both shards, through the leader and (for the co-located side) not.
    check_same_replies(remote, local, "sccache/fe");
    check_same_replies(remote, local, "a/fe");

    // A write through the front end is a write on the data layer, and the
    // reverse: no copy lives on the front end.
    BOOST_CHECK_EQUAL(remote.call({"SET", "sccache/fe/shared", "one"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(local.call({"GET", "sccache/fe/shared"}), "$3\r\none\r\n");
    BOOST_CHECK_EQUAL(local.call({"SET", "sccache/fe/back", "two"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(remote.call({"GET", "sccache/fe/back"}), "$3\r\ntwo\r\n");
    BOOST_CHECK_EQUAL(remote.call({"DBSIZE"}), ":0\r\n");

    resp_client ops(fe.port());
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    auto info = ops.call({"INFO"});
    BOOST_CHECK(info.find("kythira_roles:gateway,front_end\r\n") != std::string::npos);

    // The data layer's own leader moves: the front end follows the
    // refusals to the new one.
    const auto old_leader = c.leader_of(k_sccache_group);
    c.kill(old_leader);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
    std::string reply;
    while (std::chrono::steady_clock::now() < deadline) {
        reply = remote.call({"SET", "sccache/fe/after", "three"});
        if (reply == "+OK\r\n") {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    BOOST_REQUIRE_EQUAL(reply, "+OK\r\n");
    BOOST_CHECK_EQUAL(remote.call({"GET", "sccache/fe/after"}), "$5\r\nthree\r\n");
    BOOST_CHECK_EQUAL(remote.call({"GET", "sccache/fe/back"}), "$3\r\ntwo\r\n");
}

BOOST_AUTO_TEST_CASE(data_only_nodes_serve_front_ends_and_refuse_clients,
                     *boost::unit_test::timeout(180)) {
    redis_gateway_config data_only;
    data_only._layer_roles = {kythira::layers::role::data};
    data_only._insecure_plaintext = true;
    cluster c(data_only);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));

    // A client of a data node gets PING and nothing else.
    resp_client direct(c.port(1));
    BOOST_REQUIRE_EQUAL(direct.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(direct.call({"PING"}), "+PONG\r\n");
    BOOST_CHECK(direct.call({"GET", "sccache/x"}).rfind("-ERR this node runs no gateway", 0) == 0);

    // Every read consistency through a front end.
    for (auto consistency : {redis_read_consistency::leader, redis_read_consistency::any_replica,
                             redis_read_consistency::linearizable}) {
        redis_gateway_config cfg;
        cfg._read_consistency = consistency;
        auto& fe = c.add_front_end(cfg);
        resp_client k(fe.port());
        BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
        const auto key = "sccache/split/" + std::to_string(static_cast<int>(consistency));
        BOOST_CHECK_EQUAL(k.call({"SET", key, "v"}), "+OK\r\n");
        // A replica may lag by a moment.
        std::string got;
        for (int i = 0; i < 50 && got != "$1\r\nv\r\n"; ++i) {
            got = k.call({"GET", key});
            if (got != "$1\r\nv\r\n") {
                std::this_thread::sleep_for(std::chrono::milliseconds{20});
            }
        }
        BOOST_CHECK_EQUAL(got, "$1\r\nv\r\n");
        BOOST_CHECK_EQUAL(k.call({"DEL", key}), ":1\r\n");
        for (int i = 0; i < 50 && got != ":0\r\n"; ++i) {
            got = k.call({"EXISTS", key});
            if (got != ":0\r\n") {
                std::this_thread::sleep_for(std::chrono::milliseconds{20});
            }
        }
        BOOST_CHECK_EQUAL(got, ":0\r\n");
    }

    // READ off the wire: a follower refuses a leader read with the leader's
    // name, and never forwards it (Requirement 18.3).
    const auto leader = c.leader_of(k_sccache_group);
    const auto follower = c.a_follower_of(k_sccache_group);
    auto& link = c.gateway(follower);
    auto address = [&](node_id_t id) { return "127.0.0.1:" + std::to_string(c.port(id)); };
    auto read = [&](node_id_t at, const std::string& mode, const std::string& key) {
        auto answer = kythira::parse_redis_peer_answer(
            *link.data_call(address(at), {"KYTHIRA.DATA", "READ", mode, key}));
        BOOST_REQUIRE(answer._kind == kythira::redis_peer_answer::kind::bulk);
        auto out = kythira::redis_data_wire::decode_read<node_id_t>(answer._text);
        BOOST_REQUIRE(out.has_value());
        return *out;
    };
    using kythira::redis_data_wire::read_status;
    auto& fe = c.add_front_end();
    resp_client k(fe.port());
    BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(k.call({"SETEX", "sccache/split/ttl", "100", "w"}), "+OK\r\n");
    auto refused = read(follower, "LEADER", "sccache/split/ttl");
    BOOST_CHECK(refused.status == read_status::not_leader);
    BOOST_CHECK(refused.leader == std::optional<node_id_t>{leader});
    auto served = read(leader, "LEADER", "sccache/split/ttl");
    BOOST_CHECK(served.status == read_status::ok);
    BOOST_CHECK(served.found);
    BOOST_CHECK_EQUAL(served.value, "w");
    BOOST_CHECK_GT(served.expire_at_ms, 0u);
    auto missing = read(leader, "LINEARIZABLE", "sccache/split/none");
    BOOST_CHECK(missing.status == read_status::ok);
    BOOST_CHECK(!missing.found);
    BOOST_CHECK(link.data_call(address(leader), {"KYTHIRA.DATA", "READ", "SOMETIMES", "k"})
                    ->rfind("-ERR unknown read mode", 0) == 0);
}

#endif  // !KYTHIRA_GATEWAY_TEST_DISK_STORE

BOOST_AUTO_TEST_CASE(front_end_without_data_refuses_to_start_without_a_way_to_reach_it,
                     *boost::unit_test::timeout(60)) {
    redis_acl acl;
    acl.reload(acl_text());
    kythira::console_logger logger{kythira::log_level::error};
    kythira::noop_metrics metrics;
    message_fabric fabric{2};
    config_type hc{
        .node_id = 1,
        .network_client = fabric_client{fabric, 1},
        .network_server = fabric_server{fabric, 1},
        .store_factory = [](const group_id_type&) { return host_types::persistence_engine_type{}; },
    };
    hc.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
    with_state_machines(hc);
    host_type host(std::move(hc));
    auto attempt = [&](redis_gateway_config cfg) -> std::string {
        cfg._listen = "127.0.0.1:0";
        cfg._layer_roles = {kythira::layers::role::gateway, kythira::layers::role::front_end};
        gateway_type gw(host, acl, logger, metrics, cfg, {});
        try {
            gw.start();
        } catch (const std::exception& e) {
            return e.what();
        }
        gw.stop();
        return {};
    };
    redis_gateway_config none;
    none._internal_secret = "s";
    none._insecure_plaintext = true;
    BOOST_CHECK(attempt(none).find("KYTHIRA_REDIS_DATA_NODES") != std::string::npos);
    redis_gateway_config no_secret;
    no_secret._data_nodes = {"127.0.0.1:1"};
    no_secret._insecure_plaintext = true;
#if defined(KYTHIRA_GATEWAY_TEST_DISK_STORE)
    // The disk-backed store is refused before anything else is checked.
    BOOST_CHECK(attempt(no_secret).find("disk-backed store") != std::string::npos);
#else
    BOOST_CHECK(attempt(no_secret).find("internal secret") != std::string::npos);
    // Without insecure plaintext a node apart needs layer identities
    // (Requirement 19.4).
    redis_gateway_config no_identity = no_secret;
    no_identity._internal_secret = "s";
    no_identity._insecure_plaintext = false;
    no_identity._allow_plaintext_forwarding = true;
    BOOST_CHECK(attempt(no_identity).find("mutual TLS") != std::string::npos);
    redis_gateway_config ok = no_secret;
    ok._internal_secret = "s";
    BOOST_CHECK_EQUAL(attempt(ok), "");
#endif
}

// ── task 17: a gateway apart from its front ends, and layer identities ──────

namespace {

/// Co-located nodes carrying a layer identity with every role, so nodes
/// apart can call them and they accept those calls by identity.
auto layer_tls_config(test_pki& pki) -> redis_gateway_config {
    pki.layer_leaf("colo", "colo", "gateway,front_end,data");
    auto cfg = tls_config(pki, "colo");
    cfg._layer_cluster = "test";
    return cfg;
}

/// A gateway-only node's credentials: a client certificate naming the
/// `gateway` role, and the CA the front ends' listeners chain to.
auto gateway_apart_config(test_pki& pki) -> redis_gateway_config {
    pki.layer_leaf("gw", "gw1", "gateway");
    redis_gateway_config cfg;
    cfg._forward_tls = true;
    cfg._forward_tls_cert_path = pki.cert("gw");
    cfg._forward_tls_key_path = pki.key("gw");
    cfg._tls_ca_path = pki.cert("ca");
    cfg._layer_cluster = "test";
    return cfg;
}

/// A gateway-only node that reaches its front ends with the internal secret
/// over plaintext loopback (insecure plaintext).
auto insecure_gateway_config(std::vector<std::string> front_ends = {}) -> redis_gateway_config {
    redis_gateway_config cfg;
    cfg._insecure_plaintext = true;
    cfg._internal_secret = "internal-secret";
    cfg._front_ends = std::move(front_ends);
    return cfg;
}

/// The answer bytes inside a `KYTHIRA.CALL` reply.
auto call_answer_of(const std::string& reply)
    -> std::optional<kythira::redis_call_wire::call_answer> {
    if (reply.empty() || reply.front() != '$') {
        return std::nullopt;
    }
    const auto eol = reply.find("\r\n");
    return kythira::redis_call_wire::decode_answer(
        std::string_view(reply).substr(eol + 2, reply.size() - eol - 4));
}

/// A stand-in front end for the cases about what a gateway does when its
/// front end misbehaves. It answers AUTH with +OK, and each `KYTHIRA.CALL`
/// after `delay` either with `reply` inside a well-formed answer or, when
/// `reply` is empty, by closing the connection without a word.
class fake_front_end {
public:
    fake_front_end(std::chrono::milliseconds delay, std::string reply)
        : _delay(delay), _reply(std::move(reply)), _acceptor(_io) {
        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), 0);
        _acceptor.open(ep.protocol());
        _acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        _acceptor.bind(ep);
        _acceptor.listen();
        _acceptor.non_blocking(true);
        _port = _acceptor.local_endpoint().port();
        _accepting = std::thread([this] { accept_loop(); });
    }
    ~fake_front_end() {
        _stop = true;
        if (_accepting.joinable()) {
            _accepting.join();
        }
        for (auto& t : _serving) {
            if (t.joinable()) {
                t.join();
            }
        }
    }
    fake_front_end(const fake_front_end&) = delete;
    auto operator=(const fake_front_end&) -> fake_front_end& = delete;

    [[nodiscard]] auto endpoint() const -> std::string {
        return "127.0.0.1:" + std::to_string(_port);
    }
    [[nodiscard]] auto calls() const -> int { return _calls.load(); }

private:
    auto accept_loop() -> void {
        while (!_stop) {
            boost::system::error_code ec;
            boost::asio::ip::tcp::socket s(_io);
            (void)_acceptor.accept(s, ec);
            if (ec) {
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
                continue;
            }
            _serving.emplace_back([this, sock = std::move(s)]() mutable { serve(sock); });
        }
    }

    auto serve(boost::asio::ip::tcp::socket& sock) -> void {
        kythira::resp_parser parser;
        std::array<char, 4096> chunk{};
        while (!_stop) {
            boost::system::error_code ec;
            const auto n = sock.read_some(boost::asio::buffer(chunk), ec);
            if (ec) {
                return;
            }
            parser.feed(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(chunk.data()), n));
            while (auto cmd = parser.next()) {
                const auto upper = kythira::resp_to_upper(cmd->_argv[0]);
                if (upper == "AUTH") {
                    boost::asio::write(sock, boost::asio::buffer(std::string("+OK\r\n")), ec);
                    continue;
                }
                ++_calls;
                std::this_thread::sleep_for(_delay);
                if (_reply.empty() || upper != "KYTHIRA.CALL") {
                    (void)sock.close(ec);
                    return;
                }
                auto state = kythira::redis_call_wire::decode_state(cmd->_argv.at(1));
                kythira::redis_call_wire::call_answer answer{
                    state.value_or(kythira::redis_call_wire::call_state{}), false, _reply};
                boost::asio::write(
                    sock,
                    boost::asio::buffer(bulk(kythira::redis_call_wire::encode_answer(answer))), ec);
            }
        }
    }

    std::chrono::milliseconds _delay;
    std::string _reply;
    boost::asio::io_context _io;
    boost::asio::ip::tcp::acceptor _acceptor;
    std::uint16_t _port = 0;
    std::atomic<bool> _stop{false};
    std::atomic<int> _calls{0};
    std::thread _accepting;
    std::vector<std::thread> _serving;
};

/// One host in no group, for gateways that only start or refuse to.
struct lone_host {
    lone_host()
        : fabric{2}, host([this] {
              config_type hc{
                  .node_id = 1,
                  .network_client = fabric_client{fabric, 1},
                  .network_server = fabric_server{fabric, 1},
                  .store_factory =
                      [](const group_id_type&) { return host_types::persistence_engine_type{}; },
              };
              hc.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
              with_state_machines(hc);
              return hc;
          }()) {
        acl.reload(acl_text());
    }
    /// "" when a gateway with `cfg` starts, else why it refused.
    auto attempt(redis_gateway_config cfg) -> std::string {
        cfg._listen = "127.0.0.1:0";
        gateway_type gw(host, acl, logger, metrics, std::move(cfg), {});
        try {
            gw.start();
        } catch (const std::exception& e) {
            return e.what();
        }
        gw.stop();
        return {};
    }

    redis_acl acl;
    kythira::console_logger logger{kythira::log_level::error};
    kythira::noop_metrics metrics;
    message_fabric fabric;
    host_type host;
};

}  // namespace

BOOST_AUTO_TEST_CASE(a_gateway_apart_serves_clients_through_the_front_ends,
                     *boost::unit_test::timeout(180)) {
    test_pki pki;
    cluster c(layer_tls_config(pki), false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto& gw = c.add_gateway(gateway_apart_config(pki));

    resp_client remote(gw.port());
    BOOST_REQUIRE_EQUAL(remote.auth("farm", "farm-secret"), "+OK\r\n");
    resp_client local(c.port(c.leader_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(local.auth("farm", "farm-secret"), "+OK\r\n");
    // The same bytes as a co-located node, on both shards.
    check_same_replies(remote, local, "sccache/gw");
    check_same_replies(remote, local, "a/gw");
    // The ACL decides on the front end, for the gateway's user.
    resp_client reader(gw.port());
    BOOST_REQUIRE_EQUAL(reader.auth("reader", "reader-secret"), "+OK\r\n");
    resp_client local_reader(c.port(1));
    BOOST_REQUIRE_EQUAL(local_reader.auth("reader", "reader-secret"), "+OK\r\n");
    const auto refused = reader.call({"SET", "sccache/gw/ro", "v"});
    BOOST_CHECK(refused.rfind("-NOPERM", 0) == 0);
    BOOST_CHECK_EQUAL(refused, local_reader.call({"SET", "sccache/gw/ro", "v"}));
    // The protocol is connection state the gateway holds.
    resp_client r3(gw.port());
    BOOST_CHECK(r3.call({"HELLO", "3", "AUTH", "farm", "farm-secret"}).front() == '%');
    BOOST_CHECK_EQUAL(r3.call({"GET", "sccache/gw/none"}), "_\r\n");
    BOOST_CHECK_EQUAL(gw.stats()._front_end_lost.load(), 0u);
    BOOST_CHECK_GT(gw.stats()._front_end_calls.load(), 0u);

    // A front end goes away: the connections pinned to it move to another
    // before their next command, and nothing is ambiguous because nothing
    // was in flight.
    c.kill(1);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
    std::string reply;
    for (int i = 0; std::chrono::steady_clock::now() < deadline; ++i) {
        reply = remote.call({"SET", "sccache/gw/after/" + std::to_string(i), "v"});
        if (reply == "+OK\r\n") {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    BOOST_REQUIRE_EQUAL(reply, "+OK\r\n");
    for (int i = 0; i < 10; ++i) {
        resp_client k(gw.port());
        BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(k.call({"PING"}), "+PONG\r\n");
    }
    BOOST_CHECK_EQUAL(gw.stats()._front_end_lost.load(), 0u);
}

BOOST_AUTO_TEST_CASE(a_gateway_apart_never_replays_a_call_its_front_end_may_have_run,
                     *boost::unit_test::timeout(120)) {
    fake_front_end lost(std::chrono::milliseconds{0}, "");
    redis_gateway_config base;
    base._insecure_plaintext = true;
    cluster c(base);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));

    // The front end read the call and vanished: it may have run it.
    auto& gw = c.add_gateway(insecure_gateway_config({lost.endpoint()}));
    resp_client k(gw.port());
    BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(k.call({"SET", "sccache/amb", "v"}),
                      "-ERR outcome unknown, front end lost; it may have applied\r\n");
    BOOST_CHECK_EQUAL(lost.calls(), 1);
    BOOST_CHECK_EQUAL(gw.stats()._front_end_lost.load(), 1u);

    // A front end that cannot be reached never got the call: the next one
    // runs it, for every connection.
    const auto closed = "127.0.0.1:" + std::to_string(kythira::testing::free_port());
    auto& gw2 =
        c.add_gateway(insecure_gateway_config({closed, "127.0.0.1:" + std::to_string(c.port(1))}));
    for (int i = 0; i < 20; ++i) {
        resp_client one(gw2.port());
        BOOST_REQUIRE_EQUAL(one.auth("farm", "farm-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(one.call({"PING"}), "+PONG\r\n");
    }
    BOOST_CHECK_EQUAL(gw2.stats()._front_end_lost.load(), 0u);
}

BOOST_AUTO_TEST_CASE(a_draining_gateway_finishes_what_it_received,
                     *boost::unit_test::timeout(120)) {
    fake_front_end slow(std::chrono::milliseconds{400}, "+OK\r\n");
    fake_front_end stuck(std::chrono::milliseconds{2000}, "+OK\r\n");
    redis_gateway_config base;
    base._insecure_plaintext = true;
    cluster c(base);

    auto cfg = insecure_gateway_config({slow.endpoint()});
    cfg._drain_timeout = std::chrono::milliseconds{5000};
    auto& gw = c.add_gateway(cfg);
    const auto port = gw.port();
    resp_client k(port);
    BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
    k.send_raw(resp_client::encode({"SET", "sccache/drain", "v"}));
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    std::thread drainer([&] { gw.drain(); });
    // In flight when the drain began: it finishes and is answered.
    BOOST_CHECK_EQUAL(k.read_reply(), "+OK\r\n");
    drainer.join();
    BOOST_CHECK(!gw.is_running());
    BOOST_CHECK(k.wait_closed());
    BOOST_CHECK_THROW(resp_client late(port), std::exception);

    // The bound: a command that outlives it does not hold the drain.
    auto bounded = insecure_gateway_config({stuck.endpoint()});
    bounded._drain_timeout = std::chrono::milliseconds{200};
    auto& gw2 = c.add_gateway(bounded);
    resp_client k2(gw2.port());
    BOOST_REQUIRE_EQUAL(k2.auth("farm", "farm-secret"), "+OK\r\n");
    k2.send_raw(resp_client::encode({"SET", "sccache/drain2", "v"}));
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    gw2.drain();
    BOOST_CHECK(!gw2.is_running());
    BOOST_CHECK(k2.wait_closed());
}

BOOST_AUTO_TEST_CASE(internal_commands_check_the_callers_layer_roles,
                     *boost::unit_test::timeout(120)) {
    test_pki pki;
    cluster c(layer_tls_config(pki), false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    pki.layer_leaf("as-data", "d1", "data");
    pki.layer_leaf("as-gateway", "g1", "gateway");
    pki.layer_leaf("elsewhere", "g2", "gateway", "another-cluster");
    using kythira::redis_call_wire::call_state;
    using kythira::redis_call_wire::encode_state;
    const auto farm = encode_state(call_state{.user = "farm"});
    const auto n = c.leader_of(k_sccache_group);

    // A data node's identity may use the data-layer API, never call a
    // front end (Requirement 19.2).
    resp_client data(c.tls_port(n), client_tls(pki, "as-data"));
    BOOST_CHECK(
        data.call({"KYTHIRA.CALL", farm, "PING"})
            .rfind("-NOPERM a caller with the layer roles data may not send KYTHIRA.CALL", 0) == 0);
    BOOST_CHECK(data.call({"KYTHIRA.DATA", "ROUTE", "sccache/x"}).front() == '$');

    // A gateway's may call, as the connection's user, and nothing else.
    resp_client gw(c.tls_port(n), client_tls(pki, "as-gateway"));
    auto answer = call_answer_of(gw.call({"KYTHIRA.CALL", farm, "SET", "sccache/roles", "v"}));
    BOOST_REQUIRE(answer.has_value());
    BOOST_CHECK_EQUAL(answer->reply, "+OK\r\n");
    auto denied =
        call_answer_of(gw.call({"KYTHIRA.CALL", encode_state(call_state{.user = "reader"}), "SET",
                                "sccache/roles2", "v"}));
    BOOST_REQUIRE(denied.has_value());
    BOOST_CHECK(denied->reply.rfind("-NOPERM", 0) == 0);
    BOOST_CHECK(gw.call({"KYTHIRA.DATA", "ROUTE", "sccache/x"})
                    .rfind("-NOPERM a caller with the layer roles gateway", 0) == 0);
    BOOST_CHECK(gw.call({"KYTHIRA.CALL", encode_state(call_state{.user = "nobody"}), "PING"})
                    .rfind("-NOAUTH", 0) == 0);
    BOOST_CHECK(
        gw.call({"KYTHIRA.CALL", "junk", "PING"}).rfind("-ERR malformed connection state", 0) == 0);
    // The internal secret is no way around it (Requirement 19.3).
    BOOST_CHECK(gw.auth("kythira-internal", "internal-secret")
                    .rfind("-NOPERM the caller's layer identity names roles=gateway", 0) == 0);
    BOOST_CHECK(gw.call({"KYTHIRA.DATA", "ROUTE", "sccache/x"}).rfind("-NOPERM", 0) == 0);

    // Another cluster's identity is no identity here.
    resp_client stranger(c.tls_port(n), client_tls(pki, "elsewhere"));
    BOOST_CHECK(stranger.call({"KYTHIRA.CALL", farm, "PING"}).rfind("-NOAUTH", 0) == 0);

    // The secret alone implies the data role: no authenticated calls.
    resp_client secret(c.port(n));
    BOOST_REQUIRE_EQUAL(secret.auth("kythira-internal", "internal-secret"), "+OK\r\n");
    BOOST_CHECK(secret.call({"KYTHIRA.CALL", farm, "PING"})
                    .rfind("-NOPERM a caller with the layer roles data", 0) == 0);
    BOOST_CHECK(secret.call({"KYTHIRA.DATA", "ROUTE", "sccache/x"}).front() == '$');

    // A client may not call at all.
    resp_client client(c.port(n));
    BOOST_REQUIRE_EQUAL(client.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(
        client.call({"KYTHIRA.CALL", farm, "PING"}).rfind("-NOPERM KYTHIRA.CALL is internal", 0) ==
        0);
}

BOOST_AUTO_TEST_CASE(nodes_apart_need_layer_identities_and_refuse_the_secret,
                     *boost::unit_test::timeout(60)) {
    test_pki pki;
    lone_host h;
    const kythira::layers::role_set gateway_only{kythira::layers::role::gateway};

    // A gateway without the front end needs front ends, then a way to
    // reach them: an identity naming its roles (Requirement 19.4).
    redis_gateway_config gw;
    gw._layer_roles = gateway_only;
    BOOST_CHECK(h.attempt(gw).find("KYTHIRA_REDIS_FRONT_ENDS") != std::string::npos);
    gw._front_ends = {"127.0.0.1:1"};
    BOOST_CHECK(h.attempt(gw).find("mutual TLS") != std::string::npos);
    gw._forward_tls = true;
    gw._tls_ca_path = pki.cert("ca");
    gw._forward_tls_cert_path = pki.cert("farm");
    gw._forward_tls_key_path = pki.key("farm");
    gw._layer_cluster = "test";
    BOOST_CHECK(h.attempt(gw).find("carries no layer identity") != std::string::npos);
    pki.layer_leaf("wrong-roles", "g1", "front_end");
    gw._forward_tls_cert_path = pki.cert("wrong-roles");
    gw._forward_tls_key_path = pki.key("wrong-roles");
    BOOST_CHECK(h.attempt(gw).find("names other roles") != std::string::npos);
    pki.layer_leaf("gw", "g1", "gateway");
    gw._forward_tls_cert_path = pki.cert("gw");
    gw._forward_tls_key_path = pki.key("gw");
    BOOST_CHECK_EQUAL(h.attempt(gw), "");
    // ... or insecure plaintext, with the secret standing in.
    redis_gateway_config insecure;
    insecure._layer_roles = gateway_only;
    insecure._front_ends = {"127.0.0.1:1"};
    insecure._insecure_plaintext = true;
    BOOST_CHECK(h.attempt(insecure).find("internal secret") != std::string::npos);
    insecure._internal_secret = "s";
    BOOST_CHECK_EQUAL(h.attempt(insecure), "");

    // A front end with data and no gateway is called on its TLS listener.
    pki.layer_leaf("fe", "f1", "front_end,data");
    redis_gateway_config fe;
    fe._layer_roles = {kythira::layers::role::front_end, kythira::layers::role::data};
    fe._forward_tls = true;
    fe._tls_cert_path = pki.cert("fe");
    fe._tls_key_path = pki.key("fe");
    fe._tls_ca_path = pki.cert("ca");
    fe._layer_cluster = "test";
    BOOST_CHECK(h.attempt(fe).find("TLS listener") != std::string::npos);
    fe._tls_listen = "127.0.0.1:0";
    fe._internal_secret = "internal-secret";
    fe._listen = "127.0.0.1:0";
    gateway_type node(h.host, h.acl, h.logger, h.metrics, fe, {});
    node.start();
    // It is not co-located, so the secret is refused (Requirement 19.3),
    // and it serves no clients.
    resp_client k(node.port());
    BOOST_CHECK(k.auth("kythira-internal", "internal-secret")
                    .rfind("-NOPERM this node is not co-located", 0) == 0);
    BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(k.call({"GET", "sccache/x"}).rfind("-ERR this node runs no gateway", 0) == 0);
    node.stop();
}

BOOST_AUTO_TEST_CASE(certificates_rotate_without_a_restart, *boost::unit_test::timeout(120)) {
    test_pki pki;
    auto cfg = layer_tls_config(pki);
    cfg._tls_reload_interval = std::chrono::milliseconds{0};
    cluster c(cfg, false);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto gcfg = gateway_apart_config(pki);
    gcfg._tls_reload_interval = std::chrono::milliseconds{0};
    auto& gw = c.add_gateway(gcfg);
    resp_client through(gw.port());
    BOOST_REQUIRE_EQUAL(through.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(through.call({"SET", "sccache/rot/1", "v"}), "+OK\r\n");

    resp_client before(c.tls_port(1), client_tls(pki, "farm"));
    const auto old_serial = before.peer_serial();
    // Every node's certificate, and the gateway's, are reissued in place.
    pki.layer_leaf("colo", "colo", "gateway,front_end,data");
    pki.layer_leaf("gw", "gw1", "gateway");
    resp_client after(c.tls_port(1), client_tls(pki, "farm"));
    BOOST_CHECK_NE(after.peer_serial(), old_serial);
    // Open connections keep working; new ones use the new certificates.
    BOOST_CHECK_EQUAL(before.call({"PING"}), "+PONG\r\n");
    BOOST_CHECK_EQUAL(after.call({"PING"}), "+PONG\r\n");
    BOOST_CHECK_EQUAL(through.call({"SET", "sccache/rot/2", "v"}), "+OK\r\n");
    resp_client follower(c.port(c.a_follower_of(k_sccache_group)));
    BOOST_REQUIRE_EQUAL(follower.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(follower.call({"SET", "sccache/rot/3", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(gw.stats()._front_end_lost.load(), 0u);
}

// ── task 18: layer membership ────────────────────────────────────────────────

namespace {

/// One replica of the layer membership group, shared by the nodes that are
/// its voters in these cases. The group's Raft replication is
/// layer_membership_test's; here it is what the gateways do with the list.
class shared_membership {
public:
    auto replica() -> redis_gateway_config::membership_replica {
        return {
            ._propose =
                [this](std::vector<std::byte> command) -> std::optional<std::vector<std::byte>> {
                std::lock_guard lock(_mu);
                return std::vector<std::byte>{_core.apply_command(command) ? std::byte{1}
                                                                           : std::byte{0}};
            },
            ._read = [this] { return members(); },
        };
    }
    auto members() -> std::vector<kythira::layers::layer_member> {
        std::lock_guard lock(_mu);
        return _core.members();
    }
    auto find(const std::string& id) -> std::optional<kythira::layers::layer_member> {
        std::lock_guard lock(_mu);
        return _core.find(id);
    }

private:
    std::mutex _mu;
    kythira::layers::layer_membership_core _core;
};

template<typename Pred> auto eventually(Pred pred, std::chrono::milliseconds budget) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    return pred();
}

/// The value of `field` in an INFO reply.
auto info_field(const std::string& info, const std::string& field) -> std::string {
    const auto at = info.find("\r\n" + field + ":");
    if (at == std::string::npos) {
        return {};
    }
    const auto start = at + 2 + field.size() + 1;
    return info.substr(start, info.find("\r\n", start) - start);
}

auto calls_served(cluster& c, node_id_t id) -> std::uint64_t {
    return c.gateway(id).stats()._front_end_calls_served.load();
}

auto connect_refused(std::uint16_t port) -> bool {
    boost::asio::io_context io;
    boost::asio::ip::tcp::socket sock(io);
    boost::system::error_code ec;
    (void)sock.connect({boost::asio::ip::make_address("127.0.0.1"), port}, ec);
    return static_cast<bool>(ec);
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_gateway_finds_its_front_ends_in_the_layer_membership_group,
                     *boost::unit_test::timeout(180)) {
    // Requirement 20.1: the co-located nodes hold the group (one shared
    // replica here) and announce themselves; the gateway apart reaches it
    // through node 1's KYTHIRA.MEMBERS and calls whoever is serving.
    shared_membership group;
    redis_gateway_config base;
    base._insecure_plaintext = true;
    base._membership_local = group.replica();
    base._membership_interval = std::chrono::milliseconds{100};
    cluster c(base);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    BOOST_REQUIRE(
        eventually([&] { return group.members().size() == 3U; }, std::chrono::seconds{10}));
    for (node_id_t n = 1; n <= k_node_count; ++n) {
        const auto m = group.find(std::to_string(n));
        BOOST_REQUIRE(m.has_value());
        BOOST_CHECK_EQUAL(m->address, "127.0.0.1:" + std::to_string(c.port(n)));
        BOOST_CHECK_EQUAL(m->roles.to_string(), "gateway,front_end,data");
        BOOST_CHECK_EQUAL(m->index, 0u);  // no index configured
    }

    auto cfg = insecure_gateway_config();
    cfg._membership_voters = {"127.0.0.1:" + std::to_string(c.port(1))};
    cfg._membership_interval = std::chrono::milliseconds{100};
    cfg._member_id = "gw-apart";
    cfg._drain_timeout = std::chrono::milliseconds{2000};
    auto& gw = c.add_gateway(cfg);
    BOOST_REQUIRE(
        eventually([&] { return group.find("gw-apart").has_value(); }, std::chrono::seconds{10}));
    BOOST_CHECK_EQUAL(group.find("gw-apart")->roles.to_string(), "gateway");

    resp_client ops(gw.port());
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    // The list as the gateway read it on its last round. (INFO here would
    // be a front end's: the gateway sends it on like any command.)
    std::string list;
    BOOST_CHECK(eventually(
        [&] {
            list = ops.call({"KYTHIRA.LAYERS", "LIST"});
            return list.rfind("*4\r\n", 0) == 0;
        },
        std::chrono::seconds{5}));
    BOOST_CHECK(list.find("gw-apart 127.0.0.1:" + std::to_string(gw.port()) + " roles=gateway") !=
                std::string::npos);
    resp_client farm(gw.port());
    BOOST_REQUIRE_EQUAL(farm.auth("farm", "farm-secret"), "+OK\r\n");
    BOOST_CHECK(farm.call({"KYTHIRA.LAYERS"}).rfind("-NOPERM", 0) == 0);
    BOOST_CHECK(farm.call({"KYTHIRA.MEMBERS", "LIST"}).rfind("-NOPERM", 0) == 0);
    BOOST_CHECK_EQUAL(farm.call({"SET", "sccache/mg/1", "v"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(farm.call({"GET", "sccache/mg/1"}), "$1\r\nv\r\n");

    // Requirement 20.3: a drained front end gets no new calls. Node 1 holds
    // data, so it keeps its listener and only stops being chosen.
    BOOST_CHECK_EQUAL(ops.call({"KYTHIRA.LAYERS", "DRAIN", "nobody"}),
                      "-ERR no member 'nobody' in the layer membership group\r\n");
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.LAYERS", "DRAIN", "1"}), "+OK\r\n");
    BOOST_REQUIRE(
        eventually([&] { return group.find("1")->drain == kythira::layers::drain_state::drained; },
                   std::chrono::seconds{10}));
    resp_client node1(c.port(1));
    BOOST_REQUIRE_EQUAL(node1.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_CHECK_EQUAL(info_field(node1.call({"INFO"}), "kythira_member_drain"), "drained");
    const auto served_by_1 = calls_served(c, 1);
    const auto served_by_others = calls_served(c, 2) + calls_served(c, 3);
    for (int i = 0; i < 30; ++i) {
        resp_client k(gw.port());
        BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(k.call({"SET", "sccache/mg/d/" + std::to_string(i), "v"}), "+OK\r\n");
    }
    BOOST_CHECK_EQUAL(calls_served(c, 1), served_by_1);
    BOOST_CHECK_GE(calls_served(c, 2) + calls_served(c, 3), served_by_others + 30);

    // Back to serving: it takes calls again.
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.LAYERS", "SERVE", "1"}), "+OK\r\n");
    BOOST_REQUIRE(eventually(
        [&] {
            resp_client k(gw.port());
            (void)k.auth("farm", "farm-secret");
            (void)k.call({"PING"});
            return calls_served(c, 1) > served_by_1;
        },
        std::chrono::seconds{10}));
    BOOST_CHECK_EQUAL(gw.stats()._front_end_lost.load(), 0u);

    // A gateway apart that drains stops taking connections, closes its
    // clients once their commands are done, and reports itself drained.
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.LAYERS", "DRAIN", "gw-apart"}), "+OK\r\n");
    BOOST_REQUIRE(eventually(
        [&] { return group.find("gw-apart")->drain == kythira::layers::drain_state::drained; },
        std::chrono::seconds{10}));
    BOOST_CHECK(connect_refused(gw.port()));
    BOOST_CHECK_GT(gw.stats()._membership_announces.load(), 0u);
    BOOST_CHECK_GT(gw.stats()._membership_reports.load(), 0u);
}

BOOST_AUTO_TEST_CASE(a_gateway_finds_its_front_ends_by_dns, *boost::unit_test::timeout(120)) {
    // Requirement 20.2: without the group, a name whose every address is a
    // front end, re-resolved on an interval.
    redis_gateway_config base;
    base._insecure_plaintext = true;
    cluster c(base);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto cfg = insecure_gateway_config();
    cfg._front_ends_dns = "localhost:" + std::to_string(c.port(2));
    cfg._discovery_interval = std::chrono::milliseconds{200};
    auto& gw = c.add_gateway(cfg);
    resp_client ops(gw.port());
    BOOST_REQUIRE_EQUAL(ops.auth("ops", "ops-secret"), "+OK\r\n");
    BOOST_CHECK(
        ops.call({"KYTHIRA.LAYERS", "LIST"}).find("127.0.0.1:" + std::to_string(c.port(2))) !=
        std::string::npos);
    // Drain needs the group.
    BOOST_CHECK(
        ops.call({"KYTHIRA.LAYERS", "DRAIN", "x"}).rfind("-ERR draining a member needs", 0) == 0);
    const auto before = calls_served(c, 2);
    for (int i = 0; i < 5; ++i) {
        resp_client k(gw.port());
        BOOST_REQUIRE_EQUAL(k.auth("farm", "farm-secret"), "+OK\r\n");
        BOOST_CHECK_EQUAL(k.call({"SET", "sccache/dns/" + std::to_string(i), "v"}), "+OK\r\n");
    }
    BOOST_CHECK_GE(calls_served(c, 2), before + 5);
}

BOOST_AUTO_TEST_CASE(only_a_replica_of_the_group_answers_members_calls,
                     *boost::unit_test::timeout(120)) {
    redis_gateway_config base;
    base._insecure_plaintext = true;
    cluster c(base);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    // A node that holds no replica points the caller elsewhere.
    resp_client internal(c.port(1));
    BOOST_REQUIRE_EQUAL(internal.auth("kythira-internal", "internal-secret"), "+OK\r\n");
    BOOST_CHECK(internal.call({"KYTHIRA.MEMBERS", "LIST"}).rfind("-TRYAGAIN", 0) == 0);
}
