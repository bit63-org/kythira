// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// s3_gateway_node: the Amazon S3-compatible daemon
// (.kiro/specs/s3-compatible-storage/ task 16).
//
// Reads its settings from the environment (s3_node_config.hpp lists them;
// --help prints them) and runs the layers KYTHIRA_S3_ROLES names:
//
//  - blobs: a chunk store under KYTHIRA_S3_DATA_DIR.
//  - metadata: the object index group in process (local_metadata), the
//    metadata routes for front ends on other nodes, and the leader-side
//    workers (lifecycle, tiers, notifications, replication, the chunk
//    sweeper) on a schedule (s3_workers.hpp).
//  - front_end (with gateway): the S3 API listener, and the website
//    listener when KYTHIRA_S3_WEBSITE_LISTEN is set. Without the metadata
//    role it reaches the metadata node through remote_metadata and writes
//    chunks to that node's blob store.
//
// The internal listener (KYTHIRA_S3_INTERNAL_LISTEN) serves the metadata
// and chunk routes over mutual TLS, each route open to the roles
// internal_route_rules() names (s3_roles.hpp).
//
// What is not here yet: the index on Raft (one metadata node holds the only
// copy, in memory, so nothing in the index survives a restart, as with
// dynamodb_gateway_node without peers), the gateway apart from the front
// end and streaming bodies (task 17), blob pools (task 18), cloud tiers
// (the tier worker runs with none configured) and IAM authentication
// (static keys only).

#include <kythira/s3/model/operations.hpp>
#include <kythira/s3/s3_lifecycle.hpp>
#include <kythira/s3/s3_node_config.hpp>
#include <kythira/s3/s3_notifications.hpp>
#include <kythira/s3/s3_outbound.hpp>
#include <kythira/s3/s3_remote_metadata.hpp>
#include <kythira/s3/s3_replication.hpp>
#include <kythira/s3/s3_roles.hpp>
#include <kythira/s3/s3_service.hpp>
#include <kythira/s3/s3_sweeps.hpp>
#include <kythira/s3/s3_tiers.hpp>
#include <kythira/s3/s3_workers.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/chunk_service.hpp>
#include <raft/chunk_store.hpp>
#include <raft/layer_identity.hpp>
#include <raft/mtls_https_client.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/static_key_authorizer.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
// The Folly backend (the default, which defines no macro of its own) needs
// folly::Init before the first future: its timekeeper is a Folly singleton.
#include <folly/init/Init.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {

namespace s3 = kythira::s3;
namespace https = kythira::https;
namespace http = boost::beast::http;

constexpr std::string_view k_usage =
    "usage: s3_gateway_node [--help | --self-test]\n"
    "\n"
    "The Kythira Amazon S3-compatible daemon. Point the AWS CLI, an AWS SDK,\n"
    "rclone or Mountpoint at it with an endpoint URL. Settings come from the\n"
    "environment:\n"
    "\n";

using kythira::s3::model::operation_info;

auto find_operation(std::string_view name) -> const operation_info* {
    const auto& ops = kythira::s3::model::operations;
    const auto* it =
        std::find_if(ops.begin(), ops.end(), [&](const auto& o) { return o._name == name; });
    return it == ops.end() ? nullptr : it;
}

auto fail(const char* what) -> int {
    std::fprintf(stderr, "self-test: %s\n", what);
    return 1;
}

/// Checks the generated operation table (task 1), without starting anything.
auto self_test() -> int {
    namespace m = kythira::s3::model;
    const auto& ops = m::operations;
    if (!std::is_sorted(ops.begin(), ops.end(),
                        [](const auto& a, const auto& b) { return a._name < b._name; })) {
        return fail("operation table is not sorted");
    }
    constexpr std::array<std::string_view, 5> methods{"GET", "HEAD", "PUT", "POST", "DELETE"};
    for (const auto& op : ops) {
        if (std::find(methods.begin(), methods.end(), op._method) == methods.end()) {
            return fail("an operation has an unknown HTTP method");
        }
        if (!op._request_uri.starts_with('/')) {
            return fail("an operation's request URI does not start with '/'");
        }
    }
    const auto* put = find_operation("PutObject");
    if (put == nullptr || put->_method != "PUT" || !put->_streaming_input) {
        return fail("PutObject missing, not a PUT, or not a streaming upload");
    }
    const auto* part = find_operation("UploadPart");
    if (part == nullptr || !part->_streaming_input) {
        return fail("UploadPart missing or not a streaming upload");
    }
    const auto* get = find_operation("GetObject");
    if (get == nullptr || get->_method != "GET" || !get->_streaming_output) {
        return fail("GetObject missing, not a GET, or not a streaming download");
    }
    const auto* v2 = find_operation("ListObjectsV2");
    if (v2 == nullptr || v2->_request_uri != "/{Bucket}?list-type=2") {
        return fail("ListObjectsV2 missing or not told apart by ?list-type=2");
    }
    const auto* del = find_operation("DeleteObjects");
    if (del == nullptr || !del->_checksum_required) {
        return fail("DeleteObjects missing or not marked as needing a checksum");
    }
    const auto streaming = std::count_if(ops.begin(), ops.end(), [](const auto& o) {
        return o._streaming_input || o._streaming_output;
    });
    const auto deprecated =
        std::count_if(ops.begin(), ops.end(), [](const auto& o) { return o._deprecated; });
    std::printf(
        "self-test ok: %zu operations (%td streaming, %td deprecated), %.*s, botocore %.*s\n",
        ops.size(), streaming, deprecated, static_cast<int>(m::protocol.size()), m::protocol.data(),
        static_cast<int>(m::botocore_version.size()), m::botocore_version.data());
    return 0;
}

void log_line(bool warning, std::string_view line) {
    std::cerr << (warning ? "[warn] " : "[info] ") << "s3_gateway_node: " << line << "\n";
}

auto wait_for_signal() -> int {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    int sig = 0;
    sigwait(&set, &sig);
    return sig;
}

auto plain(unsigned status, std::string body) -> https::response {
    https::response r{static_cast<http::status>(status), 11};
    r.set(http::field::content_type, "text/plain");
    r.body() = std::move(body);
    return r;
}

/// One request from the listener as the pipeline takes it.
auto to_s3(const https::request& req, const https::request_context& ctx, bool secure)
    -> s3::http_request {
    s3::http_request in;
    in.method = std::string(req.method_string());
    in.target = std::string(req.target());
    for (const auto& f : req) {
        in.headers.emplace_back(std::string(f.name_string()), std::string(f.value()));
    }
    in.host = s3::find_header(in.headers, "Host").value_or("");
    in.body = s3::memory_body(req.body());
    in.source_ip = ctx.peer_address;
    in.secure_transport = secure;
    return in;
}

/// The pipeline's answer as the listener sends it. A streamed body is
/// collected here: the listener writes whole bodies until the gateway
/// streams (task 17).
auto from_s3(s3::s3_response out) -> https::response {
    https::response res{static_cast<http::status>(out.status), 11};
    for (const auto& [k, v] : out.headers) {
        if (kythira::aws_rest_xml::detail::iequals(k, "Content-Length")) {
            // Through content_length(), so the listener sees it is set and
            // keeps it on a HEAD answer.
            res.content_length(std::stoull(v));
        } else {
            res.insert(k, v);
        }
    }
    if (out.stream) {
        std::string body;
        body.reserve(out.stream_length);
        const auto err = out.stream([&body](std::span<const std::byte> b) {
            body.append(reinterpret_cast<const char*>(b.data()), b.size());  // NOLINT
            return true;
        });
        if (err) {
            // After the headers S3 can only cut the connection; before them
            // the listener answers 500 and closes.
            throw std::runtime_error("object read failed: " + err->message);
        }
        res.body() = std::move(body);
    } else {
        res.body() = std::move(out.body);
    }
    return res;
}

/// A static-key authorizer that also answers anonymous requests: refused,
/// so only ACL grants to AllUsers open a bucket to anonymous readers (there
/// is no policy evaluator without IAM).
struct static_authorizer {
    kythira::aws_auth::static_key_authorizer keys;

    static_authorizer(std::vector<kythira::aws_auth::static_key> k, std::string partition)
        : keys(std::move(k), std::move(partition)) {
        keys.register_service(s3::s3_static_roles());
    }

    auto authenticate(const kythira::sigv4::request& r, const kythira::sigv4::service_rules& rules)
        -> kythira::aws_auth::authn_result {
        return keys.authenticate(r, rules);
    }
    auto resolve(const kythira::sigv4::claim& c, kythira::sigv4::error_protocol p)
        -> kythira::aws_auth::resolve_result {
        return keys.resolve(c, p);
    }
    auto authorize(const kythira::aws_auth::principal_context& w,
                   const kythira::aws_auth::authz_request& r) -> kythira::aws_auth::authz_decision {
        return keys.authorize(w, r);
    }
};

/// Everything a node runs, built from its settings.
class node {
public:
    explicit node(const s3::node_config& cfg) : _cfg(cfg) {}

    node(const node&) = delete;
    auto operator=(const node&) -> node& = delete;
    node(node&&) = delete;
    auto operator=(node&&) -> node& = delete;
    ~node() { stop(); }

    void start() {
        build_blobs();
        build_outbound();
        if (_cfg.roles.has(s3::role::data)) {
            // The index is in memory, so the change log it keeps state for
            // starts empty too.
            std::filesystem::remove_all(_cfg.data_dir / "changes");
            _changes = std::make_unique<kythira::record_segment_store>(
                kythira::record_segment_store_options{._data_dir = _cfg.data_dir / "changes"});
            _local = std::make_unique<s3::local_metadata>(s3::index_options{}, _changes.get());
            _metadata_server = std::make_unique<s3::metadata_server<s3::local_metadata>>(*_local);
        } else if (!_cfg.metadata_endpoints.empty()) {
            std::vector<std::string> urls;
            for (const auto& [id, url] : _cfg.metadata_endpoints) {
                urls.push_back(url);
            }
            auto client = std::make_shared<kythira::mtls::client>(internal_client());
            _remote = std::make_unique<s3::remote_metadata>(s3::endpoint_transport(
                urls, [client](const std::string& url, const std::string& target,
                               const std::string& body) {
                    return client->request("POST", url, target, body, "application/octet-stream",
                                           "kythira-s3");
                }));
        }
        build_data_path();
        start_internal();
        if (_local) {
            start_front_end(*_local);
            start_workers(*_local);
        } else if (_remote) {
            start_front_end(*_remote);
        }
        log_line(false, "running roles " + s3::s3_roles_string(_cfg.roles) + " as node " +
                            _cfg.node_id + " in cluster " + _cfg.cluster);
    }

    void stop() {
        if (_workers) {
            _workers->stop();
        }
        for (auto* s : {_website.get(), _api.get(), _internal.get()}) {
            if (s != nullptr) {
                s->stop();
            }
        }
    }

private:
    /// The metadata nodes' ids, or this node's: where co-located placement
    /// puts a chunk.
    [[nodiscard]] auto replicas() const -> std::vector<std::string> {
        if (_cfg.roles.has(s3::role::data)) {
            return {_cfg.node_id};
        }
        std::vector<std::string> out;
        for (const auto& [id, url] : _cfg.metadata_endpoints) {
            out.push_back(id);
        }
        return out;
    }

    [[nodiscard]] auto grace_ms() const -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(_cfg.sweep_grace).count());
    }

    /// The longest write the front end lets commit: 15 minutes, or less
    /// when the sweeper's grace period is short, which must exceed it plus
    /// the clock allowance (`s3_sweeps.hpp`).
    [[nodiscard]] auto max_write_ms() const -> std::uint64_t {
        const std::uint64_t standard = std::uint64_t{15} * 60 * 1000;
        const auto grace = grace_ms();
        if (grace > standard + s3::chunk_clock_skew_ms) {
            return standard;
        }
        return grace > 2 * s3::chunk_clock_skew_ms ? (grace - s3::chunk_clock_skew_ms) / 2 : 1;
    }

    [[nodiscard]] auto internal_client() const -> kythira::mtls::client_config {
        kythira::mtls::client_config c;
        c.cert_path = _cfg.internal_tls.cert;
        c.key_path = _cfg.internal_tls.key;
        c.ca_path = _cfg.internal_tls.ca;
        c.timeout = std::chrono::seconds(30);
        c.max_body_bytes = std::uint64_t{64} << 20U;
        return c;
    }

    void build_blobs() {
        if (!_cfg.roles.has(s3::role::segments)) {
            return;
        }
        kythira::chunk_store_options o;
        o._data_dir = _cfg.data_dir / "blobs";
        _store = std::make_unique<kythira::chunk_store>(std::move(o));
        _local_chunks = std::make_unique<kythira::local_chunk_access>(*_store);
        // The route guard has already checked the caller's layer identity.
        _chunk_service = std::make_unique<kythira::chunk_service>(
            *_store, [](const https::request_context&) { return true; });
    }

    void build_outbound() {
        _keys = std::make_shared<s3::sse_keys>();
        _keys->partition = _cfg.partition;
        if (!_cfg.sse_passphrase.empty()) {
            _keys->s3_managed = s3::key_provider(s3::local_key_provider(_cfg.sse_passphrase));
        }
        if (_cfg.outbound.empty()) {
            log_line(false,
                     "no outbound credentials: SSE-KMS is refused, notifications and "
                     "replication are off");
            return;
        }
        kythira::mtls::client_config tls;
        tls.ca_path = _cfg.outbound_ca;
        tls.client_certificate = false;
        tls.timeout = std::chrono::seconds(30);
        tls.max_body_bytes = _cfg.max_request_bytes;
        auto secure = std::make_shared<kythira::mtls::client>(tls);
        tls.plaintext = true;
        auto plain_client = std::make_shared<kythira::mtls::client>(tls);
        _outbound.endpoints = _cfg.endpoints;
        _outbound.credentials = _cfg.outbound;
        _outbound.region = _cfg.region;
        _outbound.send =
            [secure, plain_client](
                const s3::outbound_request& r) -> std::optional<std::pair<unsigned, std::string>> {
            std::vector<std::pair<std::string, std::string>> extra;
            std::string content_type;
            for (const auto& [k, v] : r.headers) {
                if (kythira::aws_rest_xml::detail::iequals(k, "Content-Type")) {
                    content_type = v;
                } else if (!kythira::aws_rest_xml::detail::iequals(k, "Host")) {
                    extra.emplace_back(k, v);
                }
            }
            const auto& c = r.url.starts_with("http://") ? *plain_client : *secure;
            return c.request(r.method, r.url, r.target, r.body, content_type, "kythira-s3", extra);
        };
        _keys->kms = s3::key_provider(s3::kms_api_provider(s3::make_kms_call(_outbound)));
        _notifications =
            s3::notification_sink(s3::notification_api_sink(s3::make_event_api_call(_outbound)));
    }

    void build_data_path() {
        if (!_cfg.roles.has(s3::role::front_end) && !_cfg.roles.has(s3::role::data)) {
            return;
        }
        if (_local_chunks) {
            _copies.emplace_back(_cfg.node_id, *_local_chunks);
        }
        for (const auto& [id, url] : _cfg.metadata_endpoints) {
            _remote_chunks.push_back(std::make_unique<kythira::remote_chunk_access>(
                internal_client(), url, kythira::chunk_store_options{}._max_chunk_bytes));
            _copies.emplace_back(id, *_remote_chunks.back());
        }
        _replicas = replicas();
        _data = std::make_unique<s3::data_path>(
            [this](const kythira::chunk_sha& sha) {
                return s3::place(s3::placement_map{}, sha, _replicas);
            },
            s3::resolver_for(_copies), s3::data_path_options{},
            [](const s3::chunk_event& e) {
                log_line(true, "chunk copy on " + e.node + (e.repaired ? " repaired" : " missing"));
            });
    }

    void start_internal() {
        if (!_cfg.internal) {
            return;
        }
        _guard =
            std::make_unique<kythira::layers::route_guard>(kythira::layers::route_guard_options{
                std::string(s3::layer_service), _cfg.cluster, s3::internal_route_rules(), {}, {}});
        https::server_config sc;
        sc.bind_address = _cfg.internal->bind;
        sc.port = _cfg.internal->port;
        sc.tls_cert_path = _cfg.internal_tls.cert;
        sc.tls_key_path = _cfg.internal_tls.key;
        sc.client_ca_path = _cfg.internal_tls.ca;
        sc.max_body_bytes = kythira::chunk_store_options{}._max_chunk_bytes + (1U << 20U);
        _internal = std::make_unique<https::server>(
            sc,
            [this](const https::request& req, const https::request_context& ctx) {
                return internal(req, ctx);
            },
            log_line);
        _internal->start();
        log_line(false, "internal listener on " + _cfg.internal->bind + ":" +
                            std::to_string(_internal->port()));
    }

    auto internal(const https::request& req, const https::request_context& ctx) -> https::response {
        const std::string_view target(req.target().data(), req.target().size());
        const auto v = _guard->check(req, ctx);
        if (v.kind == kythira::layers::verdict_kind::not_internal) {
            return plain(404, "not an internal route\n");
        }
        if (!v.permitted()) {
            return plain(403, v.reason + "\n");
        }
        if (s3::metadata_server<s3::local_metadata>::owns(target)) {
            if (!_metadata_server) {
                return plain(404, "this node has no metadata role\n");
            }
            auto [status, body] =
                _metadata_server->handle(std::string_view(req.method_string()), target, req.body());
            auto res = plain(status, std::move(body));
            res.set(http::field::content_type, "application/octet-stream");
            return res;
        }
        if (kythira::chunk_service::owns(target) && _chunk_service) {
            if (auto res = _chunk_service->handle(req, ctx)) {
                return std::move(*res);
            }
        }
        return plain(404, "this node has no blobs role\n");
    }

    template<s3::metadata_access M> void start_front_end(M& meta) {
        if (!_cfg.roles.has(s3::role::front_end)) {
            return;
        }
        _auth = std::make_unique<static_authorizer>(_cfg.keys, _cfg.partition);

        s3::service_options o;
        o.region = _cfg.region;
        o.partition = _cfg.partition;
        o.addressing.domains = _cfg.domains;
        o.account_namespaces = _cfg.account_namespaces;
        o.encryption = _keys;
        o.notifications = _notifications;
        o.website_domains = _cfg.website_domains;
        o.max_write_ms = max_write_ms();
        auto svc = std::make_shared<s3::s3_service<M, static_authorizer>>(meta, *_data, *_auth,
                                                                          std::move(o));
        _service_keepalive = svc;

        https::server_config sc;
        sc.bind_address = _cfg.api.bind;
        sc.port = _cfg.api.port;
        sc.tls_cert_path = _cfg.api_tls.cert;
        sc.tls_key_path = _cfg.api_tls.key;
        sc.insecure_plaintext = _cfg.insecure_plaintext;
        sc.max_body_bytes = _cfg.max_request_bytes;
        sc.io_timeout = std::chrono::seconds(300);
        const bool secure = !_cfg.insecure_plaintext;
        _api = std::make_unique<https::server>(
            sc,
            [svc, secure](const https::request& req, const https::request_context& ctx) {
                return from_s3(svc->serve(to_s3(req, ctx, secure)));
            },
            log_line);
        _api->start();
        log_line(false, "S3 API on " + _cfg.api.bind + ":" + std::to_string(_api->port()) +
                            (secure ? " (HTTPS)" : " (plain HTTP)"));

        if (_cfg.website) {
            https::server_config wc;
            wc.bind_address = _cfg.website->bind;
            wc.port = _cfg.website->port;
            // S3's website endpoints are plain HTTP; HTTPS in front of them
            // is a CDN's job, as on AWS.
            wc.insecure_plaintext = true;
            wc.max_body_bytes = 64 * 1024;
            _website = std::make_unique<https::server>(
                wc,
                [svc](const https::request& req, const https::request_context& ctx) {
                    return from_s3(svc->serve(to_s3(req, ctx, false)));
                },
                [](bool warning, std::string_view line) {
                    // The listener's plaintext warning is aimed at the API;
                    // a website endpoint is plain HTTP on purpose.
                    if (line.find("PLAINTEXT") == std::string_view::npos) {
                        log_line(warning, line);
                    }
                });
            _website->start();
            log_line(false, "website endpoint on " + _cfg.website->bind + ":" +
                                std::to_string(_website->port()) + " for *." +
                                _cfg.website_domains.front());
        }
    }

    void start_workers(s3::local_metadata& meta) {
        const auto every =
            std::chrono::duration_cast<std::chrono::milliseconds>(_cfg.worker_interval);
        std::vector<s3::worker_job> jobs;
        _lifecycle = std::make_unique<s3::lifecycle_worker<s3::local_metadata>>(meta);
        jobs.push_back({"lifecycle", every, [this] {
                            const auto r = _lifecycle->run();
                            return r.expired + r.transitioned + r.uploads_aborted == 0
                                       ? std::string{}
                                       : std::to_string(r.expired) + " expired, " +
                                             std::to_string(r.transitioned) + " transitioned, " +
                                             std::to_string(r.uploads_aborted) + " uploads aborted";
                        }});
        _tiers = std::make_unique<s3::tier_worker<s3::local_metadata>>(
            meta, *_data, std::vector<const s3::cloud_tier*>{});
        jobs.push_back({"tiers", every, [this] {
                            const auto r = _tiers->run();
                            return r.failures == 0 ? std::string{}
                                                   : std::to_string(r.failures) + " failures";
                        }});
        if (_local_chunks) {
            _inventories.push_back(
                std::make_unique<s3::chunk_inventory>(_cfg.node_id, *_local_chunks));
            s3::sweep_options so;
            so.grace_ms = grace_ms();
            so.max_write_ms = max_write_ms();
            _sweeper = std::make_unique<s3::chunk_sweeper<s3::local_metadata>>(
                meta,
                [this] {
                    std::vector<const s3::chunk_inventory*> out;
                    for (const auto& i : _inventories) {
                        out.push_back(i.get());
                    }
                    return out;
                },
                [this](const kythira::chunk_sha& sha) {
                    return s3::place(s3::placement_map{}, sha, _replicas);
                },
                so);
            jobs.push_back({"sweeper", every, [this] {
                                const auto r = _sweeper->sweep();
                                return r.deleted + r.repaired == 0
                                           ? std::string{}
                                           : std::to_string(r.deleted) + " deleted, " +
                                                 std::to_string(r.repaired) + " repaired";
                            }});
        }
        if (_notifications) {
            s3::notification_options no;
            no.region = _cfg.region;
            no.partition = _cfg.partition;
            no.account_namespaces = _cfg.account_namespaces;
            _notifier = std::make_unique<s3::notification_worker<s3::local_metadata>>(
                meta, _notifications, no);
            jobs.push_back(
                {"notifications", std::min(every, std::chrono::milliseconds(5000)), [this] {
                     const auto r = _notifier->run();
                     return r.delivered + r.dropped == 0
                                ? std::string{}
                                : std::to_string(r.delivered) + " delivered, " +
                                      std::to_string(r.dropped) + " dropped";
                 }});
            s3::replication_options ro;
            ro.account_namespaces = _cfg.account_namespaces;
            _replicator = std::make_unique<s3::replication_worker<s3::local_metadata>>(
                meta, *_data, _keys, s3::make_replication_call(_outbound, _cfg.max_request_bytes),
                ro);
            jobs.push_back(
                {"replication", std::min(every, std::chrono::milliseconds(5000)), [this] {
                     const auto r = _replicator->run();
                     return r.failures == 0 ? std::string{}
                                            : std::to_string(r.failures) + " failures";
                 }});
        }
        // One metadata node holds its group alone, so it always leads it.
        _workers = std::make_unique<s3::worker_runner>(_cfg.roles, std::function<bool()>{},
                                                       std::move(jobs), log_line);
        _workers->start();
    }

    const s3::node_config& _cfg;
    std::unique_ptr<kythira::chunk_store> _store;
    std::unique_ptr<kythira::local_chunk_access> _local_chunks;
    std::unique_ptr<kythira::chunk_service> _chunk_service;
    std::vector<std::unique_ptr<kythira::remote_chunk_access>> _remote_chunks;
    std::vector<s3::chunk_copy> _copies;
    std::vector<std::string> _replicas;
    std::unique_ptr<s3::data_path> _data;

    std::unique_ptr<kythira::record_segment_store> _changes;
    std::unique_ptr<s3::local_metadata> _local;
    std::unique_ptr<s3::metadata_server<s3::local_metadata>> _metadata_server;
    std::unique_ptr<s3::remote_metadata> _remote;

    std::shared_ptr<s3::sse_keys> _keys;
    s3::outbound_options _outbound;
    s3::notification_sink _notifications;
    std::unique_ptr<static_authorizer> _auth;
    std::shared_ptr<void> _service_keepalive;

    std::unique_ptr<kythira::layers::route_guard> _guard;
    std::unique_ptr<https::server> _internal;
    std::unique_ptr<https::server> _api;
    std::unique_ptr<https::server> _website;

    std::unique_ptr<s3::lifecycle_worker<s3::local_metadata>> _lifecycle;
    std::unique_ptr<s3::tier_worker<s3::local_metadata>> _tiers;
    std::vector<std::unique_ptr<s3::chunk_inventory>> _inventories;
    std::unique_ptr<s3::chunk_sweeper<s3::local_metadata>> _sweeper;
    std::unique_ptr<s3::notification_worker<s3::local_metadata>> _notifier;
    std::unique_ptr<s3::replication_worker<s3::local_metadata>> _replicator;
    std::unique_ptr<s3::worker_runner> _workers;
};

}  // namespace

auto main(int argc, char** argv) -> int {
    if (argc > 1) {
        const std::string_view arg(argv[1]);
        if (argc == 2 && arg == "--self-test") {
            return self_test();
        }
        const bool help = argc == 2 && arg == "--help";
        std::FILE* out = help ? stdout : stderr;
        std::fputs(k_usage.data(), out);
        std::fwrite(s3::node_env_help.data(), 1, s3::node_env_help.size(), out);
        return help ? 0 : 2;
    }

    // Block the stop signals in every thread, so sigwait() below receives
    // them; the listeners' threads inherit the mask.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
    const folly::Init folly_init(&argc, &argv);
#endif

    const s3::env_lookup env = [](std::string_view name) -> std::optional<std::string> {
        const std::string n(name);
        const char* v = std::getenv(n.c_str());  // NOLINT(concurrency-mt-unsafe): before threads
        return v == nullptr ? std::nullopt : std::optional<std::string>(v);
    };
    auto parsed = s3::node_config_from_env(env);
    if (auto* e = std::get_if<std::string>(&parsed)) {
        std::cerr << "s3_gateway_node: " << *e << "\n";
        return 2;
    }
    const auto& cfg = std::get<s3::node_config>(parsed);

    int status = 0;
    {
        node n(cfg);
        try {
            n.start();
            const int sig = wait_for_signal();
            log_line(false, "signal " + std::to_string(sig) + ", stopping");
        } catch (const std::invalid_argument& e) {
            std::cerr << "s3_gateway_node: " << e.what() << "\n";
            status = 2;
        } catch (const std::exception& e) {
            std::cerr << "s3_gateway_node: " << e.what() << "\n";
            status = 1;
        }
        n.stop();
    }
    return status;
}
