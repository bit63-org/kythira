// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// What one S3 node runs, built from its settings
// (.kiro/specs/s3-compatible-storage/ tasks 16 and 16a): the chunk store,
// the outbound clients, the data path, the internal listener, the S3 API
// and website listeners, and the leader-side workers, over whichever
// metadata layer the node has:
//
//  - `start()`: the group in process and in memory (local_metadata) on a
//    metadata node without Raft peers, or the metadata nodes over the
//    internal transport (remote_metadata) on a front end.
//  - `start_with(meta, leads, group_routes)`: any metadata_access; the S3
//    module (s3_module.hpp) passes the index group on Raft, its leadership
//    and the routes the members forward on.

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

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3_node {

namespace s3 = kythira::s3;
namespace https = kythira::https;
namespace http = boost::beast::http;

inline void log_line(bool warning, std::string_view line) {
    std::cerr << (warning ? "[warn] " : "[info] ") << "s3_gateway_node: " << line << "\n";
}

inline auto plain(unsigned status, std::string body) -> https::response {
    https::response r{static_cast<http::status>(status), 11};
    r.set(http::field::content_type, "text/plain");
    r.body() = std::move(body);
    return r;
}

/// One request from the listener as the pipeline takes it.
inline auto to_s3(const https::request& req, const https::request_context& ctx, bool secure)
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
inline auto from_s3(s3::s3_response out) -> https::response {
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

/// A route the internal listener hands over: (method, target, body) to the
/// status and body.
using route_handler = std::function<std::pair<unsigned, std::string>(
    std::string_view method, std::string_view target, std::string_view body)>;

/// The mutual-TLS client settings for calls to other S3 nodes.
[[nodiscard]] inline auto internal_client_config(const s3::node_config& cfg)
    -> kythira::mtls::client_config {
    kythira::mtls::client_config c;
    c.cert_path = cfg.internal_tls.cert;
    c.key_path = cfg.internal_tls.key;
    c.ca_path = cfg.internal_tls.ca;
    c.timeout = std::chrono::seconds(30);
    c.max_body_bytes = std::uint64_t{64} << 20U;
    return c;
}

class node {
public:
    explicit node(const s3::node_config& cfg) : _cfg(cfg) {}

    node(const node&) = delete;
    auto operator=(const node&) -> node& = delete;
    node(node&&) = delete;
    auto operator=(node&&) -> node& = delete;
    ~node() { stop(); }

    /// Starts a node whose metadata is in process and in memory, or remote.
    void start() {
        if (_cfg.raft()) {
            throw std::logic_error("s3 node: a Raft member starts through the S3 module");
        }
        if (_cfg.roles.has(s3::role::data)) {
            // The index is in memory, so the change log it keeps state for
            // starts empty too.
            std::filesystem::remove_all(_cfg.data_dir / "changes");
            _changes = std::make_unique<kythira::record_segment_store>(
                kythira::record_segment_store_options{._data_dir = _cfg.data_dir / "changes"});
            _local = std::make_unique<s3::local_metadata>(s3::index_options{}, _changes.get());
            // One metadata node holds its group alone, so it always leads.
            start_with(*_local, {}, {});
        } else if (!_cfg.metadata_endpoints.empty()) {
            std::vector<std::string> urls;
            for (const auto& [id, url] : _cfg.metadata_endpoints) {
                urls.push_back(url);
            }
            auto client = std::make_shared<kythira::mtls::client>(internal_client_config(_cfg));
            _remote = std::make_unique<s3::remote_metadata>(s3::endpoint_transport(
                urls, [client](const std::string& url, const std::string& target,
                               const std::string& body) {
                    return client->request("POST", url, target, body, "application/octet-stream",
                                           "kythira-s3");
                }));
            start_with(*_remote, {}, {});
        } else {
            start_with(_none, {}, {});
        }
    }

    /// Starts every layer the roles name over `meta`. `leads` gates the
    /// workers (empty: this node always leads); `group_routes` serves the
    /// index group's member routes (empty: none here).
    template<s3::metadata_access M>
    void start_with(M& meta, std::function<bool()> leads, route_handler group_routes) {
        build_blobs();
        build_outbound();
        build_data_path();
        if (_cfg.roles.has(s3::role::data)) {
            auto server = std::make_shared<s3::metadata_server<M>>(meta);
            _metadata_routes = [server](std::string_view method, std::string_view target,
                                        std::string_view body) {
                return server->handle(method, target, body);
            };
        }
        _group_routes = std::move(group_routes);
        start_internal();
        if (_cfg.roles.has(s3::role::front_end)) {
            start_front_end(meta);
        }
        if constexpr (s3::change_log_access<M> && s3::tier_metadata_access<M> &&
                      s3::chunk_metadata_access<M>) {
            if (_cfg.roles.has(s3::role::data)) {
                start_workers(meta, std::move(leads));
            }
        }
        log_line(false, "running roles " + s3::s3_roles_string(_cfg.roles) + " as node " +
                            _cfg.node_id + " in cluster " + _cfg.cluster +
                            (_cfg.raft() ? ", index on Raft with " +
                                               std::to_string(_cfg.raft_peers.size()) + " members"
                                         : ""));
    }

    /// Stops taking requests (the workers and every listener).
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

    [[nodiscard]] auto api_port() const -> std::uint16_t { return _api ? _api->port() : 0; }

    /// The workers' counters, by job name.
    [[nodiscard]] auto worker_stats(std::string_view job) const -> s3::worker_job_stats {
        return _workers ? _workers->stats(job) : s3::worker_job_stats{};
    }

private:
    /// A front end with no metadata node to reach: never started (the
    /// settings refuse it), here so `start()` has something to pass.
    struct no_metadata {
        static auto none() -> s3::metadata_unavailable {
            return s3::metadata_unavailable("no metadata nodes");
        }
        auto propose(const s3::index_command&) -> s3::index_result { throw none(); }
        [[nodiscard]] auto bucket(std::string_view) const -> std::optional<s3::bucket_descriptor> {
            throw none();
        }
        [[nodiscard]] auto list_buckets(std::string_view) const
            -> std::vector<s3::bucket_descriptor> {
            throw none();
        }
        [[nodiscard]] auto version(std::uint64_t, std::string_view,
                                   const std::optional<std::string>&) const
            -> std::optional<s3::object_version> {
            throw none();
        }
        [[nodiscard]] auto list_objects(std::uint64_t, std::string_view, std::string_view,
                                        std::string_view, std::size_t) const -> s3::object_listing {
            throw none();
        }
        [[nodiscard]] auto list_versions(std::uint64_t, std::string_view, std::string_view,
                                         std::string_view, std::string_view, std::size_t) const
            -> s3::version_listing {
            throw none();
        }
        [[nodiscard]] auto upload(std::uint64_t, std::string_view, std::string_view) const
            -> std::optional<s3::upload_record> {
            throw none();
        }
        [[nodiscard]] auto list_uploads(std::uint64_t, std::string_view, std::string_view,
                                        std::string_view, std::size_t) const
            -> std::pair<std::vector<s3::upload_record>, bool> {
            throw none();
        }
    };

    /// Where co-located placement puts a chunk: the index group's members
    /// (every Raft member, or this node alone), or for a front end the
    /// metadata nodes it reaches.
    [[nodiscard]] auto replicas() const -> std::vector<std::string> {
        std::vector<std::string> out;
        if (_cfg.raft()) {
            for (const auto& [id, addr] : _cfg.raft_peers) {
                out.push_back(id);
            }
            return out;
        }
        if (_cfg.roles.has(s3::role::data)) {
            return {_cfg.node_id};
        }
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
            _inventories.push_back(
                std::make_unique<s3::chunk_inventory>(_cfg.node_id, *_local_chunks));
        }
        for (const auto& [id, url] : _cfg.metadata_endpoints) {
            if (id == _cfg.node_id) {
                continue;  // this node's own store, in process
            }
            _remote_chunks.push_back(std::make_unique<kythira::remote_chunk_access>(
                internal_client_config(_cfg), url,
                kythira::chunk_store_options{}._max_chunk_bytes));
            _copies.emplace_back(id, *_remote_chunks.back());
            _inventories.push_back(
                std::make_unique<s3::chunk_inventory>(id, *_remote_chunks.back()));
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
        const auto binary = [&](const route_handler& h, std::string_view missing) {
            if (!h) {
                return plain(404, std::string(missing));
            }
            auto [status, body] = h(std::string_view(req.method_string()), target, req.body());
            auto res = plain(status, std::move(body));
            res.set(http::field::content_type, "application/octet-stream");
            return res;
        };
        if (target.starts_with(s3::metadata_route_prefix)) {
            return binary(_metadata_routes, "this node has no metadata role\n");
        }
        if (target.starts_with(s3::group_route_prefix)) {
            return binary(_group_routes, "this node is not a member of an index group\n");
        }
        if (kythira::chunk_service::owns(target) && _chunk_service) {
            if (auto res = _chunk_service->handle(req, ctx)) {
                return std::move(*res);
            }
        }
        return plain(404, "this node has no blobs role\n");
    }

    template<s3::metadata_access M> void start_front_end(M& meta) {
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

    template<s3::metadata_access M> void start_workers(M& meta, std::function<bool()> leads) {
        const auto every =
            std::chrono::duration_cast<std::chrono::milliseconds>(_cfg.worker_interval);
        const auto often = std::min(every, std::chrono::milliseconds(5000));
        std::vector<s3::worker_job> jobs;
        auto lifecycle = std::make_shared<s3::lifecycle_worker<M>>(meta);
        jobs.push_back({"lifecycle", every, [lifecycle] {
                            const auto r = lifecycle->run();
                            return r.expired + r.transitioned + r.uploads_aborted == 0
                                       ? std::string{}
                                       : std::to_string(r.expired) + " expired, " +
                                             std::to_string(r.transitioned) + " transitioned, " +
                                             std::to_string(r.uploads_aborted) + " uploads aborted";
                        }});
        auto tiers = std::make_shared<s3::tier_worker<M>>(meta, *_data,
                                                          std::vector<const s3::cloud_tier*>{});
        jobs.push_back({"tiers", every, [tiers] {
                            const auto r = tiers->run();
                            return r.failures == 0 ? std::string{}
                                                   : std::to_string(r.failures) + " failures";
                        }});
        if (!_inventories.empty()) {
            s3::sweep_options so;
            so.grace_ms = grace_ms();
            so.max_write_ms = max_write_ms();
            auto sweeper = std::make_shared<s3::chunk_sweeper<M>>(
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
            jobs.push_back({"sweeper", every, [sweeper] {
                                const auto r = sweeper->sweep();
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
            auto notifier = std::make_shared<s3::notification_worker<M>>(meta, _notifications, no);
            jobs.push_back({"notifications", often, [notifier] {
                                const auto r = notifier->run();
                                return r.delivered + r.dropped == 0
                                           ? std::string{}
                                           : std::to_string(r.delivered) + " delivered, " +
                                                 std::to_string(r.dropped) + " dropped";
                            }});
            s3::replication_options ro;
            ro.account_namespaces = _cfg.account_namespaces;
            auto replicator = std::make_shared<s3::replication_worker<M>>(
                meta, *_data, _keys, s3::make_replication_call(_outbound, _cfg.max_request_bytes),
                ro);
            jobs.push_back({"replication", often, [replicator] {
                                const auto r = replicator->run();
                                return r.failures == 0 ? std::string{}
                                                       : std::to_string(r.failures) + " failures";
                            }});
        }
        _workers = std::make_unique<s3::worker_runner>(_cfg.roles, std::move(leads),
                                                       std::move(jobs), log_line);
        _workers->start();
    }

    const s3::node_config& _cfg;
    std::unique_ptr<kythira::chunk_store> _store;
    std::unique_ptr<kythira::local_chunk_access> _local_chunks;
    std::unique_ptr<kythira::chunk_service> _chunk_service;
    std::vector<std::unique_ptr<kythira::remote_chunk_access>> _remote_chunks;
    std::vector<s3::chunk_copy> _copies;
    std::vector<std::unique_ptr<s3::chunk_inventory>> _inventories;
    std::vector<std::string> _replicas;
    std::unique_ptr<s3::data_path> _data;

    std::unique_ptr<kythira::record_segment_store> _changes;
    std::unique_ptr<s3::local_metadata> _local;
    std::unique_ptr<s3::remote_metadata> _remote;
    no_metadata _none;
    route_handler _metadata_routes;
    route_handler _group_routes;

    std::shared_ptr<s3::sse_keys> _keys;
    s3::outbound_options _outbound;
    s3::notification_sink _notifications;
    std::unique_ptr<static_authorizer> _auth;
    std::shared_ptr<void> _service_keepalive;

    std::unique_ptr<kythira::layers::route_guard> _guard;
    std::unique_ptr<https::server> _internal;
    std::unique_ptr<https::server> _api;
    std::unique_ptr<https::server> _website;

    std::unique_ptr<s3::worker_runner> _workers;
};

}  // namespace kythira::s3_node
