// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The loopback data node of kinesis_layouts.hpp's apart and mixed layouts:
// a gateway serving the data-layer API on an HTTPS listener.

#include "kinesis_layouts.hpp"
#include "kinesis_layouts_detail.hpp"

#include <kythira/kinesis/kinesis_catalog.hpp>
#include <kythira/kinesis/kinesis_data_api.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_gateway.hpp>

#include <raft/beast_https_server.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kinesis::test::layout_detail {
namespace {

constexpr std::string_view k_data_node = "d1";

/// Refuses every Kinesis call: the data node's gateway serves only the
/// internal routes.
struct refuse_all {
    auto authenticate(const sigv4::request&, const sigv4::service_rules&)
        -> aws_auth::authn_result {
        return sigv4::aws_error{
            .code = "AccessDeniedException", .message = "data node only", .http_status = 403};
    }
    auto authorize(const aws_auth::principal_context&, const aws_auth::authz_request&)
        -> aws_auth::authz_decision {
        return {};
    }
};

}  // namespace

struct loopback_data_node::impl {
    explicit impl(cluster_handle cluster)
        : _cluster(std::move(cluster)),
          _view(_cluster, [](const std::string&) { return true; }),
          _local(_view) {
        data_api_deps deps;
        deps._local = &_local;
        deps._propose_here = [this](const std::string& key, const std::vector<std::byte>& command,
                                    admission mode) {
            data_node_proposal p;
            p._result = _view.propose(key, command, mode);
            p._kind =
                p._result ? data_node_proposal::kind::committed : data_node_proposal::kind::failed;
            return p;
        };
        deps._check = [](const std::string&, const std::optional<route_ref>& ref) {
            route_verdict v;
            if (ref && ref->_group != 1) {
                v._kind = route_check_kind::stale;
                v._route = route();
            }
            return v;
        };
        deps._routes = [this](const shard_range<std::string>&) {
            data_route_cache::routes_reply reply;
            reply.routes.push_back(route());
            reply.addresses.emplace_back(std::string(k_data_node), address());
            return reply;
        };
        _gateway = std::make_unique<gateway_type>(
            _fe,
            [this](const std::string& key, const std::vector<std::byte>& command, admission mode) {
                return _view.propose(key, command, mode);
            },
            nullptr, std::string(layout_detail::k_secret));
        _gateway->set_roles(layers::role_set::parse("data,segments"));
        _gateway->set_data_api(std::move(deps));
        https::server_config sc;
        sc.bind_address = "127.0.0.1";
        sc.port = 0;
        sc.insecure_plaintext = true;
        // A node's internal listener takes KINESIS_MAX_BODY_BYTES (8 MiB by
        // default), enough for a full PutRecords command.
        sc.max_body_bytes = std::uint64_t{8} * 1024 * 1024;
        _server = std::make_unique<https::server>(
            sc, [this](const https::request& req, const https::request_context& ctx) {
                return _gateway->handle_internal(req, ctx);
            });
        _server->start();
    }

    impl(const impl&) = delete;
    auto operator=(const impl&) -> impl& = delete;
    impl(impl&&) = delete;
    auto operator=(impl&&) -> impl& = delete;
    ~impl() { _server->stop(); }

    [[nodiscard]] auto address() const -> std::string {
        return "127.0.0.1:" + std::to_string(_server->port());
    }

    [[nodiscard]] auto served() const -> std::uint64_t {
        return _gateway->stats()._data_api_served;
    }

    using front_end_type = front_end<refuse_all>;
    using gateway_type = gateway<front_end_type>;

    [[nodiscard]] static auto route() -> data_route {
        data_route r;
        r._group_id = 1;
        r._range = shard_range<std::string>{._start = std::nullopt, ._end = std::nullopt};
        r._epoch = {._version = 1, ._conf_version = 1};
        r._voters = {std::string(k_data_node)};
        r._leader_hint = std::string(k_data_node);
        return r;
    }

    cluster_handle _cluster;
    replica_view<cluster_handle> _view;
    local_data_access<replica_view<cluster_handle>> _local;
    refuse_all _auth;
    front_end_type _fe{front_end_config{}, _auth};
    std::unique_ptr<gateway_type> _gateway;
    std::unique_ptr<https::server> _server;
};

loopback_data_node::loopback_data_node(cluster_handle cluster)
    : _impl(std::make_unique<impl>(std::move(cluster))) {}

loopback_data_node::~loopback_data_node() = default;

auto loopback_data_node::address() const -> std::string {
    return _impl->address();
}

auto loopback_data_node::served() const -> std::uint64_t {
    return _impl->served();
}

}  // namespace kythira::kinesis::test::layout_detail
