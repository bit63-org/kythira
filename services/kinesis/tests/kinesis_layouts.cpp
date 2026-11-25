// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The role layouts of kinesis_layouts.hpp, compiled once for every suite
// that runs in them. The data node they reach is in
// kinesis_layouts_node.cpp.

#include "kinesis_layouts.hpp"
#include "kinesis_layouts_detail.hpp"

#include <kythira/kinesis/kinesis_catalog.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_data_access.hpp>
#include <kythira/kinesis/kinesis_data_api.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kinesis::test {

struct layered_access::impl {
    // Declared first: everything below refers to it.
    cluster_handle _cluster;
    std::unique_ptr<local_data_access<cluster_handle>> _co_located;
    std::unique_ptr<layout_detail::loopback_data_node> _data_node;
    std::unique_ptr<peer_client> _peers;
    std::unique_ptr<remote_data_access> _remote;
    std::unique_ptr<layout_detail::replica_view<cluster_handle>> _catalog_view;
    std::unique_ptr<local_data_access<layout_detail::replica_view<cluster_handle>>> _catalog_local;
    std::unique_ptr<hybrid_data_access<layout_detail::replica_view<cluster_handle>>> _hybrid;
    data_access* _access = nullptr;
};

layered_access::layered_access(local_stream_cluster& cluster, layout_kind kind)
    : layered_access(cluster_handle::of(cluster), kind) {}

layered_access::layered_access(const cluster_handle& handle, layout_kind kind)
    : _kind(kind), _impl(std::make_unique<impl>()) {
    auto& i = *_impl;
    i._cluster = handle;
    auto& cluster = i._cluster;
    if (kind == layout_kind::co_located) {
        i._co_located = std::make_unique<local_data_access<cluster_handle>>(cluster);
        i._access = i._co_located.get();
        return;
    }
    i._data_node = std::make_unique<layout_detail::loopback_data_node>(cluster);
    i._peers = std::make_unique<peer_client>(peer_client_config{._tls = false, ._ca_path = {}});
    remote_data_options ro;
    ro._clock = [&cluster] { return cluster.now_ms(); };
    i._remote = std::make_unique<remote_data_access>(
        std::vector<std::string>{i._data_node->address()},
        make_http_data_transport(*i._peers, std::string(layout_detail::k_secret)), ro);
    if (kind == layout_kind::front_end_apart) {
        i._access = i._remote.get();
        return;
    }
    // Mixed: this node holds the catalog group, the data node the
    // stream groups.
    i._catalog_view = std::make_unique<layout_detail::replica_view<cluster_handle>>(
        cluster, [](const std::string& key) { return key.starts_with(catalog_prefix()); });
    i._catalog_local =
        std::make_unique<local_data_access<layout_detail::replica_view<cluster_handle>>>(
            *i._catalog_view);
    i._hybrid = std::make_unique<hybrid_data_access<layout_detail::replica_view<cluster_handle>>>(
        *i._catalog_local, *i._remote);
    i._access = i._hybrid.get();
}

layered_access::~layered_access() = default;

auto layered_access::get() const noexcept -> data_access& {
    return *_impl->_access;
}

auto layered_access::remote_calls() const -> std::uint64_t {
    return _impl->_data_node ? _impl->_data_node->served() : 0;
}

auto remote_access_to(const std::string& address) -> remote_access {
    // The transport refers to the peer client, so the two live and die
    // together, the client last.
    struct owner {
        peer_client _peers{peer_client_config{._tls = false, ._ca_path = {}}};
        remote_data_access _remote;
        explicit owner(const std::string& a)
            : _remote({a}, make_http_data_transport(_peers, std::string(layout_detail::k_secret))) {
        }
    };
    auto o = std::make_shared<owner>(address);
    return {._access = std::shared_ptr<data_access>(o, &o->_remote),
            ._unreachable = [o] { return o->_remote.stats()._unreachable; }};
}

}  // namespace kythira::kinesis::test
