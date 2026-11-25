// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The pieces kinesis_layouts.cpp and kinesis_layouts_node.cpp share. The
// data node's gateway and listener compile in their own translation unit,
// apart from the remote and hybrid access, so neither TU holds both:
// together they took one TU to 5.4 GB of compiler memory at -O2.

#include "kinesis_cluster_handle.hpp"

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_data_access.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kinesis::test::layout_detail {

/// A replica's view of `Cluster`: the keys `holds` admits, as a node that
/// holds only some groups sees them. Reads and proposals of any other key
/// find no replica; transactions run on the whole cluster, as the tier-1
/// coordinator on a data node reaches every group's leader.
template<stream_cluster Cluster> class replica_view {
public:
    replica_view(Cluster& cluster, std::function<bool(const std::string&)> holds)
        : _cluster(cluster), _holds(std::move(holds)) {}

    auto propose(const std::string& key, std::vector<std::byte> command,
                 admission mode = admission::none) -> std::optional<apply_result> {
        if (!_holds(key)) {
            return std::nullopt;
        }
        return _cluster.propose(key, std::move(command), mode);
    }

    auto read(const std::string& key, const stream_reader& f) -> bool {
        return _holds(key) && _cluster.read(key, f);
    }

    [[nodiscard]] auto now_ms() -> std::int64_t { return _cluster.now_ms(); }

    auto transact(std::vector<txn_write> writes) -> transact_outcome
    requires transacts<Cluster>
    {
        return _cluster.transact(std::move(writes));
    }

    [[nodiscard]] auto holds(const std::string& key) const -> bool { return _holds(key); }

private:
    Cluster& _cluster;
    std::function<bool(const std::string&)> _holds;
};

/// One data node on a loopback listener: the data-layer API over a
/// `replica_view` of the test's cluster, one group over every key, led
/// here.
class loopback_data_node {
public:
    explicit loopback_data_node(cluster_handle cluster);

    loopback_data_node(const loopback_data_node&) = delete;
    auto operator=(const loopback_data_node&) -> loopback_data_node& = delete;
    loopback_data_node(loopback_data_node&&) = delete;
    auto operator=(loopback_data_node&&) -> loopback_data_node& = delete;
    ~loopback_data_node();

    /// "127.0.0.1:<port>".
    [[nodiscard]] auto address() const -> std::string;

    /// Data-layer API calls the node answered.
    [[nodiscard]] auto served() const -> std::uint64_t;

private:
    struct impl;
    std::unique_ptr<impl> _impl;
};

}  // namespace kythira::kinesis::test::layout_detail
