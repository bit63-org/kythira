// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Any test's data layer as one concrete `stream_cluster` type, so the role
// layouts (kinesis_layouts.hpp), compiled once into kythira_kinesis_layouts,
// can run over a `local_stream_cluster` or over the replicated data layer
// the migration path tests move between nodes (kinesis_migration_rig.hpp)
// without instantiating the listener, peer client and remote access twice.

#include <kythira/kinesis/kinesis_cluster.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kinesis::test {

/// Every call forwards to the cluster it was made `of`, which must outlive
/// it. It meets every concept `local_data_access` looks for, so the
/// service over it behaves as over the cluster itself.
struct cluster_handle {
    std::function<std::optional<apply_result>(const std::string&, std::vector<std::byte>,
                                              admission)>
        _propose;
    std::function<bool(const std::string&, const stream_reader&)> _read;
    std::function<std::int64_t()> _now_ms;
    std::function<transact_outcome(std::vector<txn_write>)> _transact;
    std::function<std::optional<std::uint64_t>(const std::string&)> _group_of;
    std::function<bool(const std::string&)> _leads;

    template<typename Cluster>
    requires stream_cluster<Cluster> && transacts<Cluster> && groups_keys<Cluster> &&
             leads_keys<Cluster>
    [[nodiscard]] static auto of(Cluster& c) -> cluster_handle {
        return {
            ._propose = [&c](const std::string& key, std::vector<std::byte> command,
                             admission mode) { return c.propose(key, std::move(command), mode); },
            ._read = [&c](const std::string& key,
                          const stream_reader& f) { return c.read(key, f); },
            ._now_ms = [&c] { return c.now_ms(); },
            ._transact = [&c](std::vector<txn_write> w) { return c.transact(std::move(w)); },
            ._group_of = [&c](const std::string& key) { return c.group_of(key); },
            ._leads = [&c](const std::string& key) { return c.leads(key); },
        };
    }

    auto propose(const std::string& key, std::vector<std::byte> command,
                 admission mode = admission::none) -> std::optional<apply_result> {
        return _propose(key, std::move(command), mode);
    }
    auto read(const std::string& key, const stream_reader& f) -> bool { return _read(key, f); }
    [[nodiscard]] auto now_ms() const -> std::int64_t { return _now_ms(); }
    auto transact(std::vector<txn_write> writes) -> transact_outcome {
        return _transact(std::move(writes));
    }
    [[nodiscard]] auto group_of(const std::string& key) const -> std::optional<std::uint64_t> {
        return _group_of(key);
    }
    [[nodiscard]] auto leads(const std::string& key) const -> bool { return _leads(key); }
};

static_assert(stream_cluster<cluster_handle>);
static_assert(transacts<cluster_handle>);
static_assert(groups_keys<cluster_handle>);
static_assert(leads_keys<cluster_handle>);

}  // namespace kythira::kinesis::test
