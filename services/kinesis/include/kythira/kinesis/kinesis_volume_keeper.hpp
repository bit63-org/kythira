// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file kinesis_volume_keeper.hpp
/// @brief Keeps the catalog's segment volume assignments
///        (.kiro/specs/kinesis-independent-layers/ task 10, design "Losing a
///        volume", Requirements 9.4, 9.5 and 9.8).
///
/// Every data node runs a `volume_keeper` pass from its maintenance loop.
/// The node that leads the catalog group does the placement work:
///
/// - **Seeding.** A replica with no record yet gets the first placement,
///   computed from the settings exactly as each data node computed it at
///   start (`initial_volume_assignments`), so the record says what the
///   replica already uses.
/// - **Replacement.** It asks each segment node for its room (the volume
///   API's `space` op). A segment node that has not answered for
///   `_replace_after_ms` is lost: each volume on it moves to another
///   segment node that answers and holds none of the other replicas'
///   volumes, at the next epoch (`replace_volume`). The record changes by
///   an epoch compare-and-set, so leaders racing each other move a volume
///   once.
///
/// Every node, leader or not, reads its own record from its catalog
/// replica; the pass returns it so the node can see that its volume moved
/// (the node then restarts into the new volume, restoring from a snapshot
/// and its peers).
///
/// Nothing here holds a lock across a proposal; a pass is called from one
/// thread.

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>
#include <kythira/kinesis/kinesis_volumes.hpp>
#include <raft/segment_volume_placement.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kinesis {

/// A segment node's `{capacity, available}` bytes, or nullopt when it does
/// not answer.
using segment_probe = std::function<std::optional<std::pair<std::uint64_t, std::uint64_t>>(
    const kythira::segment_node_info&)>;

struct volume_keeper_config {
    /// The volume id prefix (`volume_id_for`).
    std::string _service = "kinesis";
    /// This node's id, as volume records name replicas.
    std::string _self;
    /// Every data replica that has a volume record: the voters.
    std::vector<std::string> _replicas;
    /// The segment layer from the settings (KINESIS_SEGMENT_NODES).
    std::vector<kythira::segment_node_info> _nodes;
    /// How long a segment node may stay silent before its volumes move.
    std::int64_t _replace_after_ms = 60'000;
    segment_probe _probe;
};

/// What one pass did.
struct volume_keeper_pass {
    /// Records written for replicas that had none.
    std::size_t _seeded = 0;
    /// Volumes moved off a lost segment node.
    std::size_t _replaced = 0;
    /// Volumes on a lost segment node with nowhere to go.
    std::size_t _unplaceable = 0;
    /// Proposals that did not commit (no leader, timeout, a rival won).
    std::size_t _failures = 0;
    /// Whether this node led the catalog group this pass.
    bool _leader = false;
    /// This node's own record as its catalog replica has it after the pass.
    std::optional<kythira::volume_assignment> _self;
};

template<typename Cluster>
requires stream_cluster<Cluster> && leads_keys<Cluster>
class volume_keeper {
public:
    volume_keeper(Cluster& cluster, volume_keeper_config config)
        : _cluster(cluster), _config(std::move(config)) {
        if (!_config._probe) {
            throw std::invalid_argument("volume_keeper: no segment probe");
        }
    }

    /// Every record in this node's catalog replica, in replica order; empty
    /// when this node holds no replica of the catalog.
    [[nodiscard]] auto assignments() -> std::vector<kythira::volume_assignment> {
        std::vector<kythira::volume_assignment> out;
        const auto prefix = volumes_prefix();
        (void)_cluster.read(next_id_key(), [&](const auto& sm) {
            const auto& entries = sm.entries();
            for (auto it = entries.lower_bound(prefix);
                 it != entries.end() && it->first.starts_with(prefix); ++it) {
                if (const auto* v = std::get_if<volume_record>(&it->second)) {
                    out.push_back({._replica = it->first.substr(prefix.size()),
                                   ._segment_node = v->_segment_node,
                                   ._volume = v->_volume,
                                   ._epoch = v->_epoch});
                }
            }
        });
        return out;
    }

    auto pass(std::int64_t now_ms) -> volume_keeper_pass {
        volume_keeper_pass out;
        auto current = assignments();
        if (_cluster.leads(volumes_prefix())) {
            out._leader = true;
            lead(now_ms, current, out);
            current = assignments();
        } else {
            // Whoever leads next starts its own clocks: a silence seen
            // here proves nothing to it.
            _silent_since.clear();
        }
        out._self = kythira::assignment_of(current, _config._self);
        return out;
    }

private:
    void lead(std::int64_t now_ms, std::vector<kythira::volume_assignment> current,
              volume_keeper_pass& out) {
        // Who answers now, with their room for ranking.
        std::vector<kythira::segment_node_info> answering;
        std::set<std::string> lost;
        for (const auto& n : _config._nodes) {
            if (auto space = _config._probe(n)) {
                _silent_since.erase(n._id);
                auto ranked = n;
                ranked._capacity_bytes = space->first;
                ranked._available_bytes = space->second;
                answering.push_back(std::move(ranked));
                continue;
            }
            const auto [it, first] = _silent_since.try_emplace(n._id, now_ms);
            if (now_ms - it->second >= _config._replace_after_ms) {
                lost.insert(n._id);
            }
        }

        // Seeding: the settings' placement, the one every replica opened.
        std::vector<kythira::volume_assignment> initial;
        try {
            initial = kythira::initial_volume_assignments(_config._service, _config._replicas,
                                                          _config._nodes);
        } catch (const std::invalid_argument&) {
            // Settings the config check refused; nothing to seed from.
        }
        for (const auto& a : initial) {
            if (kythira::assignment_of(current, a._replica)) {
                continue;
            }
            if (propose(a, 0)) {
                ++out._seeded;
            } else {
                ++out._failures;
            }
        }

        // Replacement: a volume on a lost segment node, or on one the
        // settings no longer list, moves to one that answers.
        // `current` follows each move, so two volumes leaving one lost node
        // in the same pass never land on the same segment node.
        for (auto& a : current) {
            // A replica a store move took back to its own disk has no
            // volume to lose.
            if (a._segment_node == k_local_store) {
                continue;
            }
            const bool listed =
                kythira::segment_node_of(_config._nodes, a._segment_node).has_value();
            if (listed && !lost.contains(a._segment_node)) {
                continue;
            }
            std::vector<kythira::volume_assignment> peers;
            for (const auto& p : current) {
                if (p._replica != a._replica) {
                    peers.push_back(p);
                }
            }
            auto next = kythira::replace_volume(a, peers, answering);
            if (!next) {
                ++out._unplaceable;
                continue;
            }
            if (propose(*next, a._epoch)) {
                a = *next;
                ++out._replaced;
            } else {
                ++out._failures;
            }
        }
    }

    auto propose(const kythira::volume_assignment& a, std::uint64_t expected) -> bool {
        const volume_assignment_command c{._replica = a._replica,
                                          ._segment_node = a._segment_node,
                                          ._volume = a._volume,
                                          ._expected_epoch = expected,
                                          ._epoch = a._epoch};
        const auto r = _cluster.propose(volume_key(a._replica), encode_command(c), admission::none);
        return r && r->_status == apply_status::ok;
    }

    Cluster& _cluster;
    volume_keeper_config _config;
    /// When each silent segment node was first seen silent, by this leader.
    std::map<std::string, std::int64_t> _silent_since;
};

}  // namespace kythira::kinesis
