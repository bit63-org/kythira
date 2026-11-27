// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_placement.hpp
/// @brief Where a chunk's copies live (.kiro/specs/s3-compatible-storage/
///        task 5, design "Placement"; Requirements 15.1, 15.2 and 15.5).
///
/// Both placements are one `placement_map` with an epoch, as the design
/// asks, so a migration between them is a change of map:
///
/// - **Co-located** (`placement_rule::co_located`, the default). A chunk's
///   copies are the nodes holding the metadata replicas of the group that
///   owns the object, so the copy count is the replica count (15.1). The map
///   names no nodes; the caller passes the owning group's replicas. The
///   write quorum is a majority of them, which for three replicas is the
///   blob pool's default of two.
/// - **Rendezvous** (`placement_rule::rendezvous`). A chunk's copies are
///   chosen from the map's blob nodes by weighted rendezvous hashing of its
///   SHA-256, one per placement group before any group holds two, with the
///   map's copy count and write quorum (15.2). Every node computes the same
///   answer from the map alone, and adding or removing a node moves only the
///   chunks whose top choices change. The map's replication in the catalog
///   and the background move between maps are tasks 12 and 18.
///
/// Erasure coding (15.5) would be a third rule whose copies are shards; the
/// callers see only "these nodes, this quorum".

#include <raft/chunk_store.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

enum class placement_rule : std::uint8_t {
    co_located = 1,
    rendezvous = 2,
};

/// A node that stores chunks under the rendezvous rule.
struct blob_node {
    std::string id;
    /// Failure domain (rack, zone). Copies spread across groups first.
    std::string group;
    /// Relative capacity; a node of weight 2 gets about twice the chunks.
    std::uint32_t weight = 1;

    friend auto operator==(const blob_node&, const blob_node&) -> bool = default;
};

struct placement_map {
    placement_rule rule = placement_rule::co_located;
    std::uint64_t epoch = 0;
    /// Rendezvous only.
    std::vector<blob_node> nodes;
    std::uint32_t copies = 3;
    std::uint32_t write_quorum = 2;

    friend auto operator==(const placement_map&, const placement_map&) -> bool = default;
};

/// The nodes to hold a chunk, most preferred first, and how many durable
/// copies a write needs before its manifest may be committed.
struct chunk_placement {
    std::vector<std::string> nodes;
    std::size_t write_quorum = 0;
};

namespace detail {

/// A uniform value in (0, 1) from SHA-256(chunk || node): the node's
/// rendezvous draw for this chunk.
[[nodiscard]] inline auto rendezvous_draw(const chunk_sha& sha, std::string_view node) -> double {
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int len = 0;
    auto* ctx = ::EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("s3 placement: EVP_MD_CTX_new failed");
    }
    const bool ok = ::EVP_DigestInit_ex(ctx, ::EVP_sha256(), nullptr) == 1 &&
                    ::EVP_DigestUpdate(ctx, sha.data(), sha.size()) == 1 &&
                    ::EVP_DigestUpdate(ctx, node.data(), node.size()) == 1 &&
                    ::EVP_DigestFinal_ex(ctx, md.data(), &len) == 1;
    ::EVP_MD_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("s3 placement: SHA-256 failed");
    }
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        v = (v << 8U) | md.at(i);
    }
    // 53 bits fill a double's mantissa; +0.5 keeps it off both 0 and 1.
    return (static_cast<double>(v >> 11U) + 0.5) / 9007199254740992.0;
}

}  // namespace detail

/// Check a map before it is used or stored.
inline void validate(const placement_map& map) {
    if (map.rule == placement_rule::co_located) {
        return;
    }
    if (map.rule != placement_rule::rendezvous) {
        throw std::invalid_argument("s3 placement: unknown rule");
    }
    if (map.copies == 0 || map.write_quorum == 0 || map.write_quorum > map.copies) {
        throw std::invalid_argument("s3 placement: need 1 <= write quorum <= copies");
    }
    std::set<std::string> ids;
    for (const auto& n : map.nodes) {
        if (n.id.empty() || n.weight == 0 || !ids.insert(n.id).second) {
            throw std::invalid_argument("s3 placement: blob nodes need distinct ids and weights");
        }
    }
    if (map.nodes.size() < map.copies) {
        throw std::invalid_argument("s3 placement: fewer blob nodes than copies");
    }
}

/// Where `sha` goes. `owning_replicas` are the nodes holding the owning
/// group's metadata replicas, leader first if the caller knows it; only the
/// co-located rule reads them.
[[nodiscard]] inline auto place(const placement_map& map, const chunk_sha& sha,
                                std::span<const std::string> owning_replicas) -> chunk_placement {
    if (map.rule == placement_rule::co_located) {
        chunk_placement p;
        p.nodes.assign(owning_replicas.begin(), owning_replicas.end());
        p.write_quorum = p.nodes.size() / 2 + 1;
        if (p.nodes.empty()) {
            throw std::invalid_argument("s3 placement: no replicas to place on");
        }
        return p;
    }
    validate(map);
    // Weighted rendezvous: the score -w / ln(u) gives each node a share of
    // first choices proportional to its weight.
    std::vector<std::pair<double, const blob_node*>> ranked;
    ranked.reserve(map.nodes.size());
    for (const auto& n : map.nodes) {
        const double u = detail::rendezvous_draw(sha, n.id);
        ranked.emplace_back(-static_cast<double>(n.weight) / std::log(u), &n);
    }
    std::ranges::sort(ranked, [](const auto& a, const auto& b) {
        return a.first != b.first ? a.first > b.first : a.second->id < b.second->id;
    });
    chunk_placement p;
    p.write_quorum = map.write_quorum;
    std::set<std::string> groups;
    std::vector<bool> taken(ranked.size(), false);
    // First pass: the best node of each group not yet used.
    for (std::size_t i = 0; i < ranked.size() && p.nodes.size() < map.copies; ++i) {
        if (groups.insert(ranked[i].second->group).second) {
            p.nodes.push_back(ranked[i].second->id);
            taken[i] = true;
        }
    }
    // Fewer groups than copies: fill from the rest, best first.
    for (std::size_t i = 0; i < ranked.size() && p.nodes.size() < map.copies; ++i) {
        if (!taken[i]) {
            p.nodes.push_back(ranked[i].second->id);
        }
    }
    return p;
}

}  // namespace kythira::s3
