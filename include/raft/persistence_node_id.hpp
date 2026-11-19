// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file persistence_node_id.hpp
/// @brief How the text-and-JSON persistence engines store a node id.
///
/// `file_persistence_engine` and `object_store_persistence_engine` keep node
/// ids in two places: a plain-text vote (`voted_for`, or the legacy vote
/// object) and JSON (snapshot member lists, the combined hard-state record).
/// Both engines used to branch on `std::string` versus "everything else",
/// and "everything else" was an integer cast, so a composite cloud id
/// (`.kiro/specs/cloud-composite-node-ids/`) did not compile in either.
///
/// The rule here keeps both existing on-disk formats byte for byte:
///
///   * an unsigned id is a decimal number in text and a JSON integer;
///   * a `std::string` id is its own text and a JSON string, empty included,
///     as before;
///   * a composite id is its canonical text (`node_id_traits::to_text`) and
///     that text as a JSON string, and reading it back goes through the
///     type's strict `parse`, so a value naming another provider, or a
///     malformed one, is refused rather than taken as some other node.
///
/// Integer parsing stays with each engine: the object store's strict decimal
/// parse is part of its rollback guard and is not touched here.

#include <raft/composite_node_id.hpp>

#include <boost/json.hpp>

#include <concepts>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace kythira::persistence_node_id {

/// @brief A textual node id's stored text: the string itself, or a composite
///        id's canonical text.
template<textual_node_id NodeId> [[nodiscard]] auto to_text(const NodeId& id) -> std::string {
    if constexpr (std::same_as<NodeId, std::string>) {
        return id;
    } else {
        return node_id_traits<NodeId>::to_text(id);
    }
}

/// @brief The textual node id @p text names, or `std::nullopt` when a
///        composite type's `parse` refuses it. A `std::string` id accepts any
///        text, as the engines always have.
template<textual_node_id NodeId>
[[nodiscard]] auto from_text(std::string_view text) -> std::optional<NodeId> {
    if constexpr (std::same_as<NodeId, std::string>) {
        return std::string(text);
    } else {
        return node_id_traits<NodeId>::from_text(text);
    }
}

/// @brief A node id as a JSON value: an integer for an unsigned id, a string
///        for a textual one.
template<node_id NodeId> [[nodiscard]] auto to_json(const NodeId& id) -> boost::json::value {
    if constexpr (std::unsigned_integral<NodeId>) {
        return boost::json::value(static_cast<std::uint64_t>(id));
    } else {
        return boost::json::value(boost::json::string(to_text(id)));
    }
}

/// @brief The node id a JSON value holds, or `std::nullopt` when it is the
///        wrong JSON type, out of range, or text the id type refuses.
///
/// An unsigned id accepts whatever `boost::json::value::to_number` converts
/// exactly, which is what the snapshot readers have always accepted.
template<node_id NodeId>
[[nodiscard]] auto from_json(const boost::json::value& v) -> std::optional<NodeId> {
    if constexpr (std::unsigned_integral<NodeId>) {
        boost::system::error_code ec;
        const auto n = v.to_number<NodeId>(ec);
        if (ec) {
            return std::nullopt;
        }
        return n;
    } else {
        if (!v.is_string()) {
            return std::nullopt;
        }
        const auto& s = v.get_string();
        return from_text<NodeId>(std::string_view(s.data(), s.size()));
    }
}

}  // namespace kythira::persistence_node_id
