// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file kinesis_volumes.hpp
/// @brief Segment volume assignments in the Kinesis catalog
///        (.kiro/specs/kinesis-independent-layers/ task 10, design "Writer
///        fencing", Requirements 9.4, 9.5 and 9.8).
///
/// A data node without the `segments` role keeps its record segments in a
/// volume on a segment node. Which segment node, and the writer epoch the
/// segment node fences with, is recorded in the catalog so that a change
/// reaches every node through Raft:
///
/// | Key | Holds |
/// |---|---|
/// | `\0meta/kinesis/volumes/(node id)` | a `volume_record` |
///
/// The record changes only by a committed `volume_assignment_command`
/// that names the epoch it expects to replace, so two leaders racing a
/// replacement cannot both win, and an epoch never goes back.

#include <kythira/kinesis/kinesis_catalog.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace kythira::kinesis {

/// Where one data replica's volume is.
struct volume_record {
    /// The segment node holding it (its id in KINESIS_SEGMENT_NODES).
    std::string _segment_node{};
    /// The volume's id on that node.
    std::string _volume{};
    /// The writer epoch; starts at 1 and only rises.
    std::uint64_t _epoch = 0;
    friend auto operator==(const volume_record&, const volume_record&) -> bool = default;
};

[[nodiscard]] inline auto volumes_prefix() -> std::string {
    return catalog_prefix() + "volumes/";
}

[[nodiscard]] inline auto volume_key(std::string_view replica) -> std::string {
    return volumes_prefix() + std::string(replica);
}

/// A replica id a volume key can hold: 1 to 128 bytes, no '/' and no
/// control characters.
[[nodiscard]] inline auto valid_volume_replica(std::string_view s) -> bool {
    if (s.empty() || s.size() > 128) {
        return false;
    }
    for (const char c : s) {
        if (c == '/' || static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
            return false;
        }
    }
    return true;
}

inline auto encode(codec::writer& w, const volume_record& v) -> void {
    w.str(v._segment_node).str(v._volume).u64(v._epoch);
}

[[nodiscard]] inline auto decode_volume_record(codec::reader& r) -> volume_record {
    volume_record v;
    v._segment_node = r.str();
    v._volume = r.str();
    v._epoch = r.u64();
    return v;
}

}  // namespace kythira::kinesis
