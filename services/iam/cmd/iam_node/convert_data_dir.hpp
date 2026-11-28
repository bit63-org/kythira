// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file convert_data_dir.hpp
/// @brief `iam_node --convert-data-dir`: moves a member's Raft state from
///        the plain Raft group iam_node ran before
///        (.kiro/specs/service-colocation/ task 8b) into the IAM group on
///        the multi-raft host (iam_raft.hpp).
///
/// The old layout is file_persistence_engine's, directly in --data-dir:
/// `term`, `voted_for`, `log` and `snapshot`. The new one is
/// binary_file_persistence_engine's, in `raft/<k_iam_group_id>/`. The state
/// machine, the node ids and the entries are the same in both, so the
/// conversion copies the member's whole Raft state rather than only its
/// latest snapshot: the snapshot, every entry after it (committed or not,
/// exactly as Raft left them, so nothing a quorum acknowledged is lost),
/// and the term and vote. Each member is converted on its own, with the
/// whole cluster stopped; afterwards they elect as before, and every
/// replica follows the new group once its front end runs the new build.
///
/// The old files move to `pre-host/` under --data-dir, so a member can be
/// rolled back by moving them back with the previous binary. A data
/// directory already converted is left alone.

#include <kythira/iam/iam_raft.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/file_persistence.hpp>
#include <raft/host_node_id.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

namespace iam_node {

/// The files the plain Raft group kept directly in the data directory.
inline constexpr const char* k_old_layout_files[] = {"term", "voted_for", "log", "snapshot"};

/// Whether `data_dir` holds the plain Raft group's state and nothing has
/// converted it yet: iam_node refuses to start on one rather than start an
/// empty group beside it.
[[nodiscard]] inline auto has_unconverted_state(const std::filesystem::path& data_dir) -> bool {
    std::error_code ec;
    if (std::filesystem::exists(kythira::iam::iam_raft_dir(data_dir), ec)) {
        return false;
    }
    for (const auto* name : k_old_layout_files) {
        if (std::filesystem::exists(data_dir / name, ec)) {
            return true;
        }
    }
    return false;
}

/// What a conversion copied.
struct conversion_summary {
    std::uint64_t snapshot_index = 0;
    std::uint64_t first_entry = 0;
    std::uint64_t last_entry = 0;
    std::uint64_t term = 0;
};

/// Converts `data_dir` in place. The new log is written with
/// `log_options`, so a node that seals its Raft logs at rest
/// (`.kiro/specs/raft-log-encryption/`) starts on a sealed log rather than
/// on plaintext waiting for compaction.
/// @throws std::runtime_error when there is nothing to convert, it was
///         converted already, or a file cannot be read or written; a
///         failure before the old files move leaves them untouched.
inline auto convert_data_dir(const std::filesystem::path& data_dir,
                             const kythira::binary_file_persistence_options& log_options = {})
    -> conversion_summary {
    using node_id = kythira::host_node_id;
    if (std::filesystem::exists(kythira::iam::iam_raft_dir(data_dir))) {
        throw std::runtime_error(data_dir.string() +
                                 " is already converted: it has a raft/ directory");
    }
    if (!has_unconverted_state(data_dir)) {
        throw std::runtime_error(data_dir.string() + " holds no iam_node Raft state to convert");
    }

    conversion_summary out;
    // A staging directory beside the target, renamed into place once
    // complete, so an interrupted conversion leaves no raft/ that a start
    // would take for a converted one.
    const auto staging = data_dir / "raft.converting";
    std::filesystem::remove_all(staging);
    {
        kythira::file_persistence_engine<node_id> old(data_dir);
        kythira::binary_file_persistence_engine<node_id> fresh(
            staging / std::to_string(kythira::iam::k_iam_group_id), log_options);

        const auto snap = old.load_snapshot();
        if (snap) {
            fresh.save_snapshot(*snap);
            out.snapshot_index = snap->_last_included_index;
        }
        const auto last = old.get_last_log_index();
        kythira::write_sequence seq{};
        for (std::uint64_t i = out.snapshot_index + 1; i <= last; ++i) {
            auto entry = old.get_log_entry(i);
            if (!entry) {
                if (out.first_entry == 0) {
                    continue;  // compacted below the snapshot's successor
                }
                throw std::runtime_error("the iam_node log has a gap at index " +
                                         std::to_string(i));
            }
            seq = fresh.append_log_entry_sequenced(*entry);
            if (out.first_entry == 0) {
                out.first_entry = i;
            }
            out.last_entry = i;
        }
        if (out.last_entry != 0) {
            fresh.barrier_through(seq);
        }
        out.term = old.load_current_term();
        fresh.save_hard_state(out.term, old.load_voted_for());
    }
    std::filesystem::rename(staging, kythira::iam::iam_raft_dir(data_dir));

    const auto backup = data_dir / "pre-host";
    std::filesystem::create_directories(backup);
    for (const auto* name : k_old_layout_files) {
        if (std::filesystem::exists(data_dir / name)) {
            std::filesystem::rename(data_dir / name, backup / name);
        }
    }
    return out;
}

}  // namespace iam_node
