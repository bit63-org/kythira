// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_cluster.hpp
/// @brief What the SQS handlers need from the data layer
///        (`.kiro/specs/sqs-compatible-queues/` task 4).
///
/// The handlers commit catalog and partition entries in whichever group
/// owns a key and read the owning group's state; `queue_cluster` is that
/// surface. The daemon implements it over its `multi_raft` host (task 10
/// adds the remote and hybrid forms); `local_queue_cluster` implements it
/// over one in-process state machine holding every key, for tests and a
/// single-node development mode.

#include <kythira/sqs/sqs_queue_state_machine.hpp>

#include <raft/memory_kv_engine.hpp>

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::sqs {

/// - `propose(key, entry)`: commit `entry` (an encoded `queue_command` or
///   `catalog_command`) in the group owning `key` and return what `apply()`
///   returned, or nullopt when it could not be committed in time (no
///   leader, timeout). A nullopt is ambiguous: the entry may still commit.
/// - `read(key, f)`: run `f` on the state machine of the group owning
///   `key`, as this node's replica has it; false when this node cannot.
/// - `now_ms()`: the clock leaders stamp entries with (Requirement 5.4).
template<typename C>
concept queue_cluster = requires(C& c, const std::string& key, std::vector<std::byte> entry,
                                 std::function<void(const typename C::state_machine_type&)> f) {
    { c.propose(key, std::move(entry)) } -> std::same_as<std::optional<std::vector<std::byte>>>;
    { c.read(key, f) } -> std::same_as<bool>;
    { c.now_ms() } -> std::same_as<std::uint64_t>;
};

/// Every key in one state machine on one `memory_kv_engine`, behind one
/// mutex: entries commit in call order, reads see every committed entry.
class local_queue_cluster {
public:
    using state_machine_type = sqs_queue_state_machine<memory_kv_engine>;
    using clock_fn = std::function<std::uint64_t()>;

    explicit local_queue_cluster(clock_fn clock = system_clock_ms)
        : _clock(std::move(clock)), _engine(std::make_unique<memory_kv_engine>()) {
        _sm.open(*_engine, key_range{"", std::nullopt});
    }

    auto propose(const std::string& /*key*/, std::vector<std::byte> entry)
        -> std::optional<std::vector<std::byte>> {
        const std::scoped_lock lock(_mutex);
        return _sm.apply(entry, ++_index);
    }

    auto read(const std::string& /*key*/, const std::function<void(const state_machine_type&)>& f)
        -> bool {
        const std::scoped_lock lock(_mutex);
        f(_sm);
        return true;
    }

    [[nodiscard]] auto now_ms() -> std::uint64_t { return _clock(); }

    [[nodiscard]] static auto system_clock_ms() -> std::uint64_t {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

private:
    clock_fn _clock;
    std::unique_ptr<memory_kv_engine> _engine;
    state_machine_type _sm;
    std::uint64_t _index = 0;
    std::mutex _mutex;
};

static_assert(queue_cluster<local_queue_cluster>);

}  // namespace kythira::sqs
