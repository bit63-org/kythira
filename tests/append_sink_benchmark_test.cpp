// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file append_sink_benchmark_test.cpp
/// @brief The append sink's benchmark rows (.kiro/specs/khold-block-service/
///        task 3): what an append costs on an engine without a sink, through
///        the adaptor with a sink that takes nothing, and through the adaptor
///        with a sink that takes the payload.
///
/// The first row is the one task 3 asks for. A node without a sink does not
/// instantiate `append_sink_persistence` at all, so its append is the engine's
/// own call, unchanged; the row records that cost so later rows (and later
/// changes) have the baseline beside them. The second row prices the
/// adaptor itself, and the third what khold's shape adds: a payload moved
/// into the sink and a small descriptor stored instead.
///
/// Labelled `benchmark;performance`, which ci.yml's ctest filter excludes:
/// the numbers are for reading, not for a gate on a shared runner. Each row
/// is the median of seven runs of 20,000 appends of 4 KiB commands.

#define BOOST_TEST_MODULE append_sink_benchmark_test
#include <boost/test/unit_test.hpp>

#include <raft/append_sink.hpp>
#include <raft/persistence.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace {

using entry_t = kythira::log_entry<std::uint64_t, std::uint64_t>;
using mem_engine = kythira::memory_persistence_engine<>;

constexpr std::size_t appends = 20000;
constexpr std::size_t command_size = 4096;
constexpr int runs = 7;

// Returns entries as they are: the adaptor's own overhead.
struct identity_sink {
    auto on_append(const entry_t& e) -> entry_t { return e; }
    auto has_payload(const entry_t&) -> bool { return true; }
    auto rehydrate(const entry_t& e) -> std::optional<entry_t> { return e; }
    auto sync() -> void {}
    auto on_truncate(std::uint64_t) -> void {}
    auto release_before(std::uint64_t) -> void {}
};

// Moves the payload into its own store and returns an 8-byte descriptor,
// the shape khold's block store has.
struct taking_sink {
    std::map<std::uint64_t, std::vector<std::byte>> payloads;
    auto on_append(const entry_t& e) -> entry_t {
        payloads.emplace(e.index(), e.command());
        entry_t d{._term = e.term(), ._index = e.index(), ._command = {}, ._type = e.type()};
        d._command.resize(8);
        return d;
    }
    auto has_payload(const entry_t& e) -> bool { return payloads.contains(e.index()); }
    auto rehydrate(const entry_t& e) -> std::optional<entry_t> {
        auto it = payloads.find(e.index());
        if (it == payloads.end()) {
            return std::nullopt;
        }
        auto f = e;
        f._command = it->second;
        return f;
    }
    auto sync() -> void {}
    auto on_truncate(std::uint64_t from) -> void {
        payloads.erase(payloads.lower_bound(from), payloads.end());
    }
    auto release_before(std::uint64_t before) -> void {
        payloads.erase(payloads.begin(), payloads.lower_bound(before));
    }
};

auto entries() -> std::vector<entry_t> {
    std::vector<entry_t> out;
    out.reserve(appends);
    for (std::size_t i = 1; i <= appends; ++i) {
        out.push_back(entry_t{._term = 1,
                              ._index = i,
                              ._command = std::vector<std::byte>(command_size, std::byte{1}),
                              ._type = kythira::entry_type::normal});
    }
    return out;
}

template<typename MakeEngine> auto ns_per_append(MakeEngine make) -> double {
    const auto input = entries();
    std::vector<double> samples;
    for (int r = 0; r < runs; ++r) {
        auto engine = make();
        const auto start = std::chrono::steady_clock::now();
        for (const auto& e : input) {
            (void)engine.append_log_entry_sequenced(e);
        }
        engine.barrier_through(engine.durable_through());
        const auto ns =
            std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - start)
                .count();
        samples.push_back(ns / static_cast<double>(appends));
    }
    std::ranges::sort(samples);
    return samples[samples.size() / 2];
}

}  // namespace

BOOST_AUTO_TEST_CASE(append_cost_rows) {
    const auto bare = ns_per_append([] { return mem_engine{}; });
    const auto identity = ns_per_append([] {
        return kythira::append_sink_persistence<mem_engine, identity_sink>{
            mem_engine{}, std::make_shared<identity_sink>()};
    });
    const auto taking = ns_per_append([] {
        return kythira::append_sink_persistence<mem_engine, taking_sink>{
            mem_engine{}, std::make_shared<taking_sink>()};
    });
    std::cout << "append_sink rows (memory engine, 4 KiB commands, ns per append, median of "
              << runs << "):\n"
              << "  no sink (engine alone, what a node without a sink runs): " << bare << "\n"
              << "  adaptor, identity sink: " << identity << "\n"
              << "  adaptor, payload-taking sink: " << taking << "\n";
    BOOST_TEST(bare > 0.0);
}
