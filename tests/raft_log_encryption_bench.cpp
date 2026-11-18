// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file raft_log_encryption_bench.cpp
/// @brief What sealing costs a binary Raft log
///        (.kiro/specs/raft-log-encryption/ task 7, requirement 6.3).
///
/// For each command size, the same appends go through a plain engine and a
/// sealing one, each append followed by its durability barrier as the node
/// takes it, and reads of every entry after. Prints appends per second, the
/// p50 and p99 of append plus barrier, and reads per second, plain against
/// sealed. A row per size; nothing is asserted beyond the round trip, since
/// the numbers depend on the disk.
///
/// `KYTHIRA_RLE_BENCH_APPENDS` sets the appends per row (default 2000).

#define BOOST_TEST_MODULE raft_log_encryption_bench
#include <boost/test/unit_test.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/raft_log_encryption.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

namespace fs = std::filesystem;
using engine_t = kythira::binary_file_persistence_engine<>;
using clock_type = std::chrono::steady_clock;

namespace {

struct result {
    double appends_per_s = 0;
    double p50_us = 0;
    double p99_us = 0;
    double reads_per_s = 0;
};

auto appends_per_row() -> std::size_t {
    const char* v = std::getenv("KYTHIRA_RLE_BENCH_APPENDS");  // NOLINT(concurrency-mt-unsafe)
    return v != nullptr ? static_cast<std::size_t>(std::stoul(v)) : std::size_t{2000};
}

auto run(const fs::path& dir, const kythira::binary_file_persistence_options& opts,
         std::size_t size, std::size_t count) -> result {
    fs::remove_all(dir);
    engine_t eng(dir, opts);
    std::vector<std::byte> cmd(size);
    for (std::size_t i = 0; i < size; ++i) {
        cmd[i] = static_cast<std::byte>(i * 31U);
    }
    std::vector<double> lat;
    lat.reserve(count);
    const auto start = clock_type::now();
    for (std::size_t i = 1; i <= count; ++i) {
        kythira::log_entry<> e;
        e._term = 1;
        e._index = i;
        e._command = cmd;
        const auto t0 = clock_type::now();
        eng.barrier_through(eng.append_log_entry_sequenced(e));
        lat.push_back(std::chrono::duration<double, std::micro>(clock_type::now() - t0).count());
    }
    const double append_s = std::chrono::duration<double>(clock_type::now() - start).count();
    const auto rstart = clock_type::now();
    for (std::size_t i = 1; i <= count; ++i) {
        const auto e = eng.get_log_entry(i);
        BOOST_REQUIRE(e && e->command() == cmd);
    }
    const double read_s = std::chrono::duration<double>(clock_type::now() - rstart).count();
    std::sort(lat.begin(), lat.end());
    return result{.appends_per_s = static_cast<double>(count) / append_s,
                  .p50_us = lat[lat.size() / 2],
                  .p99_us = lat[std::min(lat.size() - 1, lat.size() * 99 / 100)],
                  .reads_per_s = static_cast<double>(count) / read_s};
}

}  // namespace

BOOST_AUTO_TEST_CASE(sealed_against_plain, *boost::unit_test::timeout(600)) {
    const auto root =
        fs::temp_directory_path() / ("kythira_rle_bench_" + std::to_string(::getpid()));
    fs::create_directories(root);
    kythira::raft_log_data_key_bytes wk{};
    wk.fill(0x5A);
    auto ring = kythira::raft_log_key_file_ring::open(root / "keys",
                                                      kythira::raft_log_fixed_key_source(wk));
    kythira::binary_file_persistence_options plain;
    kythira::binary_file_persistence_options sealed;
    sealed._key_ring = ring;
    const auto count = appends_per_row();
    std::ostringstream table;
    table << std::fixed << std::setprecision(0)
          << "| command | appends/s plain | sealed | p50 us plain | sealed | p99 us plain | sealed "
             "| reads/s plain | sealed |\n|---|---|---|---|---|---|---|---|---|\n";
    for (const std::size_t size : {64U, 1024U, 16384U, 262144U}) {
        const auto n = size >= 262144U ? std::max<std::size_t>(count / 10, 50) : count;
        const auto p = run(root / "plain", plain, size, n);
        const auto s = run(root / "sealed", sealed, size, n);
        table << "| " << size << " B | " << p.appends_per_s << " | " << s.appends_per_s << " | "
              << p.p50_us << " | " << s.p50_us << " | " << p.p99_us << " | " << s.p99_us << " | "
              << p.reads_per_s << " | " << s.reads_per_s << " |\n";
    }
    BOOST_TEST_MESSAGE("raft log sealing, " << count << " appends per row (barrier per append)\n"
                                            << table.str());
    fs::remove_all(root);
}
