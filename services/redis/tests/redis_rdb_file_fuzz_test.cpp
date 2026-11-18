// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_rdb_file_fuzz_test.cpp
/// @brief Seeded mutations of real RDB files through the reader
///        (.kiro/specs/redis-migration-tooling/ task 1; design "Testing
///        strategy": fuzzing the parser).
///
/// The seeds are the server-written files in `golden/rdb/` (every value
/// encoding of Redis 7.2-8.4 and Valkey 7.2-9.0) plus the writer's own.
/// Each mutation flips a bit, sets a byte, cuts the file, inserts random
/// bytes, duplicates a range or splices bytes from another seed. For every
/// input:
///
/// - the reader either returns records up to `rdb_eof` or throws
///   `rdb_error`; nothing else escapes, and the sanitizer legs run this
///   test, so nothing reads or writes out of bounds;
/// - a value-size limit is honoured (no payload grows past it);
/// - whatever reads successfully (checksum verification off, so mutations
///   that keep the structure get through) is written back at the same
///   format and reads back as the same records.
///
/// LZF gets its own random inputs: decompression of garbage never
/// overruns, and compression round trips.
///
/// KYTHIRA_RDB_FUZZ_ITERATIONS overrides the count (default 20000).

#define BOOST_TEST_MODULE redis_rdb_file_fuzz_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_rdb_file.hpp>
#include <kythira/redis/redis_rdb_lzf.hpp>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#ifndef KYTHIRA_REDIS_RDB_GOLDEN_DIR
#error "KYTHIRA_REDIS_RDB_GOLDEN_DIR must name services/redis/tests/golden/rdb"
#endif

namespace {

using namespace kythira;

auto iterations() -> int {
    if (const char* v = std::getenv("KYTHIRA_RDB_FUZZ_ITERATIONS")) {
        return std::atoi(v);
    }
    return 20000;
}

auto seeds() -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& e : std::filesystem::directory_iterator(KYTHIRA_REDIS_RDB_GOLDEN_DIR)) {
        if (e.path().extension() == ".rdb") {
            std::ifstream in(e.path(), std::ios::binary);
            std::ostringstream ss;
            ss << in.rdbuf();
            out.push_back(ss.str());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

auto mutate(std::string in, const std::vector<std::string>& pool, std::mt19937_64& rng)
    -> std::string {
    auto pick = [&](std::size_t n) {
        return n == 0 ? std::size_t{0} : static_cast<std::size_t>(rng() % n);
    };
    // Several small mutations at once reach states one mutation cannot.
    const std::size_t count = 1 + pick(3);
    for (std::size_t m = 0; m < count; ++m) {
        switch (pick(6)) {
            case 0:
                if (!in.empty()) {
                    const std::size_t at = pick(in.size());
                    in[at] =
                        static_cast<char>(static_cast<unsigned char>(in[at]) ^ (1U << pick(8)));
                }
                break;
            case 1:
                if (!in.empty()) {
                    in[pick(in.size())] = static_cast<char>(rng());
                }
                break;
            case 2:
                in.resize(pick(in.size() + 1));
                break;
            case 3: {
                std::string ins(1 + pick(16), '\0');
                for (auto& ch : ins) {
                    ch = static_cast<char>(rng());
                }
                in.insert(pick(in.size() + 1), ins);
                break;
            }
            case 4:
                if (!in.empty()) {
                    const std::size_t at = pick(in.size());
                    const std::size_t len = std::min<std::size_t>(1 + pick(64), in.size() - at);
                    in.insert(pick(in.size() + 1), in.substr(at, len));
                }
                break;
            default: {
                const std::string& other = pool[pick(pool.size())];
                if (!other.empty() && !in.empty()) {
                    const std::size_t at = pick(other.size());
                    const std::size_t len = std::min<std::size_t>(1 + pick(256), other.size() - at);
                    const std::size_t to = pick(in.size());
                    in.replace(to, std::min(len, in.size() - to), other.substr(at, len));
                }
                break;
            }
        }
    }
    return in;
}

}  // namespace

BOOST_AUTO_TEST_CASE(mutated_files_read_or_fail_cleanly) {
    const auto pool = seeds();
    BOOST_REQUIRE_GE(pool.size(), 18U);
    std::mt19937_64 rng(0x5244420a);
    const int n = iterations();
    int clean_reads = 0;
    int round_trips = 0;
    for (int i = 0; i < n; ++i) {
        const std::string input =
            mutate(pool[static_cast<std::size_t>(rng() % pool.size())], pool, rng);
        rdb_reader_options o;
        o._verify_checksum = (i % 2) == 0;
        o._max_value_bytes = 64U * 1024U;
        o._max_string_bytes = 64U * 1024U;
        std::vector<rdb_record> recs;
        rdb_format format;
        try {
            rdb_memory_source src(input);
            rdb_reader r(src, o);
            format = r.format();
            while (auto rec = r.next()) {
                if (const auto* k = std::get_if<rdb_key>(&*rec)) {
                    BOOST_REQUIRE_LE(k->_payload.size(), o._max_value_bytes);
                }
                recs.push_back(std::move(*rec));
            }
        } catch (const rdb_error&) {
            continue;
        }
        ++clean_reads;
        // What reads writes back and reads the same (when the mutation left
        // only records the writer accepts at this format).
        rdb_string_sink sink;
        try {
            rdb_writer w(sink, format);
            bool all = true;
            for (const auto& r : recs) {
                all = w.write(r) && all;
            }
            if (!all) {
                continue;
            }
        } catch (const rdb_error&) {
            continue;  // e.g. SLOT_INFO spliced into an RDB 11 file
        }
        rdb_memory_source src2(sink.str());
        rdb_reader r2(src2, o);
        std::vector<rdb_record> back;
        while (auto rec = r2.next()) {
            back.push_back(std::move(*rec));
        }
        BOOST_REQUIRE_EQUAL(back.size(), recs.size());
        for (std::size_t j = 0; j + 1 < recs.size(); ++j) {
            BOOST_REQUIRE(back[j] == recs[j]);
        }
        ++round_trips;
    }
    BOOST_TEST_MESSAGE(clean_reads << " of " << n << " mutated files read cleanly, " << round_trips
                                   << " round-tripped");
    // The mutations are not all fatal: some reach the end of the file.
    BOOST_TEST(clean_reads > 0);
}

BOOST_AUTO_TEST_CASE(lzf_never_overruns_on_garbage) {
    std::mt19937_64 rng(0x4c5a46);
    const int n = iterations();
    for (int i = 0; i < n; ++i) {
        std::vector<std::uint8_t> in(rng() % 64);
        for (auto& b : in) {
            b = static_cast<std::uint8_t>(rng());
        }
        const std::size_t out_len = rng() % 512;
        if (const auto out = rdb_lzf_decompress(in, out_len)) {
            BOOST_REQUIRE_EQUAL(out->size(), out_len);
        }
        std::string plain(rng() % 2048, '\0');
        const unsigned alphabet = 1U + static_cast<unsigned>(rng() % 8);
        for (auto& ch : plain) {
            ch = static_cast<char>('a' + rng() % alphabet);
        }
        if (const auto c = rdb_lzf_compress(plain)) {
            const auto d = rdb_lzf_decompress(
                {reinterpret_cast<const std::uint8_t*>(c->data()), c->size()}, plain.size());
            BOOST_REQUIRE(d.has_value());
            BOOST_REQUIRE(*d == plain);
        }
    }
}
