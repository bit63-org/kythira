// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_kv_v3_codec_fuzz_test.cpp
/// @brief Seeded fuzzing of the format-0x03 log records
///        (.kiro/specs/redis-general-data-types/ task 1, Requirement 14.1).
///
/// A replica decodes whatever the log holds, so the decoder must never read
/// out of bounds, allocate from an untrusted count, or accept a buffer two
/// replicas could read differently. The properties checked here:
///
/// - every generated record survives encode/decode unchanged;
/// - every mutation of a valid encoding (bit flips, truncation, inserted and
///   deleted bytes, overwritten length fields, random buffers) either throws
///   `redis_kv_codec_error` or decodes to a record whose encoding is exactly
///   the mutated buffer, so the decoder accepts only canonical bytes;
/// - the 0x01/0x02 decoder refuses every 0x03 record and the 0x03 decoder
///   every 0x01/0x02 record;
/// - `redis_kv_command_key` and `peek_redis_kv_opcode` never throw.
///
/// The seed is fixed so a failure reproduces; KYTHIRA_FUZZ_SEED overrides it
/// and KYTHIRA_FUZZ_ITERATIONS scales the run.

#define BOOST_TEST_MODULE redis_kv_v3_codec_fuzz_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_kv_commands.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

namespace {

using namespace kythira;

auto env_u64(const char* name, std::uint64_t fallback) -> std::uint64_t {
    const char* v = std::getenv(name);  // NOLINT(concurrency-mt-unsafe): read once at start
    return v != nullptr && *v != '\0' ? std::strtoull(v, nullptr, 10) : fallback;
}

class generator {
public:
    explicit generator(std::uint64_t seed) : _rng(seed) {}

    auto below(std::uint64_t n) -> std::uint64_t {
        return std::uniform_int_distribution<std::uint64_t>(0, n - 1)(_rng);
    }

    auto string(std::size_t max_len = 24) -> std::string {
        std::string s(below(max_len + 1), '\0');
        for (auto& c : s) {
            c = static_cast<char>(below(256));
        }
        return s;
    }

    auto strings(std::size_t max_n) -> std::vector<std::string> {
        std::vector<std::string> out(below(max_n + 1));
        for (auto& s : out) {
            s = string();
        }
        return out;
    }

    auto record() -> redis_kv_v3_command {
        switch (below(4)) {
            case 0: {
                redis_kv_exec_command c;
                c._key = string();
                c._command_id = static_cast<std::uint16_t>(below(65536));
                c._now_ms = _rng();
                c._policy = static_cast<std::uint8_t>(below(2));
                c._args = strings(8);
                c._mutable_keys.resize(below(4));
                for (auto& b : c._mutable_keys) {
                    b = static_cast<std::byte>(below(256));
                }
                return c;
            }
            case 1:
                return redis_kv_range_delete_command{string(), string(), string(),
                                                     static_cast<std::uint32_t>(_rng())};
            case 2:
                return redis_kv_format_gate_command{string(),
                                                    static_cast<std::uint16_t>(below(65536))};
            default:
                return redis_kv_remove_members_command{string(), strings(8)};
        }
    }

    /// One random change to a valid encoding.
    auto mutate(std::vector<std::byte> bytes) -> std::vector<std::byte> {
        switch (below(6)) {
            case 0:  // flip one bit
                if (!bytes.empty()) {
                    bytes[below(bytes.size())] ^= static_cast<std::byte>(1U << below(8));
                }
                break;
            case 1:  // truncate
                bytes.resize(below(bytes.size() + 1));
                break;
            case 2:  // insert a byte
                bytes.insert(bytes.begin() + static_cast<std::ptrdiff_t>(below(bytes.size() + 1)),
                             static_cast<std::byte>(below(256)));
                break;
            case 3:  // delete a byte
                if (!bytes.empty()) {
                    bytes.erase(bytes.begin() + static_cast<std::ptrdiff_t>(below(bytes.size())));
                }
                break;
            case 4:  // overwrite four bytes, often a length or count field, with a big value
                if (bytes.size() >= 4) {
                    const auto at = below(bytes.size() - 3);
                    const auto v = below(2) == 0 ? 0xFFFFFFFFU : static_cast<std::uint32_t>(_rng());
                    for (int i = 0; i < 4; ++i) {
                        bytes[at + static_cast<std::size_t>(i)] =
                            static_cast<std::byte>((v >> (24 - (8 * i))) & 0xFFU);
                    }
                }
                break;
            default:  // a random buffer that keeps the 0x03 version byte
                bytes.assign(below(48), std::byte{0});
                for (auto& b : bytes) {
                    b = static_cast<std::byte>(below(256));
                }
                if (!bytes.empty()) {
                    bytes[0] = std::byte{redis_kv_format_version_3};
                }
                break;
        }
        return bytes;
    }

private:
    std::mt19937_64 _rng;
};

const std::uint64_t k_seed = env_u64("KYTHIRA_FUZZ_SEED", 0x6b797468697261ULL);
const std::uint64_t k_iterations = env_u64("KYTHIRA_FUZZ_ITERATIONS", 20000);

}  // namespace

BOOST_AUTO_TEST_CASE(generated_records_round_trip, *boost::unit_test::timeout(120)) {
    generator g(k_seed);
    for (std::uint64_t i = 0; i < k_iterations; ++i) {
        const auto rec = g.record();
        const auto bytes = encode_redis_kv_command(rec);
        BOOST_REQUIRE_MESSAGE(decode_redis_kv_v3_command(bytes) == rec,
                              "seed " << k_seed << " iteration " << i);
        BOOST_REQUIRE(peek_redis_kv_opcode(bytes).has_value());
    }
}

BOOST_AUTO_TEST_CASE(mutations_are_refused_or_canonical, *boost::unit_test::timeout(300)) {
    generator g(k_seed + 1);
    std::uint64_t refused = 0;
    std::uint64_t accepted = 0;
    for (std::uint64_t i = 0; i < k_iterations; ++i) {
        auto bytes = encode_redis_kv_command(g.record());
        const auto rounds = 1 + g.below(3);
        for (std::uint64_t r = 0; r < rounds; ++r) {
            bytes = g.mutate(std::move(bytes));
        }
        (void)redis_kv_command_key(bytes);  // must not throw
        (void)peek_redis_kv_opcode(bytes);
        try {
            const auto rec = decode_redis_kv_v3_command(bytes);
            ++accepted;
            BOOST_REQUIRE_MESSAGE(
                encode_redis_kv_command(rec) == bytes,
                "a non-canonical buffer decoded, seed " << k_seed << " iteration " << i);
        } catch (const redis_kv_codec_error&) {
            ++refused;
        }
    }
    // Both outcomes occur, so the mutations reach past the first check.
    BOOST_CHECK_GT(refused, 0U);
    BOOST_CHECK_GT(accepted, 0U);
}

BOOST_AUTO_TEST_CASE(the_two_decoders_keep_to_their_versions, *boost::unit_test::timeout(60)) {
    generator g(k_seed + 2);
    for (std::uint64_t i = 0; i < 1000; ++i) {
        const auto v3 = encode_redis_kv_command(g.record());
        BOOST_CHECK_THROW((void)decode_redis_kv_command(v3), redis_kv_codec_error);
    }
    const std::vector<redis_kv_command> old{
        redis_kv_set_command{"k", {std::byte{1}}, 0},
        redis_kv_del_command{"k"},
        redis_kv_sweep_command{{{"k", 5}}},
        redis_kv_evict_command{{"k"}},
        redis_kv_put_chunk_command{"k", {}, {}},
        redis_kv_commit_command{"k", 0, 0, {}, {}},
        redis_kv_touch_command{{"k"}},
    };
    for (const auto& c : old) {
        const auto bytes = encode_redis_kv_command(c);
        BOOST_CHECK(!is_redis_kv_v3_record(bytes));
        BOOST_CHECK_THROW((void)decode_redis_kv_v3_command(bytes), redis_kv_codec_error);
    }
}

// The reserved script opcode and unknown policy bits are refused, and a
// record never routes anywhere but its header key.
BOOST_AUTO_TEST_CASE(reserved_and_unknown_fields_are_refused, *boost::unit_test::timeout(30)) {
    auto gate = encode_redis_kv_command(redis_kv_format_gate_command{"g", 1});
    BOOST_CHECK_EQUAL(redis_kv_command_key(gate), "g");
    gate[1] = std::byte{static_cast<std::uint8_t>(redis_kv_opcode::script)};
    BOOST_CHECK_THROW((void)decode_redis_kv_v3_command(gate), redis_kv_codec_error);
    BOOST_CHECK(!peek_redis_kv_opcode(gate).has_value());
    gate[1] = std::byte{static_cast<std::uint8_t>(redis_kv_opcode::set)};
    BOOST_CHECK_THROW((void)decode_redis_kv_v3_command(gate), redis_kv_codec_error);

    redis_kv_exec_command exec{"k", 1, 2, 0, {"k"}, {}};
    auto bytes = encode_redis_kv_command(exec);
    // byte 0 version, 1 opcode, 2-5 key length, 6 key, 7-8 id, 9-16 now, 17 policy
    bytes[17] = std::byte{0x02};
    BOOST_CHECK_THROW((void)decode_redis_kv_v3_command(bytes), redis_kv_codec_error);
    exec._policy = 0x80;
    BOOST_CHECK_THROW((void)encode_redis_kv_command(exec), redis_kv_codec_error);
}
