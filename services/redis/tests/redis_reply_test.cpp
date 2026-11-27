// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_reply_test.cpp
/// @brief The typed reply tree (.kiro/specs/redis-general-data-types/
///        design Component 2, task 3): RESP2 and RESP3 rendering against the
///        bytes Redis sends, and a seeded fuzz of the binary codec a data
///        node uses to send replies to a front end.
///
/// The codec properties match the 0x03 log codec's: every generated reply
/// survives encode/decode unchanged, and every mutation of a valid encoding
/// either throws `redis_reply_error` or decodes to a reply whose encoding is
/// exactly the mutated buffer. KYTHIRA_FUZZ_SEED and KYTHIRA_FUZZ_ITERATIONS
/// override the seed and the run length.

#define BOOST_TEST_MODULE redis_reply_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_reply.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

namespace {

using kythira::redis_reply;
using kythira::redis_reply_error;
using kythira::render_redis_reply;

auto both(const redis_reply& r) -> std::pair<std::string, std::string> {
    return {render_redis_reply(r, 2), render_redis_reply(r, 3)};
}

/// The reply renders as `resp2` on a RESP2 connection and `resp3` on RESP3.
auto expect(const redis_reply& r, const std::string& resp2, const std::string& resp3) -> void {
    const auto [two, three] = both(r);
    BOOST_CHECK_EQUAL(two, resp2);
    BOOST_CHECK_EQUAL(three, resp3);
}

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

    auto bytes(std::size_t max_len = 12) -> std::string {
        std::string s(below(max_len + 1), '\0');
        for (auto& c : s) {
            c = static_cast<char>(below(256));
        }
        return s;
    }

    auto line(std::size_t max_len = 12) -> std::string {
        std::string s(below(max_len + 1), '\0');
        for (auto& c : s) {
            c = static_cast<char>(' ' + below(95));
        }
        return s;
    }

    auto reply(int depth = 0) -> redis_reply {
        const auto pick = below(depth >= 3 ? 9 : 12);
        switch (pick) {
            case 0:
                return redis_reply::simple(line());
            case 1:
                return redis_reply::error("ERR " + line());
            case 2:
                return redis_reply::integer(static_cast<std::int64_t>(_rng()));
            case 3:
                return redis_reply::bulk(bytes());
            case 4:
                return below(2) == 0 ? redis_reply::null() : redis_reply::null_array();
            case 5:
                return redis_reply::double_value(
                    std::to_string(static_cast<double>(below(1000)) / 8));
            case 6:
                return redis_reply::boolean(below(2) == 1);
            case 7:
                return redis_reply::verbatim(below(2) == 0 ? "txt" : "mkd", bytes());
            case 8:
                return redis_reply::big_number((below(2) == 0 ? "-" : "") +
                                               std::to_string(1 + below(1000000)));
            default: {
                std::vector<redis_reply> elements(below(4));
                for (auto& e : elements) {
                    e = reply(depth + 1);
                }
                if (pick == 9) {
                    return redis_reply::array(std::move(elements));
                }
                if (pick == 10) {
                    return redis_reply::set(std::move(elements));
                }
                if (elements.size() % 2 != 0) {
                    elements.pop_back();
                }
                return redis_reply::map(std::move(elements));
            }
        }
    }

    auto mutate(std::vector<std::byte> b) -> std::vector<std::byte> {
        switch (below(5)) {
            case 0:
                if (!b.empty()) {
                    b[below(b.size())] ^= static_cast<std::byte>(1U << below(8));
                }
                break;
            case 1:
                b.resize(below(b.size() + 1));
                break;
            case 2:
                b.insert(b.begin() + static_cast<std::ptrdiff_t>(below(b.size() + 1)),
                         static_cast<std::byte>(below(256)));
                break;
            case 3:
                if (!b.empty()) {
                    b.erase(b.begin() + static_cast<std::ptrdiff_t>(below(b.size())));
                }
                break;
            default:
                if (b.size() >= 4) {
                    const auto at = below(b.size() - 3);
                    for (std::size_t i = 0; i < 4; ++i) {
                        b[at + i] = std::byte{0xFF};
                    }
                }
                break;
        }
        return b;
    }

private:
    std::mt19937_64 _rng;
};

const std::uint64_t k_seed = env_u64("KYTHIRA_FUZZ_SEED", 0x7265706c79ULL);
const std::uint64_t k_iterations = env_u64("KYTHIRA_FUZZ_ITERATIONS", 20000);

}  // namespace

// The bytes Redis 7.2 sends for each kind, in both protocols.
BOOST_AUTO_TEST_CASE(rendering_matches_redis) {
    expect(redis_reply::simple("OK"), "+OK\r\n", "+OK\r\n");
    const std::string wrongtype =
        "WRONGTYPE Operation against a key holding the wrong kind of value";
    expect(redis_reply::error(wrongtype), "-" + wrongtype + "\r\n", "-" + wrongtype + "\r\n");
    expect(redis_reply::integer(-7), ":-7\r\n", ":-7\r\n");
    const std::string nul("$3\r\na\0b\r\n", 9);
    expect(redis_reply::bulk(std::string("a\0b", 3)), nul, nul);
    expect(redis_reply::null(), "$-1\r\n", "_\r\n");
    expect(redis_reply::null_array(), "*-1\r\n", "_\r\n");
    expect(redis_reply::double_value("3.5"), "$3\r\n3.5\r\n", ",3.5\r\n");
    expect(redis_reply::double_value("inf"), "$3\r\ninf\r\n", ",inf\r\n");
    expect(redis_reply::boolean(true), ":1\r\n", "#t\r\n");
    expect(redis_reply::boolean(false), ":0\r\n", "#f\r\n");
    expect(redis_reply::verbatim("txt", "hi"), "$2\r\nhi\r\n", "=6\r\ntxt:hi\r\n");
    expect(redis_reply::big_number("-12345678901234567890"), "$21\r\n-12345678901234567890\r\n",
           "(-12345678901234567890\r\n");
    const auto map = redis_reply::map({redis_reply::bulk("f"), redis_reply::bulk("v"),
                                       redis_reply::bulk("g"), redis_reply::null()});
    expect(map, "*4\r\n$1\r\nf\r\n$1\r\nv\r\n$1\r\ng\r\n$-1\r\n",
           "%2\r\n$1\r\nf\r\n$1\r\nv\r\n$1\r\ng\r\n_\r\n");
    const auto set = redis_reply::set({redis_reply::bulk("a"), redis_reply::bulk("b")});
    expect(set, "*2\r\n$1\r\na\r\n$1\r\nb\r\n", "~2\r\n$1\r\na\r\n$1\r\nb\r\n");
    const auto nested = redis_reply::array({redis_reply::integer(1), set, redis_reply::array({})});
    expect(nested, "*3\r\n:1\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n*0\r\n",
           "*3\r\n:1\r\n~2\r\n$1\r\na\r\n$1\r\nb\r\n*0\r\n");
}

BOOST_AUTO_TEST_CASE(unframeable_replies_are_refused) {
    BOOST_CHECK_THROW((void)render_redis_reply(redis_reply::simple("a\r\nb"), 2),
                      redis_reply_error);
    BOOST_CHECK_THROW((void)render_redis_reply(redis_reply::error("ERR \n"), 3), redis_reply_error);
    BOOST_CHECK_THROW((void)render_redis_reply(redis_reply::verbatim("text", "x"), 3),
                      redis_reply_error);
    BOOST_CHECK_THROW((void)render_redis_reply(redis_reply::big_number("1.5"), 3),
                      redis_reply_error);
    BOOST_CHECK_THROW((void)render_redis_reply(redis_reply::map({redis_reply::bulk("k")}), 3),
                      redis_reply_error);
    auto deep = redis_reply::array({});
    for (int i = 0; i < 40; ++i) {
        deep = redis_reply::array({std::move(deep)});
    }
    BOOST_CHECK_THROW((void)kythira::encode_redis_reply(deep), redis_reply_error);
    redis_reply stray = redis_reply::integer(1);
    stray._text = "x";
    BOOST_CHECK_THROW((void)kythira::encode_redis_reply(stray), redis_reply_error);
}

BOOST_AUTO_TEST_CASE(generated_replies_round_trip, *boost::unit_test::timeout(120)) {
    generator g(k_seed);
    for (std::uint64_t i = 0; i < k_iterations; ++i) {
        const auto r = g.reply();
        const auto bytes = kythira::encode_redis_reply(r);
        BOOST_REQUIRE_MESSAGE(kythira::decode_redis_reply(bytes) == r,
                              "seed " << k_seed << " iteration " << i);
        // Rendering never throws for a reply the codec carries.
        (void)render_redis_reply(r, 2);
        (void)render_redis_reply(r, 3);
    }
}

BOOST_AUTO_TEST_CASE(mutations_are_refused_or_canonical, *boost::unit_test::timeout(300)) {
    generator g(k_seed + 1);
    std::uint64_t refused = 0;
    std::uint64_t accepted = 0;
    for (std::uint64_t i = 0; i < k_iterations; ++i) {
        auto bytes = kythira::encode_redis_reply(g.reply());
        const auto rounds = 1 + g.below(3);
        for (std::uint64_t r = 0; r < rounds; ++r) {
            bytes = g.mutate(std::move(bytes));
        }
        try {
            const auto rec = kythira::decode_redis_reply(bytes);
            ++accepted;
            BOOST_REQUIRE_MESSAGE(
                kythira::encode_redis_reply(rec) == bytes,
                "a non-canonical buffer decoded, seed " << k_seed << " iteration " << i);
        } catch (const redis_reply_error&) {
            ++refused;
        }
    }
    BOOST_CHECK_GT(refused, 0U);
    BOOST_CHECK_GT(accepted, 0U);
}

BOOST_AUTO_TEST_CASE(a_huge_count_allocates_nothing) {
    // An array claiming 2^32-1 elements in a five-byte buffer.
    const std::vector<std::byte> lie{std::byte{6}, std::byte{0xFF}, std::byte{0xFF},
                                     std::byte{0xFF}, std::byte{0xFF}};
    BOOST_CHECK_THROW((void)kythira::decode_redis_reply(lie), redis_reply_error);
    BOOST_CHECK_THROW((void)kythira::decode_redis_reply({}), redis_reply_error);
    const std::vector<std::byte> unknown{std::byte{0}};
    BOOST_CHECK_THROW((void)kythira::decode_redis_reply(unknown), redis_reply_error);
}
