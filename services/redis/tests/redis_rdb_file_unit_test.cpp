// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_rdb_file_unit_test.cpp
/// @brief The RDB file codec's pieces one at a time
///        (.kiro/specs/redis-migration-tooling/ task 1, Requirements
///        2.1-2.4): CRC64, LZF, lengths and strings, the header and version
///        table, every opcode through a write/read round trip, the errors
///        (truncation at every byte, checksum mismatch, unknown types and
///        opcodes, limits), and each source and sink adapter.

#define BOOST_TEST_MODULE redis_rdb_file_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_rdb_crc64.hpp>
#include <kythira/redis/redis_rdb_file.hpp>
#include <kythira/redis/redis_rdb_lzf.hpp>

#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace {

using namespace kythira;

auto bytes_of(std::string_view s) -> std::span<const std::uint8_t> {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

auto read_all(std::string_view bytes, rdb_reader_options o = {}) -> std::vector<rdb_record> {
    rdb_memory_source src(bytes);
    rdb_reader r(src, o);
    std::vector<rdb_record> out;
    while (auto rec = r.next()) {
        out.push_back(std::move(*rec));
    }
    return out;
}

auto expect_error(std::string_view bytes, rdb_error_kind kind, rdb_reader_options o = {}) -> void {
    try {
        (void)read_all(bytes, o);
        BOOST_ERROR("expected rdb_error " << to_string(kind));
    } catch (const rdb_error& e) {
        BOOST_TEST(to_string(e.kind()) == to_string(kind), e.what());
    }
}

auto key_record(std::string key, std::string value, std::uint64_t db = 0) -> rdb_key {
    rdb_key k;
    k._db = db;
    k._key = std::move(key);
    k._payload = rdb_encode_string_payload(value);
    return k;
}

// A file with one of every record the writer can produce at `f`.
auto sample_file(rdb_format f, rdb_writer_options o = {}) -> std::string {
    rdb_string_sink sink;
    rdb_writer w(sink, f, o);
    w.aux("redis-ver", "7.2.0");
    w.aux("redis-bits", "64");
    w.aux("ctime", "1795030000");
    w.function("#!lua name=lib\nredis.register_function('f', function() return 1 end)");
    w.module_aux({._module_id = 0x1234567890ULL << 10U | 3U,
                  ._when = 2,
                  ._body = std::string("\x05\x03"
                                       "abc",
                                       5)});
    w.select_db(0);
    w.resize_db(3, 1);
    if (f._magic == rdb_magic::valkey || f._version >= 12) {
        w.slot_info(42, 3, 1);
    }
    if (f._magic == rdb_magic::valkey) {
        w.slot_import({._job = "job-1", ._ranges = {{0, 100}, {200, 300}}});
    }
    auto k1 = key_record("a", "1");
    k1._expire_ms = 4102444800000;
    k1._lfu_freq = 5;
    BOOST_REQUIRE(w.key(k1));
    auto k2 = key_record("b", std::string(100, 'x'));
    k2._idle_seconds = 77777;
    BOOST_REQUIRE(w.key(k2));
    w.select_db(7);
    BOOST_REQUIRE(w.key(key_record("c", "", 7)));
    w.finish();
    return sink.take();
}

}  // namespace

// --- CRC64 and LZF -------------------------------------------------------

BOOST_AUTO_TEST_CASE(crc64_matches_the_jones_check_value_and_composes) {
    BOOST_TEST(rdb_crc64(0, std::string_view{"123456789"}) == 0xe9c6d914c4b8d9caULL);
    BOOST_TEST(rdb_crc64(0, std::string_view{}) == 0U);
    const std::string s = "split across two calls";
    BOOST_TEST(rdb_crc64(rdb_crc64(0, std::string_view(s).substr(0, 7)),
                         std::string_view(s).substr(7)) == rdb_crc64(0, s));
}

BOOST_AUTO_TEST_CASE(lzf_round_trips_and_refuses_corruption) {
    std::mt19937_64 rng(7);
    for (int round = 0; round < 300; ++round) {
        std::string in;
        const auto n = static_cast<std::size_t>(rng() % 20000);
        const unsigned alphabet = 1U + static_cast<unsigned>(rng() % 255);
        for (std::size_t i = 0; i < n; ++i) {
            in.push_back(static_cast<char>(rng() % alphabet));
        }
        if (auto c = rdb_lzf_compress(in)) {
            BOOST_TEST(c->size() < in.size());
            const auto d = rdb_lzf_decompress(bytes_of(*c), in.size());
            BOOST_REQUIRE(d.has_value());
            BOOST_TEST((*d == in));
            // Wrong declared length is refused, never over- or under-run.
            BOOST_TEST(!rdb_lzf_decompress(bytes_of(*c), in.size() + 1).has_value());
            if (!in.empty()) {
                BOOST_TEST(!rdb_lzf_decompress(bytes_of(*c), in.size() - 1).has_value());
            }
        }
    }
    // Long runs use the overlapping copy and the 8-bit length extension.
    const std::string run(100000, 'z');
    const auto c = rdb_lzf_compress(run);
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(c->size() < 1500U);
    BOOST_TEST((rdb_lzf_decompress(bytes_of(*c), run.size()).value() == run));
    // A back reference before the start, and a claimed length no input of
    // that size can produce.
    const std::string bad_ref("\x20\x05", 2);
    BOOST_TEST(!rdb_lzf_decompress(bytes_of(bad_ref), 3).has_value());
    BOOST_TEST(!rdb_lzf_decompress(bytes_of(std::string("\x00x", 2)), 1000000).has_value());
    // Too short or incompressible input is not compressed.
    BOOST_TEST(!rdb_lzf_compress("abc").has_value());
    BOOST_TEST(!rdb_lzf_compress("abcdefghijklmnopqrstuvwxyz", 4).has_value());
}

// --- lengths and strings ---------------------------------------------------

BOOST_AUTO_TEST_CASE(lengths_use_the_shortest_form_and_read_back) {
    const std::vector<std::pair<std::uint64_t, std::size_t>> cases = {
        {0, 1},
        {63, 1},
        {64, 2},
        {16383, 2},
        {16384, 5},
        {0xffffffffULL, 5},
        {0x100000000ULL, 9},
        {0xffffffffffffffffULL, 9},
    };
    for (const auto& [v, size] : cases) {
        std::string out;
        rdb_detail::put_length(out, v);
        BOOST_TEST(out.size() == size);
        rdb_memory_source src(out);
        rdb_detail::cursor c(src, 0);
        BOOST_TEST(c.length() == v);
    }
    // 10xxxxxx other than 0x80/0x81 is not a length.
    rdb_memory_source src(std::string_view("\x82", 1));
    rdb_detail::cursor c(src, 0);
    BOOST_CHECK_THROW((void)c.length(), rdb_error);
}

BOOST_AUTO_TEST_CASE(strings_take_redis_encodings) {
    const auto first = [](std::string_view v, bool compress = true) {
        return static_cast<std::uint8_t>(rdb_encode_string_payload(v, compress)[0]);
    };
    BOOST_TEST(first("-128") == 0xc0U);  // int8
    BOOST_TEST(first("127") == 0xc0U);
    BOOST_TEST(first("128") == 0xc1U);  // int16
    BOOST_TEST(first("-32768") == 0xc1U);
    BOOST_TEST(first("32768") == 0xc2U);  // int32
    BOOST_TEST(first("-2147483648") == 0xc2U);
    BOOST_TEST(first("2147483648") == 10U);  // too big: raw, length 10
    BOOST_TEST(first("007") == 3U);          // not canonical: raw
    BOOST_TEST(first("+1") == 2U);
    BOOST_TEST(first("-0") == 2U);
    BOOST_TEST(first(std::string(30, 'a')) == 0xc3U);  // LZF
    BOOST_TEST(first(std::string(30, 'a'), false) == 30U);
    BOOST_TEST(first(std::string(20, 'a')) == 20U);  // 20 bytes: never compressed
    for (const std::string& v :
         std::vector<std::string>{"", "0", "-1", "255", "-32769", "2147483647", "12345678901",
                                  "hello", std::string(5000, 'q'), std::string("\x00\x01", 2)}) {
        BOOST_TEST(rdb_decode_string_payload(rdb_encode_string_payload(v)) == v);
        BOOST_TEST(rdb_decode_string_payload(rdb_encode_string_payload(v, false)) == v);
    }
    BOOST_CHECK_THROW((void)rdb_decode_string_payload(std::string_view("\x01xy", 3)), rdb_error);
    BOOST_CHECK_THROW((void)rdb_decode_string_payload(std::string_view("\xc4", 1)), rdb_error);
}

// --- header, version table, types ----------------------------------------

BOOST_AUTO_TEST_CASE(headers_and_the_version_table) {
    BOOST_TEST(rdb_header_bytes({rdb_magic::redis, 11}) == "REDIS0011");
    BOOST_TEST(rdb_header_bytes({rdb_magic::valkey, 80}) == "VALKEY080");
    BOOST_TEST((rdb_find_target("redis-8.4").value() == rdb_format{rdb_magic::redis, 12}));
    BOOST_TEST((rdb_find_target("valkey-8.1").value() == rdb_format{rdb_magic::redis, 11}));
    BOOST_TEST((rdb_find_target("valkey-9.0").value() == rdb_format{rdb_magic::valkey, 80}));
    BOOST_TEST(!rdb_find_target("redis-6.2").has_value());
    for (const auto& t : rdb_targets) {
        BOOST_TEST(rdb_format_supported(t._format), t._name);
    }
    BOOST_TEST(!rdb_format_supported({rdb_magic::redis, 8}));
    BOOST_TEST(!rdb_format_supported({rdb_magic::redis, 13}));
    BOOST_TEST(!rdb_format_supported({rdb_magic::valkey, 12}));

    const rdb_format r11{rdb_magic::redis, 11};
    const rdb_format r12{rdb_magic::redis, 12};
    const rdb_format v80{rdb_magic::valkey, 80};
    BOOST_TEST(rdb_type_known(r11, rdb_type::set_listpack));
    BOOST_TEST(!rdb_type_known({rdb_magic::redis, 10}, rdb_type::set_listpack));
    BOOST_TEST(!rdb_type_known(r11, 22));
    BOOST_TEST(rdb_type_known(r12, rdb_type::redis_hash_listpack_ex));
    BOOST_TEST(rdb_type_known(v80, rdb_type::valkey_hash_2));
    BOOST_TEST(!rdb_type_known(v80, rdb_type::redis_hash_metadata));
    BOOST_TEST(!rdb_type_known(r12, 26));
    BOOST_TEST(!rdb_type_known(r12, 8));
    // 22 exists in both dialects but means different hashes.
    BOOST_TEST(!rdb_type_portable(r12, v80, 22));
    BOOST_TEST(!rdb_type_portable(v80, r12, 22));
    BOOST_TEST(rdb_type_portable(r12, v80, rdb_type::stream_listpacks_3));
    BOOST_TEST(rdb_type_portable(v80, r11, rdb_type::set_listpack));
    BOOST_TEST(rdb_type_name(v80, 22) == "valkey_hash_2");
    BOOST_TEST(rdb_type_name(r12, 22) == "redis_hash_metadata_pre_ga");
}

BOOST_AUTO_TEST_CASE(module_ids_name_the_module) {
    // "ReJSON-RL" with encoding version 3, the RedisJSON id.
    const std::string_view charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::uint64_t id = 0;
    for (const char ch : std::string_view("ReJSON-RL")) {
        id = (id << 6U) | charset.find(ch);
    }
    id = (id << 10U) | 3U;
    BOOST_TEST(rdb_module_type_name(id) == "ReJSON-RL");
    BOOST_TEST(rdb_module_encoding_version(id) == 3U);
}

BOOST_AUTO_TEST_CASE(readers_refuse_unknown_magic_and_versions) {
    expect_error("", rdb_error_kind::truncated);
    expect_error("REDIS00", rdb_error_kind::truncated);
    expect_error("NOTRDB000", rdb_error_kind::unsupported_version);
    expect_error("REDIS0008\xff", rdb_error_kind::unsupported_version);
    expect_error("REDIS0013\xff", rdb_error_kind::unsupported_version);
    expect_error("REDIS0080\xff", rdb_error_kind::unsupported_version);
    expect_error("VALKEY012\xff", rdb_error_kind::unsupported_version);
    expect_error("VALKEX080\xff", rdb_error_kind::unsupported_version);
    expect_error("REDIS00x1\xff", rdb_error_kind::unsupported_version);
}

// --- full files -------------------------------------------------------------

BOOST_AUTO_TEST_CASE(every_record_round_trips_at_every_target) {
    for (const auto& t : rdb_targets) {
        BOOST_TEST_CONTEXT(t._name) {
            const std::string file = sample_file(t._format);
            BOOST_TEST(file.substr(0, 9) == rdb_header_bytes(t._format));
            const auto recs = read_all(file);
            std::size_t keys = 0;
            for (const auto& r : recs) {
                if (const auto* k = std::get_if<rdb_key>(&r)) {
                    ++keys;
                    if (k->_key == "a") {
                        BOOST_TEST(k->_expire_ms.value() == 4102444800000);
                        BOOST_TEST(k->_lfu_freq.value() == 5);
                        BOOST_TEST(rdb_decode_string_payload(k->_payload) == "1");
                    } else if (k->_key == "b") {
                        BOOST_TEST(k->_idle_seconds.value() == 77777U);
                        BOOST_TEST(rdb_decode_string_payload(k->_payload) == std::string(100, 'x'));
                    } else {
                        BOOST_TEST(k->_db == 7U);
                    }
                }
                if (const auto* m = std::get_if<rdb_module_aux>(&r)) {
                    BOOST_TEST(m->_when == 2U);
                    BOOST_TEST(m->_body == std::string("\x05\x03"
                                                       "abc",
                                                       5));
                }
                if (const auto* s = std::get_if<rdb_slot_import>(&r)) {
                    BOOST_TEST(s->_job == "job-1");
                    BOOST_TEST(s->_ranges.size() == 2U);
                }
            }
            BOOST_TEST(keys == 3U);
            // Rewriting what was read gives the same bytes.
            rdb_string_sink sink;
            rdb_writer w(sink, t._format);
            for (const auto& r : recs) {
                (void)w.write(r);
            }
            BOOST_TEST((sink.str() == file));
        }
    }
}

BOOST_AUTO_TEST_CASE(truncation_at_every_byte_is_refused) {
    const std::string file = sample_file({rdb_magic::valkey, 80});
    for (std::size_t n = 0; n < file.size(); ++n) {
        try {
            (void)read_all(std::string_view(file).substr(0, n));
            BOOST_ERROR("prefix of " << n << " bytes read without error");
        } catch (const rdb_error& e) {
            BOOST_TEST((e.kind() == rdb_error_kind::truncated ||
                        e.kind() == rdb_error_kind::unsupported_version),
                       e.what());
        }
    }
}

BOOST_AUTO_TEST_CASE(checksums_are_verified_unless_zero) {
    std::string file = sample_file({rdb_magic::redis, 11});
    // Change one character of an AUX value: still parses, CRC no longer
    // matches.
    const auto pos = file.find("7.2.0");
    BOOST_REQUIRE(pos != std::string::npos);
    std::string corrupt = file;
    corrupt[pos] = '8';
    expect_error(corrupt, rdb_error_kind::checksum_mismatch);
    rdb_reader_options lax;
    lax._verify_checksum = false;
    BOOST_TEST(read_all(corrupt, lax).size() == read_all(file).size());

    rdb_writer_options no_crc;
    no_crc._checksum = false;
    const std::string unchecked = sample_file({rdb_magic::redis, 11}, no_crc);
    BOOST_TEST(unchecked.substr(unchecked.size() - 8) == std::string(8, '\0'));
    const auto recs = read_all(unchecked);
    BOOST_TEST(std::get<rdb_eof>(recs.back())._checksum == 0U);
}

BOOST_AUTO_TEST_CASE(unknown_types_and_opcodes_are_refused) {
    const auto file_with = [](rdb_format f, std::string body) {
        std::string s = rdb_header_bytes(f) + body + "\xff";
        const std::uint64_t crc = rdb_crc64(0, s);
        rdb_detail::put_le(s, crc, 8);
        return s;
    };
    const rdb_format r11{rdb_magic::redis, 11};
    // Type 22 in an RDB 11 file, 8 anywhere, 6 (pre-release modules).
    expect_error(file_with(r11, std::string("\x16\x01k\x01v", 5)),
                 rdb_error_kind::unsupported_type);
    expect_error(file_with(r11, std::string("\x08\x01k\x01v", 5)),
                 rdb_error_kind::unsupported_type);
    expect_error(file_with(r11, std::string("\x06\x01k\x00", 4)), rdb_error_kind::unsupported_type);
    // SLOT_IMPORT outside Valkey, an unused opcode, FUNCTION_PRE_GA.
    expect_error(file_with(r11, std::string("\xf3\x01j\x00", 4)), rdb_error_kind::corrupt);
    expect_error(file_with(r11, std::string("\xf6\x00", 2)), rdb_error_kind::unsupported_type);
    // Expiry not followed by a key.
    expect_error(file_with(r11, std::string("\xfc\x00\x00\x00\x00\x00\x00\x00\x00\xfe\x00", 11)),
                 rdb_error_kind::corrupt);
    // Bad quicklist container, unknown module field opcode.
    expect_error(file_with(r11, std::string("\x12\x01k\x01\x03\x01x", 7)), rdb_error_kind::corrupt);
    expect_error(file_with(r11, std::string("\x07\x01k\x05\x09", 5)), rdb_error_kind::corrupt);
    // Valkey's hash type 22 reads in a Valkey file.
    const rdb_format v80{rdb_magic::valkey, 80};
    const auto recs = read_all(file_with(v80, std::string("\x16\x01k\x01\x01"
                                                          "f\x01v\xff\xff\xff\xff\xff\xff\xff\xff",
                                                          16)));
    BOOST_TEST(std::get<rdb_key>(recs.at(0))._type == 22U);
    BOOST_TEST(std::get<rdb_key>(recs.at(0))._payload.size() == 13U);
}

BOOST_AUTO_TEST_CASE(limits_stop_oversized_strings_before_allocating) {
    rdb_reader_options o;
    o._max_string_bytes = 16;
    rdb_string_sink sink;
    rdb_writer w(sink, {rdb_magic::redis, 11}, {._checksum = true, ._compress = false});
    w.aux("k", std::string(17, 'v'));
    w.finish();
    expect_error(sink.str(), rdb_error_kind::limit_exceeded, o);

    rdb_reader_options v;
    v._max_value_bytes = 3;  // "1" fits (2 bytes), "b"'s value does not
    expect_error(sample_file({rdb_magic::redis, 11}, {._checksum = true, ._compress = false}),
                 rdb_error_kind::limit_exceeded, v);

    // A 64-bit length with no bytes behind it runs out of input; nothing
    // of that size is allocated.
    std::string huge = rdb_header_bytes({rdb_magic::redis, 11});
    huge += std::string("\xfa\x81\x00\x00\x00\xff\xff\xff\xff\xff", 10);
    expect_error(huge, rdb_error_kind::limit_exceeded);
    rdb_reader_options big;
    big._max_string_bytes = ~0ULL;
    expect_error(huge, rdb_error_kind::truncated, big);
    // An LZF length its compressed size cannot produce.
    std::string lzf = rdb_header_bytes({rdb_magic::redis, 11});
    lzf += std::string("\xfa\x01k\xc3\x01\x80\x00\x01\x00\x00\x00", 11);
    expect_error(lzf, rdb_error_kind::corrupt, big);
}

BOOST_AUTO_TEST_CASE(writers_refuse_what_the_target_cannot_hold) {
    rdb_string_sink sink;
    rdb_writer w(sink, {rdb_magic::redis, 11});
    BOOST_CHECK_THROW(w.slot_info(1, 2, 3), rdb_error);
    BOOST_CHECK_THROW(w.slot_import({}), rdb_error);
    rdb_key k = key_record("h", "x");
    k._type = rdb_type::redis_hash_listpack_ex;
    BOOST_TEST(!w.key(k));
    k._type = rdb_type::module_pre_ga;
    BOOST_TEST(!w.key(k));
    k._type = rdb_type::valkey_hash_2;
    BOOST_TEST(!w.key(k));
    // A Valkey 9 hash read from a Valkey file is refused by a Redis 12
    // writer even though 22 exists there.
    rdb_string_sink sink12;
    rdb_writer w12(sink12, {rdb_magic::redis, 12});
    BOOST_TEST(!w12.key(k, {rdb_magic::valkey, 80}));
    BOOST_TEST(w12.key(k));  // the same byte as Redis's own type 22
    BOOST_CHECK_THROW(rdb_writer(sink, {rdb_magic::redis, 13}), rdb_error);
}

// --- sources and sinks ------------------------------------------------------

BOOST_AUTO_TEST_CASE(fd_file_and_pipe_sources_and_sinks) {
    const std::string file = sample_file({rdb_magic::redis, 12});
    char tmpl[] = "/tmp/kythira-rdb-XXXXXX";
    const int fd = ::mkstemp(tmpl);
    BOOST_REQUIRE(fd >= 0);
    ::close(fd);
    const std::string path = tmpl;
    {
        rdb_file_sink sink(path);
        rdb_writer w(sink, {rdb_magic::redis, 12});
        for (const auto& r : read_all(file)) {
            (void)w.write(r);
        }
    }
    {
        rdb_file_source src(path);
        rdb_reader r(src);
        std::size_t n = 0;
        while (r.next()) {
            ++n;
        }
        BOOST_TEST(n == read_all(file).size());
    }
    ::unlink(path.c_str());
    BOOST_CHECK_THROW(rdb_file_source("/nonexistent/kythira.rdb"), rdb_error);

    // A pipe stands in for the replication socket.
    int p[2];
    BOOST_REQUIRE(::pipe(p) == 0);
    {
        rdb_fd_sink sink(p[1]);
        sink.write(bytes_of(file));
        ::close(p[1]);
    }
    rdb_fd_source src(p[0]);
    rdb_reader r(src);
    std::size_t n = 0;
    while (r.next()) {
        ++n;
    }
    ::close(p[0]);
    BOOST_TEST(n == read_all(file).size());
}

BOOST_AUTO_TEST_CASE(limited_source_stops_at_the_announced_length) {
    const std::string file = sample_file({rdb_magic::redis, 11});
    const std::string stream = file + "+next reply\r\n";
    rdb_memory_source inner(stream);
    rdb_limited_source src(inner, file.size());
    rdb_reader r(src);
    while (r.next()) {
    }
    BOOST_TEST(src.remaining() == 0U);
    std::array<std::uint8_t, 13> rest{};
    BOOST_TEST(inner.read_some(rest) == rest.size());
    BOOST_TEST(std::string(rest.begin(), rest.end()) == "+next reply\r\n");
}

BOOST_AUTO_TEST_CASE(ranged_source_and_part_sink) {
    const std::string file = sample_file({rdb_magic::valkey, 80});
    std::vector<std::pair<std::uint64_t, std::size_t>> fetches;
    auto fetch = [&](std::uint64_t offset, std::size_t len) {
        fetches.emplace_back(offset, len);
        return offset >= file.size() ? std::string() : file.substr(offset, len);
    };
    rdb_ranged_source<decltype(fetch)> src(fetch, 17);
    rdb_reader r(src);
    std::size_t n = 0;
    while (r.next()) {
        ++n;
    }
    BOOST_TEST(n == read_all(file).size());
    for (std::size_t i = 0; i < fetches.size(); ++i) {
        BOOST_TEST(fetches[i].first == i * 17U);
    }

    std::vector<std::pair<std::size_t, std::string>> parts;
    auto upload = [&](std::size_t part, std::string_view bytes) {
        parts.emplace_back(part, std::string(bytes));
    };
    {
        rdb_part_sink<decltype(upload)> sink(upload, 10);
        rdb_writer w(sink, {rdb_magic::valkey, 80});
        for (const auto& rec : read_all(file)) {
            (void)w.write(rec);
        }
        BOOST_TEST(sink.parts() == parts.size());
    }
    std::string joined;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        BOOST_TEST(parts[i].first == i + 1);
        if (i + 1 < parts.size()) {
            BOOST_TEST(parts[i].second.size() == 10U);
        }
        joined += parts[i].second;
    }
    BOOST_TEST((joined == file));

    // An empty upload still sends one (empty) part so the upload completes.
    std::vector<std::size_t> empty_parts;
    auto up2 = [&](std::size_t part, std::string_view) { empty_parts.push_back(part); };
    rdb_part_sink<decltype(up2)> empty(up2, 10);
    empty.finish();
    BOOST_TEST(empty_parts.size() == 1U);
}
