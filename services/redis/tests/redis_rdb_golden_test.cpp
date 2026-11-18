// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_rdb_golden_test.cpp
/// @brief The RDB file codec against files written by the real servers
///        (.kiro/specs/redis-migration-tooling/ task 1, Requirements 2.1,
///        2.2 and 14.1; design "Testing strategy", codec row).
///
/// `golden/rdb/` holds a `dump.rdb` from each pinned server (Redis 7.2,
/// 7.4, 8.0, 8.2, 8.4; Valkey 7.2, 8.0, 8.1, 9.0) and the server's own key
/// listing: database, key, PEXPIRETIME and the `DUMP` reply of every key
/// (`generate_rdb_goldens.py` writes both). For each file:
///
/// - the reader returns exactly the listed keys, each with the listed
///   expiry, and with the type byte and payload of its `DUMP` reply (the
///   server serializes a value the same way into both), so every value
///   encoding each server writes is delimited byte for byte;
/// - each `DUMP` footer's CRC64 checks out with `rdb_crc64` and names the
///   file's version, and the file's own trailer verified;
/// - string payloads decode to the values the generator wrote (integer
///   forms, LZF, binary, empty);
/// - written back at the same format and read again, every record is equal;
/// - written at every other target, a key is refused exactly when its type
///   is not portable there (Requirement 2.2 reports it), and the rest read
///   back unchanged.
///
/// `aws/` holds backups exported by ElastiCache (Redis OSS 7.1, Valkey 9.1)
/// and MemoryDB (Redis OSS 7.1, Valkey 7.3), each the engine's own rewrite
/// of one of the files above loaded as a seed from S3 (the `.txt` beside
/// each records engine, version, date and seed). They must read with a
/// verified trailer, hold exactly the seed's keys, expiries and string
/// values, and round trip (Requirement 14.1).
///
/// `writer-<target>.rdb` are files the writer produced (strings encoded by
/// Kythira, including LZF from the in-tree compressor, plus a few values
/// copied from the server's file) and that the target server loaded
/// (`generate_rdb_goldens.py --load-check`). The test pins the writer's
/// bytes to them, so a change to the writer's output needs a new load
/// check. Set KYTHIRA_RDB_WRITE_GOLDENS=1 to rewrite them.

#define BOOST_TEST_MODULE redis_rdb_golden_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_rdb_crc64.hpp>
#include <kythira/redis/redis_rdb_file.hpp>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef KYTHIRA_REDIS_RDB_GOLDEN_DIR
#error "KYTHIRA_REDIS_RDB_GOLDEN_DIR must name services/redis/tests/golden/rdb"
#endif

namespace {

using namespace kythira;

const std::string golden_dir = KYTHIRA_REDIS_RDB_GOLDEN_DIR;

auto read_file(const std::string& path) -> std::string {
    std::ifstream in(path, std::ios::binary);
    BOOST_REQUIRE_MESSAGE(in, "cannot open " << path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

auto unhex(std::string_view h) -> std::string {
    std::string out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<char>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

struct listed_key {
    std::int64_t _pexpiretime = -1;
    std::string _dump;
};

using listing = std::map<std::pair<std::uint64_t, std::string>, listed_key>;

auto read_listing(const std::string& name) -> listing {
    listing out;
    std::istringstream in(read_file(golden_dir + "/" + name + ".keys"));
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream f(line);
        std::uint64_t db = 0;
        std::string key_hex;
        std::int64_t exp = 0;
        std::string dump_hex;
        f >> db >> key_hex >> exp >> dump_hex;
        out[{db, unhex(key_hex)}] = {exp, unhex(dump_hex)};
    }
    return out;
}

auto read_all(std::string_view bytes) -> std::pair<rdb_format, std::vector<rdb_record>> {
    rdb_memory_source src(bytes);
    rdb_reader r(src);
    std::vector<rdb_record> out;
    while (auto rec = r.next()) {
        out.push_back(std::move(*rec));
    }
    BOOST_REQUIRE_EQUAL(r.offset(), bytes.size());
    return {r.format(), std::move(out)};
}

auto keys_of(const std::vector<rdb_record>& recs) -> std::vector<rdb_key> {
    std::vector<rdb_key> out;
    for (const auto& r : recs) {
        if (const auto* k = std::get_if<rdb_key>(&r)) {
            out.push_back(*k);
        }
    }
    return out;
}

// Every record but the EOF trailer value, which changes with the bytes.
auto without_eof(std::vector<rdb_record> recs) -> std::vector<rdb_record> {
    std::erase_if(recs, [](const rdb_record& r) { return std::holds_alternative<rdb_eof>(r); });
    return recs;
}

const std::vector<std::string> server_names = {
    "redis-7.2",  "redis-7.4",  "redis-8.0",  "redis-8.2",  "redis-8.4",
    "valkey-7.2", "valkey-8.0", "valkey-8.1", "valkey-9.0",
};

auto le16(std::string_view s) -> std::uint16_t {
    return static_cast<std::uint16_t>(static_cast<std::uint8_t>(s[0]) |
                                      (static_cast<std::uint8_t>(s[1]) << 8U));
}

auto le64(std::string_view s) -> std::uint64_t {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8U) | static_cast<std::uint8_t>(s[static_cast<std::size_t>(i)]);
    }
    return v;
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_server_file_reads_as_its_dump_listing) {
    for (const auto& name : server_names) {
        BOOST_TEST_CONTEXT(name) {
            const std::string bytes = read_file(golden_dir + "/" + name + ".rdb");
            const auto [format, recs] = read_all(bytes);
            BOOST_TEST((format == rdb_find_target(name).value()));

            // Exactly one EOF, last, with a verified (non-zero) trailer.
            BOOST_REQUIRE(!recs.empty());
            BOOST_TEST(std::holds_alternative<rdb_eof>(recs.back()));
            BOOST_TEST(std::get<rdb_eof>(recs.back())._checksum != 0U);

            bool saw_version_aux = false;
            bool saw_function = false;
            for (const auto& r : recs) {
                if (const auto* a = std::get_if<rdb_aux>(&r)) {
                    saw_version_aux |= a->_key == "redis-ver" || a->_key == "valkey-ver";
                }
                if (const auto* f = std::get_if<rdb_function>(&r)) {
                    saw_function |= f->_code.find("name=goldlib") != std::string::npos;
                }
            }
            BOOST_TEST(saw_version_aux);
            BOOST_TEST(saw_function);

            const listing expected = read_listing(name);
            const auto keys = keys_of(recs);
            BOOST_TEST(keys.size() == expected.size());
            for (const auto& k : keys) {
                BOOST_TEST_CONTEXT("db " << k._db << " key " << k._key) {
                    const auto it = expected.find({k._db, k._key});
                    BOOST_REQUIRE(it != expected.end());
                    const std::string& dump = it->second._dump;
                    BOOST_REQUIRE(dump.size() > 11);
                    // DUMP = type, payload, 2-byte version, CRC64 of all before.
                    BOOST_TEST(static_cast<std::uint8_t>(dump[0]) == k._type);
                    BOOST_TEST((std::string_view(dump).substr(1, dump.size() - 11) == k._payload));
                    BOOST_TEST(le16(std::string_view(dump).substr(dump.size() - 10)) ==
                               format._version);
                    BOOST_TEST(le64(std::string_view(dump).substr(dump.size() - 8)) ==
                               rdb_crc64(0, std::string_view(dump).substr(0, dump.size() - 8)));
                    if (it->second._pexpiretime < 0) {
                        BOOST_TEST(!k._expire_ms.has_value());
                    } else {
                        BOOST_TEST(k._expire_ms.value_or(-1) == it->second._pexpiretime);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(string_payloads_decode_to_what_was_written) {
    for (const auto& name : server_names) {
        BOOST_TEST_CONTEXT(name) {
            const auto [format, recs] = read_all(read_file(golden_dir + "/" + name + ".rdb"));
            std::map<std::string, std::string> strings;
            for (const auto& k : keys_of(recs)) {
                if (k._db == 0 && k._type == rdb_type::string) {
                    strings[k._key] = rdb_decode_string_payload(k._payload);
                }
            }
            std::string lzf;
            for (int i = 0; i < 300; ++i) {
                lzf += "abcabcabc";
            }
            BOOST_TEST(strings.at("s:int8") == "-7");
            BOOST_TEST(strings.at("s:int16") == "1234");
            BOOST_TEST(strings.at("s:int32") == "-2000000000");
            BOOST_TEST(strings.at("s:int64") == "9000000000000000000");
            BOOST_TEST(strings.at("s:short") == "hello");
            BOOST_TEST(strings.at("s:lzf") == lzf);
            BOOST_TEST(strings.at("s:random").size() == 300U);
            BOOST_TEST(strings.at("s:binary") == std::string("\x00\xff\r\n\x80key", 8));
            BOOST_TEST(strings.at("s:empty").empty());
            BOOST_TEST(strings.at(std::string("\xc3\xa9\x00k", 4)) == "binary key");
        }
    }
}

BOOST_AUTO_TEST_CASE(write_at_the_same_format_reads_back_equal) {
    for (const auto& name : server_names) {
        BOOST_TEST_CONTEXT(name) {
            const auto [format, recs] = read_all(read_file(golden_dir + "/" + name + ".rdb"));
            rdb_string_sink sink;
            rdb_writer w(sink, format);
            for (const auto& r : recs) {
                BOOST_TEST(w.write(r));
            }
            const auto [format2, recs2] = read_all(sink.str());
            BOOST_TEST((format2 == format));
            BOOST_TEST((without_eof(recs2) == without_eof(recs)));
            BOOST_TEST(std::get<rdb_eof>(recs2.back())._checksum != 0U);
        }
    }
}

BOOST_AUTO_TEST_CASE(write_at_other_targets_refuses_only_unportable_types) {
    for (const auto& name : server_names) {
        const auto [from, recs] = read_all(read_file(golden_dir + "/" + name + ".rdb"));
        for (const auto& target : rdb_targets) {
            BOOST_TEST_CONTEXT(name << " -> " << target._name) {
                rdb_string_sink sink;
                rdb_writer w(sink, target._format);
                std::vector<rdb_key> kept;
                std::size_t refused = 0;
                for (const auto& r : recs) {
                    if (std::holds_alternative<rdb_slot_info>(r) ||
                        std::holds_alternative<rdb_slot_import>(r)) {
                        continue;  // cluster-mode only; none in these files
                    }
                    if (const auto* k = std::get_if<rdb_key>(&r)) {
                        const bool portable = rdb_type_portable(from, target._format, k->_type);
                        BOOST_TEST(w.write(r, from) == portable);
                        if (portable) {
                            kept.push_back(*k);
                        } else {
                            ++refused;
                        }
                        continue;
                    }
                    if (std::holds_alternative<rdb_function>(r) &&
                        target._format._magic == rdb_magic::redis && target._format._version < 10) {
                        continue;
                    }
                    w.write(r, from);
                }
                const auto [fmt, back] = read_all(sink.str());
                BOOST_TEST((keys_of(back) == kept));
                // Valkey 9 and Redis 7.4+ hashes with field TTLs never cross.
                if (from._magic != target._format._magic &&
                    (from._version >= 12 || from._magic == rdb_magic::valkey)) {
                    BOOST_TEST(refused > 0U);
                }
            }
        }
    }
}

namespace {

// The writer's own file for a target: Kythira-encoded strings (one LZF,
// one integer, one expiring, one in another database) plus a few small
// values copied from that server's file.
auto writer_file(const std::string& name) -> std::string {
    const auto [format, recs] = read_all(read_file(golden_dir + "/" + name + ".rdb"));
    std::map<std::string, rdb_key> source;
    std::string function_code;
    for (const auto& r : recs) {
        if (const auto* k = std::get_if<rdb_key>(&r); k != nullptr && k->_db == 0) {
            source[k->_key] = *k;
        }
        if (const auto* f = std::get_if<rdb_function>(&r)) {
            function_code = f->_code;
        }
    }
    rdb_string_sink sink;
    rdb_writer w(sink, format);
    w.aux("kythira-rdb-writer", "1");
    w.aux("redis-bits", "64");
    w.function(function_code);
    w.select_db(0);
    w.resize_db(16, 1);

    std::string text;
    for (int i = 0; i < 40; ++i) {
        text += "kythira lzf line " + std::to_string(i % 7) + "; ";
    }
    const auto put = [&w](std::string key, std::string payload,
                          std::optional<std::int64_t> exp = {}) {
        rdb_key k;
        k._key = std::move(key);
        k._payload = std::move(payload);
        k._expire_ms = exp;
        BOOST_REQUIRE(w.key(k));
    };
    put("kythira:lzf", rdb_encode_string_payload(text));
    put("kythira:raw", rdb_encode_string_payload(text, false));
    put("kythira:int", rdb_encode_string_payload("-32768"));
    put("kythira:big-int", rdb_encode_string_payload("2147483647"));
    put("kythira:not-int", rdb_encode_string_payload("007"));
    put("kythira:expire", rdb_encode_string_payload("soon"), 4102444803000);
    // A long key, LZF-compressed by the writer.
    put(std::string(64, 'k'), rdb_encode_string_payload("long key"));
    for (const char* copied :
         {"l:small", "set:small", "set:int", "z:small", "h:small", "st", "hx:small", "m:json"}) {
        if (auto it = source.find(copied); it != source.end()) {
            BOOST_REQUIRE(w.key(it->second));
        }
    }
    w.select_db(3);
    put("kythira:db3", rdb_encode_string_payload("three"));
    w.finish();
    return sink.take();
}

}  // namespace

BOOST_AUTO_TEST_CASE(writer_output_matches_the_load_checked_files) {
    const bool rewrite = std::getenv("KYTHIRA_RDB_WRITE_GOLDENS") != nullptr;
    for (const auto& name : server_names) {
        BOOST_TEST_CONTEXT(name) {
            const std::string bytes = writer_file(name);
            const std::string path = golden_dir + "/writer-" + name + ".rdb";
            if (rewrite) {
                std::ofstream(path, std::ios::binary) << bytes;
            }
            BOOST_TEST((bytes == read_file(path)), "writer output differs from " << path);
            // And it reads back, Kythira's strings decoding as written.
            const auto [format, recs] = read_all(bytes);
            for (const auto& k : keys_of(recs)) {
                if (k._key == "kythira:int") {
                    BOOST_TEST(rdb_decode_string_payload(k._payload) == "-32768");
                }
                if (k._key == "kythira:not-int") {
                    BOOST_TEST(rdb_decode_string_payload(k._payload) == "007");
                }
            }
        }
    }
}

namespace {

struct aws_golden {
    std::string _name;
    rdb_format _format;
    std::string _seed;
    bool _db0_only;
};

// Backups exported by the managed services (Requirement 14.1), each the
// engine's own rewrite of a seed loaded from S3 (golden/rdb/aws/*.txt
// records the engine, version, date and seed). MemoryDB has only database
// 0, so its seeds were cut to db 0 first.
const std::vector<aws_golden> aws_goldens = {
    {"elasticache-redis-7.1.0", {rdb_magic::redis, 10}, "redis-7.2", false},
    {"elasticache-valkey-9.1.0", {rdb_magic::valkey, 80}, "valkey-8.0", false},
    {"memorydb-redis-7.1.1", {rdb_magic::redis, 10}, "redis-7.2", true},
    {"memorydb-valkey-7.3.0", {rdb_magic::redis, 11}, "valkey-8.0", true},
};

}  // namespace

BOOST_AUTO_TEST_CASE(managed_service_backups_hold_their_seeds) {
    for (const auto& g : aws_goldens) {
        BOOST_TEST_CONTEXT(g._name) {
            const auto [format, recs] =
                read_all(read_file(golden_dir + "/aws/" + g._name + ".rdb"));
            BOOST_TEST((format == g._format));
            BOOST_TEST(std::get<rdb_eof>(recs.back())._checksum != 0U);

            // The seed's keys, values decoded where they are strings.
            const auto [seed_format, seed_recs] =
                read_all(read_file(golden_dir + "/" + g._seed + ".rdb"));
            std::map<std::pair<std::uint64_t, std::string>, rdb_key> seed;
            for (const auto& k : keys_of(seed_recs)) {
                if (!g._db0_only || k._db == 0) {
                    seed[{k._db, k._key}] = k;
                }
            }
            const auto keys = keys_of(recs);
            BOOST_TEST(keys.size() == seed.size());
            for (const auto& k : keys) {
                BOOST_TEST_CONTEXT("db " << k._db << " key " << k._key) {
                    const auto it = seed.find({k._db, k._key});
                    BOOST_REQUIRE(it != seed.end());
                    BOOST_TEST(k._expire_ms.value_or(-1) == it->second._expire_ms.value_or(-1));
                    BOOST_TEST((k._type == rdb_type::string) ==
                               (it->second._type == rdb_type::string));
                    if (k._type == rdb_type::string) {
                        BOOST_TEST(rdb_decode_string_payload(k._payload) ==
                                   rdb_decode_string_payload(it->second._payload));
                    }
                }
            }
            // And it writes back at its own format and reads the same.
            rdb_string_sink sink;
            rdb_writer w(sink, format);
            for (const auto& r : recs) {
                BOOST_TEST(w.write(r));
            }
            const auto [format2, recs2] = read_all(sink.str());
            BOOST_TEST((without_eof(recs2) == without_eof(recs)));
        }
    }
}
