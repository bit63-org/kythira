// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A test-only Parquet reader for the files kinesis_parquet.hpp writes: the
// footer's Thrift compact structures read generically, and the values of
// top-level (non-repeated) leaf columns decoded from PLAIN data pages with
// RLE / bit-packed levels, uncompressed, Snappy or ZSTD. Enough for tests
// to check what a channel wrote; nested and repeated columns are checked
// by pyarrow (services/kinesis/tests/iceberg/read_exported_table.py).

#include <kythira/kinesis/kinesis_snappy.hpp>

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>

#ifdef KYTHIRA_KINESIS_HAS_ZSTD
#include <zstd.h>
#endif

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace parquet_test {

/// A Thrift compact value: a struct is an object keyed by field id, a list
/// an array, integers int64, binaries strings, bools bools.
class compact_reader {
public:
    explicit compact_reader(std::string_view in, std::size_t at = 0) : _in(in), _at(at) {}

    auto read_struct() -> boost::json::object {
        boost::json::object out;
        std::int64_t last = 0;
        for (;;) {
            const auto b = byte();
            if (b == 0) {
                return out;
            }
            const auto type = b & 0x0FU;
            const auto delta = b >> 4U;
            const auto id = delta != 0 ? last + delta : unzigzag(varint());
            last = id;
            out[std::to_string(id)] = value(type);
        }
    }

    [[nodiscard]] auto at() const -> std::size_t { return _at; }

private:
    std::string_view _in;
    std::size_t _at;

    auto byte() -> unsigned {
        BOOST_REQUIRE(_at < _in.size());
        return static_cast<unsigned char>(_in[_at++]);
    }
    auto varint() -> std::uint64_t {
        std::uint64_t v = 0;
        for (unsigned shift = 0;; shift += 7) {
            const auto b = byte();
            v |= static_cast<std::uint64_t>(b & 0x7FU) << shift;
            if ((b & 0x80U) == 0) {
                return v;
            }
        }
    }
    static auto unzigzag(std::uint64_t v) -> std::int64_t {
        return static_cast<std::int64_t>(v >> 1U) ^ -static_cast<std::int64_t>(v & 1U);
    }
    auto value(unsigned type) -> boost::json::value {
        switch (type) {
            case 1:
                return true;
            case 2:
                return false;
            case 3:
                return static_cast<std::int64_t>(static_cast<std::int8_t>(byte()));
            case 4:
            case 5:
            case 6:
                return unzigzag(varint());
            case 8: {
                const auto n = varint();
                BOOST_REQUIRE(n <= _in.size() - _at);
                std::string s(_in.substr(_at, n));
                _at += n;
                return boost::json::string(s);
            }
            case 9: {
                const auto h = byte();
                std::uint64_t n = h >> 4U;
                if (n == 15) {
                    n = varint();
                }
                const auto elem = h & 0x0FU;
                boost::json::array a;
                for (std::uint64_t i = 0; i < n; ++i) {
                    a.push_back(elem == 1 || elem == 2 ? boost::json::value(byte() == 1)
                                                       : value(elem));
                }
                return a;
            }
            case 12:
                return read_struct();
            default:
                BOOST_FAIL("unexpected Thrift compact type " << type);
        }
        return nullptr;
    }
};

struct file {
    std::string _bytes;
    boost::json::object _meta;

    explicit file(std::string bytes) : _bytes(std::move(bytes)) {
        BOOST_REQUIRE(_bytes.size() > 12);
        BOOST_REQUIRE(_bytes.substr(0, 4) == "PAR1");
        BOOST_REQUIRE(_bytes.substr(_bytes.size() - 4) == "PAR1");
        std::uint32_t len = 0;
        std::memcpy(&len, _bytes.data() + _bytes.size() - 8, 4);
        compact_reader r(_bytes, _bytes.size() - 8 - len);
        _meta = r.read_struct();
    }

    [[nodiscard]] auto rows() const -> std::int64_t { return _meta.at("3").as_int64(); }

    [[nodiscard]] auto key_value(std::string_view k) const -> std::optional<std::string> {
        if (const auto* kv = _meta.if_contains("5")) {
            for (const auto& e : kv->as_array()) {
                if (e.at("1").as_string() == k) {
                    return std::string(e.at("2").as_string());
                }
            }
        }
        return std::nullopt;
    }

    /// One leaf column as stored: its levels and its non-null values.
    struct leaf {
        int _max_def = 0;
        int _max_rep = 0;
        std::vector<std::uint32_t> _reps;
        std::vector<std::uint32_t> _defs;
        std::vector<boost::json::value> _values;
    };

    /// The leaf at `path` (dot-separated, e.g. `tags.list.element`).
    [[nodiscard]] auto read_leaf(std::string_view path) const -> leaf {
        const auto [max_def, max_rep] = levels_of(path);
        const auto& chunks = _meta.at("4").as_array().at(0).at("1").as_array();
        for (const auto& ch : chunks) {
            const auto& md = ch.at("3").as_object();
            std::string joined;
            for (const auto& p : md.at("3").as_array()) {
                joined += (joined.empty() ? "" : ".") + std::string(p.as_string());
            }
            if (joined != path) {
                continue;
            }
            const auto type = md.at("1").as_int64();
            const auto codec = md.at("4").as_int64();
            const auto n = static_cast<std::size_t>(md.at("5").as_int64());
            const auto offset = static_cast<std::size_t>(md.at("9").as_int64());
            compact_reader hr(_bytes, offset);
            const auto header = hr.read_struct();
            const auto compressed = static_cast<std::size_t>(header.at("3").as_int64());
            const auto plain_size = static_cast<std::size_t>(header.at("2").as_int64());
            std::string page = _bytes.substr(hr.at(), compressed);
            if (codec == 1) {
                auto d = kythira::kinesis::snappy::decompress(page);
                BOOST_REQUIRE(d);
                page = *d;
            } else if (codec == 6) {
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
                std::string d(plain_size, '\0');
                const auto k = ZSTD_decompress(d.data(), d.size(), page.data(), page.size());
                BOOST_REQUIRE(ZSTD_isError(k) == 0U);
                page = d;
#endif
            }
            BOOST_REQUIRE(page.size() == plain_size);
            leaf out{
                ._max_def = max_def, ._max_rep = max_rep, ._reps = {}, ._defs = {}, ._values = {}};
            std::size_t at = 0;
            auto read_levels = [&](int max) {
                std::uint32_t len = 0;
                std::memcpy(&len, page.data() + at, 4);
                auto l = levels(std::string_view(page).substr(at + 4, len), n, width(max));
                at += 4 + len;
                return l;
            };
            out._reps = max_rep > 0 ? read_levels(max_rep) : std::vector<std::uint32_t>(n, 0);
            out._defs = max_def > 0 ? read_levels(max_def) : std::vector<std::uint32_t>(n, 0);
            int bit = 0;
            for (const auto d : out._defs) {
                if (static_cast<int>(d) != max_def) {
                    continue;
                }
                switch (type) {
                    case 0: {
                        const auto b = static_cast<unsigned char>(page[at]);
                        out._values.emplace_back(((b >> bit) & 1U) != 0);
                        if (++bit == 8) {
                            bit = 0;
                            ++at;
                        }
                        break;
                    }
                    case 1: {
                        std::int32_t v = 0;
                        std::memcpy(&v, page.data() + at, 4);
                        at += 4;
                        out._values.emplace_back(static_cast<std::int64_t>(v));
                        break;
                    }
                    case 2: {
                        std::int64_t v = 0;
                        std::memcpy(&v, page.data() + at, 8);
                        at += 8;
                        out._values.emplace_back(v);
                        break;
                    }
                    case 5: {
                        double v = 0;
                        std::memcpy(&v, page.data() + at, 8);
                        at += 8;
                        out._values.emplace_back(v);
                        break;
                    }
                    case 6: {
                        std::uint32_t len = 0;
                        std::memcpy(&len, page.data() + at, 4);
                        out._values.emplace_back(boost::json::string(page.substr(at + 4, len)));
                        at += 4 + len;
                        break;
                    }
                    default:
                        BOOST_FAIL("type " << type << " not read by this test reader");
                }
            }
            return out;
        }
        BOOST_FAIL("no column " << path);
        return {};
    }

    /// A non-repeated column's values, one per row, null where not defined
    /// down to the leaf.
    [[nodiscard]] auto column(std::string_view path) const -> std::vector<boost::json::value> {
        const auto l = read_leaf(path);
        BOOST_REQUIRE(l._max_rep == 0);
        std::vector<boost::json::value> out;
        std::size_t v = 0;
        for (const auto d : l._defs) {
            out.push_back(static_cast<int>(d) == l._max_def ? l._values[v++]
                                                            : boost::json::value(nullptr));
        }
        return out;
    }

private:
    /// The maximum definition and repetition levels of `path`, from the
    /// schema elements (depth first, groups giving their child counts).
    [[nodiscard]] auto levels_of(std::string_view path) const -> std::pair<int, int> {
        const auto& elems = _meta.at("2").as_array();
        std::size_t i = 1;  // past the root
        int def = 0;
        int rep = 0;
        std::string_view rest = path;
        std::size_t siblings = static_cast<std::size_t>(elems[0].at("5").as_int64());
        for (;;) {
            const auto dot = rest.find('.');
            const auto name = rest.substr(0, dot);
            bool found = false;
            for (std::size_t k = 0; k < siblings; ++k) {
                const auto& e = elems[i].as_object();
                if (e.at("4").as_string() == name) {
                    const auto r = e.at("3").as_int64();
                    def += r != 0 ? 1 : 0;
                    rep += r == 2 ? 1 : 0;
                    if (dot == std::string_view::npos) {
                        return {def, rep};
                    }
                    siblings = static_cast<std::size_t>(e.at("5").as_int64());
                    ++i;
                    rest = rest.substr(dot + 1);
                    found = true;
                    break;
                }
                i = skip(i);
            }
            BOOST_REQUIRE_MESSAGE(found, "no schema element " << name);
        }
    }

    /// The index after element `i` and all its descendants.
    [[nodiscard]] auto skip(std::size_t i) const -> std::size_t {
        const auto& e = _meta.at("2").as_array()[i].as_object();
        const auto* n = e.if_contains("5");
        auto next = i + 1;
        for (std::int64_t k = 0; n != nullptr && k < n->as_int64(); ++k) {
            next = skip(next);
        }
        return next;
    }

    static auto width(int max) -> int {
        int w = 0;
        while ((1 << w) <= max) {
            ++w;
        }
        return w;
    }

    /// RLE / bit-packed hybrid levels of bit width `w`.
    static auto levels(std::string_view in, std::size_t n, int w) -> std::vector<std::uint32_t> {
        std::vector<std::uint32_t> out;
        std::size_t at = 0;
        const auto bytes = static_cast<std::size_t>((w + 7) / 8);
        while (out.size() < n && at < in.size()) {
            std::uint64_t h = 0;
            for (unsigned shift = 0;; shift += 7) {
                const auto b = static_cast<unsigned char>(in[at++]);
                h |= static_cast<std::uint64_t>(b & 0x7FU) << shift;
                if ((b & 0x80U) == 0) {
                    break;
                }
            }
            if ((h & 1U) == 0) {
                std::uint32_t v = 0;
                for (std::size_t b = 0; b < bytes; ++b) {
                    v |= static_cast<std::uint32_t>(static_cast<unsigned char>(in[at++]))
                         << (8 * b);
                }
                out.insert(out.end(), h >> 1U, v);
            } else {
                // Bit-packed groups of eight values, LSB first.
                const auto groups = h >> 1U;
                std::uint64_t acc = 0;
                int have = 0;
                for (std::uint64_t g = 0; g < groups * 8; ++g) {
                    while (have < w) {
                        acc |= static_cast<std::uint64_t>(static_cast<unsigned char>(in[at++]))
                               << have;
                        have += 8;
                    }
                    out.push_back(static_cast<std::uint32_t>(acc & ((1U << w) - 1U)));
                    acc >>= w;
                    have -= w;
                }
            }
        }
        out.resize(n);
        return out;
    }
};

}  // namespace parquet_test
