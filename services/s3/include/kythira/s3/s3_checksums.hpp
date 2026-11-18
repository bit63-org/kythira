// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_checksums.hpp
/// @brief S3's additional checksums (.kiro/specs/s3-compatible-storage/
///        task 8, Requirement 7.4): CRC32, CRC32C, CRC64NVME, SHA-1 and
///        SHA-256, full-object and composite, from headers or trailers.
///
/// **On the wire.** A checksum is the base64 of the big-endian digest, in
/// `x-amz-checksum-<algorithm>`, as a header or as an `aws-chunked`
/// trailer named by `x-amz-trailer`. `x-amz-sdk-checksum-algorithm` names
/// the algorithm when the value comes later. At most one algorithm per
/// request.
///
/// **Stored.** A PUT computes the checksum the request names while the
/// body streams and refuses a mismatch with `BadDigest`; with none named,
/// it computes CRC64NVME, as S3 has for every new object since December
/// 2024. The object keeps `x-amz-checksum-<algorithm>` and
/// `x-amz-checksum-type` (`FULL_OBJECT`, or `COMPOSITE` for a multipart
/// object whose checksum covers its parts' checksums) and returns them
/// when a read asks with `x-amz-checksum-mode: ENABLED`.
///
/// **Multipart** (task 9 uses these). A composite checksum is the
/// algorithm over the parts' raw checksums, concatenated, written
/// `<base64>-<part count>`. A full-object checksum of a multipart object
/// (CRCs only) is the parts' CRCs combined with `crc_combine`, the GF(2)
/// shift zlib's `crc32_combine` uses, so no byte is read twice.

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_rest_xml_protocol.hpp>

#include <boost/crc.hpp>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

enum class checksum_algorithm : std::uint8_t {
    crc32,
    crc32c,
    crc64nvme,
    sha1,
    sha256
};

inline constexpr std::array<checksum_algorithm, 5> all_checksum_algorithms{
    checksum_algorithm::crc32, checksum_algorithm::crc32c, checksum_algorithm::crc64nvme,
    checksum_algorithm::sha1, checksum_algorithm::sha256};

/// `CRC32`, as `x-amz-sdk-checksum-algorithm` and error messages spell it.
[[nodiscard]] inline auto to_string(checksum_algorithm a) -> std::string_view {
    switch (a) {
        case checksum_algorithm::crc32:
            return "CRC32";
        case checksum_algorithm::crc32c:
            return "CRC32C";
        case checksum_algorithm::crc64nvme:
            return "CRC64NVME";
        case checksum_algorithm::sha1:
            return "SHA1";
        case checksum_algorithm::sha256:
            return "SHA256";
    }
    return "CRC64NVME";
}

/// `x-amz-checksum-crc32`.
[[nodiscard]] inline auto checksum_header(checksum_algorithm a) -> std::string {
    std::string out = "x-amz-checksum-";
    for (char c : to_string(a)) {
        out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    return out;
}

/// `ChecksumCRC32`, the XML element name.
[[nodiscard]] inline auto checksum_element(checksum_algorithm a) -> std::string {
    return "Checksum" + std::string(to_string(a));
}

[[nodiscard]] inline auto parse_checksum_algorithm(std::string_view s)
    -> std::optional<checksum_algorithm> {
    for (auto a : all_checksum_algorithms) {
        if (aws_rest_xml::detail::iequals(to_string(a), s)) {
            return a;
        }
    }
    return std::nullopt;
}

/// The algorithm an `x-amz-checksum-*` name stands for.
[[nodiscard]] inline auto algorithm_of_header(std::string_view name)
    -> std::optional<checksum_algorithm> {
    for (auto a : all_checksum_algorithms) {
        if (aws_rest_xml::detail::iequals(checksum_header(a), name)) {
            return a;
        }
    }
    return std::nullopt;
}

/// Digest size in bytes.
[[nodiscard]] constexpr auto digest_bytes(checksum_algorithm a) noexcept -> std::size_t {
    switch (a) {
        case checksum_algorithm::crc32:
        case checksum_algorithm::crc32c:
            return 4;
        case checksum_algorithm::crc64nvme:
            return 8;
        case checksum_algorithm::sha1:
            return 20;
        case checksum_algorithm::sha256:
            return 32;
    }
    return 0;
}

[[nodiscard]] constexpr auto is_crc(checksum_algorithm a) noexcept -> bool {
    return a == checksum_algorithm::crc32 || a == checksum_algorithm::crc32c ||
           a == checksum_algorithm::crc64nvme;
}

namespace checksum_detail {

using crc32_t = boost::crc_optimal<32, 0x04C11DB7U, 0xFFFFFFFFU, 0xFFFFFFFFU, true, true>;
using crc32c_t = boost::crc_optimal<32, 0x1EDC6F41U, 0xFFFFFFFFU, 0xFFFFFFFFU, true, true>;
using crc64nvme_t = boost::crc_optimal<64, 0xAD93D23594C93659ULL, ~0ULL, ~0ULL, true, true>;

[[nodiscard]] inline auto big_endian(std::uint64_t v, std::size_t bytes) -> std::string {
    std::string out(bytes, '\0');
    for (std::size_t i = 0; i < bytes; ++i) {
        out[bytes - 1 - i] = static_cast<char>(v & 0xFFU);
        v >>= 8U;
    }
    return out;
}

[[nodiscard]] inline auto from_big_endian(std::string_view raw) -> std::uint64_t {
    std::uint64_t v = 0;
    for (unsigned char c : raw) {
        v = (v << 8U) | c;
    }
    return v;
}

[[nodiscard]] inline auto b64(std::string_view raw) -> std::string {
    return aws_json::base64_encode(std::as_bytes(std::span(raw.data(), raw.size())));
}

/// The reflected polynomial of a CRC.
[[nodiscard]] constexpr auto reflected_poly(checksum_algorithm a) noexcept -> std::uint64_t {
    switch (a) {
        case checksum_algorithm::crc32:
            return 0xEDB88320U;
        case checksum_algorithm::crc32c:
            return 0x82F63B78U;
        case checksum_algorithm::crc64nvme:
            return 0x9A6C9329AC4BC9B5ULL;
        default:
            return 0;
    }
}

}  // namespace checksum_detail

/// The raw digest from a wire value, or nothing when it is not valid
/// base64 of the right length.
[[nodiscard]] inline auto decode_checksum(checksum_algorithm a, std::string_view value)
    -> std::optional<std::string> {
    auto bytes = aws_json::base64_decode(value);
    if (!bytes || bytes->size() != digest_bytes(a)) {
        return std::nullopt;
    }
    std::string out(bytes->size(), '\0');
    for (std::size_t i = 0; i < bytes->size(); ++i) {
        out[i] = static_cast<char>((*bytes)[i]);
    }
    return out;
}

/// A streaming digest.
class checksummer {
public:
    explicit checksummer(checksum_algorithm a) : _a(a) {
        if (!is_crc(a)) {
            _md.reset(::EVP_MD_CTX_new());
            const auto* md = a == checksum_algorithm::sha1 ? ::EVP_sha1() : ::EVP_sha256();
            if (!_md || ::EVP_DigestInit_ex(_md.get(), md, nullptr) != 1) {
                throw std::runtime_error("s3 checksums: digest init failed");
            }
        }
    }

    [[nodiscard]] auto algorithm() const noexcept -> checksum_algorithm { return _a; }

    void update(std::span<const std::byte> bytes) {
        switch (_a) {
            case checksum_algorithm::crc32:
                _crc32.process_bytes(bytes.data(), bytes.size());
                break;
            case checksum_algorithm::crc32c:
                _crc32c.process_bytes(bytes.data(), bytes.size());
                break;
            case checksum_algorithm::crc64nvme:
                _crc64.process_bytes(bytes.data(), bytes.size());
                break;
            case checksum_algorithm::sha1:
            case checksum_algorithm::sha256:
                if (!bytes.empty() &&
                    ::EVP_DigestUpdate(_md.get(), bytes.data(), bytes.size()) != 1) {
                    throw std::runtime_error("s3 checksums: digest update failed");
                }
                break;
        }
    }
    void update(std::string_view s) { update(std::as_bytes(std::span(s.data(), s.size()))); }

    /// The raw big-endian digest. Call once.
    [[nodiscard]] auto raw() -> std::string {
        using checksum_detail::big_endian;
        switch (_a) {
            case checksum_algorithm::crc32:
                return big_endian(_crc32.checksum(), 4);
            case checksum_algorithm::crc32c:
                return big_endian(_crc32c.checksum(), 4);
            case checksum_algorithm::crc64nvme:
                return big_endian(_crc64.checksum(), 8);
            case checksum_algorithm::sha1:
            case checksum_algorithm::sha256: {
                std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
                unsigned int len = 0;
                if (::EVP_DigestFinal_ex(_md.get(), md.data(), &len) != 1) {
                    throw std::runtime_error("s3 checksums: digest final failed");
                }
                return {reinterpret_cast<const char*>(md.data()), len};  // NOLINT
            }
        }
        return {};
    }
    /// The wire value (base64). Call once.
    [[nodiscard]] auto value() -> std::string { return checksum_detail::b64(raw()); }

private:
    struct free_ctx {
        void operator()(EVP_MD_CTX* c) const noexcept { ::EVP_MD_CTX_free(c); }
    };
    checksum_algorithm _a;
    checksum_detail::crc32_t _crc32;
    checksum_detail::crc32c_t _crc32c;
    checksum_detail::crc64nvme_t _crc64;
    std::unique_ptr<EVP_MD_CTX, free_ctx> _md;
};

/// The wire checksum of `data`.
[[nodiscard]] inline auto checksum_of(checksum_algorithm a, std::string_view data) -> std::string {
    checksummer c(a);
    c.update(data);
    return c.value();
}

// ---------------------------------------------------------------------------
// Combining CRCs (multipart full-object checksums)
// ---------------------------------------------------------------------------

namespace checksum_detail {

/// Multiply the GF(2) matrix `mat` (one column per bit) by `vec`.
[[nodiscard]] inline auto gf2_times(const std::array<std::uint64_t, 64>& mat, std::uint64_t vec)
    -> std::uint64_t {
    std::uint64_t sum = 0;
    for (std::size_t i = 0; vec != 0; ++i, vec >>= 1U) {
        if ((vec & 1U) != 0) {
            sum ^= mat.at(i);
        }
    }
    return sum;
}

inline void gf2_square(std::array<std::uint64_t, 64>& square,
                       const std::array<std::uint64_t, 64>& mat, std::size_t width) {
    for (std::size_t n = 0; n < width; ++n) {
        square.at(n) = gf2_times(mat, mat.at(n));
    }
}

}  // namespace checksum_detail

/// The CRC of A followed by B, from CRC(A), CRC(B) and B's length (zlib's
/// `crc32_combine`, for any reflected CRC with all-ones initial value and
/// final XOR, which all three of S3's are).
[[nodiscard]] inline auto crc_combine(checksum_algorithm a, std::uint64_t crc_a,
                                      std::uint64_t crc_b, std::uint64_t len_b) -> std::uint64_t {
    using checksum_detail::gf2_square;
    using checksum_detail::gf2_times;
    if (!is_crc(a)) {
        throw std::invalid_argument("crc_combine: not a CRC");
    }
    if (len_b == 0) {
        return crc_a;
    }
    const std::size_t width = digest_bytes(a) * 8;
    std::array<std::uint64_t, 64> even{};
    std::array<std::uint64_t, 64> odd{};
    // The operator for one zero bit.
    odd.at(0) = checksum_detail::reflected_poly(a);
    std::uint64_t row = 1;
    for (std::size_t n = 1; n < width; ++n) {
        odd.at(n) = row;
        row <<= 1U;
    }
    gf2_square(even, odd, width);  // two zero bits
    gf2_square(odd, even, width);  // four zero bits
    // Apply len_b zero bytes to crc_a, squaring as we go.
    do {
        gf2_square(even, odd, width);
        if ((len_b & 1U) != 0) {
            crc_a = gf2_times(even, crc_a);
        }
        len_b >>= 1U;
        if (len_b == 0) {
            break;
        }
        gf2_square(odd, even, width);
        if ((len_b & 1U) != 0) {
            crc_a = gf2_times(odd, crc_a);
        }
        len_b >>= 1U;
    } while (len_b != 0);
    return crc_a ^ crc_b;
}

/// A multipart object's full-object CRC from its parts' wire checksums and
/// sizes, or nothing when a part's value is malformed.
[[nodiscard]] inline auto combine_full_object(
    checksum_algorithm a, const std::vector<std::pair<std::string, std::uint64_t>>& parts)
    -> std::optional<std::string> {
    std::uint64_t crc = 0;
    bool first = true;
    for (const auto& [value, size] : parts) {
        auto raw = decode_checksum(a, value);
        if (!raw) {
            return std::nullopt;
        }
        const auto part = checksum_detail::from_big_endian(*raw);
        crc = first ? part : crc_combine(a, crc, part, size);
        first = false;
    }
    if (first) {
        return checksum_of(a, {});
    }
    return checksum_detail::b64(checksum_detail::big_endian(crc, digest_bytes(a)));
}

/// A composite checksum: the algorithm over the parts' raw checksums,
/// `<base64>-<parts>`.
[[nodiscard]] inline auto composite_checksum(checksum_algorithm a,
                                             const std::vector<std::string>& part_values)
    -> std::optional<std::string> {
    checksummer c(a);
    for (const auto& v : part_values) {
        auto raw = decode_checksum(a, v);
        if (!raw) {
            return std::nullopt;
        }
        c.update(*raw);
    }
    return c.value() + "-" + std::to_string(part_values.size());
}

// ---------------------------------------------------------------------------
// What a request asks for
// ---------------------------------------------------------------------------

/// The checksum a request names: its algorithm, and its value when it
/// came as a header (a trailer's arrives with the body's end).
struct requested_checksum {
    checksum_algorithm algorithm = checksum_algorithm::crc64nvme;
    std::optional<std::string> value;
    bool trailer = false;
    /// None named: S3's default, computed and stored.
    bool defaulted = true;
};

[[nodiscard]] inline auto invalid_checksum_request(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest", std::move(message));
}

/// Read the request's checksum headers.
[[nodiscard]] inline auto requested(const std::vector<std::pair<std::string, std::string>>& headers)
    -> aws_rest_xml::result<requested_checksum> {
    requested_checksum out;
    std::optional<checksum_algorithm> from_header;
    std::optional<checksum_algorithm> from_trailer;
    std::optional<checksum_algorithm> from_sdk;
    for (const auto& [k, v] : headers) {
        if (auto a = algorithm_of_header(k)) {
            if (from_header && *from_header != *a) {
                return invalid_checksum_request(
                    "Expecting a single x-amz-checksum- header. Multiple checksum Types are not "
                    "allowed.");
            }
            from_header = a;
            if (!decode_checksum(*a, v)) {
                return invalid_checksum_request("Value for " + checksum_header(*a) +
                                                " header is invalid.");
            }
            out.value = v;
        } else if (aws_rest_xml::detail::iequals(k, "x-amz-trailer")) {
            for (auto name : aws_rest_xml::detail::split_list(v)) {
                while (!name.empty() && name.front() == ' ') {
                    name.remove_prefix(1);
                }
                if (auto t = algorithm_of_header(name)) {
                    from_trailer = t;
                }
            }
        } else if (aws_rest_xml::detail::iequals(k, "x-amz-sdk-checksum-algorithm")) {
            from_sdk = parse_checksum_algorithm(v);
            if (!from_sdk) {
                return invalid_checksum_request(
                    "Value for x-amz-sdk-checksum-algorithm header is invalid.");
            }
        }
    }
    if (from_header && from_trailer) {
        return invalid_checksum_request(
            "Expecting a single x-amz-checksum- header. Multiple checksum Types are not "
            "allowed.");
    }
    const auto named = from_header ? from_header : from_trailer;
    if (from_sdk && !named) {
        return invalid_checksum_request(
            "x-amz-sdk-checksum-algorithm specified, but no corresponding x-amz-checksum-* or "
            "x-amz-trailer headers were found.");
    }
    if (from_sdk && named && *from_sdk != *named) {
        return invalid_checksum_request(
            "Value for x-amz-sdk-checksum-algorithm header is invalid.");
    }
    if (named) {
        out.algorithm = *named;
        out.defaulted = false;
        out.trailer = from_trailer.has_value();
    }
    return out;
}

[[nodiscard]] inline auto bad_digest(checksum_algorithm a) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "BadDigest",
                                      "The " + std::string(to_string(a)) +
                                          " you specified did not match the calculated "
                                          "checksum.");
}

/// Compare what was computed with what the request said (header, or the
/// trailer among `trailers`).
[[nodiscard]] inline auto verify(const requested_checksum& want, const std::string& computed,
                                 const std::vector<std::pair<std::string, std::string>>& trailers)
    -> std::optional<aws_rest_xml::error> {
    if (want.defaulted) {
        return std::nullopt;
    }
    std::optional<std::string> expected = want.value;
    if (want.trailer) {
        for (const auto& [k, v] : trailers) {
            if (aws_rest_xml::detail::iequals(k, checksum_header(want.algorithm))) {
                expected = v;
            }
        }
        if (!expected) {
            return invalid_checksum_request("The trailer " + checksum_header(want.algorithm) +
                                            " was declared but not sent.");
        }
        if (!decode_checksum(want.algorithm, *expected)) {
            return invalid_checksum_request("Value for " + checksum_header(want.algorithm) +
                                            " trailing header is invalid.");
        }
    }
    if (expected && *expected != computed) {
        return bad_digest(want.algorithm);
    }
    return std::nullopt;
}

}  // namespace kythira::s3
