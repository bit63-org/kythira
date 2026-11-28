// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file ec2_catalog.hpp
/// @brief The regional catalog group: identifier counters handed out in
///        blocks, VNI and MAC counters, and the ClientToken index
///        (`.kiro/specs/ec2-compatible-api/` task 4, design "Identifiers"
///        and "Partitioning"; Requirements 4.1-4.3).
///
/// ### Identifiers
///
/// Every resource kind has a 64-bit counter. A group that creates resources
/// takes a block of IDs (`allocate_ids`) and hands them out locally
/// (`id_block`), so creating a volume does not round-trip to the catalog.
/// A counter only grows, a block is never handed out twice, and the
/// counters are in the catalog's snapshots, so no ID is reused across
/// leader changes, restarts or snapshot installs (Requirement 4.1). A group
/// that splits does not share its block: each side keeps or takes its own,
/// and the IDs a side never used are simply skipped. IDs start at 1;
/// running out is `exhausted`, never a wrap. The EC2 form of an ID
/// (`i-0` and 16 hex digits) is antikythera's `proto::ec2_id`, applied by
/// the handlers.
///
/// ### VNIs and MACs
///
/// VNIs come one at a time from the 24-bit space above the configured
/// first VNI, MACs from a locally administered prefix with 24 or 32 bits
/// of counter (Requirement 4.2). Neither is ever reused.
///
/// ### ClientToken index
///
/// `record_token` stores (account, operation, token) with a fingerprint of
/// the request and its result. A later request with the same key and
/// fingerprint gets the stored result (the original answer, Requirement
/// 4.3); with another fingerprint `mismatch`, which the front end answers
/// as `IdempotentParameterMismatch`. Entries expire after the profile's
/// retention, by the leader's clock stamped into the command, so every
/// replica decides alike; `expire_tokens` drops them. The index is one map
/// in the catalog group, so a retry reaches the same entry whichever front
/// end it lands on and whichever leader the group has.

#include <kythira/ec2/ec2_codec.hpp>

#include <raft/aws_ec2_protocol.hpp>

#include <openssl/sha.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::ec2 {

/// Every kind of resource with an identifier from the catalog.
enum class id_kind : std::uint8_t {
    instance,
    volume,
    snapshot,
    image,
    vpc,
    subnet,
    route_table,
    network_interface,
    route_table_association,
    vpc_cidr_association,
    subnet_cidr_association,
};

inline constexpr std::size_t k_id_kinds = 11;

/// The EC2 prefix of each kind, with its hyphen (Requirement 4.1).
[[nodiscard]] constexpr auto id_prefix(id_kind k) -> std::string_view {
    constexpr std::array<std::string_view, k_id_kinds> prefixes = {
        "i-",
        "vol-",
        "snap-",
        "ami-",
        "vpc-",
        "subnet-",
        "rtb-",
        "eni-",
        "rtbassoc-",
        "vpc-cidr-assoc-",
        "subnet-cidr-assoc-",
    };
    return prefixes.at(static_cast<std::size_t>(k));
}

/// A range of IDs a group owns: `[_next, _end)`.
struct id_block {
    std::uint64_t _next = 0;
    std::uint64_t _end = 0;

    [[nodiscard]] auto remaining() const -> std::uint64_t { return _end - _next; }

    /// The next ID, or nullopt when the block is used up (take another).
    [[nodiscard]] auto take() -> std::optional<std::uint64_t> {
        if (_next >= _end) {
            return std::nullopt;
        }
        return _next++;
    }

    friend auto operator==(const id_block&, const id_block&) -> bool = default;
};

/// The catalog's fixed configuration (the same on every replica).
struct catalog_config {
    /// The first VNI handed out; VNIs below it are left to the operator.
    std::uint32_t _first_vni = 4096;
    /// The locally administered MAC prefix, in the high bytes of a 48-bit
    /// value, and how many low bits the counter owns (24 or 32).
    std::uint64_t _mac_prefix = 0x02'4b'59'00'00'00ULL;  // 02:4b:59 ("KY")
    unsigned _mac_counter_bits = 24;
    /// The largest block one request may take.
    std::uint64_t _max_block = 1U << 20U;

    friend auto operator==(const catalog_config&, const catalog_config&) -> bool = default;
};

inline constexpr std::uint32_t k_max_vni = (1U << 24U) - 1U;

/// One stored ClientToken.
struct token_record {
    std::string _fingerprint;
    std::string _result;
    std::int64_t _created_ms = 0;
    std::int64_t _expires_ms = 0;

    friend auto operator==(const token_record&, const token_record&) -> bool = default;
};

// ---- commands ----------------------------------------------------------

struct allocate_ids_command {
    id_kind _kind = id_kind::instance;
    std::uint64_t _count = 0;
};
struct allocate_vni_command {};
struct allocate_mac_command {};
struct record_token_command {
    std::string _account;
    std::string _operation;
    std::string _token;
    std::string _fingerprint;
    std::string _result;
    std::int64_t _now_ms = 0;
    std::int64_t _retention_ms = 0;
};
struct expire_tokens_command {
    std::int64_t _now_ms = 0;
};

using catalog_command =
    std::variant<allocate_ids_command, allocate_vni_command, allocate_mac_command,
                 record_token_command, expire_tokens_command>;

enum class catalog_status : std::uint8_t {
    ok,
    invalid,    // a command that does not decode or asks for nothing
    exhausted,  // the counter cannot cover the request
    duplicate,  // a ClientToken already recorded with this fingerprint
    mismatch,   // a ClientToken already recorded with another fingerprint
};

struct catalog_result {
    catalog_status _status = catalog_status::ok;
    /// allocate_ids: the block; allocate_vni / allocate_mac: `_first` is the
    /// value.
    std::uint64_t _first = 0;
    std::uint64_t _end = 0;
    /// record_token: the stored result (the new one, or the original on
    /// `duplicate`); expire_tokens: empty.
    std::string _result{};
    std::uint64_t _expired = 0;

    friend auto operator==(const catalog_result&, const catalog_result&) -> bool = default;
};

inline constexpr std::uint8_t k_catalog_command_version = 1;

[[nodiscard]] inline auto encode_command(const catalog_command& c) -> std::vector<std::byte> {
    codec::writer w;
    w.u8(k_catalog_command_version).u8(static_cast<std::uint8_t>(c.index()));
    std::visit(
        [&w](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, allocate_ids_command>) {
                w.u8(static_cast<std::uint8_t>(v._kind)).u64(v._count);
            } else if constexpr (std::is_same_v<T, record_token_command>) {
                w.str(v._account).str(v._operation).str(v._token).str(v._fingerprint);
                w.str(v._result).i64(v._now_ms).i64(v._retention_ms);
            } else if constexpr (std::is_same_v<T, expire_tokens_command>) {
                w.i64(v._now_ms);
            }
        },
        c);
    return w.take();
}

[[nodiscard]] inline auto decode_command(std::span<const std::byte> bytes) -> catalog_command {
    codec::reader r(bytes);
    if (r.u8() != k_catalog_command_version) {
        throw ec2_codec_error("ec2 codec: unknown catalog command version");
    }
    catalog_command out;
    switch (r.u8()) {
        case 0: {
            allocate_ids_command c;
            c._kind = r.enumeration<id_kind>(static_cast<std::uint8_t>(k_id_kinds - 1));
            c._count = r.u64();
            out = c;
            break;
        }
        case 1:
            out = allocate_vni_command{};
            break;
        case 2:
            out = allocate_mac_command{};
            break;
        case 3: {
            record_token_command c;
            c._account = r.str();
            c._operation = r.str();
            c._token = r.str();
            c._fingerprint = r.str();
            c._result = r.str();
            c._now_ms = r.i64();
            c._retention_ms = r.i64();
            out = std::move(c);
            break;
        }
        case 4:
            out = expire_tokens_command{r.i64()};
            break;
        default:
            throw ec2_codec_error("ec2 codec: unknown catalog command");
    }
    r.expect_end("catalog command");
    return out;
}

[[nodiscard]] inline auto encode_result(const catalog_result& res) -> std::vector<std::byte> {
    codec::writer w;
    w.u8(static_cast<std::uint8_t>(res._status)).u64(res._first).u64(res._end).str(res._result);
    w.u64(res._expired);
    return w.take();
}

[[nodiscard]] inline auto decode_result(std::span<const std::byte> bytes) -> catalog_result {
    codec::reader r(bytes);
    catalog_result out;
    out._status =
        r.enumeration<catalog_status>(static_cast<std::uint8_t>(catalog_status::mismatch));
    out._first = r.u64();
    out._end = r.u64();
    out._result = r.str();
    out._expired = r.u64();
    r.expect_end("catalog result");
    return out;
}

/// SHA-256 over a request's parameters, without the ones that do not change
/// what it asks for (`ClientToken` itself, `DryRun`, the SigV4 parameters
/// of a presigned GET), in the sorted encoding: two requests with the same
/// parameters in any order, from any SDK, fingerprint alike.
[[nodiscard]] inline auto request_fingerprint(std::string_view operation, const aws_ec2::params& p)
    -> std::string {
    aws_ec2::params::map_type kept;
    for (const auto& [k, v] : p.all()) {
        if (k == "ClientToken" || k == "DryRun" || k.starts_with("X-Amz-")) {
            continue;
        }
        kept.emplace(k, v);
    }
    const auto text = std::string(operation) + "\n" + aws_ec2::params(std::move(kept)).encode();
    std::array<unsigned char, SHA256_DIGEST_LENGTH> md{};
    SHA256(reinterpret_cast<const unsigned char*>(text.data()), text.size(), md.data());
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    for (const auto b : md) {
        out.push_back(hex[b >> 4U]);
        out.push_back(hex[b & 0x0FU]);
    }
    return out;
}

/// A ClientToken as EC2 accepts it: 1 to 64 printable ASCII characters.
[[nodiscard]] inline auto check_client_token(std::string_view token)
    -> std::optional<aws_ec2::error> {
    if (token.empty() || token.size() > 64) {
        return aws_ec2::make_error(aws_ec2::codes::invalid_parameter_value,
                                   "The client token must be 1 to 64 ASCII characters.");
    }
    for (const char c : token) {
        if (c < 0x20 || c > 0x7E) {
            return aws_ec2::make_error(aws_ec2::codes::invalid_parameter_value,
                                       "The client token must be 1 to 64 ASCII characters.");
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline auto idempotent_parameter_mismatch() -> aws_ec2::error {
    return aws_ec2::make_error(aws_ec2::codes::idempotent_parameter_mismatch,
                               "The client token you have provided is associated with a "
                               "request with different parameters.");
}

class catalog_state_machine {
public:
    catalog_state_machine() = default;
    explicit catalog_state_machine(catalog_config config) : _config(config) {}

    // ---- kythira::state_machine -------------------------------------------

    auto apply(const std::vector<std::byte>& command, std::uint64_t index)
        -> std::vector<std::byte> {
        _last_applied = index;
        catalog_command c;
        try {
            c = decode_command(command);
        } catch (const ec2_codec_error&) {
            return encode_result({._status = catalog_status::invalid});
        }
        return encode_result(std::visit([this](const auto& v) { return apply_one(v); }, c));
    }

    [[nodiscard]] auto get_state() const -> std::vector<std::byte> {
        codec::writer w;
        w.u8(k_snapshot_version);
        for (const auto n : _next_id) {
            w.u64(n);
        }
        w.u32(_next_vni).u64(_next_mac);
        w.u32(static_cast<std::uint32_t>(_tokens.size()));
        for (const auto& [key, t] : _tokens) {
            w.str(std::get<0>(key)).str(std::get<1>(key)).str(std::get<2>(key));
            w.str(t._fingerprint).str(t._result).i64(t._created_ms).i64(t._expires_ms);
        }
        return w.take();
    }

    auto restore_from_snapshot(const std::vector<std::byte>& data, std::uint64_t index) -> void {
        codec::reader r(data);
        if (r.u8() != k_snapshot_version) {
            throw ec2_codec_error("ec2 codec: unknown catalog snapshot version");
        }
        std::array<std::uint64_t, k_id_kinds> next{};
        for (auto& n : next) {
            n = r.u64();
        }
        const auto vni = r.u32();
        const auto mac = r.u64();
        std::map<token_key, token_record, std::less<>> tokens;
        const auto n = r.count(8U * 4U);
        for (std::uint32_t i = 0; i < n; ++i) {
            token_key key{r.str(), r.str(), r.str()};
            token_record t;
            t._fingerprint = r.str();
            t._result = r.str();
            t._created_ms = r.i64();
            t._expires_ms = r.i64();
            tokens.emplace(std::move(key), std::move(t));
        }
        r.expect_end("catalog snapshot");
        _next_id = next;
        _next_vni = vni;
        _next_mac = mac;
        _tokens = std::move(tokens);
        _last_applied = index;
    }

    // ---- queries -------------------------------------------------------------

    [[nodiscard]] auto last_applied_index() const -> std::uint64_t { return _last_applied; }
    [[nodiscard]] auto next_id(id_kind k) const -> std::uint64_t {
        return _next_id.at(static_cast<std::size_t>(k));
    }
    [[nodiscard]] auto next_vni() const -> std::uint32_t { return _next_vni; }
    [[nodiscard]] auto token_count() const -> std::size_t { return _tokens.size(); }

    /// A live token's record (expired ones read as absent), for a front end
    /// that checks before it starts the work.
    [[nodiscard]] auto find_token(std::string_view account, std::string_view operation,
                                  std::string_view token, std::int64_t now_ms) const
        -> const token_record* {
        const auto it = _tokens.find(std::tuple{account, operation, token});
        return it == _tokens.end() || it->second._expires_ms <= now_ms ? nullptr : &it->second;
    }

    /// A MAC from the counter value `allocate_mac` returned, as EC2 writes
    /// it (`02:4b:59:00:00:01`).
    [[nodiscard]] auto mac_text(std::uint64_t value) const -> std::string {
        static constexpr std::string_view hex = "0123456789abcdef";
        std::string out;
        for (int byte = 5; byte >= 0; --byte) {
            const auto b =
                static_cast<unsigned>((value >> (8U * static_cast<unsigned>(byte))) & 0xFFU);
            out.push_back(hex[b >> 4U]);
            out.push_back(hex[b & 0xFU]);
            if (byte != 0) {
                out.push_back(':');
            }
        }
        return out;
    }

private:
    using token_key = std::tuple<std::string, std::string, std::string>;
    static constexpr std::uint8_t k_snapshot_version = 1;

    catalog_config _config;
    std::array<std::uint64_t, k_id_kinds> _next_id = [] {
        std::array<std::uint64_t, k_id_kinds> a{};
        a.fill(1);
        return a;
    }();
    std::uint32_t _next_vni = 0;  // 0: not started, the configured first VNI
    std::uint64_t _next_mac = 1;
    std::map<token_key, token_record, std::less<>> _tokens;
    std::uint64_t _last_applied = 0;

    auto apply_one(const allocate_ids_command& c) -> catalog_result {
        if (c._count == 0 || c._count > _config._max_block) {
            return {._status = catalog_status::invalid};
        }
        auto& next = _next_id.at(static_cast<std::size_t>(c._kind));
        if (next > std::numeric_limits<std::uint64_t>::max() - c._count) {
            return {._status = catalog_status::exhausted};
        }
        catalog_result out{._first = next, ._end = next + c._count};
        next += c._count;
        return out;
    }

    auto apply_one(const allocate_vni_command&) -> catalog_result {
        if (_next_vni == 0) {
            _next_vni = _config._first_vni;
        }
        if (_next_vni > k_max_vni) {
            return {._status = catalog_status::exhausted};
        }
        return {._first = _next_vni++};
    }

    auto apply_one(const allocate_mac_command&) -> catalog_result {
        const auto limit = (std::uint64_t{1} << _config._mac_counter_bits) - 1U;
        if (_next_mac > limit) {
            return {._status = catalog_status::exhausted};
        }
        return {._first = _config._mac_prefix | _next_mac++};
    }

    auto apply_one(const record_token_command& c) -> catalog_result {
        if (c._token.empty() || c._retention_ms <= 0) {
            return {._status = catalog_status::invalid};
        }
        const auto it =
            _tokens.find(std::tuple{std::string_view(c._account), std::string_view(c._operation),
                                    std::string_view(c._token)});
        if (it != _tokens.end() && it->second._expires_ms > c._now_ms) {
            if (it->second._fingerprint == c._fingerprint) {
                return {._status = catalog_status::duplicate, ._result = it->second._result};
            }
            return {._status = catalog_status::mismatch};
        }
        token_record t{c._fingerprint, c._result, c._now_ms, c._now_ms + c._retention_ms};
        _tokens.insert_or_assign(token_key{c._account, c._operation, c._token}, t);
        return {._result = c._result};
    }

    auto apply_one(const expire_tokens_command& c) -> catalog_result {
        const auto n = std::erase_if(
            _tokens, [&](const auto& kv) { return kv.second._expires_ms <= c._now_ms; });
        return {._expired = static_cast<std::uint64_t>(n)};
    }
};

}  // namespace kythira::ec2
