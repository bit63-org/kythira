// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_kms.hpp
/// @brief Encryption at rest (`.kiro/specs/kinesis-compatible-streams/` task 14,
///        Requirement 14.1): sealing records. The `kms_key_provider`
///        concept and the local provider are core's
///        (raft/kms_key_provider.hpp), shared with DynamoDB.
///
/// An encrypted stream seals each record with an AES-256-GCM data key. The
/// gateway that takes the write seals it before proposing, so the Raft log,
/// the segments on every replica, peer fetches and tiered objects all carry
/// ciphertext, and the replicas stay byte-identical. The data key itself is
/// stored in the catalog only wrapped by a key provider; each node unwraps
/// it once and keeps it in memory.
///
/// A sealed stored record is:
///
///     u16 0xFFFF | u32 generation | 12-byte nonce | ciphertext | 16-byte tag
///
/// The ciphertext is the plaintext stored record (partition key and data).
/// The marker cannot start a plaintext record (partition keys are at most
/// 256 bytes), so one shard holds both kinds after encryption starts or
/// stops. The additional data is the shard's routing key and the
/// generation, so a record copied into another shard or relabelled with
/// another key does not open. The nonce is random: 96 bits leave the
/// chance of a repeat under one key negligible at any write rate a shard
/// takes before its stream is re-keyed.
///
/// Providers throw `kms_error`, which the service answers as the matching
/// `KMS*Exception`.

#include <kythira/kinesis/kinesis_stream_state_machine.hpp>

#include <raft/kms_key_provider.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::kinesis {

using kms_provider::data_key_bytes;
using kms_provider::encryption_context;
using kms_provider::generated_data_key;
using kms_provider::key_provider;
using kms_provider::kms_caller;
using kms_provider::kms_error;
using kms_provider::kms_failure;
using kms_provider::kms_key_provider;
using kms_provider::local_kms_provider;
using kms_provider::per_caller_kms_key_provider;
using kms_provider::shared_kms_key_provider;

/// A sealed record that does not open: its tag fails, it is truncated, or
/// its generation has no data key. Data corruption, not a provider error.
class record_open_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace kms_detail {

using namespace kms_provider::detail;  // NOLINT(google-build-using-namespace)

[[nodiscard]] inline auto record_aad(std::string_view routing_key, std::uint32_t generation)
    -> std::string {
    std::string out(routing_key);
    out.push_back('\0');
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((generation >> shift) & 0xFFU));
    }
    return out;
}

}  // namespace kms_detail

// ---- sealed records -------------------------------------------------------

/// `partition_key` and `data` sealed under `key` (generation `generation`)
/// for the shard at `routing_key`.
[[nodiscard]] inline auto seal_record(const data_key_bytes& key, std::uint32_t generation,
                                      std::string_view routing_key, std::string_view partition_key,
                                      std::span<const std::byte> data) -> std::vector<std::byte> {
    auto plain = encode_stored_record(partition_key, data);
    std::array<unsigned char, kms_detail::k_nonce_len> nonce{};
    kms_detail::random_fill(nonce);
    std::vector<std::byte> out;
    out.reserve(6 + nonce.size() + plain.size() + kms_detail::k_tag_len);
    out.push_back(std::byte{0xFF});
    out.push_back(std::byte{0xFF});
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::byte>((generation >> shift) & 0xFFU));
    }
    for (const auto b : nonce) {
        out.push_back(static_cast<std::byte>(b));
    }
    kms_detail::gcm_seal(key, nonce, kms_detail::record_aad(routing_key, generation), plain, out);
    OPENSSL_cleanse(plain.data(), plain.size());
    return out;
}

/// The data key generation a sealed record names; nullopt for a plaintext
/// or truncated one.
[[nodiscard]] inline auto sealed_generation(std::span<const std::byte> bytes)
    -> std::optional<std::uint32_t> {
    if (!is_sealed_record(bytes) || bytes.size() < k_sealed_record_overhead) {
        return std::nullopt;
    }
    std::uint32_t g = 0;
    for (std::size_t i = 2; i < 6; ++i) {
        g = (g << 8) | std::to_integer<std::uint32_t>(bytes[i]);
    }
    return g;
}

/// The stored record inside sealed `bytes`. Throws `record_open_error` when
/// it does not open under `key` for `routing_key`.
[[nodiscard]] inline auto open_record(const data_key_bytes& key, std::string_view routing_key,
                                      std::span<const std::byte> bytes) -> stored_record {
    const auto generation = sealed_generation(bytes);
    if (!generation) {
        throw record_open_error("kinesis kms: not a sealed record");
    }
    std::array<unsigned char, kms_detail::k_nonce_len> nonce{};
    std::memcpy(nonce.data(), bytes.data() + 6, nonce.size());
    auto plain = kms_detail::gcm_open(key, nonce, kms_detail::record_aad(routing_key, *generation),
                                      bytes.subspan(6 + nonce.size()));
    if (!plain) {
        throw record_open_error("kinesis kms: a sealed record failed its tag");
    }
    try {
        auto out = decode_stored_record(*plain);
        OPENSSL_cleanse(plain->data(), plain->size());
        return out;
    } catch (const std::exception&) {
        throw record_open_error("kinesis kms: a sealed record holds no stored record");
    }
}

}  // namespace kythira::kinesis
