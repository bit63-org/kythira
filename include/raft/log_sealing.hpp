// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file log_sealing.hpp
/// @brief The seam between `binary_file_persistence_engine` and whatever
///        seals its records (.kiro/specs/raft-log-encryption/).
///
/// The engine only needs to ask for "the newest generation" and to seal or
/// open a payload under a generation, bound to additional data. Keeping that
/// behind two small abstract classes keeps OpenSSL out of the engine's
/// header: `raft_log_encryption.hpp` holds the AES-256-GCM implementation and
/// the key ring, and only nodes that turn sealing on include it.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace kythira {

/// The 16 random bytes that name one log; part of every per-log key, so a
/// record copied into another log's directory does not open.
inline constexpr std::size_t log_id_bytes = 16;

/// Seals and opens one log's payloads. Not thread-safe: the engine calls it
/// under its own mutex.
class log_cipher {
public:
    log_cipher() = default;
    log_cipher(const log_cipher&) = delete;
    log_cipher(log_cipher&&) = delete;
    auto operator=(const log_cipher&) -> log_cipher& = delete;
    auto operator=(log_cipher&&) -> log_cipher& = delete;
    virtual ~log_cipher() = default;

    /// The generation new payloads are sealed under.
    [[nodiscard]] virtual auto newest_generation() const -> std::uint32_t = 0;

    /// `nonce || ciphertext || tag` for `plaintext` under `generation`.
    [[nodiscard]] virtual auto seal(std::uint32_t generation, std::span<const std::byte> aad,
                                    std::span<const std::byte> plaintext)
        -> std::vector<std::byte> = 0;

    /// The plaintext of `sealed`. Throws `persistence_exception` if the
    /// generation is unknown or the payload fails authentication.
    [[nodiscard]] virtual auto open(std::uint32_t generation, std::span<const std::byte> aad,
                                    std::span<const std::byte> sealed)
        -> std::vector<std::byte> = 0;
};

/// Bytes a sealed payload adds to its plaintext: a 96-bit nonce and a 128-bit
/// tag.
inline constexpr std::size_t sealed_overhead_bytes = 12 + 16;

/// A node's key ring as the engine sees it: one cipher per log.
class log_key_ring {
public:
    log_key_ring() = default;
    log_key_ring(const log_key_ring&) = delete;
    log_key_ring(log_key_ring&&) = delete;
    auto operator=(const log_key_ring&) -> log_key_ring& = delete;
    auto operator=(log_key_ring&&) -> log_key_ring& = delete;
    virtual ~log_key_ring() = default;

    [[nodiscard]] virtual auto cipher_for(std::span<const std::byte, log_id_bytes> log_id)
        -> std::unique_ptr<log_cipher> = 0;
};

/// What an engine with a key ring does with new records.
enum class log_encryption_mode : std::uint8_t {
    /// Seal every new record and snapshot under the newest generation.
    seal = 0,
    /// Write plaintext, but still open sealed records: the step on the way
    /// to turning sealing off (requirement 4.2).
    decrypt_only = 1,
};

}  // namespace kythira
