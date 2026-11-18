// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file raft_log_encryption.hpp
/// @brief The key ring and AES-256-GCM cipher that seal Raft log records and
///        snapshots at rest (.kiro/specs/raft-log-encryption/ task 1).
///
/// **Keys.** A node holds one key ring, shared by every Raft group's engine.
/// Each generation is a random 256-bit data key that a key provider wrapped;
/// only the wrapped form reaches disk, in one file (`raft-log-keys`) written
/// atomically:
///
/// ```
/// magic "KRLK", u32 version, u32 count,
/// { u32 generation, str key_id, str wrapped }*, u32 crc
/// ```
///
/// Every generation is unwrapped once when the ring opens, so a node makes
/// one provider call per generation per start, however many groups it runs
/// (requirement 3.2). A provider that cannot unwrap one is fatal: a node must
/// not start with a log it cannot read (requirement 3.5).
///
/// **Per-log keys.** A log's key for generation g is HKDF-SHA256 of the data
/// key, salted with the log's 16-byte id, so a record copied into another
/// log's directory, or a directory copied to another node, does not open
/// (requirement 1.3).
///
/// **Sealing.** AES-256-GCM with a fresh random 96-bit nonce per payload; the
/// caller's additional data binds the record's place in the log. Each log
/// has its own key per generation, so a log stays far inside GCM's 2^32
/// messages per key with random nonces, and rotation resets the count.
///
/// The provider is reached through `raft_log_key_source`, two callbacks, so
/// this header does not depend on any KMS client. `raft_log_kms.hpp` adapts
/// the services' shared `kms_provider::key_provider` to it.

#include <raft/binary_file_persistence.hpp>
#include <raft/exceptions.hpp>
#include <raft/log_sealing.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira {

using raft_log_data_key_bytes = std::array<unsigned char, 32>;

/// A data key fresh from a provider: the plaintext, its wrapped form, and the
/// provider's id for the key that wrapped it.
struct raft_log_data_key {
    raft_log_data_key_bytes _plaintext{};
    std::string _wrapped{};
    std::string _key_id{};
};

/// How a key ring reaches its key provider. Both callbacks throw on failure
/// (any exception); the ring reports which generation it was working on.
struct raft_log_key_source {
    std::function<raft_log_data_key()> _generate;
    std::function<raft_log_data_key_bytes(const std::string& key_id, const std::string& wrapped)>
        _unwrap;
};

namespace detail::log_encryption {

inline constexpr std::uint32_t key_ring_magic = 0x4B524C4BU;  // "KRLK"
inline constexpr std::uint32_t key_ring_version = 1;
inline constexpr std::size_t nonce_len = 12;
inline constexpr std::size_t tag_len = 16;
static_assert(nonce_len + tag_len == sealed_overhead_bytes);
inline constexpr std::string_view hkdf_info = "kythira raft log v1";

/// A data key that wipes itself.
struct wiped_key {
    raft_log_data_key_bytes _bytes{};
    wiped_key() = default;
    explicit wiped_key(const raft_log_data_key_bytes& b) : _bytes(b) {}
    wiped_key(const wiped_key&) = default;
    auto operator=(const wiped_key&) -> wiped_key& = default;
    wiped_key(wiped_key&&) = default;
    auto operator=(wiped_key&&) -> wiped_key& = default;
    ~wiped_key() { OPENSSL_cleanse(_bytes.data(), _bytes.size()); }
};

inline void random_fill(std::span<unsigned char> out) {
    if (!out.empty() && RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw persistence_exception("raft log encryption: RAND_bytes failed");
    }
}

/// HKDF-SHA256(ikm = key, salt = log_id, info = hkdf_info), 32 bytes.
[[nodiscard]] inline auto derive_log_key(const raft_log_data_key_bytes& key,
                                         std::span<const std::byte, log_id_bytes> log_id)
    -> wiped_key {
    wiped_key out;
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), &EVP_PKEY_CTX_free);
    std::size_t len = out._bytes.size();
    const bool ok =
        ctx && EVP_PKEY_derive_init(ctx.get()) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(log_id.data()),
                                    static_cast<int>(log_id.size())) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key.data(), static_cast<int>(key.size())) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(hkdf_info.data()),
                                    static_cast<int>(hkdf_info.size())) == 1 &&
        EVP_PKEY_derive(ctx.get(), out._bytes.data(), &len) == 1 && len == out._bytes.size();
    if (!ok) {
        throw persistence_exception("raft log encryption: HKDF failed");
    }
    return out;
}

using cipher_ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

[[nodiscard]] inline auto new_ctx() -> cipher_ctx {
    cipher_ctx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw persistence_exception("raft log encryption: EVP_CIPHER_CTX_new failed");
    }
    return ctx;
}

[[nodiscard]] inline auto as_uc(std::span<const std::byte> s) -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(s.data());
}

/// `nonce || ciphertext || tag`.
[[nodiscard]] inline auto gcm_seal(const raft_log_data_key_bytes& key,
                                   std::span<const std::byte> aad,
                                   std::span<const std::byte> plaintext) -> std::vector<std::byte> {
    std::vector<std::byte> out(nonce_len + plaintext.size() + tag_len);
    auto* base = reinterpret_cast<unsigned char*>(out.data());
    random_fill(std::span<unsigned char>(base, nonce_len));
    auto ctx = new_ctx();
    int n = 0;
    int fin = 0;
    const bool ok =
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_len),
                            nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), base) == 1 &&
        (aad.empty() || EVP_EncryptUpdate(ctx.get(), nullptr, &n, as_uc(aad),
                                          static_cast<int>(aad.size())) == 1) &&
        (plaintext.empty() || EVP_EncryptUpdate(ctx.get(), base + nonce_len, &n, as_uc(plaintext),
                                                static_cast<int>(plaintext.size())) == 1) &&
        EVP_EncryptFinal_ex(ctx.get(), base + nonce_len + plaintext.size(), &fin) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_len),
                            base + nonce_len + plaintext.size()) == 1;
    if (!ok) {
        throw persistence_exception("raft log encryption: AES-256-GCM seal failed");
    }
    return out;
}

/// The plaintext, or nullopt if `sealed` fails authentication.
[[nodiscard]] inline auto gcm_open(const raft_log_data_key_bytes& key,
                                   std::span<const std::byte> aad,
                                   std::span<const std::byte> sealed)
    -> std::optional<std::vector<std::byte>> {
    if (sealed.size() < nonce_len + tag_len) {
        return std::nullopt;
    }
    const auto body = sealed.size() - nonce_len - tag_len;
    std::vector<std::byte> out(body);
    auto* dst = reinterpret_cast<unsigned char*>(out.data());
    const auto* src = as_uc(sealed);
    std::array<unsigned char, tag_len> tag{};
    std::memcpy(tag.data(), src + nonce_len + body, tag_len);
    auto ctx = new_ctx();
    int n = 0;
    int fin = 0;
    const bool setup =
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_len),
                            nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), src) == 1 &&
        (aad.empty() || EVP_DecryptUpdate(ctx.get(), nullptr, &n, as_uc(aad),
                                          static_cast<int>(aad.size())) == 1) &&
        (body == 0 ||
         EVP_DecryptUpdate(ctx.get(), dst, &n, src + nonce_len, static_cast<int>(body)) == 1) &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len),
                            tag.data()) == 1;
    if (!setup) {
        throw persistence_exception("raft log encryption: AES-256-GCM open failed");
    }
    if (EVP_DecryptFinal_ex(ctx.get(), dst + body, &fin) != 1) {
        OPENSSL_cleanse(out.data(), out.size());
        return std::nullopt;
    }
    return out;
}

}  // namespace detail::log_encryption

/// A node's key ring for its Raft logs, kept in one file. Thread-safe.
///
/// Make one with `open` and share it: every engine on the node takes the
/// same `std::shared_ptr` in its `binary_file_persistence_options`.
class raft_log_key_file_ring final : public log_key_ring,
                                     public std::enable_shared_from_this<raft_log_key_file_ring> {
    struct private_tag {};

public:
    /// Load `file`, unwrapping every generation through `source`. A missing
    /// or empty file gets generation 1 from the provider before this returns.
    [[nodiscard]] static auto open(std::filesystem::path file, raft_log_key_source source)
        -> std::shared_ptr<raft_log_key_file_ring> {
        auto ring = std::make_shared<raft_log_key_file_ring>(private_tag{}, std::move(file),
                                                             std::move(source));
        const std::lock_guard lock(ring->_mu);
        ring->load_locked();
        if (ring->_keys.empty()) {
            ring->add_generation_locked();
        }
        return ring;
    }

    raft_log_key_file_ring(private_tag /*unused*/, std::filesystem::path file,
                           raft_log_key_source source)
        : _file(std::move(file)), _source(std::move(source)) {
        if (!_source._generate || !_source._unwrap) {
            throw std::invalid_argument(
                "raft_log_key_file_ring: a key source needs both "
                "callbacks");
        }
    }

    /// Wrap a new data key and make it the newest generation; every engine
    /// seals under it from its next write (requirement 5.1).
    auto rotate() -> std::uint32_t {
        const std::lock_guard lock(_mu);
        return add_generation_locked();
    }

    /// Drop every generation below `lowest_needed`, the lowest any live
    /// record or snapshot on the node still names (requirement 5.2). The
    /// newest generation always stays.
    void prune(std::uint32_t lowest_needed) {
        const std::lock_guard lock(_mu);
        const auto newest = _keys.rbegin()->first;
        bool changed = false;
        for (auto it = _keys.begin();
             it != _keys.end() && it->first < lowest_needed && it->first != newest;) {
            it = _keys.erase(it);
            changed = true;
        }
        if (changed) {
            write_locked();
        }
    }

    [[nodiscard]] auto newest_generation() const -> std::uint32_t {
        const std::lock_guard lock(_mu);
        return _keys.rbegin()->first;
    }

    [[nodiscard]] auto generations() const -> std::vector<std::uint32_t> {
        const std::lock_guard lock(_mu);
        std::vector<std::uint32_t> out;
        out.reserve(_keys.size());
        for (const auto& [g, k] : _keys) {
            out.push_back(g);
        }
        return out;
    }

    /// The provider's key id for `generation`, for operator messages.
    [[nodiscard]] auto key_id(std::uint32_t generation) const -> std::optional<std::string> {
        const std::lock_guard lock(_mu);
        if (auto it = _keys.find(generation); it != _keys.end()) {
            return it->second._key_id;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto file() const -> const std::filesystem::path& { return _file; }

    [[nodiscard]] auto cipher_for(std::span<const std::byte, log_id_bytes> log_id)
        -> std::unique_ptr<log_cipher> override;

    /// The data key for `generation`, if the ring holds it.
    [[nodiscard]] auto data_key(std::uint32_t generation) const
        -> std::optional<detail::log_encryption::wiped_key> {
        const std::lock_guard lock(_mu);
        if (auto it = _keys.find(generation); it != _keys.end()) {
            return it->second._plaintext;
        }
        return std::nullopt;
    }

private:
    struct entry {
        std::string _key_id;
        std::string _wrapped;
        detail::log_encryption::wiped_key _plaintext;
    };

    auto add_generation_locked() -> std::uint32_t {
        const std::uint32_t g = _keys.empty() ? 1U : _keys.rbegin()->first + 1U;
        raft_log_data_key fresh;
        try {
            fresh = _source._generate();
        } catch (const std::exception& e) {
            throw persistence_exception(
                "raft log key ring: the key provider could not make "
                "generation " +
                std::to_string(g) + ": " + e.what());
        }
        entry en{._key_id = std::move(fresh._key_id),
                 ._wrapped = std::move(fresh._wrapped),
                 ._plaintext = detail::log_encryption::wiped_key(fresh._plaintext)};
        OPENSSL_cleanse(fresh._plaintext.data(), fresh._plaintext.size());
        _keys.emplace(g, std::move(en));
        try {
            write_locked();
        } catch (...) {
            _keys.erase(g);
            throw;
        }
        return g;
    }

    void write_locked() const {
        namespace bp = detail::binary_persistence;
        namespace le = detail::log_encryption;
        bp::writer w;
        w.u32(le::key_ring_magic);
        w.u32(le::key_ring_version);
        w.u32(static_cast<std::uint32_t>(_keys.size()));
        for (const auto& [g, en] : _keys) {
            w.u32(g);
            w.str(en._key_id);
            w.str(en._wrapped);
        }
        w.crc();
        if (_file.has_parent_path()) {
            std::filesystem::create_directories(_file.parent_path());
        }
        bp::atomic_replace(_file, w.data());
    }

    void load_locked() {
        namespace bp = detail::binary_persistence;
        namespace le = detail::log_encryption;
        auto bytes = bp::read_whole(_file);
        if (!bytes || bytes->empty()) {
            return;
        }
        if (bytes->size() < 16) {
            throw persistence_exception("raft log key ring: " + _file.string() + " is too short");
        }
        const std::span<const std::byte> body(bytes->data(), bytes->size() - 4);
        bp::reader tail(std::span<const std::byte>(bytes->data() + body.size(), 4));
        if (tail.u32() != crc32(body)) {
            throw persistence_exception("raft log key ring: " + _file.string() + " fails its CRC");
        }
        bp::reader r(body);
        if (r.u32() != le::key_ring_magic || r.u32() != le::key_ring_version) {
            throw persistence_exception("raft log key ring: " + _file.string() +
                                        " has an unknown format");
        }
        const auto count = r.u32();
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto g = r.u32();
            entry en;
            en._key_id = r.str();
            en._wrapped = r.str();
            try {
                auto plain = _source._unwrap(en._key_id, en._wrapped);
                en._plaintext = le::wiped_key(plain);
                OPENSSL_cleanse(plain.data(), plain.size());
            } catch (const std::exception& e) {
                throw persistence_exception(
                    "raft log key ring: the key provider could not unwrap generation " +
                    std::to_string(g) + " (key " + en._key_id + ") from " + _file.string() +
                    ", so this node cannot read its Raft logs: " + e.what());
            }
            if (!_keys.emplace(g, std::move(en)).second || g == 0) {
                throw persistence_exception("raft log key ring: " + _file.string() +
                                            " names generation " + std::to_string(g) +
                                            " twice or as zero");
            }
        }
    }

    std::filesystem::path _file;
    raft_log_key_source _source;
    mutable std::mutex _mu;
    std::map<std::uint32_t, entry> _keys;
};

/// One log's AES-256-GCM cipher over a `raft_log_key_file_ring`. Derived keys
/// are cached per generation and wiped with the cipher.
class raft_log_gcm_cipher final : public log_cipher {
public:
    raft_log_gcm_cipher(std::shared_ptr<raft_log_key_file_ring> ring,
                        std::span<const std::byte, log_id_bytes> log_id)
        : _ring(std::move(ring)) {
        std::copy(log_id.begin(), log_id.end(), _log_id.begin());
    }

    [[nodiscard]] auto newest_generation() const -> std::uint32_t override {
        return _ring->newest_generation();
    }

    [[nodiscard]] auto seal(std::uint32_t generation, std::span<const std::byte> aad,
                            std::span<const std::byte> plaintext)
        -> std::vector<std::byte> override {
        return detail::log_encryption::gcm_seal(key(generation)._bytes, aad, plaintext);
    }

    [[nodiscard]] auto open(std::uint32_t generation, std::span<const std::byte> aad,
                            std::span<const std::byte> sealed) -> std::vector<std::byte> override {
        auto out = detail::log_encryption::gcm_open(key(generation)._bytes, aad, sealed);
        if (!out) {
            throw persistence_exception(
                "raft log encryption: a payload sealed under generation " +
                std::to_string(generation) +
                " fails authentication (tampered, moved, or sealed by another log's key)");
        }
        return std::move(*out);
    }

private:
    auto key(std::uint32_t generation) -> const detail::log_encryption::wiped_key& {
        if (auto it = _derived.find(generation); it != _derived.end()) {
            return it->second;
        }
        auto data = _ring->data_key(generation);
        if (!data) {
            throw persistence_exception("raft log encryption: generation " +
                                        std::to_string(generation) + " is not in the key ring " +
                                        _ring->file().string() +
                                        "; a live record needs it, so it must not be pruned");
        }
        auto derived = detail::log_encryption::derive_log_key(
            data->_bytes, std::span<const std::byte, log_id_bytes>(_log_id));
        return _derived.emplace(generation, std::move(derived)).first->second;
    }

    std::shared_ptr<raft_log_key_file_ring> _ring;
    std::array<std::byte, log_id_bytes> _log_id{};
    std::map<std::uint32_t, detail::log_encryption::wiped_key> _derived;
};

inline auto raft_log_key_file_ring::cipher_for(std::span<const std::byte, log_id_bytes> log_id)
    -> std::unique_ptr<log_cipher> {
    return std::make_unique<raft_log_gcm_cipher>(shared_from_this(), log_id);
}

/// A key source with no provider: one fixed key wraps every data key with
/// AES-256-GCM. For tests and single-machine development only; production
/// nodes use a KMS through `raft_log_kms.hpp`.
[[nodiscard]] inline auto raft_log_fixed_key_source(raft_log_data_key_bytes wrapping_key,
                                                    std::string key_id = "fixed")
    -> raft_log_key_source {
    auto wk = std::make_shared<detail::log_encryption::wiped_key>(wrapping_key);
    OPENSSL_cleanse(wrapping_key.data(), wrapping_key.size());
    raft_log_key_source s;
    s._generate = [wk, key_id]() {
        raft_log_data_key out;
        detail::log_encryption::random_fill(out._plaintext);
        const auto sealed = detail::log_encryption::gcm_seal(
            wk->_bytes, std::as_bytes(std::span(key_id.data(), key_id.size())),
            std::as_bytes(std::span(out._plaintext)));
        out._wrapped.assign(reinterpret_cast<const char*>(sealed.data()), sealed.size());
        out._key_id = key_id;
        return out;
    };
    s._unwrap = [wk](const std::string& id, const std::string& wrapped) {
        const auto plain = detail::log_encryption::gcm_open(
            wk->_bytes, std::as_bytes(std::span(id.data(), id.size())),
            std::as_bytes(std::span(wrapped.data(), wrapped.size())));
        if (!plain || plain->size() != 32) {
            throw std::runtime_error("the wrapped key does not open under this fixed key");
        }
        raft_log_data_key_bytes out{};
        std::memcpy(out.data(), plain->data(), out.size());
        return out;
    };
    return s;
}

}  // namespace kythira
