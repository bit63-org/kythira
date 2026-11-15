// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file item_sealing.hpp
/// @brief Item values sealed under their table's key before they reach the
///        storage engine (`.kiro/specs/kms-compatible-api/` task 16,
///        Requirement 12.3-12.4).
///
/// A sealed value is
///
/// | byte | `k_sealed_item_format` (2) |
/// | 12 bytes | nonce |
/// | rest | AES-256-GCM ciphertext of the encoded item, then its 16-byte tag |
///
/// The first byte sits where a clear value has `k_item_format_version`
/// (1), so a node that predates sealing reads a sealed value as an unknown
/// item format and refuses it rather than misreading it.
///
/// Two keys come from the 256-bit table key by HKDF-Expand (SHA-256; the
/// table key is uniformly random, so it serves as the pseudorandom key and
/// no extract step is needed): one encrypts, one makes nonces. The nonce
/// is the first 12 bytes of HMAC-SHA256 under the nonce key of the key's
/// table id, the engine key and the clear value. Every replica therefore
/// writes the same bytes from the same entry (Requirement 12.4), and a
/// nonce repeats only for the same value at the same key, where the
/// ciphertext repeats with it: the construction is deterministic
/// authenticated encryption (SIV-style), so a nonce is never reused with
/// different data, whatever a split, merge or restore does to log indexes.
/// The associated data binds the value to its table (or index) id, so a
/// value copied under another table's key does not open.
///
/// Keys stay in the clear: the engine orders by them.

#include <kythira/dynamodb/key_layout.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::dynamodb {

/// The first byte of a sealed item value.
inline constexpr std::uint8_t k_sealed_item_format = 2;

/// A table key as its provider unwraps it.
using table_key_bytes = std::array<unsigned char, 32>;

/// A table's key cannot be had on this node yet (its provider has not
/// answered, or refused). Thrown in apply, it halts the group, which
/// retries the entry on its next heartbeat; thrown in a read, it fails the
/// read.
class table_key_unavailable : public std::runtime_error {
public:
    explicit table_key_unavailable(std::uint64_t id)
        : std::runtime_error("dynamodb: the key of table " + std::to_string(id) +
                             " is not available on this node"),
          _id(id) {}
    [[nodiscard]] auto id() const noexcept -> std::uint64_t { return _id; }

private:
    std::uint64_t _id;
};

/// A sealed value that does not open: corrupt, or sealed under another key.
class sealed_value_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace item_sealing_detail {

inline constexpr std::size_t k_nonce_len = 12;
inline constexpr std::size_t k_tag_len = 16;
inline constexpr std::size_t k_overhead = 1 + k_nonce_len + k_tag_len;

using key32 = std::array<unsigned char, 32>;

[[nodiscard]] inline auto hmac(const key32& key, std::span<const std::string_view> parts) -> key32 {
    key32 out{};
    auto* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    auto* ctx = mac != nullptr ? EVP_MAC_CTX_new(mac) : nullptr;
    std::array<OSSL_PARAM, 2> params{
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),  // NOLINT
        OSSL_PARAM_construct_end()};
    bool ok = ctx != nullptr && EVP_MAC_init(ctx, key.data(), key.size(), params.data()) == 1;
    for (const auto part : parts) {
        ok = ok && EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(part.data()),
                                  part.size()) == 1;
    }
    std::size_t len = 0;
    ok = ok && EVP_MAC_final(ctx, out.data(), &len, out.size()) == 1 && len == out.size();
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    if (!ok) {
        throw std::runtime_error("dynamodb item sealing: HMAC-SHA256 failed");
    }
    return out;
}

/// HKDF-Expand to 32 bytes: T(1) = HMAC(PRK, info || 0x01).
[[nodiscard]] inline auto expand(const key32& prk, std::string_view info) -> key32 {
    const std::array<std::string_view, 2> parts{info, std::string_view("\x01", 1)};
    return hmac(prk, parts);
}

[[nodiscard]] inline auto id_bytes(std::uint64_t id) -> std::string {
    std::string out(8, '\0');
    for (int i = 0; i < 8; ++i) {
        out[static_cast<std::size_t>(i)] = static_cast<char>((id >> (56 - 8 * i)) & 0xFFU);
    }
    return out;
}

[[nodiscard]] inline auto length_bytes(std::size_t n) -> std::string {
    std::string out(4, '\0');
    for (int i = 0; i < 4; ++i) {
        out[static_cast<std::size_t>(i)] = static_cast<char>((n >> (24 - 8 * i)) & 0xFFU);
    }
    return out;
}

[[nodiscard]] inline auto aad(std::uint64_t id) -> std::string {
    return "kythira-ddb-item/" + id_bytes(id);
}

struct cipher_ctx {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    cipher_ctx() {
        if (ctx == nullptr) {
            throw std::runtime_error("dynamodb item sealing: EVP_CIPHER_CTX_new failed");
        }
    }
    cipher_ctx(const cipher_ctx&) = delete;
    cipher_ctx(cipher_ctx&&) = delete;
    auto operator=(const cipher_ctx&) -> cipher_ctx& = delete;
    auto operator=(cipher_ctx&&) -> cipher_ctx& = delete;
    ~cipher_ctx() { EVP_CIPHER_CTX_free(ctx); }
};

}  // namespace item_sealing_detail

/// The keys one table key gives: kept in memory by each replica of the
/// table's groups while it serves the table.
class item_key {
public:
    explicit item_key(const table_key_bytes& table_key) {
        item_sealing_detail::key32 prk{};
        std::memcpy(prk.data(), table_key.data(), prk.size());
        _encrypt = item_sealing_detail::expand(prk, "kythira-dynamodb-item-seal");
        _nonce = item_sealing_detail::expand(prk, "kythira-dynamodb-item-nonce");
        OPENSSL_cleanse(prk.data(), prk.size());
    }
    item_key(const item_key&) = delete;
    item_key(item_key&&) = delete;
    auto operator=(const item_key&) -> item_key& = delete;
    auto operator=(item_key&&) -> item_key& = delete;
    ~item_key() {
        OPENSSL_cleanse(_encrypt.data(), _encrypt.size());
        OPENSSL_cleanse(_nonce.data(), _nonce.size());
    }

    /// `clear` (an encoded item) sealed for engine key `key` of table or
    /// index `id`.
    [[nodiscard]] auto seal(std::uint64_t id, std::string_view key, std::string_view clear) const
        -> std::string {
        namespace d = item_sealing_detail;
        const auto idb = d::id_bytes(id);
        const auto klen = d::length_bytes(key.size());
        const std::array<std::string_view, 4> parts{idb, klen, key, clear};
        const auto mac = d::hmac(_nonce, parts);
        std::string out;
        out.reserve(clear.size() + d::k_overhead);
        out.push_back(static_cast<char>(k_sealed_item_format));
        out.append(reinterpret_cast<const char*>(mac.data()), d::k_nonce_len);
        const auto a = d::aad(id);
        d::cipher_ctx c;
        int len = 0;
        const auto* nonce = mac.data();
        if (EVP_EncryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(d::k_nonce_len),
                                nullptr) != 1 ||
            EVP_EncryptInit_ex(c.ctx, nullptr, nullptr, _encrypt.data(), nonce) != 1 ||
            EVP_EncryptUpdate(c.ctx, nullptr, &len,
                              reinterpret_cast<const unsigned char*>(a.data()),
                              static_cast<int>(a.size())) != 1) {
            throw std::runtime_error("dynamodb item sealing: AES-GCM setup failed");
        }
        const auto at = out.size();
        out.resize(at + clear.size() + d::k_tag_len);
        auto* dst = reinterpret_cast<unsigned char*>(out.data() + at);
        int total = 0;
        if (!clear.empty()) {
            if (EVP_EncryptUpdate(c.ctx, dst, &len,
                                  reinterpret_cast<const unsigned char*>(clear.data()),
                                  static_cast<int>(clear.size())) != 1) {
                throw std::runtime_error("dynamodb item sealing: AES-GCM encrypt failed");
            }
            total = len;
        }
        if (EVP_EncryptFinal_ex(c.ctx, dst + total, &len) != 1 ||
            EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(d::k_tag_len),
                                dst + clear.size()) != 1) {
            throw std::runtime_error("dynamodb item sealing: AES-GCM finish failed");
        }
        return out;
    }

    /// The encoded item `sealed` holds. Throws `sealed_value_error` when
    /// it does not open under this key for table or index `id`.
    [[nodiscard]] auto open(std::uint64_t id, std::string_view sealed) const -> std::string {
        namespace d = item_sealing_detail;
        if (sealed.size() < d::k_overhead ||
            static_cast<std::uint8_t>(sealed[0]) != k_sealed_item_format) {
            throw sealed_value_error("dynamodb: a sealed item value is malformed");
        }
        const auto* nonce = reinterpret_cast<const unsigned char*>(sealed.data() + 1);
        const auto body = sealed.substr(1 + d::k_nonce_len);
        const auto n = body.size() - d::k_tag_len;
        const auto a = d::aad(id);
        d::cipher_ctx c;
        int len = 0;
        if (EVP_DecryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(d::k_nonce_len),
                                nullptr) != 1 ||
            EVP_DecryptInit_ex(c.ctx, nullptr, nullptr, _encrypt.data(), nonce) != 1 ||
            EVP_DecryptUpdate(c.ctx, nullptr, &len,
                              reinterpret_cast<const unsigned char*>(a.data()),
                              static_cast<int>(a.size())) != 1) {
            throw std::runtime_error("dynamodb item sealing: AES-GCM setup failed");
        }
        std::string out(n, '\0');
        auto* dst = reinterpret_cast<unsigned char*>(out.data());
        int total = 0;
        if (n > 0) {
            if (EVP_DecryptUpdate(c.ctx, dst, &len,
                                  reinterpret_cast<const unsigned char*>(body.data()),
                                  static_cast<int>(n)) != 1) {
                throw sealed_value_error("dynamodb: a sealed item value does not open");
            }
            total = len;
        }
        std::array<unsigned char, d::k_tag_len> tag{};
        std::memcpy(tag.data(), body.data() + n, d::k_tag_len);
        if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(d::k_tag_len),
                                tag.data()) != 1 ||
            EVP_DecryptFinal_ex(c.ctx, dst + total, &len) != 1) {
            OPENSSL_cleanse(out.data(), out.size());
            throw sealed_value_error("dynamodb: a sealed item value does not open");
        }
        return out;
    }

private:
    item_sealing_detail::key32 _encrypt{};
    item_sealing_detail::key32 _nonce{};
};

/// Whether a stored value is sealed.
[[nodiscard]] inline auto is_sealed_value(std::string_view v) -> bool {
    return !v.empty() && static_cast<std::uint8_t>(v[0]) == k_sealed_item_format;
}

/// The table (or index) id an item engine key starts with (`t/<id>/`), or
/// nothing for another key.
[[nodiscard]] inline auto key_table_id(std::string_view key) -> std::optional<std::uint64_t> {
    if (key.size() < 11 || !key.starts_with("t/") || key[10] != '/') {
        return std::nullopt;
    }
    std::uint64_t id = 0;
    for (std::size_t i = 2; i < 10; ++i) {
        id = (id << 8U) | static_cast<unsigned char>(key[i]);
    }
    return id;
}

/// The table keys a node holds, by table and index id, shared by every
/// group the node hosts. A replica asks for a key when it applies or reads
/// a sealed value; a miss is remembered so the node's refresher
/// (`table_key_refresher`, `table_keys.hpp`) fetches it soon. Thread-safe.
class table_key_ring {
public:
    /// The key of table or index `id`, or null (remembered as wanted).
    [[nodiscard]] auto find(std::uint64_t id) const -> std::shared_ptr<const item_key> {
        {
            const std::shared_lock lock(_mutex);
            if (const auto it = _keys.find(id); it != _keys.end()) {
                return it->second;
            }
        }
        const std::scoped_lock lock(_mutex);
        if (const auto it = _keys.find(id); it != _keys.end()) {
            return it->second;
        }
        _wanted.insert(id);
        return nullptr;
    }

    /// The key of `id`, or throws `table_key_unavailable`.
    [[nodiscard]] auto require(std::uint64_t id) const -> std::shared_ptr<const item_key> {
        auto k = find(id);
        if (!k) {
            throw table_key_unavailable(id);
        }
        return k;
    }

    /// Holds `key` for a table and its indexes.
    auto put(std::span<const std::uint64_t> ids, const table_key_bytes& key) -> void {
        auto k = std::make_shared<const item_key>(key);
        const std::scoped_lock lock(_mutex);
        for (const auto id : ids) {
            _keys[id] = k;
            _wanted.erase(id);
        }
    }

    [[nodiscard]] auto holds(std::uint64_t id) const -> bool {
        const std::shared_lock lock(_mutex);
        return _keys.contains(id);
    }

    /// Forgets the key of `id` (its table is gone).
    auto erase(std::uint64_t id) -> void {
        const std::scoped_lock lock(_mutex);
        _keys.erase(id);
        _wanted.erase(id);
    }

    /// The ids asked for and not held.
    [[nodiscard]] auto wanted() const -> std::set<std::uint64_t> {
        const std::shared_lock lock(_mutex);
        return _wanted;
    }

private:
    mutable std::shared_mutex _mutex;
    std::map<std::uint64_t, std::shared_ptr<const item_key>> _keys;
    mutable std::set<std::uint64_t> _wanted;
};

/// Seals and opens item values for a group, through the node's ring.
/// Without a ring (unit tests, a node with no key provider), a sealed
/// write fails and a sealed value does not open.
class item_sealer {
public:
    item_sealer() = default;
    explicit item_sealer(std::shared_ptr<table_key_ring> ring) : _ring(std::move(ring)) {}

    [[nodiscard]] auto ring() const -> const std::shared_ptr<table_key_ring>& { return _ring; }

    /// `clear` as stored at `key`: sealed when `sealed`, else as is.
    [[nodiscard]] auto store(bool sealed, std::string_view key, std::string clear) const
        -> std::string {
        if (!sealed) {
            return clear;
        }
        const auto id = key_table_id(key);
        if (!id) {
            throw std::logic_error("dynamodb: a sealed write outside the item key space");
        }
        return key_for(*id)->seal(*id, key, clear);
    }

    /// The encoded item stored at `key` as `stored`.
    [[nodiscard]] auto load(std::string_view key, std::string_view stored) const -> std::string {
        if (!is_sealed_value(stored)) {
            return std::string(stored);
        }
        const auto id = key_table_id(key);
        if (!id) {
            throw sealed_value_error("dynamodb: a sealed value outside the item key space");
        }
        return key_for(*id)->open(*id, stored);
    }

private:
    [[nodiscard]] auto key_for(std::uint64_t id) const -> std::shared_ptr<const item_key> {
        if (!_ring) {
            throw table_key_unavailable(id);
        }
        return _ring->require(id);
    }

    std::shared_ptr<table_key_ring> _ring;
};

}  // namespace kythira::dynamodb
