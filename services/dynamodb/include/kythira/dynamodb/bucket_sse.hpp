// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file bucket_sse.hpp
/// @brief `S3SseKmsKeyId` for exports and imports (`.kiro/specs/
///        kms-compatible-api/` task 17, Requirement 12.9).
///
/// An export with `S3SseAlgorithm=KMS` writes every object of the export
/// under the KMS key `S3SseKmsKeyId` names (the account's AWS managed key
/// `alias/aws/s3` when none is named, as S3 does):
///
/// - A store that does server-side encryption itself (an AWS S3 bucket,
///   `backup_store::put_sse_kms`) is asked to, with the key id unchanged, and
///   S3 encrypts as it would for any client.
/// - A Kythira store (a bucket directory, a Kythira object store, memory)
///   has no server-side encryption, so the object is sealed before it is
///   stored: a fresh data key from the table's key provider under that KMS
///   key, AES-256-GCM, with the wrapped data key in the object. The
///   encryption context is `{"aws:s3:arn": "arn:aws:s3:::<bucket>/<key>"}`,
///   as S3 uses, so the data key opens only for that object. An import from
///   that store opens such objects the same way; any other reader needs
///   the key provider too.
///
/// A sealed object is
///
/// | `k_sse_magic` | `\0KSE1` |
/// | 2 bytes | key id length, then the key id that wrapped the data key |
/// | 4 bytes | wrapped data key length, then the wrapped data key |
/// | 12 bytes | nonce |
/// | rest | ciphertext, then the 16-byte tag (associated data: the object key) |

#include <kythira/dynamodb/backup.hpp>
#include <kythira/dynamodb/table_keys.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::dynamodb {

inline constexpr std::string_view k_sse_magic{"\0KSE1", 5};

/// The key an export with `S3SseAlgorithm=KMS` and no `S3SseKmsKeyId`
/// uses, as S3 does.
inline constexpr std::string_view k_default_s3_kms_key{"alias/aws/s3"};

/// An object could not be sealed or opened under its KMS key: the key
/// provider refused or could not answer, or this node has none. An export
/// or import fails with it.
class bucket_sse_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// How a sealed bucket gets and opens data keys: the table's key provider,
/// asked as the export's or import's account (`object_keys_of`; the
/// `table_keys` it is made from outlives it).
struct object_key_service {
    struct made {
        std::array<unsigned char, 32> key{};
        std::string wrapped;
        std::string key_id;
    };
    /// A fresh data key under `key_id` for `context` (the object's ARN).
    std::function<made(const std::string& key_id, const std::string& object_arn)> generate;
    /// The data key `wrapped` holds.
    std::function<std::array<unsigned char, 32>(
        const std::string& key_id, const std::string& wrapped, const std::string& object_arn)>
        decrypt;
};

namespace bucket_sse_detail {

inline constexpr std::size_t k_nonce_len = 12;
inline constexpr std::size_t k_tag_len = 16;

struct cipher_ctx {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    cipher_ctx() {
        if (ctx == nullptr) {
            throw std::runtime_error("bucket sse: EVP_CIPHER_CTX_new failed");
        }
    }
    cipher_ctx(const cipher_ctx&) = delete;
    cipher_ctx(cipher_ctx&&) = delete;
    auto operator=(const cipher_ctx&) -> cipher_ctx& = delete;
    auto operator=(cipher_ctx&&) -> cipher_ctx& = delete;
    ~cipher_ctx() { EVP_CIPHER_CTX_free(ctx); }
};

inline void put_be(std::string& out, std::uint64_t v, int bytes) {
    for (int i = bytes - 1; i >= 0; --i) {
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFFU));
    }
}

[[nodiscard]] inline auto get_be(std::string_view& in, int bytes) -> std::optional<std::uint64_t> {
    if (in.size() < static_cast<std::size_t>(bytes)) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < bytes; ++i) {
        v = (v << 8U) | static_cast<unsigned char>(in[static_cast<std::size_t>(i)]);
    }
    in.remove_prefix(static_cast<std::size_t>(bytes));
    return v;
}

[[nodiscard]] inline auto gcm(bool encrypt, const std::array<unsigned char, 32>& key,
                              const unsigned char* nonce, std::string_view aad, std::string_view in,
                              const unsigned char* tag_in, unsigned char* tag_out)
    -> std::optional<std::string> {
    cipher_ctx c;
    int len = 0;
    const auto* cipher = EVP_aes_256_gcm();
    const bool ok =
        (encrypt ? EVP_EncryptInit_ex(c.ctx, cipher, nullptr, nullptr, nullptr)
                 : EVP_DecryptInit_ex(c.ctx, cipher, nullptr, nullptr, nullptr)) == 1 &&
        EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(k_nonce_len),
                            nullptr) == 1 &&
        (encrypt ? EVP_EncryptInit_ex(c.ctx, nullptr, nullptr, key.data(), nonce)
                 : EVP_DecryptInit_ex(c.ctx, nullptr, nullptr, key.data(), nonce)) == 1 &&
        (encrypt ? EVP_EncryptUpdate(c.ctx, nullptr, &len,
                                     reinterpret_cast<const unsigned char*>(aad.data()),
                                     static_cast<int>(aad.size()))
                 : EVP_DecryptUpdate(c.ctx, nullptr, &len,
                                     reinterpret_cast<const unsigned char*>(aad.data()),
                                     static_cast<int>(aad.size()))) == 1;
    if (!ok) {
        throw std::runtime_error("bucket sse: AES-GCM setup failed");
    }
    std::string out(in.size(), '\0');
    auto* dst = reinterpret_cast<unsigned char*>(out.data());
    int total = 0;
    if (!in.empty()) {
        const auto* src = reinterpret_cast<const unsigned char*>(in.data());
        const auto n = static_cast<int>(in.size());
        if ((encrypt ? EVP_EncryptUpdate(c.ctx, dst, &len, src, n)
                     : EVP_DecryptUpdate(c.ctx, dst, &len, src, n)) != 1) {
            return std::nullopt;
        }
        total = len;
    }
    if (encrypt) {
        if (EVP_EncryptFinal_ex(c.ctx, dst + total, &len) != 1 ||
            EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(k_tag_len),
                                tag_out) != 1) {
            throw std::runtime_error("bucket sse: AES-GCM finish failed");
        }
        return out;
    }
    std::array<unsigned char, k_tag_len> tag{};
    std::memcpy(tag.data(), tag_in, k_tag_len);
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(k_tag_len), tag.data()) !=
            1 ||
        EVP_DecryptFinal_ex(c.ctx, dst + total, &len) != 1) {
        OPENSSL_cleanse(out.data(), out.size());
        return std::nullopt;
    }
    return out;
}

}  // namespace bucket_sse_detail

/// Whether a stored object is sealed by `kms_sealed_bucket`.
[[nodiscard]] inline auto is_sse_sealed(std::string_view body) -> bool {
    return body.starts_with(k_sse_magic);
}

/// A bucket seen through `S3SseKmsKeyId`: puts go under the key (natively
/// where the store can, sealed otherwise), gets open sealed objects. With
/// an empty key id it seals nothing and only opens.
class kms_sealed_bucket final : public backup_store {
public:
    kms_sealed_bucket(std::shared_ptr<backup_store> inner, std::string bucket, std::string key_id,
                      object_key_service keys)
        : _inner(std::move(inner)),
          _bucket(std::move(bucket)),
          _key_id(std::move(key_id)),
          _keys(std::move(keys)) {}

    void put(const std::string& key, std::string_view bytes) override {
        if (_key_id.empty()) {
            _inner->put(key, bytes);
            return;
        }
        if (_inner->put_sse_kms(key, bytes, _key_id)) {
            return;
        }
        if (!_keys.generate) {
            throw bucket_sse_error("S3SseKmsKeyId needs a key provider: set KYTHIRA_DYNAMODB_KMS");
        }
        namespace d = bucket_sse_detail;
        auto made = _keys.generate(_key_id, object_arn(key));
        std::array<unsigned char, d::k_nonce_len> nonce{};
        if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
            OPENSSL_cleanse(made.key.data(), made.key.size());
            throw std::runtime_error("bucket sse: RAND_bytes failed");
        }
        std::string out(k_sse_magic);
        d::put_be(out, made.key_id.size(), 2);
        out += made.key_id;
        d::put_be(out, made.wrapped.size(), 4);
        out += made.wrapped;
        out.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
        std::array<unsigned char, d::k_tag_len> tag{};
        const auto sealed = d::gcm(true, made.key, nonce.data(), key, bytes, nullptr, tag.data());
        OPENSSL_cleanse(made.key.data(), made.key.size());
        out += *sealed;
        out.append(reinterpret_cast<const char*>(tag.data()), tag.size());
        _inner->put(key, out);
    }

    [[nodiscard]] auto get(const std::string& key) -> std::optional<std::string> override {
        auto body = _inner->get(key);
        if (!body || !is_sse_sealed(*body)) {
            return body;
        }
        return open(key, *body);
    }

    void remove(const std::string& key) override { _inner->remove(key); }

    [[nodiscard]] auto list(const std::string& prefix) -> std::vector<std::string> override {
        return _inner->list(prefix);
    }

private:
    [[nodiscard]] auto object_arn(const std::string& key) const -> std::string {
        return "arn:aws:s3:::" + _bucket + "/" + key;
    }

    [[nodiscard]] auto open(const std::string& key, std::string_view body) const -> std::string {
        namespace d = bucket_sse_detail;
        std::string_view in = body.substr(k_sse_magic.size());
        const auto id_len = d::get_be(in, 2);
        if (!id_len || in.size() < *id_len) {
            throw bucket_sse_error("object " + key + " is sealed and malformed");
        }
        const std::string key_id(in.substr(0, *id_len));
        in.remove_prefix(*id_len);
        const auto wrapped_len = d::get_be(in, 4);
        if (!wrapped_len || in.size() < *wrapped_len + d::k_nonce_len + d::k_tag_len) {
            throw bucket_sse_error("object " + key + " is sealed and malformed");
        }
        const std::string wrapped(in.substr(0, *wrapped_len));
        in.remove_prefix(*wrapped_len);
        const auto* nonce = reinterpret_cast<const unsigned char*>(in.data());
        in.remove_prefix(d::k_nonce_len);
        const auto* tag =
            reinterpret_cast<const unsigned char*>(in.data() + in.size() - d::k_tag_len);
        in.remove_suffix(d::k_tag_len);
        if (!_keys.decrypt) {
            throw bucket_sse_error("object " + key +
                                   " is sealed under a KMS key and this node has no key "
                                   "provider");
        }
        auto data_key = _keys.decrypt(key_id, wrapped, object_arn(key));
        auto clear = d::gcm(false, data_key, nonce, key, in, tag, nullptr);
        OPENSSL_cleanse(data_key.data(), data_key.size());
        if (!clear) {
            throw bucket_sse_error("object " + key + " does not open under its KMS key");
        }
        return std::move(*clear);
    }

    std::shared_ptr<backup_store> _inner;
    std::string _bucket;
    std::string _key_id;
    object_key_service _keys;
};

/// The `object_key_service` of `keys` for `account` (the export's or
/// import's table's), asked as the account's root. A provider's refusal
/// becomes a `bucket_sse_error` naming the key.
[[nodiscard]] inline auto object_keys_of(const table_keys& keys, std::string account,
                                         std::string partition) -> object_key_service {
    if (!keys.configured()) {
        return {};
    }
    const auto context = [](const std::string& arn) -> kms_provider::encryption_context {
        return {{"aws:s3:arn", arn}};
    };
    object_key_service s;
    s.generate = [&keys, account, partition, context](const std::string& key_id,
                                                      const std::string& arn) {
        try {
            auto made = keys.generate_object_key(key_id, context(arn), account, partition);
            object_key_service::made out;
            out.key = made._plaintext;
            OPENSSL_cleanse(made._plaintext.data(), made._plaintext.size());
            out.wrapped = std::move(made._wrapped);
            if (made._key_id.empty()) {
                out.key_id = key_id;
            } else {
                out.key_id = std::move(made._key_id);
            }
            return out;
        } catch (const kms_provider::kms_error& e) {
            throw bucket_sse_error("KMS key " + key_id + ": " + e.what());
        }
    };
    s.decrypt = [&keys, account, partition, context](
                    const std::string& key_id, const std::string& wrapped, const std::string& arn) {
        try {
            return keys.decrypt_object_key(key_id, wrapped, context(arn), account, partition);
        } catch (const kms_provider::kms_error& e) {
            throw bucket_sse_error("KMS key " + key_id + ": " + e.what());
        }
    };
    return s;
}

/// The account and partition of an ARN (`arn:<partition>:<service>:
/// <region>:<account>:...`); empty when it has none.
[[nodiscard]] inline auto arn_account_partition(std::string_view arn)
    -> std::pair<std::string, std::string> {
    std::vector<std::string_view> parts;
    for (std::size_t at = 0; parts.size() < 5;) {
        const auto colon = arn.find(':', at);
        if (colon == std::string_view::npos) {
            return {};
        }
        parts.push_back(arn.substr(at, colon - at));
        at = colon + 1;
    }
    return {std::string(parts[4]), std::string(parts[1])};
}

}  // namespace kythira::dynamodb
