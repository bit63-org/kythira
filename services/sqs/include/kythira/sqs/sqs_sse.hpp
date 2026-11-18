// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_sse.hpp
/// @brief Server-side encryption (`.kiro/specs/sqs-compatible-queues/`
///        task 7, Requirements 8.1 and 8.2; design "Encryption at the front
///        end").
///
/// A queue with SSE-SQS (the default for new queues, as on SQS) or SSE-KMS
/// (`KmsMasterKeyId`) has each message's body and attributes sealed by the
/// front end before the send is proposed, so the Raft log, the state
/// machine's engine, snapshots and every replica hold only ciphertext. The
/// data layer never needs a key. MD5 digests and the content-based
/// deduplication hash are computed over the plaintext first and stored
/// beside the sealed body, which is what clients check.
///
/// Keys are envelope keys, as on SQS: a front end asks the queue's key
/// provider for a 256-bit data key and reuses it for the queue's
/// `KmsDataKeyReusePeriodSeconds`, then asks again. Each sealed message
/// carries its data key wrapped by the provider, so any front end opens
/// any message, a message moved to another queue (a dead-letter move, a
/// move task) still opens, and changing a queue's encryption leaves its
/// stored messages readable. A front end keeps unwrapped keys for the
/// reuse period, so a busy queue costs one provider call per period, not
/// one per message.
///
/// A provider is anything with the shape of the shared `kms_key_provider`
/// concept (the KMS spec moves Kinesis's into a common library; this one
/// has the same two calls, so that library drops in):
///
/// - `generate_data_key(key_id, context)`: a fresh key, wrapped under
///   `key_id`, and the provider's resolved id;
/// - `decrypt_data_key(key_id, wrapped, context)`: the key back.
///
/// Both throw `kms_error`, which the service answers as SQS's `Kms*`
/// error of the same meaning. The encryption context is SQS's
/// (`aws:sqs:arn` = the queue the message was sealed for).
///
/// `wrapping_provider` wraps data keys with AES-256-GCM under a 256-bit
/// master key, binding the key id and the context as additional data, so
/// a key wrapped for one id or queue does not unwrap as another. SSE-SQS
/// uses one whose master key every node of the cluster shares
/// (`SQS_SSE_KEY_FILE`, or derived from `SQS_FORWARD_SECRET`); `sqs_node`'s
/// `SQS_KMS=local` uses one keyed from a passphrase for SSE-KMS.
///
/// A sealed body is:
///
///     0x00 'K' 0x01 | str key id | str context ARN | str wrapped key |
///     12-byte nonce | ciphertext | 16-byte tag
///
/// where `str` is a u32 length (little-endian) and the bytes. The
/// plaintext is the body's length (u32), the body and the encoded
/// attributes. SQS refuses a NUL in a body, so a leading 0x00 never starts
/// a plaintext one, and one queue may hold both kinds. The additional data
/// is the format, the message id, the key id and the context ARN, so a
/// sealed body pasted onto another message does not open.

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace kythira::sqs {

using data_key_bytes = std::array<unsigned char, 32>;
using encryption_context = std::map<std::string, std::string>;

/// What went wrong in a key provider; each is answered as SQS's `Kms*`
/// error of the same name. `unavailable`: no provider is configured on
/// this node (answered as `KmsNotFound`).
enum class kms_failure : std::uint8_t {
    not_found = 0,
    access_denied = 1,
    disabled = 2,
    invalid_state = 3,
    throttling = 4,
    opt_in_required = 5,
    invalid_key_usage = 6,
    unavailable = 7,
};

class kms_error : public std::runtime_error {
public:
    kms_error(kms_failure failure, const std::string& message)
        : std::runtime_error(message), _failure(failure) {}
    [[nodiscard]] auto failure() const noexcept -> kms_failure { return _failure; }

private:
    kms_failure _failure;
};

/// A sealed body that does not open: truncated, or its tag fails. Data
/// corruption, not a provider error.
class sealed_body_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct generated_data_key {
    data_key_bytes _plaintext{};
    std::string _wrapped;
    /// The provider's id for the key that wrapped it (AWS KMS: its ARN).
    std::string _key_id;
};

template<typename P>
concept kms_key_provider = requires(P& p, const std::string& key_id, const std::string& wrapped,
                                    const encryption_context& context) {
    { p.generate_data_key(key_id, context) } -> std::same_as<generated_data_key>;
    { p.decrypt_data_key(key_id, wrapped, context) } -> std::same_as<data_key_bytes>;
};

/// Any `kms_key_provider`, shared and thread-safe. Empty: none configured.
class key_provider {
public:
    key_provider() = default;

    template<typename P>
    requires kms_key_provider<P> && (!std::same_as<std::remove_cvref_t<P>, key_provider>)
    explicit key_provider(P p) : _impl(std::make_shared<model<P>>(std::move(p))) {}

    [[nodiscard]] explicit operator bool() const noexcept { return _impl != nullptr; }

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context) const
        -> generated_data_key {
        return impl().generate(key_id, context);
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context) const -> data_key_bytes {
        return impl().decrypt(key_id, wrapped, context);
    }

private:
    struct concept_t {
        concept_t() = default;
        concept_t(const concept_t&) = delete;
        auto operator=(const concept_t&) -> concept_t& = delete;
        concept_t(concept_t&&) = delete;
        auto operator=(concept_t&&) -> concept_t& = delete;
        virtual ~concept_t() = default;
        virtual auto generate(const std::string&, const encryption_context&)
            -> generated_data_key = 0;
        virtual auto decrypt(const std::string&, const std::string&, const encryption_context&)
            -> data_key_bytes = 0;
    };
    template<typename P> struct model final : concept_t {
        explicit model(P p) : _p(std::move(p)) {}
        auto generate(const std::string& id, const encryption_context& c)
            -> generated_data_key override {
            const std::scoped_lock lock(_m);
            return _p.generate_data_key(id, c);
        }
        auto decrypt(const std::string& id, const std::string& w, const encryption_context& c)
            -> data_key_bytes override {
            const std::scoped_lock lock(_m);
            return _p.decrypt_data_key(id, w, c);
        }
        std::mutex _m;
        P _p;
    };

    [[nodiscard]] auto impl() const -> concept_t& {
        if (!_impl) {
            throw kms_error(kms_failure::unavailable,
                            "No KMS key provider is configured on this node.");
        }
        return *_impl;
    }

    std::shared_ptr<concept_t> _impl;
};

namespace sse_detail {

inline constexpr std::size_t k_nonce = 12;
inline constexpr std::size_t k_tag = 16;
inline constexpr std::string_view k_magic{"\0K\x01", 3};

inline void put_u32(std::string& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFFU));
    }
}

inline void put_str(std::string& out, std::string_view s) {
    put_u32(out, static_cast<std::uint32_t>(s.size()));
    out.append(s);
}

inline auto get_u32(std::string_view& in, std::uint32_t& v) -> bool {
    if (in.size() < 4) {
        return false;
    }
    v = 0;
    for (int i = 0; i < 4; ++i) {
        v |= static_cast<std::uint32_t>(static_cast<unsigned char>(in[static_cast<std::size_t>(i)]))
             << (8 * i);
    }
    in.remove_prefix(4);
    return true;
}

inline auto get_str(std::string_view& in, std::string_view& s) -> bool {
    std::uint32_t n = 0;
    if (!get_u32(in, n) || in.size() < n) {
        return false;
    }
    s = in.substr(0, n);
    in.remove_prefix(n);
    return true;
}

struct ctx_deleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};

/// AES-256-GCM: nonce | ciphertext | tag.
[[nodiscard]] inline auto gcm_seal(const data_key_bytes& key, std::string_view aad,
                                   std::string_view plaintext) -> std::string {
    std::array<unsigned char, k_nonce> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        throw std::runtime_error("sqs: RAND_bytes failed");
    }
    const std::unique_ptr<EVP_CIPHER_CTX, ctx_deleter> c(EVP_CIPHER_CTX_new());
    std::string out(k_nonce + plaintext.size() + k_tag, '\0');
    std::memcpy(out.data(), nonce.data(), k_nonce);
    int len = 0;
    auto* dst = reinterpret_cast<unsigned char*>(out.data() + k_nonce);  // NOLINT
    if (!c ||
        EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(c.get(), nullptr, &len,
                          reinterpret_cast<const unsigned char*>(aad.data()),  // NOLINT
                          static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(c.get(), dst, &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),  // NOLINT
                          static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(c.get(), dst + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(k_tag),
                            out.data() + k_nonce + plaintext.size()) != 1) {
        throw std::runtime_error("sqs: AES-256-GCM seal failed");
    }
    return out;
}

/// The plaintext, or nullopt when the tag fails or `sealed` is short.
[[nodiscard]] inline auto gcm_open(const data_key_bytes& key, std::string_view aad,
                                   std::string_view sealed) -> std::optional<std::string> {
    if (sealed.size() < k_nonce + k_tag) {
        return std::nullopt;
    }
    const auto ct = sealed.substr(k_nonce, sealed.size() - k_nonce - k_tag);
    std::string tag(sealed.substr(sealed.size() - k_tag));
    const std::unique_ptr<EVP_CIPHER_CTX, ctx_deleter> c(EVP_CIPHER_CTX_new());
    std::string out(ct.size(), '\0');
    int len = 0;
    auto* dst = reinterpret_cast<unsigned char*>(out.data());  // NOLINT
    if (!c ||
        EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, key.data(),
                           reinterpret_cast<const unsigned char*>(sealed.data())) != 1 ||  // NOLINT
        EVP_DecryptUpdate(c.get(), nullptr, &len,
                          reinterpret_cast<const unsigned char*>(aad.data()),  // NOLINT
                          static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(c.get(), dst, &len,
                          reinterpret_cast<const unsigned char*>(ct.data()),  // NOLINT
                          static_cast<int>(ct.size())) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(k_tag), tag.data()) !=
            1 ||
        EVP_DecryptFinal_ex(c.get(), dst + len, &len) != 1) {
        return std::nullopt;
    }
    return out;
}

[[nodiscard]] inline auto context_aad(std::string_view label, const std::string& key_id,
                                      const encryption_context& context) -> std::string {
    std::string aad(label);
    put_str(aad, key_id);
    for (const auto& [k, v] : context) {
        put_str(aad, k);
        put_str(aad, v);
    }
    return aad;
}

[[nodiscard]] inline auto body_aad(std::string_view message_id, std::string_view key_id,
                                   std::string_view context_arn) -> std::string {
    std::string aad(k_magic);
    put_str(aad, message_id);
    put_str(aad, key_id);
    put_str(aad, context_arn);
    return aad;
}

}  // namespace sse_detail

/// Wraps data keys under one master key (see the file comment). Every key
/// id is accepted and resolves to itself.
class wrapping_provider {
public:
    explicit wrapping_provider(const data_key_bytes& master) : _master(master) {}

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context) -> generated_data_key {
        generated_data_key out;
        if (RAND_bytes(out._plaintext.data(), static_cast<int>(out._plaintext.size())) != 1) {
            throw kms_error(kms_failure::invalid_state, "Could not generate a data key.");
        }
        const std::string_view plain(
            reinterpret_cast<const char*>(out._plaintext.data()),  // NOLINT
            out._plaintext.size());
        out._wrapped = sse_detail::gcm_seal(_master, aad(key_id, context), plain);
        out._key_id = key_id;
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context) -> data_key_bytes {
        const auto plain = sse_detail::gcm_open(_master, aad(key_id, context), wrapped);
        data_key_bytes out{};
        if (!plain || plain->size() != out.size()) {
            throw kms_error(kms_failure::invalid_state,
                            "The data key does not unwrap under " + key_id + ".");
        }
        std::memcpy(out.data(), plain->data(), out.size());
        return out;
    }

private:
    data_key_bytes _master;

    [[nodiscard]] static auto aad(const std::string& key_id, const encryption_context& context)
        -> std::string {
        return sse_detail::context_aad("kythira-sqs-wrap-v1", key_id, context);
    }
};

static_assert(kms_key_provider<wrapping_provider>);

/// A 256-bit key derived from a secret for `label` (HMAC-SHA256), as the
/// receipt keys are derived from the forwarding secret.
[[nodiscard]] inline auto derived_key(std::string_view secret, std::string_view label)
    -> data_key_bytes {
    data_key_bytes out{};
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(label.data()), label.size(),  // NOLINT
         out.data(), &len);
    return out;
}

/// A key from a passphrase: PBKDF2-HMAC-SHA256, 200 000 iterations, salted
/// with `label`. Run once, at start-up.
[[nodiscard]] inline auto passphrase_key(std::string_view passphrase, std::string_view label)
    -> data_key_bytes {
    data_key_bytes out{};
    if (PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()),
                          reinterpret_cast<const unsigned char*>(label.data()),  // NOLINT
                          static_cast<int>(label.size()), 200'000, EVP_sha256(),
                          static_cast<int>(out.size()), out.data()) != 1) {
        throw std::runtime_error("sqs: PBKDF2 failed");
    }
    return out;
}

/// A fresh random key (a single in-memory process's SSE-SQS master key).
[[nodiscard]] inline auto random_key() -> data_key_bytes {
    data_key_bytes out{};
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("sqs: RAND_bytes failed");
    }
    return out;
}

/// Whether a stored body is sealed.
[[nodiscard]] inline auto is_sealed(std::string_view body) -> bool {
    return body.size() >= 3 && body.substr(0, 3) == sse_detail::k_magic;
}

/// The key id SSE-SQS seals under.
inline constexpr std::string_view k_sqs_managed_key = "alias/kythira/sqs-managed";

/// How a front end seals and opens: the two providers and its data keys.
/// Thread-safe.
class sse_keys {
public:
    /// What a queue seals with: `_kms_key_id` empty means SSE-SQS.
    struct target {
        std::string _queue_arn;
        std::string _kms_key_id;
        std::uint32_t _reuse_s = 300;
    };

    struct opened {
        std::string _body;
        std::string _attributes;
    };

    sse_keys(key_provider sqs_managed, key_provider kms)
        : _sqs_managed(std::move(sqs_managed)), _kms(std::move(kms)) {}

    /// Seals `body` and `attributes` for message `message_id`. Throws
    /// `kms_error`.
    [[nodiscard]] auto seal(const target& t, std::string_view message_id, std::string_view body,
                            std::string_view attributes, std::uint64_t now_ms) -> std::string {
        const auto key = current(t, now_ms);
        std::string plain;
        sse_detail::put_u32(plain, static_cast<std::uint32_t>(body.size()));
        plain.append(body);
        plain.append(attributes);
        std::string out(sse_detail::k_magic);
        sse_detail::put_str(out, key._key_id);
        sse_detail::put_str(out, t._queue_arn);
        sse_detail::put_str(out, key._wrapped);
        out += sse_detail::gcm_seal(
            key._plaintext, sse_detail::body_aad(message_id, key._key_id, t._queue_arn), plain);
        return out;
    }

    /// Opens a sealed body. Throws `kms_error` when the provider refuses
    /// the data key and `sealed_body_error` when the body is damaged.
    [[nodiscard]] auto open(std::string_view message_id, std::string_view sealed,
                            std::uint64_t now_ms) -> opened {
        auto in = sealed.substr(sse_detail::k_magic.size());
        std::string_view key_id;
        std::string_view arn;
        std::string_view wrapped;
        if (!is_sealed(sealed) || !sse_detail::get_str(in, key_id) ||
            !sse_detail::get_str(in, arn) || !sse_detail::get_str(in, wrapped)) {
            throw sealed_body_error("sqs: sealed body is damaged");
        }
        const auto key =
            unwrap(std::string(key_id), std::string(arn), std::string(wrapped), now_ms);
        const auto plain =
            sse_detail::gcm_open(key, sse_detail::body_aad(message_id, key_id, arn), in);
        std::string_view p = plain ? std::string_view(*plain) : std::string_view();
        std::uint32_t n = 0;
        if (!plain || !sse_detail::get_u32(p, n) || p.size() < n) {
            throw sealed_body_error("sqs: sealed body does not open");
        }
        return opened{std::string(p.substr(0, n)), std::string(p.substr(n))};
    }

    /// Provider calls made (generate and decrypt), for tests and metrics.
    [[nodiscard]] auto provider_calls() const -> std::uint64_t {
        const std::scoped_lock lock(_mutex);
        return _calls;
    }

private:
    struct current_key {
        generated_data_key _key;
        std::uint64_t _expires_ms = 0;
    };
    struct cached_key {
        data_key_bytes _plaintext{};
        std::uint64_t _expires_ms = 0;
    };

    static constexpr std::size_t k_max_cached = 4096;

    key_provider _sqs_managed;
    key_provider _kms;
    mutable std::mutex _mutex;
    std::map<std::string, current_key> _current;   // by key id + queue ARN
    std::map<std::string, cached_key> _unwrapped;  // by wrapped key
    std::uint64_t _calls = 0;

    [[nodiscard]] static auto is_managed(std::string_view key_id) -> bool {
        return key_id == k_sqs_managed_key;
    }

    [[nodiscard]] auto provider_for(std::string_view key_id) const -> const key_provider& {
        return is_managed(key_id) ? _sqs_managed : _kms;
    }

    [[nodiscard]] auto current(const target& t, std::uint64_t now_ms) -> generated_data_key {
        const auto key_id = t._kms_key_id.empty() ? std::string(k_sqs_managed_key) : t._kms_key_id;
        const auto slot = key_id + '\n' + t._queue_arn;
        {
            const std::scoped_lock lock(_mutex);
            if (const auto it = _current.find(slot);
                it != _current.end() && now_ms < it->second._expires_ms) {
                return it->second._key;
            }
            ++_calls;
        }
        // The provider call is outside the lock: it may be a network call.
        auto key = provider_for(key_id).generate_data_key(key_id, {{"aws:sqs:arn", t._queue_arn}});
        const auto expires = now_ms + std::uint64_t{t._reuse_s} * 1000;
        const std::scoped_lock lock(_mutex);
        _current[slot] = current_key{key, expires};
        remember(key._wrapped, key._plaintext, now_ms, expires);
        return key;
    }

    [[nodiscard]] auto unwrap(const std::string& key_id, const std::string& arn,
                              const std::string& wrapped, std::uint64_t now_ms) -> data_key_bytes {
        {
            const std::scoped_lock lock(_mutex);
            if (const auto it = _unwrapped.find(wrapped);
                it != _unwrapped.end() && now_ms < it->second._expires_ms) {
                return it->second._plaintext;
            }
            ++_calls;
        }
        const auto key =
            provider_for(key_id).decrypt_data_key(key_id, wrapped, {{"aws:sqs:arn", arn}});
        const std::scoped_lock lock(_mutex);
        // A key unwrapped only to open is kept five minutes, SQS's default
        // reuse period.
        remember(wrapped, key, now_ms, now_ms + 300'000);
        return key;
    }

    void remember(const std::string& wrapped, const data_key_bytes& key, std::uint64_t now_ms,
                  std::uint64_t expires) {
        if (_unwrapped.size() >= k_max_cached) {
            // Expired first; failing that, any (the map's first).
            std::erase_if(_unwrapped,
                          [&](const auto& kv) { return kv.second._expires_ms <= now_ms; });
            if (_unwrapped.size() >= k_max_cached) {
                _unwrapped.erase(_unwrapped.begin());
            }
        }
        _unwrapped[wrapped] = cached_key{key, expires};
    }
};

/// A node's `sse_keys` from its settings: the SSE-SQS master key from
/// `sse_secret` (`SQS_SSE_KEY_FILE`), else from `forward_secret`, else
/// random (one in-memory node); the `local` SSE-KMS provider when a
/// passphrase is given. Secrets are used as given, less trailing white
/// space. Throws `std::invalid_argument` for a secret under 16 bytes.
[[nodiscard]] inline auto node_sse_keys(std::string sse_secret, std::string_view forward_secret,
                                        std::optional<std::string> kms_passphrase)
    -> std::shared_ptr<sse_keys> {
    const auto trim = [](std::string& v) {
        while (!v.empty() && (v.back() == '\n' || v.back() == '\r' || v.back() == ' ')) {
            v.pop_back();
        }
    };
    trim(sse_secret);
    constexpr std::string_view label = "kythira-sqs-sse-v1";
    data_key_bytes master{};
    if (!sse_secret.empty()) {
        if (sse_secret.size() < 16) {
            throw std::invalid_argument("SQS_SSE_KEY_FILE must hold at least 16 bytes");
        }
        master = derived_key(sse_secret, label);
    } else if (!forward_secret.empty()) {
        master = derived_key(forward_secret, label);
    } else {
        master = random_key();
    }
    key_provider kms;
    if (kms_passphrase) {
        trim(*kms_passphrase);
        if (kms_passphrase->size() < 16) {
            throw std::invalid_argument("SQS_KMS_PASSPHRASE_FILE must hold at least 16 bytes");
        }
        kms = key_provider(
            wrapping_provider(passphrase_key(*kms_passphrase, "kythira-sqs-kms-local-v1")));
    }
    return std::make_shared<sse_keys>(key_provider(wrapping_provider(master)), std::move(kms));
}

}  // namespace kythira::sqs
