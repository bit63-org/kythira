// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kms_hpke.hpp
/// @brief HPKE (RFC 9180) base mode for one suite: DHKEM(X25519,
///        HKDF-SHA256), HKDF-SHA256 and AES-256-GCM (kem 0x0020, kdf
///        0x0001, aead 0x0002).
///
/// The suite of Decrypt's Kythira recipient extension
/// (`KYTHIRA_HPKE_X25519_SHA256_AES256GCM`, `.kiro/specs/ec2-compatible-api/`
/// Requirement 10.2-10.3): KMS opens a data key and seals it to the
/// attaching helm's X25519 transport key, so the EC2 controller that asked
/// never holds it. antikythera's helm opens the result
/// (antikythera `src/helm/hpke.hpp`, the same construction); the tests
/// check both against the CFRG test vector for this suite and a VolumeKey
/// frame made by antikythera's code.
///
/// Built from OpenSSL 3.0 primitives (X25519, HMAC-SHA256, AES-256-GCM):
/// OSSL_HPKE needs OpenSSL 3.2 and Ubuntu 24.04 ships 3.0. Single-shot
/// only, one message per encapsulation, so the nonce is the base nonce.
/// Every intermediate secret is wiped when it goes.
///
/// Results are this file's own `result<T>` rather than std::expected:
/// clang 18 over libstdc++ (the static-analysis and clang CI setups)
/// does not provide <expected>, as raft/sigv4_verifier.hpp notes.

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms::hpke {

inline constexpr std::size_t public_key_size = 32;
inline constexpr std::size_t private_key_size = 32;
inline constexpr std::size_t enc_size = 32;  ///< the ephemeral public key
inline constexpr std::size_t tag_size = 16;
inline constexpr std::size_t ikm_size = 32;  ///< what seal() draws for the ephemeral key

using public_key = std::array<std::byte, public_key_size>;
using enc_bytes = std::array<std::byte, enc_size>;

enum class error : std::uint8_t {
    crypto_failure,  ///< OpenSSL failed, or the RNG did
    bad_public_key,  ///< a low-order X25519 point: the shared secret would be zero
    bad_size,        ///< ciphertext shorter than the tag, or output the wrong size
    open_failed,     ///< wrong key, wrong info or AAD, or a tampered ciphertext
};

[[nodiscard]] inline auto to_string(error e) noexcept -> std::string_view {
    switch (e) {
        case error::crypto_failure:
            return "crypto failure";
        case error::bad_public_key:
            return "bad public key";
        case error::bad_size:
            return "bad size";
        case error::open_failed:
            return "open failed";
    }
    return "unknown";
}

/// A value or the error that stopped it.
template<typename T> class [[nodiscard]] result {
public:
    result(T v) : _v(std::move(v)) {}  // NOLINT(google-explicit-constructor)
    result(hpke::error e) : _e(e) {}   // NOLINT(google-explicit-constructor)

    [[nodiscard]] auto has_value() const noexcept -> bool { return _v.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }
    [[nodiscard]] auto operator*() & -> T& { return *_v; }
    [[nodiscard]] auto operator*() const& -> const T& { return *_v; }
    [[nodiscard]] auto operator*() && -> T&& { return std::move(*_v); }
    [[nodiscard]] auto operator->() -> T* { return &*_v; }
    [[nodiscard]] auto operator->() const -> const T* { return &*_v; }
    [[nodiscard]] auto error() const noexcept -> hpke::error { return _e; }

private:
    std::optional<T> _v;
    hpke::error _e{hpke::error::crypto_failure};
};

/// Success, or the error that stopped it.
template<> class [[nodiscard]] result<void> {
public:
    result() = default;
    result(hpke::error e) : _ok(false), _e(e) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] auto has_value() const noexcept -> bool { return _ok; }
    explicit operator bool() const noexcept { return _ok; }
    [[nodiscard]] auto error() const noexcept -> hpke::error { return _e; }

private:
    bool _ok = true;
    hpke::error _e{hpke::error::crypto_failure};
};

/// Bytes that are wiped when they go.
class secret {
public:
    secret() = default;
    explicit secret(std::size_t n) : _b(n) {}
    secret(const secret&) = delete;
    auto operator=(const secret&) -> secret& = delete;
    secret(secret&& o) noexcept : _b(std::exchange(o._b, {})) {}
    auto operator=(secret&& o) noexcept -> secret& {
        if (this != &o) {
            wipe();
            _b = std::exchange(o._b, {});
        }
        return *this;
    }
    ~secret() { wipe(); }

    [[nodiscard]] auto span() noexcept -> std::span<std::byte> { return _b; }
    [[nodiscard]] auto span() const noexcept -> std::span<const std::byte> { return _b; }
    void append(std::span<const std::byte> s) {
        // Grow by copying into a fresh buffer so the old one is wiped,
        // never left behind by a reallocation.
        std::vector<std::byte> grown;
        grown.reserve(_b.size() + s.size());
        grown.insert(grown.end(), _b.begin(), _b.end());
        grown.insert(grown.end(), s.begin(), s.end());
        wipe();
        _b = std::move(grown);
    }

private:
    void wipe() noexcept {
        if (!_b.empty()) {
            OPENSSL_cleanse(_b.data(), _b.size());
        }
    }

    std::vector<std::byte> _b;
};

struct key_pair {
    secret private_key;
    public_key public_key_bytes{};
};

struct sealed {
    enc_bytes enc{};
    std::vector<std::byte> ciphertext;  ///< plaintext size + tag_size
};

namespace detail {

inline constexpr std::size_t hash_size = 32;   // Nh, SHA-256
inline constexpr std::size_t key_size = 32;    // Nk, AES-256
inline constexpr std::size_t nonce_size = 12;  // Nn
inline constexpr std::uint16_t kem_id = 0x0020;
inline constexpr std::uint16_t kdf_id = 0x0001;
inline constexpr std::uint16_t aead_id = 0x0002;
inline constexpr std::uint8_t mode_base = 0x00;

inline void put_u16(secret& s, std::uint16_t v) {
    const std::array<std::byte, 2> b{static_cast<std::byte>(v >> 8U), static_cast<std::byte>(v)};
    s.append(b);
}

[[nodiscard]] inline auto text(std::string_view s) -> std::span<const std::byte> {
    return std::as_bytes(std::span{s.data(), s.size()});
}

inline void kem_suite(secret& s) {
    s.append(text("KEM"));
    put_u16(s, kem_id);
}

inline void hpke_suite(secret& s) {
    s.append(text("HPKE"));
    put_u16(s, kem_id);
    put_u16(s, kdf_id);
    put_u16(s, aead_id);
}

using suite_fn = void (*)(secret&);

[[nodiscard]] inline auto uc(std::span<const std::byte> s) -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(s.data());
}
[[nodiscard]] inline auto uc(std::span<std::byte> s) -> unsigned char* {
    return reinterpret_cast<unsigned char*>(s.data());
}

[[nodiscard]] inline auto hmac(std::span<const std::byte> key, std::span<const std::byte> data,
                               std::span<std::byte> out) -> bool {
    unsigned int len = 0;
    // An empty key is the RFC 5869 default salt: HMAC pads it to zeros.
    static constexpr std::array<unsigned char, 1> none{};
    const auto* k = key.empty() ? none.data() : uc(key);
    const auto* d = data.empty() ? none.data() : uc(data);
    return out.size() == hash_size &&
           HMAC(EVP_sha256(), k, static_cast<int>(key.size()), d, data.size(), uc(out), &len) !=
               nullptr &&
           len == hash_size;
}

/// LabeledExtract(salt, label, ikm) =
///   HKDF-Extract(salt, "HPKE-v1" || suite || label || ikm)
[[nodiscard]] inline auto labeled_extract(suite_fn suite, std::span<const std::byte> salt,
                                          std::string_view label, std::span<const std::byte> ikm)
    -> result<secret> {
    secret msg;
    msg.append(text("HPKE-v1"));
    suite(msg);
    msg.append(text(label));
    msg.append(ikm);
    secret prk{hash_size};
    if (!hmac(salt, msg.span(), prk.span())) {
        return error::crypto_failure;
    }
    return prk;
}

/// LabeledExpand(prk, label, info, L) =
///   HKDF-Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite || label || info, L)
[[nodiscard]] inline auto labeled_expand(suite_fn suite, std::span<const std::byte> prk,
                                         std::string_view label, std::span<const std::byte> info,
                                         std::size_t length) -> result<secret> {
    secret labeled;
    put_u16(labeled, static_cast<std::uint16_t>(length));
    labeled.append(text("HPKE-v1"));
    suite(labeled);
    labeled.append(text(label));
    labeled.append(info);
    secret out{length};
    secret t;  // T(i-1)
    std::size_t done = 0;
    for (std::uint8_t i = 1; done < length; ++i) {
        secret block;
        block.append(t.span());
        block.append(labeled.span());
        const std::array<std::byte, 1> counter{std::byte{i}};
        block.append(counter);
        secret next{hash_size};
        if (!hmac(prk, block.span(), next.span())) {
            return error::crypto_failure;
        }
        const auto n = std::min(hash_size, length - done);
        std::ranges::copy(next.span().first(n), out.span().subspan(done).begin());
        done += n;
        t = std::move(next);
    }
    return out;
}

struct pkey_free {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
using pkey = std::unique_ptr<EVP_PKEY, pkey_free>;
struct pkey_ctx_free {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct cipher_ctx_free {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};

[[nodiscard]] inline auto private_pkey(std::span<const std::byte> sk) -> pkey {
    return pkey{EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, uc(sk), sk.size())};
}

[[nodiscard]] inline auto public_of(EVP_PKEY* key) -> result<public_key> {
    public_key pk{};
    std::size_t len = pk.size();
    if (EVP_PKEY_get_raw_public_key(key, uc(std::span<std::byte>{pk}), &len) != 1 ||
        len != pk.size()) {
        return error::crypto_failure;
    }
    return pk;
}

/// X25519(sk, pk); an all-zero result (a low-order pk) is refused.
[[nodiscard]] inline auto dh(std::span<const std::byte> sk, std::span<const std::byte> pk)
    -> result<secret> {
    const auto priv = private_pkey(sk);
    const pkey peer{EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, uc(pk), pk.size())};
    if (!priv || !peer) {
        return error::crypto_failure;
    }
    const std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free> ctx{EVP_PKEY_CTX_new(priv.get(), nullptr)};
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1) {
        return error::crypto_failure;
    }
    secret out{public_key_size};
    std::size_t len = public_key_size;
    if (EVP_PKEY_derive(ctx.get(), uc(out.span()), &len) != 1 || len != public_key_size) {
        return error::bad_public_key;  // OpenSSL refuses a zero result too
    }
    if (std::ranges::all_of(out.span(), [](std::byte b) { return b == std::byte{0}; })) {
        return error::bad_public_key;
    }
    return out;
}

/// DHKEM ExtractAndExpand(dh, enc || pkR).
[[nodiscard]] inline auto shared_secret(std::span<const std::byte> dh_out,
                                        std::span<const std::byte> enc,
                                        std::span<const std::byte> pk_r) -> result<secret> {
    auto prk = labeled_extract(kem_suite, {}, "eae_prk", dh_out);
    if (!prk) {
        return prk.error();
    }
    secret context;
    context.append(enc);
    context.append(pk_r);
    return labeled_expand(kem_suite, prk->span(), "shared_secret", context.span(), hash_size);
}

struct context {
    secret key;
    secret nonce;
};

/// KeySchedule for mode_base (no PSK).
[[nodiscard]] inline auto key_schedule(std::span<const std::byte> shared,
                                       std::span<const std::byte> info) -> result<context> {
    auto psk_id_hash = labeled_extract(hpke_suite, {}, "psk_id_hash", {});
    auto info_hash = labeled_extract(hpke_suite, {}, "info_hash", info);
    if (!psk_id_hash || !info_hash) {
        return error::crypto_failure;
    }
    secret ks_context;
    const std::array<std::byte, 1> mode{std::byte{mode_base}};
    ks_context.append(mode);
    ks_context.append(psk_id_hash->span());
    ks_context.append(info_hash->span());
    auto s = labeled_extract(hpke_suite, shared, "secret", {});
    if (!s) {
        return s.error();
    }
    auto key = labeled_expand(hpke_suite, s->span(), "key", ks_context.span(), key_size);
    auto nonce = labeled_expand(hpke_suite, s->span(), "base_nonce", ks_context.span(), nonce_size);
    if (!key || !nonce) {
        return error::crypto_failure;
    }
    return context{.key = std::move(*key), .nonce = std::move(*nonce)};
}

[[nodiscard]] inline auto aead(bool encrypt, const context& c, std::span<const std::byte> aad,
                               std::span<const std::byte> in, std::span<std::byte> out,
                               std::span<std::byte> tag) -> result<void> {
    const std::unique_ptr<EVP_CIPHER_CTX, cipher_ctx_free> ctx{EVP_CIPHER_CTX_new()};
    const int enc = encrypt ? 1 : 0;
    if (!ctx ||
        EVP_CipherInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr, enc) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce_size, nullptr) != 1 ||
        EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, uc(c.key.span()), uc(c.nonce.span()), enc) !=
            1) {
        return error::crypto_failure;
    }
    int len = 0;
    if (!aad.empty() &&
        EVP_CipherUpdate(ctx.get(), nullptr, &len, uc(aad), static_cast<int>(aad.size())) != 1) {
        return error::crypto_failure;
    }
    if (!in.empty() &&
        EVP_CipherUpdate(ctx.get(), uc(out), &len, uc(in), static_cast<int>(in.size())) != 1) {
        return error::crypto_failure;
    }
    if (!encrypt &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag.data()) != 1) {
        return error::crypto_failure;
    }
    std::array<unsigned char, 16> tail{};
    if (EVP_CipherFinal_ex(ctx.get(), tail.data(), &len) != 1) {
        return encrypt ? error::crypto_failure : error::open_failed;
    }
    if (encrypt &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, tag.data()) != 1) {
        return error::crypto_failure;
    }
    return {};
}

}  // namespace detail

/// DeriveKeyPair (RFC 9180 7.1.3): the same ikm always gives the same pair.
[[nodiscard]] inline auto derive_key_pair(std::span<const std::byte> ikm) -> result<key_pair> {
    auto prk = detail::labeled_extract(detail::kem_suite, {}, "dkp_prk", ikm);
    if (!prk) {
        return prk.error();
    }
    auto sk = detail::labeled_expand(detail::kem_suite, prk->span(), "sk", {}, private_key_size);
    if (!sk) {
        return sk.error();
    }
    const auto key = detail::private_pkey(sk->span());
    if (!key) {
        return error::crypto_failure;
    }
    auto pk = detail::public_of(key.get());
    if (!pk) {
        return pk.error();
    }
    return key_pair{.private_key = std::move(*sk), .public_key_bytes = *pk};
}

/// Encrypts `plaintext` to `recipient`, the ephemeral key derived from
/// `ikm_e` (the test vectors' way).
[[nodiscard]] inline auto seal(std::span<const std::byte, public_key_size> recipient,
                               std::span<const std::byte> info, std::span<const std::byte> aad,
                               std::span<const std::byte> plaintext,
                               std::span<const std::byte, ikm_size> ikm_e) -> result<sealed> {
    auto eph = derive_key_pair(ikm_e);
    if (!eph) {
        return eph.error();
    }
    auto d = detail::dh(eph->private_key.span(), recipient);
    if (!d) {
        return d.error();
    }
    auto shared = detail::shared_secret(d->span(), eph->public_key_bytes, recipient);
    if (!shared) {
        return shared.error();
    }
    auto ctx = detail::key_schedule(shared->span(), info);
    if (!ctx) {
        return ctx.error();
    }
    sealed out{.enc = eph->public_key_bytes,
               .ciphertext = std::vector<std::byte>(plaintext.size() + tag_size)};
    const std::span<std::byte> ct{out.ciphertext};
    if (auto r = detail::aead(true, *ctx, aad, plaintext, ct.first(plaintext.size()),
                              ct.subspan(plaintext.size()));
        !r) {
        return r.error();
    }
    return out;
}

/// Encrypts `plaintext` to `recipient` with a fresh ephemeral key.
[[nodiscard]] inline auto seal(std::span<const std::byte, public_key_size> recipient,
                               std::span<const std::byte> info, std::span<const std::byte> aad,
                               std::span<const std::byte> plaintext) -> result<sealed> {
    secret ikm{ikm_size};
    if (RAND_bytes(detail::uc(ikm.span()), static_cast<int>(ikm_size)) != 1) {
        return error::crypto_failure;
    }
    return seal(recipient, info, aad, plaintext, ikm.span().first<ikm_size>());
}

/// Decrypts into `out`, which must be ciphertext.size() - tag_size bytes.
/// On failure `out` is wiped.
[[nodiscard]] inline auto open(std::span<const std::byte, private_key_size> recipient_key,
                               std::span<const std::byte, enc_size> enc,
                               std::span<const std::byte> info, std::span<const std::byte> aad,
                               std::span<const std::byte> ciphertext, std::span<std::byte> out)
    -> result<void> {
    if (ciphertext.size() < tag_size || out.size() != ciphertext.size() - tag_size) {
        if (!out.empty()) {
            OPENSSL_cleanse(out.data(), out.size());
        }
        return error::bad_size;
    }
    const auto outcome = [&]() -> result<void> {
        const auto key = detail::private_pkey(recipient_key);
        if (!key) {
            return error::crypto_failure;
        }
        const auto pk_r = detail::public_of(key.get());
        if (!pk_r) {
            return pk_r.error();
        }
        auto d = detail::dh(recipient_key, enc);
        if (!d) {
            return d.error();
        }
        auto shared = detail::shared_secret(d->span(), enc, *pk_r);
        if (!shared) {
            return shared.error();
        }
        auto ctx = detail::key_schedule(shared->span(), info);
        if (!ctx) {
            return ctx.error();
        }
        std::array<std::byte, tag_size> tag{};
        std::ranges::copy(ciphertext.subspan(out.size()), tag.begin());
        return detail::aead(false, *ctx, aad, ciphertext.first(out.size()), out, tag);
    }();
    if (!outcome && !out.empty()) {
        OPENSSL_cleanse(out.data(), out.size());
    }
    return outcome;
}

}  // namespace kythira::kms::hpke
