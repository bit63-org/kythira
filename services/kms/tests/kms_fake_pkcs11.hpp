// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An in-memory pkcs11::backend for the KMS's job tests: objects with
// attributes, generation with random "material" the test can look for,
// and a switch that makes every call fail as a sealed virtual HSM does
// (CKR_DEVICE_ERROR). It implements only what backing_store calls:
// AES-256-GCM (CKM_AES_GCM, ciphertext || tag, a failed tag
// CKR_ENCRYPTED_DATA_INVALID) over OpenSSL with the object's material,
// random bytes, and real RSA and EC key pairs (one per size or curve per
// process, to keep the tests fast) with the PKCS#11 signing mechanisms the
// KMS uses (CKM_RSA_PKCS over a DigestInfo, CKM_RSA_PKCS_PSS, CKM_ECDSA as
// r || s), RSA-OAEP decryption and HMAC.

#include <kythira/kms/kms_public_key.hpp>

#include <raft/pkcs11_module.hpp>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace kythira::kms::test {

namespace p11 = kythira::pkcs11;

class fake_backend final : public p11::backend {
public:
    struct object {
        std::map<CK_ATTRIBUTE_TYPE, p11::bytes> attrs;
        p11::bytes material;  // what a real token would keep secret
    };

    bool sealed = false;
    int generated = 0;

    [[nodiscard]] auto library() -> p11::library_info override { return {}; }
    [[nodiscard]] auto tokens() -> std::vector<p11::token_info> override { return {}; }
    [[nodiscard]] auto mechanisms(CK_SLOT_ID) -> std::vector<CK_MECHANISM_TYPE> override {
        return {};
    }
    [[nodiscard]] auto open_session(CK_SLOT_ID) -> CK_SESSION_HANDLE override {
        const std::lock_guard l(_mu);
        return ++_sessions;
    }
    void close_session(CK_SESSION_HANDLE) override {}
    void login(CK_SESSION_HANDLE, std::string_view pin) override {
        if (pin != "1234") {
            throw p11::error("login", CKR_PIN_INCORRECT);
        }
    }

    [[nodiscard]] auto find_objects(CK_SESSION_HANDLE, std::span<const p11::attribute> tmpl)
        -> std::vector<CK_OBJECT_HANDLE> override {
        const std::lock_guard l(_mu);
        std::vector<CK_OBJECT_HANDLE> out;
        for (const auto& [h, o] : _objects) {
            bool match = true;
            for (const auto& a : tmpl) {
                const auto it = o.attrs.find(a.type);
                match = match && it != o.attrs.end() && it->second == a.value;
            }
            if (match) {
                out.push_back(h);
            }
        }
        return out;
    }

    [[nodiscard]] auto get_attributes(CK_SESSION_HANDLE, CK_OBJECT_HANDLE o,
                                      std::span<const CK_ATTRIBUTE_TYPE> types)
        -> std::vector<std::optional<p11::bytes>> override {
        const std::lock_guard l(_mu);
        std::vector<std::optional<p11::bytes>> out;
        const auto& obj = _objects.at(o);
        for (const auto t : types) {
            const auto it = obj.attrs.find(t);
            out.push_back(it == obj.attrs.end() ? std::nullopt
                                                : std::optional<p11::bytes>(it->second));
        }
        return out;
    }

    [[nodiscard]] auto generate_key(CK_SESSION_HANDLE, const CK_MECHANISM& m,
                                    std::span<const p11::attribute> tmpl)
        -> CK_OBJECT_HANDLE override {
        check_unsealed();
        if (m.mechanism != CKM_AES_KEY_GEN && m.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            throw p11::error("generate_key", CKR_MECHANISM_INVALID);
        }
        std::size_t len = 32;
        for (const auto& a : tmpl) {
            if (a.type == CKA_VALUE_LEN && a.value.size() == sizeof(CK_ULONG)) {
                CK_ULONG v = 0;
                std::memcpy(&v, a.value.data(), sizeof v);
                len = v;
            }
        }
        return add(tmpl, len);
    }

    [[nodiscard]] auto generate_key_pair(CK_SESSION_HANDLE, const CK_MECHANISM& m,
                                         std::span<const p11::attribute> pub,
                                         std::span<const p11::attribute> priv)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> override {
        check_unsealed();
        if (m.mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN && m.mechanism != CKM_EC_KEY_PAIR_GEN) {
            throw p11::error("generate_key_pair", CKR_MECHANISM_INVALID);
        }
        std::vector<p11::attribute> p(pub.begin(), pub.end());
        p.push_back(p11::attribute::of_ulong(CKA_CLASS, CKO_PUBLIC_KEY));
        std::vector<p11::attribute> s(priv.begin(), priv.end());
        s.push_back(p11::attribute::of_ulong(CKA_CLASS, CKO_PRIVATE_KEY));
        const auto* k = pair_for(pub);
        const BIGNUM* n = nullptr;
        if (EVP_PKEY_get_bn_param(k, "n", const_cast<BIGNUM**>(&n)) == 1) {  // NOLINT
            BIGNUM* e = nullptr;
            EVP_PKEY_get_bn_param(k, "e", &e);
            p.push_back(p11::attribute::of_bytes(CKA_MODULUS, bn_bytes(n)));
            p.push_back(p11::attribute::of_bytes(CKA_PUBLIC_EXPONENT, bn_bytes(e)));
            BN_free(const_cast<BIGNUM*>(n));  // NOLINT
            BN_free(e);
        } else {
            std::array<unsigned char, 200> point{};
            std::size_t len = 0;
            EVP_PKEY_get_octet_string_param(k, "encoded-pub-key", point.data(), point.size(), &len);
            // DER OCTET STRING, as PKCS#11 returns CKA_EC_POINT.
            p11::bytes wrapped{0x04};
            if (len >= 128) {
                wrapped.push_back(0x81);
            }
            wrapped.push_back(static_cast<std::uint8_t>(len));
            wrapped.insert(wrapped.end(), point.begin(), point.begin() + static_cast<long>(len));
            p.push_back(p11::attribute::of_bytes(CKA_EC_POINT, wrapped));
        }
        const int dl = i2d_PrivateKey(k, nullptr);
        p11::bytes der(static_cast<std::size_t>(dl));
        unsigned char* dp = der.data();
        i2d_PrivateKey(k, &dp);
        const auto ph = add(p, 0);
        return {ph, add_with(s, std::move(der))};
    }

    [[nodiscard]] auto create_object(CK_SESSION_HANDLE, std::span<const p11::attribute>)
        -> CK_OBJECT_HANDLE override {
        throw p11::error("create_object", CKR_FUNCTION_NOT_SUPPORTED);
    }
    void destroy_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE o) override {
        check_unsealed();
        const std::lock_guard l(_mu);
        if (_objects.erase(o) == 0) {
            throw p11::error("destroy_object", CKR_OBJECT_HANDLE_INVALID);
        }
    }
    [[nodiscard]] auto sign(CK_SESSION_HANDLE, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                            std::span<const std::uint8_t> data) -> p11::bytes override {
        check_unsealed();
        const auto material = usable(key, CKA_SIGN);
        switch (m.mechanism) {
            case CKM_SHA224_HMAC:
            case CKM_SHA256_HMAC:
            case CKM_SHA384_HMAC:
            case CKM_SHA512_HMAC: {
                const EVP_MD* md = m.mechanism == CKM_SHA224_HMAC   ? EVP_sha224()
                                   : m.mechanism == CKM_SHA256_HMAC ? EVP_sha256()
                                   : m.mechanism == CKM_SHA384_HMAC ? EVP_sha384()
                                                                    : EVP_sha512();
                p11::bytes out(EVP_MAX_MD_SIZE);
                unsigned int n = 0;
                HMAC(md, material.data(), static_cast<int>(material.size()), data.data(),
                     data.size(), out.data(), &n);
                out.resize(n);
                return out;
            }
            case CKM_RSA_PKCS:
            case CKM_RSA_PKCS_PSS:
            case CKM_ECDSA:
                break;
            default:
                throw p11::error("sign", CKR_MECHANISM_INVALID);
        }
        const auto k = private_key(material);
        const pctx ctx(EVP_PKEY_CTX_new(k.get(), nullptr));
        bool ok = ctx && EVP_PKEY_sign_init(ctx.get()) == 1;
        if (m.mechanism == CKM_RSA_PKCS) {
            ok = ok && EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) == 1;
        } else if (m.mechanism == CKM_RSA_PKCS_PSS) {
            const auto& pp = *static_cast<const CK_RSA_PKCS_PSS_PARAMS*>(m.pParameter);
            ok = ok && EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) == 1 &&
                 EVP_PKEY_CTX_set_signature_md(ctx.get(), md_of(pp.hashAlg)) == 1 &&
                 EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md_of(pp.hashAlg)) == 1 &&
                 EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), static_cast<int>(pp.sLen)) == 1;
        }
        std::size_t n = 0;
        ok = ok && EVP_PKEY_sign(ctx.get(), nullptr, &n, data.data(), data.size()) == 1;
        p11::bytes sig(n);
        ok = ok && EVP_PKEY_sign(ctx.get(), sig.data(), &n, data.data(), data.size()) == 1;
        if (!ok) {
            throw p11::error("sign", CKR_FUNCTION_FAILED);
        }
        sig.resize(n);
        if (m.mechanism != CKM_ECDSA) {
            return sig;
        }
        // DER to r || s, each the order's length.
        const unsigned char* sp = sig.data();
        ECDSA_SIG* es = d2i_ECDSA_SIG(nullptr, &sp, static_cast<long>(sig.size()));
        const auto half = static_cast<std::size_t>((EVP_PKEY_get_bits(k.get()) + 7) / 8);
        p11::bytes raw(2 * half);
        BN_bn2binpad(ECDSA_SIG_get0_r(es), raw.data(), static_cast<int>(half));
        BN_bn2binpad(ECDSA_SIG_get0_s(es), raw.data() + half, static_cast<int>(half));
        ECDSA_SIG_free(es);
        return raw;
    }
    [[nodiscard]] auto verify(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                              std::span<const std::uint8_t>, std::span<const std::uint8_t>)
        -> bool override {
        throw p11::error("verify", CKR_FUNCTION_NOT_SUPPORTED);
    }
    [[nodiscard]] auto encrypt(CK_SESSION_HANDLE, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                               std::span<const std::uint8_t> data) -> p11::bytes override {
        return gcm(true, m, key, data);
    }
    [[nodiscard]] auto decrypt(CK_SESSION_HANDLE, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                               std::span<const std::uint8_t> data) -> p11::bytes override {
        if (m.mechanism != CKM_RSA_PKCS_OAEP) {
            return gcm(false, m, key, data);
        }
        check_unsealed();
        const auto& op = *static_cast<const CK_RSA_PKCS_OAEP_PARAMS*>(m.pParameter);
        const auto k = private_key(usable(key, CKA_DECRYPT));
        const pctx ctx(EVP_PKEY_CTX_new(k.get(), nullptr));
        std::size_t n = 0;
        bool ok = ctx && EVP_PKEY_decrypt_init(ctx.get()) == 1 &&
                  EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) == 1 &&
                  EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), md_of(op.hashAlg)) == 1 &&
                  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md_of(op.hashAlg)) == 1 &&
                  EVP_PKEY_decrypt(ctx.get(), nullptr, &n, data.data(), data.size()) == 1;
        p11::bytes out(n);
        ok = ok && EVP_PKEY_decrypt(ctx.get(), out.data(), &n, data.data(), data.size()) == 1;
        if (!ok) {
            throw p11::error("decrypt", CKR_ENCRYPTED_DATA_INVALID);
        }
        out.resize(n);
        return out;
    }
    [[nodiscard]] auto generate_random(CK_SESSION_HANDLE, std::size_t length)
        -> p11::bytes override {
        check_unsealed();
        p11::bytes out(length);
        if (length > 0 && RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
            throw p11::error("generate_random", CKR_FUNCTION_FAILED);
        }
        return out;
    }
    [[nodiscard]] auto wrap_key(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                                CK_OBJECT_HANDLE) -> p11::bytes override {
        throw p11::error("wrap_key", CKR_FUNCTION_NOT_SUPPORTED);
    }
    [[nodiscard]] auto unwrap_key(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                                  std::span<const std::uint8_t>, std::span<const p11::attribute>)
        -> CK_OBJECT_HANDLE override {
        throw p11::error("unwrap_key", CKR_FUNCTION_NOT_SUPPORTED);
    }

    /// Adds an object with `label` (a stray, or another application's).
    auto plant(const std::string& label, CK_OBJECT_CLASS cls = CKO_SECRET_KEY) -> CK_OBJECT_HANDLE {
        const std::vector<p11::attribute> t{p11::attribute::of_ulong(CKA_CLASS, cls),
                                            p11::attribute::of_string(CKA_LABEL, label)};
        return add(t, 32);
    }

    [[nodiscard]] auto objects() const -> std::map<CK_OBJECT_HANDLE, object> {
        const std::lock_guard l(_mu);
        return _objects;
    }

    /// Encryptions and decryptions so far.
    int crypto_calls = 0;

private:
    struct pkey_free {
        void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
    };
    struct pctx_free {
        void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
    };
    using pkey = std::unique_ptr<EVP_PKEY, pkey_free>;
    using pctx = std::unique_ptr<EVP_PKEY_CTX, pctx_free>;

    static auto md_of(CK_MECHANISM_TYPE h) -> const EVP_MD* {
        switch (h) {
            case CKM_SHA_1:
                return EVP_sha1();
            case CKM_SHA384:
                return EVP_sha384();
            case CKM_SHA512:
                return EVP_sha512();
            default:
                return EVP_sha256();
        }
    }

    static auto bn_bytes(const BIGNUM* b) -> p11::bytes {
        p11::bytes out(static_cast<std::size_t>(BN_num_bytes(b)));
        BN_bn2bin(b, out.data());
        return out;
    }

    static auto private_key(const p11::bytes& der) -> pkey {
        const unsigned char* p = der.data();
        pkey k(d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(der.size())));
        if (!k) {
            throw p11::error("private key", CKR_KEY_HANDLE_INVALID);
        }
        return k;
    }

    /// The process's key pair for the size or curve `pub` asks for.
    auto pair_for(std::span<const p11::attribute> pub) -> const EVP_PKEY* {
        std::string which;
        for (const auto& a : pub) {
            if (a.type == CKA_MODULUS_BITS && a.value.size() == sizeof(CK_ULONG)) {
                CK_ULONG bits = 0;
                std::memcpy(&bits, a.value.data(), sizeof bits);
                which = "rsa" + std::to_string(bits);
            } else if (a.type == CKA_EC_PARAMS) {
                which = std::string(kythira::kms::curve_name(a.value));
            }
        }
        static std::mutex mu;
        static std::map<std::string, pkey> keys;
        const std::lock_guard l(mu);
        auto& k = keys[which];
        if (!k) {
            k.reset(which.starts_with("rsa") ? EVP_RSA_gen(std::stoul(which.substr(3)))
                                             : EVP_EC_gen(which.c_str()));
        }
        if (!k) {
            throw p11::error("generate_key_pair", CKR_CURVE_NOT_SUPPORTED);
        }
        return k.get();
    }

    /// An object's material, when it allows `use`.
    auto usable(CK_OBJECT_HANDLE key, CK_ATTRIBUTE_TYPE use) -> p11::bytes {
        const std::lock_guard l(_mu);
        const auto it = _objects.find(key);
        if (it == _objects.end()) {
            throw p11::error("use", CKR_KEY_HANDLE_INVALID);
        }
        const auto e = it->second.attrs.find(use);
        if (e == it->second.attrs.end() || e->second != p11::bytes{CK_TRUE}) {
            throw p11::error("use", CKR_KEY_FUNCTION_NOT_PERMITTED);
        }
        ++crypto_calls;
        return it->second.material;
    }

    auto gcm(bool enc, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
             std::span<const std::uint8_t> in) -> p11::bytes {
        check_unsealed();
        if (m.mechanism != CKM_AES_GCM || m.pParameter == nullptr ||
            m.ulParameterLen != sizeof(CK_GCM_PARAMS)) {
            throw p11::error("gcm", CKR_MECHANISM_INVALID);
        }
        const auto& p = *static_cast<const CK_GCM_PARAMS*>(m.pParameter);
        p11::bytes material;
        {
            const std::lock_guard l(_mu);
            const auto it = _objects.find(key);
            if (it == _objects.end()) {
                throw p11::error("gcm", CKR_KEY_HANDLE_INVALID);
            }
            const auto e = it->second.attrs.find(enc ? CKA_ENCRYPT : CKA_DECRYPT);
            if (e == it->second.attrs.end() || e->second != p11::bytes{CK_TRUE}) {
                throw p11::error("gcm", CKR_KEY_FUNCTION_NOT_PERMITTED);
            }
            material = it->second.material;
            ++crypto_calls;
        }
        constexpr std::size_t tag = 16;
        if (p.ulTagBits != tag * 8 || material.size() != 32 || (!enc && in.size() < tag)) {
            throw p11::error("gcm",
                             enc ? CKR_MECHANISM_PARAM_INVALID : CKR_ENCRYPTED_DATA_LEN_RANGE);
        }
        const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
            EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
        const auto body = enc ? in.size() : in.size() - tag;
        p11::bytes out(body + (enc ? tag : 0));
        int n = 0;
        bool ok = EVP_CipherInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr,
                                    enc ? 1 : 0) == 1 &&
                  EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                      static_cast<int>(p.ulIvLen), nullptr) == 1 &&
                  EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, material.data(), p.pIv, -1) == 1;
        ok = ok && (p.ulAADLen == 0 || EVP_CipherUpdate(ctx.get(), nullptr, &n, p.pAAD,
                                                        static_cast<int>(p.ulAADLen)) == 1);
        ok = ok &&
             EVP_CipherUpdate(ctx.get(), out.data(), &n, in.data(), static_cast<int>(body)) == 1;
        if (!enc) {
            p11::bytes t(in.end() - tag, in.end());
            ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag, t.data()) == 1;
        }
        int f = 0;
        ok = ok && EVP_CipherFinal_ex(ctx.get(), out.data() + n, &f) == 1;
        if (!ok) {
            throw p11::error("gcm", enc ? CKR_FUNCTION_FAILED : CKR_ENCRYPTED_DATA_INVALID);
        }
        if (enc) {
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag, out.data() + body);
        }
        return out;
    }

    void check_unsealed() const {
        if (sealed) {
            throw p11::error("sealed", CKR_DEVICE_ERROR);
        }
    }

    auto add_with(std::span<const p11::attribute> tmpl, p11::bytes material) -> CK_OBJECT_HANDLE {
        const std::lock_guard l(_mu);
        object o;
        for (const auto& a : tmpl) {
            o.attrs[a.type] = a.value;
        }
        o.material = std::move(material);
        ++generated;
        const auto h = _next++;
        _objects.emplace(h, std::move(o));
        return h;
    }

    auto add(std::span<const p11::attribute> tmpl, std::size_t material) -> CK_OBJECT_HANDLE {
        const std::lock_guard l(_mu);
        object o;
        for (const auto& a : tmpl) {
            o.attrs[a.type] = a.value;
        }
        o.material.resize(material);
        if (material > 0 &&
            RAND_bytes(o.material.data(), static_cast<int>(o.material.size())) != 1) {
            throw std::runtime_error("RAND_bytes");
        }
        ++generated;
        const auto h = _next++;
        _objects.emplace(h, std::move(o));
        return h;
    }

    mutable std::mutex _mu;
    CK_SESSION_HANDLE _sessions = 0;
    CK_OBJECT_HANDLE _next = 0x1000;
    std::map<CK_OBJECT_HANDLE, object> _objects;
};

}  // namespace kythira::kms::test
