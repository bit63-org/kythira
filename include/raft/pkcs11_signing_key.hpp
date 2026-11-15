// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A signing key on a PKCS#11 token, as a consumer holds it
// (.kiro/specs/virtual-hsm/ task 13, Requirements 10.1 and 10.3): the
// cluster CA's root key, IAM's OIDC and STS keys. One URI names the module,
// token, PIN and key, so the same configuration line points at the virtual
// HSM, a YubiHSM 2, CloudHSM or SoftHSM2.
//
// Signing stays inside the common subset (raft/pkcs11_module.hpp): ECDSA
// over P-256 or P-384 and RSA PKCS#1 v1.5 over a caller's SHA-256 or
// SHA-384 digest. Signatures come back as X.509 and JOSE consumers need
// them, DER for ECDSA through `x509_signature`, raw r || s otherwise.
//
// The session opens on first use. A call that finds it gone (the module
// restarted, the HSM failed over) opens a new one and tries once more.

#include <raft/certificate_authority.hpp>
#include <raft/pkcs11_module.hpp>
#include <raft/pkcs11_uri.hpp>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::pkcs11 {

/// The SubjectPublicKeyInfo PEM of a token key's public half (EC P-256,
/// P-384 or RSA).
[[nodiscard]] inline auto public_key_pem(const public_key_info& k) -> std::string {
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> bld(OSSL_PARAM_BLD_new(),
                                                                        &OSSL_PARAM_BLD_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n(nullptr, &BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e(nullptr, &BN_free);
    const char* type = "RSA";
    bool ok = bld != nullptr;
    if (k.key_type == CKK_RSA) {
        n.reset(BN_bin2bn(k.modulus.data(), static_cast<int>(k.modulus.size()), nullptr));
        e.reset(BN_bin2bn(k.public_exponent.data(), static_cast<int>(k.public_exponent.size()),
                          nullptr));
        ok = ok && n && e &&
             OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n.get()) == 1 &&
             OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e.get()) == 1;
    } else if (k.key_type == CKK_EC) {
        type = "EC";
        const char* group = nullptr;
        if (std::ranges::equal(k.ec_params, detail::p256_params)) {
            group = "prime256v1";
        } else if (std::ranges::equal(k.ec_params, detail::p384_params)) {
            group = "secp384r1";
        } else {
            throw error("public_key_pem: EC keys must be P-256 or P-384", CKR_CURVE_NOT_SUPPORTED);
        }
        ok =
            ok &&
            OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, group, 0) == 1 &&
            OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, k.ec_point.data(),
                                             k.ec_point.size()) == 1;
    } else {
        throw error("public_key_pem: neither RSA nor EC", CKR_KEY_TYPE_INCONSISTENT);
    }
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
        ok ? OSSL_PARAM_BLD_to_param(bld.get()) : nullptr, &OSSL_PARAM_free);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr), &EVP_PKEY_CTX_free);
    EVP_PKEY* raw = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
        throw error("public_key_pem: bad public key", CKR_KEY_TYPE_INCONSISTENT);
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, &EVP_PKEY_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key.get()) != 1) {
        throw error("public_key_pem: PEM encoding failed", CKR_FUNCTION_FAILED);
    }
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return {data, static_cast<std::size_t>(len)};
}

/// One signing key pair on a token.
class signing_key {
public:
    /// Called once, on first use, for the module to open.
    using module_source = std::function<module()>;

    /// `key` names the token (token= or serial=, the PIN) and the private
    /// key (object= or id=); `source` opens the module, by default the
    /// URI's module-path.
    explicit signing_key(uri key, module_source source = {})
        : _state(std::make_shared<state>(std::move(key), std::move(source))) {
        auto& u = _state->_uri;
        if (!u.object && !u.id) {
            throw std::invalid_argument("pkcs11 signing key " + u.to_string() +
                                        " names no key (object= or id=)");
        }
        if (u.type && u.type != object_type::private_key) {
            throw std::invalid_argument("pkcs11 signing key " + u.to_string() +
                                        " is not a private key");
        }
        u.type = object_type::private_key;
        if (!_state->_source) {
            if (!u.module_path) {
                throw std::invalid_argument("pkcs11 signing key " + u.to_string() +
                                            " has no module-path");
            }
            _state->_source = [path = *u.module_path] { return module::load(path); };
        }
    }

    /// The key's public half, as the token reports it.
    [[nodiscard]] auto public_key() const -> public_key_info {
        return with_session([](session& s, CK_OBJECT_HANDLE k) { return s.public_key(k); });
    }

    /// Signs a SHA-256 or SHA-384 digest: ECDSA (r || s) for an EC key,
    /// PKCS#1 v1.5 for RSA.
    [[nodiscard]] auto sign_digest(std::span<const std::uint8_t> digest) const -> bytes {
        hash_algorithm hash = hash_algorithm::sha256;
        if (digest.size() == digest_length(hash_algorithm::sha384)) {
            hash = hash_algorithm::sha384;
        } else if (digest.size() != digest_length(hash_algorithm::sha256)) {
            throw error("signing_key: the digest is neither SHA-256 nor SHA-384",
                        CKR_DATA_LEN_RANGE);
        }
        return with_session([&](session& s, CK_OBJECT_HANDLE k) {
            const auto scheme =
                _state->_key_type == CKK_EC ? signature_scheme::ecdsa : signature_scheme::rsa_pkcs1;
            return s.sign_digest(k, scheme, hash, digest);
        });
    }

    /// `sign_digest` with ECDSA in X.509's DER form.
    [[nodiscard]] auto x509_signature(std::span<const std::uint8_t> digest) const -> bytes {
        const auto sig = sign_digest(digest);
        const std::scoped_lock lock(_state->_mutex);
        return _state->_key_type == CKK_EC ? ecdsa_der(sig) : sig;
    }

    /// The key as a certificate authority's signer.
    [[nodiscard]] auto as_ca_key() const -> raft::testing::external_ca_key {
        return {[self = *this](std::span<const std::uint8_t> digest) {
            return self.x509_signature(digest);
        }};
    }

    /// The URI without its PIN, for logs.
    [[nodiscard]] auto name() const -> std::string { return _state->_uri.to_string(); }

private:
    struct state {
        state(uri u, module_source s) : _uri(std::move(u)), _source(std::move(s)) {}
        uri _uri;
        module_source _source;
        std::mutex _mutex;
        std::optional<module> _module;
        std::optional<session> _session;
        CK_OBJECT_HANDLE _key = CK_INVALID_HANDLE;
        CK_KEY_TYPE _key_type = CKK_RSA;
    };

    [[nodiscard]] static auto key_type(session& s, CK_OBJECT_HANDLE k) -> CK_KEY_TYPE {
        const auto t = s.public_key(k).key_type;
        if (t != CKK_EC && t != CKK_RSA) {
            throw error("signing_key: the key is neither EC nor RSA", CKR_KEY_TYPE_INCONSISTENT);
        }
        return t;
    }

    template<class Use>
    [[nodiscard]] auto with_session(Use use) const
        -> std::invoke_result_t<Use, session&, CK_OBJECT_HANDLE> {
        auto& st = *_state;
        const std::scoped_lock lock(st._mutex);
        for (int attempt = 0;; ++attempt) {
            try {
                if (!st._module) {
                    st._module.emplace(st._source());
                }
                if (!st._session) {
                    st._session.emplace(st._module->open(st._uri));
                    st._key = st._session->find(st._uri);
                    st._key_type = key_type(*st._session, st._key);
                }
                return use(*st._session, st._key);
            } catch (const error& e) {
                if (attempt == 0 && session_lost(e.rv())) {
                    st._session.reset();
                    continue;
                }
                throw;
            }
        }
    }

    std::shared_ptr<state> _state;
};

}  // namespace kythira::pkcs11
