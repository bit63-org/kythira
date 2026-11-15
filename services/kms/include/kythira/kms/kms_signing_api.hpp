// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Signing, MACs and public keys (.kiro/specs/kms-compatible-api/ task 8,
// Requirements 3.2, 5.1, 5.4 and 5.5): Sign, Verify, GetPublicKey,
// GenerateMac and VerifyMac.
//
// The token signs and computes MACs; the private and HMAC keys never leave
// it. The message is hashed here for MessageType RAW (a hash is not
// secret), so the token always signs a digest: CKM_RSA_PKCS over the
// DigestInfo, CKM_RSA_PKCS_PSS with a salt the digest's length (as AWS),
// or CKM_ECDSA, whose r || s this side encodes as the DER AWS returns.
// Verify checks against the key's public key here with OpenSSL, as any
// holder of GetPublicKey's answer can. VerifyMac recomputes the MAC on the
// token and compares in constant time.
//
// Like the other cryptographic operations these write nothing and run on
// any replica after a read-index check.

#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_crypto_api.hpp>
#include <kythira/kms/kms_errors.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_public_key.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>

#include <boost/json.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

/// A signing algorithm AWS names, and how the token makes it.
struct signing_algorithm {
    std::string_view name;
    sig_scheme scheme;
    hash_alg hash;
};

inline constexpr std::array<signing_algorithm, 9> k_signing_algorithms{{
    {"RSASSA_PSS_SHA_256", sig_scheme::pss, hash_alg::sha256},
    {"RSASSA_PSS_SHA_384", sig_scheme::pss, hash_alg::sha384},
    {"RSASSA_PSS_SHA_512", sig_scheme::pss, hash_alg::sha512},
    {"RSASSA_PKCS1_V1_5_SHA_256", sig_scheme::pkcs1, hash_alg::sha256},
    {"RSASSA_PKCS1_V1_5_SHA_384", sig_scheme::pkcs1, hash_alg::sha384},
    {"RSASSA_PKCS1_V1_5_SHA_512", sig_scheme::pkcs1, hash_alg::sha512},
    {"ECDSA_SHA_256", sig_scheme::ecdsa, hash_alg::sha256},
    {"ECDSA_SHA_384", sig_scheme::ecdsa, hash_alg::sha384},
    {"ECDSA_SHA_512", sig_scheme::ecdsa, hash_alg::sha512},
}};

/// The PKCS#11 HMAC mechanism for an AWS MAC algorithm, or 0.
[[nodiscard]] constexpr auto hmac_mechanism(std::string_view alg) -> CK_MECHANISM_TYPE {
    if (alg == "HMAC_SHA_224") {
        return CKM_SHA224_HMAC;
    }
    if (alg == "HMAC_SHA_256") {
        return CKM_SHA256_HMAC;
    }
    if (alg == "HMAC_SHA_384") {
        return CKM_SHA384_HMAC;
    }
    if (alg == "HMAC_SHA_512") {
        return CKM_SHA512_HMAC;
    }
    return 0;
}

template<typename Catalog> class signing_api : protected crypto_common {
public:
    using result = aws_json::result<boost::json::object>;

    explicit signing_api(crypto_deps<Catalog> deps) : _d(std::move(deps)) {}

    static constexpr std::array<std::string_view, 5> k_operations{"GenerateMac", "GetPublicKey",
                                                                  "Sign", "Verify", "VerifyMac"};

    template<typename FrontEnd> void register_on(FrontEnd& fe) {
        const auto bind = [this](auto method) {
            return [this, method](call_context& ctx, boost::json::object& in) -> result {
                return (this->*method)(ctx, in);
            };
        };
        fe.on("Sign", bind(&signing_api::sign));
        fe.on("Verify", bind(&signing_api::verify));
        fe.on("GetPublicKey", bind(&signing_api::get_public_key));
        fe.on("GenerateMac", bind(&signing_api::generate_mac));
        fe.on("VerifyMac", bind(&signing_api::verify_mac));
    }

    auto sign(call_context& ctx, boost::json::object& in) -> result {
        auto prepared = prepare_signature(ctx, in, "Sign");
        if (!prepared) {
            return prepared.error();
        }
        auto& p = *prepared;
        auto s = store();
        if (!s) {
            return s.error();
        }
        try {
            std::vector<std::uint8_t> signature;
            const auto& k = p.key;
            switch (p.alg.scheme) {
                case sig_scheme::pkcs1: {
                    auto info = digest_info_prefix(p.alg.hash);
                    info.insert(info.end(), p.digest.begin(), p.digest.end());
                    const CK_MECHANISM m{CKM_RSA_PKCS, nullptr, 0};
                    signature = (*s)->sign(k.key_id, k.current_version, CKO_PRIVATE_KEY, m, info);
                    break;
                }
                case sig_scheme::pss: {
                    CK_RSA_PKCS_PSS_PARAMS params{pss_hash(p.alg.hash), pss_mgf(p.alg.hash),
                                                  static_cast<CK_ULONG>(hash_size(p.alg.hash))};
                    const CK_MECHANISM m{CKM_RSA_PKCS_PSS, &params, sizeof params};
                    signature =
                        (*s)->sign(k.key_id, k.current_version, CKO_PRIVATE_KEY, m, p.digest);
                    break;
                }
                case sig_scheme::ecdsa: {
                    const CK_MECHANISM m{CKM_ECDSA, nullptr, 0};
                    signature = ecdsa_der(
                        (*s)->sign(k.key_id, k.current_version, CKO_PRIVATE_KEY, m, p.digest));
                    break;
                }
            }
            return boost::json::object{
                {"KeyId", ctx.key_arn(k.account, k.key_id)},
                {"Signature", aws_json::base64_encode(std::as_bytes(std::span(signature)))},
                {"SigningAlgorithm", p.alg.name}};
        } catch (const backing_error& e) {
            return hsm_error(e);
        } catch (const std::runtime_error&) {
            return internal_error();
        }
    }

    auto verify(call_context& ctx, boost::json::object& in) -> result {
        const auto signature = blob(in, "Signature");
        if (!signature) {
            return validation_error("Signature is required");
        }
        auto prepared = prepare_signature(ctx, in, "Verify");
        if (!prepared) {
            return prepared.error();
        }
        auto& p = *prepared;
        auto s = store();
        if (!s) {
            return s.error();
        }
        try {
            const auto spki = (*s)->public_key(p.key.key_id, p.key.current_version);
            if (!verify_digest(spki, p.alg.scheme, p.alg.hash, p.digest, *signature)) {
                return kms_error("KMSInvalidSignatureException",
                                 "The signature does not verify with this key and algorithm.");
            }
        } catch (const backing_error& e) {
            return hsm_error(e);
        }
        return boost::json::object{{"KeyId", ctx.key_arn(p.key.account, p.key.key_id)},
                                   {"SignatureValid", true},
                                   {"SigningAlgorithm", p.alg.name}};
    }

    auto get_public_key(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        if (auto denied = authorize_key(ctx, **c, *k, "GetPublicKey")) {
            return *denied;
        }
        const auto& key = k->record;
        if (auto bad = check_state(ctx, key)) {
            return *bad;
        }
        if (is_symmetric(key.spec) || key.usage == key_usage::generate_verify_mac) {
            return unsupported(ctx.key_arn(key.account, key.key_id) +
                               " is not an asymmetric key and has no public key");
        }
        auto s = store();
        if (!s) {
            return s.error();
        }
        der_bytes spki;
        try {
            spki = (*s)->public_key(key.key_id, key.current_version);
        } catch (const backing_error& e) {
            return hsm_error(e);
        }
        const auto* info = find_key_spec(key.spec);
        const std::string spec(info != nullptr ? info->name : "");
        boost::json::object out{
            {"KeyId", ctx.key_arn(key.account, key.key_id)},
            {"PublicKey", aws_json::base64_encode(std::as_bytes(std::span(spki)))},
            {"CustomerMasterKeySpec", spec},
            {"KeySpec", spec},
            {"KeyUsage", usage_name(key.usage)}};
        const auto algs = algorithms_of(key.spec, key.usage);
        const auto list = [](const std::vector<std::string_view>& v) {
            boost::json::array a;
            for (const auto s : v) {
                a.emplace_back(s);
            }
            return a;
        };
        if (!algs.encryption.empty()) {
            out["EncryptionAlgorithms"] = list(algs.encryption);
        }
        if (!algs.signing.empty()) {
            out["SigningAlgorithms"] = list(algs.signing);
        }
        return out;
    }

    auto generate_mac(call_context& ctx, boost::json::object& in) -> result {
        auto computed = compute_mac(ctx, in, "GenerateMac");
        if (!computed) {
            return computed.error();
        }
        return boost::json::object{
            {"Mac", aws_json::base64_encode(std::as_bytes(std::span(computed->mac)))},
            {"MacAlgorithm", computed->algorithm},
            {"KeyId", computed->key_arn}};
    }

    auto verify_mac(call_context& ctx, boost::json::object& in) -> result {
        const auto given = blob(in, "Mac");
        if (!given) {
            return validation_error("Mac is required");
        }
        auto computed = compute_mac(ctx, in, "VerifyMac");
        if (!computed) {
            return computed.error();
        }
        if (given->size() != computed->mac.size() ||
            CRYPTO_memcmp(given->data(), computed->mac.data(), given->size()) != 0) {
            return kms_error("KMSInvalidMacException",
                             "The MAC does not verify with this key and algorithm.");
        }
        return boost::json::object{{"KeyId", computed->key_arn},
                                   {"MacValid", true},
                                   {"MacAlgorithm", computed->algorithm}};
    }

private:
    /// A signing request checked and authorized: the key, the algorithm
    /// and the digest to sign or verify.
    struct prepared_signature {
        key_record key;
        signing_algorithm alg;
        der_bytes digest;
    };

    struct computed_mac {
        std::string key_arn;
        std::string algorithm;
        std::vector<std::uint8_t> mac;
    };

    [[nodiscard]] static auto pss_hash(hash_alg h) -> CK_MECHANISM_TYPE {
        return h == hash_alg::sha384 ? CKM_SHA384 : h == hash_alg::sha512 ? CKM_SHA512 : CKM_SHA256;
    }

    [[nodiscard]] static auto pss_mgf(hash_alg h) -> CK_RSA_PKCS_MGF_TYPE {
        return h == hash_alg::sha384   ? CKG_MGF1_SHA384
               : h == hash_alg::sha512 ? CKG_MGF1_SHA512
                                       : CKG_MGF1_SHA256;
    }

    [[nodiscard]] auto prepare_signature(call_context& ctx, const boost::json::object& in,
                                         std::string_view action) const
        -> aws_json::result<prepared_signature> {
        auto message = blob(in, "Message");
        if (!message) {
            return validation_error("Message is required");
        }
        const auto type = str(in, "MessageType").value_or("RAW");
        const auto alg_name = str(in, "SigningAlgorithm").value_or("");
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        auto r = key_request(ctx, **c, *k, action);
        r.keys.emplace_back("kms:SigningAlgorithm",
                            std::vector<std::string>{std::string(alg_name)});
        r.keys.emplace_back("kms:MessageType", std::vector<std::string>{std::string(type)});
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        const auto& key = k->record;
        if (auto bad = check_state(ctx, key)) {
            return *bad;
        }
        const auto arn = ctx.key_arn(key.account, key.key_id);
        if (key.usage != key_usage::sign_verify) {
            return kms_error("InvalidKeyUsageException",
                             "KeyUsage for " + arn + " is not SIGN_VERIFY.");
        }
        const auto allowed = algorithms_of(key.spec, key.usage).signing;
        const auto* alg = std::find_if(k_signing_algorithms.begin(), k_signing_algorithms.end(),
                                       [&](const auto& a) { return a.name == alg_name; });
        if (alg == k_signing_algorithms.end() ||
            std::find(allowed.begin(), allowed.end(), alg_name) == allowed.end()) {
            return kms_error("InvalidKeyUsageException",
                             "The signing algorithm " + std::string(alg_name) +
                                 " is not compatible with " + arn + ".");
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        prepared_signature p{key, *alg, {}};
        if (type == "DIGEST") {
            if (message->size() != hash_size(alg->hash)) {
                return validation_error("A DIGEST message must be the digest's length, " +
                                        std::to_string(hash_size(alg->hash)) + " bytes");
            }
            p.digest = std::move(*message);
        } else {
            p.digest = digest(alg->hash, *message);
        }
        return p;
    }

    [[nodiscard]] auto compute_mac(call_context& ctx, const boost::json::object& in,
                                   std::string_view action) const
        -> aws_json::result<computed_mac> {
        const auto message = blob(in, "Message");
        if (!message) {
            return validation_error("Message is required");
        }
        const auto alg_name = str(in, "MacAlgorithm").value_or("");
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        auto r = key_request(ctx, **c, *k, action);
        r.keys.emplace_back("kms:MacAlgorithm", std::vector<std::string>{std::string(alg_name)});
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        const auto& key = k->record;
        if (auto bad = check_state(ctx, key)) {
            return *bad;
        }
        const auto arn = ctx.key_arn(key.account, key.key_id);
        if (key.usage != key_usage::generate_verify_mac) {
            return kms_error("InvalidKeyUsageException",
                             "KeyUsage for " + arn + " is not GENERATE_VERIFY_MAC.");
        }
        const auto allowed = algorithms_of(key.spec, key.usage).mac;
        if (std::find(allowed.begin(), allowed.end(), alg_name) == allowed.end()) {
            return kms_error("InvalidKeyUsageException",
                             "The MAC algorithm " + std::string(alg_name) +
                                 " is not compatible with " + arn + ".");
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        auto s = store();
        if (!s) {
            return s.error();
        }
        const CK_MECHANISM m{hmac_mechanism(alg_name), nullptr, 0};
        try {
            return computed_mac{
                arn, std::string(alg_name),
                (*s)->sign(key.key_id, key.current_version, CKO_SECRET_KEY, m, *message)};
        } catch (const backing_error& e) {
            return hsm_error(e);
        }
    }

    [[nodiscard]] auto store() const -> aws_json::result<std::shared_ptr<backing_store>> {
        auto s = _d.hsm();
        if (!s) {
            return internal_error("The HSM is sealed or unreachable");
        }
        return s;
    }

    /// The catalog after a read barrier.
    [[nodiscard]] auto catalog() const -> aws_json::result<std::shared_ptr<const Catalog>> {
        if (!_d.barrier()) {
            return dependency_timeout();
        }
        auto c = _d.catalog();
        if (!c) {
            return internal_error("The KMS catalog has not opened yet");
        }
        return c;
    }

    crypto_deps<Catalog> _d;
};

}  // namespace kythira::kms
