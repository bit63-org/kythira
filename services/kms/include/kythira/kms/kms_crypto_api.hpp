// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The symmetric cryptographic operations (.kiro/specs/kms-compatible-api/
// task 7, Requirements 5.1-5.3 and 5.6): Encrypt, Decrypt, ReEncrypt,
// GenerateDataKey, GenerateDataKeyWithoutPlaintext and GenerateRandom.
//
// None of them writes to the catalog. Each passes a read barrier (a
// read-index check, which any replica can make) and then reads the key's
// metadata and calls the HSM, so throughput grows with the number of
// replicas (5.6). The AES-GCM key never leaves the token: the HSM encrypts
// with the additional data this side builds (kms_ciphertext.hpp), which
// binds the key ARN, the backing version and the encryption context (5.2).
// The blob names its key, so Decrypt needs no KeyId; given one that names
// another key, it answers IncorrectKeyException (5.3).
//
// A blob that does not decode, names a key this KMS does not have, names a
// backing version the key does not have, or fails its tag answers
// InvalidCiphertextException alike, so a caller learns nothing about which
// check failed or whether the key exists.
//
// Asymmetric keys join in task 8 and grants in task 10; until then an
// asymmetric key answers UnsupportedOperationException and GrantTokens are
// accepted and not used.
//
// Decrypt's Recipient takes a Kythira extension besides AWS's Nitro form
// (.kiro/specs/ec2-compatible-api/ Requirement 10.2-10.3): with
// KeyEncryptionAlgorithm KYTHIRA_HPKE_X25519_SHA256_AES256GCM, an X25519
// KythiraPublicKey, KythiraAssociatedData and KythiraInfo, the plaintext
// is sealed with HPKE (kms_hpke.hpp) to that key and returned as
// CiphertextForRecipient (the 32-byte encapsulation, then the ciphertext
// and tag), never as Plaintext. The caller, the EC2 controller, never
// holds the data key; only the attaching helm can open it. It is
// authorized as Decrypt with the usual condition keys plus
// kms:KythiraRecipientPublicKeySha256, the lower-case hex SHA-256 of the
// public key, so a key policy can name the enrolled transport keys it
// will seal to. AWS's Nitro form still answers
// UnsupportedOperationException.

#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_ciphertext.hpp>
#include <kythira/kms/kms_errors.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_hpke.hpp>
#include <kythira/kms/kms_public_key.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>

#include <boost/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

/// What the cryptographic operations need from the module.
template<typename Catalog> struct crypto_deps {
    /// This replica of the catalog, or null before it opens.
    std::function<std::shared_ptr<const Catalog>()> catalog;
    /// A read-index check; false when no leader answered in time.
    std::function<bool()> barrier;
    /// The token's backing store, or null while none is bound (the HSM is
    /// sealed, unreachable, or the token is missing).
    std::function<std::shared_ptr<backing_store>()> hsm;
    /// Makes an AWS managed key on first use (ensure_managed_key); empty:
    /// none is made.
    std::function<key_result(std::string_view, const managed_service&)> ensure_managed;
    /// Makes a consuming service's owned key on first use
    /// (ensure_owned_key); empty: none is made.
    std::function<key_result(std::string_view, const managed_service&)> ensure_owned = {};
};

/// Plaintext bytes that are wiped when they go.
class plaintext {
public:
    plaintext() = default;
    explicit plaintext(std::vector<std::uint8_t> b) : _b(std::move(b)) {}
    plaintext(const plaintext&) = delete;
    auto operator=(const plaintext&) -> plaintext& = delete;
    plaintext(plaintext&& o) noexcept : _b(std::move(o._b)) { o._b.clear(); }
    auto operator=(plaintext&& o) noexcept -> plaintext& {
        if (this != &o) {
            wipe();
            _b = std::move(o._b);
            o._b.clear();
        }
        return *this;
    }
    ~plaintext() { wipe(); }

    [[nodiscard]] auto bytes() const -> std::span<const std::uint8_t> { return _b; }
    [[nodiscard]] auto base64() const -> std::string {
        return aws_json::base64_encode(std::as_bytes(std::span(_b)));
    }

private:
    void wipe() {
        if (!_b.empty()) {
            OPENSSL_cleanse(_b.data(), _b.size());
        }
    }

    std::vector<std::uint8_t> _b;
};

/// What the cryptographic operations share: reading blobs and contexts,
/// DryRun, key state, and HSM failures.
class crypto_common : protected api_common {
protected:
    /// A blob member's bytes (the model has checked the base64).
    [[nodiscard]] static auto blob(const boost::json::object& in, std::string_view member)
        -> std::optional<std::vector<std::uint8_t>> {
        const auto s = str(in, member);
        if (!s) {
            return std::nullopt;
        }
        auto raw = aws_json::base64_decode(*s);
        if (!raw) {
            return std::nullopt;
        }
        std::vector<std::uint8_t> out(raw->size());
        for (std::size_t i = 0; i < raw->size(); ++i) {
            out[i] = std::to_integer<std::uint8_t>((*raw)[i]);
        }
        OPENSSL_cleanse(raw->data(), raw->size());
        return out;
    }

    [[nodiscard]] static auto read_context(const boost::json::object& in, std::string_view member)
        -> encryption_context {
        encryption_context out;
        if (const auto* m = in.if_contains(member); m != nullptr && m->is_object()) {
            for (const auto& [k, v] : m->get_object()) {
                if (v.is_string()) {
                    out.emplace(std::string(k), std::string(v.get_string()));
                }
            }
        }
        return out;
    }

    /// DryRunOperationException once everything else has passed.
    [[nodiscard]] static auto dry_run(const boost::json::object& in)
        -> std::optional<aws_json::error> {
        if (const auto* d = in.if_contains("DryRun");
            d != nullptr && d->is_bool() && d->get_bool()) {
            return kms_error("DryRunOperationException",
                             "The request would have succeeded, but the DryRun option is set.",
                             412);
        }
        return std::nullopt;
    }

    /// The key's state allows cryptographic use.
    [[nodiscard]] static auto check_state(const call_context& ctx, const key_record& k)
        -> std::optional<aws_json::error> {
        const auto arn = ctx.key_arn(k.account, k.key_id);
        switch (k.state) {
            case key_state::enabled:
                break;
            case key_state::disabled:
                return kms_error("DisabledException", arn + " is disabled.");
            case key_state::pending_deletion:
                return invalid_state(arn + " is pending deletion.");
            case key_state::creating:
                return invalid_state(arn + " is pending creation.");
        }
        if (k.current_version == 0) {
            return invalid_state(arn + " is pending creation.");
        }
        return std::nullopt;
    }

    /// The error for a backing store failure.
    [[nodiscard]] static auto hsm_error(const backing_error& e) -> aws_json::error {
        switch (e.which()) {
            case backing_error::kind::unavailable:
                return internal_error("The HSM is sealed or unreachable");
            case backing_error::kind::unsupported:
                return unsupported("The HSM does not support this operation");
            case backing_error::kind::failed:
                break;
        }
        return internal_error();
    }
};

/// Decrypt's Kythira recipient: where the plaintext is sealed instead
/// of returned.
struct hpke_recipient {
    hpke::public_key key{};
    std::vector<std::byte> aad;
    std::vector<std::byte> info;
};

/// The value of kms:KythiraRecipientPublicKeySha256 for `key`.
[[nodiscard]] inline auto recipient_key_sha256(std::span<const std::byte> key) -> std::string {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int len = 0;
    EVP_Digest(key.data(), key.size(), digest.data(), &len, EVP_sha256(), nullptr);
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(hex[digest[i] >> 4U]);
        out.push_back(hex[digest[i] & 0xFU]);
    }
    return out;
}

template<typename Catalog> class crypto_api : protected crypto_common {
public:
    using result = aws_json::result<boost::json::object>;

    explicit crypto_api(crypto_deps<Catalog> deps) : _d(std::move(deps)) {}

    static constexpr std::array<std::string_view, 8> k_operations{
        "Decrypt",
        "Encrypt",
        "GenerateDataKey",
        "GenerateDataKeyPair",
        "GenerateDataKeyPairWithoutPlaintext",
        "GenerateDataKeyWithoutPlaintext",
        "GenerateRandom",
        "ReEncrypt"};

    template<typename FrontEnd> void register_on(FrontEnd& fe) {
        const auto bind = [this](auto method) {
            return [this, method](call_context& ctx, boost::json::object& in) -> result {
                return (this->*method)(ctx, in);
            };
        };
        fe.on("Encrypt", bind(&crypto_api::encrypt));
        fe.on("Decrypt", bind(&crypto_api::decrypt));
        fe.on("ReEncrypt", bind(&crypto_api::re_encrypt));
        fe.on("GenerateDataKey", bind(&crypto_api::generate_data_key));
        fe.on("GenerateDataKeyWithoutPlaintext",
              bind(&crypto_api::generate_data_key_without_plaintext));
        fe.on("GenerateDataKeyPair", bind(&crypto_api::generate_data_key_pair));
        fe.on("GenerateDataKeyPairWithoutPlaintext",
              bind(&crypto_api::generate_data_key_pair_without_plaintext));
        fe.on("GenerateRandom", bind(&crypto_api::generate_random));
    }

    auto encrypt(call_context& ctx, boost::json::object& in) -> result {
        auto plain = blob(in, "Plaintext");
        if (!plain) {
            return validation_error("Plaintext is required");
        }
        const plaintext p(std::move(*plain));
        auto c = catalog_for(ctx, in, "KeyId");
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        const auto context = read_context(in, "EncryptionContext");
        const auto requested = str(in, "EncryptionAlgorithm");
        if (auto denied = authorize_use(ctx, **c, *k, "Encrypt", context, requested)) {
            return *denied;
        }
        auto alg = choose_encryption(ctx, k->record, requested, context);
        if (!alg) {
            return alg.error();
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        auto sealed = seal(ctx, k->record, *alg, p.bytes(), context);
        if (!sealed) {
            return sealed.error();
        }
        return boost::json::object{{"CiphertextBlob", std::move(*sealed)},
                                   {"KeyId", ctx.key_arn(k->record.account, k->record.key_id)},
                                   {"EncryptionAlgorithm", alg->name}};
    }

    static constexpr std::string_view k_hpke_recipient = "KYTHIRA_HPKE_X25519_SHA256_AES256GCM";
    static constexpr std::string_view k_recipient_key_condition =
        "kms:KythiraRecipientPublicKeySha256";

    auto decrypt(call_context& ctx, boost::json::object& in) -> result {
        std::optional<hpke_recipient> recipient;
        condition_keys extra;
        if (const auto* r = in.if_contains("Recipient")) {
            auto read = read_recipient(*r);
            if (!read) {
                return read.error();
            }
            extra.emplace_back(std::string(k_recipient_key_condition),
                               std::vector<std::string>{recipient_key_sha256(read->key)});
            recipient = std::move(*read);
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto opened = open(ctx, **c, in, "CiphertextBlob", "KeyId", "EncryptionContext",
                           "EncryptionAlgorithm", "Decrypt", &extra);
        if (!opened) {
            return opened.error();
        }
        if (recipient) {
            return seal_for_recipient(ctx, *opened, *recipient);
        }
        boost::json::object out{{"KeyId", ctx.key_arn(opened->key.account, opened->key.key_id)},
                                {"Plaintext", opened->plain.base64()},
                                {"EncryptionAlgorithm", opened->algorithm}};
        if (opened->version) {
            out["KeyMaterialId"] = key_material_id(opened->key.key_id, *opened->version);
        }
        return out;
    }

    auto re_encrypt(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog_for(ctx, in, "DestinationKeyId");
        if (!c) {
            return c.error();
        }
        // The destination first: a caller who may not use it learns
        // nothing about the source ciphertext.
        auto dest = resolve(ctx, **c, in, "DestinationKeyId", true);
        if (!dest) {
            return dest.error();
        }
        const auto dest_context = read_context(in, "DestinationEncryptionContext");
        const auto requested = str(in, "DestinationEncryptionAlgorithm");
        if (auto denied = authorize_use(ctx, **c, *dest, "ReEncryptTo", dest_context, requested)) {
            return *denied;
        }
        auto alg = choose_encryption(ctx, dest->record, requested, dest_context);
        if (!alg) {
            return alg.error();
        }
        auto opened = open(ctx, **c, in, "CiphertextBlob", "SourceKeyId", "SourceEncryptionContext",
                           "SourceEncryptionAlgorithm", "ReEncryptFrom");
        if (!opened) {
            return opened.error();
        }
        auto sealed = seal(ctx, dest->record, *alg, opened->plain.bytes(), dest_context);
        if (!sealed) {
            return sealed.error();
        }
        boost::json::object out{
            {"CiphertextBlob", std::move(*sealed)},
            {"SourceKeyId", ctx.key_arn(opened->key.account, opened->key.key_id)},
            {"KeyId", ctx.key_arn(dest->record.account, dest->record.key_id)},
            {"SourceEncryptionAlgorithm", opened->algorithm},
            {"DestinationEncryptionAlgorithm", alg->name}};
        if (opened->version) {
            out["SourceKeyMaterialId"] = key_material_id(opened->key.key_id, *opened->version);
        }
        if (alg->symmetric) {
            out["DestinationKeyMaterialId"] =
                key_material_id(dest->record.key_id, dest->record.current_version);
        }
        return out;
    }

    auto generate_data_key(call_context& ctx, boost::json::object& in) -> result {
        if (in.contains("Recipient")) {
            return unsupported("Recipient (Nitro Enclaves attestation) is not supported");
        }
        return data_key(ctx, in, "GenerateDataKey", true);
    }

    auto generate_data_key_without_plaintext(call_context& ctx, boost::json::object& in) -> result {
        return data_key(ctx, in, "GenerateDataKeyWithoutPlaintext", false);
    }

    auto generate_data_key_pair(call_context& ctx, boost::json::object& in) -> result {
        if (in.contains("Recipient")) {
            return unsupported("Recipient (Nitro Enclaves attestation) is not supported");
        }
        return make_data_key_pair(ctx, in, "GenerateDataKeyPair", true);
    }

    auto generate_data_key_pair_without_plaintext(call_context& ctx, boost::json::object& in)
        -> result {
        return make_data_key_pair(ctx, in, "GenerateDataKeyPairWithoutPlaintext", false);
    }

    auto generate_random(call_context& ctx, boost::json::object& in) -> result {
        if (in.contains("CustomKeyStoreId")) {
            return unsupported("Custom key stores are not supported");
        }
        if (in.contains("Recipient")) {
            return unsupported("Recipient (Nitro Enclaves attestation) is not supported");
        }
        const auto* n = in.if_contains("NumberOfBytes");
        if (n == nullptr || !n->is_int64()) {
            return validation_error("NumberOfBytes is required");
        }
        aws_auth::authz_request r;
        r.action = "kms:GenerateRandom";
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        auto bytes = random(static_cast<std::size_t>(n->get_int64()));
        if (!bytes) {
            return bytes.error();
        }
        return boost::json::object{{"Plaintext", bytes->base64()}};
    }

private:
    static constexpr std::string_view k_symmetric = "SYMMETRIC_DEFAULT";

    /// The encryption algorithm a request uses: AES-GCM on the token, or
    /// RSA-OAEP with `oaep` as its hash.
    struct algorithm_choice {
        std::string_view name;
        bool symmetric = true;
        hash_alg oaep = hash_alg::sha256;
    };

    /// A decrypted ciphertext, the key that made it and how.
    struct opened_blob {
        key_record key;
        plaintext plain;
        std::string_view algorithm;
        std::optional<std::uint32_t> version;  ///< the backing version, symmetric only
    };

    using condition_keys = std::vector<std::pair<std::string, std::vector<std::string>>>;

    /// A blob member of the Recipient structure (the model has checked
    /// its base64 and length).
    [[nodiscard]] static auto recipient_bytes(const boost::json::object& r, std::string_view member)
        -> std::optional<std::vector<std::byte>> {
        auto raw = blob(r, member);
        if (!raw) {
            return std::nullopt;
        }
        std::vector<std::byte> out(raw->size());
        std::ranges::transform(*raw, out.begin(), [](std::uint8_t b) { return std::byte{b}; });
        return out;
    }

    /// The Recipient member: the Kythira HPKE form, or an answer. AWS's
    /// Nitro form (RSAES_OAEP_SHA_256 or an AttestationDocument) is not
    /// supported; Kythira members are refused with it, and every Kythira
    /// member is required with the Kythira algorithm.
    [[nodiscard]] static auto read_recipient(const boost::json::value& v)
        -> aws_json::result<hpke_recipient> {
        if (!v.is_object()) {
            return validation_error("Recipient must be a structure");
        }
        const auto& r = v.get_object();
        const auto alg = str(r, "KeyEncryptionAlgorithm");
        if (!alg || *alg != k_hpke_recipient) {
            if (r.contains("KythiraPublicKey") || r.contains("KythiraAssociatedData") ||
                r.contains("KythiraInfo")) {
                return validation_error(
                    "KythiraPublicKey, KythiraAssociatedData and KythiraInfo require "
                    "KeyEncryptionAlgorithm " +
                    std::string(k_hpke_recipient));
            }
            return unsupported("Recipient (Nitro Enclaves attestation) is not supported");
        }
        if (r.contains("AttestationDocument")) {
            return validation_error("AttestationDocument is not used with KeyEncryptionAlgorithm " +
                                    std::string(k_hpke_recipient));
        }
        auto key = recipient_bytes(r, "KythiraPublicKey");
        auto aad = recipient_bytes(r, "KythiraAssociatedData");
        auto info = recipient_bytes(r, "KythiraInfo");
        if (!key || !aad || !info) {
            return validation_error(
                "KythiraPublicKey, KythiraAssociatedData and KythiraInfo are required with "
                "KeyEncryptionAlgorithm " +
                std::string(k_hpke_recipient));
        }
        if (key->size() != hpke::public_key_size) {
            return validation_error("KythiraPublicKey must be a 32-byte X25519 public key");
        }
        hpke_recipient out;
        std::ranges::copy(*key, out.key.begin());
        out.aad = std::move(*aad);
        out.info = std::move(*info);
        return out;
    }

    /// Decrypt's answer for a Kythira recipient: the plaintext sealed to
    /// it, and no Plaintext or KeyMaterialId (AWS leaves KeyMaterialId out
    /// with a Recipient too).
    [[nodiscard]] static auto seal_for_recipient(const call_context& ctx, const opened_blob& opened,
                                                 const hpke_recipient& r) -> result {
        const auto plain = std::as_bytes(opened.plain.bytes());
        auto sealed = hpke::seal(r.key, r.info, r.aad, plain);
        if (!sealed) {
            if (sealed.error() == hpke::error::bad_public_key) {
                return validation_error("KythiraPublicKey is not a valid X25519 public key");
            }
            return internal_error();
        }
        std::vector<std::byte> out;
        out.reserve(sealed->enc.size() + sealed->ciphertext.size());
        out.insert(out.end(), sealed->enc.begin(), sealed->enc.end());
        out.insert(out.end(), sealed->ciphertext.begin(), sealed->ciphertext.end());
        return boost::json::object{{"KeyId", ctx.key_arn(opened.key.account, opened.key.key_id)},
                                   {"CiphertextForRecipient", aws_json::base64_encode(out)},
                                   {"EncryptionAlgorithm", opened.algorithm}};
    }

    /// `action` on the key, with the encryption context and algorithm as
    /// condition keys (the algorithm the request names, or
    /// SYMMETRIC_DEFAULT on a symmetric key that names none).
    [[nodiscard]] static auto authorize_use(call_context& ctx, const Catalog& c, const resolved& k,
                                            std::string_view action,
                                            const encryption_context& context,
                                            std::optional<std::string_view> algorithm,
                                            const condition_keys* extra = nullptr)
        -> std::optional<aws_json::error> {
        auto r = key_request(ctx, c, k, action);
        if (extra != nullptr) {
            r.keys.insert(r.keys.end(), extra->begin(), extra->end());
        }
        std::vector<std::string> keys;
        for (const auto& [ck, cv] : context) {
            r.keys.emplace_back("kms:EncryptionContext:" + ck, std::vector<std::string>{cv});
            keys.push_back(ck);
        }
        r.keys.emplace_back("kms:EncryptionContextKeys", std::move(keys));
        const auto alg = algorithm ? *algorithm : (is_symmetric(k.record.spec) ? k_symmetric : "");
        if (!alg.empty()) {
            r.keys.emplace_back("kms:EncryptionAlgorithm",
                                std::vector<std::string>{std::string(alg)});
        }
        return authorize_with_grants(ctx, c, k.record, std::move(r), &context);
    }

    /// The algorithm the key and request settle on: SYMMETRIC_DEFAULT on a
    /// symmetric key (the default), RSAES_OAEP_SHA_1 or RSAES_OAEP_SHA_256
    /// on an RSA key (required, as on AWS). An asymmetric key takes no
    /// encryption context.
    [[nodiscard]] static auto choose_encryption(const call_context& ctx, const key_record& k,
                                                std::optional<std::string_view> requested,
                                                const encryption_context& context)
        -> aws_json::result<algorithm_choice> {
        if (auto bad = check_state(ctx, k)) {
            return *bad;
        }
        const auto arn = ctx.key_arn(k.account, k.key_id);
        if (k.usage != key_usage::encrypt_decrypt) {
            return kms_error("InvalidKeyUsageException",
                             "KeyUsage for " + arn + " is not ENCRYPT_DECRYPT.");
        }
        const auto incompatible = [&](std::string_view alg) {
            return kms_error("InvalidKeyUsageException",
                             "The encryption algorithm " + std::string(alg) +
                                 " is not compatible with " + arn + ".");
        };
        if (is_symmetric(k.spec)) {
            if (requested && *requested != k_symmetric) {
                return incompatible(*requested);
            }
            return algorithm_choice{k_symmetric, true, hash_alg::sha256};
        }
        if (!requested) {
            return validation_error("EncryptionAlgorithm is required for the asymmetric key " +
                                    arn);
        }
        if (!context.empty()) {
            return validation_error("An asymmetric key takes no encryption context");
        }
        if (*requested == "RSAES_OAEP_SHA_1") {
            return algorithm_choice{"RSAES_OAEP_SHA_1", false, hash_alg::sha1};
        }
        if (*requested == "RSAES_OAEP_SHA_256") {
            return algorithm_choice{"RSAES_OAEP_SHA_256", false, hash_alg::sha256};
        }
        return incompatible(*requested);
    }

    [[nodiscard]] auto store() const -> aws_json::result<std::shared_ptr<backing_store>> {
        auto s = _d.hsm();
        if (!s) {
            return internal_error("The HSM is sealed or unreachable");
        }
        return s;
    }

    /// `n` random bytes from the token.
    [[nodiscard]] auto random(std::size_t n) const -> aws_json::result<plaintext> {
        auto s = store();
        if (!s) {
            return s.error();
        }
        try {
            return plaintext((*s)->random(n));
        } catch (const backing_error& e) {
            return hsm_error(e);
        }
    }

    [[nodiscard]] static auto oaep_params(hash_alg h) -> CK_RSA_PKCS_OAEP_PARAMS {
        const bool sha1 = h == hash_alg::sha1;
        return CK_RSA_PKCS_OAEP_PARAMS{sha1 ? CKM_SHA_1 : CKM_SHA256,
                                       sha1 ? CKG_MGF1_SHA1 : CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED,
                                       nullptr, 0};
    }

    /// `plain` encrypted under the key's current version, as base64: a
    /// ciphertext blob for a symmetric key, the bare RSA-OAEP ciphertext
    /// (as AWS returns it) for an RSA key.
    [[nodiscard]] auto seal(const call_context& ctx, const key_record& k,
                            const algorithm_choice& alg, std::span<const std::uint8_t> plain,
                            const encryption_context& context) const
        -> aws_json::result<std::string> {
        auto s = store();
        if (!s) {
            return s.error();
        }
        try {
            if (!alg.symmetric) {
                const auto spki = (*s)->public_key(k.key_id, k.current_version);
                const auto out = oaep_encrypt(spki, alg.oaep, plain);
                if (!out) {
                    return validation_error("The plaintext is too long for " +
                                            std::string(alg.name) + " with this key");
                }
                return aws_json::base64_encode(std::as_bytes(std::span(*out)));
            }
            const auto aad =
                ciphertext_aad(ctx.key_arn(k.account, k.key_id), k.current_version, context);
            auto sealed = (*s)->gcm_encrypt(k.key_id, k.current_version, plain, aad);
            ciphertext_blob b;
            b.key_id = k.key_id;
            b.backing_version = k.current_version;
            b.nonce = sealed.nonce;
            b.ciphertext = std::move(sealed.ciphertext);
            b.tag = sealed.tag;
            const auto bytes = encode_ciphertext(b);
            return aws_json::base64_encode(std::as_bytes(std::span(bytes)));
        } catch (const backing_error& e) {
            return hsm_error(e);
        }
    }

    [[nodiscard]] static auto invalid_ciphertext() -> aws_json::error {
        return kms_error("InvalidCiphertextException",
                         "The ciphertext refers to a customer master key that does not exist, "
                         "does not exist in this region, or you are not allowed to access, or "
                         "the ciphertext or its encryption context was changed.");
    }

    /// Decrypts the ciphertext in `blob_member`, authorizing `action` on
    /// its key. A symmetric blob names its key, and `key_member`, when
    /// present, must name the same one. An RSA ciphertext names nothing,
    /// so `key_member` must name its key, as on AWS.
    [[nodiscard]] auto open(call_context& ctx, const Catalog& c, const boost::json::object& in,
                            std::string_view blob_member, std::string_view key_member,
                            std::string_view context_member, std::string_view algorithm_member,
                            std::string_view action, const condition_keys* extra = nullptr) const
        -> aws_json::result<opened_blob> {
        const auto raw = blob(in, blob_member);
        if (!raw) {
            return validation_error(std::string(blob_member) + " is required");
        }
        std::optional<resolved> named;
        if (in.contains(key_member)) {
            auto k = resolve(ctx, c, in, key_member, true);
            if (!k) {
                return k.error();
            }
            named = std::move(*k);
        }
        const auto context = read_context(in, context_member);
        const auto requested = str(in, algorithm_member);
        // An RSA algorithm with a context is refused before the ciphertext
        // is looked at, whatever key made it (the differential recording).
        if (requested && requested->starts_with("RSAES_") && !context.empty()) {
            return validation_error(
                "EncryptionContext is not supported when encrypting/decrypting with "
                "asymmetric CMKs.");
        }
        if (named && !is_symmetric(named->record.spec)) {
            return open_rsa(ctx, c, in, *named, *raw, context, requested, action, extra);
        }
        const auto b = decode_ciphertext(*raw);
        if (!b) {
            return invalid_ciphertext();
        }
        const auto key = c.key(b->key_id);
        if (!key) {
            return invalid_ciphertext();
        }
        if (named && named->record.key_id != b->key_id) {
            return kms_error("IncorrectKeyException",
                             "The key ID in the request does not identify a CMK that can "
                             "perform this operation.");
        }
        const resolved k = named ? *named : resolved{*key, false, {}};
        if (auto denied = authorize_use(ctx, c, k, action, context, requested, extra)) {
            return *denied;
        }
        if (!c.version(b->key_id, b->backing_version)) {
            return invalid_ciphertext();
        }
        // An older backing version still decrypts what it made.
        auto usable = k.record;
        usable.current_version = b->backing_version;
        auto alg = choose_encryption(ctx, usable, requested, context);
        if (!alg) {
            return alg.error();
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        auto s = store();
        if (!s) {
            return s.error();
        }
        gcm_sealed sealed;
        sealed.nonce = b->nonce;
        sealed.ciphertext = b->ciphertext;
        sealed.tag = b->tag;
        const auto aad =
            ciphertext_aad(ctx.key_arn(key->account, key->key_id), b->backing_version, context);
        try {
            auto plain = (*s)->gcm_decrypt(b->key_id, b->backing_version, sealed, aad);
            if (!plain) {
                return invalid_ciphertext();
            }
            return opened_blob{*key, plaintext(std::move(*plain)), k_symmetric, b->backing_version};
        } catch (const backing_error& e) {
            return hsm_error(e);
        }
    }

    [[nodiscard]] auto open_rsa(call_context& ctx, const Catalog& c, const boost::json::object& in,
                                const resolved& k, std::span<const std::uint8_t> raw,
                                const encryption_context& context,
                                std::optional<std::string_view> requested, std::string_view action,
                                const condition_keys* extra = nullptr) const
        -> aws_json::result<opened_blob> {
        if (auto denied = authorize_use(ctx, c, k, action, context, requested, extra)) {
            return *denied;
        }
        auto alg = choose_encryption(ctx, k.record, requested, context);
        if (!alg) {
            return alg.error();
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        auto s = store();
        if (!s) {
            return s.error();
        }
        auto params = oaep_params(alg->oaep);
        const CK_MECHANISM m{CKM_RSA_PKCS_OAEP, &params, sizeof params};
        try {
            auto plain = (*s)->private_decrypt(k.record.key_id, k.record.current_version, m, raw);
            if (!plain) {
                return invalid_ciphertext();
            }
            return opened_blob{k.record, plaintext(std::move(*plain)), alg->name, std::nullopt};
        } catch (const backing_error& e) {
            return hsm_error(e);
        }
    }

    /// GenerateDataKey and GenerateDataKeyWithoutPlaintext.
    [[nodiscard]] auto data_key(call_context& ctx, boost::json::object& in, std::string_view action,
                                bool with_plaintext) const -> result {
        const auto* n = in.if_contains("NumberOfBytes");
        const auto spec = str(in, "KeySpec");
        if ((n != nullptr) == spec.has_value()) {
            return validation_error("Please specify either number of bytes or key spec.");
        }
        std::size_t length = 0;
        if (n != nullptr) {
            if (!n->is_int64()) {
                return validation_error("NumberOfBytes must be a number");
            }
            length = static_cast<std::size_t>(n->get_int64());
        } else if (*spec == "AES_256") {
            length = 32;
        } else if (*spec == "AES_128") {
            length = 16;
        } else {
            return validation_error("KeySpec must be AES_256 or AES_128");
        }
        auto c = catalog_for(ctx, in, "KeyId");
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        const auto context = read_context(in, "EncryptionContext");
        if (auto denied = authorize_use(ctx, **c, *k, action, context, std::nullopt)) {
            return *denied;
        }
        auto alg = symmetric_only(ctx, k->record, context);
        if (!alg) {
            return alg.error();
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        auto key = random(length);
        if (!key) {
            return key.error();
        }
        auto sealed = seal(ctx, k->record, *alg, key->bytes(), context);
        if (!sealed) {
            return sealed.error();
        }
        boost::json::object out{
            {"CiphertextBlob", std::move(*sealed)},
            {"KeyId", ctx.key_arn(k->record.account, k->record.key_id)},
            {"KeyMaterialId", key_material_id(k->record.key_id, k->record.current_version)}};
        if (with_plaintext) {
            out["Plaintext"] = key->base64();
        }
        return out;
    }

    /// Data keys are sealed only under a symmetric encryption key.
    [[nodiscard]] static auto symmetric_only(const call_context& ctx, const key_record& k,
                                             const encryption_context& context)
        -> aws_json::result<algorithm_choice> {
        if (!is_symmetric(k.spec)) {
            return kms_error("InvalidKeyUsageException", ctx.key_arn(k.account, k.key_id) +
                                                             " is not a symmetric encryption key.");
        }
        return choose_encryption(ctx, k, std::nullopt, context);
    }

    /// GenerateDataKeyPair and GenerateDataKeyPairWithoutPlaintext: a key
    /// pair made here, its private key sealed under a symmetric KMS key.
    [[nodiscard]] auto make_data_key_pair(call_context& ctx, boost::json::object& in,
                                          std::string_view action, bool with_plaintext) const
        -> result {
        const auto spec = str(in, "KeyPairSpec").value_or("");
        unsigned bits = 0;
        std::string_view curve;
        if (spec == "RSA_2048" || spec == "RSA_3072" || spec == "RSA_4096") {
            bits = spec == "RSA_2048" ? 2048U : spec == "RSA_3072" ? 3072U : 4096U;
        } else if (spec == "ECC_NIST_P256") {
            curve = "prime256v1";
        } else if (spec == "ECC_NIST_P384") {
            curve = "secp384r1";
        } else if (spec == "ECC_NIST_P521") {
            curve = "secp521r1";
        } else if (spec == "ECC_SECG_P256K1") {
            curve = "secp256k1";
        } else {
            return unsupported("KeyPairSpec " + std::string(spec) + " is not supported");
        }
        auto c = catalog_for(ctx, in, "KeyId");
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        const auto context = read_context(in, "EncryptionContext");
        auto r = key_request(ctx, **c, *k, action);
        std::vector<std::string> keys;
        for (const auto& [ck, cv] : context) {
            r.keys.emplace_back("kms:EncryptionContext:" + ck, std::vector<std::string>{cv});
            keys.push_back(ck);
        }
        r.keys.emplace_back("kms:EncryptionContextKeys", std::move(keys));
        r.keys.emplace_back("kms:DataKeyPairSpec", std::vector<std::string>{std::string(spec)});
        if (auto denied = authorize_with_grants(ctx, **c, k->record, std::move(r), &context)) {
            return *denied;
        }
        auto alg = symmetric_only(ctx, k->record, context);
        if (!alg) {
            return alg.error();
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        data_key_pair pair;
        try {
            pair = generate_key_pair(bits, curve);
        } catch (const std::runtime_error&) {
            return internal_error();
        }
        const plaintext priv(std::move(pair.private_pkcs8));
        auto sealed = seal(ctx, k->record, *alg, priv.bytes(), context);
        if (!sealed) {
            return sealed.error();
        }
        boost::json::object out{
            {"PrivateKeyCiphertextBlob", std::move(*sealed)},
            {"PublicKey", aws_json::base64_encode(std::as_bytes(std::span(pair.public_spki)))},
            {"KeyId", ctx.key_arn(k->record.account, k->record.key_id)},
            {"KeyMaterialId", key_material_id(k->record.key_id, k->record.current_version)},
            {"KeyPairSpec", spec}};
        if (with_plaintext) {
            out["PrivateKeyPlaintext"] = priv.base64();
        }
        return out;
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

    /// catalog(), after making the AWS managed key `member` names if it
    /// does not exist yet.
    [[nodiscard]] auto catalog_for(const call_context& ctx, const boost::json::object& in,
                                   std::string_view member) const
        -> aws_json::result<std::shared_ptr<const Catalog>> {
        auto c = catalog();
        if (!c) {
            return c;
        }
        const auto made =
            make_managed_if_named(ctx, **c, in, member, _d.ensure_managed, _d.ensure_owned);
        if (!made) {
            return made.error();
        }
        return *made ? catalog() : c;
    }

    crypto_deps<Catalog> _d;
};

}  // namespace kythira::kms
