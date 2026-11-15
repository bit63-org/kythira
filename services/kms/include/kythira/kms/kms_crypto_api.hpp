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

#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_ciphertext.hpp>
#include <kythira/kms/kms_errors.hpp>
#include <kythira/kms/kms_front_end.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>

#include <boost/json.hpp>

#include <openssl/crypto.h>

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

template<typename Catalog> class crypto_api : protected api_common {
public:
    using result = aws_json::result<boost::json::object>;

    explicit crypto_api(crypto_deps<Catalog> deps) : _d(std::move(deps)) {}

    static constexpr std::array<std::string_view, 6> k_operations{
        "Decrypt",        "Encrypt",  "GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
        "GenerateRandom", "ReEncrypt"};

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
        fe.on("GenerateRandom", bind(&crypto_api::generate_random));
    }

    auto encrypt(call_context& ctx, boost::json::object& in) -> result {
        auto plain = blob(in, "Plaintext");
        if (!plain) {
            return validation_error("Plaintext is required");
        }
        const plaintext p(std::move(*plain));
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        const auto context = read_context(in, "EncryptionContext");
        if (auto denied = authorize_use(ctx, **c, *k, "Encrypt", context)) {
            return *denied;
        }
        if (auto bad = check_usable(ctx, k->record, str(in, "EncryptionAlgorithm"))) {
            return *bad;
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        auto sealed = seal(ctx, k->record, p.bytes(), context);
        if (!sealed) {
            return sealed.error();
        }
        return boost::json::object{{"CiphertextBlob", std::move(*sealed)},
                                   {"KeyId", ctx.key_arn(k->record.account, k->record.key_id)},
                                   {"EncryptionAlgorithm", k_symmetric}};
    }

    auto decrypt(call_context& ctx, boost::json::object& in) -> result {
        if (in.contains("Recipient")) {
            return unsupported("Recipient (Nitro Enclaves attestation) is not supported");
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto opened = open(ctx, **c, in, "CiphertextBlob", "KeyId", "EncryptionContext",
                           "EncryptionAlgorithm", "Decrypt");
        if (!opened) {
            return opened.error();
        }
        return boost::json::object{{"KeyId", ctx.key_arn(opened->key.account, opened->key.key_id)},
                                   {"Plaintext", opened->plain.base64()},
                                   {"EncryptionAlgorithm", k_symmetric}};
    }

    auto re_encrypt(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
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
        if (auto denied = authorize_use(ctx, **c, *dest, "ReEncryptTo", dest_context)) {
            return *denied;
        }
        if (auto bad = check_usable(ctx, dest->record, str(in, "DestinationEncryptionAlgorithm"))) {
            return *bad;
        }
        auto opened = open(ctx, **c, in, "CiphertextBlob", "SourceKeyId", "SourceEncryptionContext",
                           "SourceEncryptionAlgorithm", "ReEncryptFrom");
        if (!opened) {
            return opened.error();
        }
        auto sealed = seal(ctx, dest->record, opened->plain.bytes(), dest_context);
        if (!sealed) {
            return sealed.error();
        }
        return boost::json::object{
            {"CiphertextBlob", std::move(*sealed)},
            {"SourceKeyId", ctx.key_arn(opened->key.account, opened->key.key_id)},
            {"KeyId", ctx.key_arn(dest->record.account, dest->record.key_id)},
            {"SourceEncryptionAlgorithm", k_symmetric},
            {"DestinationEncryptionAlgorithm", k_symmetric}};
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

    /// A decrypted ciphertext and the key that made it.
    struct opened_blob {
        key_record key;
        plaintext plain;
    };

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

    /// `action` on the key, with the encryption context and algorithm as
    /// condition keys.
    [[nodiscard]] static auto authorize_use(call_context& ctx, const Catalog& c, const resolved& k,
                                            std::string_view action,
                                            const encryption_context& context)
        -> std::optional<aws_json::error> {
        auto r = key_request(ctx, c, k, action);
        std::vector<std::string> keys;
        for (const auto& [ck, cv] : context) {
            r.keys.emplace_back("kms:EncryptionContext:" + ck, std::vector<std::string>{cv});
            keys.push_back(ck);
        }
        r.keys.emplace_back("kms:EncryptionContextKeys", std::move(keys));
        r.keys.emplace_back("kms:EncryptionAlgorithm",
                            std::vector<std::string>{std::string(k_symmetric)});
        return ctx.authorize(std::move(r));
    }

    /// The key's state and usage allow symmetric encryption with
    /// `algorithm` (SYMMETRIC_DEFAULT when not given).
    [[nodiscard]] static auto check_usable(const call_context& ctx, const key_record& k,
                                           std::optional<std::string_view> algorithm)
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
        if (k.usage != key_usage::encrypt_decrypt) {
            return kms_error("InvalidKeyUsageException",
                             "KeyUsage for " + arn + " is not ENCRYPT_DECRYPT.");
        }
        if (!is_symmetric(k.spec)) {
            return unsupported("Encryption with an asymmetric key is not supported yet");
        }
        if (algorithm && *algorithm != k_symmetric) {
            return kms_error("InvalidKeyUsageException",
                             "The encryption algorithm " + std::string(*algorithm) +
                                 " is not compatible with " + arn + ".");
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

    /// A ciphertext blob of `plain` under the key's current version, as
    /// base64.
    [[nodiscard]] auto seal(const call_context& ctx, const key_record& k,
                            std::span<const std::uint8_t> plain,
                            const encryption_context& context) const
        -> aws_json::result<std::string> {
        auto s = store();
        if (!s) {
            return s.error();
        }
        const auto aad =
            ciphertext_aad(ctx.key_arn(k.account, k.key_id), k.current_version, context);
        try {
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

    /// Decrypts the blob in `blob_member`, authorizing `action` on the key
    /// it names; `key_member`, when present, must name the same key.
    [[nodiscard]] auto open(call_context& ctx, const Catalog& c, const boost::json::object& in,
                            std::string_view blob_member, std::string_view key_member,
                            std::string_view context_member, std::string_view algorithm_member,
                            std::string_view action) const -> aws_json::result<opened_blob> {
        const auto raw = blob(in, blob_member);
        if (!raw) {
            return validation_error(std::string(blob_member) + " is required");
        }
        const auto b = decode_ciphertext(*raw);
        if (!b) {
            return invalid_ciphertext();
        }
        const auto key = c.key(b->key_id);
        if (!key) {
            return invalid_ciphertext();
        }
        std::optional<resolved> named;
        if (in.contains(key_member)) {
            auto k = resolve(ctx, c, in, key_member, true);
            if (!k) {
                return k.error();
            }
            if (k->record.key_id != b->key_id) {
                return kms_error("IncorrectKeyException",
                                 "The key ID in the request does not identify a CMK that can "
                                 "perform this operation.");
            }
            named = std::move(*k);
        }
        const resolved k = named ? *named : resolved{*key, false, {}};
        const auto context = read_context(in, context_member);
        if (auto denied = authorize_use(ctx, c, k, action, context)) {
            return *denied;
        }
        if (!c.version(b->key_id, b->backing_version)) {
            return invalid_ciphertext();
        }
        // An older backing version still decrypts what it made.
        auto usable = k.record;
        usable.current_version = b->backing_version;
        if (auto bad = check_usable(ctx, usable, str(in, algorithm_member))) {
            return *bad;
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
            return opened_blob{*key, plaintext(std::move(*plain))};
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
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        const auto context = read_context(in, "EncryptionContext");
        if (auto denied = authorize_use(ctx, **c, *k, action, context)) {
            return *denied;
        }
        if (auto bad = check_usable(ctx, k->record, std::nullopt)) {
            return *bad;
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        auto key = random(length);
        if (!key) {
            return key.error();
        }
        auto sealed = seal(ctx, k->record, key->bytes(), context);
        if (!sealed) {
            return sealed.error();
        }
        boost::json::object out{{"CiphertextBlob", std::move(*sealed)},
                                {"KeyId", ctx.key_arn(k->record.account, k->record.key_id)}};
        if (with_plaintext) {
            out["Plaintext"] = key->base64();
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

    crypto_deps<Catalog> _d;
};

}  // namespace kythira::kms
