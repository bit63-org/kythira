// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_encryption.hpp
/// @brief Server-side encryption (.kiro/specs/s3-compatible-storage/ task 11,
///        Requirement 11): SSE-S3, SSE-KMS with bucket keys, and SSE-C.
///
/// **What gets encrypted.** Every new object is encrypted, as on S3 since
/// January 2023: with the request's choice (`x-amz-server-side-encryption`,
/// or the SSE-C headers), else the bucket's default encryption
/// (`PutBucketEncryption`), else SSE-S3. Each object gets its own 256-bit
/// data key, and its chunks are sealed under it in the front end
/// (`s3_chunk_cipher.hpp`). The data key is stored only wrapped, in the
/// version's private metadata, so the index and the blob stores never hold
/// a key that opens anything on its own.
///
/// - **SSE-S3** (`AES256`): the data key is wrapped by the endpoint's
///   S3-managed key provider (`sse_keys::s3_managed`) under the key id
///   `kythira/s3`. An endpoint with no such provider configured stores
///   objects unencrypted and says so: no `x-amz-server-side-encryption`
///   header is returned for them (development setups and tests).
/// - **SSE-KMS** (`aws:kms`): the data key comes from the KMS provider
///   (`sse_keys::kms`) with `GenerateDataKey` on the request's key, the
///   bucket default's, or `alias/aws/s3`, under the encryption context
///   `{"aws:s3:arn": "arn:aws:s3:::bucket/key"}` plus the caller's
///   `x-amz-server-side-encryption-context`, and every read asks the KMS to
///   `Decrypt` it as the reading caller, so a caller without `kms:Decrypt`
///   on the key cannot read the object (anonymous callers never can). The
///   KMS sees each call as the end caller through S3 (`kms:ViaService`).
/// - **Bucket keys** (`BucketKeyEnabled`): a bucket-level key is generated
///   by the KMS under the context `{"aws:s3:arn": "arn:aws:s3:::bucket"}`
///   and kept in memory for `bucket_key_lifetime`; each object's data key
///   is then random and wrapped locally under the bucket key, with the
///   object's context as additional data. Writes make one KMS call per
///   bucket key instead of one per object, and reads one per bucket key a
///   node has not opened recently. The KMS-wrapped bucket key is stored
///   with each object, so no bucket state is needed to read it.
/// - **SSE-C**: the caller's key is the data key. It is never stored: only
///   its salted HMAC-SHA256 (11.3), to refuse a later request with another
///   key before reading any chunk. SSE-C requests must come over TLS.
///
/// **Providers.** `key_provider` erases any `s3_key_provider`, the same
/// shape as Kinesis's `kms_key_provider` (generate and decrypt a data key
/// under a key id and context, as a caller) so the shared provider library
/// the kms-compatible-api spec moves out of Kinesis can replace it.
/// `local_key_provider` wraps under a key derived from an operator
/// passphrase; `kms_api_provider` (`s3_kms_provider.hpp`) calls Kythira's
/// KMS or AWS KMS in their shared JSON protocol.
///
/// **Stored per version** (private `x-kythira-sse-*` keys are never
/// returned): the public `x-amz-server-side-encryption`,
/// `-aws-kms-key-id`, `-bucket-key-enabled`, `-customer-algorithm` and
/// `-customer-key-md5` headers; `x-kythira-sse-wrapped` (the wrapped data
/// key), `x-kythira-sse-context` (the context it was wrapped under),
/// `x-kythira-sse-bucket-key` and `x-kythira-sse-bucket-context` (bucket
/// keys), and `x-kythira-sse-c-hmac` (SSE-C).
///
/// **Not here.** DSSE-KMS (`aws:kms:dsse`) answers `NotImplemented`.

#include <kythira/s3/s3_chunk_cipher.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_index_records.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/aws_rest_xml_protocol.hpp>

#include <boost/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <concepts>
#include <functional>
#include <cstdint>
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

namespace kythira::s3 {

// ---------------------------------------------------------------------------
// Stored metadata
// ---------------------------------------------------------------------------

inline constexpr std::string_view sse_metadata = "x-amz-server-side-encryption";
inline constexpr std::string_view sse_kms_key_metadata =
    "x-amz-server-side-encryption-aws-kms-key-id";
inline constexpr std::string_view sse_bucket_key_metadata =
    "x-amz-server-side-encryption-bucket-key-enabled";
inline constexpr std::string_view sse_c_algorithm_metadata =
    "x-amz-server-side-encryption-customer-algorithm";
inline constexpr std::string_view sse_c_key_md5_metadata =
    "x-amz-server-side-encryption-customer-key-md5";
inline constexpr std::string_view sse_wrapped_metadata = "x-kythira-sse-wrapped";
inline constexpr std::string_view sse_context_metadata = "x-kythira-sse-context";
inline constexpr std::string_view sse_bucket_key_blob_metadata = "x-kythira-sse-bucket-key";
inline constexpr std::string_view sse_bucket_context_metadata = "x-kythira-sse-bucket-context";
inline constexpr std::string_view sse_c_hmac_metadata = "x-kythira-sse-c-hmac";

/// Every stored key encryption writes, so a copy or a re-encryption can
/// replace them as a set.
inline constexpr std::array<std::string_view, 10> sse_metadata_keys{
    sse_metadata,
    sse_kms_key_metadata,
    sse_bucket_key_metadata,
    sse_c_algorithm_metadata,
    sse_c_key_md5_metadata,
    sse_wrapped_metadata,
    sse_context_metadata,
    sse_bucket_key_blob_metadata,
    sse_bucket_context_metadata,
    sse_c_hmac_metadata,
};

/// The key id SSE-S3 data keys are wrapped under.
inline constexpr std::string_view sse_s3_key_id = "kythira/s3";
/// The KMS key SSE-KMS uses when neither the request nor the bucket names
/// one: the account's AWS managed key for S3.
inline constexpr std::string_view default_kms_key_id = "alias/aws/s3";

// ---------------------------------------------------------------------------
// Key providers
// ---------------------------------------------------------------------------

/// A KMS encryption context. Sorted, so its JSON is canonical.
using encryption_context = std::map<std::string, std::string, std::less<>>;

/// Who a key provider acts for: the request's principal (empty when
/// anonymous) and address, for the KMS's own authorization.
struct kms_caller {
    std::optional<aws_auth::principal_context> principal;
    std::string source_ip;
    std::string request_id;
};

struct generated_data_key {
    std::string plaintext;  ///< 32 bytes
    std::string wrapped;
    /// The provider's resolved id for the key (a KMS key ARN, say).
    std::string key_id;
};

/// What went wrong in a key provider. Each maps to the error S3 answers.
enum class kms_failure : std::uint8_t {
    not_found,
    disabled,
    invalid_state,
    access_denied,
    invalid_ciphertext,
    unavailable,
};

class kms_error : public std::runtime_error {
public:
    kms_error(kms_failure f, const std::string& what) : std::runtime_error(what), _failure(f) {}
    [[nodiscard]] auto failure() const noexcept -> kms_failure { return _failure; }

private:
    kms_failure _failure;
};

/// A key provider: thread-safe, throws `kms_error`.
template<typename P>
concept s3_key_provider = requires(P& p, const std::string& key_id, const std::string& wrapped,
                                   const encryption_context& context, const kms_caller& who) {
    { p.generate_data_key(key_id, context, who) } -> std::same_as<generated_data_key>;
    { p.decrypt_data_key(key_id, wrapped, context, who) } -> std::same_as<std::string>;
};

/// Any `s3_key_provider`, shared; empty means none is configured.
class key_provider {
public:
    key_provider() = default;
    template<s3_key_provider P>
    requires(!std::same_as<std::remove_cvref_t<P>, key_provider>)
    explicit key_provider(P p) : _impl(std::make_shared<model<P>>(std::move(p))) {}

    [[nodiscard]] explicit operator bool() const noexcept { return _impl != nullptr; }

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context,
                                         const kms_caller& who) const -> generated_data_key {
        if (!_impl) {
            throw kms_error(kms_failure::not_found, "No KMS provider is configured");
        }
        return _impl->generate(key_id, context, who);
    }
    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context,
                                        const kms_caller& who) const -> std::string {
        if (!_impl) {
            throw kms_error(kms_failure::not_found, "No KMS provider is configured");
        }
        return _impl->decrypt(key_id, wrapped, context, who);
    }

private:
    struct base {
        base() = default;
        base(const base&) = delete;
        auto operator=(const base&) -> base& = delete;
        base(base&&) = delete;
        auto operator=(base&&) -> base& = delete;
        virtual ~base() = default;
        virtual auto generate(const std::string&, const encryption_context&, const kms_caller&)
            -> generated_data_key = 0;
        virtual auto decrypt(const std::string&, const std::string&, const encryption_context&,
                             const kms_caller&) -> std::string = 0;
    };
    template<typename P> struct model final : base {
        explicit model(P p) : provider(std::move(p)) {}
        auto generate(const std::string& id, const encryption_context& c, const kms_caller& w)
            -> generated_data_key override {
            return provider.generate_data_key(id, c, w);
        }
        auto decrypt(const std::string& id, const std::string& wrapped, const encryption_context& c,
                     const kms_caller& w) -> std::string override {
            return provider.decrypt_data_key(id, wrapped, c, w);
        }
        P provider;
    };
    std::shared_ptr<base> _impl;
};

namespace sse_detail {

[[nodiscard]] inline auto b64(std::string_view raw) -> std::string {
    return aws_json::base64_encode(std::as_bytes(std::span(raw.data(), raw.size())));
}

[[nodiscard]] inline auto unb64(std::string_view s) -> std::optional<std::string> {
    auto bytes = aws_json::base64_decode(s);
    if (!bytes) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

[[nodiscard]] inline auto random_bytes(std::size_t n) -> std::string {
    std::string out(n, '\0');
    if (::RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(n)) != 1) {
        throw std::runtime_error("s3 encryption: no randomness");
    }
    return out;
}

/// `{"k":"v",...}` in key order.
[[nodiscard]] inline auto context_json(const encryption_context& c) -> std::string {
    boost::json::object o;
    for (const auto& [k, v] : c) {
        o[k] = v;
    }
    return boost::json::serialize(o);
}

/// A JSON object of strings, or nothing.
[[nodiscard]] inline auto parse_context(std::string_view json)
    -> std::optional<encryption_context> {
    boost::system::error_code ec;
    auto v = boost::json::parse(json, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    encryption_context out;
    for (const auto& [k, val] : v.as_object()) {
        if (!val.is_string()) {
            return std::nullopt;
        }
        out.emplace(std::string(k), std::string(val.as_string()));
    }
    return out;
}

[[nodiscard]] inline auto hmac_sha256(std::string_view key, std::string_view data) -> std::string {
    std::string out(32, '\0');
    unsigned int len = 0;
    if (::HMAC(::EVP_sha256(), key.data(), static_cast<int>(key.size()),
               reinterpret_cast<const unsigned char*>(data.data()), data.size(),
               reinterpret_cast<unsigned char*>(out.data()), &len) == nullptr ||
        len != 32) {
        throw std::runtime_error("s3 encryption: HMAC failed");
    }
    return out;
}

[[nodiscard]] inline auto md5_raw(std::string_view data) -> std::string {
    std::string out(16, '\0');
    unsigned int len = 0;
    if (::EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char*>(out.data()), &len,
                     ::EVP_md5(), nullptr) != 1 ||
        len != 16) {
        throw std::runtime_error("s3 encryption: MD5 failed");
    }
    return out;
}

/// AES-256-GCM key wrap: `1 | nonce(12) | ciphertext | tag(16)`, random
/// nonce, `aad` bound.
[[nodiscard]] inline auto wrap(std::string_view kek, std::string_view key, std::string_view aad)
    -> std::string {
    const auto nonce = random_bytes(12);
    std::string out;
    out.reserve(1 + 12 + key.size() + 16);
    out.push_back('\x01');
    out += nonce;
    out.resize(1 + 12 + key.size() + 16);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)> c(::EVP_CIPHER_CTX_new(),
                                                                        &::EVP_CIPHER_CTX_free);
    auto* o = reinterpret_cast<unsigned char*>(out.data());
    int n = 0;
    if (!c ||
        ::EVP_EncryptInit_ex(c.get(), ::EVP_aes_256_gcm(), nullptr,
                             reinterpret_cast<const unsigned char*>(kek.data()), o + 1) != 1 ||
        ::EVP_EncryptUpdate(c.get(), nullptr, &n,
                            reinterpret_cast<const unsigned char*>(aad.data()),
                            static_cast<int>(aad.size())) != 1 ||
        ::EVP_EncryptUpdate(c.get(), o + 13, &n, reinterpret_cast<const unsigned char*>(key.data()),
                            static_cast<int>(key.size())) != 1 ||
        ::EVP_EncryptFinal_ex(c.get(), o + 13 + n, &n) != 1 ||
        ::EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, 16, o + 13 + key.size()) != 1) {
        throw std::runtime_error("s3 encryption: key wrap failed");
    }
    return out;
}

[[nodiscard]] inline auto unwrap(std::string_view kek, std::string_view wrapped,
                                 std::string_view aad) -> std::optional<std::string> {
    if (wrapped.size() < 1 + 12 + 16 || wrapped[0] != '\x01') {
        return std::nullopt;
    }
    const auto len = wrapped.size() - 29;
    std::string out(len, '\0');
    std::string tag(wrapped.substr(13 + len));
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)> c(::EVP_CIPHER_CTX_new(),
                                                                        &::EVP_CIPHER_CTX_free);
    const auto* w = reinterpret_cast<const unsigned char*>(wrapped.data());
    int n = 0;
    std::array<unsigned char, 16> tail{};
    if (!c ||
        ::EVP_DecryptInit_ex(c.get(), ::EVP_aes_256_gcm(), nullptr,
                             reinterpret_cast<const unsigned char*>(kek.data()), w + 1) != 1 ||
        ::EVP_DecryptUpdate(c.get(), nullptr, &n,
                            reinterpret_cast<const unsigned char*>(aad.data()),
                            static_cast<int>(aad.size())) != 1 ||
        ::EVP_DecryptUpdate(c.get(), reinterpret_cast<unsigned char*>(out.data()), &n, w + 13,
                            static_cast<int>(len)) != 1 ||
        ::EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1 ||
        ::EVP_DecryptFinal_ex(c.get(), tail.data(), &n) != 1) {
        ::OPENSSL_cleanse(out.data(), out.size());
        return std::nullopt;
    }
    return out;
}

/// The additional data binding a wrapped key to its key id and context.
[[nodiscard]] inline auto binding(std::string_view key_id, const encryption_context& context)
    -> std::string {
    std::string out(key_id);
    out.push_back('\0');
    out += context_json(context);
    return out;
}

}  // namespace sse_detail

/// Data keys wrapped under a key derived from an operator passphrase
/// (PBKDF2-HMAC-SHA256, 200 000 iterations, once at construction), like
/// Kinesis's local provider but derived once: an S3 endpoint wraps a key
/// per object, so a derivation per wrap would cost every PUT a quarter of
/// a second. Every node of an endpoint needs the same passphrase and salt.
/// Any key id names a key; the id and context are bound as additional
/// data, so a key does not unwrap under another id or context.
class local_key_provider {
public:
    local_key_provider(std::string_view passphrase, std::string_view salt = "kythira-s3-local-v1") {
        if (passphrase.empty()) {
            throw std::invalid_argument("s3 local key provider: empty passphrase");
        }
        _kek = std::make_shared<std::string>(32, '\0');
        if (::PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()),
                                reinterpret_cast<const unsigned char*>(salt.data()),
                                static_cast<int>(salt.size()), 200'000, ::EVP_sha256(), 32,
                                reinterpret_cast<unsigned char*>(_kek->data())) != 1) {
            throw std::runtime_error("s3 local key provider: key derivation failed");
        }
    }

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context,
                                         const kms_caller& /*who*/) const -> generated_data_key {
        generated_data_key out;
        out.plaintext = sse_detail::random_bytes(32);
        out.wrapped = sse_detail::wrap(*_kek, out.plaintext, sse_detail::binding(key_id, context));
        out.key_id = key_id;
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context,
                                        const kms_caller& /*who*/) const -> std::string {
        auto key = sse_detail::unwrap(*_kek, wrapped, sse_detail::binding(key_id, context));
        if (!key || key->size() != 32) {
            throw kms_error(kms_failure::invalid_ciphertext,
                            "The data key does not unwrap under key " + key_id);
        }
        return std::move(*key);
    }

private:
    std::shared_ptr<std::string> _kek;
};

static_assert(s3_key_provider<local_key_provider>);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

namespace sse_detail {

[[nodiscard]] inline auto invalid_argument(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidArgument", std::move(message));
}

[[nodiscard]] inline auto invalid_request(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest", std::move(message));
}

[[nodiscard]] inline auto kms_needs_sigv4() -> aws_rest_xml::error {
    return invalid_argument(
        "Requests specifying Server Side Encryption with AWS KMS managed keys require AWS "
        "Signature Version 4.");
}

}  // namespace sse_detail

/// What S3 answers for a provider failure.
[[nodiscard]] inline auto from_kms(const kms_error& e) -> aws_rest_xml::error {
    switch (e.failure()) {
        case kms_failure::not_found:
            return aws_rest_xml::errors::make(400, "KMS.NotFoundException", e.what());
        case kms_failure::disabled:
            return aws_rest_xml::errors::make(400, "KMS.DisabledException", e.what());
        case kms_failure::invalid_state:
            return aws_rest_xml::errors::make(400, "KMS.KMSInvalidStateException", e.what());
        case kms_failure::access_denied:
            return aws_rest_xml::errors::make(403, "AccessDenied", e.what());
        case kms_failure::invalid_ciphertext:
            return aws_rest_xml::errors::make(500, "InternalError", e.what());
        case kms_failure::unavailable:
            break;
    }
    return aws_rest_xml::errors::make(503, "ServiceUnavailable", e.what());
}

// ---------------------------------------------------------------------------
// What a request asks for
// ---------------------------------------------------------------------------

enum class sse_kind : std::uint8_t {
    none,
    s3,
    kms,
    customer
};

/// A customer-provided key, checked against its MD5.
struct customer_key {
    std::string key;      ///< 32 raw bytes
    std::string key_md5;  ///< base64, as sent
};

/// The SSE-C headers under `prefix` (`x-amz-server-side-encryption-customer-`
/// or `x-amz-copy-source-server-side-encryption-customer-`): none, a key,
/// or the error S3 gives for a partial or wrong set.
[[nodiscard]] inline auto parse_customer_key(const header_list& headers, std::string_view prefix,
                                             bool secure_transport)
    -> aws_rest_xml::result<std::optional<customer_key>> {
    const std::string p(prefix);
    const auto algorithm = find_header(headers, p + "algorithm");
    const auto key = find_header(headers, p + "key");
    const auto md5 = find_header(headers, p + "key-MD5");
    if (!algorithm && !key && !md5) {
        return std::optional<customer_key>{};
    }
    if (!secure_transport) {
        return sse_detail::invalid_request(
            "Requests specifying Server Side Encryption with Customer provided keys must be made "
            "over a secure connection.");
    }
    if (!algorithm) {
        return sse_detail::invalid_argument(
            "Requests specifying Server Side Encryption with Customer provided keys must provide "
            "a valid encryption algorithm.");
    }
    if (*algorithm != "AES256") {
        return aws_rest_xml::errors::make(
            400, "InvalidEncryptionAlgorithmError",
            "The Encryption request you specified is not valid. Supported value: AES256.");
    }
    if (!key) {
        return sse_detail::invalid_argument(
            "Requests specifying Server Side Encryption with Customer provided keys must provide "
            "an appropriate secret key.");
    }
    auto raw = sse_detail::unb64(*key);
    if (!raw || raw->size() != chunk_cipher::key_bytes) {
        return sse_detail::invalid_argument(
            "The secret key was invalid for the specified algorithm.");
    }
    if (!md5) {
        return sse_detail::invalid_argument(
            "Requests specifying Server Side Encryption with Customer provided keys must provide "
            "the client calculated MD5 of the secret key.");
    }
    if (sse_detail::unb64(*md5) != sse_detail::md5_raw(*raw)) {
        return sse_detail::invalid_argument(
            "The calculated MD5 hash of the key did not match the hash that was provided.");
    }
    return std::optional<customer_key>{customer_key{std::move(*raw), std::string(*md5)}};
}

inline constexpr std::string_view customer_prefix = "x-amz-server-side-encryption-customer-";
inline constexpr std::string_view copy_source_customer_prefix =
    "x-amz-copy-source-server-side-encryption-customer-";

/// The encryption headers of a write (PUT, POST, copy, CreateMultipartUpload).
struct sse_request {
    sse_kind kind = sse_kind::none;  ///< none: the bucket's default
    std::string kms_key_id;          ///< empty: the bucket's, or the default
    encryption_context context;      ///< the caller's, SSE-KMS only
    std::optional<bool> bucket_key;
    std::optional<customer_key> customer;
};

[[nodiscard]] inline auto parse_sse_request(const header_list& headers, bool secure_transport)
    -> aws_rest_xml::result<sse_request> {
    sse_request out;
    auto customer = parse_customer_key(headers, customer_prefix, secure_transport);
    if (!customer) {
        return customer.error();
    }
    const auto sse = find_header(headers, sse_metadata);
    if (*customer) {
        if (sse) {
            return sse_detail::invalid_argument(
                "Server Side Encryption with Customer provided key is incompatible with the "
                "encryption method specified");
        }
        out.kind = sse_kind::customer;
        out.customer = std::move(*customer);
    } else if (sse) {
        if (*sse == "AES256") {
            out.kind = sse_kind::s3;
        } else if (*sse == "aws:kms") {
            out.kind = sse_kind::kms;
        } else if (*sse == "aws:kms:dsse") {
            return aws_rest_xml::errors::make(
                501, "NotImplemented",
                "A header you provided implies functionality that is not implemented");
        } else {
            return sse_detail::invalid_argument("The encryption method specified is not supported");
        }
    }
    const auto key_id = find_header(headers, sse_kms_key_metadata);
    const auto context = find_header(headers, "x-amz-server-side-encryption-context");
    if ((key_id || context) && out.kind != sse_kind::kms) {
        return sse_detail::invalid_argument(
            "Server Side Encryption with AWS KMS managed key requires HTTP header "
            "x-amz-server-side-encryption : aws:kms");
    }
    if (key_id) {
        if (key_id->empty()) {
            return sse_detail::invalid_argument("KMS key id must not be empty");
        }
        out.kms_key_id = std::string(*key_id);
    }
    if (context) {
        auto json = sse_detail::unb64(*context);
        auto parsed = json ? sse_detail::parse_context(*json) : std::nullopt;
        if (!parsed) {
            return sse_detail::invalid_argument(
                "The header 'x-amz-server-side-encryption-context' shall be Base64-encoded "
                "UTF-8 string holding JSON which represents a string-string map");
        }
        for (const auto& [k, v] : *parsed) {
            if (k.starts_with("aws:")) {
                return sse_detail::invalid_argument(
                    "Encryption context keys starting with aws: are reserved");
            }
        }
        out.context = std::move(*parsed);
    }
    if (auto bk = find_header(headers, sse_bucket_key_metadata)) {
        const auto v = aws_rest_xml::detail::iequals(*bk, "true");
        if (!v && !aws_rest_xml::detail::iequals(*bk, "false")) {
            return sse_detail::invalid_argument(
                "x-amz-server-side-encryption-bucket-key-enabled must be true or false");
        }
        out.bucket_key = v;
    }
    return out;
}

/// A read's SSE headers: `x-amz-server-side-encryption` and the KMS ones
/// are for writes only, as on S3.
[[nodiscard]] inline auto refuse_write_headers_on_read(const header_list& headers)
    -> std::optional<aws_rest_xml::error> {
    for (const auto name : {sse_metadata, sse_kms_key_metadata,
                            std::string_view("x-amz-server-side-encryption-context")}) {
        if (find_header(headers, name)) {
            return sse_detail::invalid_argument(
                "x-amz-server-side-encryption header is not supported for this operation.");
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Bucket default encryption
// ---------------------------------------------------------------------------

/// `ServerSideEncryptionConfiguration`: one rule.
struct bucket_encryption {
    sse_kind algorithm = sse_kind::s3;
    std::string kms_key_id;
    bool bucket_key = false;
};

[[nodiscard]] inline auto bucket_encryption_xml(const bucket_encryption& e) -> std::string {
    auto w = aws_rest_xml::document("ServerSideEncryptionConfiguration");
    w.open("Rule").open("ApplyServerSideEncryptionByDefault");
    w.element("SSEAlgorithm", e.algorithm == sse_kind::kms ? "aws:kms" : "AES256");
    if (!e.kms_key_id.empty()) {
        w.element("KMSMasterKeyID", e.kms_key_id);
    }
    w.close();
    w.element("BucketKeyEnabled", e.bucket_key ? "true" : "false");
    w.close();
    w.close();
    return w.str();
}

[[nodiscard]] inline auto parse_bucket_encryption(std::string_view xml)
    -> aws_rest_xml::result<bucket_encryption> {
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "ServerSideEncryptionConfiguration" ||
        doc->children_named("Rule").size() != 1) {
        return aws_rest_xml::errors::malformed_xml(
            "expected one ServerSideEncryptionConfiguration Rule");
    }
    const auto* rule = doc->child("Rule");
    const auto* apply = rule->child("ApplyServerSideEncryptionByDefault");
    const auto algorithm = apply != nullptr ? apply->child_text("SSEAlgorithm") : std::nullopt;
    if (!algorithm) {
        return aws_rest_xml::errors::malformed_xml("expected ApplyServerSideEncryptionByDefault");
    }
    bucket_encryption out;
    if (*algorithm == "AES256") {
        out.algorithm = sse_kind::s3;
    } else if (*algorithm == "aws:kms") {
        out.algorithm = sse_kind::kms;
    } else if (*algorithm == "aws:kms:dsse") {
        return aws_rest_xml::errors::make(
            501, "NotImplemented",
            "A header you provided implies functionality that is not implemented");
    } else {
        return aws_rest_xml::errors::malformed_xml("unknown SSEAlgorithm " + *algorithm);
    }
    if (auto key = apply->child_text("KMSMasterKeyID")) {
        if (out.algorithm != sse_kind::kms) {
            return sse_detail::invalid_argument(
                "a KMSMasterKeyID is not applicable if the default sse algorithm is not aws:kms "
                "or aws:kms:dsse");
        }
        out.kms_key_id = *key;
    }
    if (auto bk = rule->child_text("BucketKeyEnabled")) {
        if (*bk != "true" && *bk != "false") {
            return aws_rest_xml::errors::malformed_xml("BucketKeyEnabled must be true or false");
        }
        out.bucket_key = *bk == "true";
    }
    return out;
}

/// The encryption a new object gets: the request's, else the bucket's.
struct sse_plan {
    sse_kind kind = sse_kind::s3;
    std::string kms_key_id;  ///< SSE-KMS: never empty
    bool bucket_key = false;
    encryption_context context;  ///< the caller's part
    std::optional<customer_key> customer;
};

[[nodiscard]] inline auto plan_for(sse_request r, const bucket_encryption& bucket) -> sse_plan {
    sse_plan out;
    out.kind = r.kind == sse_kind::none ? bucket.algorithm : r.kind;
    if (out.kind == sse_kind::kms) {
        out.kms_key_id = !r.kms_key_id.empty() ? r.kms_key_id
                         : r.kind == sse_kind::none || bucket.algorithm == sse_kind::kms
                             ? bucket.kms_key_id
                             : std::string{};
        if (out.kms_key_id.empty()) {
            out.kms_key_id = std::string(default_kms_key_id);
        }
        out.bucket_key = r.bucket_key.value_or(bucket.bucket_key);
        out.context = std::move(r.context);
    }
    out.customer = std::move(r.customer);
    return out;
}

// ---------------------------------------------------------------------------
// Keys for objects
// ---------------------------------------------------------------------------

/// A new object's encryption: the cipher its chunks are sealed with (none
/// when the endpoint stores it unencrypted), the metadata to store, and
/// the headers to answer with.
struct sealed_object {
    std::optional<chunk_cipher> cipher;
    std::map<std::string, std::string> metadata;
    header_list response;
};

/// The response headers for a stored object's encryption (PUT, GET, HEAD,
/// UploadPart, ...): the public stored keys, by their header names.
[[nodiscard]] inline auto sse_response_headers(const std::map<std::string, std::string>& metadata)
    -> header_list {
    header_list out;
    const auto add = [&](std::string_view key, std::string_view header) {
        if (auto it = metadata.find(std::string(key)); it != metadata.end()) {
            out.emplace_back(std::string(header), it->second);
        }
    };
    add(sse_metadata, "x-amz-server-side-encryption");
    add(sse_kms_key_metadata, "x-amz-server-side-encryption-aws-kms-key-id");
    add(sse_bucket_key_metadata, "x-amz-server-side-encryption-bucket-key-enabled");
    add(sse_c_algorithm_metadata, "x-amz-server-side-encryption-customer-algorithm");
    add(sse_c_key_md5_metadata, "x-amz-server-side-encryption-customer-key-MD5");
    return out;
}

/// The kind of encryption stored metadata says an object has.
[[nodiscard]] inline auto stored_kind(const std::map<std::string, std::string>& metadata)
    -> sse_kind {
    if (metadata.contains(std::string(sse_c_hmac_metadata))) {
        return sse_kind::customer;
    }
    const auto it = metadata.find(std::string(sse_metadata));
    if (it == metadata.end()) {
        return sse_kind::none;
    }
    return it->second == "aws:kms" ? sse_kind::kms : sse_kind::s3;
}

/// The key providers and the bucket-key cache, shared by the handlers.
class sse_keys {
public:
    /// Wraps SSE-S3 data keys; empty stores SSE-S3 objects unencrypted.
    key_provider s3_managed;
    /// SSE-KMS; empty refuses SSE-KMS with `KMS.NotFoundException`.
    key_provider kms;
    /// How long a node keeps using one bucket key for new objects.
    std::chrono::milliseconds bucket_key_lifetime = std::chrono::hours(1);
    /// How many opened bucket keys a node keeps for reads.
    std::size_t bucket_key_cache_size = 1024;
    std::string partition = "aws";
    /// The clock for bucket-key lifetimes; the system clock when empty.
    std::function<std::chrono::steady_clock::time_point()> clock;

    /// Counters for tests and metrics.
    struct counters {
        std::uint64_t kms_generate = 0;
        std::uint64_t kms_decrypt = 0;
    };
    [[nodiscard]] auto stats() const -> counters {
        const std::lock_guard lock(_mutex);
        return _counters;
    }

    /// The encryption for a new object `key` in `bucket` (its client name).
    [[nodiscard]] auto seal(const sse_plan& plan, std::string_view bucket, std::string_view key,
                            const kms_caller& who) -> aws_rest_xml::result<sealed_object> {
        sealed_object out;
        try {
            switch (plan.kind) {
                case sse_kind::none:
                    return out;
                case sse_kind::s3: {
                    if (!s3_managed) {
                        return out;
                    }
                    const encryption_context context{{"aws:s3:arn", object_arn(bucket, key)}};
                    auto k = s3_managed.generate_data_key(std::string(sse_s3_key_id), context, who);
                    out.metadata[std::string(sse_metadata)] = "AES256";
                    out.metadata[std::string(sse_wrapped_metadata)] = sse_detail::b64(k.wrapped);
                    out.metadata[std::string(sse_context_metadata)] =
                        sse_detail::context_json(context);
                    out.cipher.emplace(k.plaintext);
                    ::OPENSSL_cleanse(k.plaintext.data(), k.plaintext.size());
                    break;
                }
                case sse_kind::kms: {
                    if (!who.principal) {
                        return sse_detail::kms_needs_sigv4();
                    }
                    encryption_context context = plan.context;
                    context["aws:s3:arn"] = object_arn(bucket, key);
                    out.metadata[std::string(sse_metadata)] = "aws:kms";
                    out.metadata[std::string(sse_context_metadata)] =
                        sse_detail::context_json(context);
                    std::string data_key;
                    if (plan.bucket_key) {
                        const auto bk = bucket_key_for(plan.kms_key_id, bucket, who);
                        data_key = sse_detail::random_bytes(32);
                        out.metadata[std::string(sse_wrapped_metadata)] =
                            sse_detail::b64(sse_detail::wrap(
                                bk.plaintext, data_key, sse_detail::binding(bk.key_id, context)));
                        out.metadata[std::string(sse_bucket_key_blob_metadata)] =
                            sse_detail::b64(bk.wrapped);
                        out.metadata[std::string(sse_bucket_context_metadata)] =
                            sse_detail::context_json(bucket_context(bucket));
                        out.metadata[std::string(sse_bucket_key_metadata)] = "true";
                        out.metadata[std::string(sse_kms_key_metadata)] = bk.key_id;
                    } else {
                        auto k = generate(kms, plan.kms_key_id, context, who);
                        data_key = std::move(k.plaintext);
                        out.metadata[std::string(sse_wrapped_metadata)] =
                            sse_detail::b64(k.wrapped);
                        out.metadata[std::string(sse_kms_key_metadata)] = k.key_id;
                    }
                    out.cipher.emplace(data_key);
                    ::OPENSSL_cleanse(data_key.data(), data_key.size());
                    if (!plan.context.empty()) {
                        out.response.emplace_back(
                            "x-amz-server-side-encryption-context",
                            sse_detail::b64(sse_detail::context_json(context)));
                    }
                    break;
                }
                case sse_kind::customer: {
                    const auto& c = *plan.customer;
                    const auto salt = sse_detail::random_bytes(16);
                    out.metadata[std::string(sse_c_algorithm_metadata)] = "AES256";
                    out.metadata[std::string(sse_c_key_md5_metadata)] = c.key_md5;
                    out.metadata[std::string(sse_c_hmac_metadata)] =
                        sse_detail::b64(salt + sse_detail::hmac_sha256(salt, c.key));
                    out.cipher.emplace(c.key);
                    break;
                }
            }
        } catch (const kms_error& e) {
            return from_kms(e);
        }
        auto headers = sse_response_headers(out.metadata);
        headers.insert(headers.end(), out.response.begin(), out.response.end());
        out.response = std::move(headers);
        return out;
    }

    /// The cipher for a stored object (none when it is unencrypted), as
    /// `who` reads it with the SSE-C key `customer` names, if any.
    [[nodiscard]] auto open(const std::map<std::string, std::string>& metadata,
                            const std::optional<customer_key>& customer, const kms_caller& who)
        -> aws_rest_xml::result<std::optional<chunk_cipher>> {
        const auto kind = stored_kind(metadata);
        const auto get = [&](std::string_view k) -> std::string {
            auto it = metadata.find(std::string(k));
            return it == metadata.end() ? std::string{} : it->second;
        };
        if (kind == sse_kind::customer) {
            if (!customer) {
                return sse_detail::invalid_request(
                    "The object was stored using a form of Server Side Encryption. The correct "
                    "parameters must be provided to retrieve the object.");
            }
            const auto stored = sse_detail::unb64(get(sse_c_hmac_metadata));
            if (!stored || stored->size() != 48) {
                return aws_rest_xml::errors::make(500, "InternalError",
                                                  "stored SSE-C key check is malformed");
            }
            const auto mac = sse_detail::hmac_sha256(stored->substr(0, 16), customer->key);
            if (CRYPTO_memcmp(mac.data(), stored->data() + 16, 32) != 0) {
                return aws_rest_xml::errors::make(
                    403, "AccessDenied",
                    "The provided encryption key does not match the key the object was stored "
                    "with");
            }
            return std::optional<chunk_cipher>(chunk_cipher(customer->key));
        }
        if (customer) {
            return sse_detail::invalid_request(
                "The encryption parameters are not applicable to this object.");
        }
        if (kind == sse_kind::none || !metadata.contains(std::string(sse_wrapped_metadata))) {
            return std::optional<chunk_cipher>{};
        }
        const auto wrapped = sse_detail::unb64(get(sse_wrapped_metadata));
        const auto context = sse_detail::parse_context(get(sse_context_metadata));
        if (!wrapped || !context) {
            return aws_rest_xml::errors::make(500, "InternalError",
                                              "stored object key is malformed");
        }
        try {
            if (kind == sse_kind::s3) {
                auto key = s3_managed.decrypt_data_key(std::string(sse_s3_key_id), *wrapped,
                                                       *context, who);
                std::optional<chunk_cipher> out(std::in_place, key);
                ::OPENSSL_cleanse(key.data(), key.size());
                return out;
            }
            if (!who.principal) {
                return sse_detail::kms_needs_sigv4();
            }
            const auto key_id = get(sse_kms_key_metadata);
            if (metadata.contains(std::string(sse_bucket_key_blob_metadata))) {
                const auto blob = sse_detail::unb64(get(sse_bucket_key_blob_metadata));
                const auto bctx = sse_detail::parse_context(get(sse_bucket_context_metadata));
                if (!blob || !bctx) {
                    return aws_rest_xml::errors::make(500, "InternalError",
                                                      "stored bucket key is malformed");
                }
                const auto bk = open_bucket_key(key_id, *blob, *bctx, who);
                auto key = sse_detail::unwrap(bk, *wrapped, sse_detail::binding(key_id, *context));
                if (!key || key->size() != 32) {
                    return aws_rest_xml::errors::make(
                        500, "InternalError", "object key does not unwrap under its bucket key");
                }
                std::optional<chunk_cipher> out(std::in_place, *key);
                ::OPENSSL_cleanse(key->data(), key->size());
                return out;
            }
            auto key = decrypt(kms, key_id, *wrapped, *context, who);
            std::optional<chunk_cipher> out(std::in_place, key);
            ::OPENSSL_cleanse(key.data(), key.size());
            return out;
        } catch (const kms_error& e) {
            return from_kms(e);
        }
    }

    [[nodiscard]] auto object_arn(std::string_view bucket, std::string_view key) const
        -> std::string {
        return "arn:" + partition + ":s3:::" + std::string(bucket) + "/" + std::string(key);
    }

private:
    struct bucket_key {
        std::string plaintext;
        std::string wrapped;
        std::string key_id;
        std::chrono::steady_clock::time_point created;
    };

    [[nodiscard]] auto now() const -> std::chrono::steady_clock::time_point {
        return clock ? clock() : std::chrono::steady_clock::now();
    }

    [[nodiscard]] auto bucket_context(std::string_view bucket) const -> encryption_context {
        return {{"aws:s3:arn", "arn:" + partition + ":s3:::" + std::string(bucket)}};
    }

    auto generate(const key_provider& p, const std::string& id, const encryption_context& c,
                  const kms_caller& who) -> generated_data_key {
        {
            const std::lock_guard lock(_mutex);
            ++_counters.kms_generate;
        }
        return p.generate_data_key(id, c, who);
    }

    auto decrypt(const key_provider& p, const std::string& id, const std::string& wrapped,
                 const encryption_context& c, const kms_caller& who) -> std::string {
        {
            const std::lock_guard lock(_mutex);
            ++_counters.kms_decrypt;
        }
        return p.decrypt_data_key(id, wrapped, c, who);
    }

    /// The current bucket key for (`bucket`, `kms_key_id`), generating one
    /// when there is none or it has lived its lifetime. The KMS call is
    /// made outside the lock; two writers racing both generate, and the
    /// later one is kept, which costs a KMS call and nothing else.
    ///
    /// A cached bucket key was generated as some earlier caller, so a
    /// writer's own `kms:GenerateDataKey` permission is not checked again
    /// while it lives: that is what bucket keys trade on S3 too.
    auto bucket_key_for(const std::string& kms_key_id, std::string_view bucket,
                        const kms_caller& who) -> bucket_key {
        const auto id = std::string(bucket) + '\0' + kms_key_id;
        {
            const std::lock_guard lock(_mutex);
            if (auto it = _writing.find(id);
                it != _writing.end() && now() - it->second.created < bucket_key_lifetime) {
                return it->second;
            }
        }
        auto k = generate(kms, kms_key_id, bucket_context(bucket), who);
        bucket_key bk{std::move(k.plaintext), std::move(k.wrapped), std::move(k.key_id), now()};
        const std::lock_guard lock(_mutex);
        _opened[bk.wrapped] = bk.plaintext;
        _writing[id] = bk;
        return bk;
    }

    /// A stored bucket key's plaintext, from the cache or the KMS.
    auto open_bucket_key(const std::string& key_id, const std::string& wrapped,
                         const encryption_context& context, const kms_caller& who) -> std::string {
        {
            const std::lock_guard lock(_mutex);
            if (auto it = _opened.find(wrapped); it != _opened.end()) {
                return it->second;
            }
        }
        auto key = decrypt(kms, key_id, wrapped, context, who);
        const std::lock_guard lock(_mutex);
        if (_opened.size() >= bucket_key_cache_size) {
            _opened.clear();
        }
        _opened[wrapped] = key;
        return key;
    }

    mutable std::mutex _mutex;
    std::map<std::string, bucket_key> _writing;
    std::map<std::string, std::string> _opened;
    counters _counters;
};

/// The `kms_caller` for a request.
[[nodiscard]] inline auto caller_of(const std::optional<aws_auth::principal_context>& who,
                                    const s3_request& req) -> kms_caller {
    return kms_caller{who, req.source_ip, req.request_id};
}

/// The ETag of an object encrypted with SSE-KMS or SSE-C: S3 gives these
/// no MD5 of the data, and neither does Kythira, since an MD5 of the
/// plaintext would tell anyone listing the bucket which objects hold the
/// same bytes. This is the MD5 of the sealed chunks' names.
[[nodiscard]] inline auto sealed_etag(const std::vector<chunk_ref>& manifest) -> std::string {
    std::string names;
    for (const auto& c : manifest) {
        names.append(reinterpret_cast<const char*>(c.sha.data()), c.sha.size());
    }
    const auto raw = sse_detail::md5_raw(names);
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (unsigned char ch : raw) {
        out.push_back(digits[ch >> 4U]);
        out.push_back(digits[ch & 0xFU]);
    }
    return out;
}

/// Whether an object's ETag must not be an MD5 of its bytes.
[[nodiscard]] inline auto hides_md5(sse_kind k) -> bool {
    return k == sse_kind::kms || k == sse_kind::customer;
}

}  // namespace kythira::s3
