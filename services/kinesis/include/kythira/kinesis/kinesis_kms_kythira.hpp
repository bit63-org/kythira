// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_kms_kythira.hpp
/// @brief A `kms_key_provider` over Kythira's KMS (`.kiro/specs/kms-compatible-api/`
///        task 15, Requirement 11.1): `KINESIS_KMS=kythira`.
///
/// Each call goes through the `kms.client` endpoint (raft/module_interfaces.hpp):
/// in process when the KMS module runs in the same node, over HTTPS with
/// SigV4 when it runs on another cluster (raft/kms_https_client.hpp). Either
/// way the KMS authorizes the Kinesis request's own caller, with
/// `kms:ViaService` set to `kinesis.<region>.amazonaws.com`, never the
/// gateway: a key policy that denies a role denies it through Kinesis too.
///
/// A data key comes from `GenerateDataKey` (`AES_256`) and is unwrapped with
/// `Decrypt`, both with the stream's encryption context. The wrapped key is
/// the KMS's ciphertext blob, and the provider's id for it is the key ARN
/// the KMS answers, so a stream started with an alias keeps decrypting after
/// the alias moves. KMS errors map as `aws_kms_provider` maps AWS's.

#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_kms_aws.hpp>

#include <raft/module_interfaces.hpp>

#include <boost/json.hpp>

#include <openssl/crypto.h>

#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kinesis {

class kythira_kms_provider {
public:
    /// The KMS client, found once the node's modules have started; null
    /// when no KMS is reachable (every call then answers `unavailable`).
    using endpoint_fn = std::function<std::shared_ptr<service_node::kms_endpoint>()>;

    explicit kythira_kms_provider(endpoint_fn endpoint) : _endpoint(std::move(endpoint)) {}

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context,
                                         const kms_caller& caller) const -> generated_data_key {
        boost::json::object req{{"KeyId", key_id}, {"KeySpec", "AES_256"}};
        add_context(req, context);
        auto res = call("GenerateDataKey", req, caller);
        generated_data_key out;
        auto plain = blob(res, "Plaintext");
        if (plain.size() != out._plaintext.size()) {
            OPENSSL_cleanse(plain.data(), plain.size());
            throw kms_error(kms_failure::invalid_state,
                            "KMS returned a data key of the wrong size.");
        }
        std::memcpy(out._plaintext.data(), plain.data(), plain.size());
        OPENSSL_cleanse(plain.data(), plain.size());
        out._wrapped = blob(res, "CiphertextBlob");
        const auto* id = res.if_contains("KeyId");
        out._key_id = id != nullptr && id->is_string() ? std::string(id->get_string()) : key_id;
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context,
                                        const kms_caller& caller) const -> data_key_bytes {
        boost::json::object req{{"KeyId", key_id},
                                {"CiphertextBlob", kms_aws_detail::base64_encode(wrapped)}};
        add_context(req, context);
        auto res = call("Decrypt", req, caller);
        auto plain = blob(res, "Plaintext");
        data_key_bytes out{};
        if (plain.size() != out.size()) {
            OPENSSL_cleanse(plain.data(), plain.size());
            throw kms_error(kms_failure::invalid_state,
                            "KMS returned a data key of the wrong size.");
        }
        std::memcpy(out.data(), plain.data(), out.size());
        OPENSSL_cleanse(plain.data(), plain.size());
        return out;
    }

private:
    endpoint_fn _endpoint;

    static void add_context(boost::json::object& req, const encryption_context& context) {
        if (context.empty()) {
            return;
        }
        boost::json::object c;
        for (const auto& [k, v] : context) {
            c[k] = v;
        }
        req["EncryptionContext"] = std::move(c);
    }

    [[nodiscard]] static auto blob(const boost::json::object& res, std::string_view name)
        -> std::string {
        const auto* v = res.if_contains(name);
        if (v == nullptr || !v->is_string()) {
            throw kms_error(kms_failure::invalid_state,
                            "KMS answered without " + std::string(name) + ".");
        }
        auto decoded = kms_aws_detail::base64_decode(v->get_string());
        if (!decoded) {
            throw kms_error(kms_failure::invalid_state,
                            "KMS answered with a malformed " + std::string(name) + ".");
        }
        return std::move(*decoded);
    }

    [[nodiscard]] auto call(std::string_view operation, const boost::json::object& req,
                            const kms_caller& caller) const -> boost::json::object {
        if (caller._principal == nullptr) {
            // Kinesis always names its caller; a call without one would
            // have only the gateway's authority, which the KMS refuses.
            throw kms_error(kms_failure::access_denied, "No caller for the KMS call.");
        }
        const auto endpoint = _endpoint ? _endpoint() : nullptr;
        if (!endpoint) {
            throw kms_error(kms_failure::unavailable, "No KMS is reachable from this endpoint.");
        }
        service_node::caller who;
        who.module = "kinesis";
        const auto res =
            endpoint->call(who, service_node::kms_request{.operation = std::string(operation),
                                                          .body = boost::json::serialize(req),
                                                          .principal = *caller._principal,
                                                          .via_service = "kinesis",
                                                          .source_ip = caller._source_ip});
        boost::json::object parsed;
        try {
            auto v = boost::json::parse(res.body);
            if (v.is_object()) {
                parsed = std::move(v.get_object());
            }
        } catch (const std::exception&) {
            // An unparseable body is judged by its status below.
        }
        if (res.status == 200) {
            return parsed;
        }
        std::string type;
        if (const auto* t = parsed.if_contains("__type"); t != nullptr && t->is_string()) {
            type = std::string(t->get_string());
        }
        std::string message = "KMS answered " + std::to_string(res.status);
        for (const auto* key : {"message", "Message"}) {
            if (const auto* m = parsed.if_contains(key); m != nullptr && m->is_string()) {
                message = std::string(m->get_string());
            }
        }
        // A KMS that answers 503 (stopping, or no leader yet) is not a
        // missing key: KMSInvalidStateException, which clients retry.
        throw kms_error(kms_aws_detail::failure_of(type), message);
    }
};

static_assert(per_caller_kms_key_provider<kythira_kms_provider>);

}  // namespace kythira::kinesis
