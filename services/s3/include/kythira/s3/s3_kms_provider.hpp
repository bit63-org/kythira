// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_kms_provider.hpp
/// @brief SSE-KMS through a KMS's JSON API (.kiro/specs/s3-compatible-storage/
///        task 11, Requirement 11.1): the `kythira` and `aws` providers.
///
/// `kms_api_provider` makes `GenerateDataKey` and `Decrypt` calls in the
/// AWS KMS JSON protocol through a `kms_call`, which sends one operation's
/// body for a caller and returns the HTTP status and JSON answer. Kythira's
/// KMS and AWS KMS speak the same protocol, so one provider serves both;
/// what differs is the transport the daemon hands it (task 16): core's
/// `kms_endpoint` (the co-located KMS module's in-process client, or
/// `kms_https_endpoint` to a KMS on another cluster, both of which forward
/// the end caller so the KMS authorizes them through S3 with
/// `kms:ViaService`), or a SigV4 client for AWS KMS. Keeping the
/// transport a function leaves this header free of the module interfaces,
/// so the module's tests build it without a node.
///
/// Errors map by the answer's `__type`: `NotFoundException`,
/// `DisabledException`, `KMSInvalidStateException`, `AccessDeniedException`
/// and `InvalidCiphertextException` to the matching `kms_failure`; anything
/// else, and a call that throws, is `unavailable` (503).

#include <kythira/s3/s3_encryption.hpp>

#include <boost/json.hpp>

#include <functional>
#include <string>
#include <utility>

namespace kythira::s3 {

/// One KMS operation's answer.
struct kms_answer {
    int status = 0;
    std::string body;
};

/// Sends `operation` ("GenerateDataKey") with its JSON `body` for `who`.
using kms_call = std::function<kms_answer(const std::string& operation, const std::string& body,
                                          const kms_caller& who)>;

class kms_api_provider {
public:
    explicit kms_api_provider(kms_call call) : _call(std::move(call)) {
        if (!_call) {
            throw std::invalid_argument("s3 kms provider: needs a transport");
        }
    }

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context,
                                         const kms_caller& who) const -> generated_data_key {
        boost::json::object req{{"KeyId", key_id}, {"KeySpec", "AES_256"}};
        req["EncryptionContext"] = context_object(context);
        const auto res = send("GenerateDataKey", req, who);
        generated_data_key out;
        out.plaintext = blob(res, "Plaintext");
        out.wrapped = blob(res, "CiphertextBlob");
        out.key_id = text(res, "KeyId");
        if (out.plaintext.size() != chunk_cipher::key_bytes || out.wrapped.empty()) {
            throw kms_error(kms_failure::unavailable, "KMS returned no usable data key");
        }
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context,
                                        const kms_caller& who) const -> std::string {
        boost::json::object req{{"KeyId", key_id}, {"CiphertextBlob", sse_detail::b64(wrapped)}};
        req["EncryptionContext"] = context_object(context);
        const auto res = send("Decrypt", req, who);
        auto key = blob(res, "Plaintext");
        if (key.size() != chunk_cipher::key_bytes) {
            throw kms_error(kms_failure::invalid_ciphertext, "KMS returned no 256-bit key");
        }
        return key;
    }

private:
    [[nodiscard]] static auto context_object(const encryption_context& c) -> boost::json::object {
        boost::json::object o;
        for (const auto& [k, v] : c) {
            o[k] = v;
        }
        return o;
    }

    [[nodiscard]] auto send(const std::string& op, const boost::json::object& req,
                            const kms_caller& who) const -> boost::json::object {
        kms_answer a;
        try {
            a = _call(op, boost::json::serialize(req), who);
        } catch (const std::exception& e) {
            throw kms_error(kms_failure::unavailable, std::string("KMS unreachable: ") + e.what());
        }
        boost::system::error_code ec;
        auto v = boost::json::parse(a.body, ec);
        const auto* o = !ec ? v.if_object() : nullptr;
        if (a.status == 200 && o != nullptr) {
            return *o;
        }
        std::string type;
        std::string message = "KMS answered " + std::to_string(a.status);
        if (o != nullptr) {
            if (const auto* t = o->if_contains("__type"); t != nullptr && t->is_string()) {
                type = std::string(t->as_string());
                // "com.amazonaws.kms#NotFoundException" on some transports.
                if (const auto hash = type.rfind('#'); hash != std::string::npos) {
                    type = type.substr(hash + 1);
                }
            }
            for (const auto* name : {"message", "Message"}) {
                if (const auto* m = o->if_contains(name); m != nullptr && m->is_string()) {
                    message = std::string(m->as_string());
                }
            }
        }
        const auto failure = type == "NotFoundException"          ? kms_failure::not_found
                             : type == "DisabledException"        ? kms_failure::disabled
                             : type == "KMSInvalidStateException" ? kms_failure::invalid_state
                             : type == "AccessDeniedException"    ? kms_failure::access_denied
                             : type == "InvalidCiphertextException"
                                 ? kms_failure::invalid_ciphertext
                                 : kms_failure::unavailable;
        throw kms_error(failure, message);
    }

    [[nodiscard]] static auto text(const boost::json::object& o, const char* name) -> std::string {
        const auto* v = o.if_contains(name);
        return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string{};
    }

    [[nodiscard]] static auto blob(const boost::json::object& o, const char* name) -> std::string {
        return sse_detail::unb64(text(o, name)).value_or(std::string{});
    }

    kms_call _call;
};

static_assert(s3_key_provider<kms_api_provider>);

}  // namespace kythira::s3
