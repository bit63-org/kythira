// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_auth.hpp
/// @brief Who sent an S3 request, and its body as the signature vouches for
///        it (.kiro/specs/s3-compatible-storage/ task 6, Requirement 4.2).
///
/// **Authentication.** SigV4 through core `sigv4_verifier` with S3's rules
/// (S3's canonical path, `x-amz-content-sha256` required on header
/// signatures, presigned URLs up to 7 days with `UNSIGNED-PAYLOAD`), in the
/// `Authorization` header or the query string. Every payload mode S3 takes
/// is accepted: a hex SHA-256, `UNSIGNED-PAYLOAD`, and the three
/// `aws-chunked` streaming forms. A request with neither is anonymous;
/// whether an anonymous request may do anything is the access check's
/// business (bucket policy, ACL, Block Public Access), not this one's.
///
/// SigV2 (`Authorization: AWS ...`, or `AWSAccessKeyId` and `Signature` in
/// the query) and SigV4a (`AWS4-ECDSA-P256-SHA256`) are refused with the
/// error S3 gives in regions that never took them, `400 InvalidRequest`
/// asking for AWS4-HMAC-SHA256. The wire evidence (task 1) shows boto3's
/// default presigned URLs are SigV2; that is a client setting
/// (`signature_version='s3v4'`) the documentation will name.
///
/// When the authorizer can resolve a claim's key (`aws_claim_resolver`),
/// authentication is parse, resolve, verify here, and the key is kept for
/// a signed streaming body, whose chunk and trailer signatures chain on
/// the request's. With an authorizer that cannot, `authenticate()` does
/// the work and signed streaming bodies are refused with `501
/// NotImplemented`; the unsigned streaming form, which every recorded
/// client but the JS SDK uses, needs no key.
///
/// **Body.** `payload_reader` turns the body as it arrives into the bytes
/// the signature covers: a hex hash is checked when the body ends
/// (`XAmzContentSHA256Mismatch`), `UNSIGNED-PAYLOAD` passes through, and
/// the streaming forms go through `sigv4::chunk_decoder`, which releases a
/// chunk only once it is whole and, when signed, verified. Trailer values
/// (`x-amz-checksum-*`) are handed over for the checksum layer (task 8).

#include <raft/aws_request_authorizer.hpp>
#include <raft/aws_rest_xml_protocol.hpp>
#include <raft/sigv4_chunk_decoder.hpp>
#include <raft/sigv4_verifier.hpp>

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

enum class auth_kind : std::uint8_t {
    anonymous,
    header,     ///< SigV4 in the Authorization header
    presigned,  ///< SigV4 in the query string
    post,       ///< a browser POST form's policy signature (s3_post_policy.hpp)
};

/// What authentication established.
struct authenticated {
    auth_kind kind = auth_kind::anonymous;
    /// Empty when anonymous.
    std::optional<aws_auth::principal_context> who;
    std::optional<sigv4::claim> claim;
    /// Kept only for a signed streaming body.
    std::optional<sigv4::signing_key> key;
    std::optional<std::int64_t> signature_age_ms;

    [[nodiscard]] auto payload() const -> sigv4::payload_mode {
        return claim ? claim->payload : sigv4::payload_mode::unsigned_payload;
    }
    /// `s3:authType`: `REST-HEADER`, `REST-QUERY-STRING`, `POST`, or empty.
    [[nodiscard]] auto auth_type() const -> std::string {
        switch (kind) {
            case auth_kind::header:
                return "REST-HEADER";
            case auth_kind::presigned:
                return "REST-QUERY-STRING";
            case auth_kind::post:
                return "POST";
            case auth_kind::anonymous:
                break;
        }
        return {};
    }
};

/// S3's SigV4 rules. `regions` empty accepts any region in the scope.
[[nodiscard]] inline auto s3_rules(std::vector<std::string> regions = {}) -> sigv4::service_rules {
    sigv4::service_rules r;
    r.service = "s3";
    r.regions = std::move(regions);
    r.s3_path_rules = true;
    r.protocol = sigv4::error_protocol::s3;
    r.payload_modes.set();
    return r;
}

[[nodiscard]] inline auto to_error(const sigv4::aws_error& e) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(static_cast<unsigned>(e.http_status), e.code, e.message);
}

[[nodiscard]] inline auto unsupported_signature() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(
        400, "InvalidRequest",
        "The authorization mechanism you have provided is not supported. Please use "
        "AWS4-HMAC-SHA256.");
}

namespace auth_detail {

[[nodiscard]] inline auto header(const sigv4::request& req, std::string_view name)
    -> std::optional<std::string_view> {
    for (const auto& [k, v] : req.headers) {
        if (aws_rest_xml::detail::iequals(k, name)) {
            return std::string_view(v);
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline auto query_has(std::string_view raw_query, std::string_view key) -> bool {
    auto q = aws_rest_xml::parse_query(raw_query);
    return q && q->has(key);
}

[[nodiscard]] inline auto is_streaming(sigv4::payload_mode m) -> bool {
    return m == sigv4::payload_mode::streaming_signed ||
           m == sigv4::payload_mode::streaming_signed_trailer ||
           m == sigv4::payload_mode::streaming_unsigned_trailer;
}

[[nodiscard]] inline auto is_signed_streaming(sigv4::payload_mode m) -> bool {
    return m == sigv4::payload_mode::streaming_signed ||
           m == sigv4::payload_mode::streaming_signed_trailer;
}

}  // namespace auth_detail

/// Authenticate `req` (its body need not be there; `payload_reader` checks
/// it). `now` is the clock signatures are judged by.
template<aws_auth::aws_request_authorizer A>
[[nodiscard]] auto authenticate(A& authorizer, const sigv4::request& req,
                                const sigv4::service_rules& rules, std::chrono::sys_seconds now)
    -> aws_rest_xml::result<authenticated> {
    using auth_detail::header;
    authenticated out;
    const auto authz = header(req, "authorization");
    const auto q_algorithm = [&]() -> std::optional<std::string> {
        auto q = aws_rest_xml::parse_query(req.raw_query);
        return q ? q->get("X-Amz-Algorithm") : std::nullopt;
    }();
    if (authz) {
        if (authz->starts_with("AWS ") || authz->starts_with("AWS4-ECDSA-P256-SHA256")) {
            return unsupported_signature();
        }
        out.kind = auth_kind::header;
    } else if (q_algorithm) {
        if (*q_algorithm == "AWS4-ECDSA-P256-SHA256") {
            return unsupported_signature();
        }
        out.kind = auth_kind::presigned;
    } else if (auth_detail::query_has(req.raw_query, "AWSAccessKeyId") &&
               auth_detail::query_has(req.raw_query, "Signature")) {
        return unsupported_signature();
    } else {
        return out;  // anonymous
    }

    auto parsed = sigv4::parse(req, rules, now);
    if (!parsed) {
        return to_error(parsed.error());
    }
    const auto& c = *parsed;
    if constexpr (aws_auth::aws_claim_resolver<A>) {
        auto r = authorizer.resolve(c, rules.protocol);
        if (!r) {
            return to_error(r.error());
        }
        if (!sigv4::verify(c, r->key)) {
            return to_error(sigv4::signature_mismatch(rules.protocol));
        }
        out.who = r->who;
        if (auth_detail::is_signed_streaming(c.payload)) {
            out.key = r->key;
        }
    } else {
        if (auth_detail::is_signed_streaming(c.payload)) {
            return aws_rest_xml::errors::make(
                501, "NotImplemented",
                "Signed streaming uploads need an authorizer that can resolve signing keys.");
        }
        auto who = authorizer.authenticate(req, rules);
        if (!who) {
            return to_error(who.error());
        }
        out.who = *who;
    }
    out.signature_age_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - c.timestamp).count();
    out.claim = c;
    return out;
}

/// The body as the signature covers it.
class payload_reader {
public:
    /// `req` is the request `auth` came from (for `x-amz-trailer` and
    /// `x-amz-decoded-content-length`).
    payload_reader(const authenticated& auth, const sigv4::request& req,
                   sigv4::chunk_limits limits = {})
        : _mode(auth.payload()) {
        if (auth.claim && auth_detail::is_streaming(_mode)) {
            _chunks =
                std::make_unique<sigv4::chunk_decoder>(*auth.claim, auth.key ? &*auth.key : nullptr,
                                                       req, sigv4::error_protocol::s3, limits);
            if (_chunks->state() == sigv4::chunk_decoder::status::failed) {
                _error = to_error(_chunks->error());
            }
        } else if (auth.claim && _mode == sigv4::payload_mode::hex_hash) {
            _expected = auth.claim->payload_hash;
            _sha.reset(::EVP_MD_CTX_new());
            if (!_sha || ::EVP_DigestInit_ex(_sha.get(), ::EVP_sha256(), nullptr) != 1) {
                _error = aws_rest_xml::errors::make(500, "InternalError", "SHA-256 init failed");
            }
        }
    }

    /// Consume `in`, appending the bytes it vouches for to `out`. An error
    /// is final.
    auto feed(std::string_view in, std::string& out) -> std::optional<aws_rest_xml::error> {
        if (_error) {
            return _error;
        }
        if (_chunks) {
            if (_chunks->feed(in, out) == sigv4::chunk_decoder::status::failed) {
                _error = to_error(_chunks->error());
            }
            return _error;
        }
        if (_sha && !in.empty() && ::EVP_DigestUpdate(_sha.get(), in.data(), in.size()) != 1) {
            _error = aws_rest_xml::errors::make(500, "InternalError", "SHA-256 update failed");
            return _error;
        }
        out.append(in);
        return std::nullopt;
    }

    /// The body ended: check what can only be checked now.
    auto finish() -> std::optional<aws_rest_xml::error> {
        if (_error) {
            return _error;
        }
        if (_chunks) {
            if (_chunks->finish() != sigv4::chunk_decoder::status::done) {
                _error = to_error(_chunks->error());
            }
            return _error;
        }
        if (_sha) {
            std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
            unsigned int len = 0;
            if (::EVP_DigestFinal_ex(_sha.get(), md.data(), &len) != 1) {
                _error = aws_rest_xml::errors::make(500, "InternalError", "SHA-256 final failed");
                return _error;
            }
            _sha.reset();
            if (sigv4::detail::to_hex(std::span<const unsigned char>(md.data(), len)) !=
                _expected) {
                _error = aws_rest_xml::errors::make(
                    400, "XAmzContentSHA256Mismatch",
                    "The provided 'x-amz-content-sha256' header does not match what was "
                    "computed.");
            }
        }
        return _error;
    }

    /// Trailer headers of a streaming body, once it is done.
    [[nodiscard]] auto trailers() const -> std::vector<std::pair<std::string, std::string>> {
        return _chunks ? _chunks->trailers() : std::vector<std::pair<std::string, std::string>>{};
    }

private:
    struct free_ctx {
        void operator()(EVP_MD_CTX* c) const noexcept { ::EVP_MD_CTX_free(c); }
    };

    sigv4::payload_mode _mode;
    std::unique_ptr<sigv4::chunk_decoder> _chunks;
    std::unique_ptr<EVP_MD_CTX, free_ctx> _sha;
    std::string _expected;
    std::optional<aws_rest_xml::error> _error;
};

}  // namespace kythira::s3
