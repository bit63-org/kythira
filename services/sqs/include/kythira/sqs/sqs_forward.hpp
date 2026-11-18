// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_forward.hpp
/// @brief Node-to-node forwarding of SQS entries to a group's leader
///        (`.kiro/specs/sqs-compatible-queues/` task 4).
///
/// Any node takes any request. An entry whose group this node does not lead
/// is proposed by the leader instead: this node sends the encoded catalog
/// or partition entry to the leader's listener, which stamps it with its
/// own clock, proposes it and answers what `apply()` returned. Only the
/// entry crosses, not the client's request, so the leader neither
/// re-authenticates the client nor re-parses its body, and the client's
/// answer is still worded by the node it called.
///
/// The endpoint is `POST /_kythira/sqs/v1/propose` on the SQS listener. It
/// is not an AWS operation: it carries no SigV4 and is authenticated with
/// an HMAC-SHA256 over a timestamp and the body, under the forwarding
/// secret every node of the cluster shares (`SQS_FORWARD_SECRET`, which
/// also derives the default receipt key, `sqs_receipts.hpp`). A request
/// more than 60 seconds old or new is refused, so a captured one cannot be
/// replayed later. A forwarded entry is never forwarded again: a node that
/// has stopped leading answers 503 and the first node fails the request as
/// retryable.
///
/// Wire: body = u32 key length (big-endian), key bytes, entry bytes.
/// Header `x-kythira-forward: <unix seconds>:<hex HMAC>`. The same shape as
/// the Kinesis module's forwarding, so operators read one scheme.

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::sqs::forward {

inline constexpr std::string_view k_path = "/_kythira/sqs/v1/propose";
inline constexpr std::string_view k_header = "x-kythira-forward";
inline constexpr std::chrono::seconds k_max_skew{60};

struct proposal {
    std::string _key;
    std::vector<std::byte> _entry;
};

[[nodiscard]] inline auto encode_body(const proposal& p) -> std::string {
    std::string out;
    const auto n = static_cast<std::uint32_t>(p._key.size());
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((n >> static_cast<unsigned>(shift)) & 0xFFU));
    }
    out += p._key;
    for (const auto b : p._entry) {
        out.push_back(static_cast<char>(b));
    }
    return out;
}

[[nodiscard]] inline auto decode_body(std::string_view body) -> std::optional<proposal> {
    if (body.size() < 4) {
        return std::nullopt;
    }
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        n = (n << 8U) | static_cast<unsigned char>(body[i]);
    }
    if (body.size() - 4 <= n) {
        return std::nullopt;
    }
    proposal p;
    p._key = std::string(body.substr(4, n));
    const auto rest = body.substr(4 + n);
    p._entry.reserve(rest.size());
    for (const char c : rest) {
        p._entry.push_back(static_cast<std::byte>(c));
    }
    return p;
}

[[nodiscard]] inline auto mac_hex(std::string_view secret, std::int64_t unix_seconds,
                                  std::string_view body) -> std::string {
    const auto message = std::to_string(unix_seconds) + "\n" + std::string(body);
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(message.data()),  // NOLINT
         message.size(), mac.data(), &len);
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(hex[(mac.at(i) >> 4U) & 0xFU]);
        out.push_back(hex[mac.at(i) & 0xFU]);
    }
    return out;
}

/// The `x-kythira-forward` value for `body` at `now`.
[[nodiscard]] inline auto sign(std::string_view secret, std::string_view body,
                               std::chrono::system_clock::time_point now) -> std::string {
    const auto t = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return std::to_string(t) + ":" + mac_hex(secret, t, body);
}

/// True when `header` signs `body` under `secret` within the skew window.
/// An empty secret verifies nothing.
[[nodiscard]] inline auto verify(std::string_view secret, std::string_view header,
                                 std::string_view body, std::chrono::system_clock::time_point now)
    -> bool {
    if (secret.empty()) {
        return false;
    }
    const auto colon = header.find(':');
    if (colon == std::string_view::npos || colon == 0 || colon > 18) {
        return false;
    }
    std::int64_t t = 0;
    for (const char c : header.substr(0, colon)) {
        if (c < '0' || c > '9') {
            return false;
        }
        t = t * 10 + (c - '0');
    }
    const auto now_s =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    if (std::llabs(now_s - t) > k_max_skew.count()) {
        return false;
    }
    const auto want = mac_hex(secret, t, body);
    const auto got = header.substr(colon + 1);
    return got.size() == want.size() && CRYPTO_memcmp(got.data(), want.data(), want.size()) == 0;
}

}  // namespace kythira::sqs::forward
