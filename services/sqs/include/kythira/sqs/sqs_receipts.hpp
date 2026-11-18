// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_receipts.hpp
/// @brief Receipt handles (`.kiro/specs/sqs-compatible-queues/` design
///        "Receipt handles", Requirement 5.1): stateless HMAC-SHA256 tokens
///        any front end can check.
///
/// A handle names the queue (the catalog's queue id, so a handle for a
/// deleted and recreated queue is refused), the partition, the message's
/// sequence and the receive that issued it, and when that receive's
/// visibility ends. Nothing about a handle is stored: the state machine
/// accepts a delete or visibility change only while the handle's receive
/// sequence is the message's latest (`receipt_ref`), so a handle from an
/// earlier receive is stale, never wrong.
///
/// A handle that does not open (bad base64, unknown key, MAC mismatch, a
/// different queue) is `ReceiptHandleIsInvalid`. One that opens but is
/// stale is accepted and ignored by DeleteMessage and refused by
/// ChangeMessageVisibility, as SQS does; that is the state machine's call.
///
/// Keys. Handles are signed with the first key of a `receipt_key_ring` and
/// checked with whichever key the handle's key id names, so an operator
/// rotates by putting a new key first and keeping the old one for at least
/// the longest visibility timeout (12 hours). Every front end of a cluster
/// holds the same ring, from `SQS_RECEIPT_KEYS_FILE` (`parse_receipt_keys`)
/// or, without one, derived from the forwarding secret all nodes share
/// (`derived_receipt_key`), as Kinesis does for its iterators.
///
/// Wire, before base64: version 1 (u8), key id (u32), queue id (u64),
/// partition (u16), sequence (u64), receive sequence (u64), visible-at in
/// epoch milliseconds (u64), then the 32-byte MAC over everything before
/// it; integers big-endian. 71 bytes, 96 characters of base64.

#include <raft/aws_json_protocol.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::sqs {

struct receipt_key {
    std::uint32_t _id = 0;
    std::string _secret;
};

/// The keys every front end shares; the first signs.
struct receipt_key_ring {
    std::vector<receipt_key> _keys;

    [[nodiscard]] auto find(std::uint32_t id) const -> const receipt_key* {
        for (const auto& k : _keys) {
            if (k._id == id) {
                return &k;
            }
        }
        return nullptr;
    }
};

struct receipt_handle {
    std::uint64_t _queue_id = 0;
    std::uint16_t _partition = 0;
    std::uint64_t _sequence = 0;
    std::uint64_t _receive_sequence = 0;
    std::uint64_t _visible_at_ms = 0;

    friend auto operator==(const receipt_handle&, const receipt_handle&) -> bool = default;
};

namespace receipt_detail {

inline constexpr std::uint8_t k_version = 1;
inline constexpr std::size_t k_mac_bytes = 32;
inline constexpr std::size_t k_body_bytes = 1 + 4 + 8 + 2 + 8 + 8 + 8;

inline void put_u(std::string& out, std::uint64_t v, int bytes) {
    for (int i = bytes - 1; i >= 0; --i) {
        out += static_cast<char>((v >> (8U * static_cast<unsigned>(i))) & 0xFFU);
    }
}

[[nodiscard]] inline auto get_u(std::string_view in, std::size_t& at, int bytes) -> std::uint64_t {
    std::uint64_t v = 0;
    for (int i = 0; i < bytes; ++i) {
        v = (v << 8U) | static_cast<unsigned char>(in[at++]);
    }
    return v;
}

[[nodiscard]] inline auto mac(std::string_view key, std::string_view text)
    -> std::array<unsigned char, k_mac_bytes> {
    std::array<unsigned char, k_mac_bytes> out{};
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(text.data()),  // NOLINT
         text.size(), out.data(), &len);
    return out;
}

}  // namespace receipt_detail

/// The receipt key file: one key per line, `<id> <secret>`, the id a
/// decimal u32 and the secret at least 16 bytes with no blanks. The first
/// key signs; later ones only verify. Blank lines and `#` lines are
/// skipped. A bad line fails the file with its line number and without
/// echoing it.
[[nodiscard]] inline auto parse_receipt_keys(std::string_view text) -> receipt_key_ring {
    receipt_key_ring ring;
    std::size_t line_no = 0;
    while (!text.empty()) {
        ++line_no;
        const auto nl = text.find('\n');
        auto line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view() : text.substr(nl + 1);
        std::vector<std::string_view> fields;
        std::size_t i = 0;
        while (i < line.size()) {
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) {
                ++i;
            }
            const auto start = i;
            while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') {
                ++i;
            }
            if (i > start) {
                fields.push_back(line.substr(start, i - start));
            }
        }
        if (fields.empty() || fields.front().starts_with('#')) {
            continue;
        }
        const auto where = "receipt keys line " + std::to_string(line_no) + ": ";
        if (fields.size() != 2) {
            throw std::invalid_argument(where + "expected 2 fields (id, secret), found " +
                                        std::to_string(fields.size()));
        }
        std::uint64_t id = 0;
        bool ok = !fields[0].empty() && fields[0].size() <= 10;
        for (const char c : fields[0]) {
            ok = ok && c >= '0' && c <= '9';
            id = id * 10 + static_cast<std::uint64_t>(c - '0');
        }
        if (!ok || id > UINT32_MAX) {
            throw std::invalid_argument(where + "id must be a number up to 4294967295");
        }
        if (fields[1].size() < 16) {
            throw std::invalid_argument(where + "secret must be at least 16 bytes");
        }
        if (ring.find(static_cast<std::uint32_t>(id)) != nullptr) {
            throw std::invalid_argument(where + "id " + std::to_string(id) + " repeats");
        }
        ring._keys.push_back(
            {._id = static_cast<std::uint32_t>(id), ._secret = std::string(fields[1])});
    }
    if (ring._keys.empty()) {
        throw std::invalid_argument("receipt keys: no key");
    }
    return ring;
}

/// The one-key ring derived from the forwarding secret every node of a
/// cluster shares: HMAC-SHA256(secret, "kythira-sqs-receipt-key-v1"), key
/// id 0. Changing the forwarding secret invalidates outstanding handles:
/// their messages become visible again when their timeouts end.
[[nodiscard]] inline auto derived_receipt_key(std::string_view forward_secret) -> receipt_key_ring {
    const auto m = receipt_detail::mac(forward_secret, "kythira-sqs-receipt-key-v1");
    receipt_key_ring ring;
    ring._keys.push_back({._id = 0, ._secret = std::string(m.begin(), m.end())});
    return ring;
}

/// The base64 handle for `h`, signed with the ring's first key. Throws
/// `std::invalid_argument` on an empty ring.
[[nodiscard]] inline auto encode_receipt(const receipt_handle& h, const receipt_key_ring& ring)
    -> std::string {
    using namespace receipt_detail;
    if (ring._keys.empty()) {
        throw std::invalid_argument("sqs: no receipt key");
    }
    const auto& key = ring._keys.front();
    std::string text;
    text += static_cast<char>(k_version);
    put_u(text, key._id, 4);
    put_u(text, h._queue_id, 8);
    put_u(text, h._partition, 2);
    put_u(text, h._sequence, 8);
    put_u(text, h._receive_sequence, 8);
    put_u(text, h._visible_at_ms, 8);
    const auto m = mac(key._secret, text);
    text.append(reinterpret_cast<const char*>(m.data()), m.size());  // NOLINT
    return aws_json::base64_encode(std::as_bytes(std::span<const char>(text.data(), text.size())));
}

/// The handle `token` names, if a key of `ring` signed it for queue
/// `queue_id`; nullopt for anything else. The MAC is checked before
/// anything in the token is trusted, and in constant time.
[[nodiscard]] inline auto decode_receipt(std::string_view token, std::uint64_t queue_id,
                                         const receipt_key_ring& ring)
    -> std::optional<receipt_handle> {
    using namespace receipt_detail;
    const auto raw = aws_json::base64_decode(token);
    if (!raw || raw->size() != k_body_bytes + k_mac_bytes) {
        return std::nullopt;
    }
    const std::string_view text(reinterpret_cast<const char*>(raw->data()),  // NOLINT
                                k_body_bytes);
    std::size_t at = 0;
    if (static_cast<std::uint8_t>(text[at++]) != k_version) {
        return std::nullopt;
    }
    const auto* key = ring.find(static_cast<std::uint32_t>(get_u(text, at, 4)));
    if (key == nullptr) {
        return std::nullopt;
    }
    const auto want = mac(key->_secret, text);
    if (CRYPTO_memcmp(want.data(), raw->data() + k_body_bytes, k_mac_bytes) != 0) {
        return std::nullopt;
    }
    receipt_handle h;
    h._queue_id = get_u(text, at, 8);
    h._partition = static_cast<std::uint16_t>(get_u(text, at, 2));
    h._sequence = get_u(text, at, 8);
    h._receive_sequence = get_u(text, at, 8);
    h._visible_at_ms = get_u(text, at, 8);
    if (h._queue_id != queue_id) {
        return std::nullopt;
    }
    return h;
}

}  // namespace kythira::sqs
