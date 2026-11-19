// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_message.hpp
/// @brief A published message as the front end writes it into a publish
///        log record (`.kiro/specs/sns-compatible-notifications/` task 4,
///        Requirements 5.1 and 5.2).
///
/// The topic state machine stores a record's payload without looking at it
/// (`stored_message::_payload`). This is that payload: what delivery (task
/// 6) needs to build each protocol's request, decided once at publish time
/// so every delivery of a message carries the same body, subject,
/// attributes and timestamp. Under server-side encryption (task 8) the
/// front end seals these bytes with the topic's data key before
/// publishing, so the layout stays private to the front end and delivery.

#include <kythira/sns/sns_codec.hpp>
#include <kythira/sns/sns_query.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kythira::sns {

struct published_message {
    /// `Message` exactly as published. With `_json_structure`, a JSON
    /// object whose `default` member is the body for protocols without
    /// their own member.
    std::string _message{};
    bool _json_structure = false;
    std::optional<std::string> _subject{};
    message_attributes _attributes{};
    /// The leader's clock at publish, the `Timestamp` every delivery shows.
    std::int64_t _timestamp_ms = 0;
    /// The account that published.
    std::string _publisher{};

    friend auto operator==(const published_message&, const published_message&) -> bool = default;
};

inline constexpr std::uint8_t k_published_message_version = 1;

[[nodiscard]] inline auto encode_published_message(const published_message& m)
    -> std::vector<std::byte> {
    codec::writer w;
    w.u8(k_published_message_version)
        .str(m._message)
        .boolean(m._json_structure)
        .boolean(m._subject.has_value())
        .str(m._subject.value_or(""))
        .i64(m._timestamp_ms)
        .str(m._publisher)
        .u32(static_cast<std::uint32_t>(m._attributes.size()));
    for (const auto& [name, a] : m._attributes) {
        w.str(name)
            .str(a._data_type)
            .boolean(a._string_value.has_value())
            .str(a._string_value.value_or(""))
            .boolean(a._binary_value.has_value())
            .str(a._binary_value.value_or(""));
    }
    return w.take();
}

[[nodiscard]] inline auto decode_published_message(std::span<const std::byte> bytes)
    -> published_message {
    codec::reader r(bytes);
    if (r.u8() != k_published_message_version) {
        throw sns_codec_error("sns codec: unknown published message version");
    }
    published_message m;
    m._message = r.str();
    m._json_structure = r.boolean();
    const bool has_subject = r.boolean();
    auto subject = r.str();
    if (has_subject) {
        m._subject = std::move(subject);
    }
    m._timestamp_ms = r.i64();
    m._publisher = r.str();
    const auto n = r.count(4 + 4 + 1 + 4 + 1 + 4);
    for (std::uint32_t i = 0; i < n; ++i) {
        auto name = r.str();
        message_attribute a;
        a._data_type = r.str();
        const bool has_string = r.boolean();
        auto s = r.str();
        const bool has_binary = r.boolean();
        auto b = r.str();
        if (has_string) {
            a._string_value = std::move(s);
        }
        if (has_binary) {
            a._binary_value = std::move(b);
        }
        m._attributes.emplace(std::move(name), std::move(a));
    }
    r.expect_end("published message");
    return m;
}

}  // namespace kythira::sns
