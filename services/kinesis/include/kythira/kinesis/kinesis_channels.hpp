// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file kinesis_channels.hpp
/// @brief Channel catalog records (.kiro/specs/kinesis-compatible-streams/
///        task 19, Requirement 18.1).
///
/// A channel delivers the records of one or more of an account's streams to
/// a general purpose S3 bucket or to Iceberg tables on S3 Tables. Channels
/// are per account, like streams, and live in the catalog range, so the
/// group that allocates stream ids allocates channel ids too and a channel
/// can name its streams by id without a cross-group transaction:
///
/// | Key | Holds |
/// |---|---|
/// | `\0meta/kinesis/channels/<account>/<name>` | a `channel_record` |
///
/// The parts of a channel's configuration that only the delivery worker
/// reads (each stream's record configuration, the destination, encryption
/// and logging) are kept as the canonical JSON the API accepted, with
/// defaults filled in. `DescribeChannel` returns them as they are, and a
/// field the model adds later round-trips without a codec change.

#include <kythira/kinesis/kinesis_catalog.hpp>

#include <raft/static_key_authorizer.hpp>

#include <cstdint>
#include <algorithm>
#include <cstddef>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::kinesis {

/// The static-key roles for `iam:PassRole`, which `CreateChannel` asks for
/// on the channel's service execution role, in the `iam` service a
/// static-key gateway registers next to `kinesis_static_roles()`. A
/// static-key node has no IAM and no roles to check against, so only admin,
/// which may already create and delete every stream, may name one: no
/// read-only or read-write pattern.
[[nodiscard]] inline auto channel_role_static_roles() -> aws_auth::static_role_table {
    return {"iam", {}, {}};
}

[[nodiscard]] inline auto channels_prefix() -> std::string {
    return catalog_prefix() + "channels/";
}

[[nodiscard]] inline auto account_channels_prefix(std::string_view account) -> std::string {
    return channels_prefix() + std::string(account) + "/";
}

[[nodiscard]] inline auto channel_key(std::string_view account, std::string_view name)
    -> std::string {
    return account_channels_prefix(account) + std::string(name);
}

enum class channel_status : std::uint8_t {
    creating = 0,
    active = 1,
    updating = 2,
    deleting = 3,
    failed = 4
};

[[nodiscard]] inline auto channel_status_name(channel_status s) -> std::string_view {
    switch (s) {
        case channel_status::creating:
            return "CREATING";
        case channel_status::active:
            return "ACTIVE";
        case channel_status::updating:
            return "UPDATING";
        case channel_status::deleting:
            return "DELETING";
        case channel_status::failed:
            return "FAILED";
    }
    return "FAILED";
}

enum class channel_destination : std::uint8_t {
    s3 = 0,
    s3_tables = 1
};

[[nodiscard]] inline auto channel_destination_name(channel_destination d) -> std::string_view {
    return d == channel_destination::s3 ? "S3" : "S3_TABLES";
}

/// One source stream. `_stream_id` pins the stream the channel was created
/// on: a stream deleted and created again under the same name has another
/// id, and is not this channel's source.
struct channel_stream {
    std::string _stream{};
    std::uint64_t _stream_id = 0;
    std::int64_t _stream_created_ms = 0;
    /// `RecordConfiguration` as accepted, canonical JSON.
    std::string _record_config{};
    friend auto operator==(const channel_stream&, const channel_stream&) -> bool = default;
};

struct channel_record {
    /// From the catalog's id counter, shared with streams.
    std::uint64_t _id = 0;
    std::string _account{};
    std::string _name{};
    channel_status _status = channel_status::creating;
    std::string _status_reason{};
    /// Leader-stamped when the create was proposed.
    std::int64_t _created_ms = 0;
    std::string _role_arn{};
    channel_destination _destination = channel_destination::s3;
    std::vector<channel_stream> _streams{};
    /// `S3DestinationConfiguration` or `S3TablesDestinationConfiguration`,
    /// whichever `_destination` says, canonical JSON with
    /// `DataFreshnessInSeconds` filled in.
    std::string _destination_config{};
    /// `EncryptionConfiguration`, or empty when the channel has none.
    std::string _encryption_config{};
    /// `LoggingConfiguration`, canonical JSON (logging off when not given).
    std::string _logging_config{};
    std::map<std::string, std::string> _tags{};

    [[nodiscard]] auto delivers_from(std::uint64_t stream_id) const -> bool {
        for (const auto& s : _streams) {
            if (s._stream_id == stream_id) {
                return true;
            }
        }
        return false;
    }

    friend auto operator==(const channel_record&, const channel_record&) -> bool = default;
};

/// `ChannelId`: the catalog id in a UUID's shape. Ids are never reused, so
/// neither is a channel id, and with it a channel ARN.
[[nodiscard]] inline auto channel_id_text(std::uint64_t id) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out = "00000000-0000-4000-8000-000000000000";
    for (std::size_t i = 0; i < 12; ++i) {
        out[out.size() - 1 - i] = digits[(id >> (4U * i)) & 0xFU];
    }
    return out;
}

/// The inverse of `channel_id_text`, for an ARN's resource.
[[nodiscard]] inline auto parse_channel_id(std::string_view text) -> std::optional<std::uint64_t> {
    constexpr std::string_view prefix = "00000000-0000-4000-8000-";
    if (text.size() != prefix.size() + 12 || !text.starts_with(prefix)) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : text.substr(prefix.size())) {
        std::uint64_t d = 0;
        if (c >= '0' && c <= '9') {
            d = static_cast<std::uint64_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            d = static_cast<std::uint64_t>(c - 'a') + 10U;
        } else {
            return std::nullopt;
        }
        v = (v << 4U) | d;
    }
    return v;
}

inline constexpr std::uint8_t channel_record_version = 1;

inline auto encode(codec::writer& w, const channel_record& c) -> void {
    w.u8(channel_record_version).u64(c._id).str(c._account).str(c._name);
    w.u8(static_cast<std::uint8_t>(c._status)).str(c._status_reason).i64(c._created_ms);
    w.str(c._role_arn).u8(static_cast<std::uint8_t>(c._destination));
    w.u32(static_cast<std::uint32_t>(c._streams.size()));
    for (const auto& s : c._streams) {
        w.str(s._stream).u64(s._stream_id).i64(s._stream_created_ms).str(s._record_config);
    }
    w.str(c._destination_config).str(c._encryption_config).str(c._logging_config);
    w.u32(static_cast<std::uint32_t>(c._tags.size()));
    for (const auto& [k, v] : c._tags) {
        w.str(k).str(v);
    }
}

inline auto decode_channel_record(codec::reader& r) -> channel_record {
    if (r.u8() != channel_record_version) {
        throw kinesis_codec_error("kinesis codec: unknown channel record version");
    }
    channel_record c;
    c._id = r.u64();
    c._account = r.str();
    c._name = r.str();
    c._status = r.enumeration<channel_status>(4);
    c._status_reason = r.str();
    c._created_ms = r.i64();
    c._role_arn = r.str();
    c._destination = r.enumeration<channel_destination>(1);
    const auto n = r.u32();
    // Each stream takes at least 28 bytes, so a corrupt count cannot
    // reserve more than the input could hold.
    c._streams.reserve(std::min<std::size_t>(n, r.remaining() / 28));
    for (std::uint32_t i = 0; i < n; ++i) {
        channel_stream s;
        s._stream = r.str();
        s._stream_id = r.u64();
        s._stream_created_ms = r.i64();
        s._record_config = r.str();
        c._streams.push_back(std::move(s));
    }
    c._destination_config = r.str();
    c._encryption_config = r.str();
    c._logging_config = r.str();
    const auto tags = r.u32();
    for (std::uint32_t i = 0; i < tags; ++i) {
        auto k = r.str();
        c._tags[std::move(k)] = r.str();
    }
    return c;
}

[[nodiscard]] inline auto encode_channel_record(const channel_record& c) -> std::vector<std::byte> {
    codec::writer w;
    encode(w, c);
    return w.take();
}

[[nodiscard]] inline auto decode_channel_record(std::span<const std::byte> bytes)
    -> channel_record {
    codec::reader r(bytes);
    auto c = decode_channel_record(r);
    r.expect_end("channel record");
    return c;
}

}  // namespace kythira::kinesis
