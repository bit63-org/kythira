// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file kinesis_channel_delivery.hpp
/// @brief The channel delivery worker for general purpose S3 destinations
///        (`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement
///        18.2-18.3).
///
/// Every node runs `run_once()` on the maintenance timer. For each ACTIVE
/// channel and each shard of each of its source streams, the node that
/// leads the shard's group:
///
/// 1. reads the shard from the channel's checkpoint for it (a plain u64
///    catalog entry, the next counter to deliver), or, with none yet, from
///    the first record that arrived at or after the channel was created;
/// 2. once the oldest undelivered record is `DataFreshnessInSeconds` old,
///    the batch reached `_max_object_bytes`, or a closed shard has nothing
///    more, writes the batch as one object to the destination bucket;
/// 3. proposes the checkpoint move (`channel_checkpoint_command`), which
///    commits only from the position it read, so of two nodes that both
///    believed they led, one commits and the other's object is a
///    duplicate that the next one's key overwrites.
///
/// Delivery is at least once and in sequence order within a shard. An
/// object's key names the shard and its first and last sequence numbers
/// and its time path comes from the first record's arrival, so a batch
/// retried with the same records after a failed checkpoint lands on the
/// same key. A retry that read further (more records arrived meanwhile)
/// writes a longer object starting at the same sequence number, which
/// repeats the earlier object's records. A child shard
/// is delivered only once its parents' checkpoints passed their ending
/// counters, so a key's records arrive in order across a reshard.
///
/// Object layout, one record per line:
///
/// | RecordFormatType | Line |
/// |---|---|
/// | `JSON` | the record's bytes, which must parse as JSON |
/// | `STRING` | the record's bytes |
/// | `BYTE_ARRAY` | the record's bytes, base64 |
///
/// A `JSON` record that does not parse goes to the dead-letter location
/// (the configured one, or the destination bucket under `errors/`) as a
/// JSON line with the error, the sequence number and the bytes in base64.
///
/// Compression: `NONE`, `GZIP` (when zlib was found at build time) and
/// `ZSTD` (when libzstd was). A channel whose compression this build cannot
/// write is set to FAILED with the reason, rather than silently not
/// delivering.
///
/// Encryption (Requirement 18.4): a channel with an `EncryptionConfiguration`
/// has each object and dead letter sealed after compression under a data
/// key from the node's key provider (`channel_encryption::envelope`, see
/// `channel_detail::seal_object`), or asks S3 for SSE-KMS under its key
/// (`channel_encryption::sse_kms`, and always for S3 Tables).

#include <kythira/kinesis/kinesis_avro.hpp>
#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_iceberg.hpp>
#include <kythira/kinesis/kinesis_iceberg_rest.hpp>
#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_parquet.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>

#include <boost/json.hpp>

#include <openssl/sha.h>

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
#include <zlib.h>
#endif
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
#include <zstd.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <exception>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis {

/// What a channel write asks of the bucket beyond the bytes: the
/// destination's `StorageClass` and `ExpectedBucketOwner` (empty: not
/// sent).
struct channel_put_options {
    std::string _storage_class;
    std::string _expected_owner;
    /// User metadata (`x-amz-meta-<name>`, by `<name>`): an envelope-sealed
    /// object's wrapped data key and nonce (`channel_detail::seal_object`).
    std::map<std::string, std::string> _metadata{};
    /// Asks S3 to encrypt the object with SSE-KMS under this key
    /// (`x-amz-server-side-encryption: aws:kms`); nullopt asks nothing.
    std::optional<std::string> _sse_kms_key_id{};
};

/// How a node carries out a channel's `EncryptionConfiguration`
/// (`KINESIS_CHANNEL_ENCRYPTION`) for general purpose S3 destinations.
/// S3 Tables destinations always ask for SSE-KMS: an Iceberg reader opens
/// data files straight from storage, so only the store can decrypt them.
enum class channel_encryption : std::uint8_t {
    /// The node seals each object (and dead-letter object) under an
    /// AES-256-GCM data key from its own key provider (`KINESIS_KMS`:
    /// kythira, aws, local or pkcs11), asked for as the channel's
    /// execution role, the way a stream is encrypted at rest. Works on any
    /// S3-compatible store; readers unwrap the data key through the same
    /// provider.
    envelope = 0,
    /// The node sends plaintext and asks S3 to encrypt it with SSE-KMS
    /// under the channel's `KeyId`, as AWS's own delivery does: the store's
    /// KMS must know the key, and readers need nothing beyond `GetObject`.
    sse_kms = 1,
};

/// One destination bucket: `_put` writes `bytes` at `key` (from the
/// bucket's root) or throws.
struct channel_bucket {
    std::function<void(const std::string& key, std::string_view bytes,
                       const channel_put_options& options)>
        _put;
    /// Reads `key`: nullopt when there is no such object, throws when the
    /// read failed. S3 Tables channels read the parent snapshot's manifest
    /// list through it; S3 channels never read.
    std::function<std::optional<std::string>(const std::string& key)> _get;
    [[nodiscard]] auto configured() const -> bool { return static_cast<bool>(_put); }
};

/// Who a write is for: the destination writes as the channel's service
/// execution role when the node is set to assume it
/// (`kinesis_channel_role.hpp`), and names the channel in the session.
struct channel_access {
    std::string _account;
    std::string _channel;
    /// `ChannelId`.
    std::string _channel_id;
    /// `ServiceExecutionRoleARN`.
    std::string _role_arn;
};

/// The Iceberg REST catalog of one table bucket (`kinesis_iceberg_rest.hpp`
/// in the daemon, a fake in tests): each call answers, or nullopt when the
/// catalog could not be reached.
struct iceberg_catalog {
    std::function<std::optional<peer_response>(const std::string& ns, const std::string& table)>
        _load;
    std::function<std::optional<peer_response>(const std::string& ns, const std::string& table,
                                               std::string body)>
        _commit;
};

struct channel_delivery_config {
    /// The writer for a destination bucket (the name from the bucket ARN)
    /// on behalf of a channel, or nullopt when this node cannot reach it;
    /// unset turns delivery off on this node.
    std::function<std::optional<channel_bucket>(const std::string& bucket,
                                                const channel_access& access)>
        _destination;
    /// The catalog of an S3 Tables channel's table bucket (by ARN), or
    /// nullopt when this node cannot reach it; unset leaves S3 Tables
    /// channels undelivered by this node.
    std::function<std::optional<iceberg_catalog>(const std::string& table_bucket_arn,
                                                 const channel_access& access)>
        _tables;
    /// How many times a commit is rebuilt on a newer parent after another
    /// writer committed first, before the batch waits for the next pass.
    int _commit_attempts = 4;
    /// Write an object once a batch holds this many bytes, however fresh.
    std::size_t _max_object_bytes = std::size_t{64} * 1024 * 1024;
    /// Bytes read from a shard per page.
    std::size_t _page_bytes = std::size_t{4} * 1024 * 1024;
    /// When positive, write a batch once its oldest record is this old even
    /// if the channel's `DataFreshnessInSeconds` (at least 300 s) has not
    /// passed: seconds-scale delivery for tests and demos, as
    /// `KINESIS_TIER_AFTER_MS` is for tiering. 0 keeps the channel's own.
    std::int64_t _max_delay_ms = 0;
    /// Whether this node can write a `CompressionType`; unset asks what
    /// the build has (`channel_detail::can_compress`). Tests narrow it.
    std::function<bool(std::string_view)> _can_compress;
    /// How channels with an `EncryptionConfiguration` are encrypted.
    channel_encryption _encryption = channel_encryption::envelope;
    /// The key provider envelope encryption asks for data keys (the
    /// node's `KINESIS_KMS`). Empty: an S3 channel with an
    /// `EncryptionConfiguration` is set to FAILED in envelope mode, never
    /// delivered in plaintext.
    key_provider _kms{};
    /// How long one data key seals a channel's objects before the provider
    /// is asked for another: AWS reuses a stream's data keys for five
    /// minutes, and it bounds how late a disabled key or a revoked grant
    /// stops deliveries. 0 asks for a key per object.
    std::int64_t _data_key_reuse_ms = std::int64_t{5} * 60 * 1000;
};

struct channel_delivery_stats {
    std::uint64_t _objects = 0;
    std::uint64_t _records = 0;
    std::uint64_t _dead_letters = 0;
    std::uint64_t _checkpoints = 0;
    /// Failed reads, writes or proposals; the next pass retries them.
    std::uint64_t _failures = 0;
    /// Channels set to FAILED this pass.
    std::uint64_t _failed_channels = 0;
    /// What the last failed write said (an S3 error, a refused role), for
    /// the node's log; empty when nothing failed with a message.
    std::string _last_failure;
};

namespace channel_detail {

/// The session a channel's deliveries run as: its service execution role,
/// assumed by Kinesis (`arn:aws:sts::<account>:assumed-role/<role>/<session>`).
/// An encrypted stream's data keys are asked of the KMS for it, so the
/// role's key permissions decide what the channel can read, as on AWS.
[[nodiscard]] inline auto channel_principal(const channel_record& c)
    -> aws_auth::principal_context {
    aws_auth::principal_context p;
    p.type = aws_auth::principal_type::assumed_role;
    p.account = c._account;
    p.role_arn = c._role_arn;
    const auto slash = c._role_arn.rfind('/');
    p.role_name = slash == std::string::npos ? c._role_arn : c._role_arn.substr(slash + 1);
    p.session_name = "kinesis-channel-" + std::to_string(c._id);
    // arn:<partition>:iam::<account>:role/... -> the partition.
    std::string partition = "aws";
    if (c._role_arn.rfind("arn:", 0) == 0) {
        const auto end = c._role_arn.find(':', 4);
        if (end != std::string::npos) {
            partition = c._role_arn.substr(4, end - 4);
        }
    }
    p.arn = "arn:" + partition + ":sts::" + c._account + ":assumed-role/" + p.role_name + "/" +
            p.session_name;
    for (auto& ch : p.role_name) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return p;
}

/// `arn:aws:s3:::<bucket>` to `<bucket>`.
[[nodiscard]] inline auto bucket_of(std::string_view arn) -> std::string {
    const auto at = arn.rfind(':');
    return at == std::string_view::npos ? std::string() : std::string(arn.substr(at + 1));
}

[[nodiscard]] inline auto base64(std::string_view in) -> std::string {
    static constexpr std::string_view k =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const auto v = (static_cast<std::uint32_t>(static_cast<unsigned char>(in[i])) << 16U) |
                       (static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8U) |
                       static_cast<unsigned char>(in[i + 2]);
        out.push_back(k[(v >> 18U) & 63U]);
        out.push_back(k[(v >> 12U) & 63U]);
        out.push_back(k[(v >> 6U) & 63U]);
        out.push_back(k[v & 63U]);
    }
    if (i < in.size()) {
        auto v = static_cast<std::uint32_t>(static_cast<unsigned char>(in[i])) << 16U;
        if (i + 1 < in.size()) {
            v |= static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8U;
        }
        out.push_back(k[(v >> 18U) & 63U]);
        out.push_back(k[(v >> 12U) & 63U]);
        out.push_back(i + 1 < in.size() ? k[(v >> 6U) & 63U] : '=');
        out.push_back('=');
    }
    return out;
}

[[nodiscard]] inline auto two(int v) -> std::string {
    std::string s = std::to_string(v);
    return s.size() < 2 ? "0" + s : s;
}

/// The key template's placeholders, in the style of Firehose's custom
/// prefixes: `!{timestamp:<fmt>}` with `yyyy`, `MM`, `dd`, `HH` and `mm`
/// (UTC, the batch's first record's arrival), and `!{kinesis:stream-name}`,
/// `!{kinesis:shard-id}` and `!{kinesis:channel-name}`. Anything else is
/// copied as written.
[[nodiscard]] inline auto expand_template(std::string_view tpl, std::int64_t arrival_ms,
                                          std::string_view channel, std::string_view stream,
                                          std::string_view shard) -> std::string {
    const auto secs = static_cast<std::time_t>(arrival_ms / 1000);
    std::tm t{};
    (void)gmtime_r(&secs, &t);
    std::string out;
    std::size_t i = 0;
    while (i < tpl.size()) {
        if (tpl.substr(i, 2) != "!{") {
            out.push_back(tpl[i++]);
            continue;
        }
        const auto end = tpl.find('}', i);
        if (end == std::string_view::npos) {
            out.append(tpl.substr(i));
            break;
        }
        const auto body = tpl.substr(i + 2, end - i - 2);
        if (body.starts_with("timestamp:")) {
            auto fmt = body.substr(10);
            std::size_t j = 0;
            while (j < fmt.size()) {
                if (fmt.substr(j, 4) == "yyyy") {
                    out += std::to_string(t.tm_year + 1900);
                    j += 4;
                } else if (fmt.substr(j, 2) == "MM") {
                    out += two(t.tm_mon + 1);
                    j += 2;
                } else if (fmt.substr(j, 2) == "dd") {
                    out += two(t.tm_mday);
                    j += 2;
                } else if (fmt.substr(j, 2) == "HH") {
                    out += two(t.tm_hour);
                    j += 2;
                } else if (fmt.substr(j, 2) == "mm") {
                    out += two(t.tm_min);
                    j += 2;
                } else {
                    out.push_back(fmt[j++]);
                }
            }
        } else if (body == "kinesis:stream-name") {
            out.append(stream);
        } else if (body == "kinesis:shard-id") {
            out.append(shard);
        } else if (body == "kinesis:channel-name") {
            out.append(channel);
        } else {
            out.append(tpl.substr(i, end - i + 1));
        }
        i = end + 1;
    }
    return out;
}

inline constexpr std::string_view k_default_key_template =
    "!{kinesis:stream-name}/!{timestamp:yyyy/MM/dd/HH}/";

[[nodiscard]] inline auto gzip(std::string_view in) -> std::optional<std::string> {
#ifdef KYTHIRA_KINESIS_HAS_ZLIB
    z_stream z{};
    // 15 + 16: a gzip header and trailer rather than raw zlib.
    if (deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) !=
        Z_OK) {
        return std::nullopt;
    }
    std::string out(deflateBound(&z, static_cast<uLong>(in.size())), '\0');
    // zlib's API takes non-const pointers it does not write through.
    z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT
    z.avail_in = static_cast<uInt>(in.size());
    z.next_out = reinterpret_cast<Bytef*>(out.data());
    z.avail_out = static_cast<uInt>(out.size());
    const auto rc = deflate(&z, Z_FINISH);
    const auto written = z.total_out;
    deflateEnd(&z);
    if (rc != Z_STREAM_END) {
        return std::nullopt;
    }
    out.resize(written);
    return out;
#else
    (void)in;
    return std::nullopt;
#endif
}

[[nodiscard]] inline auto zstd(std::string_view in) -> std::optional<std::string> {
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
    std::string out(ZSTD_compressBound(in.size()), '\0');
    const auto written = ZSTD_compress(out.data(), out.size(), in.data(), in.size(), 3);
    if (ZSTD_isError(written) != 0U) {
        return std::nullopt;
    }
    out.resize(written);
    return out;
#else
    (void)in;
    return std::nullopt;
#endif
}

/// `body` compressed as `compression` says; nullopt when it failed or this
/// build cannot write it.
[[nodiscard]] inline auto compress(std::string_view compression, std::string body)
    -> std::optional<std::string> {
    if (compression == "GZIP") {
        return gzip(body);
    }
    if (compression == "ZSTD") {
        return zstd(body);
    }
    if (compression == "NONE") {
        return body;
    }
    return std::nullopt;
}

/// Whether this build can write `compression` (`NONE`, `GZIP`, `ZSTD`, and
/// for S3 Tables `SNAPPY`, which needs no library).
[[nodiscard]] inline auto can_compress(std::string_view compression) -> bool {
    if (compression == "NONE" || compression == "SNAPPY") {
        return true;
    }
#ifdef KYTHIRA_KINESIS_HAS_ZLIB
    if (compression == "GZIP") {
        return true;
    }
#endif
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
    if (compression == "ZSTD") {
        return true;
    }
#endif
    return false;
}

[[nodiscard]] inline auto extension_of(std::string_view compression) -> std::string_view {
    if (compression == "GZIP") {
        return ".gz";
    }
    if (compression == "ZSTD") {
        return ".zst";
    }
    return "";
}

// ── encryption of delivered objects (Requirement 18.4) ─────────────────────
//
// Envelope encryption lays an object out as the Amazon S3 Encryption
// Client's version 2 format does: the body is AES-256-GCM ciphertext then
// its 16-byte tag, with no additional data, and the user metadata carries
// the rest:
//
// | Metadata | Value |
// |---|---|
// | `x-amz-key-v2` | the wrapped data key, base64 |
// | `x-amz-iv` | the 12-byte nonce, base64 |
// | `x-amz-cek-alg` | `AES/GCM/NoPadding` |
// | `x-amz-wrap-alg` | `kms+context` |
// | `x-amz-tag-len` | `128` |
// | `x-amz-matdesc` | the encryption context, JSON |
// | `x-amz-unencrypted-content-length` | the plaintext's length |
// | `kythira-kms-key-id` | the provider's id for the wrapping key |
//
// The encryption context names the content algorithm, as that format's
// `kms+context` wrapping requires, and the channel, so a data key copied
// to another channel's object does not unwrap for it. With `KINESIS_KMS=aws`
// the wrapped key is a real KMS ciphertext blob; the local and PKCS#11
// providers' blobs open only through a Kythira provider with the same
// passphrase or token.

inline constexpr std::string_view k_cek_alg = "AES/GCM/NoPadding";

/// The channel's customer managed key, when its `EncryptionConfiguration`
/// asks for KMS encryption; nullopt for an unencrypted channel.
[[nodiscard]] inline auto channel_key_id(const channel_record& c) -> std::optional<std::string> {
    if (c._encryption_config.empty()) {
        return std::nullopt;
    }
    boost::system::error_code ec;
    const auto v = boost::json::parse(c._encryption_config, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto* type = v.as_object().if_contains("EncryptionType");
    const auto* key = v.as_object().if_contains("KeyId");
    if (type == nullptr || !type->is_string() || type->as_string() != "KMS" || key == nullptr ||
        !key->is_string() || key->as_string().empty()) {
        return std::nullopt;
    }
    return std::string(key->as_string());
}

/// The encryption context a channel's data keys are wrapped under.
[[nodiscard]] inline auto object_context(const channel_record& c) -> encryption_context {
    return encryption_context{{"aws:x-amz-cek-alg", std::string(k_cek_alg)},
                              {"kinesis:channel-id", channel_id_text(c._id)}};
}

/// Base64 back to bytes; nullopt when `in` is not padded base64.
[[nodiscard]] inline auto unbase64(std::string_view in) -> std::optional<std::string> {
    const auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        return -1;
    };
    if (in.size() % 4 != 0) {
        return std::nullopt;
    }
    std::string out;
    out.reserve(in.size() / 4 * 3);
    for (std::size_t i = 0; i < in.size(); i += 4) {
        std::uint32_t v = 0;
        int pad = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const char c = in[i + j];
            if (c == '=' && i + 4 == in.size() && j >= 2) {
                ++pad;
                v <<= 6U;
                continue;
            }
            const int d = value(c);
            if (d < 0 || pad > 0) {
                return std::nullopt;
            }
            v = (v << 6U) | static_cast<std::uint32_t>(d);
        }
        out.push_back(static_cast<char>((v >> 16U) & 0xFFU));
        if (pad < 2) {
            out.push_back(static_cast<char>((v >> 8U) & 0xFFU));
        }
        if (pad < 1) {
            out.push_back(static_cast<char>(v & 0xFFU));
        }
    }
    return out;
}

/// An envelope-sealed object: its body and the user metadata it is written
/// with.
struct sealed_object {
    std::string _body;
    std::map<std::string, std::string> _metadata;
};

/// `plain` sealed under `key` (wrapped under `context`), with a fresh nonce.
[[nodiscard]] inline auto seal_object(const generated_data_key& key,
                                      const encryption_context& context, std::string_view plain)
    -> sealed_object {
    std::array<unsigned char, kms_detail::k_nonce_len> nonce{};
    kms_detail::random_fill(nonce);
    std::vector<std::byte> sealed;
    sealed.reserve(plain.size() + kms_detail::k_tag_len);
    kms_detail::gcm_seal(key._plaintext, nonce, {},
                         std::as_bytes(std::span(plain.data(), plain.size())), sealed);
    boost::json::object matdesc;
    for (const auto& [k, v] : context) {
        matdesc[k] = v;
    }
    sealed_object out;
    out._body.assign(reinterpret_cast<const char*>(sealed.data()), sealed.size());
    out._metadata = {
        {"x-amz-key-v2", base64(key._wrapped)},
        {"x-amz-iv",
         base64(std::string_view(reinterpret_cast<const char*>(nonce.data()), nonce.size()))},
        {"x-amz-cek-alg", std::string(k_cek_alg)},
        {"x-amz-wrap-alg", "kms+context"},
        {"x-amz-tag-len", std::to_string(kms_detail::k_tag_len * 8)},
        {"x-amz-matdesc", boost::json::serialize(matdesc)},
        {"x-amz-unencrypted-content-length", std::to_string(plain.size())},
        {"kythira-kms-key-id", key._key_id},
    };
    return out;
}

/// The plaintext of an object `seal_object` sealed, from its body and user
/// metadata (names without `x-amz-meta-`, any case), its data key unwrapped
/// through `kms` for `caller`. Throws the provider's `kms_error`, or
/// `record_open_error` when the metadata is incomplete or the body fails
/// its tag.
[[nodiscard]] inline auto open_object(const key_provider& kms,
                                      const std::map<std::string, std::string>& metadata,
                                      std::string_view body, const kms_caller& caller = {})
    -> std::string {
    const auto meta = [&](std::string_view name) -> std::string {
        for (const auto& [k, v] : metadata) {
            if (k.size() == name.size() &&
                std::equal(k.begin(), k.end(), name.begin(), [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(a)) == b;
                })) {
                return v;
            }
        }
        throw record_open_error("kinesis channel object: no " + std::string(name) + " metadata");
    };
    if (meta("x-amz-cek-alg") != k_cek_alg || meta("x-amz-wrap-alg") != "kms+context") {
        throw record_open_error("kinesis channel object: not AES/GCM under a kms+context key");
    }
    const auto wrapped = unbase64(meta("x-amz-key-v2"));
    const auto nonce = unbase64(meta("x-amz-iv"));
    if (!wrapped || !nonce || nonce->size() != kms_detail::k_nonce_len) {
        throw record_open_error("kinesis channel object: malformed key or nonce metadata");
    }
    boost::system::error_code ec;
    const auto matdesc = boost::json::parse(meta("x-amz-matdesc"), ec);
    if (ec || !matdesc.is_object()) {
        throw record_open_error("kinesis channel object: malformed x-amz-matdesc");
    }
    encryption_context context;
    for (const auto& [k, v] : matdesc.as_object()) {
        if (!v.is_string()) {
            throw record_open_error("kinesis channel object: malformed x-amz-matdesc");
        }
        context.emplace(std::string(k), std::string(v.as_string()));
    }
    auto key = kms.decrypt_data_key(meta("kythira-kms-key-id"), *wrapped, context, caller);
    auto plain = kms_detail::gcm_open(
        key, std::span(reinterpret_cast<const unsigned char*>(nonce->data()), nonce->size()), {},
        std::as_bytes(std::span(body.data(), body.size())));
    OPENSSL_cleanse(key.data(), key.size());
    if (!plain) {
        throw record_open_error("kinesis channel object: the body failed its tag");
    }
    std::string out(reinterpret_cast<const char*>(plain->data()), plain->size());
    OPENSSL_cleanse(plain->data(), plain->size());
    return out;
}

}  // namespace channel_detail

/// `Service` is a `kinesis_service` (its `read_for_delivery`).
template<typename Cluster, typename Service>
requires stream_cluster<Cluster> && leads_keys<Cluster>
class channel_delivery {
public:
    channel_delivery(Cluster& cluster, Service& service, channel_delivery_config config)
        : _cluster(cluster), _service(service), _config(std::move(config)) {}

    auto run_once() -> channel_delivery_stats {
        channel_delivery_stats stats;
        if (!_config._destination) {
            return stats;
        }
        _data_keys.prune(_cluster.now_ms(), _config._data_key_reuse_ms);
        for (const auto& job : jobs()) {
            try {
                channel(job, stats);
            } catch (const std::exception& e) {
                ++stats._failures;
                stats._last_failure = e.what();
            }
        }
        return stats;
    }

private:
    struct job {
        channel_record _channel;
        /// Each source as it is now, when it still is the one the channel
        /// was created on.
        std::vector<std::pair<channel_stream, stream_record>> _sources;
    };

    /// Data keys sealing channels' objects, by channel id and `KeyId`, with
    /// when each was made. Only `run_once` touches it, from one thread.
    class data_key_cache {
    public:
        struct entry {
            generated_data_key _key;
            std::int64_t _made_ms = 0;
        };

        data_key_cache() = default;
        data_key_cache(const data_key_cache&) = delete;
        data_key_cache(data_key_cache&&) = delete;
        auto operator=(const data_key_cache&) -> data_key_cache& = delete;
        auto operator=(data_key_cache&&) -> data_key_cache& = delete;
        ~data_key_cache() {
            for (auto& [k, e] : _entries) {
                OPENSSL_cleanse(e._key._plaintext.data(), e._key._plaintext.size());
            }
        }

        [[nodiscard]] auto find(std::uint64_t channel, const std::string& key_id, std::int64_t now,
                                std::int64_t reuse_ms) -> const generated_data_key* {
            const auto it = _entries.find({channel, key_id});
            if (it == _entries.end() || now - it->second._made_ms >= reuse_ms) {
                return nullptr;
            }
            return &it->second._key;
        }

        auto put(std::uint64_t channel, const std::string& key_id, generated_data_key key,
                 std::int64_t now) -> const generated_data_key* {
            auto& e = _entries[{channel, key_id}];
            OPENSSL_cleanse(e._key._plaintext.data(), e._key._plaintext.size());
            e = entry{._key = std::move(key), ._made_ms = now};
            return &e._key;
        }

        /// Forgets keys past their reuse, so a deleted channel's go too.
        auto prune(std::int64_t now, std::int64_t reuse_ms) -> void {
            for (auto it = _entries.begin(); it != _entries.end();) {
                if (now - it->second._made_ms >= reuse_ms) {
                    OPENSSL_cleanse(it->second._key._plaintext.data(),
                                    it->second._key._plaintext.size());
                    it = _entries.erase(it);
                } else {
                    ++it;
                }
            }
        }

    private:
        std::map<std::pair<std::uint64_t, std::string>, entry> _entries;
    };

    /// What one S3 batch's writes do under the channel's
    /// `EncryptionConfiguration`: nothing, seal (envelope), or ask S3.
    struct object_sealer {
        const generated_data_key* _key = nullptr;
        encryption_context _context;
        std::optional<std::string> _sse_kms_key_id;

        /// `bytes` as written, with `options` set to match.
        [[nodiscard]] auto apply(std::string bytes, channel_put_options& options) const
            -> std::string {
            if (_key != nullptr) {
                auto sealed = channel_detail::seal_object(*_key, _context, bytes);
                options._metadata = std::move(sealed._metadata);
                return std::move(sealed._body);
            }
            options._sse_kms_key_id = _sse_kms_key_id;
            return bytes;
        }
    };

    Cluster& _cluster;
    Service& _service;
    channel_delivery_config _config;
    data_key_cache _data_keys;

    /// The sealer for a batch of `c`'s: nullopt when its data key could not
    /// be had (counted, with the KMS's reason; the batch is retried on the
    /// next pass, as AWS retries a delivery the key refused).
    auto sealer_for(const channel_record& c, channel_delivery_stats& stats)
        -> std::optional<object_sealer> {
        object_sealer out;
        const auto key_id = channel_detail::channel_key_id(c);
        if (!key_id) {
            return out;
        }
        if (_config._encryption == channel_encryption::sse_kms) {
            out._sse_kms_key_id = key_id;
            return out;
        }
        if (!_config._kms) {
            ++stats._failures;
            stats._last_failure = "No key provider (KINESIS_KMS) for an encrypted channel.";
            return std::nullopt;
        }
        out._context = channel_detail::object_context(c);
        const auto now = _cluster.now_ms();
        out._key = _data_keys.find(c._id, *key_id, now, _config._data_key_reuse_ms);
        if (out._key == nullptr) {
            // Asked for as the channel's execution role, as its reads are:
            // the role's grants on the key decide whether it delivers.
            const auto as = channel_detail::channel_principal(c);
            try {
                out._key = _data_keys.put(c._id, *key_id,
                                          _config._kms.generate_data_key(
                                              *key_id, out._context, kms_caller{._principal = &as}),
                                          now);
            } catch (const kms_error& e) {
                ++stats._failures;
                stats._last_failure = "KMS refused a data key under " + *key_id + ": " + e.what();
                return std::nullopt;
            }
        }
        return out;
    }

    template<typename F> auto read_catalog(F&& f) -> bool {
        return _cluster.read(next_id_key(), [&f](const auto& sm) { f(sm); });
    }

    auto jobs() -> std::vector<job> {
        std::vector<job> out;
        (void)read_catalog([&](const auto& sm) {
            const auto prefix = channels_prefix();
            const auto& entries = sm.entries();
            for (auto it = entries.lower_bound(prefix);
                 it != entries.end() && it->first.starts_with(prefix); ++it) {
                const auto* c = std::get_if<channel_record>(&it->second);
                if (c == nullptr || c->_status != channel_status::active ||
                    (c->_destination == channel_destination::s3_tables && !_config._tables)) {
                    continue;
                }
                job j{._channel = *c, ._sources = {}};
                for (const auto& src : c->_streams) {
                    const auto* s = sm.find_stream(c->_account, src._stream);
                    if (s != nullptr && s->_id == src._stream_id &&
                        (s->_status == stream_status::active ||
                         s->_status == stream_status::updating)) {
                        j._sources.emplace_back(src, *s);
                    }
                }
                out.push_back(std::move(j));
            }
        });
        return out;
    }

    [[nodiscard]] static auto access_of(const channel_record& c) -> channel_access {
        return channel_access{._account = c._account,
                              ._channel = c._name,
                              ._channel_id = channel_id_text(c._id),
                              ._role_arn = c._role_arn};
    }

    auto checkpoint(const channel_record& c, const std::string& shard) -> std::uint64_t {
        std::uint64_t at = 0;
        (void)read_catalog(
            [&](const auto& sm) { at = sm.channel_checkpoint(c._account, c._id, shard); });
        return at;
    }

    auto fail_channel(const channel_record& c, std::string reason, channel_delivery_stats& stats)
        -> void {
        channel_record change;
        change._status = channel_status::failed;
        change._status_reason = std::move(reason);
        const stream_command cmd = channel_command{._account = c._account,
                                                   ._name = c._name,
                                                   ._op = channel_op::set_status,
                                                   ._id = c._id,
                                                   ._record = std::move(change)};
        const auto r = _cluster.propose(command_key(cmd), encode_command(cmd), admission::none);
        if (r && r->_status == apply_status::ok) {
            ++stats._failed_channels;
        } else {
            ++stats._failures;
        }
    }

    auto channel(const job& j, channel_delivery_stats& stats) -> void {
        const auto& c = j._channel;
        const auto dest = boost::json::parse(c._destination_config).as_object();
        const std::string compression = compression_of(c, dest);
        if (!(_config._can_compress ? _config._can_compress(compression)
                                    : channel_detail::can_compress(compression))) {
            // Only the catalog group's leader fails it, so the nodes do not
            // all race to.
            if (_cluster.leads(channel_key(c._account, c._name))) {
                fail_channel(
                    c,
                    "CompressionType " + compression + " is not supported by this Kythira build.",
                    stats);
            }
            return;
        }
        if (c._destination == channel_destination::s3 &&
            _config._encryption == channel_encryption::envelope &&
            channel_detail::channel_key_id(c) && !_config._kms) {
            // Never deliver an encrypted channel's records in plaintext.
            if (_cluster.leads(channel_key(c._account, c._name))) {
                fail_channel(c,
                             "EncryptionConfiguration needs a key provider (KINESIS_KMS) on the "
                             "nodes that deliver this channel.",
                             stats);
            }
            return;
        }
        for (const auto& [src, stream] : j._sources) {
            for (const auto& shard : stream._shards) {
                const auto key = routing_key(stream._id, shard._ordinal);
                if (!_cluster.leads(key) || !parents_done(c, stream, shard)) {
                    continue;
                }
                deliver_shard(c, dest, src, stream, shard, stats);
            }
        }
    }

    // A child waits for its parents to be delivered past their ends; a
    // parent no longer in the shard table (trimmed away) is done.
    auto parents_done(const channel_record& c, const stream_record& stream,
                      const shard_entry& shard) -> bool {
        for (const auto parent : {shard._parent, shard._adjacent_parent}) {
            if (!parent) {
                continue;
            }
            const auto* p = stream.find_shard(*parent);
            if (p == nullptr) {
                continue;
            }
            if (!p->_ending_counter ||
                checkpoint(c, routing_key(stream._id, *parent)) <= *p->_ending_counter) {
                return false;
            }
        }
        return true;
    }

    auto deliver_shard(const channel_record& c, const boost::json::object& dest,
                       const channel_stream& src, const stream_record& stream,
                       const shard_entry& shard, channel_delivery_stats& stats) -> void {
        const auto key = routing_key(stream._id, shard._ordinal);
        const auto from = checkpoint(c, key);
        const auto as = channel_detail::channel_principal(c);
        // No position yet: start with what arrived once the channel existed.
        const auto min_ts = from == 0 ? c._created_ms : std::int64_t{0};
        std::vector<typename Service::delivery_record> batch;
        std::size_t bytes = 0;
        std::uint64_t next = from;
        bool exhausted = false;
        std::string shard_id;
        while (bytes < _config._max_object_bytes) {
            // Never read much past the object limit: a page holds at least
            // one record, so a batch overshoots by at most one.
            const auto room = std::min(_config._page_bytes, _config._max_object_bytes - bytes);
            auto page = _service.read_for_delivery(stream, shard, next, batch.empty() ? min_ts : 0,
                                                   10'000, room, kms_caller{._principal = &as});
            if (!page) {
                ++stats._failures;
                return;
            }
            shard_id = page->_shard_id;
            const bool progressed = page->_next_counter > next;
            next = page->_next_counter;
            exhausted = page->_exhausted;
            for (auto& r : page->_records) {
                bytes += r._data.size() + 1;
                batch.push_back(std::move(r));
            }
            if (page->_records.empty() || exhausted || !progressed) {
                break;
            }
        }
        const auto now = _cluster.now_ms();
        auto freshness_ms =
            dest.at("DataFreshnessInSeconds").to_number<std::int64_t>() * std::int64_t{1000};
        if (_config._max_delay_ms > 0) {
            freshness_ms = std::min(freshness_ms, _config._max_delay_ms);
        }
        const bool due = !batch.empty() && (batch.front()._arrival_ms + freshness_ms <= now ||
                                            bytes >= _config._max_object_bytes || exhausted);
        if (batch.empty()) {
            // A closed shard with nothing left: move past its end so its
            // children can start.
            if (exhausted && next > from) {
                propose_checkpoint(c, key, from, next, stats);
            }
            return;
        }
        if (!due) {
            return;
        }
        const bool written = c._destination == channel_destination::s3_tables
                                 ? write_table_batch(c, dest, src, shard_id, batch, stats)
                                 : write_batch(c, dest, src, shard_id, batch, stats);
        if (!written) {
            return;
        }
        // Past the batch; a closed shard read to its end moves past its end.
        const auto to = exhausted ? next : batch.back()._counter + 1;
        propose_checkpoint(c, key, from, to, stats);
    }

    auto propose_checkpoint(const channel_record& c, const std::string& shard, std::uint64_t from,
                            std::uint64_t to, channel_delivery_stats& stats) -> void {
        const stream_command cmd = channel_checkpoint_command{._account = c._account,
                                                              ._channel = c._name,
                                                              ._channel_id = c._id,
                                                              ._shard = shard,
                                                              ._expected = from,
                                                              ._next = to};
        const auto r = _cluster.propose(command_key(cmd), encode_command(cmd), admission::none);
        if (r && r->_status == apply_status::ok) {
            ++stats._checkpoints;
        } else {
            ++stats._failures;
        }
    }

    auto write_batch(const channel_record& c, const boost::json::object& dest,
                     const channel_stream& src, const std::string& shard_id,
                     const std::vector<typename Service::delivery_record>& batch,
                     channel_delivery_stats& stats) -> bool {
        const auto& storage = dest.at("StorageConfiguration").as_object();
        const std::string compression(storage.at("CompressionType").as_string());
        const auto bucket = channel_detail::bucket_of(storage.at("BucketARN").as_string());
        const auto text = [](const boost::json::object& o, const char* k) {
            const auto* v = o.if_contains(k);
            return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string();
        };
        channel_put_options options{._storage_class = text(storage, "StorageClass"),
                                    ._expected_owner = text(storage, "ExpectedBucketOwner")};
        const auto format = std::string(
            boost::json::parse(src._record_config).as_object().at("RecordFormatType").as_string());
        std::string body;
        std::string dead;
        std::size_t dead_count = 0;
        for (const auto& r : batch) {
            const std::string_view data(reinterpret_cast<const char*>(r._data.data()),
                                        r._data.size());
            if (format == "BYTE_ARRAY") {
                body += channel_detail::base64(data);
            } else if (format == "JSON") {
                boost::system::error_code ec;
                (void)boost::json::parse(data, ec);
                if (ec) {
                    boost::json::object line;
                    line["errorCode"] = "InvalidJson";
                    line["errorMessage"] = ec.message();
                    line["sequenceNumber"] = r._sequence;
                    line["partitionKey"] = r._partition_key;
                    line["approximateArrivalTimestamp"] = r._arrival_ms;
                    line["rawData"] = channel_detail::base64(data);
                    dead += boost::json::serialize(line);
                    dead.push_back('\n');
                    ++dead_count;
                    continue;
                }
                body.append(data);
            } else {
                body.append(data);
            }
            body.push_back('\n');
        }

        const auto tpl = storage.contains("OutputKeyTemplate")
                             ? std::string(storage.at("OutputKeyTemplate").as_string())
                             : std::string(channel_detail::k_default_key_template);
        const auto& first = batch.front();
        const auto name =
            c._name + "-" + shard_id + "-" + first._sequence + "-" + batch.back()._sequence;
        const auto ext = channel_detail::extension_of(compression);
        const bool has_body = !body.empty();
        auto payload = channel_detail::compress(compression, std::move(body));
        if (!payload) {
            ++stats._failures;
            return false;
        }
        // Encryption comes after compression: ciphertext does not compress.
        const auto sealer = sealer_for(c, stats);
        if (!sealer) {
            return false;
        }
        try {
            if (has_body) {
                const auto store = _config._destination(bucket, access_of(c));
                if (!store || !store->configured()) {
                    ++stats._failures;
                    return false;
                }
                const auto bytes = sealer->apply(std::move(*payload), options);
                store->_put(channel_detail::expand_template(tpl, first._arrival_ms, c._name,
                                                            src._stream, shard_id) +
                                name + std::string(ext),
                            bytes, options);
                ++stats._objects;
            }
            if (dead_count > 0) {
                std::string dlq_bucket = bucket;
                std::string prefix = "errors/";
                // Dead letters keep the default storage class; the bucket's
                // owner is checked as for the destination.
                channel_put_options dlq_options{._storage_class = {},
                                                ._expected_owner = options._expected_owner};
                if (const auto* d = dest.if_contains("DeadLetterQueueS3Configuration");
                    d != nullptr && d->is_object()) {
                    const auto& dlq = d->as_object();
                    dlq_bucket = channel_detail::bucket_of(dlq.at("BucketARN").as_string());
                    dlq_options._expected_owner = text(dlq, "ExpectedBucketOwner");
                    if (const auto* p = dlq.if_contains("ErrorOutputPrefix")) {
                        prefix = std::string(p->as_string());
                    }
                }
                const auto store = _config._destination(dlq_bucket, access_of(c));
                if (!store || !store->configured()) {
                    ++stats._failures;
                    return false;
                }
                // Dead letters hold the records' bytes: sealed like the rest.
                const auto bytes = sealer->apply(std::move(dead), dlq_options);
                store->_put(channel_detail::expand_template(prefix, first._arrival_ms, c._name,
                                                            src._stream, shard_id) +
                                name + ".json",
                            bytes, dlq_options);
                stats._dead_letters += dead_count;
            }
        } catch (const std::exception& e) {
            ++stats._failures;
            stats._last_failure = e.what();
            return false;
        }
        stats._records += batch.size() - dead_count;
        return true;
    }

    // ── S3 Tables ───────────────────────────────────────────────────────────

    /// `CompressionType` of the channel's destination.
    [[nodiscard]] static auto compression_of(const channel_record& c,
                                             const boost::json::object& dest) -> std::string {
        if (c._destination == channel_destination::s3_tables) {
            return std::string(dest.at("S3TablesConfigurationList")
                                   .as_array()
                                   .at(0)
                                   .as_object()
                                   .at("CompressionType")
                                   .as_string());
        }
        return std::string(
            dest.at("StorageConfiguration").as_object().at("CompressionType").as_string());
    }

    /// The Parquet codec a data file is written with for `compression`.
    [[nodiscard]] static auto parquet_codec(std::string_view compression) -> std::string {
        if (compression == "ZSTD" || compression == "SNAPPY") {
            return std::string(compression);
        }
        return "UNCOMPRESSED";
    }

    /// A positive snapshot id from the table and batch: the same batch
    /// retried proposes the same id, so its files and manifest are
    /// rewritten identically.
    [[nodiscard]] static auto snapshot_id_of(std::string_view table_uuid, std::string_view batch)
        -> std::int64_t {
        const auto basis = std::string(table_uuid) + "\n" + std::string(batch);
        std::array<unsigned char, SHA256_DIGEST_LENGTH> d{};
        SHA256(reinterpret_cast<const unsigned char*>(basis.data()), basis.size(), d.data());
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            v = (v << 8U) | d[i];
        }
        v &= 0x7FFFFFFFFFFFFFFFULL;
        return static_cast<std::int64_t>(v == 0 ? 1 : v);
    }

    template<typename Record>
    [[nodiscard]] static auto dead_line(const Record& r, std::string_view code,
                                        std::string_view message) -> std::string {
        const std::string_view data(reinterpret_cast<const char*>(r._data.data()), r._data.size());
        boost::json::object line;
        line["errorCode"] = code;
        line["errorMessage"] = message;
        line["sequenceNumber"] = r._sequence;
        line["partitionKey"] = r._partition_key;
        line["approximateArrivalTimestamp"] = r._arrival_ms;
        line["rawData"] = channel_detail::base64(data);
        return boost::json::serialize(line) + "\n";
    }

    struct table_target {
        std::string _arn;
        std::string _ns;
        std::string _table;
        std::string _codec;
        /// The channel's `PartitionSpec` source column for `TIME_HOUR`, or
        /// empty when it names none.
        std::string _hour_source;
    };

    [[nodiscard]] static auto table_target_of(const boost::json::object& dest) -> table_target {
        const auto& t = dest.at("S3TablesConfigurationList").as_array().at(0).as_object();
        table_target out{._arn = std::string(t.at("TableBucketARN").as_string()),
                         ._ns = std::string(t.at("Namespace").as_string()),
                         ._table = std::string(t.at("TableName").as_string()),
                         ._codec = parquet_codec(t.at("CompressionType").as_string()),
                         ._hour_source = {}};
        if (const auto* ps = t.if_contains("PartitionSpec"); ps != nullptr && ps->is_object()) {
            for (const auto& f : ps->as_object().at("PartitionFields").as_array()) {
                out._hour_source = std::string(f.as_object().at("SourceName").as_string());
            }
        }
        return out;
    }

    /// Loads the table; nullopt (with the failure counted) when it cannot
    /// be read or written, after failing the channel when the table itself
    /// is the problem.
    auto load_table(const channel_record& c, const iceberg_catalog& catalog,
                    const table_target& target, channel_delivery_stats& stats)
        -> std::optional<iceberg::table_metadata> {
        const auto res = catalog._load(target._ns, target._table);
        if (!res) {
            ++stats._failures;
            stats._last_failure =
                "The Iceberg REST catalog for " + target._arn + " did not answer.";
            return std::nullopt;
        }
        if (res->_status != 200) {
            ++stats._failures;
            stats._last_failure = "Loading table " + target._ns + "." + target._table +
                                  " failed: " + iceberg_error_message(*res);
            return std::nullopt;
        }
        try {
            auto t =
                iceberg::parse_metadata(boost::json::parse(res->_body).as_object().at("metadata"));
            return t;
        } catch (const iceberg::table_error& e) {
            fail_table_channel(c, e.what(), stats);
        } catch (const std::exception& e) {
            ++stats._failures;
            stats._last_failure =
                std::string("The catalog's table answer is malformed: ") + e.what();
        }
        return std::nullopt;
    }

    auto fail_table_channel(const channel_record& c, const std::string& reason,
                            channel_delivery_stats& stats) -> void {
        stats._last_failure = reason;
        if (_cluster.leads(channel_key(c._account, c._name))) {
            fail_channel(c, reason, stats);
        } else {
            ++stats._failures;
        }
    }

    /// The parent snapshot's manifest list entries, in the v2 form.
    auto parent_manifests(const iceberg::table_metadata& t, const channel_access& access)
        -> std::vector<boost::json::value> {
        std::vector<boost::json::value> out;
        if (!t._main_snapshot) {
            return out;
        }
        const auto* snap = t.snapshot(*t._main_snapshot);
        if (snap == nullptr) {
            throw iceberg::table_error("The table's main snapshot is not in its metadata.");
        }
        const auto* list = snap->if_contains("manifest-list");
        if (list == nullptr || !list->is_string()) {
            throw iceberg::table_error(
                "The table's main snapshot has no manifest list (format version 1 manifests "
                "are not supported).");
        }
        const auto where = iceberg::split_s3_uri(list->as_string());
        if (!where) {
            throw iceberg::table_error("The manifest list " + std::string(list->as_string()) +
                                       " is not in S3.");
        }
        const auto store = _config._destination(where->first, access);
        if (!store || !store->_get) {
            throw std::runtime_error("Cannot read " + std::string(list->as_string()) + ".");
        }
        const auto bytes = store->_get(where->second);
        if (!bytes) {
            throw std::runtime_error("The manifest list " + std::string(list->as_string()) +
                                     " does not exist.");
        }
        for (const auto& e : avro::read_file(*bytes)._records) {
            out.push_back(iceberg::normalize_list_entry(e));
        }
        return out;
    }

    /// How many leading records of `batch` the table already holds: each
    /// committed batch is found by the sequence number it starts at, and the
    /// records up to its last sequence number are skipped.
    [[nodiscard]] static auto committed_prefix(
        const iceberg::table_metadata& table, const std::string& batch_prefix,
        const std::vector<typename Service::delivery_record>& batch) -> std::size_t {
        // Sequence numbers are decimal strings without leading zeros.
        const auto at_most = [](const std::string& a, std::string_view b) {
            return a.size() != b.size() ? a.size() < b.size() : a <= b;
        };
        std::size_t done = 0;
        while (done < batch.size()) {
            const auto start = batch_prefix + batch[done]._sequence + "-";
            const auto found = table.summary_with_prefix("kythira.channel-batch", start);
            if (!found) {
                break;
            }
            const std::string_view last = std::string_view(*found).substr(start.size());
            const auto before = done;
            while (done < batch.size() && at_most(batch[done]._sequence, last)) {
                ++done;
            }
            if (done == before) {
                break;
            }
        }
        return done;
    }

    [[nodiscard]] static auto tail_of(const std::vector<typename Service::delivery_record>& batch,
                                      std::size_t from)
        -> std::vector<typename Service::delivery_record> {
        return {batch.begin() + static_cast<std::ptrdiff_t>(from), batch.end()};
    }

    auto write_table_batch(const channel_record& c, const boost::json::object& dest,
                           const channel_stream& src, const std::string& shard_id,
                           const std::vector<typename Service::delivery_record>& batch,
                           channel_delivery_stats& stats) -> bool {
        const auto target = table_target_of(dest);
        const auto access = access_of(c);
        // An Iceberg reader opens the files straight from the table bucket,
        // so an encrypted channel asks the store for SSE-KMS under its key
        // on every file it writes, dead letters included.
        const auto sse = channel_detail::channel_key_id(c);
        const channel_put_options table_options{
            ._storage_class = {}, ._expected_owner = {}, ._metadata = {}, ._sse_kms_key_id = sse};
        const auto catalog = _config._tables(target._arn, access);
        if (!catalog) {
            ++stats._failures;
            stats._last_failure = "No Iceberg REST catalog for " + target._arn + ".";
            return false;
        }
        auto table = load_table(c, *catalog, target, stats);
        if (!table) {
            return false;
        }
        const auto name =
            c._name + "-" + shard_id + "-" + batch.front()._sequence + "-" + batch.back()._sequence;
        // The batch's identity in the table's history: a batch committed
        // before a lost checkpoint is not committed again. The node that
        // retries may read further than the one that committed, so look for
        // any batch that starts where this one does and commit only what
        // follows it.
        const auto batch_prefix = channel_id_text(c._id) + "/" + shard_id + "/";
        if (const auto done = committed_prefix(*table, batch_prefix, batch); done > 0) {
            if (done == batch.size()) {
                return true;
            }
            return write_table_batch(c, dest, src, shard_id, tail_of(batch, done), stats);
        }
        const auto batch_id = batch_prefix + batch.front()._sequence + "-" + batch.back()._sequence;
        std::vector<iceberg::partition_field> spec;
        try {
            spec = iceberg::bind_spec(*table);
            if (!target._hour_source.empty()) {
                const bool matches = std::ranges::any_of(spec, [&](const auto& f) {
                    return f._transform == "hour" && f._source_name == target._hour_source;
                });
                if (!matches) {
                    throw iceberg::table_error(
                        "The channel partitions by TIME_HOUR on '" + target._hour_source +
                        "', but table " + target._ns + "." + target._table +
                        " is not partitioned by hour(" + target._hour_source + ").");
                }
            }
            iceberg::check_columns(table->_schema);
        } catch (const iceberg::table_error& e) {
            fail_table_channel(c, e.what(), stats);
            return false;
        }
        const auto location = iceberg::split_s3_uri(table->_location);
        if (!location) {
            fail_table_channel(c, "Table location " + table->_location + " is not in S3.", stats);
            return false;
        }
        const auto key_prefix = location->second.empty() ? std::string() : location->second + "/";

        // Rows by partition; records that do not fit go to dead letters.
        std::map<std::string, std::pair<boost::json::array, std::vector<boost::json::object>>>
            groups;
        std::string dead;
        std::size_t dead_count = 0;
        for (const auto& r : batch) {
            const std::string_view data(reinterpret_cast<const char*>(r._data.data()),
                                        r._data.size());
            boost::system::error_code ec;
            const auto parsed = boost::json::parse(data, ec);
            if (ec) {
                dead += dead_line(r, "InvalidJson", ec.message());
                ++dead_count;
                continue;
            }
            try {
                auto row = iceberg::to_row(table->_schema, parsed);
                boost::json::array part;
                for (const auto& f : spec) {
                    part.push_back(iceberg::partition_value(f, row));
                }
                auto& g = groups[boost::json::serialize(part)];
                g.first = std::move(part);
                g.second.push_back(std::move(row));
            } catch (const iceberg::record_error& e) {
                dead += dead_line(r, "SchemaMismatch", e.what());
                ++dead_count;
            }
        }

        try {
            const auto store = _config._destination(location->first, access);
            if (!store || !store->configured()) {
                ++stats._failures;
                stats._last_failure = "Cannot write to the table's bucket " + location->first + ".";
                return false;
            }
            if (dead_count > 0) {
                const auto& dlq = dest.at("DeadLetterQueueS3Configuration").as_object();
                const auto dlq_bucket = channel_detail::bucket_of(dlq.at("BucketARN").as_string());
                std::string prefix = "errors/";
                if (const auto* p = dlq.if_contains("ErrorOutputPrefix")) {
                    prefix = std::string(p->as_string());
                }
                const auto dlq_store = _config._destination(dlq_bucket, access);
                if (!dlq_store || !dlq_store->configured()) {
                    ++stats._failures;
                    return false;
                }
                const auto* owner = dlq.if_contains("ExpectedBucketOwner");
                dlq_store->_put(
                    channel_detail::expand_template(prefix, batch.front()._arrival_ms, c._name,
                                                    src._stream, shard_id) +
                        name + ".json",
                    dead,
                    channel_put_options{._storage_class = {},
                                        ._expected_owner = owner != nullptr && owner->is_string()
                                                               ? std::string(owner->as_string())
                                                               : std::string(),
                                        ._metadata = {},
                                        ._sse_kms_key_id = sse});
                stats._dead_letters += dead_count;
            }
            if (groups.empty()) {
                return true;
            }

            // Data files, then the manifest: both named by the batch, so a
            // retry overwrites them with the same bytes.
            const auto snapshot_id = snapshot_id_of(table->_uuid, batch_id);
            std::vector<iceberg::data_file> files;
            std::size_t part_index = 0;
            std::int64_t added_bytes = 0;
            for (auto& [k, g] : groups) {
                const auto bytes = parquet::write_file(
                    table->_schema, g.second, target._codec,
                    {{"iceberg.schema", boost::json::serialize(table->_schema)}});
                const auto key = key_prefix + "data/" + iceberg::partition_path(spec, g.first) +
                                 name + "-" + std::to_string(part_index) + ".parquet";
                store->_put(key, bytes, table_options);
                files.push_back(
                    iceberg::data_file{._path = "s3://" + location->first + "/" + key,
                                       ._partition = g.first,
                                       ._records = static_cast<std::int64_t>(g.second.size()),
                                       ._bytes = static_cast<std::int64_t>(bytes.size())});
                added_bytes += static_cast<std::int64_t>(bytes.size());
                ++part_index;
            }
            const auto manifest = iceberg::write_manifest(*table, spec, files, snapshot_id, name);
            const auto manifest_key = key_prefix + "metadata/" + name + "-m0.avro";
            store->_put(manifest_key, manifest, table_options);
            const auto manifest_uri = "s3://" + location->first + "/" + manifest_key;

            for (int attempt = 0; attempt < _config._commit_attempts; ++attempt) {
                const auto parent = parent_manifests(*table, access);
                const auto sequence = table->_last_sequence_number + 1;
                const auto first = iceberg::manifest_list_entry(
                    spec, files, manifest_uri, static_cast<std::int64_t>(manifest.size()),
                    table->_spec_id, snapshot_id, sequence);
                const auto list = iceberg::write_manifest_list(
                    first, parent, snapshot_id, table->_main_snapshot, sequence, name);
                const auto list_key = key_prefix + "metadata/snap-" + std::to_string(snapshot_id) +
                                      "-" + std::to_string(sequence) + "-" + name + ".avro";
                store->_put(list_key, list, table_options);

                auto snapshot = snapshot_of(*table, snapshot_id, sequence,
                                            "s3://" + location->first + "/" + list_key, files,
                                            added_bytes, groups.size(), batch_id, c);
                const auto request =
                    iceberg::commit_request(*table, target._ns, target._table, std::move(snapshot));
                const auto res =
                    catalog->_commit(target._ns, target._table, boost::json::serialize(request));
                if (res && res->_status == 200) {
                    stats._records += batch.size() - dead_count;
                    stats._objects += files.size();
                    return true;
                }
                if (!res || (res->_status != 409 && res->_status < 500)) {
                    ++stats._failures;
                    stats._last_failure =
                        res ? "Committing to " + target._ns + "." + target._table +
                                  " failed: " + iceberg_error_message(*res)
                            : "The Iceberg REST catalog did not answer the commit.";
                    return false;
                }
                // Another writer committed first (409), or the catalog failed
                // in a way that may have committed (5xx): read the table again;
                // if this batch is now in it, it is done.
                table = load_table(c, *catalog, target, stats);
                if (!table) {
                    return false;
                }
                if (table->snapshot_with("kythira.channel-batch", batch_id) != nullptr) {
                    stats._records += batch.size() - dead_count;
                    stats._objects += files.size();
                    return true;
                }
                // Another node committed part of this batch (it read less):
                // build again from what it left.
                if (const auto done = committed_prefix(*table, batch_prefix, batch); done > 0) {
                    if (done == batch.size()) {
                        return true;
                    }
                    return write_table_batch(c, dest, src, shard_id, tail_of(batch, done), stats);
                }
            }
            ++stats._failures;
            stats._last_failure = "Committing to " + target._ns + "." + target._table +
                                  " lost to other writers " +
                                  std::to_string(_config._commit_attempts) + " times.";
            return false;
        } catch (const iceberg::table_error& e) {
            fail_table_channel(c, e.what(), stats);
            return false;
        } catch (const std::exception& e) {
            ++stats._failures;
            stats._last_failure = e.what();
            return false;
        }
    }

    [[nodiscard]] auto snapshot_of(const iceberg::table_metadata& t, std::int64_t id,
                                   std::int64_t sequence, std::string list_uri,
                                   const std::vector<iceberg::data_file>& files,
                                   std::int64_t added_bytes, std::size_t partitions,
                                   const std::string& batch_id, const channel_record& c) const
        -> boost::json::object {
        std::int64_t rows = 0;
        for (const auto& f : files) {
            rows += f._records;
        }
        boost::json::object summary{
            {"operation", "append"},
            {"added-data-files", std::to_string(files.size())},
            {"added-records", std::to_string(rows)},
            {"added-files-size", std::to_string(added_bytes)},
            {"changed-partition-count", std::to_string(partitions)},
            {"kythira.channel-batch", batch_id},
            {"kythira.channel", c._name},
        };
        // A snapshot's timestamp may not go back past its parent's or the
        // table's last change: the catalog refuses the commit otherwise, so a
        // node whose clock lags the catalog's still commits.
        std::int64_t at = std::max(_cluster.now_ms(), t._last_updated_ms);
        if (t._main_snapshot) {
            if (const auto* p = t.snapshot(*t._main_snapshot)) {
                if (const auto* ts = p->if_contains("timestamp-ms");
                    ts != nullptr && ts->is_number()) {
                    at = std::max(at, ts->to_number<std::int64_t>());
                }
                // Running totals, when the parent kept them.
                if (const auto* ps = p->if_contains("summary"); ps != nullptr && ps->is_object()) {
                    const auto total = [&](const char* k, std::int64_t added) {
                        const auto* v = ps->as_object().if_contains(k);
                        if (v != nullptr && v->is_string()) {
                            try {
                                summary[k] =
                                    std::to_string(std::stoll(std::string(v->as_string())) + added);
                            } catch (const std::exception&) {
                                // An unreadable total is left out.
                            }
                        }
                    };
                    total("total-records", rows);
                    total("total-data-files", static_cast<std::int64_t>(files.size()));
                    total("total-files-size", added_bytes);
                    total("total-delete-files", 0);
                    total("total-position-deletes", 0);
                    total("total-equality-deletes", 0);
                }
            }
        } else {
            summary["total-records"] = std::to_string(rows);
            summary["total-data-files"] = std::to_string(files.size());
            summary["total-files-size"] = std::to_string(added_bytes);
            summary["total-delete-files"] = "0";
            summary["total-position-deletes"] = "0";
            summary["total-equality-deletes"] = "0";
        }
        boost::json::object snap{{"snapshot-id", id},
                                 {"sequence-number", sequence},
                                 {"timestamp-ms", at},
                                 {"manifest-list", std::move(list_uri)},
                                 {"summary", std::move(summary)},
                                 {"schema-id", t._schema_id}};
        if (t._main_snapshot) {
            snap["parent-snapshot-id"] = *t._main_snapshot;
        }
        return snap;
    }
};

}  // namespace kythira::kinesis
