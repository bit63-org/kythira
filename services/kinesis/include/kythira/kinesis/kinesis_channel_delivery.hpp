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
/// retried after a failed checkpoint lands on the same key. A child shard
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

#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>
#include <kythira/kinesis/kinesis_tiering.hpp>

#include <boost/json.hpp>

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
#include <zlib.h>
#endif
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
#include <zstd.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <exception>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis {

struct channel_delivery_config {
    /// The object store for a destination bucket (the name from the
    /// bucket ARN), or nullopt when this node cannot reach it; unset turns
    /// delivery off on this node.
    std::function<std::optional<tier_store>(const std::string& bucket)> _destination;
    /// Write an object once a batch holds this many bytes, however fresh.
    std::size_t _max_object_bytes = std::size_t{64} * 1024 * 1024;
    /// Bytes read from a shard per page.
    std::size_t _page_bytes = std::size_t{4} * 1024 * 1024;
    /// Whether this node can write a `CompressionType`; unset asks what
    /// the build has (`channel_detail::can_compress`). Tests narrow it.
    std::function<bool(std::string_view)> _can_compress;
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
};

namespace channel_detail {

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

/// Whether this build can write `compression` (`NONE`, `GZIP`, `ZSTD`).
[[nodiscard]] inline auto can_compress(std::string_view compression) -> bool {
    if (compression == "NONE") {
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
        for (const auto& job : jobs()) {
            try {
                channel(job, stats);
            } catch (const std::exception&) {
                ++stats._failures;
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

    Cluster& _cluster;
    Service& _service;
    channel_delivery_config _config;

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
                    c->_destination != channel_destination::s3) {
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
        const auto& storage = dest.at("StorageConfiguration").as_object();
        const std::string compression(storage.at("CompressionType").as_string());
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
                                                   10'000, room);
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
        const auto freshness_ms =
            dest.at("DataFreshnessInSeconds").to_number<std::int64_t>() * std::int64_t{1000};
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
        if (!write_batch(c, dest, src, shard_id, batch, stats)) {
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
        try {
            if (has_body) {
                const auto store = _config._destination(bucket);
                if (!store || !store->configured()) {
                    ++stats._failures;
                    return false;
                }
                store->_put(store->_prefix +
                                channel_detail::expand_template(tpl, first._arrival_ms, c._name,
                                                                src._stream, shard_id) +
                                name + std::string(ext),
                            *payload);
                ++stats._objects;
            }
            if (dead_count > 0) {
                std::string dlq_bucket = bucket;
                std::string prefix = "errors/";
                if (const auto* d = dest.if_contains("DeadLetterQueueS3Configuration");
                    d != nullptr && d->is_object()) {
                    dlq_bucket = channel_detail::bucket_of(d->at("BucketARN").as_string());
                    if (const auto* p = d->as_object().if_contains("ErrorOutputPrefix")) {
                        prefix = std::string(p->as_string());
                    }
                }
                const auto store = _config._destination(dlq_bucket);
                if (!store || !store->configured()) {
                    ++stats._failures;
                    return false;
                }
                store->_put(store->_prefix +
                                channel_detail::expand_template(prefix, first._arrival_ms, c._name,
                                                                src._stream, shard_id) +
                                name + ".json",
                            dead);
                stats._dead_letters += dead_count;
            }
        } catch (const std::exception&) {
            ++stats._failures;
            return false;
        }
        stats._records += batch.size() - dead_count;
        return true;
    }
};

}  // namespace kythira::kinesis
