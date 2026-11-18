// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file segment_store.hpp
/// @brief The record segment store as an interface
///        (.kiro/specs/kinesis-independent-layers/ task 1, design "Segment
///        store as a layer", Requirements 9.1 and 12.1).
///
/// A state machine that keeps record bytes outside its snapshot (Kinesis
/// shards, DynamoDB's change log) holds a `segment_store*` rather than a
/// concrete store, so the bytes can live on the node's own disk
/// (`record_segment_store`, `record_segment_store.hpp`) or on a separate
/// segment node's volume (`remote_segment_store`, a later task) without the
/// state machine knowing which.
///
/// The contract of every member is the one `record_segment_store`
/// documents: appends are durable only after `barrier()`, every replica fed
/// the same appends, seals and truncations holds byte-identical segments,
/// and seals, installs, trims and truncations are durable on return. A
/// virtual interface rather than a concept because its users store a
/// pointer and are not templated on the store; one virtual call per append
/// is noise beside the I/O behind it.
///
/// The value types here are shared by every implementation and know nothing
/// of Kinesis or DynamoDB: a *stream* is an opaque key and a *record* is a
/// caller-chosen 64-bit sequence, a timestamp and opaque bytes.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace kythira {

/// A segment's SHA-256, over its whole file (header, records and, once
/// sealed, footer).
using segment_sha256 = std::array<std::byte, 32>;

/// An I/O failure or an impossible on-disk state. A state machine treats it
/// as fatal for the replica: skipping an append would let it diverge.
class record_segment_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// A record as the store holds it.
struct segment_record {
    std::uint64_t _seq = 0;
    std::int64_t _timestamp_ms = 0;
    std::vector<std::byte> _data;

    friend auto operator==(const segment_record&, const segment_record&) -> bool = default;
};

/// A record to append; the bytes are borrowed for the call.
struct segment_record_view {
    std::uint64_t _seq = 0;
    std::int64_t _timestamp_ms = 0;
    std::span<const std::byte> _data;
};

/// One segment as a state machine records it in its replicated index. For
/// an active segment the size and digest are of what was written so far,
/// which is enough to fetch and verify that prefix from a peer.
struct record_segment_descriptor {
    std::string _stream;
    std::uint64_t _first_seq = 0;
    std::uint64_t _last_seq = 0;
    std::uint64_t _records = 0;
    std::int64_t _first_timestamp_ms = 0;
    std::int64_t _last_timestamp_ms = 0;
    /// File size in bytes.
    std::uint64_t _bytes = 0;
    segment_sha256 _sha256{};
    bool _sealed = false;

    friend auto operator==(const record_segment_descriptor&, const record_segment_descriptor&)
        -> bool = default;
};

struct record_segment_append_result {
    /// Segments this append sealed by rolling, oldest first. A state machine
    /// moves them to sealed in its index.
    std::vector<record_segment_descriptor> _sealed;
};

/// Limits for one read. At least one record is returned when one is
/// available, even if it alone exceeds `_max_bytes`, so a reader always
/// makes progress.
struct segment_read_limits {
    std::size_t _max_records = 10'000;
    std::uint64_t _max_bytes = std::uint64_t{10} * 1024 * 1024;
};

struct segment_read_result {
    std::vector<segment_record> _records;
    /// Where to continue: one past the last returned record, or the
    /// requested position when nothing was returned.
    std::uint64_t _next_seq = 0;
    /// `read_segment` only: the segment holds nothing at or after
    /// `_next_seq`, so the caller moves to the next segment in its index.
    /// Always `false` for an active segment, which may still grow.
    bool _segment_exhausted = false;
};

struct record_segment_store_stats {
    std::uint64_t _streams = 0;
    std::uint64_t _active_segments = 0;
    std::uint64_t _sealed_segments = 0;
    std::uint64_t _bytes_on_disk = 0;
    std::uint64_t _records_appended = 0;
    std::uint64_t _barriers = 0;
    /// Active segments whose torn tail an open scan truncated.
    std::uint64_t _torn_tails_truncated = 0;
    /// Files an open scan could not trust and renamed to `.corrupt`.
    std::uint64_t _quarantined = 0;
    /// Segments installed from a peer.
    std::uint64_t _installed = 0;
    /// Peer answers that were absent or did not match the descriptor.
    std::uint64_t _fetch_misses = 0;
    /// Records a read found failing their CRC.
    std::uint64_t _read_crc_failures = 0;
};

/// Where a state machine's record bytes are kept. See the file comment and
/// `record_segment_store` for the contract of each member.
class segment_store {
public:
    /// Fetches up to `length` bytes of a peer's copy of a segment, from
    /// offset 0 (the peer's `read_segment_bytes`). `nullopt` when the peer
    /// is down or has no copy.
    using fetch_transport = std::function<std::optional<std::vector<std::byte>>(
        const std::string& peer, const std::string& stream, std::uint64_t first_seq,
        std::uint64_t length)>;

    segment_store(const segment_store&) = delete;
    auto operator=(const segment_store&) -> segment_store& = delete;
    segment_store(segment_store&&) = delete;
    auto operator=(segment_store&&) -> segment_store& = delete;
    virtual ~segment_store() = default;

    /// The largest record payload `append` accepts.
    [[nodiscard]] virtual auto max_record_bytes() const noexcept -> std::uint32_t = 0;

    // ---- writes (from apply) --------------------------------------------

    /// Append records to `stream` in strictly increasing sequence order.
    /// Returns the segments that sealed by rolling. Durable only after
    /// `barrier()`.
    virtual auto append(const std::string& stream, std::span<const segment_record_view> records)
        -> record_segment_append_result = 0;

    /// Convenience overload for one record.
    auto append(const std::string& stream, const segment_record_view& record)
        -> record_segment_append_result {
        return append(stream, std::span<const segment_record_view>(&record, 1));
    }

    /// Make every append that returned before this call durable. Throws if
    /// that fails; the caller must not acknowledge the entries it covered.
    virtual void barrier() = 0;

    /// Seal the stream's active segment; `nullopt` if it has none.
    virtual auto seal(const std::string& stream) -> std::optional<record_segment_descriptor> = 0;

    /// Remove every record above `seq` (every record when `nullopt`).
    virtual void truncate_after(const std::string& stream, std::optional<std::uint64_t> seq) = 0;

    /// Remove sealed segments whose last record is below `seq`; returns
    /// their first sequences.
    virtual auto trim_before(const std::string& stream, std::uint64_t seq)
        -> std::vector<std::uint64_t> = 0;

    /// Remove one sealed segment's copy; returns whether one was there.
    virtual auto remove_segment(const std::string& stream, std::uint64_t first_seq) -> bool = 0;

    /// Remove a stream and all its segments.
    virtual void drop_stream(const std::string& stream) = 0;

    /// Store a segment's file bytes after checking them against `d`.
    /// Returns `false` if an identical sealed copy was already here.
    virtual auto install_segment(const record_segment_descriptor& d,
                                 std::span<const std::byte> bytes) -> bool = 0;

    /// Fetch `d` from the first peer whose bytes match it and install it.
    virtual auto fetch_segment(const record_segment_descriptor& d,
                               std::span<const std::string> peers, const fetch_transport& transport)
        -> bool = 0;

    // ---- reads ----------------------------------------------------------

    /// Up to `length` bytes of a segment's file from offset 0.
    [[nodiscard]] virtual auto read_segment_bytes(const std::string& stream,
                                                  std::uint64_t first_seq,
                                                  std::uint64_t length) const
        -> std::optional<std::vector<std::byte>> = 0;

    /// Records of one segment at or after `from_seq`; `nullopt` if the
    /// segment is not here.
    [[nodiscard]] virtual auto read_segment(const std::string& stream, std::uint64_t first_seq,
                                            std::uint64_t from_seq,
                                            const segment_read_limits& limits) const
        -> std::optional<segment_read_result> = 0;

    [[nodiscard]] auto read_segment(const std::string& stream, std::uint64_t first_seq,
                                    std::uint64_t from_seq) const
        -> std::optional<segment_read_result> {
        return read_segment(stream, first_seq, from_seq, segment_read_limits{});
    }

    /// Records at or after `from_seq` across the segments held here.
    [[nodiscard]] virtual auto read(const std::string& stream, std::uint64_t from_seq,
                                    const segment_read_limits& limits) const
        -> segment_read_result = 0;

    [[nodiscard]] auto read(const std::string& stream, std::uint64_t from_seq) const
        -> segment_read_result {
        return read(stream, from_seq, segment_read_limits{});
    }

    /// The descriptor of a segment held here, digest included.
    [[nodiscard]] virtual auto describe(const std::string& stream, std::uint64_t first_seq) const
        -> std::optional<record_segment_descriptor> = 0;

    /// Descriptors of every segment of `stream` held here, oldest first.
    [[nodiscard]] virtual auto local_segments(const std::string& stream) const
        -> std::vector<record_segment_descriptor> = 0;

    /// Whether an identical copy of `d` is held here.
    [[nodiscard]] virtual auto has_segment(const record_segment_descriptor& d) const -> bool = 0;

    /// The highest sequence stored for `stream`.
    [[nodiscard]] virtual auto last_seq(const std::string& stream) const
        -> std::optional<std::uint64_t> = 0;

    /// Every stream with at least one segment held here.
    [[nodiscard]] virtual auto streams() const -> std::vector<std::string> = 0;

    [[nodiscard]] virtual auto stats() const -> record_segment_store_stats = 0;

protected:
    segment_store() = default;
};

}  // namespace kythira
