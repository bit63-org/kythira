// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_records.hpp
/// @brief Reading one shard's records from the segment store
///        (`.kiro/specs/kinesis-compatible-streams/` task 7, Requirement
///        9.3, 9.4): what `GetRecords` serves, on any replica.
///
/// The reader takes a copy of the shard's replicated state (its sealed
/// segment index, last counter and trim point) and walks the index segment
/// by segment, so a sealed segment this replica lacks is fetched from a
/// peer through the state machine's fetcher, never silently skipped; if it
/// cannot be fetched the read reports it missing and `GetRecords` fails
/// with InternalFailure (design, "a segment failing its SHA-256 on fetch").
/// Past the sealed index it reads the active segment.
///
/// Positions below the trim point start at the trim point, as AWS starts a
/// trimmed iterator at the trim horizon (9.4). A minimum timestamp
/// (`AT_TIMESTAMP`) skips whole sealed segments by their last timestamp and
/// then single records; arrival times never decrease within a shard, so the
/// first record at or after it starts the answer.

#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>

#include <raft/record_segment_store.hpp>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <functional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kinesis {

struct read_record {
    std::uint64_t _counter = 0;
    std::int64_t _arrival_ms = 0;
    stored_record _record;
    /// Stored sealed (task 14) and opened for this read.
    bool _encrypted = false;
};

/// Opens a sealed stored record (task 14): the service's, which knows the
/// stream's data keys. Throws `kms_error` or `record_open_error`.
using record_opener = std::function<stored_record(std::span<const std::byte>)>;

struct shard_read {
    std::vector<read_record> _records;
    /// Where the next read starts: one past the last record looked at.
    std::uint64_t _next_counter = 0;
    /// Nothing past `_next_counter` exists yet.
    bool _caught_up = false;
    /// A sealed segment in the range is neither here nor fetchable.
    bool _missing = false;
};

/// A read before its records are opened: each record's stored bytes as
/// the segment holds them (sealed for an encrypted stream). What a data
/// node answers a front end's `read_records` with
/// (`.kiro/specs/kinesis-independent-layers/` task 2, Requirement 5.4), so
/// keys and plaintext stay on the front end.
struct raw_shard_read {
    /// Only records at or after the minimum timestamp; `_seq` is the
    /// shard counter.
    std::vector<segment_record> _records;
    std::uint64_t _next_counter = 0;
    bool _caught_up = false;
    bool _missing = false;

    friend auto operator==(const raw_shard_read&, const raw_shard_read&) -> bool = default;
};

/// Records of shard `key` at or after counter `from` (and, when
/// `min_timestamp_ms` is positive, arrival time), within `limits`, as
/// stored. `state` is the shard's state as copied from the replica. Throws
/// `record_segment_error` if a record fails its CRC.
[[nodiscard]] inline auto read_shard_raw(const segment_store& store, const segment_fetcher& fetch,
                                         const std::string& key, const shard_state& state,
                                         std::uint64_t from, std::int64_t min_timestamp_ms,
                                         const segment_read_limits& limits) -> raw_shard_read {
    raw_shard_read out;
    out._next_counter = std::max({from, state._trim_before, std::uint64_t{1}});
    std::size_t records_left = limits._max_records;
    std::uint64_t bytes_left = limits._max_bytes;
    const auto full = [&] { return records_left == 0 || bytes_left == 0; };
    const auto take = [&](segment_read_result& r) {
        for (auto& rec : r._records) {
            out._next_counter = rec._seq + 1;
            records_left = records_left > 0 ? records_left - 1 : 0;
            bytes_left -= std::min<std::uint64_t>(bytes_left, rec._data.size());
            if (rec._timestamp_ms < min_timestamp_ms) {
                continue;
            }
            out._records.push_back(std::move(rec));
        }
        if (r._records.empty()) {
            out._next_counter = std::max(out._next_counter, r._next_seq);
        }
    };
    const auto remaining = [&] {
        return segment_read_limits{._max_records = records_left, ._max_bytes = bytes_left};
    };

    for (const auto& d : state._sealed) {
        if (full()) {
            break;
        }
        if (d._last_seq < out._next_counter) {
            continue;
        }
        if (min_timestamp_ms > 0 && d._last_timestamp_ms < min_timestamp_ms) {
            out._next_counter = d._last_seq + 1;
            continue;
        }
        auto r = store.read_segment(key, d._first_seq, out._next_counter, remaining());
        if (!r && fetch) {
            try {
                fetch(d);
            } catch (const std::exception&) {
                // Reported as missing below.
            }
            r = store.read_segment(key, d._first_seq, out._next_counter, remaining());
        }
        if (!r) {
            out._missing = true;
            return out;
        }
        bool exhausted = r->_segment_exhausted;
        take(*r);
        if (!exhausted && !full() && fetch && !store.has_segment(d)) {
            // The local copy stops short and is not the sealed segment: a
            // short, unsealed one from before this replica went down, when
            // the others sealed it and the replica caught up by snapshot,
            // so the entries that would have filled it were never replayed
            // here. Fetch the sealed segment in its place (an install
            // replaces the copy) and read on from where the copy ended.
            // Checked only once a page stops short, so ordinary paging
            // through a sealed segment never hashes it.
            try {
                fetch(d);
                if (auto again =
                        store.read_segment(key, d._first_seq, out._next_counter, remaining())) {
                    exhausted = again->_segment_exhausted;
                    take(*again);
                }
            } catch (const std::exception&) {
                // Still short: reported as missing below.
            }
        }
        if (!exhausted && !full()) {
            // A sealed segment that stops short of its descriptor: never
            // skip past what it should hold.
            out._missing = true;
            return out;
        }
    }
    if (!full()) {
        auto r = store.read(key, out._next_counter, remaining());
        take(r);
    }
    const auto tip = std::max(state._last_counter, store.last_seq(key).value_or(0));
    out._caught_up = out._next_counter > tip;
    return out;
}

/// Opens a raw read's records: plaintext ones are decoded, sealed ones go
/// through `open`. Throws `record_open_error` for a sealed record with no
/// `open`, and whatever `open` throws.
[[nodiscard]] inline auto open_shard_read(raw_shard_read raw, const record_opener& open = {})
    -> shard_read {
    shard_read out;
    out._next_counter = raw._next_counter;
    out._caught_up = raw._caught_up;
    out._missing = raw._missing;
    out._records.reserve(raw._records.size());
    for (const auto& rec : raw._records) {
        const bool sealed = is_sealed_record(rec._data);
        if (sealed && !open) {
            throw record_open_error("kinesis: a sealed record and no key to open it");
        }
        out._records.push_back(
            {._counter = rec._seq,
             ._arrival_ms = rec._timestamp_ms,
             ._record = sealed ? open(rec._data) : decode_stored_record(rec._data),
             ._encrypted = sealed});
    }
    return out;
}

/// `read_shard_raw` then `open_shard_read`: what a replica that holds the
/// shard serves itself. Throws as both do.
[[nodiscard]] inline auto read_shard(const segment_store& store, const segment_fetcher& fetch,
                                     const std::string& key, const shard_state& state,
                                     std::uint64_t from, std::int64_t min_timestamp_ms,
                                     const segment_read_limits& limits,
                                     const record_opener& open = {}) -> shard_read {
    return open_shard_read(read_shard_raw(store, fetch, key, state, from, min_timestamp_ms, limits),
                           open);
}

}  // namespace kythira::kinesis
