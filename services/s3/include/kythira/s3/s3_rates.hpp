// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_rates.hpp
/// @brief Per-prefix request rates (.kiro/specs/s3-compatible-storage/
///        task 12, Requirement 13).
///
/// S3 scales by key prefix: each prefix takes at least 3,500 writes
/// (PUT, COPY, POST, DELETE) and 5,500 reads (GET, HEAD) a second, and
/// a client going faster gets `503 SlowDown`, which every SDK retries
/// with backoff. `prefix_rates` keeps one token bucket per (bucket,
/// prefix, reads or writes) in the front end, filled at the profile's
/// `prefix_put_rate` / `prefix_get_rate` (bucket tags override them;
/// 0 turns the limit off) with one second of burst.
///
/// A prefix here is the key up to and including its last `/`: S3's
/// partitions follow the key space and split where the load is, so
/// "folder" boundaries are the natural unit, and keys with no `/` share
/// the bucket's root prefix. Bucket-level requests (listings) count
/// against the root prefix, or the listing's `prefix` up to its last `/`.
///
/// **Hot prefixes.** A prefix refused more than `hot_refusals` times in
/// a `hot_window` is reported once per window through `on_hot`, which
/// is how the metadata layer learns to split that prefix's range so its
/// rate scales (13.1); with one metadata group per bucket (until
/// task 17's independent metadata nodes) the report is a metric.
///
/// **Affinity.** The buckets live in each front end, so a client that
/// spreads one prefix's requests over N front ends gets N times the rate.
/// Requirement 13.2's prefix-affinity routing in the gateway, which
/// sends one prefix to one front end as Kinesis routes a shard, is the
/// gateway's (task 17); until then the limit is per front end, never
/// tighter than S3's.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace kythira::s3 {

/// The prefix a key's rate counts against.
[[nodiscard]] inline auto rate_prefix(std::string_view key) -> std::string {
    const auto slash = key.rfind('/');
    return slash == std::string_view::npos ? std::string{} : std::string(key.substr(0, slash + 1));
}

class prefix_rates {
public:
    /// Called with (bucket, prefix) for a prefix refusing requests often.
    using hot_fn = std::function<void(const std::string&, const std::string&)>;

    struct options {
        std::size_t hot_refusals = 100;
        std::chrono::milliseconds hot_window = std::chrono::seconds(10);
        /// Idle buckets beyond this many are dropped (a full bucket and a
        /// missing one admit the same).
        std::size_t max_tracked = 100'000;
    };

    prefix_rates() = default;
    explicit prefix_rates(options o, hot_fn on_hot = {})
        : _options(o), _on_hot(std::move(on_hot)) {}

    /// Whether one request at `now_ms` against `bucket`'s `prefix` fits
    /// `rate` a second (0: unlimited). Refused requests take no token.
    auto admit(const std::string& bucket, const std::string& prefix, bool write, std::uint64_t rate,
               std::uint64_t now_ms) -> bool {
        if (rate == 0) {
            return true;
        }
        hot_fn report;
        bool ok = false;
        {
            const std::lock_guard lock(_mu);
            auto key = std::make_tuple(bucket, prefix, write);
            auto it = _buckets.find(key);
            if (it == _buckets.end()) {
                if (_buckets.size() >= _options.max_tracked) {
                    evict_idle(now_ms);
                }
                it = _buckets.emplace(std::move(key), state{static_cast<double>(rate), now_ms})
                         .first;
            }
            auto& s = it->second;
            const auto elapsed = static_cast<double>(now_ms > s.last_ms ? now_ms - s.last_ms : 0);
            s.tokens = std::min(static_cast<double>(rate),
                                s.tokens + elapsed * static_cast<double>(rate) / 1000.0);
            s.last_ms = std::max(s.last_ms, now_ms);
            if (s.tokens >= 1.0) {
                s.tokens -= 1.0;
                ok = true;
            } else {
                ++_refused;
                if (now_ms >= s.window_start_ms + window_ms()) {
                    s.window_start_ms = now_ms;
                    s.window_refusals = 0;
                    s.reported = false;
                }
                if (++s.window_refusals > _options.hot_refusals && !s.reported) {
                    s.reported = true;
                    ++_hot_reports;
                    report = _on_hot;
                }
            }
        }
        if (report) {
            report(bucket, prefix);
        }
        return ok;
    }

    [[nodiscard]] auto refused() const -> std::uint64_t {
        const std::lock_guard lock(_mu);
        return _refused;
    }
    [[nodiscard]] auto hot_reports() const -> std::uint64_t {
        const std::lock_guard lock(_mu);
        return _hot_reports;
    }
    [[nodiscard]] auto tracked() const -> std::size_t {
        const std::lock_guard lock(_mu);
        return _buckets.size();
    }

private:
    struct state {
        double tokens = 0;
        std::uint64_t last_ms = 0;
        std::uint64_t window_start_ms = 0;
        std::size_t window_refusals = 0;
        bool reported = false;
    };

    [[nodiscard]] auto window_ms() const -> std::uint64_t {
        return static_cast<std::uint64_t>(_options.hot_window.count());
    }

    /// Drop buckets untouched for a second or more: refilled, they hold
    /// their whole burst, which is what a fresh one starts with.
    void evict_idle(std::uint64_t now_ms) {
        std::erase_if(_buckets, [&](const auto& kv) { return now_ms >= kv.second.last_ms + 1000; });
    }

    options _options;
    hot_fn _on_hot;
    mutable std::mutex _mu;
    std::map<std::tuple<std::string, std::string, bool>, state> _buckets;
    std::uint64_t _refused = 0;
    std::uint64_t _hot_reports = 0;
};

}  // namespace kythira::s3
