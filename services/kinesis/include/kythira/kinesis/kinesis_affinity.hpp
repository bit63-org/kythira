// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_affinity.hpp
/// @brief Which front end a gateway hands a call to
///        (`.kiro/specs/kinesis-independent-layers/` task 8, design
///        "Affinity keeps each bucket in one place", Requirements 4.4,
///        8.2-8.4).
///
/// Read, iterator, control-plane and EFO buckets live in the front end that
/// serves the call. With one front end they are exact; with N, a consumer
/// whose calls spread over all N could take N times AWS's rate. So every
/// gateway picks the front end for a call the same way, by rendezvous
/// (highest random weight) hashing of an affinity key over the front ends
/// it knows:
///
/// - `GetRecords`, `GetShardIterator`, `SubscribeToShard`: the shard, as
///   (account, stream name, shard ordinal). `GetRecords` names its shard
///   only inside its iterator, which is read without checking its MAC
///   (`peek_iterator_route`); the front end checks it. The design keys by
///   stream id, which a gateway cannot know without the catalog; the name
///   in the caller's account names the same stream, and a stream deleted
///   and created again under the name merely keeps its front end.
/// - every other operation that has an account bucket (the control
///   plane): the account.
/// - writes and the Lease API: any front end, in turn. Write buckets stay
///   on the data-layer leader (Requirement 8.1), and leases have none.
///
/// Every gateway computes the same order from the same list, with no
/// coordination, so each bucket has one owner. Rendezvous hashing moves
/// only a departing front end's share when the set changes; the moved
/// buckets start full on their new owner, which can admit one extra
/// bucket's worth of traffic, the tolerance the Kinesis design accepts on a
/// leader change (Requirement 8.4).
///
/// A front end the gateway could not reach is *suspect* for a while: it
/// moves to the back of every order, so its keys go to the next front end
/// in their own order (the same one on every gateway that also failed to
/// reach it) until it answers again or the suspicion lapses.

#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_iterators.hpp>
#include <kythira/kinesis/kinesis_sequence.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis {

/// How a call is placed.
enum class affinity_kind : std::uint8_t {
    /// By shard: (account, stream, ordinal).
    shard,
    /// By account: the control plane.
    account,
    /// Anywhere: writes, leases, anything unkeyed.
    any
};

struct affinity_key {
    affinity_kind _kind = affinity_kind::any;
    /// What is hashed; empty for `any`.
    std::string _text;

    friend auto operator==(const affinity_key&, const affinity_key&) -> bool = default;
};

namespace affinity_detail {

[[nodiscard]] inline auto string_of(const boost::json::object& o, std::string_view key)
    -> std::optional<std::string_view> {
    if (const auto* v = o.if_contains(key); v != nullptr && v->is_string()) {
        return std::string_view(v->get_string());
    }
    return std::nullopt;
}

[[nodiscard]] inline auto shard_key(std::string_view account, std::string_view stream,
                                    std::uint32_t ordinal) -> affinity_key {
    std::string text = "shard\n";
    text.append(account).append("\n").append(stream).append("\n").append(std::to_string(ordinal));
    return {affinity_kind::shard, std::move(text)};
}

[[nodiscard]] inline auto account_key(std::string_view account) -> affinity_key {
    return {affinity_kind::account, "account\n" + std::string(account)};
}

/// The account and stream name a call's `StreamARN` or `StreamName`
/// names; the ARN wins (the front end refuses the call when they differ).
[[nodiscard]] inline auto stream_of(const authenticated_call& call)
    -> std::optional<std::pair<std::string, std::string>> {
    if (const auto arn = string_of(call._input, "StreamARN")) {
        const auto parts = parse_kinesis_arn(*arn);
        const auto name = stream_name_of(*arn);
        if (parts && name) {
            return std::pair{std::string(parts->_account), std::string(*name)};
        }
        return std::nullopt;
    }
    if (const auto name = string_of(call._input, "StreamName")) {
        return std::pair{call._principal.account, std::string(*name)};
    }
    return std::nullopt;
}

/// `.../stream/<name>/consumer/<consumer>:<time>`: the stream's account
/// and name.
[[nodiscard]] inline auto consumer_stream_of(std::string_view consumer_arn)
    -> std::optional<std::pair<std::string, std::string>> {
    const auto parts = parse_kinesis_arn(consumer_arn);
    if (!parts || !parts->_resource.starts_with("stream/")) {
        return std::nullopt;
    }
    auto rest = parts->_resource.substr(7);
    const auto slash = rest.find('/');
    if (slash == 0 || slash == std::string_view::npos ||
        !rest.substr(slash).starts_with("/consumer/")) {
        return std::nullopt;
    }
    return std::pair{std::string(parts->_account), std::string(rest.substr(0, slash))};
}

/// 64-bit FNV-1a, then a SplitMix64 finish so nearby texts spread: stable
/// across processes and builds, which `std::hash` is not, so every gateway
/// ranks the front ends alike.
[[nodiscard]] inline auto weight(std::string_view key, std::string_view member) -> std::uint64_t {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    const auto mix = [&h](std::string_view s) {
        for (const char c : s) {
            h ^= static_cast<unsigned char>(c);
            h *= 0x100000001b3ULL;
        }
    };
    mix(key);
    mix(std::string_view("\0", 1));
    mix(member);
    h += 0x9e3779b97f4a7c15ULL;
    h = (h ^ (h >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    h = (h ^ (h >> 27U)) * 0x94d049bb133111ebULL;
    return h ^ (h >> 31U);
}

}  // namespace affinity_detail

/// Where `call` is placed (see the file comment).
[[nodiscard]] inline auto affinity_of(const authenticated_call& call) -> affinity_key {
    using namespace affinity_detail;
    if (call._kind != call_kind::api) {
        return {};
    }
    const std::string_view op = call._operation;
    if (op == "GetRecords") {
        if (const auto token = string_of(call._input, "ShardIterator")) {
            if (const auto r = peek_iterator_route(*token)) {
                return shard_key(r->_account, r->_stream, r->_ordinal);
            }
        }
        // A malformed iterator goes anywhere and fails there.
        return {};
    }
    if (op == "GetShardIterator" || op == "SubscribeToShard") {
        const auto shard = string_of(call._input, "ShardId");
        const auto ordinal = shard ? parse_shard_id(*shard) : std::nullopt;
        std::optional<std::pair<std::string, std::string>> stream;
        if (op == "SubscribeToShard") {
            if (const auto consumer = string_of(call._input, "ConsumerARN")) {
                stream = consumer_stream_of(*consumer);
            }
        } else {
            stream = stream_of(call);
        }
        if (ordinal && stream) {
            return shard_key(stream->first, stream->second, *ordinal);
        }
        return {};
    }
    if (op == "PutRecord" || op == "PutRecords") {
        return {};
    }
    return account_key(call._principal.account);
}

/// `members` ranked for `key`, heaviest first: index order into `members`.
[[nodiscard]] inline auto rendezvous_order(std::string_view key,
                                           const std::vector<std::string>& members)
    -> std::vector<std::size_t> {
    std::vector<std::pair<std::uint64_t, std::size_t>> ranked;
    ranked.reserve(members.size());
    for (std::size_t i = 0; i < members.size(); ++i) {
        ranked.emplace_back(affinity_detail::weight(key, members[i]), i);
    }
    // Ties (practically impossible) fall to the member's text, so the order
    // is still the same on every gateway.
    std::sort(ranked.begin(), ranked.end(), [&members](const auto& a, const auto& b) {
        if (a.first != b.first) {
            return a.first > b.first;
        }
        return members[a.second] < members[b.second];
    });
    std::vector<std::size_t> out;
    out.reserve(ranked.size());
    for (const auto& [w, i] : ranked) {
        out.push_back(i);
    }
    return out;
}

struct front_end_set_options {
    /// How long a front end the gateway could not reach stays at the back
    /// of every order.
    std::chrono::milliseconds _suspect_for{2000};
    std::function<std::chrono::steady_clock::time_point()> _clock = [] {
        return std::chrono::steady_clock::now();
    };
};

/// The front ends a gateway hands calls to (`KINESIS_FRONT_ENDS`), with
/// the ones it recently failed to reach. Thread-safe.
class front_end_set {
public:
    explicit front_end_set(std::vector<std::string> addresses, front_end_set_options options = {})
        : _addresses(std::move(addresses)), _options(std::move(options)) {
        std::sort(_addresses.begin(), _addresses.end());
        _addresses.erase(std::unique(_addresses.begin(), _addresses.end()), _addresses.end());
    }

    [[nodiscard]] auto addresses() const noexcept -> const std::vector<std::string>& {
        return _addresses;
    }

    /// Every front end, in the order to try them for `key`: by rendezvous
    /// weight (or, for `any`, starting from the next in turn), with suspects
    /// moved to the back in the same relative order.
    [[nodiscard]] auto order_for(const affinity_key& key) -> std::vector<std::string> {
        std::vector<std::size_t> order;
        if (key._kind == affinity_kind::any) {
            const auto n = _addresses.size();
            const auto start = n == 0 ? 0 : _turn.fetch_add(1, std::memory_order_relaxed) % n;
            for (std::size_t i = 0; i < n; ++i) {
                order.push_back((start + i) % n);
            }
        } else {
            order = rendezvous_order(key._text, _addresses);
        }
        std::vector<std::string> live;
        std::vector<std::string> suspect;
        const auto now = _options._clock();
        const std::scoped_lock lock(_mu);
        for (const auto i : order) {
            const auto it = _suspect_until.find(_addresses[i]);
            if (it != _suspect_until.end() && it->second > now) {
                suspect.push_back(_addresses[i]);
            } else {
                live.push_back(_addresses[i]);
            }
        }
        live.insert(live.end(), suspect.begin(), suspect.end());
        return live;
    }

    /// The gateway could not reach `address`, or it said it would not take
    /// calls (draining).
    void mark_unreachable(const std::string& address) {
        const std::scoped_lock lock(_mu);
        _suspect_until[address] = _options._clock() + _options._suspect_for;
    }

    /// `address` answered.
    void mark_reachable(const std::string& address) {
        const std::scoped_lock lock(_mu);
        _suspect_until.erase(address);
    }

    /// Front ends suspect now.
    [[nodiscard]] auto suspects() const -> std::size_t {
        const auto now = _options._clock();
        const std::scoped_lock lock(_mu);
        return static_cast<std::size_t>(
            std::count_if(_suspect_until.begin(), _suspect_until.end(),
                          [now](const auto& kv) { return kv.second > now; }));
    }

private:
    std::vector<std::string> _addresses;
    front_end_set_options _options;
    std::atomic<std::uint64_t> _turn{0};
    mutable std::mutex _mu;
    std::map<std::string, std::chrono::steady_clock::time_point, std::less<>> _suspect_until;
};

}  // namespace kythira::kinesis
