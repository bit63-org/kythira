// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_data_access.hpp
/// @brief The named reads a front end makes of the data layer
///        (`.kiro/specs/sqs-compatible-queues/` task 10, Requirement 11.2).
///
/// A front end decides nothing from a replica: every decision that races
/// is `apply()`'s. What it does read is small and fixed, so it is a closed
/// set of named queries rather than a callback on the state machine,
/// which lets a front end without the data role send the same query to a
/// data node:
///
// clang-format off
/// | Query | Key it routes by | Answer |
/// |---|---|---|
/// | `find_queue(account, name)` | the queue's catalog key | the queue's record, if any |
/// | `list_queues(account, prefix, after, max)` | the account's catalog prefix | records in name order |
/// | `move_tasks(account, name)` | the queue's move-task prefix | its tasks, newest first |
/// | `counts(target)` | the partition's prefix | approximate counts, and the next deadline |
/// | `next_deadline(target)` | the partition's prefix | the earliest delay or visibility end |
// clang-format on
///
/// `answer_query` answers one from a state machine; a cluster holding a
/// replica answers through its `read` (`query_by_read`). On the wire
/// (`POST /_kythira/sqs/v1/query`, authenticated like forwarding, see
/// `sqs_forward.hpp`) a query and its answer are JSON, with records and
/// tasks in their catalog encoding, base64.

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_queue_commands.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>

#include <raft/aws_json_protocol.hpp>

#include <boost/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::sqs {

/// One named read of the data layer.
struct data_query {
    enum class kind : std::uint8_t {
        find_queue = 1,
        list_queues = 2,
        move_tasks = 3,
        counts = 4,
        next_deadline = 5,
    };
    kind _kind = kind::find_queue;
    std::string _account;
    std::string _name;
    std::string _prefix;
    std::string _after;
    std::uint64_t _max = 0;
    queue_target _target;

    [[nodiscard]] static auto find(std::string account, std::string name) -> data_query {
        data_query q;
        q._kind = kind::find_queue;
        q._account = std::move(account);
        q._name = std::move(name);
        return q;
    }
    [[nodiscard]] static auto list(std::string account, std::string prefix, std::string after,
                                   std::uint64_t max) -> data_query {
        data_query q;
        q._kind = kind::list_queues;
        q._account = std::move(account);
        q._prefix = std::move(prefix);
        q._after = std::move(after);
        q._max = max;
        return q;
    }
    [[nodiscard]] static auto moves(std::string account, std::string name) -> data_query {
        data_query q;
        q._kind = kind::move_tasks;
        q._account = std::move(account);
        q._name = std::move(name);
        return q;
    }
    [[nodiscard]] static auto counts_of(const queue_target& t) -> data_query {
        data_query q;
        q._kind = kind::counts;
        q._target = t;
        return q;
    }
    [[nodiscard]] static auto deadline_of(const queue_target& t) -> data_query {
        data_query q;
        q._kind = kind::next_deadline;
        q._target = t;
        return q;
    }

    friend auto operator==(const data_query&, const data_query&) -> bool = default;
};

/// What a query answered; only the member its kind names is set.
struct data_answer {
    std::optional<queue_record> _queue;
    std::vector<queue_record> _queues;
    std::vector<move_task> _tasks;
    partition_counts _counts;
    std::optional<std::uint64_t> _deadline;
};

/// The key a query routes by: whichever group owns it answers.
[[nodiscard]] inline auto query_key(const data_query& q) -> std::string {
    switch (q._kind) {
        case data_query::kind::find_queue:
            return catalog_keys::queue(q._account, q._name);
        case data_query::kind::list_queues:
            return catalog_keys::queues_prefix(q._account);
        case data_query::kind::move_tasks:
            return catalog_keys::moves_of(q._account, q._name);
        case data_query::kind::counts:
        case data_query::kind::next_deadline:
            break;
    }
    return queue_keys::partition_prefix(q._target);
}

/// Answers `q` from `sm`, a replica holding `query_key(q)`.
template<typename StateMachine>
[[nodiscard]] auto answer_query(const StateMachine& sm, const data_query& q) -> data_answer {
    data_answer a;
    switch (q._kind) {
        case data_query::kind::find_queue:
            a._queue = sm.find_queue(q._account, q._name);
            break;
        case data_query::kind::list_queues:
            a._queues =
                sm.list_queues(q._account, q._prefix, q._after, static_cast<std::size_t>(q._max));
            break;
        case data_query::kind::move_tasks:
            a._tasks = sm.move_tasks(q._account, q._name);
            break;
        case data_query::kind::counts:
            // With the deadline: a receive asks both, and one round trip is
            // cheaper than two across layers.
            a._counts = sm.counts(q._target);
            a._deadline = sm.next_deadline(q._target);
            break;
        case data_query::kind::next_deadline:
            a._deadline = sm.next_deadline(q._target);
            break;
    }
    return a;
}

/// `q` answered through `cluster.read` on this node's replica; nullopt
/// when this node holds none.
template<typename Cluster>
[[nodiscard]] auto query_by_read(Cluster& cluster, const data_query& q)
    -> std::optional<data_answer> {
    std::optional<data_answer> out;
    if (!cluster.read(query_key(q), [&](const typename Cluster::state_machine_type& sm) {
            out = answer_query(sm, q);
        })) {
        return std::nullopt;
    }
    return out;
}

// ---- wire -------------------------------------------------------------------

namespace data_wire {

inline constexpr std::string_view k_query_path = "/_kythira/sqs/v1/query";

[[nodiscard]] inline auto b64(const std::string& raw) -> std::string {
    return aws_json::base64_encode(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(raw.data()),  // NOLINT
                                   raw.size()));
}

[[nodiscard]] inline auto unb64(const boost::json::value& v) -> std::optional<std::string> {
    if (!v.is_string()) {
        return std::nullopt;
    }
    const auto bytes = aws_json::base64_decode(std::string_view(v.as_string()));
    if (!bytes) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());  // NOLINT
}

[[nodiscard]] inline auto str(const boost::json::object& o, std::string_view k) -> std::string {
    const auto* v = o.if_contains(k);
    return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string();
}

[[nodiscard]] inline auto u64(const boost::json::object& o, std::string_view k) -> std::uint64_t {
    const auto* v = o.if_contains(k);
    if (v == nullptr) {
        return 0;
    }
    if (v->is_uint64()) {
        return v->as_uint64();
    }
    return v->is_int64() && v->as_int64() >= 0 ? static_cast<std::uint64_t>(v->as_int64()) : 0;
}

}  // namespace data_wire

[[nodiscard]] inline auto encode_query(const data_query& q) -> std::string {
    boost::json::object o;
    o["kind"] = static_cast<std::uint64_t>(q._kind);
    o["account"] = q._account;
    o["name"] = q._name;
    o["prefix"] = q._prefix;
    o["after"] = q._after;
    o["max"] = q._max;
    o["queue_id"] = q._target.queue_id;
    o["partition"] = static_cast<std::uint64_t>(q._target.partition);
    o["fifo"] = q._target.fifo;
    o["retention_s"] = static_cast<std::uint64_t>(q._target.retention_s);
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_query(std::string_view in) -> std::optional<data_query> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto& o = v.as_object();
    const auto kind = data_wire::u64(o, "kind");
    if (kind < 1 || kind > 5) {
        return std::nullopt;
    }
    data_query q;
    q._kind = static_cast<data_query::kind>(kind);
    q._account = data_wire::str(o, "account");
    q._name = data_wire::str(o, "name");
    q._prefix = data_wire::str(o, "prefix");
    q._after = data_wire::str(o, "after");
    q._max = data_wire::u64(o, "max");
    q._target.queue_id = data_wire::u64(o, "queue_id");
    const auto partition = data_wire::u64(o, "partition");
    const auto retention = data_wire::u64(o, "retention_s");
    if (partition > 0xFFFFU || retention > 0xFFFFFFFFU) {
        return std::nullopt;
    }
    q._target.partition = static_cast<std::uint16_t>(partition);
    q._target.retention_s = static_cast<std::uint32_t>(retention);
    const auto* fifo = o.if_contains("fifo");
    q._target.fifo = fifo != nullptr && fifo->is_bool() && fifo->as_bool();
    return q;
}

[[nodiscard]] inline auto encode_answer(const data_answer& a) -> std::string {
    using data_wire::b64;
    boost::json::object o;
    if (a._queue) {
        o["queue"] = b64(encode_queue_record(*a._queue));
    }
    boost::json::array queues;
    for (const auto& r : a._queues) {
        queues.emplace_back(b64(encode_queue_record(r)));
    }
    o["queues"] = std::move(queues);
    boost::json::array tasks;
    for (const auto& t : a._tasks) {
        tasks.emplace_back(b64(encode_move_task(t)));
    }
    o["tasks"] = std::move(tasks);
    o["visible"] = a._counts.visible;
    o["not_visible"] = a._counts.not_visible;
    o["delayed"] = a._counts.delayed;
    if (a._deadline) {
        o["deadline"] = *a._deadline;
    }
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_answer(std::string_view in) -> std::optional<data_answer> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto& o = v.as_object();
    data_answer a;
    if (const auto* q = o.if_contains("queue")) {
        const auto raw = data_wire::unb64(*q);
        auto r = raw ? decode_queue_record(*raw) : std::nullopt;
        if (!r) {
            return std::nullopt;
        }
        a._queue = std::move(*r);
    }
    if (const auto* qs = o.if_contains("queues"); qs != nullptr && qs->is_array()) {
        for (const auto& e : qs->as_array()) {
            const auto raw = data_wire::unb64(e);
            auto r = raw ? decode_queue_record(*raw) : std::nullopt;
            if (!r) {
                return std::nullopt;
            }
            a._queues.push_back(std::move(*r));
        }
    }
    if (const auto* ts = o.if_contains("tasks"); ts != nullptr && ts->is_array()) {
        for (const auto& e : ts->as_array()) {
            const auto raw = data_wire::unb64(e);
            auto t = raw ? decode_move_task(*raw) : std::nullopt;
            if (!t) {
                return std::nullopt;
            }
            a._tasks.push_back(std::move(*t));
        }
    }
    a._counts.visible = data_wire::u64(o, "visible");
    a._counts.not_visible = data_wire::u64(o, "not_visible");
    a._counts.delayed = data_wire::u64(o, "delayed");
    if (o.contains("deadline")) {
        a._deadline = data_wire::u64(o, "deadline");
    }
    return a;
}

}  // namespace kythira::sqs
