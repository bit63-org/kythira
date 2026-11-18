// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_service.hpp
/// @brief The SQS queue and message handlers
///        (`.kiro/specs/sqs-compatible-queues/` task 4, Requirements 4.1,
///        5.1-5.5).
///
/// `sqs_service` registers a handler for every queue and message operation
/// with an `sqs_front_end`, which has already authenticated the caller,
/// parsed either protocol into one JSON input, resolved the queue and
/// authorized the primary action by the time a handler runs. A handler
/// reads the queue's catalog record, checks what needs the compatibility
/// profile or another queue, and commits one catalog or partition entry
/// per Raft group it touches through a `queue_cluster`.
///
/// What the handlers own (design "Encryption at the front end"): message
/// ids, MD5 digests over what the client sent, attribute encodings,
/// FIFO deduplication keys, sequence numbers and receipt handles. The
/// state machine stores those as opaque strings and decides only what
/// races.
///
/// Partitions (design "Partitions"): a standard send goes to the queue's
/// partitions in rotation, a whole batch to one partition so it is one
/// entry; a FIFO send goes to the partition its message group hashes to,
/// so a group's order is one partition's order. A receive visits the
/// partitions in rotation, skipping those this node's replica shows with
/// nothing visible and nothing due, until it has as many messages as were
/// asked for.
///
/// Long polling (task 5): a receive that finds nothing and may wait
/// (`WaitTimeSeconds`, else the queue's `ReceiveMessageWaitTimeSeconds`)
/// subscribes to all its queue's partitions on the configured
/// `availability_hub` and tries again only when one gains visible messages,
/// until the wait ends or the hub drains (`sqs_long_poll.hpp`). Without a
/// hub a receive answers at once.
///
/// Dead-letter queues (task 6): a receive carries its queue's redrive
/// target, so a message received `maxReceiveCount` times moves in the same
/// entry. The move-task operations keep their tasks in the catalog; the
/// move worker (`sqs_workers.hpp`) does the moving.
///
/// Encrypted queues (task 7): a send seals body and attributes after the
/// digests are taken; a receive opens them (`sqs_sse.hpp`).
///
/// Throughput (task 8): FIFO request rates and in-flight limits as SQS
/// keeps them; partitions grow through the grow worker
/// (`sqs_workers.hpp`), fair receives are the state machine's. FIFO
/// `ReceiveRequestAttemptId` is accepted and not yet honoured.

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_compat_profile.hpp>
#include <kythira/sqs/sqs_errors.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_long_poll.hpp>
#include <kythira/sqs/sqs_messages.hpp>
#include <kythira/sqs/sqs_queue_attributes.hpp>
#include <kythira/sqs/sqs_queue_commands.hpp>
#include <kythira/sqs/sqs_queue_policy.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>
#include <kythira/sqs/sqs_receipts.hpp>
#include <kythira/sqs/sqs_sse.hpp>

#include <raft/aws_json_protocol.hpp>

#include <boost/json.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

struct sqs_service_config {
    /// Signs and checks receipt handles (`sqs_receipts.hpp`); every front
    /// end of a cluster holds the same ring.
    receipt_key_ring _receipt_keys;
    /// The cluster's compatibility profile; a queue's `kythira:compat:*`
    /// tags narrow or widen it (`sqs_compat_profile.hpp`).
    sqs_compat_profile _profile;
    /// How many times a settings change retries when another change to the
    /// same queue committed between its read and its write.
    int _cas_attempts = 8;
    /// Where long polls park; the replica's state machines notify it. Null:
    /// every receive answers at once. Outlives the service.
    availability_hub* _waits = nullptr;
    /// Seals and opens bodies of encrypted queues (`sqs_sse.hpp`); every
    /// front end of a cluster needs the same SSE-SQS master key. Null: a
    /// random SSE-SQS key for this process and no SSE-KMS provider, which
    /// is right for one in-memory node only.
    std::shared_ptr<sse_keys> _sse;
};

namespace service_detail {

using front_end_detail::string_member;

[[nodiscard]] inline auto int_member(const boost::json::object& o, std::string_view key)
    -> std::optional<std::int64_t> {
    const auto* v = o.if_contains(key);
    if (v == nullptr) {
        return std::nullopt;
    }
    if (v->is_int64()) {
        return v->get_int64();
    }
    if (v->is_uint64()) {
        return static_cast<std::int64_t>(std::min<std::uint64_t>(v->get_uint64(), INT64_MAX));
    }
    return std::nullopt;
}

[[nodiscard]] inline auto object_member(const boost::json::object& o, std::string_view key)
    -> boost::json::object {
    const auto* v = o.if_contains(key);
    return v != nullptr && v->is_object() ? v->get_object() : boost::json::object{};
}

[[nodiscard]] inline auto strings_member(const boost::json::object& o, std::string_view key)
    -> std::vector<std::string> {
    std::vector<std::string> out;
    if (const auto* v = o.if_contains(key); v != nullptr && v->is_array()) {
        for (const auto& s : v->get_array()) {
            if (s.is_string()) {
                out.emplace_back(s.get_string());
            }
        }
    }
    return out;
}

[[nodiscard]] inline auto string_map(const boost::json::object& o)
    -> std::map<std::string, std::string> {
    std::map<std::string, std::string> out;
    for (const auto& kv : o) {
        if (kv.value().is_string()) {
            out.emplace(std::string(kv.key()), std::string(kv.value().get_string()));
        }
    }
    return out;
}

[[nodiscard]] inline auto tag_pairs(const std::map<std::string, std::string>& tags)
    -> std::vector<std::pair<std::string, std::string>> {
    return {tags.begin(), tags.end()};
}

[[nodiscard]] inline auto invalid_value(std::string_view param, std::string_view value,
                                        std::string_view reason) -> aws_json::error {
    return make_error(k_validation_error, "Value " + std::string(value) + " for parameter " +
                                              std::string(param) +
                                              " is invalid. Reason: " + std::string(reason));
}

[[nodiscard]] inline auto missing(std::string_view param) -> aws_json::error {
    return make_error(k_missing_parameter_error,
                      "The request must contain the parameter " + std::string(param) + ".");
}

[[nodiscard]] inline auto bad_receipt(std::string_view token) -> aws_json::error {
    return modeled_error(
        "ReceiptHandleIsInvalid",
        "The input receipt handle \"" + std::string(token) + "\" is not a valid receipt handle.");
}

[[nodiscard]] inline auto to_bytes(const std::string& s) -> std::vector<std::byte> {
    const auto* p = reinterpret_cast<const std::byte*>(s.data());  // NOLINT
    return {p, p + s.size()};
}

[[nodiscard]] inline auto to_string(const std::vector<std::byte>& b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};  // NOLINT
}

[[nodiscard]] inline auto sha256_hex(std::string_view bytes) -> std::string {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("sqs: SHA-256 failed");
    }
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    for (unsigned i = 0; i < len; ++i) {
        out += hex[digest.at(i) >> 4U];
        out += hex[digest.at(i) & 0xFU];
    }
    return out;
}

/// A random (version 4) UUID, as SQS message ids are.
[[nodiscard]] inline auto new_message_id() -> std::string {
    std::array<unsigned char, 16> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) {
        throw std::runtime_error("sqs: no randomness for a message id");
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0FU) | 0x40U);
    b[8] = static_cast<unsigned char>((b[8] & 0x3FU) | 0x80U);
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out += '-';
        }
        out += hex[b.at(i) >> 4U];
        out += hex[b.at(i) & 0xFU];
    }
    return out;
}

/// A FIFO message's `SequenceNumber`: 20 decimal digits, increasing with
/// the partition's sequence, so increasing within a message group.
[[nodiscard]] inline auto sequence_number(std::uint16_t partition, std::uint64_t sequence)
    -> std::string {
    const auto v =
        (static_cast<std::uint64_t>(partition) << 48U) | (sequence & ((1ULL << 48U) - 1));
    auto s = std::to_string(v);
    return std::string(20 - std::min<std::size_t>(s.size(), 20), '0') + s;
}

/// The stored system attributes: the sender and what the client sent as
/// `MessageSystemAttributes` (only `AWSTraceHeader` today).
[[nodiscard]] inline auto encode_system(std::string_view sender, const boost::json::object& sys)
    -> std::string {
    return boost::json::serialize(boost::json::object{{"s", sender}, {"a", sys}});
}

struct system_view {
    std::string _sender;
    boost::json::object _attributes;
};

[[nodiscard]] inline auto decode_system(std::string_view stored) -> system_view {
    const auto o = decode_attributes(stored);
    system_view out;
    if (const auto s = string_member(o, "s")) {
        out._sender = std::string(*s);
    }
    out._attributes = object_member(o, "a");
    return out;
}

/// A batch entry `Id`: 1 to 80 of `[A-Za-z0-9_-]`.
[[nodiscard]] inline auto valid_entry_id(std::string_view id) -> bool {
    return !id.empty() && id.size() <= 80 && std::all_of(id.begin(), id.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '_';
    });
}

/// A FIFO `MessageGroupId` or `MessageDeduplicationId`: 1 to 128 of
/// alphanumerics and ASCII punctuation.
[[nodiscard]] inline auto valid_fifo_token(std::string_view s) -> bool {
    return !s.empty() && s.size() <= 128 &&
           std::all_of(s.begin(), s.end(), [](char c) { return c > ' ' && c < 0x7F; });
}

}  // namespace service_detail

template<queue_cluster Cluster> class sqs_service {
public:
    using state_machine_type = typename Cluster::state_machine_type;

    /// @param cluster Outlives the service.
    sqs_service(Cluster& cluster, sqs_service_config config)
        : _cluster(cluster), _config(std::move(config)) {
        if (_config._receipt_keys._keys.empty()) {
            throw std::invalid_argument("sqs_service: no receipt key");
        }
        if (!_config._sse) {
            _config._sse = std::make_shared<sse_keys>(key_provider(wrapping_provider(random_key())),
                                                      key_provider{});
        }
    }

    /// The operations this service implements, as the model names them.
    static constexpr std::array<std::string_view, 23> k_operations{
        "AddPermission",
        "CancelMessageMoveTask",
        "ChangeMessageVisibility",
        "ChangeMessageVisibilityBatch",
        "CreateQueue",
        "DeleteMessage",
        "DeleteMessageBatch",
        "DeleteQueue",
        "GetQueueAttributes",
        "GetQueueUrl",
        "ListDeadLetterSourceQueues",
        "ListMessageMoveTasks",
        "ListQueueTags",
        "ListQueues",
        "PurgeQueue",
        "ReceiveMessage",
        "RemovePermission",
        "SendMessage",
        "SendMessageBatch",
        "SetQueueAttributes",
        "StartMessageMoveTask",
        "TagQueue",
        "UntagQueue",
    };

    template<typename FrontEnd> void register_with(FrontEnd& fe) {
        using ctx_t = sqs_call_context;
        using in_t = boost::json::object;
        const auto bind = [this, &fe](std::string_view op, auto method) {
            fe.on(op, [this, method](ctx_t& ctx, in_t& in) { return (this->*method)(ctx, in); });
        };
        bind("AddPermission", &sqs_service::add_permission_op);
        bind("CancelMessageMoveTask", &sqs_service::cancel_message_move_task_op);
        bind("ChangeMessageVisibility", &sqs_service::change_visibility_op);
        bind("ChangeMessageVisibilityBatch", &sqs_service::change_visibility_batch_op);
        bind("CreateQueue", &sqs_service::create_queue_op);
        bind("DeleteMessage", &sqs_service::delete_message_op);
        bind("DeleteMessageBatch", &sqs_service::delete_message_batch_op);
        bind("DeleteQueue", &sqs_service::delete_queue_op);
        bind("GetQueueAttributes", &sqs_service::get_queue_attributes_op);
        bind("GetQueueUrl", &sqs_service::get_queue_url_op);
        bind("ListDeadLetterSourceQueues", &sqs_service::list_dead_letter_source_queues_op);
        bind("ListMessageMoveTasks", &sqs_service::list_message_move_tasks_op);
        bind("ListQueueTags", &sqs_service::list_queue_tags_op);
        bind("ListQueues", &sqs_service::list_queues_op);
        bind("PurgeQueue", &sqs_service::purge_queue_op);
        bind("ReceiveMessage", &sqs_service::receive_message_op);
        bind("RemovePermission", &sqs_service::remove_permission_op);
        bind("SendMessage", &sqs_service::send_message_op);
        bind("SendMessageBatch", &sqs_service::send_message_batch_op);
        bind("SetQueueAttributes", &sqs_service::set_queue_attributes_op);
        bind("StartMessageMoveTask", &sqs_service::start_message_move_task_op);
        bind("TagQueue", &sqs_service::tag_queue_op);
        bind("UntagQueue", &sqs_service::untag_queue_op);
        fe.set_queue_lookup([this](std::string_view arn) { return lookup(arn); });
    }

    /// Authorization's view of a queue: its tags and policy.
    [[nodiscard]] auto lookup(std::string_view arn) -> std::optional<queue_facts> {
        const auto parts = parse_sqs_arn(arn);
        if (!parts) {
            return std::nullopt;
        }
        const auto q = find(parts->_account, parts->_name);
        if (!q) {
            return std::nullopt;
        }
        queue_facts f;
        f._tags = service_detail::tag_pairs(q->_tags);
        if (!q->_settings._policy.empty()) {
            f._policy = q->_settings._policy;
        }
        return f;
    }

    /// The catalog record of a queue, as this node's replica has it.
    [[nodiscard]] auto find(std::string_view account, std::string_view name)
        -> std::optional<queue_record> {
        if (!catalog_keys::valid_account(account) || name.empty()) {
            return std::nullopt;
        }
        std::optional<queue_record> out;
        const auto key = catalog_keys::queue(account, name);
        if (!_cluster.read(
                key, [&](const state_machine_type& sm) { out = sm.find_queue(account, name); })) {
            throw std::runtime_error("sqs: catalog unreadable on this node");
        }
        return out;
    }

private:
    using result = aws_json::result<boost::json::object>;
    using status = catalog_result::status;

    Cluster& _cluster;
    sqs_service_config _config;
    std::atomic<std::uint64_t> _rotation{0};
    /// FIFO request-rate buckets, by queue id and operation family.
    struct rate_bucket {
        std::uint64_t _last_ms = 0;
        double _tokens = 0;
    };
    std::mutex _throttle_mutex;
    std::map<std::string, rate_bucket> _throttle;

    // -- plumbing ---------------------------------------------------------------

    [[nodiscard]] auto commit_catalog(const catalog_command& c) -> std::optional<catalog_result> {
        const auto out = _cluster.propose(catalog_keys::queue(c._account, c._name),
                                          service_detail::to_bytes(encode_catalog_command(c)));
        if (!out) {
            return std::nullopt;
        }
        auto r = decode_catalog_result(service_detail::to_string(*out));
        if (!r || r->_outcome == status::malformed) {
            return std::nullopt;
        }
        return r;
    }

    [[nodiscard]] auto commit_queue(const queue_command& c) -> std::optional<queue_result> {
        const auto out = _cluster.propose(queue_keys::partition_prefix(c.target),
                                          service_detail::to_bytes(encode_queue_command(c)));
        if (!out) {
            return std::nullopt;
        }
        auto r = decode_queue_result(service_detail::to_string(*out));
        if (!r || r->outcome != queue_result::status::ok) {
            return std::nullopt;
        }
        return r;
    }

    [[nodiscard]] auto catalog_base(const sqs_call_context& ctx, catalog_command::kind op) const
        -> catalog_command {
        catalog_command c;
        c._op = op;
        c._account = ctx._queue->_account;
        c._name = ctx._queue->_name;
        c._now_ms = _cluster.now_ms();
        return c;
    }

    /// The record of the request's queue, or QueueDoesNotExist.
    [[nodiscard]] auto queue_of(const sqs_call_context& ctx) -> aws_json::result<queue_record> {
        if (!ctx._queue) {
            return service_detail::missing("QueueUrl");
        }
        auto q = find(ctx._queue->_account, ctx._queue->_name);
        if (!q) {
            return queue_does_not_exist();
        }
        return std::move(*q);
    }

    [[nodiscard]] auto profile_of(const queue_record& q) const -> sqs_compat_profile {
        return resolve_profile(_config._profile, service_detail::tag_pairs(q._tags));
    }

    [[nodiscard]] auto next_rotation() -> std::uint64_t {
        return _rotation.fetch_add(1, std::memory_order_relaxed);
    }

    /// SQS's FIFO request rates (Requirement 9.3), when the profile keeps
    /// them: 300 requests a second per queue for each of send, receive and
    /// delete (a batch is one request), and in high-throughput mode that
    /// much per partition. Counted by each front end on its own: with
    /// several, a queue takes that rate through each, so Kythira never
    /// refuses a request SQS would take, but may take some SQS would
    /// refuse.
    [[nodiscard]] auto throttled(const queue_record& q, std::string_view family)
        -> std::optional<aws_json::error> {
        if (!q._settings._fifo || !profile_of(q)._fifo_throughput_limits) {
            return std::nullopt;
        }
        const double rate =
            300.0 *
            (high_throughput_fifo(q._settings) ? std::max<std::uint16_t>(q._partitions, 1) : 1);
        const auto now = _cluster.now_ms();
        const std::scoped_lock lock(_throttle_mutex);
        if (_throttle.size() > 65536) {
            _throttle.clear();  // forgetting refills: only ever lenient
        }
        auto& b = _throttle[std::to_string(q._id) + "/" + std::string(family)];
        b._tokens =
            b._last_ms == 0
                ? rate
                : std::min(rate,
                           b._tokens + rate * static_cast<double>(now - std::min(now, b._last_ms)) /
                                           1000.0);
        b._last_ms = now;
        if (b._tokens < 1.0) {
            return modeled_error("RequestThrottled",
                                 "Request is throttled: the queue's request rate for this action "
                                 "is exceeded.");
        }
        b._tokens -= 1.0;
        return std::nullopt;
    }

    /// Checks a `RedrivePolicy`'s target: an existing queue of the same
    /// kind in the same account (task 6 moves messages to it).
    /// A redrive policy names an existing queue of the same account and
    /// type whose redrive allow policy lets `source_arn` use it
    /// (Requirement 7.2).
    [[nodiscard]] auto check_redrive(const queue_settings& s, std::string_view account,
                                     std::string_view source_arn)
        -> std::optional<aws_json::error> {
        if (s._redrive_policy.empty()) {
            return std::nullopt;
        }
        const auto o = attribute_detail::parse_object(s._redrive_policy);
        const auto target = o ? service_detail::string_member(*o, "deadLetterTargetArn")
                              : std::optional<std::string_view>();
        const auto arn = target ? parse_sqs_arn(*target) : std::nullopt;
        const auto dlq =
            arn && arn->_account == account ? find(arn->_account, arn->_name) : std::nullopt;
        if (!dlq) {
            return service_detail::invalid_value("RedrivePolicy", s._redrive_policy,
                                                 "Dead letter target does not exist.");
        }
        if (dlq->_settings._fifo != s._fifo) {
            return service_detail::invalid_value(
                "RedrivePolicy", s._redrive_policy,
                "Dead-letter queue must be same type of queue as the source.");
        }
        if (!redrive_allowed(dlq->_settings._redrive_allow_policy, source_arn)) {
            return service_detail::invalid_value(
                "RedrivePolicy", s._redrive_policy,
                "Queue " + std::string(*target) +
                    " does not allow this queue to use it as a dead-letter queue.");
        }
        return std::nullopt;
    }

    /// Whether a dead-letter queue's redrive allow policy admits
    /// `source_arn`: no policy or allowAll admits every queue of the
    /// account, denyAll none, byQueue those listed.
    [[nodiscard]] static auto redrive_allowed(std::string_view allow, std::string_view source_arn)
        -> bool {
        if (allow.empty()) {
            return true;
        }
        const auto o = attribute_detail::parse_object(allow);
        if (!o) {
            return false;
        }
        const auto perm = service_detail::string_member(*o, "redrivePermission").value_or("");
        if (perm == "allowAll") {
            return true;
        }
        if (perm != "byQueue") {
            return false;
        }
        const auto* arns = o->if_contains("sourceQueueArns");
        if (arns == nullptr || !arns->is_array()) {
            return false;
        }
        return std::any_of(arns->get_array().begin(), arns->get_array().end(),
                           [&](const boost::json::value& v) {
                               return v.is_string() && v.get_string() == source_arn;
                           });
    }

    /// The receive's redrive target from `q`'s policy, when its dead-letter
    /// queue exists.
    [[nodiscard]] auto redrive_of(const queue_record& q, std::string_view source_arn)
        -> std::optional<redrive_target> {
        if (q._settings._redrive_policy.empty()) {
            return std::nullopt;
        }
        const auto o = attribute_detail::parse_object(q._settings._redrive_policy);
        if (!o) {
            return std::nullopt;
        }
        const auto target = service_detail::string_member(*o, "deadLetterTargetArn");
        const auto arn = target ? parse_sqs_arn(*target) : std::nullopt;
        const auto dlq = arn ? find(arn->_account, arn->_name) : std::nullopt;
        if (!dlq) {
            return std::nullopt;
        }
        std::uint32_t count = 0;
        if (const auto* v = o->if_contains("maxReceiveCount")) {
            if (v->is_int64()) {
                count = static_cast<std::uint32_t>(std::max<std::int64_t>(v->get_int64(), 0));
            } else if (v->is_string()) {
                count = static_cast<std::uint32_t>(
                    std::strtoul(std::string(v->get_string()).c_str(), nullptr, 10));
            }
        }
        if (count == 0) {
            return std::nullopt;
        }
        return redrive_target{count, dlq->target(0), std::max<std::uint16_t>(dlq->_partitions, 1),
                              std::string(source_arn)};
    }

    // -- queues -----------------------------------------------------------------

    auto create_queue_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto& name = ctx._queue->_name;
        const auto attrs = object_member(in, "Attributes");
        const auto tags = string_map(object_member(in, "tags"));
        const auto fifo = fifo_requested(attrs);
        if (!fifo) {
            return fifo.error();
        }
        if (!valid_queue_name(name, *fifo)) {
            return make_error(k_validation_error,
                              *fifo ? "The name of a FIFO queue can only include alphanumeric "
                                      "characters, hyphens, or underscores, must end with .fifo "
                                      "suffix and be 1 to 80 in length."
                                    : "Can only include alphanumeric characters, hyphens, or "
                                      "underscores. 1 to 80 in length");
        }
        if (auto e = check_compat_tags(_config._profile, tag_pairs(tags))) {
            return *e;
        }
        const auto profile = resolve_profile(_config._profile, tag_pairs(tags));
        queue_settings s;
        s._fifo = *fifo;
        if (auto e = apply_attributes(s, attrs, true, profile)) {
            return *e;
        }
        if (auto e = check_redrive(s, ctx._queue->_account, ctx._queue->_arn)) {
            return *e;
        }
        auto c = catalog_base(ctx, catalog_command::kind::create);
        c._settings = s;
        c._tags = tags;
        c._partitions = initial_partitions(s);
        c._cooldown_ms = std::uint64_t{profile._delete_cooldown_s} * 1000;
        const auto r = commit_catalog(c);
        if (!r) {
            return internal_failure();
        }
        switch (r->_outcome) {
            case status::ok:
            case status::exists:
                return boost::json::object{{"QueueUrl", ctx._queue->_url}};
            case status::name_exists:
                return modeled_error("QueueNameExists",
                                     "A queue already exists with the same name and a different "
                                     "value for attribute(s) " +
                                         differing_attributes(r->_record->_settings, s));
            case status::deleted_recently:
                return modeled_error("QueueDeletedRecently",
                                     "You must wait " + std::to_string(profile._delete_cooldown_s) +
                                         " seconds after deleting a queue before you can create "
                                         "another with the same name.");
            case status::too_many_tags:
                return invalid_value("tags", std::to_string(tags.size()),
                                     "Too many tags added for queue " + name + ".");
            default:
                return internal_failure();
        }
    }

    [[nodiscard]] static auto differing_attributes(const queue_settings& a, const queue_settings& b)
        -> std::string {
        std::vector<std::string> names;
        const auto add = [&](bool differs, std::string_view n) {
            if (differs) {
                names.emplace_back(n);
            }
        };
        add(a._delay_s != b._delay_s, "DelaySeconds");
        add(a._max_message_bytes != b._max_message_bytes, "MaximumMessageSize");
        add(a._retention_s != b._retention_s, "MessageRetentionPeriod");
        add(a._wait_s != b._wait_s, "ReceiveMessageWaitTimeSeconds");
        add(a._visibility_s != b._visibility_s, "VisibilityTimeout");
        add(a._policy != b._policy, "Policy");
        add(a._redrive_policy != b._redrive_policy, "RedrivePolicy");
        add(a._redrive_allow_policy != b._redrive_allow_policy, "RedriveAllowPolicy");
        add(a._kms_key_id != b._kms_key_id, "KmsMasterKeyId");
        add(a._kms_reuse_s != b._kms_reuse_s, "KmsDataKeyReusePeriodSeconds");
        add(a._sqs_managed_sse != b._sqs_managed_sse, "SqsManagedSseEnabled");
        add(a._fifo != b._fifo, "FifoQueue");
        add(a._content_dedup != b._content_dedup, "ContentBasedDeduplication");
        add(a._dedup_scope != b._dedup_scope, "DeduplicationScope");
        add(a._throughput_limit != b._throughput_limit, "FifoThroughputLimit");
        std::string out;
        for (const auto& n : names) {
            out += (out.empty() ? "" : ",") + n;
        }
        return out;
    }

    auto delete_queue_op(sqs_call_context& ctx, boost::json::object& /*in*/) -> result {
        const auto r = commit_catalog(catalog_base(ctx, catalog_command::kind::delete_));
        if (!r) {
            return internal_failure();
        }
        if (r->_outcome == status::does_not_exist) {
            return queue_does_not_exist();
        }
        // The record is gone, so nothing reaches the partitions any more;
        // dropping them frees the space. A drop that does not commit leaves
        // keys under an id that is never reused, which no request can see.
        const auto& q = *r->_record;
        for (std::uint16_t p = 0; p < q._partitions; ++p) {
            queue_command drop;
            drop.op = queue_command::kind::drop;
            drop.target = q.target(p);
            drop.now_ms = _cluster.now_ms();
            (void)commit_queue(drop);
        }
        return boost::json::object{};
    }

    auto get_queue_url_op(sqs_call_context& ctx, boost::json::object& /*in*/) -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        return boost::json::object{{"QueueUrl", ctx._queue->_url}};
    }

    auto list_queues_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto prefix = string_member(in, "QueueNamePrefix").value_or("");
        const auto max = int_member(in, "MaxResults");
        if (max && (*max < 1 || *max > 1000)) {
            return invalid_value("MaxResults", std::to_string(*max),
                                 "MaxResults must be an integer between 1 and 1000.");
        }
        std::string after;
        if (const auto token = string_member(in, "NextToken")) {
            const auto raw = aws_json::base64_decode(*token);
            if (!raw || raw->empty()) {
                return make_error(k_validation_error, "Invalid NextToken value.");
            }
            after.assign(reinterpret_cast<const char*>(raw->data()), raw->size());  // NOLINT
        }
        const auto& account = ctx._principal.account;
        const auto limit = static_cast<std::size_t>(max.value_or(1000));
        std::vector<queue_record> found;
        if (catalog_keys::valid_account(account) &&
            !_cluster.read(catalog_keys::queues_prefix(account), [&](const state_machine_type& sm) {
                found = sm.list_queues(account, prefix, after, limit + 1);
            })) {
            return internal_failure();
        }
        boost::json::object out;
        boost::json::array urls;
        for (std::size_t i = 0; i < found.size() && i < limit; ++i) {
            urls.emplace_back(ctx.queue_url(account, found[i]._name));
        }
        if (max && found.size() > limit) {
            const auto& last = found[limit - 1]._name;
            out["NextToken"] = aws_json::base64_encode(
                std::as_bytes(std::span<const char>(last.data(), last.size())));
        }
        if (!urls.empty()) {
            out["QueueUrls"] = std::move(urls);
        }
        return out;
    }

    /// The account's queues whose redrive policy names this queue, in name
    /// order, paged like ListQueues.
    auto list_dead_letter_source_queues_op(sqs_call_context& ctx, boost::json::object& in)
        -> result {
        using namespace service_detail;
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        const auto max = int_member(in, "MaxResults");
        if (max && (*max < 1 || *max > 1000)) {
            return invalid_value("MaxResults", std::to_string(*max),
                                 "MaxResults must be an integer between 1 and 1000.");
        }
        std::string after;
        if (const auto token = string_member(in, "NextToken")) {
            const auto raw = aws_json::base64_decode(*token);
            if (!raw || raw->empty()) {
                return make_error(k_validation_error, "Invalid NextToken value.");
            }
            after.assign(reinterpret_cast<const char*>(raw->data()), raw->size());  // NOLINT
        }
        const auto& account = ctx._queue->_account;
        const auto& arn = ctx._queue->_arn;
        const auto limit = static_cast<std::size_t>(max.value_or(1000));
        std::vector<std::string> sources;
        bool more = false;
        if (!_cluster.read(catalog_keys::queues_prefix(account), [&](const state_machine_type& sm) {
                for (const auto& r :
                     sm.list_queues(account, "", after, std::numeric_limits<std::size_t>::max())) {
                    const auto o = attribute_detail::parse_object(r._settings._redrive_policy);
                    if (!o || string_member(*o, "deadLetterTargetArn").value_or("") != arn) {
                        continue;
                    }
                    if (sources.size() == limit) {
                        more = true;
                        break;
                    }
                    sources.push_back(r._name);
                }
            })) {
            return internal_failure();
        }
        boost::json::object out;
        boost::json::array urls;
        for (const auto& name : sources) {
            urls.emplace_back(ctx.queue_url(account, name));
        }
        out["queueUrls"] = std::move(urls);
        if (max && more) {
            const auto& last = sources.back();
            out["NextToken"] = aws_json::base64_encode(
                std::as_bytes(std::span<const char>(last.data(), last.size())));
        }
        return out;
    }

    // -- move tasks (Requirement 7.3) -------------------------------------------

    /// The source queue of a move-task operation, or ResourceNotFound.
    [[nodiscard]] auto move_source(const sqs_call_context& ctx) -> aws_json::result<queue_record> {
        if (!ctx._queue) {
            return service_detail::missing("SourceArn");
        }
        auto q = find(ctx._queue->_account, ctx._queue->_name);
        if (!q) {
            return modeled_error("ResourceNotFoundException",
                                 "The resource that you specified for the SourceArn parameter "
                                 "doesn't exist.");
        }
        return std::move(*q);
    }

    /// Whether some queue of `account` names `arn` as its dead-letter queue.
    [[nodiscard]] auto is_dead_letter_queue(std::string_view account, std::string_view arn)
        -> bool {
        bool found = false;
        (void)_cluster.read(
            catalog_keys::queues_prefix(account), [&](const state_machine_type& sm) {
                for (const auto& r :
                     sm.list_queues(account, "", "", std::numeric_limits<std::size_t>::max())) {
                    const auto o = attribute_detail::parse_object(r._settings._redrive_policy);
                    if (o &&
                        service_detail::string_member(*o, "deadLetterTargetArn").value_or("") ==
                            arn) {
                        found = true;
                        return;
                    }
                }
            });
        return found;
    }

    /// Visible messages across `q`'s partitions, as this replica has them.
    [[nodiscard]] auto visible_count(const queue_record& q) -> std::uint64_t {
        std::uint64_t n = 0;
        for (std::uint16_t p = 0; p < std::max<std::uint16_t>(q._partitions, 1); ++p) {
            const auto t = q.target(p);
            (void)_cluster.read(queue_keys::partition_prefix(t),
                                [&](const state_machine_type& sm) { n += sm.counts(t).visible; });
        }
        return n;
    }

    /// A task handle: the source ARN and the start time, base64.
    [[nodiscard]] static auto task_handle(const move_task& m) -> std::string {
        const auto raw = m._source_arn + "\n" + std::to_string(m._started_ms);
        return aws_json::base64_encode(
            std::as_bytes(std::span<const char>(raw.data(), raw.size())));
    }

    [[nodiscard]] static auto parse_task_handle(std::string_view handle)
        -> std::optional<std::pair<std::string, std::uint64_t>> {
        const auto raw = aws_json::base64_decode(handle);
        if (!raw) {
            return std::nullopt;
        }
        const std::string s(reinterpret_cast<const char*>(raw->data()), raw->size());  // NOLINT
        const auto nl = s.rfind('\n');
        if (nl == std::string::npos || nl + 1 == s.size() || nl + 21 < s.size()) {
            return std::nullopt;
        }
        std::uint64_t started = 0;
        for (const char ch : std::string_view(s).substr(nl + 1)) {
            if (ch < '0' || ch > '9') {
                return std::nullopt;
            }
            started = started * 10 + static_cast<std::uint64_t>(ch - '0');
        }
        return std::pair{s.substr(0, nl), started};
    }

    [[nodiscard]] static auto move_task_not_found() -> aws_json::error {
        return modeled_error("ResourceNotFoundException",
                             "The task handle doesn't refer to a running task.");
    }

    auto start_message_move_task_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto q = move_source(ctx);
        if (!q) {
            return q.error();
        }
        const auto& account = ctx._queue->_account;
        const auto& source_arn = ctx._queue->_arn;
        if (!is_dead_letter_queue(account, source_arn)) {
            return invalid_value("SourceArn", source_arn,
                                 "Source queue must be configured as a Dead Letter Queue.");
        }
        move_task m;
        m._source_arn = source_arn;
        if (const auto dest = string_member(in, "DestinationArn")) {
            const auto parts = parse_sqs_arn(*dest);
            const auto d = parts ? find(parts->_account, parts->_name) : std::nullopt;
            if (!d) {
                return modeled_error("ResourceNotFoundException",
                                     "The resource that you specified for the DestinationArn "
                                     "parameter doesn't exist.");
            }
            if (*dest == source_arn) {
                return invalid_value("DestinationArn", *dest,
                                     "Source queue and destination queue can not be the same.");
            }
            if (d->_settings._fifo != q->_settings._fifo) {
                return invalid_value("DestinationArn", *dest,
                                     "Destination queue must be same type of queue as the source.");
            }
            // Moving in sends to the destination: the caller needs that too.
            aws_auth::authz_request r;
            r.action = "sqs:SendMessage";
            r.resource = std::string(*dest);
            if (auto denied = ctx.authorize(std::move(r))) {
                return *denied;
            }
            m._destination_arn = std::string(*dest);
        }
        if (const auto rate = int_member(in, "MaxNumberOfMessagesPerSecond")) {
            if (*rate < 1 || *rate > 500) {
                return invalid_value("MaxNumberOfMessagesPerSecond", std::to_string(*rate),
                                     "Value must be between 1 and 500.");
            }
            m._rate = static_cast<std::uint32_t>(*rate);
        }
        m._to_move = visible_count(*q);
        auto c = catalog_base(ctx, catalog_command::kind::move_start);
        c._move = std::move(m);
        const auto r = commit_catalog(c);
        if (!r) {
            return internal_failure();
        }
        if (r->_outcome == status::does_not_exist) {
            return move_source(ctx).error();
        }
        if (r->_outcome == status::move_in_progress) {
            return modeled_error("UnsupportedOperation",
                                 "There is already a task running. Only one active task is "
                                 "allowed for each source queue arn at a given time.");
        }
        if (r->_outcome != status::ok || !r->_move) {
            return internal_failure();
        }
        boost::json::object out;
        out["TaskHandle"] = task_handle(*r->_move);
        return out;
    }

    auto list_message_move_tasks_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto q = move_source(ctx);
        if (!q) {
            return q.error();
        }
        const auto max = int_member(in, "MaxResults");
        if (max && (*max < 1 || *max > 10)) {
            return invalid_value("MaxResults", std::to_string(*max),
                                 "Value must be between 1 and 10.");
        }
        std::vector<move_task> tasks;
        if (!_cluster.read(catalog_keys::moves_of(q->_account, q->_name),
                           [&](const state_machine_type& sm) {
                               tasks = sm.move_tasks(q->_account, q->_name);
                           })) {
            return internal_failure();
        }
        boost::json::array results;
        for (const auto& m : tasks) {
            if (results.size() == static_cast<std::size_t>(max.value_or(1))) {
                break;
            }
            boost::json::object o;
            if (m._status == move_task::state::running) {
                o["TaskHandle"] = task_handle(m);
            }
            o["Status"] = move_state_name(m._status);
            o["SourceArn"] = m._source_arn;
            if (!m._destination_arn.empty()) {
                o["DestinationArn"] = m._destination_arn;
            }
            if (m._rate != 0) {
                o["MaxNumberOfMessagesPerSecond"] = m._rate;
            }
            o["ApproximateNumberOfMessagesMoved"] = m._moved;
            o["ApproximateNumberOfMessagesToMove"] = m._to_move;
            if (!m._failure.empty()) {
                o["FailureReason"] = m._failure;
            }
            o["StartedTimestamp"] = m._started_ms;
            results.emplace_back(std::move(o));
        }
        boost::json::object out;
        out["Results"] = std::move(results);
        return out;
    }

    auto cancel_message_move_task_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto handle = string_member(in, "TaskHandle");
        if (!handle) {
            return missing("TaskHandle");
        }
        const auto parsed = parse_task_handle(*handle);
        const auto arn = parsed ? parse_sqs_arn(parsed->first) : std::nullopt;
        if (!arn) {
            return move_task_not_found();
        }
        // The handle names the queue: authorize on it (the front end could
        // not).
        aws_auth::authz_request r;
        r.action = "sqs:CancelMessageMoveTask";
        r.resource = parsed->first;
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        catalog_command c;
        c._op = catalog_command::kind::move_cancel;
        c._account = std::string(arn->_account);
        c._name = std::string(arn->_name);
        c._now_ms = _cluster.now_ms();
        c._move._started_ms = parsed->second;
        const auto res = commit_catalog(c);
        if (!res) {
            return internal_failure();
        }
        if (res->_outcome != status::ok || !res->_move) {
            return move_task_not_found();
        }
        boost::json::object out;
        out["ApproximateNumberOfMessagesMoved"] = res->_move->_moved;
        return out;
    }

    auto get_queue_attributes_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        queue_facts_view f;
        f._arn = ctx._queue->_arn;
        f._created_s = static_cast<std::int64_t>(q->_created_ms / 1000);
        f._modified_s = static_cast<std::int64_t>(q->_modified_ms / 1000);
        for (std::uint16_t p = 0; p < q->_partitions; ++p) {
            const auto t = q->target(p);
            // A partition this node holds no replica of counts as empty:
            // the counts are approximate (Requirement 4.3).
            (void)_cluster.read(queue_keys::partition_prefix(t), [&](const state_machine_type& sm) {
                const auto c = sm.counts(t);
                f._visible += c.visible;
                f._not_visible += c.not_visible;
                f._delayed += c.delayed;
            });
        }
        auto values =
            attribute_values(q->_settings, f, service_detail::strings_member(in, "AttributeNames"));
        if (!values) {
            return values.error();
        }
        boost::json::object out;
        if (!values->empty()) {
            out["Attributes"] = std::move(*values);
        }
        return out;
    }

    /// Re-reads the queue and commits `change(settings)` until no other
    /// change slips in between (compare-and-set on the record's version).
    template<typename Change>
    auto change_settings(const sqs_call_context& ctx, Change&& change) -> result {
        for (int attempt = 0; attempt < _config._cas_attempts; ++attempt) {
            const auto q = queue_of(ctx);
            if (!q) {
                return q.error();
            }
            auto next = q->_settings;
            if (auto e = change(*q, next)) {
                return *e;
            }
            auto c = catalog_base(ctx, catalog_command::kind::set_settings);
            c._settings = std::move(next);
            c._expected_version = q->_version;
            const auto r = commit_catalog(c);
            if (!r) {
                return internal_failure();
            }
            if (r->_outcome == status::ok) {
                return boost::json::object{};
            }
            if (r->_outcome == status::does_not_exist) {
                return queue_does_not_exist();
            }
        }
        return internal_failure();
    }

    auto set_queue_attributes_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        const auto attrs = service_detail::object_member(in, "Attributes");
        return change_settings(
            ctx, [&](const queue_record& q, queue_settings& s) -> std::optional<aws_json::error> {
                if (auto e = apply_attributes(s, attrs, false, profile_of(q))) {
                    return e;
                }
                // A high-throughput FIFO queue spans partitions, each with
                // its own deduplication records: queue-wide deduplication
                // would need them in one place (sqs_catalog.hpp).
                if (s._fifo && q._partitions > 1 && s._dedup_scope != "messageGroup") {
                    return service_detail::invalid_value(
                        "DeduplicationScope", s._dedup_scope,
                        "This queue was created for high throughput; its deduplication scope "
                        "must stay messageGroup.");
                }
                if (attrs.contains("RedrivePolicy")) {
                    return check_redrive(s, q._account, ctx._queue->_arn);
                }
                return std::nullopt;
            });
    }

    auto add_permission_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto label = string_member(in, "Label").value_or("");
        const auto accounts = strings_member(in, "AWSAccountIds");
        const auto actions = strings_member(in, "Actions");
        return change_settings(
            ctx, [&](const queue_record&, queue_settings& s) -> std::optional<aws_json::error> {
                auto policy = add_permission(s._policy, ctx._queue->_arn, ctx._partition, label,
                                             accounts, actions);
                if (!policy) {
                    return policy.error();
                }
                s._policy = std::move(*policy);
                return std::nullopt;
            });
    }

    auto remove_permission_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        const auto label = service_detail::string_member(in, "Label").value_or("");
        return change_settings(
            ctx, [&](const queue_record&, queue_settings& s) -> std::optional<aws_json::error> {
                auto policy = remove_permission(s._policy, ctx._queue->_arn, label);
                if (!policy) {
                    return policy.error();
                }
                s._policy = std::move(*policy);
                return std::nullopt;
            });
    }

    auto purge_queue_op(sqs_call_context& ctx, boost::json::object& /*in*/) -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        const auto profile = profile_of(*q);
        auto c = catalog_base(ctx, catalog_command::kind::purge);
        c._cooldown_ms = std::uint64_t{profile._purge_cooldown_s} * 1000;
        const auto r = commit_catalog(c);
        if (!r) {
            return internal_failure();
        }
        if (r->_outcome == status::does_not_exist) {
            return queue_does_not_exist();
        }
        if (r->_outcome == status::purge_in_progress) {
            return modeled_error("PurgeQueueInProgress",
                                 "Only one PurgeQueue operation on " + ctx._queue->_name +
                                     " is allowed every " +
                                     std::to_string(profile._purge_cooldown_s) + " seconds.");
        }
        for (std::uint16_t p = 0; p < r->_record->_partitions; ++p) {
            queue_command purge;
            purge.op = queue_command::kind::purge;
            purge.target = r->_record->target(p);
            purge.now_ms = c._now_ms;
            if (!commit_queue(purge)) {
                return internal_failure();
            }
        }
        return boost::json::object{};
    }

    auto list_queue_tags_op(sqs_call_context& ctx, boost::json::object& /*in*/) -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        boost::json::object out;
        if (!q->_tags.empty()) {
            boost::json::object tags;
            for (const auto& [k, v] : q->_tags) {
                tags[k] = v;
            }
            out["Tags"] = std::move(tags);
        }
        return out;
    }

    auto tag_queue_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto tags = string_map(object_member(in, "Tags"));
        if (tags.empty()) {
            return missing("Tags");
        }
        if (auto e = check_compat_tags(_config._profile, tag_pairs(tags))) {
            return *e;
        }
        auto c = catalog_base(ctx, catalog_command::kind::tag);
        c._tags = tags;
        const auto r = commit_catalog(c);
        if (!r) {
            return internal_failure();
        }
        if (r->_outcome == status::does_not_exist) {
            return queue_does_not_exist();
        }
        if (r->_outcome == status::too_many_tags) {
            return invalid_value("Tags", std::to_string(tags.size()),
                                 "Too many tags added for queue " + ctx._queue->_name + ".");
        }
        return boost::json::object{};
    }

    auto untag_queue_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog_base(ctx, catalog_command::kind::untag);
        c._tag_keys = service_detail::strings_member(in, "TagKeys");
        if (c._tag_keys.empty()) {
            return service_detail::missing("TagKeys");
        }
        const auto r = commit_catalog(c);
        if (!r) {
            return internal_failure();
        }
        if (r->_outcome == status::does_not_exist) {
            return queue_does_not_exist();
        }
        return boost::json::object{};
    }

    // -- sends ------------------------------------------------------------------

    /// A send entry ready to commit, from one `SendMessage` input or one
    /// batch entry, and the bytes it counts against the size limit.
    struct prepared_send {
        send_entry _entry;
        std::size_t _bytes = 0;
    };

    [[nodiscard]] auto prepare_send(const sqs_call_context& ctx, const queue_record& q,
                                    const boost::json::object& in)
        -> aws_json::result<prepared_send> {
        using namespace service_detail;
        const auto& s = q._settings;
        const auto body = string_member(in, "MessageBody");
        if (!body || body->empty()) {
            return missing("MessageBody");
        }
        if (!valid_body(*body)) {
            return modeled_error("InvalidMessageContents",
                                 "Invalid characters found. Valid unicode characters are #x9 | "
                                 "#xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to "
                                 "#x10FFFF");
        }
        const auto attrs = object_member(in, "MessageAttributes");
        if (auto e = check_attributes(attrs, false)) {
            return *e;
        }
        const auto sys = object_member(in, "MessageSystemAttributes");
        if (auto e = check_attributes(sys, true)) {
            return *e;
        }
        prepared_send out;
        out._bytes = body->size() + attributes_size(attrs);
        if (out._bytes > s._max_message_bytes) {
            return make_error(k_validation_error,
                              "One or more parameters are invalid. Reason: Message must be "
                              "shorter than " +
                                  std::to_string(s._max_message_bytes) + " bytes.");
        }
        auto& e = out._entry;
        e.delay_s = s._delay_s;
        if (const auto d = int_member(in, "DelaySeconds")) {
            if (s._fifo) {
                return invalid_value("DelaySeconds", std::to_string(*d),
                                     "The request include parameter that is not valid for this "
                                     "queue type.");
            }
            if (*d < 0 || *d > 900) {
                return invalid_value("DelaySeconds", std::to_string(*d),
                                     "DelaySeconds must be >= 0 and <= 900.");
            }
            e.delay_s = static_cast<std::uint32_t>(*d);
        }
        const auto group = string_member(in, "MessageGroupId");
        const auto dedup = string_member(in, "MessageDeduplicationId");
        if (s._fifo) {
            if (!group) {
                return missing("MessageGroupId");
            }
            if (!valid_fifo_token(*group)) {
                return invalid_value("MessageGroupId", *group,
                                     "MessageGroupId can only include alphanumeric and "
                                     "punctuation characters. 1 to 128 in length.");
            }
            if (dedup && !valid_fifo_token(*dedup)) {
                return invalid_value("MessageDeduplicationId", *dedup,
                                     "MessageDeduplicationId can only include alphanumeric and "
                                     "punctuation characters. 1 to 128 in length.");
            }
            if (!dedup && !s._content_dedup) {
                return make_error(k_validation_error,
                                  "The queue should either have ContentBasedDeduplication "
                                  "enabled or MessageDeduplicationId provided explicitly");
            }
            e.dedup_id = dedup ? std::string(*dedup) : sha256_hex(*body);
            e.dedup_key = s._dedup_scope == "messageGroup"
                              ? std::string(*group) + std::string(1, '\0') + e.dedup_id
                              : e.dedup_id;
        } else if (dedup) {
            return invalid_value("MessageDeduplicationId", *dedup,
                                 "The request includes a parameter that is not valid for this "
                                 "queue type.");
        }
        if (group) {
            // Standard queues keep the group for fair queues (task 8) and
            // hand it back as the MessageGroupId attribute.
            e.group_id = std::string(*group);
        }
        e.entry_id = std::string(string_member(in, "Id").value_or(""));
        e.message_id = new_message_id();
        e.body = std::string(*body);
        e.attributes = encode_attributes(attrs);
        e.system_attributes = encode_system(
            ctx._principal.userid.empty() ? ctx._principal.account : ctx._principal.userid, sys);
        e.md5_of_body = md5_hex(*body);
        e.md5_of_attributes = md5_of_attributes(attrs);
        e.md5_of_system_attributes = md5_of_attributes(sys);
        // Sealed last: the digests and the deduplication hash are over the
        // plaintext (Requirement 8.2).
        if (s._sqs_managed_sse || !s._kms_key_id.empty()) {
            try {
                e.body = _config._sse->seal(
                    sse_keys::target{ctx._queue->_arn, s._kms_key_id, s._kms_reuse_s}, e.message_id,
                    e.body, e.attributes, _cluster.now_ms());
                e.attributes.clear();
            } catch (const kms_error& k) {
                return kms_error_of(k);
            }
        }
        return out;
    }

    /// SQS's error for a key provider's failure.
    [[nodiscard]] static auto kms_error_of(const kms_error& k) -> aws_json::error {
        switch (k.failure()) {
            case kms_failure::access_denied:
                return modeled_error("KmsAccessDenied", k.what());
            case kms_failure::disabled:
                return modeled_error("KmsDisabled", k.what());
            case kms_failure::invalid_state:
                return modeled_error("KmsInvalidState", k.what());
            case kms_failure::throttling:
                return modeled_error("KmsThrottled", k.what());
            case kms_failure::opt_in_required:
                return modeled_error("KmsOptInRequired", k.what());
            case kms_failure::invalid_key_usage:
                return modeled_error("KmsInvalidKeyUsage", k.what());
            case kms_failure::not_found:
            case kms_failure::unavailable:
            default:
                return modeled_error("KmsNotFound", k.what());
        }
    }

    [[nodiscard]] auto send_partition(const queue_record& q, const send_entry& e,
                                      std::uint64_t rotation) const -> std::uint16_t {
        const auto n = std::max<std::uint16_t>(q._partitions, 1);
        if (q._settings._fifo) {
            return static_cast<std::uint16_t>(group_hash(e.group_id) % n);
        }
        return static_cast<std::uint16_t>(rotation % n);
    }

    [[nodiscard]] static auto sent_entry(const queue_record& q, std::uint16_t partition,
                                         const send_entry& e, const entry_result& r)
        -> boost::json::object {
        boost::json::object out;
        out["MessageId"] = r.message_id;
        out["MD5OfMessageBody"] = e.md5_of_body;
        if (!e.md5_of_attributes.empty()) {
            out["MD5OfMessageAttributes"] = e.md5_of_attributes;
        }
        if (!e.md5_of_system_attributes.empty()) {
            out["MD5OfMessageSystemAttributes"] = e.md5_of_system_attributes;
        }
        if (q._settings._fifo) {
            out["SequenceNumber"] = service_detail::sequence_number(partition, r.sequence);
        }
        return out;
    }

    auto send_message_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        if (auto e = throttled(*q, "send")) {
            return *e;
        }
        auto prepared = prepare_send(ctx, *q, in);
        if (!prepared) {
            return prepared.error();
        }
        auto& e = prepared->_entry;
        e.entry_id.clear();
        queue_command c;
        c.op = queue_command::kind::send;
        c.target = q->target(send_partition(*q, e, next_rotation()));
        c.now_ms = _cluster.now_ms();
        c.sends.push_back(e);
        const auto r = commit_queue(c);
        if (!r || r->entries.size() != 1) {
            return internal_failure();
        }
        return sent_entry(*q, c.target.partition, e, r->entries.front());
    }

    /// The entries of a batch request, checked as SQS checks them before
    /// any entry is tried.
    [[nodiscard]] auto batch_entries(const boost::json::object& in, std::string_view entry_shape,
                                     const sqs_compat_profile& profile)
        -> aws_json::result<std::vector<const boost::json::object*>> {
        std::vector<const boost::json::object*> out;
        if (const auto* v = in.if_contains("Entries"); v != nullptr && v->is_array()) {
            for (const auto& e : v->get_array()) {
                if (e.is_object()) {
                    out.push_back(&e.get_object());
                }
            }
        }
        if (out.empty()) {
            return modeled_error(
                "EmptyBatchRequest",
                "There should be at least one " + std::string(entry_shape) + " in the request.");
        }
        if (out.size() > profile._max_batch_entries) {
            return modeled_error("TooManyEntriesInBatchRequest",
                                 "Maximum number of entries per request are " +
                                     std::to_string(profile._max_batch_entries) +
                                     ". You have sent " + std::to_string(out.size()) + ".");
        }
        std::set<std::string, std::less<>> seen;
        for (const auto* e : out) {
            const auto id = service_detail::string_member(*e, "Id").value_or("");
            if (!service_detail::valid_entry_id(id)) {
                return modeled_error("InvalidBatchEntryId",
                                     "A batch entry id can only contain alphanumeric characters, "
                                     "hyphens and underscores. It can be at most 80 letters long.");
            }
            if (!seen.emplace(id).second) {
                return modeled_error("BatchEntryIdsNotDistinct",
                                     "Id " + std::string(id) + " repeated.");
            }
        }
        return out;
    }

    [[nodiscard]] static auto failed_entry(std::string_view id, const aws_json::error& e)
        -> boost::json::object {
        const auto q = to_query(e);
        return boost::json::object{{"Id", id},
                                   {"SenderFault", q.sender},
                                   {"Code", q.code},
                                   {"Message", e.message.value_or("")}};
    }

    [[nodiscard]] static auto batch_reply(boost::json::array ok, boost::json::array failed)
        -> boost::json::object {
        boost::json::object out;
        out["Successful"] = std::move(ok);
        out["Failed"] = std::move(failed);
        return out;
    }

    auto send_message_batch_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        if (auto e = throttled(*q, "send")) {
            return *e;
        }
        const auto entries = batch_entries(in, "SendMessageBatchRequestEntry", profile_of(*q));
        if (!entries) {
            return entries.error();
        }
        boost::json::array ok;
        boost::json::array failed;
        // Valid entries by partition, in request order.
        std::map<std::uint16_t, std::vector<send_entry>> by_partition;
        std::size_t total = 0;
        const auto rotation = next_rotation();
        for (const auto* e : *entries) {
            auto p = prepare_send(ctx, *q, *e);
            if (!p) {
                failed.push_back(
                    failed_entry(service_detail::string_member(*e, "Id").value_or(""), p.error()));
                continue;
            }
            total += p->_bytes;
            const auto part = send_partition(*q, p->_entry, rotation);
            by_partition[part].push_back(std::move(p->_entry));
        }
        if (total > q->_settings._max_message_bytes) {
            return modeled_error(
                "BatchRequestTooLong",
                "Batch requested message too long. Size: " + std::to_string(total) +
                    ", Max: " + std::to_string(q->_settings._max_message_bytes));
        }
        for (auto& [part, sends] : by_partition) {
            queue_command c;
            c.op = queue_command::kind::send;
            c.target = q->target(part);
            c.now_ms = _cluster.now_ms();
            c.sends = sends;
            const auto r = commit_queue(c);
            if (!r || r->entries.size() != sends.size()) {
                // Ambiguous: the entries may have committed. Each is
                // reported failed and retryable, as SQS reports an internal
                // error per entry.
                for (const auto& s : sends) {
                    failed.push_back(failed_entry(s.entry_id, internal_failure()));
                }
                continue;
            }
            for (std::size_t i = 0; i < sends.size(); ++i) {
                auto entry = sent_entry(*q, part, sends[i], r->entries[i]);
                entry["Id"] = sends[i].entry_id;
                ok.push_back(std::move(entry));
            }
        }
        return batch_reply(std::move(ok), std::move(failed));
    }

    // -- receives ---------------------------------------------------------------

    /// The system attributes a receive returns, by the names asked for.
    [[nodiscard]] static auto system_attributes(const queue_record& q, std::uint16_t partition,
                                                const received_message& m,
                                                const std::set<std::string, std::less<>>& wanted)
        -> boost::json::object {
        const bool all = wanted.contains("All");
        const auto want = [&](std::string_view n) { return all || wanted.contains(n); };
        boost::json::object out;
        const auto sys = service_detail::decode_system(m.system_attributes);
        if (want("SenderId")) {
            out["SenderId"] = sys._sender;
        }
        if (want("SentTimestamp")) {
            out["SentTimestamp"] = std::to_string(m.sent_ms);
        }
        if (want("ApproximateReceiveCount")) {
            out["ApproximateReceiveCount"] = std::to_string(m.receive_count);
        }
        if (want("ApproximateFirstReceiveTimestamp")) {
            out["ApproximateFirstReceiveTimestamp"] = std::to_string(m.first_receive_ms);
        }
        if (want("AWSTraceHeader")) {
            const auto trace = service_detail::object_member(sys._attributes, "AWSTraceHeader");
            if (const auto v = service_detail::string_member(trace, "StringValue")) {
                out["AWSTraceHeader"] = *v;
            }
        }
        if (!m.group_id.empty() && want("MessageGroupId")) {
            out["MessageGroupId"] = m.group_id;
        }
        if (!m.dead_letter_source.empty() && want("DeadLetterQueueSourceArn")) {
            out["DeadLetterQueueSourceArn"] = m.dead_letter_source;
        }
        if (q._settings._fifo) {
            if (want("MessageDeduplicationId")) {
                out["MessageDeduplicationId"] = m.dedup_id;
            }
            if (want("SequenceNumber")) {
                out["SequenceNumber"] = service_detail::sequence_number(partition, m.sequence);
            }
        }
        return out;
    }

    /// Whether this node's replica shows partition `t` with something to
    /// receive now (visible, or due by `now`); true when it cannot tell.
    [[nodiscard]] auto worth_receiving(const queue_target& t, std::uint64_t now) -> bool {
        bool worth = true;
        (void)_cluster.read(queue_keys::partition_prefix(t), [&](const state_machine_type& sm) {
            const auto due = sm.next_deadline(t);
            worth = sm.counts(t).visible > 0 || (due && *due <= now);
        });
        return worth;
    }

    auto receive_message_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        try {
            return receive_messages(ctx, in);
        } catch (const kms_error& k) {
            // The messages taken stay in flight and come back after their
            // visibility timeout, as on SQS.
            return kms_error_of(k);
        }
    }

    auto receive_messages(sqs_call_context& ctx, boost::json::object& in) -> result {
        using namespace service_detail;
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        if (auto e = throttled(*q, "receive")) {
            return *e;
        }
        // SQS's in-flight limits: a standard queue answers OverLimit, a
        // FIFO queue no messages. Counted from this replica, so
        // approximate, as SQS's own counts are.
        {
            const auto profile = profile_of(*q);
            const auto limit =
                q->_settings._fifo ? profile._max_inflight_fifo : profile._max_inflight_standard;
            std::uint64_t in_flight = 0;
            for (std::uint16_t p = 0; p < std::max<std::uint16_t>(q->_partitions, 1); ++p) {
                const auto t = q->target(p);
                (void)_cluster.read(
                    queue_keys::partition_prefix(t),
                    [&](const state_machine_type& sm) { in_flight += sm.counts(t).not_visible; });
            }
            if (in_flight >= limit) {
                if (q->_settings._fifo) {
                    return boost::json::object{};
                }
                return modeled_error("OverLimit",
                                     "Too many messages in flight: the queue has reached its "
                                     "limit of " +
                                         std::to_string(limit) + " in-flight messages.");
            }
        }
        const auto max = int_member(in, "MaxNumberOfMessages").value_or(1);
        if (max < 1 || max > 10) {
            return invalid_value("MaxNumberOfMessages", std::to_string(max),
                                 "Must be between 1 and 10, if provided.");
        }
        const auto visibility =
            int_member(in, "VisibilityTimeout").value_or(q->_settings._visibility_s);
        if (visibility < 0 || visibility > 43200) {
            return invalid_value("VisibilityTimeout", std::to_string(visibility),
                                 "Must be >= 0 and <= 43200, if provided.");
        }
        const auto profile = profile_of(*q);
        const auto wait_member = int_member(in, "WaitTimeSeconds");
        if (wait_member && (*wait_member < 0 || *wait_member > profile._max_wait_s)) {
            return invalid_value(
                "WaitTimeSeconds", std::to_string(*wait_member),
                "Must be >= 0 and <= " + std::to_string(profile._max_wait_s) + ", if provided.");
        }
        const auto wait_s =
            wait_member ? static_cast<std::uint32_t>(*wait_member)
                        : std::min<std::uint32_t>(q->_settings._wait_s, profile._max_wait_s);
        std::set<std::string, std::less<>> system_names;
        for (const auto* member : {"AttributeNames", "MessageSystemAttributeNames"}) {
            for (auto& n : strings_member(in, member)) {
                system_names.insert(std::move(n));
            }
        }
        const auto attribute_names = strings_member(in, "MessageAttributeNames");

        boost::json::array messages;
        const auto n = std::max<std::uint16_t>(q->_partitions, 1);
        const auto redrive = redrive_of(*q, ctx._queue->_arn);
        // One pass over the partitions; false when nothing could commit.
        const auto pass = [&]() -> bool {
            const auto start = next_rotation();
            auto remaining = static_cast<std::uint32_t>(max);
            for (std::uint16_t i = 0; i < n && remaining > 0; ++i) {
                const auto part = static_cast<std::uint16_t>((start + i) % n);
                const auto t = q->target(part);
                const auto now = _cluster.now_ms();
                if (!worth_receiving(t, now)) {
                    continue;
                }
                queue_command c;
                c.op = queue_command::kind::receive;
                c.target = t;
                c.now_ms = now;
                c.max_messages = remaining;
                c.visibility_timeout_s = static_cast<std::uint32_t>(visibility);
                c.redrive = redrive;
                const auto r = commit_queue(c);
                if (!r) {
                    return !messages.empty();
                }
                for (const auto& m : r->messages) {
                    messages.push_back(render_message(*q, part, m, system_names, attribute_names));
                }
                remaining -= std::min<std::uint32_t>(
                    remaining, static_cast<std::uint32_t>(r->messages.size()));
            }
            return true;
        };
        if (wait_s == 0 || _config._waits == nullptr) {
            if (!pass()) {
                return internal_failure();
            }
        } else {
            // Subscribed before the first pass, so a send committed between
            // a pass that found nothing and the wait still wakes it.
            std::vector<std::string> keys;
            keys.reserve(n);
            for (std::uint16_t part = 0; part < n; ++part) {
                keys.push_back(queue_keys::partition_prefix(q->target(part)));
            }
            auto sub = _config._waits->subscribe(std::move(keys));
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(wait_s);
            for (;;) {
                if (!pass()) {
                    return internal_failure();
                }
                if (!messages.empty() ||
                    sub.wait_until(deadline) != availability_hub::wake::ready) {
                    break;
                }
            }
        }
        boost::json::object out;
        if (!messages.empty()) {
            out["Messages"] = std::move(messages);
        }
        return out;
    }

    [[nodiscard]] auto render_message(const queue_record& q, std::uint16_t partition,
                                      const received_message& m,
                                      const std::set<std::string, std::less<>>& system_names,
                                      const std::vector<std::string>& attribute_names) const
        -> boost::json::object {
        boost::json::object out;
        out["MessageId"] = m.message_id;
        out["ReceiptHandle"] = encode_receipt(
            receipt_handle{q._id, partition, m.sequence, m.receive_sequence, m.visible_at_ms},
            _config._receipt_keys);
        out["MD5OfBody"] = m.md5_of_body;
        std::string attributes_stored = m.attributes;
        if (is_sealed(m.body)) {
            auto o = _config._sse->open(m.message_id, m.body, _cluster.now_ms());
            out["Body"] = std::move(o._body);
            attributes_stored = std::move(o._attributes);
        } else {
            out["Body"] = m.body;
        }
        if (auto sys = system_attributes(q, partition, m, system_names); !sys.empty()) {
            out["Attributes"] = std::move(sys);
        }
        // The digest is over the attributes returned, which is what an SDK
        // recomputes and compares.
        if (auto attrs = select_attributes(decode_attributes(attributes_stored), attribute_names);
            !attrs.empty()) {
            out["MD5OfMessageAttributes"] = md5_of_attributes(attrs);
            out["MessageAttributes"] = std::move(attrs);
        }
        return out;
    }

    // -- deletes and visibility --------------------------------------------------

    /// One delete or visibility change: the batch entry id (empty for the
    /// single forms), the token as sent, and the timeout.
    struct receipt_request {
        std::string _id;
        std::string _token;
        std::uint32_t _timeout_s = 0;
    };

    /// Commits `requests` (already validated apart from their tokens) and
    /// returns, per request, nullopt for success or the entry's error.
    [[nodiscard]] auto apply_receipts(const queue_record& q, queue_command::kind op,
                                      const std::vector<receipt_request>& requests)
        -> std::vector<std::optional<aws_json::error>> {
        using namespace service_detail;
        std::vector<std::optional<aws_json::error>> out(requests.size());
        std::map<std::uint16_t, std::vector<std::size_t>> by_partition;
        std::vector<receipt_handle> handles(requests.size());
        for (std::size_t i = 0; i < requests.size(); ++i) {
            const auto h = decode_receipt(requests[i]._token, q._id, _config._receipt_keys);
            if (!h || h->_partition >= q._partitions) {
                out[i] = bad_receipt(requests[i]._token);
                continue;
            }
            handles[i] = *h;
            by_partition[h->_partition].push_back(i);
        }
        for (const auto& [part, idx] : by_partition) {
            queue_command c;
            c.op = op;
            c.target = q.target(part);
            c.now_ms = _cluster.now_ms();
            for (const auto i : idx) {
                c.receipts.push_back(receipt_ref{std::to_string(i), handles[i]._sequence,
                                                 handles[i]._receive_sequence,
                                                 requests[i]._timeout_s});
            }
            const auto r = commit_queue(c);
            if (!r || r->entries.size() != idx.size()) {
                for (const auto i : idx) {
                    out[i] = internal_failure();
                }
                continue;
            }
            for (std::size_t k = 0; k < idx.size(); ++k) {
                const auto i = idx[k];
                switch (r->entries[k].outcome) {
                    case entry_result::status::ok:
                    case entry_result::status::stale:  // a stale delete is accepted
                        break;
                    case entry_result::status::not_inflight:
                        out[i] = modeled_error("MessageNotInflight",
                                               "The message referred to is not in flight.");
                        break;
                    case entry_result::status::timeout_too_long:
                        out[i] = invalid_value("VisibilityTimeout",
                                               std::to_string(requests[i]._timeout_s),
                                               "Total VisibilityTimeout for the message is beyond "
                                               "the limit [43200 seconds]");
                        break;
                    default:
                        out[i] = invalid_value("ReceiptHandle", requests[i]._token,
                                               "Message does not exist or is not available for "
                                               "visibility timeout change.");
                        break;
                }
            }
        }
        return out;
    }

    [[nodiscard]] static auto timeout_of(const boost::json::object& in)
        -> aws_json::result<std::uint32_t> {
        const auto v = service_detail::int_member(in, "VisibilityTimeout");
        if (!v) {
            return service_detail::missing("VisibilityTimeout");
        }
        if (*v < 0 || *v > 43200) {
            return service_detail::invalid_value("VisibilityTimeout", std::to_string(*v),
                                                 "VisibilityTimeout must be an integer between 0 "
                                                 "and 43200");
        }
        return static_cast<std::uint32_t>(*v);
    }

    auto single_receipt(sqs_call_context& ctx, boost::json::object& in, queue_command::kind op)
        -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        if (op == queue_command::kind::delete_) {
            if (auto e = throttled(*q, "delete")) {
                return *e;
            }
        }
        receipt_request r;
        r._token = std::string(service_detail::string_member(in, "ReceiptHandle").value_or(""));
        if (r._token.empty()) {
            return service_detail::missing("ReceiptHandle");
        }
        if (op == queue_command::kind::change_visibility) {
            const auto t = timeout_of(in);
            if (!t) {
                return t.error();
            }
            r._timeout_s = *t;
        }
        auto out = apply_receipts(*q, op, {r});
        if (out.front()) {
            return *out.front();
        }
        return boost::json::object{};
    }

    auto batch_receipts(sqs_call_context& ctx, boost::json::object& in, queue_command::kind op,
                        std::string_view entry_shape) -> result {
        const auto q = queue_of(ctx);
        if (!q) {
            return q.error();
        }
        if (op == queue_command::kind::delete_) {
            if (auto e = throttled(*q, "delete")) {
                return *e;
            }
        }
        const auto entries = batch_entries(in, entry_shape, profile_of(*q));
        if (!entries) {
            return entries.error();
        }
        boost::json::array failed;
        std::vector<receipt_request> requests;
        for (const auto* e : *entries) {
            receipt_request r;
            r._id = std::string(service_detail::string_member(*e, "Id").value_or(""));
            r._token = std::string(service_detail::string_member(*e, "ReceiptHandle").value_or(""));
            if (r._token.empty()) {
                failed.push_back(failed_entry(r._id, service_detail::missing("ReceiptHandle")));
                continue;
            }
            if (op == queue_command::kind::change_visibility) {
                const auto t = timeout_of(*e);
                if (!t) {
                    failed.push_back(failed_entry(r._id, t.error()));
                    continue;
                }
                r._timeout_s = *t;
            }
            requests.push_back(std::move(r));
        }
        const auto outcomes = apply_receipts(*q, op, requests);
        boost::json::array ok;
        for (std::size_t i = 0; i < requests.size(); ++i) {
            if (outcomes[i]) {
                failed.push_back(failed_entry(requests[i]._id, *outcomes[i]));
            } else {
                ok.push_back(boost::json::object{{"Id", requests[i]._id}});
            }
        }
        return batch_reply(std::move(ok), std::move(failed));
    }

    auto delete_message_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        return single_receipt(ctx, in, queue_command::kind::delete_);
    }

    auto change_visibility_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        return single_receipt(ctx, in, queue_command::kind::change_visibility);
    }

    auto delete_message_batch_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        return batch_receipts(ctx, in, queue_command::kind::delete_,
                              "DeleteMessageBatchRequestEntry");
    }

    auto change_visibility_batch_op(sqs_call_context& ctx, boost::json::object& in) -> result {
        return batch_receipts(ctx, in, queue_command::kind::change_visibility,
                              "ChangeMessageVisibilityBatchRequestEntry");
    }
};

}  // namespace kythira::sqs
