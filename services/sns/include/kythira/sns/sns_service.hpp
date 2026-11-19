// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_service.hpp
/// @brief The SNS operation handlers (`.kiro/specs/sns-compatible-notifications/`
///        task 4, Requirement 4.1): topics, their attributes, tags,
///        permissions and data protection policies.
///
/// `sns_service` registers one handler per operation on a `front_end`, which
/// has already authenticated the caller, decoded the form, found the topic
/// the request names and authorized the operation on it (task 3). A handler
/// validates its parameters as SNS does, turns the request into a
/// `topic_command`, commits it through the `topic_store`, and writes the
/// result XML.
///
/// Topics are found by the ARN the request names, not by the caller's
/// account: a caller another account's topic policy admits acts on that
/// account's topic, as on SNS. An ARN for another region or partition names
/// no topic here, so it is NotFound.
///
/// What the state machine stores is what the API set: attributes exactly as
/// given (`FifoTopic` is the record's `_fifo` flag, not an attribute, so
/// CreateTopic stays idempotent whichever way the caller spells it), and a
/// `Policy` only once one is set. `GetTopicAttributes` adds the derived
/// attributes SNS reports (`TopicArn`, `Owner`, the subscription counts,
/// `EffectiveDeliveryPolicy`, and the default policy while none is set);
/// the same effective policy goes to authorization through `lookup`.
///
/// The `DataProtectionPolicy` is stored as a topic attribute and returned by
/// GetDataProtectionPolicy, never by GetTopicAttributes, as on SNS. Kythira
/// stores it but does not enforce it (doc/unsupported.md says so).
///
/// Task 12's recorded SNS responses pin the exact error messages; the ones
/// here follow SNS's documented `Invalid parameter: <name> Reason: <why>`
/// form.

#include <kythira/sns/sns_compat_profile.hpp>
#include <kythira/sns/sns_errors.hpp>
#include <kythira/sns/sns_filter_policy.hpp>
#include <kythira/sns/sns_front_end.hpp>
#include <kythira/sns/sns_message.hpp>
#include <kythira/sns/sns_query.hpp>
#include <kythira/sns/sns_topic_policy.hpp>
#include <kythira/sns/sns_topic_state_machine.hpp>

#include <raft/aws_query_protocol.hpp>

#include <boost/json.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sns {

// ---- the store ------------------------------------------------------------

/// Where the handlers commit commands and read topics. One Raft group per
/// store today; routing a topic to its group is the layers' work (task 9).
class topic_store {
public:
    topic_store() = default;
    topic_store(const topic_store&) = delete;
    topic_store(topic_store&&) = delete;
    auto operator=(const topic_store&) -> topic_store& = delete;
    auto operator=(topic_store&&) -> topic_store& = delete;
    virtual ~topic_store() = default;

    /// Commits `c` and answers its result, or nullopt when it could not be
    /// committed (no leader, no quorum, a timeout): InternalError, which
    /// clients retry.
    virtual auto submit(const topic_command& c) -> std::optional<apply_result> = 0;

    [[nodiscard]] virtual auto find_topic(std::string_view account, std::string_view name) const
        -> std::optional<topic_record> = 0;

    /// An account's topics by name, after `start_after`, at most `limit`.
    [[nodiscard]] virtual auto list_topics(std::string_view account, std::string_view start_after,
                                           std::size_t limit) const
        -> std::vector<topic_record> = 0;

    [[nodiscard]] virtual auto subscriptions_of(std::uint64_t topic_id) const
        -> std::vector<subscription_record> = 0;

    [[nodiscard]] virtual auto find_subscription(std::uint64_t id) const
        -> std::optional<subscription_record> = 0;

    [[nodiscard]] virtual auto topic_by_id(std::uint64_t id) const
        -> std::optional<topic_record> = 0;

    /// Every subscription by id, after `after_id`, at most `limit`.
    [[nodiscard]] virtual auto subscriptions_after(std::uint64_t after_id, std::size_t limit) const
        -> std::vector<subscription_record> = 0;
};

/// A store over one in-process topic state machine: a single-node cluster,
/// and the handlers' tests. Commands apply in submission order, as a Raft
/// log would order them.
template<typename LogIndex = std::uint64_t> class local_topic_store final : public topic_store {
public:
    local_topic_store() = default;
    explicit local_topic_store(record_segment_store* store) : _sm(store) {}

    auto submit(const topic_command& c) -> std::optional<apply_result> override {
        return decode_result(_sm.apply(encode_command(c), ++_index));
    }

    [[nodiscard]] auto find_topic(std::string_view account, std::string_view name) const
        -> std::optional<topic_record> override {
        const auto* t = _sm.find_topic(account, name);
        return t == nullptr ? std::nullopt : std::optional<topic_record>(*t);
    }

    [[nodiscard]] auto list_topics(std::string_view account, std::string_view start_after,
                                   std::size_t limit) const -> std::vector<topic_record> override {
        std::vector<topic_record> out;
        for (const auto* t : _sm.list_topics(account, start_after, limit)) {
            out.push_back(*t);
        }
        return out;
    }

    [[nodiscard]] auto subscriptions_of(std::uint64_t topic_id) const
        -> std::vector<subscription_record> override {
        std::vector<subscription_record> out;
        for (const auto* s : _sm.subscriptions_of(topic_id)) {
            out.push_back(*s);
        }
        return out;
    }

    [[nodiscard]] auto find_subscription(std::uint64_t id) const
        -> std::optional<subscription_record> override {
        const auto* sub = _sm.find_subscription(id);
        return sub == nullptr ? std::nullopt : std::optional<subscription_record>(*sub);
    }

    [[nodiscard]] auto topic_by_id(std::uint64_t id) const -> std::optional<topic_record> override {
        const auto* t = _sm.topic_by_id(id);
        return t == nullptr ? std::nullopt : std::optional<topic_record>(*t);
    }

    [[nodiscard]] auto subscriptions_after(std::uint64_t after_id, std::size_t limit) const
        -> std::vector<subscription_record> override {
        std::vector<subscription_record> out;
        for (const auto* sub : _sm.subscriptions_after(after_id, limit)) {
            out.push_back(*sub);
        }
        return out;
    }

    [[nodiscard]] auto machine() const -> const topic_state_machine<LogIndex>& { return _sm; }

private:
    topic_state_machine<LogIndex> _sm;
    LogIndex _index{0};
};

// ---- attributes -----------------------------------------------------------

/// The page size of ListTopics, as on SNS.
inline constexpr std::size_t k_list_topics_page = 100;
/// The page size of ListSubscriptions and ListSubscriptionsByTopic.
inline constexpr std::size_t k_list_subscriptions_page = 100;
/// What Subscribe answers for a subscription waiting for confirmation, and
/// what the list operations show in place of its ARN, as on SNS.
inline constexpr std::string_view k_pending_confirmation = "pending confirmation";
inline constexpr std::string_view k_pending_arn = "PendingConfirmation";
/// Confirmation tokens: random bytes, hex encoded (SNS's are 256 hex
/// characters too).
inline constexpr std::size_t k_token_bytes = 128;
/// Subscriptions with a filter policy, per topic (SNS's quota).
inline constexpr std::size_t k_max_filter_policies_per_topic = 200;
/// Tags per topic, and the lengths SNS allows.
inline constexpr std::size_t k_max_tags = 50;
inline constexpr std::size_t k_max_tag_key = 128;
inline constexpr std::size_t k_max_tag_value = 256;

/// What SNS reports as `EffectiveDeliveryPolicy` for a topic with no
/// `DeliveryPolicy`: the HTTP defaults (three retries, 20 seconds apart).
inline constexpr std::string_view k_default_effective_delivery_policy =
    R"({"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,)"
    R"("numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,)"
    R"("backoffFunction":"linear"},"disableSubscriptionOverrides":false,)"
    R"("defaultRequestPolicy":{"headerContentType":"text/plain; charset=UTF-8"}}})";

namespace service_detail {

/// Where a topic attribute may be set.
enum class attr_scope : std::uint8_t {
    any,        ///< CreateTopic and SetTopicAttributes, either kind of topic
    fifo_only,  ///< both, FIFO topics only
    create,     ///< CreateTopic only
};

struct attr_rule {
    std::string_view _name;
    attr_scope _scope;
};

/// The settable topic attributes (CreateTopic's and SetTopicAttributes'
/// `AttributeName` values in the SNS API reference), sorted by name.
inline constexpr std::array<attr_rule, 25> k_topic_attributes{{
    {"ApplicationFailureFeedbackRoleArn", attr_scope::any},
    {"ApplicationSuccessFeedbackRoleArn", attr_scope::any},
    {"ApplicationSuccessFeedbackSampleRate", attr_scope::any},
    {"ArchivePolicy", attr_scope::fifo_only},
    {"ContentBasedDeduplication", attr_scope::fifo_only},
    {"DataProtectionPolicy", attr_scope::create},
    {"DeliveryPolicy", attr_scope::any},
    {"DisplayName", attr_scope::any},
    {"FifoThroughputScope", attr_scope::fifo_only},
    {"FifoTopic", attr_scope::create},
    {"FirehoseFailureFeedbackRoleArn", attr_scope::any},
    {"FirehoseSuccessFeedbackRoleArn", attr_scope::any},
    {"FirehoseSuccessFeedbackSampleRate", attr_scope::any},
    {"HTTPFailureFeedbackRoleArn", attr_scope::any},
    {"HTTPSuccessFeedbackRoleArn", attr_scope::any},
    {"HTTPSuccessFeedbackSampleRate", attr_scope::any},
    {"KmsMasterKeyId", attr_scope::any},
    {"LambdaFailureFeedbackRoleArn", attr_scope::any},
    {"LambdaSuccessFeedbackRoleArn", attr_scope::any},
    {"LambdaSuccessFeedbackSampleRate", attr_scope::any},
    {"Policy", attr_scope::any},
    {"SQSFailureFeedbackRoleArn", attr_scope::any},
    {"SQSSuccessFeedbackRoleArn", attr_scope::any},
    {"SQSSuccessFeedbackSampleRate", attr_scope::any},
    {"SignatureVersion", attr_scope::any},
}};

/// Attributes set nowhere else that SNS also accepts on SetTopicAttributes.
inline constexpr std::string_view k_tracing_config = "TracingConfig";

[[nodiscard]] inline auto find_attr(std::string_view name) -> const attr_rule* {
    if (name == k_tracing_config) {
        static constexpr attr_rule tracing{k_tracing_config, attr_scope::any};
        return &tracing;
    }
    const auto* it =
        std::lower_bound(k_topic_attributes.begin(), k_topic_attributes.end(), name,
                         [](const attr_rule& r, std::string_view n) { return r._name < n; });
    return it != k_topic_attributes.end() && it->_name == name ? it : nullptr;
}

[[nodiscard]] inline auto is_json_object(std::string_view text) -> bool {
    boost::system::error_code ec;
    const auto v = boost::json::parse(text, ec);
    return !ec && v.is_object();
}

[[nodiscard]] inline auto ends_with(std::string_view s, std::string_view suffix) -> bool {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

/// A sample rate: an integer percentage, 0 to 100.
[[nodiscard]] inline auto valid_sample_rate(std::string_view v) -> bool {
    if (v.empty() || v.size() > 3 ||
        !std::all_of(v.begin(), v.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
        return false;
    }
    return std::stoi(std::string(v)) <= 100;
}

/// Checks one attribute's value; the error names the attribute.
[[nodiscard]] inline auto check_value(std::string_view name, std::string_view value)
    -> std::optional<sns_error> {
    const auto bad = [name] {
        return invalid_parameter("Attributes", "Invalid value for " + std::string(name));
    };
    if (name == "Policy") {
        if (auto p = check_topic_policy(value); !p.has_value()) {
            return p.error();
        }
        return std::nullopt;
    }
    if (name == "DeliveryPolicy" || name == "ArchivePolicy" || name == "DataProtectionPolicy") {
        return is_json_object(value) ? std::nullopt : std::optional(bad());
    }
    if (name == "SignatureVersion") {
        return value == "1" || value == "2" ? std::nullopt : std::optional(bad());
    }
    if (name == k_tracing_config) {
        return value == "PassThrough" || value == "Active" ? std::nullopt : std::optional(bad());
    }
    if (name == "ContentBasedDeduplication" || name == "FifoTopic") {
        return value == "true" || value == "false" ? std::nullopt : std::optional(bad());
    }
    if (name == "FifoThroughputScope") {
        return value == "Topic" || value == "MessageGroup" ? std::nullopt : std::optional(bad());
    }
    if (ends_with(name, "SampleRate")) {
        return valid_sample_rate(value) ? std::nullopt : std::optional(bad());
    }
    return std::nullopt;
}

/// A random lowercase hex string of `bytes` bytes.
[[nodiscard]] inline auto random_hex(std::size_t bytes) -> std::string {
    std::vector<unsigned char> raw(bytes);
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        throw std::runtime_error("sns: RAND_bytes failed");
    }
    static constexpr std::string_view k_hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (const auto b : raw) {
        out += k_hex.at(b >> 4U);
        out += k_hex.at(b & 0x0FU);
    }
    return out;
}

/// The protocols Kythira delivers to. SMS and mobile push (`sms`,
/// `application`) are out of scope.
[[nodiscard]] inline auto known_protocol(std::string_view p) -> bool {
    return p == "http" || p == "https" || p == "email" || p == "email-json" || p == "sqs" ||
           p == "lambda" || p == "firehose";
}

/// The settable subscription attributes, as the SNS API reference lists
/// them for Subscribe and SetSubscriptionAttributes.
[[nodiscard]] inline auto known_subscription_attribute(std::string_view a) -> bool {
    return a == "DeliveryPolicy" || a == "FilterPolicy" || a == "FilterPolicyScope" ||
           a == "RawMessageDelivery" || a == "RedrivePolicy" || a == "SubscriptionRoleArn" ||
           a == "ReplayPolicy";
}

/// The account of an `arn:<partition>:<service>:<region>:<account>:...`
/// ARN of `service`, or empty when `arn` is not one.
[[nodiscard]] inline auto arn_account(std::string_view arn, std::string_view service)
    -> std::string_view {
    std::array<std::string_view, 5> parts{};
    for (auto& part : parts) {
        const auto colon = arn.find(':');
        if (colon == std::string_view::npos) {
            return {};
        }
        part = arn.substr(0, colon);
        arn.remove_prefix(colon + 1);
    }
    if (parts[0] != "arn" || parts[2] != service || arn.empty()) {
        return {};
    }
    return parts[4];
}

/// The suffix of a subscription's ARN: the topic and subscription ids in
/// the shape of a UUID, so clients that parse SNS's ARNs accept it. Both
/// counters only grow, so a suffix is never reused.
[[nodiscard]] inline auto subscription_suffix(std::uint64_t topic_id, std::uint64_t id)
    -> std::string {
    static constexpr std::string_view k_hex = "0123456789abcdef";
    const auto hex = [](std::uint64_t v, int digits) {
        std::string out(static_cast<std::size_t>(digits), '0');
        for (int i = digits - 1; i >= 0; --i) {
            out[static_cast<std::size_t>(i)] = k_hex.at(v & 0xFU);
            v >>= 4U;
        }
        return out;
    };
    return hex(topic_id, 8) + "-0000-4000-8000-" + hex(id, 12);
}

/// The subscription id inside a suffix `subscription_suffix` made, with the
/// topic id's low 32 bits; nullopt for anything else.
[[nodiscard]] inline auto parse_subscription_suffix(std::string_view suffix)
    -> std::optional<std::pair<std::uint32_t, std::uint64_t>> {
    if (suffix.size() != 36 || suffix.substr(8, 16) != "-0000-4000-8000-") {
        return std::nullopt;
    }
    const auto parse = [](std::string_view hex) -> std::optional<std::uint64_t> {
        std::uint64_t v = 0;
        for (const char c : hex) {
            const auto d = c >= '0' && c <= '9'   ? c - '0'
                           : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                                  : -1;
            if (d < 0) {
                return std::nullopt;
            }
            v = (v << 4U) | static_cast<std::uint64_t>(d);
        }
        return v;
    };
    const auto topic = parse(suffix.substr(0, 8));
    const auto id = parse(suffix.substr(24));
    if (!topic || !id) {
        return std::nullopt;
    }
    return std::pair{static_cast<std::uint32_t>(*topic), *id};
}

/// A random version 4 UUID, lowercase: a message id.
[[nodiscard]] inline auto random_uuid() -> std::string {
    auto h = random_hex(16);
    h[12] = '4';
    static constexpr std::string_view k_variant = "89ab";
    h[16] = k_variant.at(static_cast<std::size_t>(h[16] - (h[16] >= 'a' ? 'a' - 10 : '0')) & 3U);
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) +
           "-" + h.substr(20);
}

/// SHA-256 of `data`, lowercase hex: the deduplication id of a FIFO
/// message under content-based deduplication.
[[nodiscard]] inline auto sha256_hex(std::string_view data) -> std::string {
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), md.data(), &len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("sns: SHA-256 failed");
    }
    static constexpr std::string_view k_hex = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
        out += k_hex.at(md.at(i) >> 4U);
        out += k_hex.at(md.at(i) & 0x0FU);
    }
    return out;
}

/// 64-bit FNV-1a: a FIFO message group's log partition, the same on every
/// node and release.
[[nodiscard]] inline auto fnv1a(std::string_view s) -> std::uint64_t {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (const unsigned char c : s) {
        h = (h ^ c) * 0x100000001b3ULL;
    }
    return h;
}

/// A message group or deduplication id: 1 to 128 characters of letters,
/// digits and ASCII punctuation, as SNS takes them.
[[nodiscard]] inline auto valid_fifo_id(std::string_view id) -> bool {
    return !id.empty() && id.size() <= 128 &&
           std::all_of(id.begin(), id.end(), [](unsigned char c) {
               return std::isalnum(c) != 0 || std::ispunct(c) != 0;
           });
}

/// A message attribute name SNS accepts: up to 256 letters, digits,
/// hyphens, underscores and periods, no leading, trailing or doubled
/// period, and no `AWS.` or `Amazon.` prefix in any case.
[[nodiscard]] inline auto valid_attribute_name(std::string_view n) -> bool {
    if (n.empty() || n.size() > 256 || n.front() == '.' || n.back() == '.' ||
        n.find("..") != std::string_view::npos) {
        return false;
    }
    std::string lower(n);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.starts_with("aws.") || lower.starts_with("amazon.")) {
        return false;
    }
    return std::all_of(n.begin(), n.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.';
    });
}

/// A Number attribute's value: an optional sign, digits with at most one
/// decimal point, and an optional exponent.
[[nodiscard]] inline auto valid_number(std::string_view v) -> bool {
    std::size_t i = 0;
    if (i < v.size() && (v[i] == '+' || v[i] == '-')) {
        ++i;
    }
    bool digits = false;
    bool point = false;
    for (; i < v.size(); ++i) {
        if (std::isdigit(static_cast<unsigned char>(v[i])) != 0) {
            digits = true;
        } else if (v[i] == '.' && !point) {
            point = true;
        } else {
            break;
        }
    }
    if (!digits) {
        return false;
    }
    if (i < v.size() && (v[i] == 'e' || v[i] == 'E')) {
        ++i;
        if (i < v.size() && (v[i] == '+' || v[i] == '-')) {
            ++i;
        }
        const auto start = i;
        while (i < v.size() && std::isdigit(static_cast<unsigned char>(v[i])) != 0) {
            ++i;
        }
        if (i == start) {
            return false;
        }
    }
    return i == v.size();
}

[[nodiscard]] inline auto system_now_ms() -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace service_detail

struct service_config {
    /// Log partitions and delivery buckets of a new topic (fixed at
    /// creation; the state machine allows up to 1024 of each).
    std::uint32_t _standard_partitions = 1;
    std::uint32_t _fifo_partitions = 1;
    std::uint32_t _delivery_buckets = 1;
    /// The cluster's compatibility profile; topics overlay their
    /// `kythira:compat:*` tags on it.
    sns_compat_profile _profile{};
    /// Seals ListTopics' `NextToken`; 32 random bytes per process unless
    /// set (a token then opens only on the node that issued it).
    std::vector<unsigned char> _marker_key{};
    /// The leader's clock, stamped into commands. Tests set it.
    std::function<std::int64_t()> _now_ms = service_detail::system_now_ms;
};

// ---- the service ----------------------------------------------------------

class sns_service {
public:
    sns_service(topic_store& store, service_config config)
        : _store(store), _config(std::move(config)), _sealer(marker_key(_config)) {}

    /// Registers every handler this service implements on `fe`, and its
    /// resource lookup.
    template<typename FrontEnd> void attach(FrontEnd& fe) {
        fe.set_resource_lookup([this](std::string_view arn) { return lookup(arn); });
        const auto bind = [this, &fe](std::string_view op, auto member) {
            fe.on(op, [this, member](call_context& ctx, const params& in) {
                return (this->*member)(ctx, in);
            });
        };
        bind("CreateTopic", &sns_service::create_topic);
        bind("DeleteTopic", &sns_service::delete_topic);
        bind("GetTopicAttributes", &sns_service::get_topic_attributes);
        bind("SetTopicAttributes", &sns_service::set_topic_attributes);
        bind("ListTopics", &sns_service::list_topics);
        bind("TagResource", &sns_service::tag_resource);
        bind("UntagResource", &sns_service::untag_resource);
        bind("ListTagsForResource", &sns_service::list_tags_for_resource);
        bind("AddPermission", &sns_service::add_permission_op);
        bind("RemovePermission", &sns_service::remove_permission_op);
        bind("GetDataProtectionPolicy", &sns_service::get_data_protection_policy);
        bind("PutDataProtectionPolicy", &sns_service::put_data_protection_policy);
        bind("Subscribe", &sns_service::subscribe);
        bind("ConfirmSubscription", &sns_service::confirm_subscription);
        bind("Unsubscribe", &sns_service::unsubscribe);
        bind("GetSubscriptionAttributes", &sns_service::get_subscription_attributes);
        bind("SetSubscriptionAttributes", &sns_service::set_subscription_attributes);
        bind("ListSubscriptionsByTopic", &sns_service::list_subscriptions_by_topic);
        bind("ListSubscriptions", &sns_service::list_subscriptions);
        bind("Publish", &sns_service::publish);
        bind("PublishBatch", &sns_service::publish_batch);
    }

    /// The facts authorization needs about a topic: its effective policy
    /// (the default one while none is set) and its tags.
    [[nodiscard]] auto lookup(std::string_view arn) const -> std::optional<resource_facts> {
        const auto parts = parse_topic_arn(arn);
        if (!parts) {
            return std::nullopt;
        }
        const auto t = _store.find_topic(parts->_account, parts->_name);
        if (!t) {
            return std::nullopt;
        }
        resource_facts f;
        f._policy = effective_policy(*t, arn);
        for (const auto& [k, v] : t->_tags) {
            f._tags.emplace_back(k, v);
        }
        return f;
    }

    // ---- topics -----------------------------------------------------------

    auto create_topic(call_context& ctx, const params& in) -> query_result<std::string> {
        auto name = in.required("Name");
        if (!name.has_value()) {
            return name.error();
        }
        auto attrs = in.string_map("Attributes");
        if (!attrs.has_value()) {
            return attrs.error();
        }
        auto tags = in.tags();
        if (!tags.has_value()) {
            return tags.error();
        }
        bool fifo = false;
        string_map stored;
        for (const auto& [k, v] : *attrs) {
            const auto* rule = service_detail::find_attr(k);
            if (rule == nullptr) {
                return invalid_parameter("Attributes", "Unknown attribute " + k);
            }
            if (auto bad = service_detail::check_value(k, v)) {
                return *bad;
            }
            if (k == "FifoTopic") {
                fifo = v == "true";
                continue;
            }
            stored.insert_or_assign(k, v);
        }
        if (!fifo) {
            for (const auto& [k, v] : stored) {
                if (service_detail::find_attr(k)->_scope == service_detail::attr_scope::fifo_only) {
                    return invalid_parameter("Attributes", k + " is only valid for FIFO topics");
                }
            }
        }
        if (!valid_topic_name(*name, fifo)) {
            return invalid_parameter("Topic Name");
        }
        auto tag_map = check_tags(*tags);
        if (!tag_map.has_value()) {
            return tag_map.error();
        }
        const std::string account = ctx._principal.account;
        if (const auto limit = limits(ctx).topics_per_account(fifo); limit != 0) {
            if (!_store.find_topic(account, *name) && count_topics(account, fifo) >= limit) {
                return model_error("TopicLimitExceededException", "Topic limit exceeded");
            }
        }
        create_topic_command c;
        c._account = account;
        c._name = std::string(*name);
        c._fifo = fifo;
        c._partitions = fifo ? _config._fifo_partitions : _config._standard_partitions;
        c._delivery_buckets = _config._delivery_buckets;
        c._attributes = std::move(stored);
        c._tags = std::move(*tag_map);
        c._now_ms = _config._now_ms();
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        switch (r->_status) {
            case apply_status::ok:
                break;
            case apply_status::topic_exists_with_different_attributes:
                return invalid_parameter("Attributes",
                                         "Topic already exists with different attributes");
            case apply_status::topic_exists_with_different_tags:
                return invalid_parameter("Tags", "Topic already exists with different tags");
            default:
                return internal_error();
        }
        aws_query::xml_writer w;
        w.element("TopicArn", ctx.topic_arn(*name));
        return w.str();
    }

    auto delete_topic(call_context& ctx, const params&) -> query_result<std::string> {
        if (!ctx._topic) {
            return invalid_parameter("TopicArn");
        }
        if (!here(ctx)) {
            return topic_not_found();
        }
        delete_topic_command c;
        c._account = ctx._topic->_account;
        c._name = ctx._topic->_name;
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        return std::string{};
    }

    auto get_topic_attributes(call_context& ctx, const params&) -> query_result<std::string> {
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        string_map out;
        for (const auto& [k, v] : t->_attributes) {
            if (k != "DataProtectionPolicy") {
                out.insert_or_assign(k, v);
            }
        }
        out.insert_or_assign("TopicArn", ctx._topic_arn);
        out.insert_or_assign("Owner", t->_account);
        out.insert_or_assign("Policy", effective_policy(*t, ctx._topic_arn));
        out.try_emplace("DisplayName", "");
        out.insert_or_assign("EffectiveDeliveryPolicy",
                             t->_attributes.contains("DeliveryPolicy")
                                 ? t->_attributes.at("DeliveryPolicy")
                                 : std::string(k_default_effective_delivery_policy));
        std::size_t confirmed = 0;
        std::size_t pending = 0;
        for (const auto& s : _store.subscriptions_of(t->_id)) {
            (s._confirmed ? confirmed : pending) += 1;
        }
        out.insert_or_assign("SubscriptionsConfirmed", std::to_string(confirmed));
        out.insert_or_assign("SubscriptionsPending", std::to_string(pending));
        out.insert_or_assign("SubscriptionsDeleted", "0");
        if (t->_fifo) {
            out.insert_or_assign("FifoTopic", "true");
            out.try_emplace("ContentBasedDeduplication", "false");
        }
        aws_query::xml_writer w;
        write_map(w, "Attributes", out);
        return w.str();
    }

    auto set_topic_attributes(call_context& ctx, const params& in) -> query_result<std::string> {
        auto name = in.required("AttributeName");
        if (!name.has_value()) {
            return name.error();
        }
        const auto value = std::string(in.get("AttributeValue").value_or(""));
        const auto* rule = service_detail::find_attr(*name);
        if (rule == nullptr || rule->_scope == service_detail::attr_scope::create) {
            return invalid_parameter("AttributeName");
        }
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        if (rule->_scope == service_detail::attr_scope::fifo_only && !t->_fifo) {
            return invalid_parameter("AttributeName",
                                     std::string(*name) + " is only valid for FIFO topics");
        }
        if (auto bad = service_detail::check_value(*name, value)) {
            return *bad;
        }
        return set_attribute(ctx, std::string(*name), value);
    }

    auto list_topics(call_context& ctx, const params& in) -> query_result<std::string> {
        const std::string account = ctx._principal.account;
        const auto context = "ListTopics/" + account;
        std::string start;
        if (const auto token = in.get("NextToken"); token && !token->empty()) {
            auto opened = _sealer.open(context, *token);
            if (!opened) {
                return invalid_parameter("NextToken");
            }
            start = std::move(*opened);
        }
        auto page = _store.list_topics(account, start, k_list_topics_page + 1);
        const bool more = page.size() > k_list_topics_page;
        if (more) {
            page.pop_back();
        }
        aws_query::xml_writer w;
        w.open("Topics");
        for (const auto& t : page) {
            w.open("member").element("TopicArn", ctx.topic_arn(t._name)).close();
        }
        w.close();
        if (more) {
            w.element("NextToken", _sealer.seal(context, page.back()._name));
        }
        return w.str();
    }

    // ---- tags -------------------------------------------------------------

    auto tag_resource(call_context& ctx, const params& in) -> query_result<std::string> {
        auto tags = in.tags();
        if (!tags.has_value()) {
            return tags.error();
        }
        if (tags->empty()) {
            return invalid_parameter("Tags");
        }
        auto t = topic_of(ctx, true);
        if (!t.has_value()) {
            return t.error();
        }
        auto merged = t->_tags;
        for (const auto& [k, v] : *tags) {
            merged.insert_or_assign(k, v);
        }
        if (auto checked = check_tags(*tags); !checked.has_value()) {
            return checked.error();
        }
        if (merged.size() > k_max_tags) {
            return tag_limit();
        }
        tag_topic_command c;
        c._account = t->_account;
        c._name = t->_name;
        for (const auto& [k, v] : *tags) {
            c._set.insert_or_assign(k, v);
        }
        return commit_tags(std::move(c));
    }

    auto untag_resource(call_context& ctx, const params& in) -> query_result<std::string> {
        auto keys = in.list("TagKeys");
        if (!keys.has_value()) {
            return keys.error();
        }
        if (keys->empty()) {
            return invalid_parameter("TagKeys");
        }
        auto t = topic_of(ctx, true);
        if (!t.has_value()) {
            return t.error();
        }
        tag_topic_command c;
        c._account = t->_account;
        c._name = t->_name;
        c._remove = std::move(*keys);
        return commit_tags(std::move(c));
    }

    auto list_tags_for_resource(call_context& ctx, const params&) -> query_result<std::string> {
        auto t = topic_of(ctx, true);
        if (!t.has_value()) {
            return t.error();
        }
        aws_query::xml_writer w;
        w.open("Tags");
        for (const auto& [k, v] : t->_tags) {
            w.open("member").element("Key", k).element("Value", v).close();
        }
        w.close();
        return w.str();
    }

    // ---- permissions ------------------------------------------------------

    auto add_permission_op(call_context& ctx, const params& in) -> query_result<std::string> {
        auto label = in.required("Label");
        if (!label.has_value()) {
            return label.error();
        }
        auto accounts = in.list("AWSAccountId");
        if (!accounts.has_value()) {
            return accounts.error();
        }
        auto actions = in.list("ActionName");
        if (!actions.has_value()) {
            return actions.error();
        }
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        auto policy = add_permission(effective_policy(*t, ctx._topic_arn), ctx._topic_arn,
                                     ctx._topic->_partition, *label, *accounts, *actions);
        if (!policy.has_value()) {
            return policy.error();
        }
        return set_attribute(ctx, "Policy", *policy);
    }

    auto remove_permission_op(call_context& ctx, const params& in) -> query_result<std::string> {
        auto label = in.required("Label");
        if (!label.has_value()) {
            return label.error();
        }
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        auto policy = remove_permission(effective_policy(*t, ctx._topic_arn), *label);
        if (!policy.has_value()) {
            return policy.error();
        }
        return set_attribute(ctx, "Policy", *policy);
    }

    // ---- subscriptions ----------------------------------------------------

    /// Subscribe. HTTP, HTTPS and email endpoints wait for confirmation
    /// with a fresh token, and so does an SQS queue in another account than
    /// the caller's (Requirement 4.2); the confirmation message itself is
    /// sent by delivery (task 6). Subscribing the same endpoint again with
    /// the same attributes answers the same subscription, and a pending one
    /// takes a new token, as SNS sends a new confirmation.
    auto subscribe(call_context& ctx, const params& in) -> query_result<std::string> {
        auto protocol = in.required("Protocol");
        if (!protocol.has_value()) {
            return protocol.error();
        }
        if (!service_detail::known_protocol(*protocol)) {
            return invalid_parameter("Protocol");
        }
        const auto endpoint = std::string(in.get("Endpoint").value_or(""));
        auto attrs = in.string_map("Attributes");
        if (!attrs.has_value()) {
            return attrs.error();
        }
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        if (auto bad = check_endpoint(*t, *protocol, endpoint, *attrs)) {
            return *bad;
        }
        string_map stored;
        for (const auto& [k, v] : *attrs) {
            if (auto bad = check_subscription_attribute(*protocol, k, v)) {
                return *bad;
            }
            stored.insert_or_assign(k, v);
        }
        if (auto bad = check_filter_policy(*t, stored, 0)) {
            return *bad;
        }
        const auto& caller = ctx._principal.account;
        if (const auto limit = limits(ctx).subscriptions_per_topic(t->_fifo); limit != 0) {
            if (_store.subscriptions_of(t->_id).size() >= limit) {
                return model_error("SubscriptionLimitExceededException",
                                   "Subscription limit exceeded");
            }
        }
        subscribe_command c;
        c._account = t->_account;
        c._name = t->_name;
        c._protocol = std::string(*protocol);
        c._endpoint = endpoint;
        c._owner = caller;
        c._attributes = std::move(stored);
        c._needs_confirmation =
            *protocol != "sqs" && *protocol != "lambda" && *protocol != "firehose"
                ? true
                : *protocol == "sqs" && service_detail::arn_account(endpoint, "sqs") != caller;
        if (c._needs_confirmation) {
            c._token = service_detail::random_hex(k_token_bytes);
        }
        c._now_ms = _config._now_ms();
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        if (r->_status == apply_status::topic_not_found) {
            return topic_not_found();
        }
        if (r->_status == apply_status::subscription_exists_with_different_attributes) {
            return invalid_parameter("Attributes",
                                     "Subscription already exists with different attributes");
        }
        if (r->_status != apply_status::ok) {
            return internal_error();
        }
        const auto sub = _store.find_subscription(r->_id);
        if (!sub) {
            return internal_error();
        }
        aws_query::xml_writer w;
        if (sub->_confirmed ||
            in.get("ReturnSubscriptionArn") == std::optional<std::string_view>("true")) {
            w.element("SubscriptionArn", subscription_arn(ctx._topic_arn, *sub));
        } else {
            w.element("SubscriptionArn", k_pending_confirmation);
        }
        return w.str();
    }

    /// ConfirmSubscription: the token a confirmation message carried, while
    /// it is valid (three days). Every call here is signed, so
    /// `AuthenticateOnUnsubscribe` changes nothing: Unsubscribe always
    /// needs a signed, authorized caller.
    auto confirm_subscription(call_context& ctx, const params& in) -> query_result<std::string> {
        auto token = in.required("Token");
        if (!token.has_value()) {
            return token.error();
        }
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        confirm_subscription_command c;
        c._account = t->_account;
        c._name = t->_name;
        c._token = std::string(*token);
        c._now_ms = _config._now_ms();
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        if (r->_status == apply_status::topic_not_found) {
            return topic_not_found();
        }
        if (r->_status == apply_status::invalid_token) {
            return invalid_parameter("Token");
        }
        if (r->_status != apply_status::ok) {
            return internal_error();
        }
        const auto sub = _store.find_subscription(r->_id);
        if (!sub) {
            return internal_error();
        }
        aws_query::xml_writer w;
        w.element("SubscriptionArn", subscription_arn(ctx._topic_arn, *sub));
        return w.str();
    }

    auto unsubscribe(call_context& ctx, const params& in) -> query_result<std::string> {
        auto sub = subscription_of(ctx, in);
        if (!sub.has_value()) {
            return sub.error();
        }
        const auto r = _store.submit(unsubscribe_command{sub->_id});
        if (!r) {
            return internal_error();
        }
        if (r->_status == apply_status::subscription_not_found) {
            return subscription_not_found();
        }
        return r->_status == apply_status::ok ? query_result<std::string>(std::string{})
                                              : query_result<std::string>(internal_error());
    }

    auto get_subscription_attributes(call_context& ctx, const params& in)
        -> query_result<std::string> {
        auto sub = subscription_of(ctx, in);
        if (!sub.has_value()) {
            return sub.error();
        }
        const auto t = _store.topic_by_id(sub->_topic_id);
        if (!t) {
            return subscription_not_found();
        }
        string_map out = sub->_attributes;
        out.insert_or_assign("SubscriptionArn", subscription_arn(ctx._topic_arn, *sub));
        out.insert_or_assign("TopicArn", ctx._topic_arn);
        out.insert_or_assign("Owner", sub->_owner);
        out.insert_or_assign("Protocol", sub->_protocol);
        out.insert_or_assign("Endpoint", sub->_endpoint);
        out.insert_or_assign("PendingConfirmation", sub->_confirmed ? "false" : "true");
        out.insert_or_assign("ConfirmationWasAuthenticated", sub->_confirmed ? "true" : "false");
        out.try_emplace("RawMessageDelivery", "false");
        if (sub->_protocol == "http" || sub->_protocol == "https") {
            const auto own = sub->_attributes.find("DeliveryPolicy");
            const auto topic = t->_attributes.find("DeliveryPolicy");
            out.insert_or_assign("EffectiveDeliveryPolicy",
                                 own != sub->_attributes.end() ? own->second
                                 : topic != t->_attributes.end()
                                     ? topic->second
                                     : std::string(k_default_effective_delivery_policy));
        }
        aws_query::xml_writer w;
        write_map(w, "Attributes", out);
        return w.str();
    }

    auto set_subscription_attributes(call_context& ctx, const params& in)
        -> query_result<std::string> {
        auto name = in.required("AttributeName");
        if (!name.has_value()) {
            return name.error();
        }
        const auto value = std::string(in.get("AttributeValue").value_or(""));
        auto sub = subscription_of(ctx, in);
        if (!sub.has_value()) {
            return sub.error();
        }
        if (!service_detail::known_subscription_attribute(*name)) {
            return invalid_parameter("AttributeName");
        }
        if (auto bad = check_subscription_attribute(sub->_protocol, *name, value)) {
            return *bad;
        }
        if (*name == "FilterPolicy" || *name == "FilterPolicyScope") {
            auto after = sub->_attributes;
            after.insert_or_assign(std::string(*name), value);
            const auto t = _store.topic_by_id(sub->_topic_id);
            if (!t) {
                return subscription_not_found();
            }
            if (auto bad = check_filter_policy(*t, after, sub->_id)) {
                return *bad;
            }
        }
        set_subscription_attribute_command c;
        c._subscription_id = sub->_id;
        c._key = std::string(*name);
        c._value = value;
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        if (r->_status == apply_status::subscription_not_found) {
            return subscription_not_found();
        }
        return r->_status == apply_status::ok ? query_result<std::string>(std::string{})
                                              : query_result<std::string>(internal_error());
    }

    auto list_subscriptions_by_topic(call_context& ctx, const params& in)
        -> query_result<std::string> {
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        const auto context = "ListSubscriptionsByTopic/" + ctx._topic_arn;
        auto after = open_id_token(context, in);
        if (!after.has_value()) {
            return after.error();
        }
        std::vector<subscription_record> page;
        bool more = false;
        for (auto& sub : _store.subscriptions_of(t->_id)) {
            if (sub._id <= *after) {
                continue;
            }
            if (page.size() == k_list_subscriptions_page) {
                more = true;
                break;
            }
            page.push_back(std::move(sub));
        }
        aws_query::xml_writer w;
        w.open("Subscriptions");
        for (const auto& sub : page) {
            write_subscription(w, ctx._topic_arn, sub);
        }
        w.close();
        if (more) {
            w.element("NextToken", _sealer.seal(context, std::to_string(page.back()._id)));
        }
        return w.str();
    }

    /// ListSubscriptions: the caller's account's subscriptions, on any
    /// topic, by id.
    auto list_subscriptions(call_context& ctx, const params& in) -> query_result<std::string> {
        const std::string account = ctx._principal.account;
        const auto context = "ListSubscriptions/" + account;
        auto after = open_id_token(context, in);
        if (!after.has_value()) {
            return after.error();
        }
        std::vector<std::pair<std::string, subscription_record>> page;
        bool more = false;
        std::uint64_t cursor = *after;
        while (!more) {
            auto batch = _store.subscriptions_after(cursor, 1000);
            for (auto& sub : batch) {
                cursor = sub._id;
                if (sub._owner != account) {
                    continue;
                }
                if (page.size() == k_list_subscriptions_page) {
                    more = true;
                    break;
                }
                const auto t = _store.topic_by_id(sub._topic_id);
                if (!t) {
                    continue;
                }
                page.emplace_back("arn:" + ctx._partition + ":sns:" + ctx._region + ":" +
                                      t->_account + ":" + t->_name,
                                  std::move(sub));
            }
            if (batch.size() < 1000) {
                break;
            }
        }
        aws_query::xml_writer w;
        w.open("Subscriptions");
        for (const auto& [arn, sub] : page) {
            write_subscription(w, arn, sub);
        }
        w.close();
        if (more) {
            w.element("NextToken", _sealer.seal(context, std::to_string(page.back().second._id)));
        }
        return w.str();
    }

    // ---- publishing -------------------------------------------------------

    /// Publish (Requirements 5.1 to 5.4): one entry, committed to the topic's
    /// publish log before the message id is answered, and never waiting for
    /// delivery. A FIFO duplicate within five minutes answers the original
    /// message id and sequence number.
    auto publish(call_context& ctx, const params& in) -> query_result<std::string> {
        if (!ctx._topic) {
            if (in.contains("PhoneNumber")) {
                return invalid_parameter("PhoneNumber", "SMS is not supported");
            }
            return invalid_parameter("TopicArn or TargetArn", "no value for required parameter");
        }
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        const auto now = _config._now_ms();
        std::size_t bytes = 0;
        auto e = prepare_entry(ctx, *t, in, now, bytes);
        if (!e.has_value()) {
            return e.error();
        }
        publish_command c;
        c._account = t->_account;
        c._name = t->_name;
        c._entries.push_back(std::move(*e));
        c._now_ms = now;
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        if (r->_status == apply_status::topic_not_found) {
            return topic_not_found();
        }
        if (r->_status != apply_status::ok || r->_entries.size() != 1 ||
            r->_entries[0]._status == publish_status::invalid_parameter) {
            return internal_error();
        }
        aws_query::xml_writer w;
        w.element("MessageId", r->_entries[0]._message_id);
        if (t->_fifo) {
            w.element("SequenceNumber", sequence_number(r->_entries[0]._seq));
        }
        return w.str();
    }

    /// PublishBatch: up to ten entries in one command. An entry that fails
    /// validation is reported under `Failed` and the rest are published;
    /// the whole batch's messages together may not exceed one message's
    /// limit, as on SNS.
    auto publish_batch(call_context& ctx, const params& in) -> query_result<std::string> {
        auto entries = in.batch("PublishBatchRequestEntries", k_max_publish_entries);
        if (!entries.has_value()) {
            return entries.error();
        }
        auto t = topic_of(ctx);
        if (!t.has_value()) {
            return t.error();
        }
        const auto now = _config._now_ms();
        struct failure {
            std::string _id;
            sns_error _error;
        };
        std::vector<failure> failed;
        std::vector<std::string> ids;
        publish_command c;
        c._account = t->_account;
        c._name = t->_name;
        c._now_ms = now;
        std::size_t total = 0;
        for (const auto& entry : *entries) {
            const auto id = std::string(entry.get("Id").value_or(""));
            std::size_t bytes = 0;
            auto e = prepare_entry(ctx, *t, entry, now, bytes);
            total += bytes;
            if (!e.has_value()) {
                failed.push_back({id, e.error()});
                continue;
            }
            ids.push_back(id);
            c._entries.push_back(std::move(*e));
        }
        if (total > limits(ctx).max_message_bytes(std::nullopt)) {
            return model_error("BatchRequestTooLongException",
                               "The length of all the messages put together is more than the "
                               "limit.");
        }
        std::vector<publish_entry_result> results;
        if (!c._entries.empty()) {
            const auto r = _store.submit(c);
            if (!r) {
                return internal_error();
            }
            if (r->_status == apply_status::topic_not_found) {
                return topic_not_found();
            }
            if (r->_status != apply_status::ok || r->_entries.size() != c._entries.size()) {
                return internal_error();
            }
            results = r->_entries;
        }
        aws_query::xml_writer w;
        w.open("Successful");
        for (std::size_t i = 0; i < results.size(); ++i) {
            if (results[i]._status == publish_status::invalid_parameter) {
                failed.push_back({ids[i], internal_error()});
                continue;
            }
            w.open("member").element("Id", ids[i]).element("MessageId", results[i]._message_id);
            if (t->_fifo) {
                w.element("SequenceNumber", sequence_number(results[i]._seq));
            }
            w.close();
        }
        w.close();
        w.open("Failed");
        for (const auto& f : failed) {
            w.open("member")
                .element("Id", f._id)
                .element("Code", f._error._code)
                .element("Message", f._error._message)
                .boolean("SenderFault", f._error._sender_fault)
                .close();
        }
        w.close();
        return w.str();
    }

    // ---- data protection --------------------------------------------------

    auto get_data_protection_policy(call_context& ctx, const params&) -> query_result<std::string> {
        auto t = topic_of(ctx, true);
        if (!t.has_value()) {
            return t.error();
        }
        aws_query::xml_writer w;
        const auto it = t->_attributes.find("DataProtectionPolicy");
        w.element("DataProtectionPolicy", it == t->_attributes.end() ? "" : it->second);
        return w.str();
    }

    auto put_data_protection_policy(call_context& ctx, const params& in)
        -> query_result<std::string> {
        auto doc = in.required("DataProtectionPolicy");
        if (!doc.has_value()) {
            return doc.error();
        }
        if (!service_detail::is_json_object(*doc)) {
            return invalid_parameter("DataProtectionPolicy");
        }
        auto t = topic_of(ctx, true);
        if (!t.has_value()) {
            return t.error();
        }
        return set_attribute(ctx, "DataProtectionPolicy", std::string(*doc));
    }

private:
    [[nodiscard]] static auto marker_key(service_config& c) -> std::vector<unsigned char> {
        if (c._marker_key.empty()) {
            c._marker_key.resize(32);
            if (RAND_bytes(c._marker_key.data(), static_cast<int>(c._marker_key.size())) != 1) {
                throw std::runtime_error("sns: RAND_bytes failed");
            }
        }
        return c._marker_key;
    }

    [[nodiscard]] auto limits(const call_context& ctx) const -> sns_limits {
        return {_config._profile, ctx._region};
    }

    /// Whether the topic the request names is in this region and partition.
    [[nodiscard]] static auto here(const call_context& ctx) -> bool {
        return ctx._topic && ctx._topic->_region == ctx._region &&
               ctx._topic->_partition == ctx._partition;
    }

    [[nodiscard]] static auto topic_not_found() -> sns_error {
        return not_found("Topic does not exist");
    }

    [[nodiscard]] static auto tag_limit() -> sns_error {
        return model_error("TagLimitExceededException",
                           "Could not complete request: tag quota of per resource exceeded");
    }

    /// The topic the request names. The tag and data protection operations
    /// name it as a `ResourceArn`, and SNS answers ResourceNotFound for
    /// those; the rest answer NotFound.
    [[nodiscard]] auto topic_of(const call_context& ctx, bool resource = false) const
        -> query_result<topic_record> {
        const auto missing = [resource] {
            return resource ? model_error("ResourceNotFoundException", "Resource does not exist")
                            : topic_not_found();
        };
        if (!ctx._topic) {
            return invalid_parameter(resource ? "ResourceArn" : "TopicArn");
        }
        if (!here(ctx)) {
            return missing();
        }
        auto t = _store.find_topic(ctx._topic->_account, ctx._topic->_name);
        if (!t) {
            return missing();
        }
        return std::move(*t);
    }

    [[nodiscard]] static auto effective_policy(const topic_record& t, std::string_view arn)
        -> std::string {
        const auto it = t._attributes.find("Policy");
        return it != t._attributes.end() ? it->second : default_topic_policy(arn, t._account);
    }

    [[nodiscard]] auto count_topics(const std::string& account, bool fifo) const -> std::uint64_t {
        std::uint64_t n = 0;
        std::string after;
        for (;;) {
            const auto page = _store.list_topics(account, after, 1000);
            for (const auto& t : page) {
                n += t._fifo == fifo ? 1 : 0;
            }
            if (page.size() < 1000) {
                return n;
            }
            after = page.back()._name;
        }
    }

    /// Validates tags as SNS does and returns them as a map; a key given
    /// twice keeps the last value.
    [[nodiscard]] static auto check_tags(const tag_list& tags) -> query_result<string_map> {
        string_map out;
        for (const auto& [k, v] : tags) {
            if (k.empty() || k.size() > k_max_tag_key) {
                return invalid_parameter("Tags", "Tag key length must be between 1 and 128");
            }
            if (v.size() > k_max_tag_value) {
                return invalid_parameter("Tags", "Tag value length must be at most 256");
            }
            if (k.starts_with("aws:")) {
                return invalid_parameter("Tags", "Tag keys can not start with aws:");
            }
            out.insert_or_assign(k, v);
        }
        if (out.size() > k_max_tags) {
            return tag_limit();
        }
        if (auto bad = check_compat_tags(tags)) {
            return *bad;
        }
        return out;
    }

    auto commit_tags(tag_topic_command c) -> query_result<std::string> {
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        if (r->_status == apply_status::topic_not_found) {
            return model_error("ResourceNotFoundException", "Resource does not exist");
        }
        return r->_status == apply_status::ok ? query_result<std::string>(std::string{})
                                              : query_result<std::string>(internal_error());
    }

    auto set_attribute(const call_context& ctx, std::string key, std::string value)
        -> query_result<std::string> {
        set_topic_attribute_command c;
        c._account = ctx._topic->_account;
        c._name = ctx._topic->_name;
        c._key = std::move(key);
        c._value = std::move(value);
        const auto r = _store.submit(c);
        if (!r) {
            return internal_error();
        }
        if (r->_status == apply_status::topic_not_found) {
            return topic_not_found();
        }
        return r->_status == apply_status::ok ? query_result<std::string>(std::string{})
                                              : query_result<std::string>(internal_error());
    }

    [[nodiscard]] static auto subscription_not_found() -> sns_error {
        return not_found("Subscription does not exist");
    }

    [[nodiscard]] static auto subscription_arn(std::string_view topic_arn,
                                               const subscription_record& sub) -> std::string {
        return std::string(topic_arn) + ":" +
               service_detail::subscription_suffix(sub._topic_id, sub._id);
    }

    /// The subscription a `SubscriptionArn` names: the front end found its
    /// topic; the suffix must name a subscription of that topic.
    [[nodiscard]] auto subscription_of(const call_context& ctx, const params& in) const
        -> query_result<subscription_record> {
        const auto arn = in.get("SubscriptionArn");
        if (!arn || !ctx._topic) {
            return invalid_parameter("SubscriptionArn");
        }
        if (!here(ctx)) {
            return subscription_not_found();
        }
        const auto parsed =
            service_detail::parse_subscription_suffix(arn->substr(arn->rfind(':') + 1));
        if (!parsed) {
            return invalid_parameter("SubscriptionArn");
        }
        const auto t = _store.find_topic(ctx._topic->_account, ctx._topic->_name);
        auto sub = _store.find_subscription(parsed->second);
        if (!t || !sub || sub->_topic_id != t->_id ||
            static_cast<std::uint32_t>(t->_id) != parsed->first) {
            return subscription_not_found();
        }
        return std::move(*sub);
    }

    /// Checks an endpoint against its protocol and the topic, as SNS does.
    [[nodiscard]] static auto check_endpoint(const topic_record& t, std::string_view protocol,
                                             std::string_view endpoint, const string_map& attrs)
        -> std::optional<sns_error> {
        if (t._fifo) {
            if (protocol != "sqs") {
                return invalid_parameter("Invalid protocol type: " + std::string(protocol));
            }
            if (!service_detail::ends_with(endpoint, ".fifo")) {
                return invalid_parameter("Endpoint", "Please use FIFO SQS queue");
            }
        }
        if (endpoint.empty()) {
            return invalid_parameter("Endpoint");
        }
        bool ok = true;
        if (protocol == "http") {
            ok = endpoint.starts_with("http://");
        } else if (protocol == "https") {
            ok = endpoint.starts_with("https://");
        } else if (protocol == "email" || protocol == "email-json") {
            const auto at = endpoint.find('@');
            ok = at != std::string_view::npos && at != 0 && at + 1 != endpoint.size();
        } else if (protocol == "sqs") {
            ok = !service_detail::arn_account(endpoint, "sqs").empty();
        } else if (protocol == "lambda") {
            ok = !service_detail::arn_account(endpoint, "lambda").empty();
        } else if (protocol == "firehose") {
            ok = !service_detail::arn_account(endpoint, "firehose").empty();
            if (ok && !attrs.contains("SubscriptionRoleArn")) {
                return invalid_parameter("Attributes",
                                         "SubscriptionRoleArn is required for firehose");
            }
        }
        if (!ok) {
            return invalid_parameter("Endpoint");
        }
        return std::nullopt;
    }

    /// Checks the filter policy a subscription's attributes would hold
    /// (task 5): its grammar in its scope, so a scope change that would
    /// strand a nested policy is refused too, and SNS's limit of filter
    /// policies per topic. `self` is the subscription being changed, 0 for
    /// a new one. An empty policy removes it, as on SNS.
    [[nodiscard]] auto check_filter_policy(const topic_record& t, const string_map& attrs,
                                           std::uint64_t self) const -> std::optional<sns_error> {
        const auto it = attrs.find("FilterPolicy");
        if (it == attrs.end() || it->second.empty()) {
            return std::nullopt;
        }
        const auto scope_it = attrs.find("FilterPolicyScope");
        const auto parsed = filter_policy::parse(
            it->second,
            parse_filter_scope(scope_it == attrs.end() ? std::string_view{} : scope_it->second));
        if (!parsed.has_value()) {
            return parsed.error();
        }
        std::size_t others = 0;
        for (const auto& s : _store.subscriptions_of(t._id)) {
            const auto f = s._attributes.find("FilterPolicy");
            if (s._id != self && f != s._attributes.end() && !f->second.empty()) {
                ++others;
            }
        }
        if (others >= k_max_filter_policies_per_topic) {
            return model_error("FilterPolicyLimitExceededException",
                               "Filter policy limit exceeded");
        }
        return std::nullopt;
    }

    /// Checks one subscription attribute's name and value for a protocol.
    [[nodiscard]] static auto check_subscription_attribute(std::string_view protocol,
                                                           std::string_view name,
                                                           std::string_view value)
        -> std::optional<sns_error> {
        if (!service_detail::known_subscription_attribute(name)) {
            return invalid_parameter("Attributes", "Unknown attribute " + std::string(name));
        }
        const auto bad = [name] {
            return invalid_parameter("Attributes", "Invalid value for " + std::string(name));
        };
        if (name == "RawMessageDelivery") {
            if (value != "true" && value != "false") {
                return bad();
            }
            if (protocol != "sqs" && protocol != "http" && protocol != "https" &&
                protocol != "firehose") {
                return invalid_parameter("Attributes", "Delivery protocol [" +
                                                           std::string(protocol) +
                                                           "] does not support raw message "
                                                           "delivery.");
            }
        } else if (name == "FilterPolicyScope") {
            if (value != "MessageAttributes" && value != "MessageBody") {
                return bad();
            }
        } else if (name == "DeliveryPolicy" || name == "ReplayPolicy") {
            if (!service_detail::is_json_object(value)) {
                return bad();
            }
        } else if (name == "RedrivePolicy") {
            boost::system::error_code ec;
            const auto v = boost::json::parse(value, ec);
            const auto* target =
                !ec && v.is_object() ? v.as_object().if_contains("deadLetterTargetArn") : nullptr;
            if (target == nullptr || !target->is_string() ||
                service_detail::arn_account(target->as_string(), "sqs").empty()) {
                return bad();
            }
        } else if (name == "SubscriptionRoleArn") {
            if (!value.starts_with("arn:") || value.find(":iam::") == std::string_view::npos) {
                return bad();
            }
        }
        return std::nullopt;
    }

    /// The id a list's `NextToken` was sealed over; 0 without a token.
    [[nodiscard]] auto open_id_token(const std::string& context, const params& in) const
        -> query_result<std::uint64_t> {
        const auto token = in.get("NextToken");
        if (!token || token->empty()) {
            return std::uint64_t{0};
        }
        const auto opened = _sealer.open(context, *token);
        if (!opened || opened->empty() ||
            !std::all_of(opened->begin(), opened->end(),
                         [](unsigned char c) { return std::isdigit(c) != 0; })) {
            return invalid_parameter("NextToken");
        }
        return std::stoull(*opened);
    }

    static auto write_subscription(aws_query::xml_writer& w, std::string_view topic_arn,
                                   const subscription_record& sub) -> void {
        w.open("member");
        w.element("SubscriptionArn",
                  sub._confirmed ? subscription_arn(topic_arn, sub) : std::string(k_pending_arn));
        w.element("Owner", sub._owner);
        w.element("Protocol", sub._protocol);
        w.element("Endpoint", sub._endpoint);
        w.element("TopicArn", topic_arn);
        w.close();
    }

    /// SNS's 20-digit sequence numbers: the log sequence, zero padded, so
    /// they sort as numbers and as strings within a message group.
    [[nodiscard]] static auto sequence_number(std::uint64_t seq) -> std::string {
        auto s = std::to_string(seq);
        return std::string(s.size() < 20 ? 20 - s.size() : 0, '0') + s;
    }

    /// Validates one Publish or PublishBatch entry as SNS does and builds it
    /// for the publish command; `bytes` gets the message's size as SNS
    /// counts it (the body, and each attribute's name, type and value).
    [[nodiscard]] auto prepare_entry(const call_context& ctx, const topic_record& t,
                                     const params& in, std::int64_t now, std::size_t& bytes) const
        -> query_result<publish_entry> {
        const auto message = in.get("Message");
        if (!message || message->empty()) {
            return invalid_parameter("Empty message");
        }
        published_message m;
        m._message = std::string(*message);
        m._timestamp_ms = now;
        m._publisher = ctx._principal.account;
        if (const auto subject = in.get("Subject")) {
            if (subject->empty() || subject->size() > 100 ||
                !std::all_of(subject->begin(), subject->end(),
                             [](unsigned char c) { return c >= 0x20 && c < 0x7F; })) {
                return invalid_parameter("Subject");
            }
            m._subject = std::string(*subject);
        }
        if (const auto structure = in.get("MessageStructure")) {
            if (*structure != "json") {
                return invalid_parameter("MessageStructure");
            }
            boost::system::error_code ec;
            const auto doc = boost::json::parse(*message, ec);
            if (ec || !doc.is_object()) {
                return invalid_parameter("Message Structure - JSON message body failed to parse");
            }
            const auto* def = doc.as_object().if_contains("default");
            if (def == nullptr || !def->is_string()) {
                return invalid_parameter(
                    "Message Structure - No default entry in JSON message body");
            }
            for (const auto& member : doc.as_object()) {
                if (!member.value().is_string()) {
                    return invalid_parameter(
                        "Message Structure - JSON message body failed to parse");
                }
            }
            m._json_structure = true;
        }
        auto attrs = in.message_attrs();
        if (!attrs.has_value()) {
            return attrs.error();
        }
        bytes = m._message.size();
        for (const auto& [name, a] : *attrs) {
            if (!service_detail::valid_attribute_name(name)) {
                return invalid_parameter_value("The message attribute name '" + name +
                                               "' is invalid.");
            }
            if (a._string_value && a._string_value->empty()) {
                return invalid_parameter_value("The message attribute '" + name +
                                               "' must contain non-empty message attribute "
                                               "value.");
            }
            if (a._data_type.starts_with("Number") &&
                !service_detail::valid_number(*a._string_value)) {
                return invalid_parameter_value("The message attribute '" + name +
                                               "' has an invalid numeric value.");
            }
            bytes += name.size() + a._data_type.size() + a._string_value.value_or("").size() +
                     a._binary_value.value_or("").size();
        }
        m._attributes = std::move(*attrs);
        if (bytes > limits(ctx).max_message_bytes(std::nullopt)) {
            return invalid_parameter("Message too long");
        }
        publish_entry e;
        const auto group = in.get("MessageGroupId");
        const auto dedup = in.get("MessageDeduplicationId");
        if (t._fifo) {
            if (!group) {
                return invalid_parameter(
                    "The MessageGroupId parameter is required for FIFO "
                    "topics");
            }
            if (!service_detail::valid_fifo_id(*group)) {
                return invalid_parameter("MessageGroupId");
            }
            if (dedup) {
                if (!service_detail::valid_fifo_id(*dedup)) {
                    return invalid_parameter("MessageDeduplicationId");
                }
                e._dedup_id = std::string(*dedup);
            } else if (const auto it = t._attributes.find("ContentBasedDeduplication");
                       it != t._attributes.end() && it->second == "true") {
                e._dedup_id = service_detail::sha256_hex(m._message);
            } else {
                return invalid_parameter(
                    "The topic should either have ContentBasedDeduplication "
                    "enabled or MessageDeduplicationId provided explicitly");
            }
            e._group_id = std::string(*group);
            e._partition =
                static_cast<std::uint32_t>(service_detail::fnv1a(*group) % t._partitions);
        } else {
            if (dedup) {
                return invalid_parameter("MessageDeduplicationId",
                                         "The request includes MessageDeduplicationId parameter "
                                         "that is not valid for this topic type");
            }
            if (t._partitions > 1) {
                std::array<unsigned char, 4> raw{};
                if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
                    throw std::runtime_error("sns: RAND_bytes failed");
                }
                const std::uint32_t r = (std::uint32_t{raw[0]} << 24U) |
                                        (std::uint32_t{raw[1]} << 16U) |
                                        (std::uint32_t{raw[2]} << 8U) | std::uint32_t{raw[3]};
                e._partition = r % t._partitions;
            }
        }
        e._message_id = service_detail::random_uuid();
        e._payload = encode_published_message(m);
        return e;
    }

    /// `<name><entry><key>k</key><value>v</value></entry>...</name>`.
    static auto write_map(aws_query::xml_writer& w, std::string_view name, const string_map& m)
        -> void {
        w.open(name);
        for (const auto& [k, v] : m) {
            w.open("entry").element("key", k).element("value", v).close();
        }
        w.close();
    }

    topic_store& _store;
    service_config _config;
    aws_query::marker_sealer _sealer;
};

}  // namespace kythira::sns
