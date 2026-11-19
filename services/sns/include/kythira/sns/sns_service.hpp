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
#include <kythira/sns/sns_front_end.hpp>
#include <kythira/sns/sns_query.hpp>
#include <kythira/sns/sns_topic_policy.hpp>
#include <kythira/sns/sns_topic_state_machine.hpp>

#include <raft/aws_query_protocol.hpp>

#include <boost/json.hpp>

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

    [[nodiscard]] auto machine() const -> const topic_state_machine<LogIndex>& { return _sm; }

private:
    topic_state_machine<LogIndex> _sm;
    LogIndex _index{0};
};

// ---- attributes -----------------------------------------------------------

/// The page size of ListTopics, as on SNS.
inline constexpr std::size_t k_list_topics_page = 100;
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
