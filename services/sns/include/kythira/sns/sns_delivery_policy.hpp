// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_delivery_policy.hpp
/// @brief When a failed delivery is tried again
///        (`.kiro/specs/sns-compatible-notifications/` task 6, Requirement
///        6.4).
///
/// SNS retries a failed delivery in four phases, then gives up (and sends
/// the message to the subscription's dead-letter queue, if it has one):
///
/// 1. immediate: `numNoDelayRetries` retries with no delay;
/// 2. pre-backoff: `numMinDelayRetries` retries `minDelayTarget` apart;
/// 3. backoff: the remaining retries, spaced from `minDelayTarget` up to
///    `maxDelayTarget` by `backoffFunction`;
/// 4. post-backoff: `numMaxDelayRetries` retries `maxDelayTarget` apart.
///
/// `numRetries` counts every retry, so a message is tried at most
/// `numRetries + 1` times. HTTP and HTTPS subscriptions take the policy
/// from the subscription's `DeliveryPolicy`, else the topic's `http`
/// defaults, else SNS's default (3 retries 20 seconds apart). SNS's
/// policies for the endpoints it manages (SQS, Lambda, Firehose) and for
/// SMTP are fixed, as its documentation tabulates.
///
/// The backoff curves follow the shapes SNS's console draws; SNS does not
/// publish exact formulas, so these are approximations with the right end
/// points: `linear` is evenly spaced, `arithmetic` grows by an evenly
/// growing step, `geometric` doubles toward the top, and `exponential` is
/// even on a log scale.

#include <boost/json.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::sns {

enum class backoff_function : std::uint8_t {
    linear,
    arithmetic,
    geometric,
    exponential
};

struct retry_policy {
    std::int64_t _min_delay_s = 20;
    std::int64_t _max_delay_s = 20;
    std::uint32_t _num_retries = 3;
    std::uint32_t _num_no_delay_retries = 0;
    std::uint32_t _num_min_delay_retries = 0;
    std::uint32_t _num_max_delay_retries = 0;
    backoff_function _backoff = backoff_function::linear;

    friend auto operator==(const retry_policy&, const retry_policy&) -> bool = default;

    /// The delay before retry `n` (1-based) in milliseconds, or nothing
    /// once the retries are spent.
    [[nodiscard]] auto delay_before_retry(std::uint32_t n) const -> std::optional<std::int64_t> {
        if (n == 0 || n > _num_retries) {
            return std::nullopt;
        }
        constexpr std::int64_t ms = 1000;
        if (n <= _num_no_delay_retries) {
            return 0;
        }
        n -= _num_no_delay_retries;
        if (n <= _num_min_delay_retries) {
            return _min_delay_s * ms;
        }
        n -= _num_min_delay_retries;
        const auto shaped = backoff_retries();
        if (n <= shaped) {
            return static_cast<std::int64_t>(std::llround(backoff_delay_s(n, shaped) * ms));
        }
        return _max_delay_s * ms;
    }

    /// Retries in the backoff phase.
    [[nodiscard]] auto backoff_retries() const -> std::uint32_t {
        const auto fixed =
            std::uint64_t{_num_no_delay_retries} + _num_min_delay_retries + _num_max_delay_retries;
        return fixed >= _num_retries ? 0 : static_cast<std::uint32_t>(_num_retries - fixed);
    }

private:
    [[nodiscard]] auto backoff_delay_s(std::uint32_t i, std::uint32_t n) const -> double {
        const auto lo = static_cast<double>(_min_delay_s);
        const auto hi = static_cast<double>(_max_delay_s);
        if (n == 1 || hi <= lo) {
            return n == 1 ? hi : lo;
        }
        const double x = static_cast<double>(i - 1) / static_cast<double>(n - 1);  // 0 .. 1
        switch (_backoff) {
            case backoff_function::linear:
                return lo + (hi - lo) * x;
            case backoff_function::arithmetic:
                return lo + (hi - lo) * x * x;
            case backoff_function::geometric: {
                const auto k = static_cast<double>(n - 1);
                return lo + (hi - lo) * (std::exp2(x * k) - 1) / (std::exp2(k) - 1);
            }
            case backoff_function::exponential:
                return lo * std::pow(hi / lo, x);
        }
        return hi;
    }
};

/// SNS's default for HTTP and HTTPS: three retries, 20 seconds apart.
[[nodiscard]] inline auto default_http_retry_policy() -> retry_policy {
    return {};
}

/// SNS's fixed policy for the endpoints it manages (SQS, Lambda, Firehose):
/// 3 immediate, 2 at 1 second, 10 backing off to 20 seconds, then 100,000
/// at 20 seconds, about 23 days in all.
[[nodiscard]] inline auto managed_endpoint_retry_policy() -> retry_policy {
    return {1, 20, 3 + 2 + 10 + 100'000, 3, 2, 100'000, backoff_function::exponential};
}

/// SNS's fixed policy for email (SMTP): 10 at 10 seconds, 38 backing off
/// to 600 seconds, then 2 at 600 seconds, 50 retries over several hours.
[[nodiscard]] inline auto smtp_retry_policy() -> retry_policy {
    return {10, 600, 10 + 38 + 2, 0, 10, 2, backoff_function::exponential};
}

/// The parts of a `DeliveryPolicy` delivery needs.
struct delivery_policy {
    retry_policy _retry{};
    /// `throttlePolicy.maxReceivesPerSecond`; 0 for no limit.
    std::uint32_t _max_receives_per_second = 0;
    /// `requestPolicy.headerContentType`; empty for SNS's default.
    std::string _content_type{};

    friend auto operator==(const delivery_policy&, const delivery_policy&) -> bool = default;
};

namespace delivery_policy_detail {

[[nodiscard]] inline auto uint_member(const boost::json::object& o, std::string_view name,
                                      std::int64_t lo, std::int64_t hi,
                                      std::optional<std::int64_t>& out) -> bool {
    const auto* v = o.if_contains(name);
    if (v == nullptr) {
        return true;
    }
    std::int64_t n = 0;
    if (v->is_int64()) {
        n = v->get_int64();
    } else if (v->is_uint64() && v->get_uint64() <= static_cast<std::uint64_t>(hi)) {
        n = static_cast<std::int64_t>(v->get_uint64());
    } else {
        return false;
    }
    if (n < lo || n > hi) {
        return false;
    }
    out = n;
    return true;
}

[[nodiscard]] inline auto read_retry(const boost::json::object& o, retry_policy& r) -> bool {
    std::optional<std::int64_t> min, max, retries, no_delay, min_delay, max_delay;
    if (!uint_member(o, "minDelayTarget", 1, 3600, min) ||
        !uint_member(o, "maxDelayTarget", 1, 3600, max) ||
        !uint_member(o, "numRetries", 0, 100, retries) ||
        !uint_member(o, "numNoDelayRetries", 0, 100, no_delay) ||
        !uint_member(o, "numMinDelayRetries", 0, 100, min_delay) ||
        !uint_member(o, "numMaxDelayRetries", 0, 100, max_delay)) {
        return false;
    }
    r._min_delay_s = min.value_or(r._min_delay_s);
    r._max_delay_s = max.value_or(r._max_delay_s);
    r._num_retries = static_cast<std::uint32_t>(retries.value_or(r._num_retries));
    r._num_no_delay_retries = static_cast<std::uint32_t>(no_delay.value_or(0));
    r._num_min_delay_retries = static_cast<std::uint32_t>(min_delay.value_or(0));
    r._num_max_delay_retries = static_cast<std::uint32_t>(max_delay.value_or(0));
    if (r._min_delay_s > r._max_delay_s || std::uint64_t{r._num_no_delay_retries} +
                                                   r._num_min_delay_retries +
                                                   r._num_max_delay_retries >
                                               r._num_retries) {
        return false;
    }
    if (const auto* f = o.if_contains("backoffFunction")) {
        if (!f->is_string()) {
            return false;
        }
        const std::string_view name = f->get_string();
        if (name == "linear") {
            r._backoff = backoff_function::linear;
        } else if (name == "arithmetic") {
            r._backoff = backoff_function::arithmetic;
        } else if (name == "geometric") {
            r._backoff = backoff_function::geometric;
        } else if (name == "exponential") {
            r._backoff = backoff_function::exponential;
        } else {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline auto read_parts(const boost::json::object& o, std::string_view retry_key,
                                     std::string_view throttle_key, std::string_view request_key,
                                     delivery_policy& p) -> bool {
    if (const auto* r = o.if_contains(retry_key)) {
        if (!r->is_object() || !read_retry(r->get_object(), p._retry)) {
            return false;
        }
    }
    if (const auto* t = o.if_contains(throttle_key)) {
        std::optional<std::int64_t> n;
        if (!t->is_object() ||
            !uint_member(t->get_object(), "maxReceivesPerSecond", 1, 1'000'000, n)) {
            return false;
        }
        p._max_receives_per_second = static_cast<std::uint32_t>(n.value_or(0));
    }
    if (const auto* q = o.if_contains(request_key)) {
        if (!q->is_object()) {
            return false;
        }
        if (const auto* c = q->get_object().if_contains("headerContentType")) {
            if (!c->is_string()) {
                return false;
            }
            p._content_type = std::string(c->get_string());
        }
    }
    return true;
}

}  // namespace delivery_policy_detail

/// Lays a subscription `DeliveryPolicy` over `base`: each part it names
/// replaces that part. False, leaving `base` as it was, when it is not
/// valid.
[[nodiscard]] inline auto apply_subscription_delivery_policy(std::string_view text,
                                                             delivery_policy& base) -> bool {
    boost::system::error_code ec;
    const auto v = boost::json::parse(text, ec);
    if (ec || !v.is_object()) {
        return false;
    }
    auto p = base;
    if (!delivery_policy_detail::read_parts(v.get_object(), "healthyRetryPolicy", "throttlePolicy",
                                            "requestPolicy", p)) {
        return false;
    }
    base = std::move(p);
    return true;
}

/// A subscription `DeliveryPolicy` over SNS's default, if it is valid.
[[nodiscard]] inline auto parse_subscription_delivery_policy(std::string_view text)
    -> std::optional<delivery_policy> {
    delivery_policy p;
    return apply_subscription_delivery_policy(text, p) ? std::optional(std::move(p)) : std::nullopt;
}

/// The `http` defaults of a topic `DeliveryPolicy`, and whether they
/// forbid subscription overrides.
struct topic_delivery_policy {
    delivery_policy _defaults{};
    bool _disable_subscription_overrides = false;
};

[[nodiscard]] inline auto parse_topic_delivery_policy(std::string_view text)
    -> std::optional<topic_delivery_policy> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(text, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    topic_delivery_policy t;
    const auto* http = v.get_object().if_contains("http");
    if (http == nullptr) {
        return t;
    }
    if (!http->is_object()) {
        return std::nullopt;
    }
    const auto& o = http->get_object();
    if (!delivery_policy_detail::read_parts(o, "defaultHealthyRetryPolicy", "defaultThrottlePolicy",
                                            "defaultRequestPolicy", t._defaults)) {
        return std::nullopt;
    }
    if (const auto* d = o.if_contains("disableSubscriptionOverrides")) {
        if (!d->is_bool()) {
            return std::nullopt;
        }
        t._disable_subscription_overrides = d->get_bool();
    }
    return t;
}

/// The policy one subscription's deliveries follow: fixed for the
/// protocols SNS manages, else the subscription's own policy over the
/// topic's defaults (unless the topic forbids overrides) over SNS's
/// default. Policies that do not parse are ignored; the API refuses them
/// when they are set.
[[nodiscard]] inline auto effective_delivery_policy(std::string_view protocol,
                                                    std::string_view topic_policy,
                                                    std::string_view subscription_policy)
    -> delivery_policy {
    if (protocol == "sqs" || protocol == "lambda" || protocol == "firehose") {
        return {managed_endpoint_retry_policy(), 0, {}};
    }
    if (protocol == "email" || protocol == "email-json") {
        return {smtp_retry_policy(), 0, {}};
    }
    delivery_policy p;
    bool overrides = true;
    if (!topic_policy.empty()) {
        if (auto t = parse_topic_delivery_policy(topic_policy)) {
            p = t->_defaults;
            overrides = !t->_disable_subscription_overrides;
        }
    }
    if (overrides && !subscription_policy.empty()) {
        static_cast<void>(apply_subscription_delivery_policy(subscription_policy, p));
    }
    return p;
}

}  // namespace kythira::sns
