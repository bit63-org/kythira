// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_channel_role.hpp
/// @brief Assuming a channel's service execution role
///        (`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement 18).
///
/// AWS writes a channel's objects as the channel's `ServiceExecutionRoleARN`,
/// not as the service itself, so a bucket policy or a table bucket's grants
/// decide what a channel may touch. A Kythira node does the same when
/// `KINESIS_CHANNEL_ROLE=assume`: before it writes for a channel, it calls
/// STS `AssumeRole` on the role with its own credentials and writes with the
/// temporary credentials it gets back.
///
/// `channel_role_credentials` keeps one set per role and session name and
/// asks STS again once a set is within `_refresh_before_ms` of expiring. A
/// refusal is remembered for `_retry_after_ms`, so a channel whose role does
/// not trust the node costs one STS call per interval, not one per shard per
/// pass; the error names the role and STS's code, and the delivery worker
/// records it as the shard's failure until the role is fixed.
///
/// The STS call is the query protocol's `AssumeRole`, signed with SigV4
/// (`kinesis_aws_call.hpp`), so it needs no AWS SDK component and works
/// against AWS's STS and Kythira's own IAM service alike.

#include <kythira/kinesis/kinesis_aws_call.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kinesis {

/// STS refused, or did not answer, an `AssumeRole`.
class channel_role_error : public std::runtime_error {
public:
    channel_role_error(std::string code, const std::string& message)
        : std::runtime_error(message), _code(std::move(code)) {}
    [[nodiscard]] auto code() const -> const std::string& { return _code; }

private:
    std::string _code;
};

struct sts_config {
    std::string _region;
    /// STS's URL; empty is `https://sts.<region>.amazonaws.com`.
    std::string _endpoint;
    /// The node's own credentials, which sign the call.
    std::function<sigv4_credentials()> _credentials;
    /// The signing clock; the system clock when empty.
    std::function<std::chrono::sys_seconds()> _clock;
    /// `DurationSeconds` asked for: 900 to the role's maximum.
    int _duration_seconds = 3600;
};

class sts_client {
public:
    sts_client(sts_config config, aws_transport transport)
        : _config(std::move(config)), _transport(std::move(transport)) {
        const auto url = _config._endpoint.empty()
                             ? "https://sts." + _config._region + ".amazonaws.com"
                             : _config._endpoint;
        auto e = parse_aws_endpoint(url);
        if (!e) {
            throw std::invalid_argument("STS endpoint is not an http(s) URL: " + url);
        }
        _endpoint = std::move(*e);
    }

    /// `AssumeRole` on `role_arn` as `session_name`; throws
    /// `channel_role_error`.
    [[nodiscard]] auto assume_role(std::string_view role_arn, std::string_view session_name) const
        -> sigv4_credentials {
        const auto creds = _config._credentials ? _config._credentials() : sigv4_credentials{};
        if (creds.empty()) {
            throw channel_role_error(
                "MissingAuthenticationToken",
                "No credentials to call sts:AssumeRole on " + std::string(role_arn) + " with.");
        }
        aws_request req;
        req._method = boost::beast::http::verb::post;
        req._path = _endpoint._base_path.empty() ? "/" : _endpoint._base_path + "/";
        req._headers.emplace_back("Content-Type",
                                  "application/x-www-form-urlencoded; charset=utf-8");
        req._body = "Action=AssumeRole&Version=2011-06-15&RoleArn=" + aws_form_encode(role_arn) +
                    "&RoleSessionName=" + aws_form_encode(session_name) +
                    "&DurationSeconds=" + std::to_string(_config._duration_seconds);
        const auto now =
            _config._clock
                ? _config._clock()
                : std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        sign_aws_request(req, _endpoint, creds, _config._region, "sts", now);
        const auto res = _transport(_endpoint, req);
        if (!res) {
            throw channel_role_error("ServiceUnavailable", "STS did not answer sts:AssumeRole on " +
                                                               std::string(role_arn) + ".");
        }
        if (res->_status != 200) {
            const auto code =
                xml_text(res->_body, "Code").value_or("HTTP" + std::to_string(res->_status));
            const auto message = xml_text(res->_body, "Message").value_or("");
            throw channel_role_error(code, "sts:AssumeRole on " + std::string(role_arn) +
                                               " was refused: " + code +
                                               (message.empty() ? "" : " (" + message + ")"));
        }
        const auto at = res->_body.find("<Credentials>");
        sigv4_credentials out;
        if (at != std::string::npos) {
            out._access_key_id = xml_text(res->_body, "AccessKeyId", at).value_or("");
            out._secret_access_key = xml_text(res->_body, "SecretAccessKey", at).value_or("");
            out._session_token = xml_text(res->_body, "SessionToken", at).value_or("");
            out._expires_ms =
                parse_iso8601_ms(xml_text(res->_body, "Expiration", at).value_or("")).value_or(0);
        }
        if (out.empty() || out._session_token.empty() || out._expires_ms == 0) {
            throw channel_role_error("InvalidResponse", "STS answered sts:AssumeRole on " +
                                                            std::string(role_arn) +
                                                            " without credentials.");
        }
        return out;
    }

private:
    sts_config _config;
    aws_transport _transport;
    aws_endpoint _endpoint;
};

/// The session name a channel's writes carry: `kythira-channel-<ChannelId>`,
/// so CloudTrail and bucket logs name the channel.
[[nodiscard]] inline auto channel_role_session(std::string_view channel_id) -> std::string {
    return "kythira-channel-" + std::string(channel_id);
}

struct channel_role_cache_config {
    /// Ask again once a set has less than this left.
    std::int64_t _refresh_before_ms = std::int64_t{5} * 60 * 1000;
    /// After a refusal, answer with it for this long before asking again.
    std::int64_t _retry_after_ms = std::int64_t{30} * 1000;
    /// Milliseconds since the epoch; the system clock when empty.
    std::function<std::int64_t()> _now_ms;
};

/// Temporary credentials per (role, session), refreshed before they expire.
/// Thread-safe; one STS call at a time.
class channel_role_credentials {
public:
    using assume_fn =
        std::function<sigv4_credentials(std::string_view role, std::string_view session)>;

    channel_role_credentials(assume_fn assume, channel_role_cache_config config = {})
        : _assume(std::move(assume)), _config(std::move(config)) {}

    /// The role's credentials; throws `channel_role_error` with STS's
    /// refusal (remembered for `_retry_after_ms`).
    [[nodiscard]] auto get(const std::string& role, const std::string& session)
        -> sigv4_credentials {
        const std::lock_guard lock(_mutex);
        const auto now = now_ms();
        auto& e = _entries[{role, session}];
        if (!e._creds.empty() && e._creds._expires_ms - _config._refresh_before_ms > now) {
            return e._creds;
        }
        if (e._error && e._failed_at + _config._retry_after_ms > now) {
            if (!e._creds.empty() && e._creds._expires_ms > now) {
                return e._creds;
            }
            throw *e._error;
        }
        try {
            e._creds = _assume(role, session);
            e._error.reset();
            ++_calls;
            return e._creds;
        } catch (const channel_role_error& err) {
            ++_calls;
            e._error = err;
            e._failed_at = now;
            // Credentials that have not expired yet still work while STS
            // refuses a refresh (a throttle, a brief outage).
            if (!e._creds.empty() && e._creds._expires_ms > now) {
                return e._creds;
            }
            throw;
        }
    }

    /// STS calls made, for tests and metrics.
    [[nodiscard]] auto calls() const -> std::uint64_t {
        const std::lock_guard lock(_mutex);
        return _calls;
    }

private:
    struct entry {
        sigv4_credentials _creds;
        std::optional<channel_role_error> _error;
        std::int64_t _failed_at = 0;
    };

    assume_fn _assume;
    channel_role_cache_config _config;
    mutable std::mutex _mutex;
    std::map<std::pair<std::string, std::string>, entry> _entries;
    std::uint64_t _calls = 0;

    [[nodiscard]] auto now_ms() const -> std::int64_t {
        if (_config._now_ms) {
            return _config._now_ms();
        }
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }
};

}  // namespace kythira::kinesis
