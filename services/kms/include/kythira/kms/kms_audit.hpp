// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS's audit records and request metrics
// (.kiro/specs/kms-compatible-api/ task 14, Requirements 13.1 and 13.2).
//
// Every request the front end answers becomes one JSON line in the shape
// CloudTrail records KMS events (eventSource kms.amazonaws.com, the
// userIdentity, requestParameters, resources and so on), queued on the
// same bounded audit log IAM's authorizer and the virtual HSM write
// through (raft/audit_log.hpp). Where CloudTrail would log encryption
// context values, the record lists only the context's keys: a value may
// be a secret the caller bound to the ciphertext. No key material ever
// reaches a request record, so none can reach a line or a metric.

#include <kythira/kms/kms_front_end.hpp>

#include <raft/audit_log.hpp>
#include <raft/service_module.hpp>

#include <boost/json.hpp>

#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace kythira::kms {

namespace audit_detail {

/// ISO 8601 in UTC to the second, as CloudTrail writes eventTime.
[[nodiscard]] inline auto iso_time(std::chrono::system_clock::time_point t) -> std::string {
    const auto secs = std::chrono::system_clock::to_time_t(t);
    std::tm tm{};
    gmtime_r(&secs, &tm);
    std::array<char, 32> out{};
    (void)std::strftime(out.data(), out.size(), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return out.data();
}

[[nodiscard]] inline auto event_id() -> std::string {
    std::array<unsigned char, 16> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) {
        return "00000000-0000-4000-8000-000000000000";
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0FU) | 0x40U);
    b[8] = static_cast<unsigned char>((b[8] & 0x3FU) | 0x80U);
    std::array<char, 37> out{};
    std::snprintf(out.data(), out.size(),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0],
                  b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
                  b[14], b[15]);
    return out.data();
}

/// The account part of a KMS key ARN.
[[nodiscard]] inline auto arn_account(std::string_view arn) -> std::string {
    const auto parts = parse_kms_arn(arn);
    return parts ? std::string(parts->account) : std::string();
}

}  // namespace audit_detail

/// `r` as one CloudTrail-shaped JSON line (no trailing newline).
[[nodiscard]] inline auto cloudtrail_line(const request_record& r, std::string_view region)
    -> std::string {
    namespace json = boost::json;
    json::object ev;
    ev["eventVersion"] = "1.08";
    if (r.principal) {
        const auto& p = *r.principal;
        json::object who{
            {"type", std::string(aws_auth::to_string(p.type))},
            {"principalId", p.userid},
            {"arn", p.arn},
            {"accountId", p.account},
        };
        if (!r.access_key_id.empty()) {
            who["accessKeyId"] = r.access_key_id;
        }
        if (!p.role_arn.empty()) {
            who["sessionContext"] =
                json::object{{"sessionIssuer", json::object{{"type", "Role"},
                                                            {"arn", p.role_arn},
                                                            {"userName", p.role_name},
                                                            {"accountId", p.account}}}};
        }
        if (!r.via_service.empty()) {
            who["invokedBy"] = r.via_service + ".amazonaws.com";
        }
        ev["userIdentity"] = std::move(who);
    } else if (!r.access_key_id.empty()) {
        ev["userIdentity"] = json::object{{"accessKeyId", r.access_key_id}};
    }
    ev["eventTime"] = audit_detail::iso_time(r.time);
    ev["eventSource"] = "kms.amazonaws.com";
    ev["eventName"] = r.operation;
    ev["awsRegion"] = std::string(region);
    // CloudTrail names the service, not an address, for a call a service
    // made for its caller.
    ev["sourceIPAddress"] = r.via_service.empty() ? r.source_ip : r.via_service + ".amazonaws.com";
    ev["userAgent"] = r.via_service.empty() ? r.user_agent : r.via_service + ".amazonaws.com";
    if (!r.error_type.empty()) {
        ev["errorCode"] = r.error_type;
        ev["errorMessage"] = r.error_message;
    }
    json::object params;
    if (!r.key_arn.empty()) {
        params["keyId"] = r.key_arn;
    }
    if (!r.context_keys.empty()) {
        json::array keys;
        for (const auto& k : r.context_keys) {
            keys.emplace_back(k);
        }
        params["encryptionContextKeys"] = std::move(keys);
    }
    ev["requestParameters"] = params.empty() ? json::value(nullptr) : json::value(params);
    ev["responseElements"] = nullptr;
    if (!r.grant_id.empty()) {
        ev["additionalEventData"] = json::object{{"grantId", r.grant_id}};
    }
    ev["requestID"] = r.request_id;
    ev["eventID"] = audit_detail::event_id();
    ev["readOnly"] = r.read_only;
    if (!r.key_arn.empty()) {
        ev["resources"] =
            json::array{json::object{{"accountId", audit_detail::arn_account(r.key_arn)},
                                     {"type", "AWS::KMS::Key"},
                                     {"ARN", r.key_arn}}};
    }
    ev["eventType"] = "AwsApiCall";
    ev["managementEvent"] = true;
    const auto key_account = audit_detail::arn_account(r.key_arn);
    ev["recipientAccountId"] =
        !key_account.empty() ? key_account : (r.principal ? r.principal->account : std::string());
    ev["eventCategory"] = "Management";
    return json::serialize(ev);
}

/// Requests by operation, outcome and account, and their latency by
/// operation, as module metrics (the node prefixes them kms_).
class request_metrics {
public:
    void record(const request_record& r) {
        const std::scoped_lock lock(_mu);
        const auto account = r.principal ? r.principal->account : std::string("unknown");
        ++_requests[{r.operation.empty() ? std::string("unknown") : r.operation,
                     r.error_type.empty() ? std::string("ok") : r.error_type, account}];
        auto& l = _latency[r.operation];
        ++l.first;
        l.second += static_cast<std::uint64_t>(r.duration.count());
    }

    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> {
        std::vector<service_node::module_metric> out;
        const std::scoped_lock lock(_mu);
        for (const auto& [k, n] : _requests) {
            const auto& [op, outcome, account] = k;
            out.push_back({"api_requests",
                           static_cast<double>(n),
                           {{"operation", op}, {"outcome", outcome}, {"account", account}}});
        }
        for (const auto& [op, l] : _latency) {
            out.push_back(
                {"api_latency_seconds_count", static_cast<double>(l.first), {{"operation", op}}});
            out.push_back({"api_latency_seconds_sum",
                           static_cast<double>(l.second) / 1e6,
                           {{"operation", op}}});
        }
        return out;
    }

private:
    mutable std::mutex _mu;
    std::map<std::tuple<std::string, std::string, std::string>, std::uint64_t> _requests;
    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> _latency;
};

/// Where the module's request records go (KYTHIRA_KMS_AUDIT): "stderr",
/// "off" or "file:<path>", queued on a bounded audit log so a request
/// never waits for the sink. Every request is counted in the metrics,
/// whether or not its line is written.
class request_audit {
public:
    request_audit(const std::string& where, std::string region) : _region(std::move(region)) {
        if (where.starts_with("file:")) {
            const auto path = where.substr(5);
            _file.open(path, std::ios::app);
            if (!_file) {
                throw std::runtime_error("KYTHIRA_KMS_AUDIT: cannot append to " + path);
            }
        } else if (where != "stderr" && where != "off") {
            throw std::invalid_argument("KYTHIRA_KMS_AUDIT must be stderr, off or file:<path>");
        }
        _to_stderr = where == "stderr";
        if (_to_stderr || _file.is_open()) {
            _log = std::make_unique<kythira::audit_log>(
                kythira::audit_log::batch_sink(
                    [this](std::span<const std::string> lines) { write(lines); }),
                8192);
        }
    }

    request_audit(const request_audit&) = delete;
    auto operator=(const request_audit&) -> request_audit& = delete;
    request_audit(request_audit&&) = delete;
    auto operator=(request_audit&&) -> request_audit& = delete;
    ~request_audit() { _log.reset(); }  // drains the queue while the sinks exist

    void record(const request_record& r) {
        _metrics.record(r);
        if (_log) {
            _log->post(cloudtrail_line(r, _region));
        }
    }

    /// Blocks until every queued line was written (tests, shutdown).
    void flush() {
        if (_log) {
            _log->flush();
        }
    }

    [[nodiscard]] auto dropped() const -> std::uint64_t { return _log ? _log->dropped() : 0; }

    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> {
        auto out = _metrics.metrics();
        out.push_back({"audit_dropped", static_cast<double>(dropped()), {}});
        return out;
    }

private:
    void write(std::span<const std::string> lines) {
        for (const auto& line : lines) {
            if (_file.is_open()) {
                _file << line << '\n';
            }
            if (_to_stderr) {
                std::cerr << line << '\n';
            }
        }
        if (_file.is_open()) {
            _file.flush();
        }
        if (_to_stderr) {
            std::cerr.flush();
        }
    }

    std::string _region;
    bool _to_stderr = false;
    std::ofstream _file;
    request_metrics _metrics;
    std::unique_ptr<kythira::audit_log> _log;
};

}  // namespace kythira::kms
