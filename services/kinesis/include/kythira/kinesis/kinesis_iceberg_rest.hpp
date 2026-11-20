// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_iceberg_rest.hpp
/// @brief The two Iceberg REST catalog calls a channel append makes
///        (`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement
///        18.3): load a table, commit a snapshot.
///
/// S3 Tables serves the Iceberg REST catalog at
/// `https://s3tables.<region>.amazonaws.com/iceberg`, with the table
/// bucket's ARN as the warehouse and SigV4 under the signing name
/// `s3tables`. A local catalog (Apache Iceberg's REST fixture, Polaris,
/// Nessie, Lakekeeper) answers the same calls without SigV4, optionally
/// with a bearer token. Either way the client first asks `GET /v1/config`
/// for the warehouse's path prefix, once per client, then:
///
/// - `GET  /v1/{prefix}/namespaces/{ns}/tables/{table}`
/// - `POST /v1/{prefix}/namespaces/{ns}/tables/{table}` (CommitTableRequest)
///
/// Answers are handed back whole; the delivery worker reads 200, 404 and
/// 409 (CommitFailedException: another writer committed first).

#include <kythira/kinesis/kinesis_aws_call.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kinesis {

struct iceberg_rest_config {
    /// The catalog's base URL, e.g.
    /// `https://s3tables.us-east-1.amazonaws.com/iceberg` or
    /// `http://iceberg-rest:8181`.
    std::string _uri;
    /// The `warehouse` asked for in `/v1/config` (S3 Tables: the table
    /// bucket ARN); empty asks without one.
    std::string _warehouse;
    /// Sign with SigV4 as `_signing_name` in `_region`.
    bool _sigv4 = false;
    std::string _region;
    std::string _signing_name = "s3tables";
    std::function<sigv4_credentials()> _credentials;
    /// `Authorization: Bearer <token>` when set and not signing.
    std::string _token;
    std::function<std::chrono::sys_seconds()> _clock;
};

class iceberg_rest_client {
public:
    iceberg_rest_client(iceberg_rest_config config, aws_transport transport)
        : _config(std::move(config)), _transport(std::move(transport)) {
        auto e = parse_aws_endpoint(_config._uri);
        if (!e) {
            throw std::invalid_argument("Iceberg REST catalog URI is not an http(s) URL: " +
                                        _config._uri);
        }
        _endpoint = std::move(*e);
    }

    [[nodiscard]] auto load_table(std::string_view ns, std::string_view table)
        -> std::optional<peer_response> {
        const auto p = table_path(ns, table);
        if (!p) {
            return std::nullopt;
        }
        return call(boost::beast::http::verb::get, *p, {}, {});
    }

    [[nodiscard]] auto commit(std::string_view ns, std::string_view table, std::string body)
        -> std::optional<peer_response> {
        const auto p = table_path(ns, table);
        if (!p) {
            return std::nullopt;
        }
        return call(boost::beast::http::verb::post, *p, {}, std::move(body));
    }

    /// The path prefix the catalog named for the warehouse ("" for none),
    /// or nullopt when `/v1/config` did not answer.
    [[nodiscard]] auto prefix() -> std::optional<std::string> {
        {
            const std::lock_guard lock(_mutex);
            if (_prefix) {
                return _prefix;
            }
        }
        const auto res =
            call(boost::beast::http::verb::get, "/v1/config",
                 _config._warehouse.empty() ? std::string()
                                            : "warehouse=" + aws_form_encode(_config._warehouse),
                 {});
        if (!res || res->_status != 200) {
            return std::nullopt;
        }
        std::string prefix;
        try {
            const auto v = boost::json::parse(res->_body);
            for (const auto* section : {"defaults", "overrides"}) {
                const auto* s = v.as_object().if_contains(section);
                if (s != nullptr && s->is_object()) {
                    if (const auto* p = s->as_object().if_contains("prefix");
                        p != nullptr && p->is_string()) {
                        prefix = std::string(p->as_string());
                    }
                }
            }
        } catch (const std::exception&) {
            return std::nullopt;
        }
        // An ARN (S3 Tables) is one path segment: its ':' and '/' are
        // escaped. Anything else is used as the catalog wrote it.
        if (prefix.starts_with("arn:")) {
            prefix = aws_form_encode(prefix);
        }
        const std::lock_guard lock(_mutex);
        _prefix = prefix;
        return _prefix;
    }

private:
    iceberg_rest_config _config;
    aws_transport _transport;
    aws_endpoint _endpoint;
    std::mutex _mutex;
    std::optional<std::string> _prefix;

    [[nodiscard]] auto table_path(std::string_view ns, std::string_view table)
        -> std::optional<std::string> {
        const auto p = prefix();
        if (!p) {
            return std::nullopt;
        }
        return "/v1/" + (p->empty() ? std::string() : *p + "/") + "namespaces/" +
               aws_form_encode(ns) + "/tables/" + aws_form_encode(table);
    }

    [[nodiscard]] auto call(boost::beast::http::verb method, std::string_view path,
                            std::string query, std::string body) -> std::optional<peer_response> {
        aws_request req;
        req._method = method;
        req._path = _endpoint._base_path + std::string(path);
        req._query = std::move(query);
        req._body = std::move(body);
        req._headers.emplace_back("Accept", "application/json");
        if (method == boost::beast::http::verb::post) {
            req._headers.emplace_back("Content-Type", "application/json");
        }
        if (_config._sigv4) {
            const auto creds = _config._credentials ? _config._credentials() : sigv4_credentials{};
            if (creds.empty()) {
                return peer_response{
                    ._status = 401,
                    ._body =
                        R"({"error":{"message":"No AWS credentials to sign the Iceberg REST call with."}})"};
            }
            const auto now =
                _config._clock
                    ? _config._clock()
                    : std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
            sign_aws_request(req, _endpoint, creds, _config._region, _config._signing_name, now);
        } else {
            req._headers.emplace_back("Host", _endpoint._host);
            if (!_config._token.empty()) {
                req._headers.emplace_back("Authorization", "Bearer " + _config._token);
            }
        }
        return _transport(_endpoint, req);
    }
};

/// The message of an Iceberg REST `ErrorModel` answer, or the start of the
/// body when it is not one.
[[nodiscard]] inline auto iceberg_error_message(const peer_response& r) -> std::string {
    try {
        const auto v = boost::json::parse(r._body);
        const auto& e = v.as_object().at("error").as_object();
        std::string out(e.at("message").as_string());
        if (const auto* t = e.if_contains("type"); t != nullptr && t->is_string()) {
            out = std::string(t->as_string()) + ": " + out;
        }
        return out;
    } catch (const std::exception&) {
        return "HTTP " + std::to_string(r._status) + " " + r._body.substr(0, 200);
    }
}

}  // namespace kythira::kinesis
