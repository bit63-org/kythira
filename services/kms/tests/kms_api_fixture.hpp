// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS API tests' fixture: a catalog replica, the fake PKCS#11 token,
// the key jobs, a test authorizer over static keys, and the front end with
// every operation registered, driven by signed JSON 1.1 requests.

#include <boost/test/unit_test.hpp>

#include "kms_fake_pkcs11.hpp"

#include <kythira/kms/kms_actions.hpp>
#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_crypto_api.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/sigv4_verifier.hpp>
#include <raft/static_key_authorizer.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace kms_api_fixture {

namespace kms = kythira::kms;
namespace kt = kythira::kms::test;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;

inline constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
inline constexpr std::string_view k_account = "111122223333";
inline constexpr std::string_view k_other = "444455556666";
inline const auto k_now = sv4::detail::parse_amz_date("20261115T120000Z").value();

using catalog_t = kms::kms_catalog_state_machine<>;

/// Static keys for authentication; authorization through a hook the test
/// can replace, recording every request it is asked.
struct test_authorizer {
    az::static_key_authorizer keys{{
                                       {"AKIDADMIN", std::string(k_secret), std::string(k_account),
                                        "admin", az::static_role::admin},
                                       {"AKIDREAD", std::string(k_secret), std::string(k_account),
                                        "reader", az::static_role::read_only},
                                       {"AKIDOTHER", std::string(k_secret), std::string(k_other),
                                        "stranger", az::static_role::admin},
                                   },
                                   "aws",
                                   [] { return k_now; }};
    std::vector<az::authz_request> asked;
    std::function<az::authz_decision(const az::principal_context&, const az::authz_request&)>
        decide;

    test_authorizer() { keys.register_service(kms::kms_static_roles()); }

    auto authenticate(const sv4::request& req, const sv4::service_rules& rules)
        -> az::authn_result {
        return keys.authenticate(req, rules);
    }
    auto authorize(const az::principal_context& who, const az::authz_request& r)
        -> az::authz_decision {
        asked.push_back(r);
        return decide ? decide(who, r) : keys.authorize(who, r);
    }
};

static_assert(az::aws_request_authorizer<test_authorizer>);

inline auto request(std::string_view op, const std::string& body) -> kms::front_end_request {
    kms::front_end_request r;
    r.method = "POST";
    r.path = "/";
    r.body = body;
    r.source_ip = "192.0.2.10";
    r.headers = {{"Host", "kms.us-east-1.amazonaws.com"},
                 {"Content-Type", "application/x-amz-json-1.1"},
                 {"X-Amz-Date", "20261115T120000Z"},
                 {"X-Amz-Target", "TrentService." + std::string(op)}};
    return r;
}

inline auto sign(kms::front_end_request r, std::string_view akid) -> kms::front_end_request {
    sv4::service_rules rules;
    rules.service = "kms";
    rules.protocol = sv4::error_protocol::json;
    const sv4::credential_scope scope{"20261115", "us-east-1", "kms"};
    r.headers.emplace_back("Authorization",
                           "AWS4-HMAC-SHA256 Credential=" + std::string(akid) + "/" + scope.text() +
                               ", SignedHeaders=content-type;host;x-amz-date;x-amz-target"
                               ", Signature=" +
                               std::string(64, '0'));
    const auto parsed =
        sv4::parse(sv4::request{r.method, r.path, r.query, r.headers, r.body}, rules, k_now);
    BOOST_REQUIRE(parsed.has_value());
    const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
    r.headers.back().second.replace(r.headers.back().second.size() - 64, 64, sig);
    return r;
}

struct reply {
    unsigned status = 0;
    json::object body;

    [[nodiscard]] auto type() const -> std::string {
        const auto* t = body.if_contains("__type");
        if (t == nullptr) {
            return {};
        }
        const std::string full(t->as_string());
        return full.substr(full.find('#') + 1);
    }
    [[nodiscard]] auto message() const -> std::string {
        for (const char* k : {"message", "Message"}) {
            if (const auto* m = body.if_contains(k)) {
                return std::string(m->as_string());
            }
        }
        return {};
    }
    [[nodiscard]] auto str(std::string_view a, std::string_view b = {}) const -> std::string {
        const auto& v = b.empty() ? body.at(a) : body.at(a).as_object().at(b);
        return std::string(v.as_string());
    }
};

struct fixture {
    kythira::memory_kv_engine engine;
    catalog_t sm{"kms/"};
    std::shared_ptr<kt::fake_backend> hsm_backend = std::make_shared<kt::fake_backend>();
    std::shared_ptr<kms::backing_store> hsm =
        std::make_shared<kms::backing_store>(hsm_backend, 1, "1234");
    bool hsm_bound = true;
    std::uint64_t index = 0;
    std::uint64_t now = 1'790'000'000'000;
    bool leaderless = false;
    int next_id = 0;
    kms::key_jobs<catalog_t> jobs{sm, *hsm,
                                  [this](const std::vector<std::byte>& c) { return propose(c); },
                                  [this] { return now; }, std::chrono::minutes(5)};
    test_authorizer auth;
    kms::front_end<test_authorizer> fe{kms::front_end_config{}, auth};
    kms::key_management_api<catalog_t> api{kms::api_deps<catalog_t>{
        .catalog =
            [this] { return std::shared_ptr<const catalog_t>(&sm, [](const catalog_t*) {}); },
        .barrier = [this] { return !leaderless; },
        .propose = [this](const std::vector<std::byte>& c) { return propose(c); },
        .create_key = [this](kms::key_record k,
                             const kms::tag_map& t) { return jobs.create_key(std::move(k), t); },
        .clock_ms = [this] { return now; },
        .new_key_id =
            [this] {
                char buf[37];
                std::snprintf(buf, sizeof buf, "%08x-2222-4000-8000-000000000000", ++next_id);
                return std::string(buf);
            },
    }};

    kms::crypto_api<catalog_t> crypto{kms::crypto_deps<catalog_t>{
        .catalog =
            [this] { return std::shared_ptr<const catalog_t>(&sm, [](const catalog_t*) {}); },
        .barrier = [this] { return !leaderless; },
        .hsm = [this] { return hsm_bound ? hsm : nullptr; },
    }};

    fixture() {
        sm.open(engine, sm.engine_range());
        api.register_on(fe);
        crypto.register_on(fe);
    }

    auto propose(const std::vector<std::byte>& c) -> kms::catalog_status {
        if (leaderless) {
            throw std::runtime_error("no leader");
        }
        return kms::catalog_reply_status(sm.apply(c, ++index));
    }

    auto call(std::string_view op, const std::string& body, std::string_view akid = "AKIDADMIN")
        -> reply {
        return answer(fe.handle(sign(request(op, body), akid)));
    }

    static auto answer(const kythira::aws_json::http_response& res) -> reply {
        reply r;
        r.status = res.status;
        if (!res.body.empty()) {
            r.body = json::parse(res.body).as_object();
        }
        return r;
    }

    /// CreateKey with `body`; the new key's id.
    auto create(const std::string& body = "{}", std::string_view akid = "AKIDADMIN")
        -> std::string {
        const auto r = call("CreateKey", body, akid);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
        return r.str("KeyMetadata", "KeyId");
    }

    [[nodiscard]] static auto arn(std::string_view id, std::string_view account = k_account)
        -> std::string {
        return "arn:aws:kms:us-east-1:" + std::string(account) + ":key/" + std::string(id);
    }
};

inline auto kid(std::string_view id) -> std::string {
    return R"({"KeyId":")" + std::string(id) + R"("})";
}

}  // namespace kms_api_fixture
