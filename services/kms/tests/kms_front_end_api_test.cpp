// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The gateway apart from the front end (.kiro/specs/kms-independent-layers/
// task 4): the authenticated call's wire, the front-end API's answers, who
// may call which internal route (Requirement 9), the gateway's handover
// with its not-executed rule, the live front ends and the quota share over
// them (Requirement 7), and a gateway and front end end to end.

#define BOOST_TEST_MODULE kms_front_end_api_test
#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_front_end_api.hpp>
#include <kythira/kms/kms_peer.hpp>
#include <kythira/kms/kms_quotas.hpp>

#include <raft/kms_forwarding.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)
namespace fe_api = kythira::kms::front_end_api;
namespace layers = kythira::layers;
using namespace std::chrono_literals;

namespace {

auto sample_call() -> kms::authenticated_call {
    kms::authenticated_call c;
    c.operation = "Encrypt";
    c.request_id = "0f9a4c1e-1111-4000-8000-000000000001";
    c.principal.type = az::principal_type::assumed_role;
    c.principal.account = std::string(k_account);
    c.principal.arn = "arn:aws:sts::111122223333:assumed-role/app/s1";
    c.principal.userid = "AROAEXAMPLE:s1";
    c.principal.access_key_id = "ASIAEXAMPLE";
    c.principal.role_arn = "arn:aws:iam::111122223333:role/app";
    c.principal.role_name = "app";
    c.principal.session_name = "s1";
    c.principal.tags = {{"team", "blue"}};
    c.principal.session_policies = {R"({"Version":"2012-10-17"})"};
    c.request.method = "POST";
    c.request.path = "/";
    c.request.query = "";
    c.request.headers = {{"Content-Type", "application/x-amz-json-1.1"},
                         {"X-Amz-Target", "TrentService.Encrypt"},
                         {"X-Odd", std::string("\xff\xfe binary", 9)}};
    // A client may send any bytes; the front end, not the gateway, answers
    // for them.
    c.request.body = std::string("{\"KeyId\":\"k\"}\x80\x00", 15);
    c.request.source_ip = "203.0.113.9";
    c.request.secure = true;
    return c;
}

/// A verified caller presenting `uris` as URI SANs.
auto caller(std::vector<std::string> uris, std::vector<std::string> dns = {}) -> kms::peer_caller {
    return {true, true, std::move(uris), std::move(dns)};
}

auto layer_uri(std::string_view roles, std::string_view cluster = "prod") -> std::string {
    return "kythira://kms/" + std::string(cluster) + "/7?roles=" + std::string(roles);
}

/// A steady clock the test moves.
struct test_clock {
    std::chrono::steady_clock::time_point at{std::chrono::seconds(1000)};
    auto fn() {
        return [this] { return at; };
    }
};

}  // namespace

// -- The wire -----------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_call_survives_the_wire_byte_for_byte) {
    const auto c = sample_call();
    const auto back = fe_api::decode_call(fe_api::encode_call(c));
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->operation == c.operation);
    BOOST_TEST(back->request_id == c.request_id);
    BOOST_TEST(back->principal.arn == c.principal.arn);
    BOOST_TEST(back->principal.role_arn == c.principal.role_arn);
    BOOST_TEST(back->principal.access_key_id == c.principal.access_key_id);
    BOOST_TEST((back->principal.type == az::principal_type::assumed_role));
    BOOST_TEST(back->principal.tags == c.principal.tags);
    BOOST_TEST(back->principal.session_policies == c.principal.session_policies);
    BOOST_TEST(back->request.method == c.request.method);
    BOOST_TEST(back->request.path == c.request.path);
    BOOST_TEST(back->request.headers == c.request.headers);
    BOOST_TEST(back->request.body == c.request.body);
    BOOST_TEST(back->request.source_ip == c.request.source_ip);
    BOOST_TEST(back->request.secure == c.request.secure);
}

BOOST_AUTO_TEST_CASE(anything_but_a_whole_call_of_this_version_is_refused) {
    const auto wire = fe_api::encode_call(sample_call());
    BOOST_TEST(!fe_api::decode_call("").has_value());
    BOOST_TEST(!fe_api::decode_call(wire + "x").has_value());  // trailing bytes
    for (std::size_t cut = 0; cut < wire.size(); cut += 7) {
        BOOST_TEST(!fe_api::decode_call(wire.substr(0, cut)).has_value(), cut);
    }
    auto other_version = wire;
    other_version[0] = 2;
    BOOST_TEST(!fe_api::decode_call(other_version).has_value());

    // A principal that does not decode.
    auto bad = sample_call();
    std::string text = fe_api::encode_call(bad);
    const auto at = text.find(kythira::kms_forwarding::encode_principal(bad.principal));
    BOOST_REQUIRE(at != std::string::npos);
    text[at] = '!';
    BOOST_TEST(!fe_api::decode_call(text).has_value());

    // An operation is required.
    bad.operation.clear();
    BOOST_TEST(!fe_api::decode_call(fe_api::encode_call(bad)).has_value());
}

BOOST_AUTO_TEST_CASE(seeded_mutations_never_crash_the_decoders) {
    const auto call_wire = fe_api::encode_call(sample_call());
    kythira::aws_json::http_response res;
    res.status = 400;
    res.headers = {{"x-amzn-RequestId", "r"}};
    res.body = R"({"__type":"NotFoundException"})";
    const auto answer_wire = fe_api::encode_answer(res);
    std::mt19937 rng(20261127);
    for (int i = 0; i < 4000; ++i) {
        auto m = (i % 2 == 0) ? call_wire : answer_wire;
        const auto edits = 1 + rng() % 4;
        for (unsigned e = 0; e < edits; ++e) {
            const auto pos = rng() % m.size();
            switch (rng() % 3) {
                case 0:
                    m[pos] = static_cast<char>(rng());
                    break;
                case 1:
                    m.erase(pos, 1 + rng() % 8);
                    break;
                default:
                    m.insert(pos, std::string(1 + rng() % 8, static_cast<char>(rng())));
                    break;
            }
            if (m.empty()) {
                m = "\x01";
            }
        }
        (void)fe_api::decode_call(m);
        (void)fe_api::decode_answer(m);
    }
    BOOST_TEST(fe_api::decode_answer(answer_wire)->body == res.body);
}

BOOST_AUTO_TEST_CASE(an_answer_survives_the_wire_and_a_bad_status_does_not) {
    kythira::aws_json::http_response res;
    res.status = 200;
    res.headers = {{"Content-Type", "application/x-amz-json-1.1"}, {"x-amzn-RequestId", "abc"}};
    res.body = R"({"KeyId":"k"})";
    const auto back = fe_api::decode_answer(fe_api::encode_answer(res));
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->status == 200U);
    BOOST_TEST(back->headers == res.headers);
    BOOST_TEST(back->body == res.body);
    res.status = 42;
    BOOST_TEST(!fe_api::decode_answer(fe_api::encode_answer(res)).has_value());
}

// -- The front-end API's answers --------------------------------------------------------

BOOST_AUTO_TEST_CASE(the_front_end_api_answers) {
    int ran = 0;
    const fe_api::executor run = [&](kms::authenticated_call c) {
        ++ran;
        kythira::aws_json::http_response r;
        r.body = c.operation;
        return r;
    };
    const auto wire = fe_api::encode_call(sample_call());
    BOOST_TEST(
        fe_api::serve_front_end(true, true, "POST", "/v1/kms/peer/propose", wire, run).status ==
        fe_api::k_not_found);
    BOOST_TEST(
        fe_api::serve_front_end(false, true, "POST", fe_api::k_call_path, wire, run).status ==
        fe_api::k_refused);
    BOOST_TEST(fe_api::serve_front_end(true, true, "GET", fe_api::k_call_path, wire, run).status ==
               fe_api::k_malformed);
    BOOST_TEST(
        fe_api::serve_front_end(true, true, "POST", "/v1/kms/front-end/other", wire, run).status ==
        fe_api::k_malformed);
    BOOST_TEST(
        fe_api::serve_front_end(true, true, "POST", fe_api::k_call_path, "junk", run).status ==
        fe_api::k_malformed);
    // Draining, or no front end on the node: not executed, so a gateway
    // goes elsewhere.
    BOOST_TEST(
        fe_api::serve_front_end(true, false, "POST", fe_api::k_call_path, wire, run).status ==
        fe_api::k_not_executed);
    BOOST_TEST(
        fe_api::serve_front_end(true, false, "POST", fe_api::k_health_path, "", run).status ==
        fe_api::k_not_executed);
    BOOST_TEST(ran == 0);
    BOOST_TEST(fe_api::serve_front_end(true, true, "POST", fe_api::k_health_path, "", run).status ==
               fe_api::k_ok);
    const auto ok = fe_api::serve_front_end(true, true, "POST", fe_api::k_call_path, wire, run);
    BOOST_TEST(ok.status == fe_api::k_ok);
    BOOST_TEST(fe_api::decode_answer(ok.body)->body == "Encrypt");
    BOOST_TEST(ran == 1);
}

// -- Who may call (Requirement 9) ---------------------------------------------------------

BOOST_AUTO_TEST_CASE(layer_identities_are_held_to_their_roles_route_by_route) {
    kms::peer_policy p;
    p.cluster = "prod";
    p.identities = {"spiffe://kms/legacy-1", layer_uri("gateway")};

    const auto gateway = caller({layer_uri("gateway")});
    BOOST_TEST(kms::admits(p, gateway, kms::front_end_call_roles));
    BOOST_TEST(kms::admits(p, gateway, kms::front_end_health_roles));
    // Listed among the members, a gateway still may not read the catalog
    // or forward proposals: its identity's roles decide.
    BOOST_TEST(!kms::admits(p, gateway, kms::catalog_route_roles));
    BOOST_TEST(!kms::admits(p, gateway, kms::peer_route_roles));
    BOOST_TEST(!kms::is_member(p, gateway));

    const auto front_end = caller({layer_uri("front_end")});
    BOOST_TEST(!kms::admits(p, front_end, kms::front_end_call_roles));
    BOOST_TEST(kms::admits(p, front_end, kms::front_end_health_roles));
    BOOST_TEST(kms::admits(p, front_end, kms::catalog_route_roles));
    BOOST_TEST(!kms::admits(p, front_end, kms::peer_route_roles));

    const auto data = caller({layer_uri("data")});
    BOOST_TEST(!kms::admits(p, data, kms::front_end_call_roles));
    BOOST_TEST(kms::admits(p, data, kms::catalog_route_roles));
    BOOST_TEST(kms::admits(p, data, kms::peer_route_roles));

    const auto co_located = caller({layer_uri("gateway,front_end,data")});
    for (const auto roles : {kms::front_end_call_roles, kms::front_end_health_roles,
                             kms::catalog_route_roles, kms::peer_route_roles}) {
        BOOST_TEST(kms::admits(p, co_located, roles));
    }

    // Another cluster's identity, or another service's, is no identity
    // here: only the member list could admit it.
    BOOST_TEST(
        !kms::admits(p, caller({layer_uri("gateway", "staging")}), kms::front_end_call_roles));
    BOOST_TEST(!kms::admits(p, caller({"kythira://kinesis/prod/7?roles=gateway"}),
                            kms::front_end_call_roles));

    // A listed member without a layer identity is trusted as every layer,
    // as before layer identities.
    const auto legacy = caller({"spiffe://kms/legacy-1"});
    for (const auto roles :
         {kms::front_end_call_roles, kms::catalog_route_roles, kms::peer_route_roles}) {
        BOOST_TEST(kms::admits(p, legacy, roles));
    }
    BOOST_TEST(!kms::admits(p, caller({"spiffe://kms/stranger"}), kms::front_end_call_roles));

    // Unverified callers never; plaintext only when tests allow it.
    BOOST_TEST(!kms::admits(p, kms::peer_caller{true, false, {layer_uri("gateway")}, {}},
                            kms::front_end_call_roles));
    BOOST_TEST(!kms::admits(p, kms::peer_caller{}, kms::front_end_call_roles));
    p.allow_plaintext = true;
    BOOST_TEST(kms::admits(p, kms::peer_caller{}, kms::front_end_call_roles));
}

// -- Live front ends (Requirement 7.2) ------------------------------------------------------

BOOST_AUTO_TEST_CASE(live_front_ends_are_those_that_answered_lately) {
    test_clock clock;
    kms::front_end_directory d({{"2", "https://fe-2:8443"}, {"3", "https://fe-3:8443"}}, true, 3s,
                               clock.fn());
    // Nothing answered yet: only this front end.
    BOOST_TEST(d.live_count() == 1U);
    d.probe([](std::string_view url) { return url == "https://fe-2:8443"; });
    BOOST_TEST(d.live_count() == 2U);
    d.mark("https://fe-3:8443", true);
    BOOST_TEST(d.live_count() == 3U);
    clock.at += 2s;
    d.mark("https://fe-2:8443", true);
    clock.at += 2s;  // fe-3 last answered 4 s ago
    BOOST_TEST(d.live_count() == 2U);
    d.mark("https://fe-2:8443", false);  // a failed dial
    BOOST_TEST(d.live_count() == 1U);

    // A gateway is no front end: it counts only the others.
    kms::front_end_directory g({{"2", "https://fe-2:8443"}}, false, 3s, clock.fn());
    BOOST_TEST(g.live_count() == 0U);
}

BOOST_AUTO_TEST_CASE(calls_go_to_live_front_ends_first_in_turn) {
    test_clock clock;
    kms::front_end_directory d({{"1", "https://a:1"}, {"2", "https://b:1"}, {"3", "https://c:1"}},
                               false, 3s, clock.fn());
    d.mark("https://a:1", true);
    d.mark("https://c:1", true);
    std::map<std::string, int> first;
    for (int i = 0; i < 6; ++i) {
        const auto o = d.order();
        BOOST_REQUIRE_EQUAL(o.size(), 3U);
        BOOST_TEST(o.back() == "https://b:1");  // not live: tried last
        ++first[o.front()];
    }
    BOOST_TEST(first["https://a:1"] > 0);
    BOOST_TEST(first["https://c:1"] > 0);
}

BOOST_AUTO_TEST_CASE(the_quota_share_follows_the_live_count) {
    std::int64_t now = 0;
    kms::quota_config c;
    c.defaults.symmetric = 10;  // per second, over every front end
    c.members = 1;
    kms::request_quotas q(c, [&] { return now; });
    // The first second's burst is the whole rate either way.
    int admitted = 0;
    for (int i = 0; i < 20; ++i) {
        admitted += q.admit_key_use("a", "Encrypt", kms::key_spec::symmetric_default) ? 1 : 0;
    }
    BOOST_TEST(admitted == 10);
    // Two front ends live: each refills at half the rate.
    q.set_members(2);
    BOOST_TEST(q.members() == 2U);
    now += 1000;
    admitted = 0;
    for (int i = 0; i < 20; ++i) {
        admitted += q.admit_key_use("a", "Encrypt", kms::key_spec::symmetric_default) ? 1 : 0;
    }
    BOOST_TEST(admitted == 5);
    q.set_members(0);  // never below one
    BOOST_TEST(q.members() == 1U);
}

// -- The gateway's handover --------------------------------------------------------------

namespace {

/// Front ends standing behind URLs, each answering as told.
struct fake_front_ends {
    struct behaviour {
        std::optional<unsigned> status;  ///< nothing: no answer
        bool arrived = false;            ///< when there is no answer
        std::string body;
    };
    std::map<std::string, behaviour> by_url;
    std::vector<std::string> tried;

    auto send() -> kms::front_end_link::send_fn {
        return [this](std::string_view url, std::string_view target, std::string body) {
            BOOST_TEST(target == fe_api::k_call_path);
            BOOST_TEST(fe_api::decode_call(body).has_value());
            tried.emplace_back(url);
            const auto& b = by_url.at(std::string(url));
            if (!b.status) {
                return kms::front_end_attempt{std::nullopt, b.arrived};
            }
            return kms::front_end_attempt{std::make_pair(*b.status, b.body), true};
        };
    }
};

auto ok_answer(std::string body) -> std::string {
    kythira::aws_json::http_response r;
    r.body = std::move(body);
    return fe_api::encode_answer(r);
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_gateway_moves_on_only_when_the_call_cannot_have_run) {
    test_clock clock;
    kms::front_end_directory d({{"1", "https://a:1"}, {"2", "https://b:1"}, {"3", "https://c:1"}},
                               false, 3s, clock.fn());
    fake_front_ends fes;
    fes.by_url["https://a:1"] = {fe_api::k_not_executed, false, "draining"};
    fes.by_url["https://b:1"] = {std::nullopt, false, ""};  // refused the dial
    fes.by_url["https://c:1"] = {fe_api::k_ok, false, ok_answer("from c")};
    kms::front_end_link link(d, fes.send());
    const auto r = link.hand_over(sample_call());
    BOOST_REQUIRE(std::holds_alternative<kythira::aws_json::http_response>(r));
    BOOST_TEST(std::get<kythira::aws_json::http_response>(r).body == "from c");
    BOOST_TEST(fes.tried.size() == 3U);
    // Only c answered, so it is the one live front end and goes first.
    BOOST_TEST(d.order().front() == "https://c:1");
    BOOST_TEST(link.counters().handed_over == 1U);
    BOOST_TEST(link.counters().not_executed == 1U);

    // Sent and unanswered: it may have run, so no second front end.
    fes.tried.clear();
    fes.by_url["https://c:1"] = {std::nullopt, true, ""};
    const auto lost = link.hand_over(sample_call());
    BOOST_REQUIRE(std::holds_alternative<kms::handoff_failure>(lost));
    BOOST_TEST((std::get<kms::handoff_failure>(lost) == kms::handoff_failure::outcome_unknown));
    BOOST_TEST(fes.tried.size() == 1U);

    // A refusal (a front end that does not know this gateway) did not run
    // it either.
    fes.tried.clear();
    fes.by_url["https://a:1"] = {fe_api::k_refused, false, "who?"};
    fes.by_url["https://c:1"] = {fe_api::k_not_executed, false, ""};
    const auto none = link.hand_over(sample_call());
    BOOST_REQUIRE(std::holds_alternative<kms::handoff_failure>(none));
    BOOST_TEST((std::get<kms::handoff_failure>(none) == kms::handoff_failure::no_front_end));
    BOOST_TEST(fes.tried.size() == 3U);
    BOOST_TEST(kms::front_end_link::error_for(kms::handoff_failure::no_front_end).type ==
               "KMSInternalException");
    BOOST_TEST(link.counters().no_front_end == 1U);
    BOOST_TEST(link.counters().outcome_unknown == 1U);
}

BOOST_AUTO_TEST_CASE(an_unreadable_answer_is_an_unknown_outcome) {
    test_clock clock;
    kms::front_end_directory d({{"1", "https://a:1"}, {"2", "https://b:1"}}, false, 3s, clock.fn());
    fake_front_ends fes;
    fes.by_url["https://a:1"] = {fe_api::k_ok, false, "not a wire answer"};
    fes.by_url["https://b:1"] = {fe_api::k_ok, false, "not a wire answer"};
    kms::front_end_link link(d, fes.send());
    const auto r = link.hand_over(sample_call());
    BOOST_REQUIRE(std::holds_alternative<kms::handoff_failure>(r));
    BOOST_TEST((std::get<kms::handoff_failure>(r) == kms::handoff_failure::outcome_unknown));
    BOOST_TEST(fes.tried.size() == 1U);
}

// -- Gateway and front end end to end --------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_gateway_and_a_front_end_answer_as_one_node_does) {
    split_layout() = true;
    fixture f;
    std::vector<kms::request_record> front_end_records;
    std::vector<kms::request_record> gateway_records;
    f.fe.set_observer([&](const kms::request_record& r) { front_end_records.push_back(r); });
    f.gateway.set_observer([&](const kms::request_record& r) { gateway_records.push_back(r); });

    const auto id = f.create(R"({"Description":"through the gateway"})");
    const auto enc = f.call("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"aGVsbG8="})");
    BOOST_REQUIRE_MESSAGE(enc.status == 200U, enc.type() + ": " + enc.message());
    const auto dec =
        f.call("Decrypt", R"({"CiphertextBlob":")" + enc.str("CiphertextBlob") + R"("})");
    BOOST_REQUIRE_MESSAGE(dec.status == 200U, dec.type() + ": " + dec.message());
    BOOST_TEST(dec.str("Plaintext") == "aGVsbG8=");

    // The front end authorized and recorded each; the gateway, which only
    // verified signatures, recorded none of them.
    BOOST_TEST(front_end_records.size() == 3U);
    BOOST_TEST(gateway_records.empty());
    BOOST_TEST(front_end_records.back().operation == "Decrypt");
    BOOST_TEST(front_end_records.back().principal->arn == "arn:aws:iam::111122223333:user/admin");
    BOOST_TEST(front_end_records.back().source_ip == "192.0.2.10");

    // A refused signature stops at the gateway, which records it; the
    // front end never sees it.
    auto forged = sign(request("ListKeys", "{}"), "AKIDADMIN");
    forged.body = R"({"Limit":1})";
    BOOST_TEST(fixture::answer(f.handle(forged)).type() == "InvalidSignatureException");
    BOOST_TEST(gateway_records.size() == 1U);
    BOOST_TEST(gateway_records.back().access_key_id == "AKIDADMIN");
    BOOST_TEST(front_end_records.size() == 3U);

    // Authorization is the front end's: the read-only key may describe but
    // not disable, through the gateway as on one node.
    BOOST_TEST(f.call("DescribeKey", R"({"KeyId":")" + id + R"("})", "AKIDREAD").status == 200U);
    BOOST_TEST(f.call("DisableKey", R"({"KeyId":")" + id + R"("})", "AKIDREAD").type() ==
               "AccessDeniedException");

    // A gateway answers a call no front end took with a retryable error,
    // recorded as its own.
    const auto call = std::get<kms::authenticated_call>(
        f.gateway.authenticate(sign(request("ListKeys", "{}"), "AKIDADMIN")));
    const auto failed = fixture::answer(
        f.gateway.fail(call, kms::front_end_link::error_for(kms::handoff_failure::no_front_end)));
    BOOST_TEST(failed.status == 500U);
    BOOST_TEST(failed.type() == "KMSInternalException");
    BOOST_TEST(gateway_records.back().request_id == call.request_id);
    BOOST_TEST(gateway_records.back().status == 500U);
    split_layout() = false;
}

BOOST_AUTO_TEST_CASE(execute_takes_the_operation_the_gateway_resolved_only) {
    fixture f;
    auto call = std::get<kms::authenticated_call>(
        f.fe.authenticate(sign(request("ListKeys", "{}"), "AKIDADMIN")));
    call.operation = "CreateKey";  // not what the target names
    const auto r = fixture::answer(f.fe.execute(call));
    BOOST_TEST(r.status == 500U);
    BOOST_TEST(r.type() == "KMSInternalException");
    BOOST_TEST(f.auth.asked.empty());
}
