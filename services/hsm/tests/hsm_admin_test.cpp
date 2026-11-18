// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The HSM's operator API (.kiro/specs/virtual-hsm/ tasks 6d and 7) over the
// direct store: only operators get in, the status reflects the catalog and
// the vault, tokens are created sealed under the master key and only on an
// unsealed node, bindings take percent-encoded identities, and each
// refusal from the catalog maps to its HTTP status. Init hands out shares
// once, unseal takes them one at a time, seal reaches every node, and
// rekey keeps every token while retiring the old shares.

#define BOOST_TEST_MODULE hsm_admin_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_store.hpp"

#include <kythira/hsm/audit_json.hpp>
#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_admin.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/shamir.hpp>

#include <boost/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

namespace hsm = kythira::hsm;

/// The direct store with the two calls the API needs from hsm_host.
struct admin_host {
    hsm::test::direct_store& store;

    [[nodiscard]] auto catalog() const { return store.catalog(); }
    [[nodiscard]] auto tokens() const { return store.tokens(); }
    [[nodiscard]] auto hosts(std::uint64_t id) const { return store.hosts(id); }
    [[nodiscard]] auto crypto_members() const { return store.crypto_members(); }
    auto propose_catalog(std::vector<std::byte> cmd) {
        return store.propose_catalog(std::move(cmd));
    }
    [[nodiscard]] static auto fits(std::uint64_t id) -> bool { return id != 0 && id <= 1000; }
    [[nodiscard]] static auto leads(std::uint64_t /*local*/) -> bool { return true; }
    [[nodiscard]] static auto catalog_barrier() -> hsm::ck_result<void> { return {}; }
};

const std::string k_operator = "spiffe://ops/alice";

struct fixture {
    hsm::test::direct_store store;
    admin_host host{store};
    hsm::key_vault vault;
    hsm::admin_api<admin_host> api{host, vault, hsm::admin_policy{{k_operator, "ops.example"}}};
    hsm::secret_bytes mk{32};

    fixture() { BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value()); }

    auto call(const std::string& method, const std::string& path, const std::string& body = "",
              std::vector<std::string> identities = {k_operator}) -> hsm::admin_response {
        return api.handle({method, path, body, std::move(identities)});
    }

    static auto json(const hsm::admin_response& r) -> boost::json::object {
        return boost::json::parse(r.body).as_object();
    }

    void initialize() {
        auto r = store.propose_catalog(hsm::make_initialize_command(
            hsm::unseal_mode::operator_shares, 2, 3, hsm::key_check_value(mk.view())));
        BOOST_REQUIRE(r.has_value());
        BOOST_REQUIRE(hsm::catalog_reply_rv(*r) == CKR_OK);
    }

    void unseal() {
        BOOST_REQUIRE(vault.unseal(mk.clone(), store.catalog()) == hsm::unseal_result::unsealed);
    }
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(only_operators_get_in, fixture) {
    BOOST_TEST(call("GET", "/v1/status", "", {}).status == 403U);
    BOOST_TEST(call("GET", "/v1/status", "", {"spiffe://apps/payments"}).status == 403U);
    BOOST_TEST(json(call("GET", "/v1/status", "", {"spiffe://apps/payments"})).at("error") ==
               "forbidden");
    // Any SAN the certificate carries may be the operator's.
    BOOST_TEST(call("GET", "/v1/status", "", {"node-7", "ops.example"}).status == 200U);
    BOOST_TEST(store.log.empty());
}

BOOST_FIXTURE_TEST_CASE(status_follows_the_catalog_and_the_vault, fixture) {
    auto before = json(call("GET", "/v1/status"));
    BOOST_TEST(before.at("initialized") == false);
    BOOST_TEST(before.at("sealed") == true);
    BOOST_TEST(!before.contains("generation"));
    initialize();
    unseal();
    auto after = json(call("GET", "/v1/status"));
    BOOST_TEST(after.at("initialized") == true);
    BOOST_TEST(after.at("sealed") == false);
    BOOST_TEST(after.at("mode") == "operator");
    BOOST_TEST(after.at("k").to_number<int>() == 2);
    BOOST_TEST(after.at("n").to_number<int>() == 3);
    BOOST_TEST(after.at("generation").to_number<int>() == 1);
    BOOST_TEST(after.at("tokens").to_number<int>() == 0);
    BOOST_TEST(after.at("catalog_leader") == true);
}

BOOST_FIXTURE_TEST_CASE(tokens_need_an_initialized_unsealed_node, fixture) {
    const std::string body = R"({"id": 7, "label": "payments"})";
    BOOST_TEST(call("POST", "/v1/tokens", body).status == 409U);
    initialize();
    const auto sealed = call("POST", "/v1/tokens", body);
    BOOST_TEST(sealed.status == 503U);
    BOOST_TEST(json(sealed).at("error") == "sealed");
    BOOST_TEST(store.tokens().empty());
    unseal();
    const auto created = call("POST", "/v1/tokens", body);
    BOOST_TEST(created.status == 201U);
    BOOST_REQUIRE(store.token(7).has_value());
    // The token key is sealed under the master key, never in the clear.
    BOOST_TEST(store.token(7)->label == "payments");
    BOOST_TEST(store.token(7)->sealed_tk.size() > 32U);
    BOOST_TEST(store.hosts(7));
    const auto list = json(call("GET", "/v1/tokens"));
    BOOST_REQUIRE(list.at("tokens").as_array().size() == 1U);
    BOOST_TEST(list.at("tokens").as_array()[0].as_object().at("id").to_number<int>() == 7);
    BOOST_TEST(call("POST", "/v1/tokens", body).status == 409U);  // id taken
}

BOOST_FIXTURE_TEST_CASE(malformed_token_requests_are_refused, fixture) {
    initialize();
    unseal();
    for (const auto* body :
         {R"({"id": 0, "label": "x"})", R"({"id": -3, "label": "x"})",
          R"({"id": "7", "label": "x"})", R"({"label": "x"})", R"({"id": 7})",
          R"({"id": 1001, "label": "outside the space"})",
          R"({"id": 7, "label": "a label longer than thirty-two bytes"})", "not json", "[1, 2]"}) {
        BOOST_TEST(call("POST", "/v1/tokens", body).status == 400U, body);
    }
    BOOST_TEST(store.tokens().empty());
}

BOOST_FIXTURE_TEST_CASE(bindings_take_percent_encoded_identities, fixture) {
    initialize();
    unseal();
    BOOST_REQUIRE(call("POST", "/v1/tokens", R"({"id": 3, "label": "ca"})").status == 201U);
    const std::string path = "/v1/tokens/3/bindings/spiffe%3A%2F%2Fapps%2Fca";
    BOOST_TEST(call("PUT", path).status == 200U);
    BOOST_TEST(store.may_open("spiffe://apps/ca", 3));
    BOOST_TEST(call("DELETE", path).status == 200U);
    BOOST_TEST(!store.may_open("spiffe://apps/ca", 3));
    BOOST_TEST(call("PUT", "/v1/tokens/4/bindings/app").status == 404U);
    BOOST_TEST(call("PUT", "/v1/tokens/3/bindings/bad%2").status == 400U);
    BOOST_TEST(call("PUT", "/v1/tokens/3/bindings/").status == 404U);
    BOOST_TEST(call("PUT", "/v1/tokens/x/bindings/app").status == 400U);
}

BOOST_FIXTURE_TEST_CASE(deleted_tokens_are_gone_for_good, fixture) {
    initialize();
    unseal();
    const std::string body = R"({"id": 5, "label": "old"})";
    BOOST_REQUIRE(call("POST", "/v1/tokens", body).status == 201U);
    BOOST_TEST(call("DELETE", "/v1/tokens/5").status == 200U);
    BOOST_TEST(!store.token(5).has_value());
    BOOST_TEST(call("DELETE", "/v1/tokens/5").status == 404U);
    BOOST_TEST(call("POST", "/v1/tokens", body).status == 409U);  // never reused
}

BOOST_FIXTURE_TEST_CASE(routes_methods_and_commit_failures, fixture) {
    initialize();
    unseal();
    BOOST_TEST(call("GET", "/v1/nothing").status == 404U);
    BOOST_TEST(call("POST", "/v1/status").status == 405U);
    BOOST_TEST(call("PATCH", "/v1/tokens").status == 405U);
    BOOST_TEST(call("GET", "/v1/tokens/5").status == 405U);
    BOOST_TEST(call("GET", "/v1/tokens/5/other").status == 404U);
    store.fail_proposals = true;
    const auto r = call("POST", "/v1/tokens", R"({"id": 9, "label": "x"})");
    BOOST_TEST(r.status == 503U);
    BOOST_TEST(json(r).at("error") == "unavailable");
}

namespace {

auto shares_of(const boost::json::object& o) -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& v : o.at("shares").as_array()) {
        out.emplace_back(v.as_string());
    }
    return out;
}

auto unseal_body(const std::string& share) -> std::string {
    return boost::json::serialize(boost::json::object{{"share", share}});
}

/// A second node on the same replicated store, with its own vault.
struct other_node {
    hsm::key_vault vault;
    hsm::admin_api<admin_host> api;

    explicit other_node(admin_host& host) : api{host, vault, hsm::admin_policy{{k_operator}}} {}

    auto call(const std::string& method, const std::string& path, const std::string& body = "")
        -> hsm::admin_response {
        return api.handle({method, path, body, {k_operator}});
    }
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(init_hands_out_shares_once_and_leaves_nodes_sealed, fixture) {
    BOOST_TEST(call("POST", "/v1/init", R"({"mode": "operator", "k": 1, "n": 1})").status == 400U);
    BOOST_TEST(call("POST", "/v1/init", R"({"mode": "operator", "k": 4, "n": 3})").status == 400U);
    BOOST_TEST(call("POST", "/v1/init", R"({"mode": "hybrid", "k": 2, "n": 3})").status == 400U);
    BOOST_TEST(call("POST", "/v1/init", R"({"k": 2})").status == 400U);
    BOOST_TEST(call("GET", "/v1/init").status == 405U);
    const auto r = call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})");
    BOOST_REQUIRE(r.status == 200U);
    const auto shares = shares_of(json(r));
    BOOST_TEST(shares.size() == 3U);
    BOOST_TEST(json(r).at("generation").to_number<int>() == 1);
    BOOST_TEST(vault.sealed());
    BOOST_REQUIRE(store.catalog().has_value());
    BOOST_TEST(store.catalog()->k == 2);
    const auto again = call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})");
    BOOST_TEST(again.status == 409U);
    BOOST_TEST(json(again).at("error") == "already_initialized");
    BOOST_TEST(!json(again).contains("shares"));
}

BOOST_FIXTURE_TEST_CASE(single_share_needs_the_development_flag, fixture) {
    hsm::key_vault v;
    hsm::admin_policy policy{{k_operator}};
    policy.allow_single_share = true;
    hsm::admin_api<admin_host> dev{host, v, policy};
    const auto r =
        dev.handle({"POST", "/v1/init", R"({"mode": "operator", "k": 1, "n": 1})", {k_operator}});
    BOOST_REQUIRE(r.status == 200U);
    const auto shares = shares_of(json(r));
    BOOST_REQUIRE(shares.size() == 1U);
    BOOST_TEST(json(dev.handle({"POST", "/v1/unseal", unseal_body(shares[0]), {k_operator}}))
                   .at("sealed") == false);
}

BOOST_FIXTURE_TEST_CASE(unseal_takes_k_shares_one_at_a_time, fixture) {
    BOOST_TEST(call("POST", "/v1/unseal", unseal_body("khs1-00")).status == 409U);  // no catalog
    const auto shares =
        shares_of(json(call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})")));
    BOOST_TEST(call("POST", "/v1/unseal", R"({"key": 1})").status == 400U);
    BOOST_TEST(json(call("POST", "/v1/unseal", unseal_body("khs1-00"))).at("error") ==
               "malformed_share");
    const auto first = json(call("POST", "/v1/unseal", unseal_body(shares[2])));
    BOOST_TEST(first.at("sealed") == true);
    BOOST_TEST(first.at("unseal_received").to_number<int>() == 1);
    BOOST_TEST(first.at("unseal_needed").to_number<int>() == 2);
    BOOST_TEST(json(call("GET", "/v1/status")).at("unseal_received").to_number<int>() == 1);
    BOOST_TEST(call("POST", "/v1/unseal", unseal_body(shares[2])).status == 409U);  // duplicate
    // An operator can discard what was entered.
    BOOST_TEST(call("DELETE", "/v1/unseal").status == 200U);
    BOOST_TEST(json(call("GET", "/v1/status")).at("unseal_received").to_number<int>() == 0);
    BOOST_TEST(json(call("POST", "/v1/unseal", unseal_body(shares[0]))).at("sealed") == true);
    const auto last = json(call("POST", "/v1/unseal", unseal_body(shares[1])));
    BOOST_TEST(last.at("sealed") == false);
    BOOST_TEST(!vault.sealed());
    BOOST_TEST(call("POST", "/v1/tokens", R"({"id": 2, "label": "after"})").status == 201U);
}

BOOST_FIXTURE_TEST_CASE(seal_reaches_every_node, fixture) {
    other_node peer(host);
    const auto shares =
        shares_of(json(call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})")));
    for (const auto& s : {shares[0], shares[1]}) {
        (void)call("POST", "/v1/unseal", unseal_body(s));
        (void)peer.call("POST", "/v1/unseal", unseal_body(s));
    }
    BOOST_REQUIRE(!vault.sealed());
    BOOST_REQUIRE(!peer.vault.sealed());
    // The module's hook (session_layer::seal) runs on both paths.
    int here = 0;
    int there = 0;
    api.set_seal_hook([&] {
        ++here;
        vault.seal();
    });
    peer.api.set_seal_hook([&] {
        ++there;
        peer.vault.seal();
    });
    BOOST_TEST(!peer.api.maintain());
    BOOST_TEST(call("POST", "/v1/seal").status == 200U);
    BOOST_TEST(vault.sealed());
    BOOST_TEST(here == 1);
    BOOST_TEST(store.catalog()->seal_epoch == 1U);
    // The other node seals itself on its next maintenance pass.
    BOOST_TEST(!peer.vault.sealed());
    BOOST_TEST(peer.api.maintain());
    BOOST_TEST(peer.vault.sealed());
    BOOST_TEST(there == 1);
    // And the same shares unseal again.
    (void)call("POST", "/v1/unseal", unseal_body(shares[2]));
    BOOST_TEST(json(call("POST", "/v1/unseal", unseal_body(shares[0]))).at("sealed") == false);
    BOOST_TEST(!api.maintain());
}

BOOST_FIXTURE_TEST_CASE(rekey_keeps_tokens_and_retires_old_shares, fixture) {
    other_node peer(host);
    BOOST_TEST(call("POST", "/v1/rekey").status == 409U);  // not initialized
    const auto old_shares =
        shares_of(json(call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})")));
    BOOST_TEST(call("POST", "/v1/rekey").status == 503U);  // sealed
    for (const auto& s : {old_shares[0], old_shares[1]}) {
        (void)call("POST", "/v1/unseal", unseal_body(s));
        (void)peer.call("POST", "/v1/unseal", unseal_body(s));
    }
    BOOST_REQUIRE(call("POST", "/v1/tokens", R"({"id": 4, "label": "ca"})").status == 201U);
    const auto tk_before = vault.with_token_key(
        *store.token(4), [](auto tk) { return std::vector<std::uint8_t>(tk.begin(), tk.end()); });
    BOOST_REQUIRE(tk_before.has_value());

    BOOST_TEST(call("POST", "/v1/rekey", R"({"k": 5})").status == 400U);  // k > n
    const auto r = call("POST", "/v1/rekey", R"({"k": 3, "n": 4})");
    BOOST_REQUIRE(r.status == 200U);
    const auto new_shares = shares_of(json(r));
    BOOST_TEST(new_shares.size() == 4U);
    BOOST_TEST(store.catalog()->generation == 2U);
    BOOST_TEST(store.catalog()->k == 3);
    BOOST_TEST(store.token(4)->generation == 2U);
    // This node holds the new key; the token key under it is the same.
    BOOST_TEST(!vault.sealed());
    const auto tk_after = vault.with_token_key(
        *store.token(4), [](auto tk) { return std::vector<std::uint8_t>(tk.begin(), tk.end()); });
    BOOST_REQUIRE(tk_after.has_value());
    BOOST_TEST(*tk_after == *tk_before);
    // The other node held the old key, which opens nothing now: it seals,
    // and its status says so at once, before any maintenance pass (an
    // operator reading "unsealed" here would skip the unseal it needs).
    BOOST_TEST(!peer.vault.sealed());
    BOOST_TEST(json(peer.call("GET", "/v1/status")).at("sealed") == true);
    BOOST_TEST(peer.vault.sealed());
    BOOST_TEST(!peer.api.maintain());
    BOOST_TEST(json(peer.call("POST", "/v1/unseal", unseal_body(old_shares[0]))).at("error") ==
               "wrong_split");
    for (const auto& s : {new_shares[3], new_shares[0]}) {
        BOOST_TEST(json(peer.call("POST", "/v1/unseal", unseal_body(s))).at("sealed") == true);
    }
    BOOST_TEST(json(peer.call("POST", "/v1/unseal", unseal_body(new_shares[1]))).at("sealed") ==
               false);
    BOOST_TEST(peer.vault.with_token_key(*store.token(4), [](auto) { return 0; }).has_value());
}

BOOST_FIXTURE_TEST_CASE(uncertain_commits_still_hand_out_the_shares, fixture) {
    store.fail_proposals = true;
    const auto r = call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})");
    BOOST_TEST(r.status == 503U);
    BOOST_TEST(shares_of(json(r)).size() == 3U);
    BOOST_TEST(json(r).at("error") == "unavailable");
    store.fail_proposals = false;
    initialize();
    unseal();
    store.fail_proposals = true;
    const auto rk = call("POST", "/v1/rekey");
    BOOST_TEST(rk.status == 503U);
    BOOST_TEST(shares_of(json(rk)).size() == 3U);
    BOOST_TEST(json(rk).at("generation").to_number<int>() == 2);
    BOOST_TEST(call("POST", "/v1/seal").status == 503U);
    BOOST_TEST(!vault.sealed());  // the seal did not commit, so nothing changed here
}

// Task 14 (Requirement 11.1): init, unseal, seal, tokens and bindings each
// give an audit event naming the operator and the result; a refused caller
// does too; reads do not; no event carries a share.
BOOST_FIXTURE_TEST_CASE(operator_actions_are_audited, fixture) {
    std::vector<hsm::audit_event> events;
    api.set_audit_hook([&](const hsm::audit_event& e) { events.push_back(e); });
    const auto shares =
        shares_of(json(call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})")));
    (void)call("POST", "/v1/unseal", unseal_body(shares[0]));
    (void)call("POST", "/v1/unseal", unseal_body(shares[1]));
    (void)call("GET", "/v1/status");
    (void)call("POST", "/v1/tokens", R"({"id": 3, "label": "ca"})");
    (void)call("PUT", "/v1/tokens/3/bindings/app");
    (void)call("DELETE", "/v1/tokens/3/bindings/app");
    (void)call("POST", "/v1/seal", "", {"spiffe://apps/payments"});
    (void)call("POST", "/v1/seal");
    std::vector<std::string> actions;
    for (const auto& e : events) {
        actions.emplace_back(e.action);
        const auto line = hsm::audit_line(e, 1);
        for (const auto& s : shares) {
            BOOST_TEST(line.find(s) == std::string::npos);
        }
    }
    BOOST_TEST(actions == (std::vector<std::string>{"init", "unseal", "unseal", "create_token",
                                                    "bind", "unbind", "seal", "seal"}),
               boost::test_tools::per_element());
    BOOST_REQUIRE(events.size() == 8U);
    BOOST_TEST(events[0].identity == k_operator);
    BOOST_TEST(events[0].rv == CKR_OK);
    BOOST_TEST(events[4].token.value_or(0) == 3U);
    BOOST_TEST(events[6].identity == "spiffe://apps/payments");
    BOOST_TEST(events[6].http_status == 403U);
    BOOST_TEST(events[6].rv == CKR_USER_NOT_LOGGED_IN);
    BOOST_TEST(events[7].rv == CKR_OK);
}
