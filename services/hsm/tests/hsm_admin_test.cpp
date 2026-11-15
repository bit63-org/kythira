// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The HSM's operator API (.kiro/specs/virtual-hsm/ task 6d) over the
// direct store: only operators get in, the status reflects the catalog and
// the vault, tokens are created sealed under the master key and only on an
// unsealed node, bindings take percent-encoded identities, and each
// refusal from the catalog maps to its HTTP status.

#define BOOST_TEST_MODULE hsm_admin_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_store.hpp"

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
    auto propose_catalog(std::vector<std::byte> cmd) {
        return store.propose_catalog(std::move(cmd));
    }
    [[nodiscard]] static auto fits(std::uint64_t id) -> bool { return id != 0 && id <= 1000; }
    [[nodiscard]] static auto leads(std::uint64_t /*local*/) -> bool { return true; }
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
