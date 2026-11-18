// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hsm-independent-layers task 1 (Requirements 1.1, 2.1-2.5):
// KYTHIRA_HSM_ROLES, what each role set runs, and the start-time check.

#define BOOST_TEST_MODULE hsm_roles_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/hsm_roles.hpp>

#include <raft/layer_identity.hpp>

#include <ostream>
#include <stdexcept>
#include <string>

namespace hsm = kythira::hsm;
using kythira::layers::role;
using kythira::layers::role_set;

namespace kythira::layers {
// Boost.Test prints a failed comparison's operands.
inline auto operator<<(std::ostream& os, role_set s) -> std::ostream& {
    return os << '{' << s.to_string() << '}';
}
}  // namespace kythira::layers

namespace {

auto inputs(std::string_view roles) -> hsm::hsm_role_inputs {
    hsm::hsm_role_inputs in;
    in.roles = hsm::parse_hsm_roles(roles);
    return in;
}

auto contains(const std::optional<std::string>& text, std::string_view part) -> bool {
    return text.has_value() && text->find(part) != std::string::npos;
}

}  // namespace

BOOST_AUTO_TEST_CASE(names_parse_both_ways_and_map_onto_the_shared_bits) {
    BOOST_TEST(hsm::parse_hsm_roles("endpoint,crypto,store") == hsm::all_hsm_roles());
    BOOST_TEST(hsm::parse_hsm_roles(" store , crypto ") == (role_set{role::front_end, role::data}));
    BOOST_TEST(hsm::parse_hsm_roles("endpoint") == role_set{role::gateway});
    BOOST_TEST(hsm::hsm_role_names(hsm::parse_hsm_roles("store,endpoint")) == "endpoint,store");
    BOOST_TEST(hsm::hsm_role_names(hsm::all_hsm_roles()) == "endpoint,crypto,store");
    BOOST_TEST(!hsm::all_hsm_roles().has(role::segments));

    // The shared names layer identities carry.
    BOOST_TEST(hsm::parse_hsm_roles("crypto").to_string() == "front_end");
    const auto id = kythira::layers::identity::parse_uri("kythira://hsm/prod/7?roles=front_end");
    BOOST_REQUIRE(id.has_value());
    BOOST_TEST(hsm::hsm_role_names(id->roles) == "crypto");
}

BOOST_AUTO_TEST_CASE(bad_values_name_what_is_wrong) {
    for (const auto* bad : {"", "  ", "crypto,", ",store", "crypto,,store", "Crypto", "gateway",
                            "front_end", "data", "segments", "store,store"}) {
        BOOST_TEST_CONTEXT("value \"" << bad << "\"") {
            BOOST_CHECK_THROW((void)hsm::parse_hsm_roles(bad), std::invalid_argument);
        }
    }
    try {
        (void)hsm::parse_hsm_roles("crypto,vault");
        BOOST_FAIL("vault parsed");
    } catch (const std::invalid_argument& e) {
        BOOST_TEST(std::string(e.what()).find("\"vault\"") != std::string::npos);
    }
    try {
        (void)hsm::parse_hsm_roles("store,store");
        BOOST_FAIL("store twice parsed");
    } catch (const std::invalid_argument& e) {
        BOOST_TEST(std::string(e.what()).find("twice") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(each_set_runs_only_its_layers) {
    const hsm::hsm_role_plan all{};
    BOOST_TEST(all.co_located());
    BOOST_TEST(all.runs_crypto());
    BOOST_TEST(all.runs_store());
    BOOST_TEST(!all.uses_remote_store());
    BOOST_TEST(!all.relays_clients());

    const hsm::hsm_role_plan store{hsm::parse_hsm_roles("store")};
    BOOST_TEST(!store.runs_crypto());  // no vault, unseal, share or wire listener
    BOOST_TEST(store.runs_store());
    BOOST_TEST(!store.relays_clients());

    const hsm::hsm_role_plan crypto{hsm::parse_hsm_roles("crypto")};
    BOOST_TEST(crypto.runs_crypto());
    BOOST_TEST(!crypto.runs_store());  // no engine, no Raft log, no group membership
    BOOST_TEST(crypto.uses_remote_store());

    const hsm::hsm_role_plan endpoint{hsm::parse_hsm_roles("endpoint")};
    BOOST_TEST(endpoint.relays_clients());
    BOOST_TEST(!endpoint.runs_crypto());
    BOOST_TEST(!endpoint.runs_store());

    // Endpoint beside crypto serves its own clients, as a co-located node.
    const hsm::hsm_role_plan front{hsm::parse_hsm_roles("endpoint,crypto")};
    BOOST_TEST(!front.relays_clients());
    BOOST_TEST(front.uses_remote_store());
}

BOOST_AUTO_TEST_CASE(the_default_needs_nothing_new) {
    // Requirement 1.1: unset is all three, and a co-located node's settings
    // are checked exactly as before.
    BOOST_TEST(!hsm::check_hsm_roles(hsm::hsm_role_inputs{}).has_value());
    BOOST_TEST(!hsm::check_hsm_roles(inputs("endpoint,crypto,store")).has_value());
}

BOOST_AUTO_TEST_CASE(a_set_the_node_cannot_serve_stops_it_with_the_reason) {
    BOOST_TEST(
        contains(hsm::check_hsm_roles(hsm::hsm_role_inputs{.roles = role_set{}}), "names no role"));
    BOOST_TEST(contains(hsm::check_hsm_roles(hsm::hsm_role_inputs{
                            .roles = role_set{role::front_end, role::segments}}),
                        "segments"));

    auto crypto = inputs("crypto");
    BOOST_TEST(contains(hsm::check_hsm_roles(crypto), "KYTHIRA_HSM_API_URLS"));
    BOOST_TEST(contains(hsm::check_hsm_roles(crypto), "KYTHIRA_HSM_ROLES=crypto: "));
    crypto.has_store_urls = true;
    BOOST_TEST(contains(hsm::check_hsm_roles(crypto), "mutual TLS"));
    crypto.has_peer_tls = true;
    BOOST_TEST(!hsm::check_hsm_roles(crypto).has_value());

    auto endpoint = inputs("endpoint");
    BOOST_TEST(contains(hsm::check_hsm_roles(endpoint), "KYTHIRA_HSM_RELAY_BACKENDS"));
    endpoint.has_relay_backends = true;
    BOOST_TEST(!hsm::check_hsm_roles(endpoint).has_value());

    auto store = inputs("store");
    BOOST_TEST(contains(hsm::check_hsm_roles(store), "KYTHIRA_PEERS"));
    store.has_raft_peers = true;
    BOOST_TEST(contains(hsm::check_hsm_roles(store), "store API"));
    store.has_peer_tls = true;
    BOOST_TEST(!hsm::check_hsm_roles(store).has_value());

    // A store node with an endpoint in front still relays to crypto nodes.
    auto relay_store = inputs("endpoint,store");
    relay_store.has_raft_peers = true;
    relay_store.has_peer_tls = true;
    BOOST_TEST(contains(hsm::check_hsm_roles(relay_store), "KYTHIRA_HSM_RELAY_BACKENDS"));
    relay_store.has_relay_backends = true;
    BOOST_TEST(!hsm::check_hsm_roles(relay_store).has_value());

    // Crypto beside store reads its own replica: no store URLs needed.
    auto both = inputs("crypto,store");
    both.has_raft_peers = true;
    BOOST_TEST(!hsm::check_hsm_roles(both).has_value());
}
