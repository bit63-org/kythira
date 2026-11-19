// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hsm-independent-layers task 1 (Requirements 1.1, 2.1-2.5, 6): the HSM
// module's configuration for each role set: what each needs, what each
// refuses, and that a node without KYTHIRA_HSM_ROLES reads as before.

#define BOOST_TEST_MODULE hsm_node_config_test
#include <boost/test/unit_test.hpp>

#include "hsm_config.hpp"

#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace hn = kythira::hsm_node;
namespace hsm = kythira::hsm;

namespace {

using vars = std::map<std::string, std::string, std::less<>>;

/// A plaintext two-member cluster seen from node 1.
auto base() -> vars {
    return {{"KYTHIRA_NODE_ID", "1"},
            {"KYTHIRA_HSM_DATA_DIR", "/tmp/hsm-config-test"},
            {"KYTHIRA_HSM_INSECURE_PLAINTEXT", "true"},
            {"KYTHIRA_HSM_API_URLS", "1=http://a:9443,2=http://b:9443"},
            {"KYTHIRA_HSM_OPERATORS", "spiffe://op"}};
}

auto read(const vars& v) -> hn::hsm_options {
    return hn::from_env([&v](std::string_view name) -> std::optional<std::string> {
        const auto it = v.find(name);
        return it == v.end() ? std::nullopt : std::optional<std::string>(it->second);
    });
}

/// The text from_env throws for `v`; empty when it reads.
auto refusal(const vars& v) -> std::string {
    try {
        (void)read(v);
    } catch (const std::invalid_argument& e) {
        return e.what();
    }
    return {};
}

auto with(vars v, const std::string& name, const std::string& value) -> vars {
    v[name] = value;
    return v;
}

}  // namespace

BOOST_AUTO_TEST_CASE(unset_roles_read_as_before) {
    const auto o = read(base());
    BOOST_TEST((o.roles == hsm::all_hsm_roles()));
    BOOST_TEST(o.relay_backends.empty());
    BOOST_TEST(o.store_clients.empty());
    BOOST_TEST(o.crypto_urls.empty());
    BOOST_TEST(!o.client_listen.has_value());  // plaintext: the socket only, as before
    BOOST_TEST((read(with(base(), "KYTHIRA_HSM_ROLES", "endpoint,crypto,store")).roles ==
                hsm::all_hsm_roles()));
}

BOOST_AUTO_TEST_CASE(a_store_member_reads_and_refuses_crypto_settings) {
    auto v = with(base(), "KYTHIRA_HSM_ROLES", "store");
    v["KYTHIRA_HSM_STORE_CLIENTS"] = "spiffe://crypto-a, spiffe://crypto-b";
    const auto o = read(v);
    BOOST_TEST(!hsm::hsm_role_plan{o.roles}.runs_crypto());
    BOOST_TEST(o.store_clients.size() == 2U);
    BOOST_TEST(o.store_clients.contains("spiffe://crypto-a"));

    // It must still be among the members, and serves no socket.
    BOOST_TEST(refusal(with(v, "KYTHIRA_HSM_API_URLS", "2=http://b:9443")).find("own id") !=
               std::string::npos);
    auto socket = with(v, "KYTHIRA_HSM_SOCKET", "/tmp/hsm.sock");
    socket["KYTHIRA_HSM_SOCKET_ALLOW"] = "0=root";
    BOOST_TEST(refusal(socket).find("KYTHIRA_HSM_SOCKET") != std::string::npos);
    BOOST_TEST(refusal(with(v, "KYTHIRA_HSM_RELAY_BACKENDS", "c:9444"))
                   .find("only an endpoint without the crypto role relays") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(an_endpoint_needs_backends_and_is_no_member) {
    auto v = with(base(), "KYTHIRA_HSM_ROLES", "endpoint");
    v["KYTHIRA_HSM_API_URLS"] = "2=http://b:9443,3=http://c:9443";
    BOOST_TEST(refusal(v).find("KYTHIRA_HSM_RELAY_BACKENDS") != std::string::npos);

    v["KYTHIRA_HSM_RELAY_BACKENDS"] = "b:9444, c:9445";
    v["KYTHIRA_HSM_CLIENT_LISTEN"] = "127.0.0.1:0";
    const auto o = read(v);
    BOOST_TEST(o.relay_backends.size() == 2U);
    BOOST_TEST(o.relay_backends[1].first == "c");
    BOOST_TEST(o.relay_backends[1].second == 9445);
    // Plaintext does not turn the relay's listener off: it never sees TLS.
    BOOST_REQUIRE(o.client_listen.has_value());
    BOOST_TEST(o.client_listen->first == "127.0.0.1");

    BOOST_TEST(refusal(with(v, "KYTHIRA_HSM_CLIENT_LISTEN", "off")).find("relays clients") !=
               std::string::npos);
    BOOST_TEST(refusal(with(v, "KYTHIRA_HSM_API_URLS", "1=http://a:9443,2=http://b:9443"))
                   .find("no member") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(an_endpoint_beside_a_store_member_relays_too) {
    auto v = with(base(), "KYTHIRA_HSM_ROLES", "store,endpoint");
    v["KYTHIRA_HSM_RELAY_BACKENDS"] = "c:9444";
    const auto o = read(v);
    const hsm::hsm_role_plan plan{o.roles};
    BOOST_TEST(plan.runs_store());
    BOOST_TEST(plan.relays_clients());
    BOOST_TEST(o.client_listen.has_value());
}

BOOST_AUTO_TEST_CASE(a_crypto_node_without_store_waits_for_the_remote_store_wiring) {
    auto v = with(base(), "KYTHIRA_HSM_ROLES", "crypto");
    v["KYTHIRA_HSM_API_URLS"] = "2=http://b:9443";
    BOOST_TEST(refusal(v).find("not wired into hsm_node yet") != std::string::npos);
    BOOST_TEST(refusal(with(base(), "KYTHIRA_HSM_ROLES", "crypto,vault")).find("\"vault\"") !=
               std::string::npos);
    BOOST_TEST(refusal(with(base(), "KYTHIRA_HSM_ROLES", "")).find("names no role") !=
               std::string::npos);
}

BOOST_AUTO_TEST_CASE(crypto_urls_take_identities_that_hold_equals_signs) {
    auto v = with(base(), "KYTHIRA_HSM_CRYPTO_URLS",
                  "kythira://hsm/prod/1?roles=front_end=http://a:9443,"
                  "spiffe://crypto-b=http://b:9443");
    const auto o = read(v);
    BOOST_TEST(o.crypto_urls.size() == 2U);
    BOOST_TEST(o.crypto_urls.at("kythira://hsm/prod/1?roles=front_end") == "http://a:9443");
    BOOST_TEST(o.crypto_urls.at("spiffe://crypto-b") == "http://b:9443");

    BOOST_TEST(refusal(with(base(), "KYTHIRA_HSM_CRYPTO_URLS", "spiffe://x=https://a:1"))
                   .find("is not an http://") != std::string::npos);
    BOOST_TEST(
        refusal(with(base(), "KYTHIRA_HSM_CRYPTO_URLS", "spiffe://x")).find("expects identity=") !=
        std::string::npos);
    BOOST_TEST(refusal(with(base(), "KYTHIRA_HSM_CRYPTO_URLS",
                            "spiffe://x=http://a:1,spiffe://x=http://b:1"))
                   .find("twice") != std::string::npos);
}
