// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/kms-independent-layers/ task 3 (Requirements 1.1, 2.1-2.4
// and 4.2): KYTHIRA_KMS_ROLES and the settings that follow from it. No
// setting means every layer, as before; a role set the node cannot serve
// stops it at start with the reason; only data nodes are catalog members
// and only front ends hold the HSM PIN or read with bounded staleness.

#define BOOST_TEST_MODULE kms_node_config_test

#include "kms_config.hpp"

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>

namespace fs = std::filesystem;
namespace kn = kythira::kms_node;
using kythira::layers::role;

namespace {

/// A plaintext three-member node 1 with a PIN file; `set` overrides or
/// adds variables, and an empty value removes one.
class env_fixture {
public:
    env_fixture() {
        std::random_device rd;
        _dir = fs::temp_directory_path() / ("kythira-kms-config-" + std::to_string(rd()));
        fs::create_directories(_dir);
        std::ofstream(_dir / "pin") << "1234\n";
        _vars = {
            {"KYTHIRA_NODE_ID", "1"},
            {"KYTHIRA_KMS_DATA_DIR", (_dir / "kms").string()},
            {"KYTHIRA_KMS_INSECURE_PLAINTEXT", "1"},
            {"KYTHIRA_KMS_API_URLS", "1=http://a:1,2=http://b:1,3=http://c:1"},
            {"KYTHIRA_KMS_PIN_FILE", (_dir / "pin").string()},
        };
    }
    env_fixture(const env_fixture&) = delete;
    auto operator=(const env_fixture&) -> env_fixture& = delete;
    env_fixture(env_fixture&&) = delete;
    auto operator=(env_fixture&&) -> env_fixture& = delete;
    ~env_fixture() {
        std::error_code ec;
        fs::remove_all(_dir, ec);
    }

    auto set(const std::string& name, const std::string& value) -> env_fixture& {
        if (value.empty()) {
            _vars.erase(name);
        } else {
            _vars[name] = value;
        }
        return *this;
    }

    [[nodiscard]] auto options() const -> kn::kms_options {
        return kn::from_env([this](std::string_view n) -> std::optional<std::string> {
            const auto it = _vars.find(std::string(n));
            if (it == _vars.end()) {
                return std::nullopt;
            }
            return it->second;
        });
    }

    /// The fixture's PIN file.
    [[nodiscard]] auto options_pin() const -> std::string { return (_dir / "pin").string(); }

    /// The message from_env refuses with, or "" when it accepts.
    [[nodiscard]] auto refusal() const -> std::string {
        try {
            (void)options();
        } catch (const std::invalid_argument& e) {
            return e.what();
        }
        return {};
    }

private:
    fs::path _dir;
    std::map<std::string, std::string> _vars;
};

auto contains(const std::string& text, std::string_view part) -> bool {
    return text.find(part) != std::string::npos;
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(no_setting_runs_every_layer, env_fixture) {
    const auto o = options();
    BOOST_TEST(o.roles.to_string() == "gateway,front_end,data");
    BOOST_TEST((o.roles == kn::kms_roles));
    BOOST_TEST(o.bounded_staleness.count() == 0);
    BOOST_TEST(o.api_urls.size() == 3U);
}

BOOST_FIXTURE_TEST_CASE(the_role_sets_a_node_can_serve, env_fixture) {
    // The co-located set in any order, and a front end with its gateway
    // (and with or without data).
    for (const auto* roles :
         {"data,front_end,gateway", "gateway,front_end,data", "front_end,data", "data"}) {
        set("KYTHIRA_KMS_ROLES", roles);
        if (std::string_view(roles) == "data") {
            set("KYTHIRA_KMS_PIN_FILE", "");
        }
        BOOST_TEST(refusal().empty(), roles << ": " << refusal());
    }
}

BOOST_FIXTURE_TEST_CASE(role_sets_it_cannot_serve_stop_it_with_the_reason, env_fixture) {
    // A gateway without its own front end must know the front ends.
    set("KYTHIRA_KMS_ROLES", "gateway").set("KYTHIRA_KMS_PIN_FILE", "");
    set("KYTHIRA_NODE_ID", "9");
    BOOST_TEST(contains(refusal(), "needs KYTHIRA_KMS_FRONT_END_URLS"));
    set("KYTHIRA_NODE_ID", "1").set("KYTHIRA_KMS_ROLES", "gateway,data");
    BOOST_TEST(contains(refusal(), "needs KYTHIRA_KMS_FRONT_END_URLS"));
    set("KYTHIRA_KMS_PIN_FILE", options_pin());
    set("KYTHIRA_KMS_ROLES", "front_end,segments");
    BOOST_TEST(contains(refusal(), "segments is Kinesis's"));
    set("KYTHIRA_KMS_ROLES", "frontend");
    BOOST_TEST(contains(refusal(), "KYTHIRA_KMS_ROLES: unknown layer role \"frontend\""));
    set("KYTHIRA_KMS_ROLES", "data,data");
    BOOST_TEST(contains(refusal(), "listed twice"));
    set("KYTHIRA_KMS_ROLES", "data,");
    BOOST_TEST(contains(refusal(), "KYTHIRA_KMS_ROLES"));
}

// Requirement 2.2: the catalog's members are the data nodes.
BOOST_FIXTURE_TEST_CASE(only_data_nodes_are_catalog_members, env_fixture) {
    set("KYTHIRA_KMS_ROLES", "gateway,front_end");
    BOOST_TEST(contains(refusal(), "a node without the data role is not a catalog member"));
    set("KYTHIRA_NODE_ID", "4");
    const auto o = options();
    BOOST_TEST(!o.roles.has(role::data));
    BOOST_TEST(o.api_urls.size() == 3U);  // the data nodes it reads from

    set("KYTHIRA_KMS_ROLES", "data").set("KYTHIRA_KMS_PIN_FILE", "");
    BOOST_TEST(contains(refusal(), "must include this node's own id"));
}

// Requirement 2.3: the HSM PIN is the front end's alone.
BOOST_FIXTURE_TEST_CASE(only_front_ends_hold_the_pin, env_fixture) {
    set("KYTHIRA_KMS_ROLES", "data");
    BOOST_TEST(contains(refusal(), "a node without the front_end role holds no HSM PIN"));
    set("KYTHIRA_KMS_PIN_FILE", "");
    BOOST_TEST(options().pin_file.empty());

    set("KYTHIRA_KMS_ROLES", "front_end,data");
    BOOST_TEST(contains(refusal(), "missing required env var KYTHIRA_KMS_PIN_FILE"));
}

// Requirement 4.2: off by default, a front end's choice.
BOOST_FIXTURE_TEST_CASE(bounded_staleness_is_a_front_end_switch, env_fixture) {
    set("KYTHIRA_KMS_BOUNDED_STALENESS_MS", "250");
    BOOST_TEST(options().bounded_staleness.count() == 250);
    set("KYTHIRA_KMS_ROLES", "data").set("KYTHIRA_KMS_PIN_FILE", "");
    BOOST_TEST(contains(refusal(), "only a front end reads key metadata"));
    set("KYTHIRA_KMS_BOUNDED_STALENESS_MS", "soon");
    BOOST_TEST(contains(refusal(), "must be a number of milliseconds"));
}

// Task 4: a gateway apart from the front end (Requirement 6.1).
BOOST_FIXTURE_TEST_CASE(a_gateway_alone_hands_calls_to_the_listed_front_ends, env_fixture) {
    set("KYTHIRA_NODE_ID", "9").set("KYTHIRA_KMS_ROLES", "gateway").set("KYTHIRA_KMS_PIN_FILE", "");
    set("KYTHIRA_KMS_FRONT_END_URLS", "4=http://fe-4:1,5=http://fe-5:1");
    // It reaches no catalog, so the data nodes need not be listed.
    set("KYTHIRA_KMS_API_URLS", "");
    auto o = options();
    BOOST_TEST(o.roles.to_string() == "gateway");
    BOOST_TEST(o.front_end_urls.size() == 2U);
    BOOST_TEST(o.api_urls.empty());
    BOOST_TEST(o.pin_file.empty());

    // It holds no PIN (Requirement 2.3) and is no front end.
    set("KYTHIRA_KMS_PIN_FILE", "/some/pin");
    BOOST_TEST(contains(refusal(), "holds no HSM PIN"));
    set("KYTHIRA_KMS_PIN_FILE", "");
    set("KYTHIRA_KMS_FRONT_END_URLS", "9=http://self:1,4=http://fe-4:1");
    BOOST_TEST(contains(refusal(), "but it runs no front end"));
    set("KYTHIRA_KMS_FRONT_END_URLS", "4=https://fe-4:1");
    BOOST_TEST(contains(refusal(), "is not an http:// URL"));

    // A front end that lists the front ends lists itself among them: the
    // live ones share the quotas.
    set("KYTHIRA_NODE_ID", "4").set("KYTHIRA_KMS_ROLES", "front_end");
    set("KYTHIRA_KMS_PIN_FILE", options_pin());
    set("KYTHIRA_KMS_API_URLS", "1=http://a:1");
    set("KYTHIRA_KMS_FRONT_END_URLS", "5=http://fe-5:1");
    BOOST_TEST(contains(refusal(), "must include this front end's own id 4"));
    set("KYTHIRA_KMS_FRONT_END_URLS", "4=http://fe-4:1,5=http://fe-5:1");
    o = options();
    BOOST_TEST(o.front_end_urls.size() == 2U);
    BOOST_TEST(o.front_end_probe.count() == 1000);
    // A front end without the data role still needs the data nodes.
    set("KYTHIRA_KMS_API_URLS", "");
    BOOST_TEST(contains(refusal(), "KYTHIRA_KMS_API_URLS"));
}

BOOST_FIXTURE_TEST_CASE(layer_identities_name_the_cluster, env_fixture) {
    BOOST_TEST(options().cluster == "default");
    set("KYTHIRA_CLUSTER", "prod-east");
    BOOST_TEST(options().cluster == "prod-east");
    set("KYTHIRA_KMS_CLUSTER", "kms-east");
    BOOST_TEST(options().cluster == "kms-east");
    set("KYTHIRA_KMS_CLUSTER", "bad/name");
    BOOST_TEST(contains(refusal(), "KYTHIRA_KMS_CLUSTER"));
    set("KYTHIRA_KMS_CLUSTER", "").set("KYTHIRA_KMS_FRONT_END_PROBE_MS", "0");
    BOOST_TEST(contains(refusal(), "KYTHIRA_KMS_FRONT_END_PROBE_MS must be at least 1"));
}

BOOST_AUTO_TEST_CASE(usage_names_the_new_settings) {
    const auto u = std::string(kn::usage_text());
    for (const auto* name :
         {"KYTHIRA_KMS_ROLES", "KYTHIRA_KMS_BOUNDED_STALENESS_MS", "KYTHIRA_KMS_JOB_LEASE_MS",
          "KYTHIRA_KMS_FRONT_END_URLS", "KYTHIRA_KMS_FRONT_END_PROBE_MS", "KYTHIRA_KMS_CLUSTER"}) {
        BOOST_TEST(contains(u, name), name);
    }
}
