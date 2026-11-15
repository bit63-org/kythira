// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The Kinesis module's settings in kythira_node
// (.kiro/specs/service-colocation/ task 5, Requirements 8.1 and 8.2): the
// node's KYTHIRA_NODE_* settings fill in what the module's own variables
// leave unset, the data directory is always the node's kinesis/, and the
// stand-alone daemon reads exactly what it always has.

#define BOOST_TEST_MODULE kinesis_node_config_test

#include <boost/test/unit_test.hpp>

#include "config.hpp"

#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace kn = kythira::kinesis_node;
namespace sn = kythira::service_node;

namespace {

auto lookup(std::map<std::string, std::string> vars) -> sn::env_lookup {
    return [vars = std::move(vars)](std::string_view name) -> std::optional<std::string> {
        const auto it = vars.find(std::string(name));
        if (it == vars.end() || it->second.empty()) {
            return std::nullopt;
        }
        return it->second;
    };
}

auto node_vars() -> std::map<std::string, std::string> {
    return {
        {"KYTHIRA_NODE_ID", "2"},
        {"KYTHIRA_NODE_PEERS", "1=10.0.0.1:7400,2=10.0.0.2:7400,3=10.0.0.3:7400"},
        {"KYTHIRA_NODE_DATA_DIR", "/var/lib/kythira"},
        {"KYTHIRA_NODE_RAFT_BIND", "0.0.0.0"},
        {"KYTHIRA_NODE_TLS_CERT", "/etc/kythira/node.pem"},
        {"KYTHIRA_NODE_TLS_KEY", "/etc/kythira/node.key"},
        {"KYTHIRA_NODE_TLS_CA", "/etc/kythira/ca.pem"},
        {"KINESIS_STATIC_KEYS_FILE", "/etc/kythira/kinesis-keys"},
        {"KINESIS_FORWARD_SECRET", "0123456789abcdef0123"},
    };
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_node_settings_fill_in) {
    const auto o = kn::from_env(kn::composite_env(lookup(node_vars())));
    BOOST_TEST(kythira::host_node_id_text(o._node_id) == "2");
    BOOST_TEST(o._data_dir.string() == "/var/lib/kythira/kinesis");
    BOOST_TEST(o._peers.size() == 3U);
    BOOST_TEST(o._peers.at(o._node_id) == "https://10.0.0.2:7400");
    BOOST_TEST(o._raft_port == 7400);
    // The node's mutual TLS: the API's certificate and the peers' CA.
    BOOST_TEST(o._tls_cert_path == "/etc/kythira/node.pem");
    BOOST_TEST(o._tls_key_path == "/etc/kythira/node.key");
    BOOST_TEST(o._peer_ca_path == "/etc/kythira/ca.pem");
    BOOST_TEST(!o._allow_plaintext);
    // Raft is the node's listener: the daemon's plaintext guard is off,
    // even bound off loopback.
    BOOST_TEST(o._allow_plaintext_raft);
    // The peer gateways default to each Raft host with this node's API port.
    BOOST_TEST(o._peer_gateways.size() == 3U);
    for (const auto& [id, gw] : o._peer_gateways) {
        BOOST_TEST(gw.ends_with(":4567"));
    }
}

BOOST_AUTO_TEST_CASE(the_module_variables_win) {
    auto vars = node_vars();
    vars["KINESIS_TLS_CERT"] = "/etc/kinesis/api.pem";
    vars["KINESIS_TLS_KEY"] = "/etc/kinesis/api.key";
    vars["KINESIS_PEER_CA"] = "/etc/kinesis/ca.pem";
    vars["KYTHIRA_PEERS"] = "1=https://k1:7400,2=https://k2:7400";
    const auto o = kn::from_env(kn::composite_env(lookup(vars)));
    BOOST_TEST(o._tls_cert_path == "/etc/kinesis/api.pem");
    BOOST_TEST(o._peer_ca_path == "/etc/kinesis/ca.pem");
    BOOST_TEST(o._peers.size() == 2U);
}

BOOST_AUTO_TEST_CASE(the_data_directory_is_always_the_nodes) {
    auto vars = node_vars();
    vars["KINESIS_DATA_DIR"] = "/somewhere/else";
    const auto o = kn::from_env(kn::composite_env(lookup(vars)));
    BOOST_TEST(o._data_dir.string() == "/var/lib/kythira/kinesis");
}

BOOST_AUTO_TEST_CASE(a_plaintext_node_serves_http) {
    auto vars = node_vars();
    vars.erase("KYTHIRA_NODE_TLS_CERT");
    vars.erase("KYTHIRA_NODE_TLS_KEY");
    vars.erase("KYTHIRA_NODE_TLS_CA");
    vars["KYTHIRA_NODE_INSECURE_PLAINTEXT"] = "1";
    const auto o = kn::from_env(kn::composite_env(lookup(vars)));
    BOOST_TEST(o._allow_plaintext);
    BOOST_TEST(o._tls_cert_path.empty());
    for (const auto& [id, url] : o._peers) {
        BOOST_TEST(url.starts_with("http://"));
    }
}

BOOST_AUTO_TEST_CASE(stand_alone_reads_the_daemons_variables) {
    // The module interface's lookup over the daemon's own variables: no
    // KYTHIRA_NODE_* fallback, and KINESIS_DATA_DIR as given.
    const auto o = kn::from_env(lookup({
        {"KYTHIRA_NODE_ID", "1"},
        {"KYTHIRA_PEERS", "1=http://127.0.0.1:7001"},
        {"KYTHIRA_RAFT_BIND", "127.0.0.1"},
        {"KINESIS_ALLOW_PLAINTEXT", "true"},
        {"KINESIS_STATIC_KEYS_FILE", "/k"},
        {"KINESIS_DATA_DIR", "/data/kinesis-1"},
        {"KYTHIRA_NODE_TLS_CERT", "/ignored.pem"},
    }));
    BOOST_TEST(o._data_dir.string() == "/data/kinesis-1");
    BOOST_TEST(o._raft_port == 7000);
    BOOST_TEST(o._tls_cert_path.empty());
    BOOST_TEST(!o._allow_plaintext_raft);
    // Off loopback without the opt-in, the daemon still refuses plaintext
    // Raft.
    BOOST_CHECK_THROW(kn::from_env(lookup({{"KYTHIRA_NODE_ID", "1"},
                                           {"KYTHIRA_PEERS", "1=http://10.0.0.1:7001"},
                                           {"KINESIS_ALLOW_PLAINTEXT", "true"},
                                           {"KINESIS_STATIC_KEYS_FILE", "/k"},
                                           {"KINESIS_DATA_DIR", "/d"}})),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(a_composite_node_without_a_data_directory_is_refused) {
    auto vars = node_vars();
    vars.erase("KYTHIRA_NODE_DATA_DIR");
    BOOST_CHECK_EXCEPTION(kn::from_env(kn::composite_env(lookup(vars))), std::invalid_argument,
                          [](const std::invalid_argument& e) {
                              return std::string_view(e.what()).find("KINESIS_DATA_DIR") !=
                                     std::string_view::npos;
                          });
}

// The tier store's settings (.kiro/specs/kinesis-compatible-streams/ task
// 10): a provider per KINESIS_TIER_PROVIDER, the provider-neutral names
// beside the older S3 ones, and every refusal before anything starts.
namespace {

auto tier_vars() -> std::map<std::string, std::string> {
    return {
        {"KYTHIRA_NODE_ID", "1"},           {"KYTHIRA_PEERS", "1=http://127.0.0.1:7001"},
        {"KYTHIRA_RAFT_BIND", "127.0.0.1"}, {"KINESIS_ALLOW_PLAINTEXT", "true"},
        {"KINESIS_STATIC_KEYS_FILE", "/k"}, {"KINESIS_DATA_DIR", "/d"},
        {"KINESIS_TIER_AFTER_HOURS", "1"},
    };
}

auto refused_naming(std::map<std::string, std::string> vars, std::string_view text) -> bool {
    try {
        (void)kn::from_env(lookup(std::move(vars)));
    } catch (const std::invalid_argument& e) {
        if (std::string_view(e.what()).find(text) != std::string_view::npos) {
            return true;
        }
        BOOST_TEST_MESSAGE("refused, but with: " << e.what());
        return false;
    }
    return false;
}

}  // namespace

BOOST_AUTO_TEST_CASE(tiering_needs_a_bucket_and_names_the_provider_neutral_variable) {
    BOOST_TEST(refused_naming(tier_vars(), "needs KINESIS_TIER_BUCKET"));
}

BOOST_AUTO_TEST_CASE(an_unknown_tier_provider_is_refused_with_the_known_ones) {
    auto vars = tier_vars();
    vars["KINESIS_TIER_PROVIDER"] = "swift";
    vars["KINESIS_TIER_BUCKET"] = "b";
    BOOST_TEST(refused_naming(vars, "s3, azure-blob, gcs, oci-objectstorage, oss"));
    // Even with tiering off: a typo should not wait until someone turns it on.
    vars.erase("KINESIS_TIER_BUCKET");
    vars.erase("KINESIS_TIER_AFTER_HOURS");
    BOOST_TEST(refused_naming(vars, "KINESIS_TIER_PROVIDER"));
}

BOOST_AUTO_TEST_CASE(a_provider_missing_from_the_build_is_refused_naming_what_enables_it) {
    for (const char* provider : {"s3", "azure-blob", "gcs", "oci-objectstorage", "oss"}) {
        const auto support = kn::tier_provider_support(provider);
        BOOST_TEST_CONTEXT(provider) {
            if (support._available) {
                BOOST_TEST(support._needs.empty());
                continue;
            }
            BOOST_TEST(!support._needs.empty());
            auto vars = tier_vars();
            vars["KINESIS_TIER_PROVIDER"] = provider;
            vars["KINESIS_TIER_BUCKET"] = "b";
            vars["KINESIS_TIER_AZURE_ACCOUNT"] = "acct";
            BOOST_TEST(refused_naming(vars, std::string(support._needs)));
        }
    }
    BOOST_TEST(!kn::tier_provider_support("swift")._available);
    BOOST_TEST(kn::tier_provider_support("swift")._needs.empty());
}

BOOST_AUTO_TEST_CASE(the_older_s3_spellings_still_work_and_may_not_disagree) {
    if (!kn::tier_provider_support("s3")._available) {
        BOOST_TEST_MESSAGE("no S3 tier in this build; the spellings are checked where there is");
        return;
    }
    auto vars = tier_vars();
    vars["KINESIS_TIER_S3_BUCKET"] = "segments";
    vars["KINESIS_TIER_S3_PREFIX"] = "k/";
    vars["KINESIS_TIER_S3_ENDPOINT"] = "http://mock:9000";
    const auto o = kn::from_env(lookup(vars));
    BOOST_TEST(o._tier_provider == "s3");
    BOOST_TEST(o._tier_bucket == "segments");
    BOOST_TEST(o._tier_prefix == "k/");
    BOOST_TEST(o._tier_endpoint == "http://mock:9000");
    // The same value under both names is fine; different values are not.
    vars["KINESIS_TIER_BUCKET"] = "segments";
    BOOST_TEST(kn::from_env(lookup(vars))._tier_bucket == "segments");
    vars["KINESIS_TIER_BUCKET"] = "other";
    BOOST_TEST(refused_naming(vars, "KINESIS_TIER_BUCKET and KINESIS_TIER_S3_BUCKET"));
}

BOOST_AUTO_TEST_CASE(provider_specific_settings_are_refused_on_the_wrong_provider) {
    for (const char* provider : {"azure-blob", "gcs", "oci-objectstorage", "oss"}) {
        if (!kn::tier_provider_support(provider)._available) {
            continue;
        }
        BOOST_TEST_CONTEXT(provider) {
            auto vars = tier_vars();
            vars["KINESIS_TIER_PROVIDER"] = provider;
            vars["KINESIS_TIER_BUCKET"] = "b";
            vars["KINESIS_TIER_AZURE_ACCOUNT"] = "acct";
            vars["KINESIS_TIER_S3_REGION"] = "us-west-2";
            BOOST_TEST(refused_naming(vars, "applies only to KINESIS_TIER_PROVIDER=s3"));
        }
    }
    for (const char* provider : {"oci-objectstorage", "oss"}) {
        if (!kn::tier_provider_support(provider)._available) {
            continue;
        }
        BOOST_TEST_CONTEXT(provider) {
            auto vars = tier_vars();
            vars["KINESIS_TIER_PROVIDER"] = provider;
            vars["KINESIS_TIER_BUCKET"] = "b";
            vars["KINESIS_TIER_ENDPOINT"] = "https://elsewhere";
            BOOST_TEST(refused_naming(vars, "does not apply to"));
        }
    }
}

BOOST_AUTO_TEST_CASE(azure_needs_its_storage_account) {
    if (!kn::tier_provider_support("azure-blob")._available) {
        BOOST_TEST_MESSAGE("no Azure tier in this build");
        return;
    }
    auto vars = tier_vars();
    vars["KINESIS_TIER_PROVIDER"] = "azure-blob";
    vars["KINESIS_TIER_BUCKET"] = "container";
    BOOST_TEST(refused_naming(vars, "KINESIS_TIER_AZURE_ACCOUNT"));
    // The account the rest of Kythira reads serves as the default ...
    vars["KYTHIRA_AZURE_STORAGE_ACCOUNT"] = "shared";
    BOOST_TEST(kn::from_env(lookup(vars))._tier_azure_account == "shared");
    // ... the module's own wins ...
    vars["KINESIS_TIER_AZURE_ACCOUNT"] = "mine";
    BOOST_TEST(kn::from_env(lookup(vars))._tier_azure_account == "mine");
    // ... and an endpoint naming the whole origin (Azurite) needs neither.
    vars.erase("KINESIS_TIER_AZURE_ACCOUNT");
    vars.erase("KYTHIRA_AZURE_STORAGE_ACCOUNT");
    vars["KINESIS_TIER_ENDPOINT"] = "http://azurite:10000/devstoreaccount1";
    BOOST_TEST(kn::from_env(lookup(vars))._tier_endpoint ==
               "http://azurite:10000/devstoreaccount1");
}

// Virtual HSM task 13: KINESIS_KMS=pkcs11 names a token and its PIN; the
// library is the URI's module-path or the co-located HSM.
BOOST_AUTO_TEST_CASE(the_pkcs11_key_provider_settings) {
    auto vars = node_vars();
    vars["KINESIS_KMS"] = "pkcs11";
    vars["KINESIS_KMS_PKCS11_URI"] = "pkcs11:token=kinesis?pin-source=/run/secrets/pin";
    auto o = kn::from_env(kn::composite_env(lookup(vars)));
    BOOST_TEST(o._kms == "pkcs11");
    BOOST_TEST(o._kms_pkcs11_identity == "kinesis");
    BOOST_TEST(o._kms_pkcs11_oaep == "sha256");

    vars["KINESIS_KMS_PKCS11_IDENTITY"] = "streams";
    vars["KINESIS_KMS_PKCS11_OAEP"] = "sha1";
    o = kn::from_env(kn::composite_env(lookup(vars)));
    BOOST_TEST(o._kms_pkcs11_identity == "streams");
    BOOST_TEST(o._kms_pkcs11_oaep == "sha1");

    for (const std::string_view uri :
         {"", "pkcs11:object=key?pin-source=/p", "pkcs11:token=kinesis", "pkcs11:token=a;token=b",
          "not a uri"}) {
        BOOST_TEST_CONTEXT("URI '" << uri << "'") {
            vars["KINESIS_KMS_PKCS11_URI"] = std::string(uri);
            BOOST_CHECK_THROW((void)kn::from_env(kn::composite_env(lookup(vars))),
                              std::invalid_argument);
        }
    }
    vars["KINESIS_KMS_PKCS11_URI"] = "pkcs11:token=kinesis?pin-value=1234";
    vars["KINESIS_KMS_PKCS11_OAEP"] = "sha512";
    BOOST_CHECK_THROW((void)kn::from_env(kn::composite_env(lookup(vars))), std::invalid_argument);
}
