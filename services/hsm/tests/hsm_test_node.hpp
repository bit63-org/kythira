// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A node for session-layer tests: an initialized, unsealed vault over the
// direct store, two tokens bound to two identities, and a client logged in
// as the user of the first on a read-write session.

#include "hsm_test_store.hpp"

#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/native_client.hpp>
#include <kythira/hsm/session_layer.hpp>
#include <kythira/hsm/shamir.hpp>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::hsm::test {

namespace hsm = kythira::hsm;

inline constexpr std::uint64_t k_token = 1;
inline constexpr std::uint64_t k_other_token = 2;
inline const std::string k_so_pin = "so-secret";
inline const std::string k_user_pin = "user-1234";
inline const hsm::bytes k_p256 = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

inline auto rv(const auto& result) -> CK_RV {
    return result ? CKR_OK : result.error();
}

inline auto data(std::string_view s) -> std::vector<std::uint8_t> {
    return {s.begin(), s.end()};
}

inline auto options() -> hsm::session_options {
    hsm::session_options o;
    o.pin_log2_n = 10;  // fast tests; the cost is stored per verifier
    o.max_login_failures = 3;
    o.max_operation_bytes = 4096;
    return o;
}

inline auto aes_template(bool token, CK_ULONG len = 32) -> hsm::attribute_map {
    hsm::attribute_map t;
    t.set_bool(CKA_TOKEN, token);
    t.set_ulong(CKA_VALUE_LEN, len);
    t.set_bool(CKA_ENCRYPT, true);
    t.set_bool(CKA_DECRYPT, true);
    return t;
}

inline const CK_MECHANISM k_aes_gen{CKM_AES_KEY_GEN, nullptr, 0};
inline const CK_MECHANISM k_ec_gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
inline const CK_MECHANISM k_ecdsa{CKM_ECDSA_SHA256, nullptr, 0};
inline const CK_MECHANISM k_sha256{CKM_SHA256, nullptr, 0};

/// An initialized, unsealed node with one token bound to "app-a", whose SO
/// and user PINs are set, and a client logged in as the user on a
/// read-write session.
struct node {
    hsm::test::direct_store store;
    hsm::key_vault vault;
    hsm::session_layer layer{store, vault, options()};
    hsm::secret_bytes mk{32};
    std::unique_ptr<hsm::native_client> client;
    CK_SESSION_HANDLE session = 0;

    node() {
        BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value());
        const auto check = hsm::key_check_value(mk.view());
        BOOST_REQUIRE(propose_catalog(hsm::make_initialize_command(
                          hsm::unseal_mode::operator_shares, 2, 3, check)) == CKR_OK);
        BOOST_REQUIRE(vault.unseal(mk.clone(), store.catalog()) == hsm::unseal_result::unsealed);
        add_token(k_token, "alpha", "app-a");
        add_token(k_other_token, "beta", "app-b");
        client = std::make_unique<hsm::native_client>(layer, "app-a");
        BOOST_REQUIRE(rv(client->init_token(k_token, k_so_pin, "alpha")) == CKR_OK);
        auto s = client->open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        BOOST_REQUIRE(s.has_value());
        session = *s;
        BOOST_REQUIRE(rv(client->login(session, CKU_SO, k_so_pin)) == CKR_OK);
        BOOST_REQUIRE(rv(client->init_pin(session, k_user_pin)) == CKR_OK);
        BOOST_REQUIRE(rv(client->logout(session)) == CKR_OK);
        BOOST_REQUIRE(rv(client->login(session, CKU_USER, k_user_pin)) == CKR_OK);
    }

    auto propose_catalog(std::vector<std::byte> cmd) -> CK_RV {
        auto r = store.propose_catalog(std::move(cmd));
        BOOST_REQUIRE(r.has_value());
        return hsm::catalog_reply_rv(*r);
    }

    void add_token(std::uint64_t id, const std::string& label, const std::string& identity) {
        auto t = hsm::prepare_token(mk.view(), 1, id, label);
        BOOST_REQUIRE(propose_catalog(hsm::make_create_token_command(t.entry)) == CKR_OK);
        BOOST_REQUIRE(propose_catalog(hsm::make_bind_command(identity, id)) == CKR_OK);
    }

    auto ec_pair(bool token = true) -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> {
        hsm::attribute_map pub;
        pub.set_bool(CKA_TOKEN, token);
        pub.set_bytes(CKA_EC_PARAMS, k_p256);
        pub.set_bool(CKA_VERIFY, true);
        hsm::attribute_map priv;
        priv.set_bool(CKA_TOKEN, token);
        priv.set_bool(CKA_SIGN, true);
        auto pair = client->generate_key_pair(session, k_ec_gen, pub, priv);
        BOOST_REQUIRE(pair.has_value());
        return *pair;
    }

    auto aes_key(bool token = true) -> CK_OBJECT_HANDLE {
        auto k = client->generate_key(session, k_aes_gen, aes_template(token));
        BOOST_REQUIRE(k.has_value());
        return *k;
    }

    auto sign(CK_OBJECT_HANDLE key, std::string_view msg) -> hsm::ck_result<hsm::bytes> {
        if (auto r = client->sign_init(session, k_ecdsa, key); !r) {
            return unexpected(r.error());
        }
        return client->sign(session, data(msg));
    }
};

}  // namespace kythira::hsm::test
