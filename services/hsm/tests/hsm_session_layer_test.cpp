// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 6, requirements 2.3, 3.4, 3.5, 4.7, 7.1-7.3 and 8.2: the key vault,
// the session layer and the native client over a store applied to
// directly: applications, bindings, sessions and logins, replicated PIN
// counters, token and session objects, the read-index check before every
// use, the key cache, multi-part operations and sealing.

#define BOOST_TEST_MODULE hsm_session_layer_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_store.hpp"

#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/native_client.hpp>
#include <kythira/hsm/session_layer.hpp>
#include <kythira/hsm/shamir.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace hsm = kythira::hsm;

namespace kythira::hsm {
inline auto operator<<(std::ostream& os, unseal_result r) -> std::ostream& {
    return os << static_cast<int>(r);
}
}  // namespace kythira::hsm

namespace {

constexpr std::uint64_t k_token = 1;
constexpr std::uint64_t k_other_token = 2;
const std::string k_so_pin = "so-secret";
const std::string k_user_pin = "user-1234";
const hsm::bytes k_p256 = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

auto rv(const auto& result) -> CK_RV {
    return result ? CKR_OK : result.error();
}

auto data(std::string_view s) -> std::vector<std::uint8_t> {
    return {s.begin(), s.end()};
}

auto options() -> hsm::session_options {
    hsm::session_options o;
    o.pin_log2_n = 10;  // fast tests; the cost is stored per verifier
    o.max_login_failures = 3;
    o.max_operation_bytes = 4096;
    return o;
}

auto aes_template(bool token, CK_ULONG len = 32) -> hsm::attribute_map {
    hsm::attribute_map t;
    t.set_bool(CKA_TOKEN, token);
    t.set_ulong(CKA_VALUE_LEN, len);
    t.set_bool(CKA_ENCRYPT, true);
    t.set_bool(CKA_DECRYPT, true);
    return t;
}

const CK_MECHANISM k_aes_gen{CKM_AES_KEY_GEN, nullptr, 0};
const CK_MECHANISM k_ec_gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
const CK_MECHANISM k_ecdsa{CKM_ECDSA_SHA256, nullptr, 0};
const CK_MECHANISM k_sha256{CKM_SHA256, nullptr, 0};

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
            return hsm::unexpected(r.error());
        }
        return client->sign(session, data(msg));
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(the_vault_takes_only_the_catalogs_master_key) {
    hsm::test::direct_store store;
    hsm::key_vault vault;
    hsm::secret_bytes mk(32);
    BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value());
    BOOST_TEST(vault.unseal(mk.clone(), store.catalog()) == hsm::unseal_result::not_initialized);
    const auto check = hsm::key_check_value(mk.view());
    BOOST_REQUIRE(store
                      .propose_catalog(hsm::make_initialize_command(
                          hsm::unseal_mode::operator_shares, 2, 3, check))
                      .has_value());
    hsm::secret_bytes wrong(32);
    BOOST_REQUIRE(hsm::generate_random(wrong.span()).has_value());
    const auto refused = vault.unseal(std::move(wrong), store.catalog());
    BOOST_TEST(refused == hsm::unseal_result::wrong_key);
    BOOST_TEST(vault.sealed());

    const auto e0 = vault.epoch();
    BOOST_TEST(vault.unseal(mk.clone(), store.catalog()) == hsm::unseal_result::unsealed);
    BOOST_TEST(!vault.sealed());
    BOOST_TEST(vault.generation() == 1U);
    BOOST_TEST(vault.epoch() > e0);

    auto t = hsm::prepare_token(mk.view(), 1, 7, "t");
    auto opened = vault.with_token_key(t.entry, [&](std::span<const std::uint8_t> tk) {
        return hsm::constant_time_equal(tk, t.tk.view());
    });
    BOOST_REQUIRE(opened.has_value());
    BOOST_TEST(*opened);
    // A token key sealed under another MK generation does not open.
    auto stale = t.entry;
    stale.generation = 2;
    BOOST_TEST(rv(vault.with_token_key(stale, [](auto) { return true; })) == CKR_DEVICE_ERROR);
    // Nor does one whose sealed bytes were altered.
    auto bad = hsm::prepare_token(mk.view(), 1, 8, "u").entry;
    bad.sealed_tk.back() ^= 1U;
    BOOST_TEST(rv(vault.with_token_key(bad, [](auto) { return true; })) == CKR_DEVICE_ERROR);

    vault.seal();
    BOOST_TEST(vault.sealed());
    BOOST_TEST(vault.generation() == 0U);
    BOOST_TEST(rv(vault.with_token_key(t.entry, [](auto) { return true; })) == CKR_DEVICE_ERROR);
    BOOST_TEST(rv(vault.with_master_key([](auto) { return true; })) == CKR_DEVICE_ERROR);
}

BOOST_AUTO_TEST_CASE(tokens_not_bound_to_the_identity_are_not_present) {
    node n;
    BOOST_TEST(n.client->get_slot_list() == std::vector<CK_SLOT_ID>{k_token});
    BOOST_TEST(rv(n.client->get_token_info(k_other_token)) == CKR_TOKEN_NOT_PRESENT);
    BOOST_TEST(rv(n.client->open_session(k_other_token, CKF_SERIAL_SESSION)) ==
               CKR_TOKEN_NOT_PRESENT);
    // A token that does not exist answers the same, so binding is not an
    // oracle for which tokens exist.
    BOOST_TEST(rv(n.client->get_token_info(99)) == CKR_TOKEN_NOT_PRESENT);

    hsm::native_client stranger(n.layer, "nobody");
    BOOST_TEST(stranger.get_slot_list().empty());
    BOOST_TEST(rv(stranger.open_session(k_token, CKF_SERIAL_SESSION)) == CKR_TOKEN_NOT_PRESENT);
    // Another client cannot use a session it does not own.
    BOOST_TEST(rv(stranger.get_session_info(n.session)) == CKR_SESSION_HANDLE_INVALID);

    auto info = n.client->get_token_info(k_token);
    BOOST_REQUIRE(info.has_value());
    BOOST_TEST(info->label == "alpha");
    BOOST_TEST((info->flags & CKF_TOKEN_INITIALIZED) != 0U);
    BOOST_TEST((info->flags & CKF_USER_PIN_INITIALIZED) != 0U);
    BOOST_TEST(info->session_count == 1U);
    BOOST_TEST(info->rw_session_count == 1U);
}

BOOST_AUTO_TEST_CASE(session_states_follow_pkcs11) {
    node n;
    auto& c = *n.client;
    BOOST_TEST(rv(c.open_session(k_token, 0)) == CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    auto info = c.get_session_info(n.session);
    BOOST_REQUIRE(info.has_value());
    BOOST_TEST(info->state == CKS_RW_USER_FUNCTIONS);

    auto ro = c.open_session(k_token, CKF_SERIAL_SESSION);
    BOOST_REQUIRE(ro.has_value());
    // The login is the application's: the new session shares it.
    BOOST_TEST(c.get_session_info(*ro)->state == CKS_RO_USER_FUNCTIONS);
    BOOST_TEST(rv(c.login(*ro, CKU_USER, k_user_pin)) == CKR_USER_ALREADY_LOGGED_IN);
    BOOST_TEST(rv(c.login(*ro, CKU_SO, k_so_pin)) == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
    BOOST_TEST(rv(c.logout(*ro)) == CKR_OK);
    BOOST_TEST(c.get_session_info(n.session)->state == CKS_RW_PUBLIC_SESSION);
    BOOST_TEST(rv(c.logout(*ro)) == CKR_USER_NOT_LOGGED_IN);
    // The SO cannot log in while a read-only session is open.
    BOOST_TEST(rv(c.login(n.session, CKU_SO, k_so_pin)) == CKR_SESSION_READ_ONLY_EXISTS);
    BOOST_TEST(rv(c.close_session(*ro)) == CKR_OK);
    BOOST_TEST(rv(c.close_session(*ro)) == CKR_SESSION_HANDLE_INVALID);
    BOOST_TEST(rv(c.login(n.session, CKU_SO, k_so_pin)) == CKR_OK);
    BOOST_TEST(c.get_session_info(n.session)->state == CKS_RW_SO_FUNCTIONS);
    BOOST_TEST(rv(c.open_session(k_token, CKF_SERIAL_SESSION)) == CKR_SESSION_READ_WRITE_SO_EXISTS);

    // Closing the last session on the token logs the application out.
    BOOST_TEST(rv(c.close_all_sessions(k_token)) == CKR_OK);
    auto again = c.open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(c.get_session_info(*again)->state == CKS_RW_PUBLIC_SESSION);

    // Destroying the client is C_Finalize: its sessions close.
    const auto before = n.layer.session_count();
    {
        hsm::native_client other(n.layer, "app-a");
        BOOST_REQUIRE(other.open_session(k_token, CKF_SERIAL_SESSION).has_value());
        BOOST_TEST(n.layer.session_count() == before + 1);
    }
    BOOST_TEST(n.layer.session_count() == before);
}

BOOST_AUTO_TEST_CASE(pin_failures_are_counted_in_the_token_group_and_lock) {
    node n;
    auto& c = *n.client;
    BOOST_REQUIRE(rv(c.logout(n.session)) == CKR_OK);
    BOOST_TEST(rv(c.login(n.session, CKU_USER, "wrong-pin")) == CKR_PIN_INCORRECT);
    auto rec = n.store.token_record_of(k_token);
    BOOST_REQUIRE(rec.has_value());
    BOOST_TEST(rec->user_failures == 1U);
    BOOST_TEST((c.get_token_info(k_token)->flags & CKF_USER_PIN_COUNT_LOW) != 0U);
    BOOST_TEST(rv(c.login(n.session, CKU_USER, "wrong-pin")) == CKR_PIN_INCORRECT);
    BOOST_TEST((c.get_token_info(k_token)->flags & CKF_USER_PIN_FINAL_TRY) != 0U);
    BOOST_TEST(rv(c.login(n.session, CKU_USER, "wrong-pin")) == CKR_PIN_LOCKED);
    // Locked: the right PIN no longer logs in.
    BOOST_TEST(rv(c.login(n.session, CKU_USER, k_user_pin)) == CKR_PIN_LOCKED);
    BOOST_TEST((c.get_token_info(k_token)->flags & CKF_USER_PIN_LOCKED) != 0U);

    // The lock is decided in log order: a replica that has not applied it
    // still learns it from the reply to the outcome it proposes.
    const auto before = n.store.proposals;
    BOOST_TEST(rv(c.login(n.session, CKU_SO, k_so_pin)) == CKR_OK);
    BOOST_TEST(n.store.proposals == before + 1);  // successes are recorded too

    // The SO's C_InitPIN unlocks the user.
    BOOST_TEST(rv(c.init_pin(n.session, "user-5678")) == CKR_OK);
    BOOST_TEST(rv(c.logout(n.session)) == CKR_OK);
    BOOST_TEST(rv(c.login(n.session, CKU_USER, "user-5678")) == CKR_OK);
    BOOST_TEST(n.store.token_record_of(k_token)->user_failures == 0U);

    // C_SetPIN checks the old PIN (a wrong one counts) and the length.
    BOOST_TEST(rv(c.set_pin(n.session, "nope-nope", "user-9999")) == CKR_PIN_INCORRECT);
    BOOST_TEST(n.store.token_record_of(k_token)->user_failures == 1U);
    BOOST_TEST(rv(c.set_pin(n.session, "user-5678", "abc")) == CKR_PIN_LEN_RANGE);
    BOOST_TEST(rv(c.set_pin(n.session, "user-5678", "user-9999")) == CKR_OK);
    BOOST_TEST(rv(c.logout(n.session)) == CKR_OK);
    BOOST_TEST(rv(c.login(n.session, CKU_USER, "user-9999")) == CKR_OK);

    // Only the SO, on a read-write session, sets the user PIN.
    BOOST_TEST(rv(c.init_pin(n.session, "user-0000")) == CKR_USER_NOT_LOGGED_IN);
}

BOOST_AUTO_TEST_CASE(no_pin_or_verifier_is_in_any_entry) {
    node n;
    for (const auto& entry : n.store.log) {
        const std::string text(reinterpret_cast<const char*>(entry.data()), entry.size());
        BOOST_TEST(text.find(k_so_pin) == std::string::npos);
        BOOST_TEST(text.find(k_user_pin) == std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(token_keys_are_generated_sealed_and_used) {
    node n;
    auto& c = *n.client;
    const auto key = n.aes_key();
    BOOST_TEST(key <= hsm::max_token_object_handle);
    auto stored = n.store.object(k_token, key);
    BOOST_REQUIRE(stored.has_value());
    BOOST_TEST(!stored->sealed.empty());
    BOOST_TEST(stored->attributes.flag(CKA_TOKEN));
    BOOST_TEST(stored->attributes.flag(CKA_PRIVATE));
    BOOST_TEST(stored->attributes.flag(CKA_SENSITIVE));

    std::array<std::uint8_t, 12> iv{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    CK_GCM_PARAMS gcm{iv.data(), iv.size(), 96, nullptr, 0, 128};
    const CK_MECHANISM mech{CKM_AES_GCM, &gcm, sizeof gcm};
    BOOST_REQUIRE(rv(c.encrypt_init(n.session, mech, key)) == CKR_OK);
    auto ct = c.encrypt(n.session, data("attack at dawn"));
    BOOST_REQUIRE(ct.has_value());
    BOOST_REQUIRE(rv(c.decrypt_init(n.session, mech, key)) == CKR_OK);
    auto pt = c.decrypt(n.session, *ct);
    BOOST_REQUIRE(pt.has_value());
    BOOST_TEST(std::ranges::equal(pt->view(), data("attack at dawn")));

    // Multi-part gives the same result.
    BOOST_REQUIRE(rv(c.encrypt_init(n.session, mech, key)) == CKR_OK);
    BOOST_REQUIRE(rv(c.encrypt_update(n.session, data("attack "))) == CKR_OK);
    BOOST_REQUIRE(rv(c.encrypt_update(n.session, data("at dawn"))) == CKR_OK);
    auto ct2 = c.encrypt_final(n.session);
    BOOST_REQUIRE(ct2.has_value());
    BOOST_TEST(*ct2 == *ct);

    // Not allowed to sign.
    BOOST_TEST(rv(c.sign_init(n.session, CK_MECHANISM{CKM_SHA256_HMAC, nullptr, 0}, key)) ==
               CKR_KEY_FUNCTION_NOT_PERMITTED);
}

BOOST_AUTO_TEST_CASE(operation_parameters_are_copied_at_init) {
    node n;
    auto& c = *n.client;
    const auto key = n.aes_key();
    std::vector<std::uint8_t> expected;
    {
        auto iv = std::make_unique<std::array<std::uint8_t, 12>>();
        iv->fill(7);
        CK_GCM_PARAMS gcm{iv->data(), iv->size(), 96, nullptr, 0, 128};
        const CK_MECHANISM mech{CKM_AES_GCM, &gcm, sizeof gcm};
        BOOST_REQUIRE(rv(c.encrypt_init(n.session, mech, key)) == CKR_OK);
        BOOST_REQUIRE(rv(c.encrypt_update(n.session, data("x"))) == CKR_OK);
        auto check = std::make_unique<std::array<std::uint8_t, 12>>();
        check->fill(7);
        // The caller's buffers are overwritten and freed before the final
        // call; the operation uses its own copy.
        iv->fill(0);
        gcm = CK_GCM_PARAMS{};
        iv.reset();
        auto out = c.encrypt_final(n.session);
        BOOST_REQUIRE(out.has_value());
        expected = *out;
        CK_GCM_PARAMS again{check->data(), check->size(), 96, nullptr, 0, 128};
        const CK_MECHANISM m2{CKM_AES_GCM, &again, sizeof again};
        BOOST_REQUIRE(rv(c.encrypt_init(n.session, m2, key)) == CKR_OK);
        auto direct = c.encrypt(n.session, data("x"));
        BOOST_REQUIRE(direct.has_value());
        BOOST_TEST(*direct == expected);
    }
}

BOOST_AUTO_TEST_CASE(key_pairs_sign_and_verify_single_and_multi_part) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    BOOST_TEST(n.store.object(k_token, pub).has_value());
    BOOST_TEST(n.store.object(k_token, priv).has_value());
    BOOST_TEST(n.store.object(k_token, pub)->sealed.empty());

    auto sig = n.sign(priv, "hello");
    BOOST_REQUIRE(sig.has_value());
    BOOST_REQUIRE(rv(c.verify_init(n.session, k_ecdsa, pub)) == CKR_OK);
    BOOST_TEST(rv(c.verify(n.session, data("hello"), *sig)) == CKR_OK);
    BOOST_REQUIRE(rv(c.verify_init(n.session, k_ecdsa, pub)) == CKR_OK);
    BOOST_TEST(rv(c.verify(n.session, data("hellO"), *sig)) == CKR_SIGNATURE_INVALID);

    BOOST_REQUIRE(rv(c.sign_init(n.session, k_ecdsa, priv)) == CKR_OK);
    BOOST_REQUIRE(rv(c.sign_update(n.session, data("hel"))) == CKR_OK);
    BOOST_REQUIRE(rv(c.sign_update(n.session, data("lo"))) == CKR_OK);
    auto sig2 = c.sign_final(n.session);
    BOOST_REQUIRE(sig2.has_value());
    BOOST_REQUIRE(rv(c.verify_init(n.session, k_ecdsa, pub)) == CKR_OK);
    BOOST_REQUIRE(rv(c.verify_update(n.session, data("hello"))) == CKR_OK);
    BOOST_TEST(rv(c.verify_final(n.session, *sig2)) == CKR_OK);

    // A public key does not sign.
    BOOST_TEST(rv(c.sign_init(n.session, k_ecdsa, pub)) == CKR_KEY_FUNCTION_NOT_PERMITTED);
}

BOOST_AUTO_TEST_CASE(every_use_waits_for_a_read_index_round) {
    node n;
    const auto [pub, priv] = n.ec_pair();
    const auto before = n.store.barriers;
    BOOST_REQUIRE(n.sign(priv, "a").has_value());
    BOOST_TEST(n.store.barriers == before + 1);
    BOOST_REQUIRE(n.sign(priv, "b").has_value());
    BOOST_TEST(n.store.barriers == before + 2);

    // No quorum: the call fails rather than answer from this replica.
    n.store.fail_barrier = true;
    BOOST_TEST(rv(n.sign(priv, "c")) == CKR_DEVICE_ERROR);
    n.store.fail_barrier = false;
}

BOOST_AUTO_TEST_CASE(a_key_destroyed_elsewhere_is_never_used_after_the_round) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    BOOST_REQUIRE(n.sign(priv, "warm the cache").has_value());
    BOOST_TEST(n.layer.cached_keys() == 1U);

    // Another node destroys the key after this session's C_SignInit and
    // before its C_Sign: the round sees the destroy, and the cached key is
    // dropped.
    BOOST_REQUIRE(rv(c.sign_init(n.session, k_ecdsa, priv)) == CKR_OK);
    n.store.before_barrier = [&] {
        n.store.apply_elsewhere(k_token, hsm::make_destroy_object_command(priv));
    };
    BOOST_TEST(rv(c.sign(n.session, data("late"))) == CKR_KEY_HANDLE_INVALID);
    BOOST_TEST(n.layer.cached_keys() == 0U);
    // The operation ended with the failure.
    BOOST_TEST(rv(c.sign(n.session, data("late"))) == CKR_OPERATION_NOT_INITIALIZED);
}

BOOST_AUTO_TEST_CASE(a_key_narrowed_elsewhere_is_refused_after_the_round) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    BOOST_REQUIRE(n.sign(priv, "ok").has_value());
    BOOST_REQUIRE(rv(c.sign_init(n.session, k_ecdsa, priv)) == CKR_OK);
    n.store.before_barrier = [&] {
        auto o = n.store.object(k_token, priv);
        BOOST_REQUIRE(o.has_value());
        hsm::attribute_map changes;
        changes.set_bool(CKA_SIGN, false);
        auto done =
            n.vault.with_token_key(*n.store.token(k_token), [&](std::span<const std::uint8_t> tk) {
                auto cmd =
                    hsm::prepare_set_attributes(tk, k_token, *o, changes, hsm::session_user::user);
                BOOST_REQUIRE(cmd.has_value());
                n.store.apply_elsewhere(k_token, *cmd);
                return true;
            });
        BOOST_REQUIRE(done.has_value());
    };
    BOOST_TEST(rv(c.sign(n.session, data("now"))) == CKR_KEY_FUNCTION_NOT_PERMITTED);
}

BOOST_AUTO_TEST_CASE(the_key_cache_follows_object_versions) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    BOOST_REQUIRE(n.sign(priv, "1").has_value());
    BOOST_TEST(n.layer.cached_keys() == 1U);
    hsm::attribute_map label;
    const auto text = data("renamed");
    label.set_bytes(CKA_LABEL, text);
    BOOST_REQUIRE(rv(c.set_attribute_value(n.session, priv, label)) == CKR_OK);
    BOOST_TEST(n.store.object(k_token, priv)->version == 2U);
    BOOST_TEST(n.layer.cached_keys() == 0U);
    // The re-sealed key still opens and signs.
    BOOST_REQUIRE(n.sign(priv, "2").has_value());
    BOOST_TEST(n.layer.cached_keys() == 1U);
    BOOST_REQUIRE(rv(c.destroy_object(n.session, priv)) == CKR_OK);
    BOOST_TEST(n.layer.cached_keys() == 0U);
    BOOST_TEST(!n.store.object(k_token, priv).has_value());
    BOOST_TEST(rv(c.destroy_object(n.session, priv)) == CKR_OBJECT_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(a_sealed_node_answers_device_error_to_cryptography) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    const auto session_key = n.aes_key(false);
    BOOST_REQUIRE(n.sign(priv, "before").has_value());
    n.layer.seal();
    BOOST_TEST(n.vault.sealed());
    BOOST_TEST(n.layer.cached_keys() == 0U);
    BOOST_TEST(rv(n.sign(priv, "after")) == CKR_DEVICE_ERROR);
    BOOST_TEST(rv(c.generate_key(n.session, k_aes_gen, aes_template(true))) == CKR_DEVICE_ERROR);
    BOOST_TEST(rv(c.generate_random(n.session, 16)) == CKR_DEVICE_ERROR);
    BOOST_TEST(rv(c.digest_init(n.session, k_sha256)) == CKR_DEVICE_ERROR);
    // Sessions and logins need no key.
    BOOST_TEST(rv(c.logout(n.session)) == CKR_OK);
    BOOST_TEST(rv(c.login(n.session, CKU_USER, k_user_pin)) == CKR_OK);
    // Session objects went with the keys.
    BOOST_TEST(rv(c.destroy_object(n.session, session_key)) == CKR_OBJECT_HANDLE_INVALID);

    BOOST_REQUIRE(n.vault.unseal(n.mk.clone(), n.store.catalog()) == hsm::unseal_result::unsealed);
    BOOST_TEST(n.sign(priv, "again").has_value());
}

BOOST_AUTO_TEST_CASE(session_objects_stay_on_the_node_and_end_with_their_session) {
    node n;
    auto& c = *n.client;
    const auto proposals = n.store.proposals;
    const auto key = n.aes_key(false);
    BOOST_TEST(key >= hsm::first_session_object_handle);
    BOOST_TEST(n.store.proposals == proposals);  // nothing replicated
    BOOST_TEST(n.store.objects(k_token).empty());

    std::array<std::uint8_t, 12> iv{};
    CK_GCM_PARAMS gcm{iv.data(), iv.size(), 96, nullptr, 0, 128};
    const CK_MECHANISM mech{CKM_AES_GCM, &gcm, sizeof gcm};
    BOOST_REQUIRE(rv(c.encrypt_init(n.session, mech, key)) == CKR_OK);
    BOOST_TEST(c.encrypt(n.session, data("x")).has_value());

    // Other sessions of the application see it; it ends with the session
    // that made it.
    auto other = c.open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    BOOST_REQUIRE(other.has_value());
    BOOST_TEST(rv(c.get_attribute_value(*other, key,
                                        std::array<CK_ATTRIBUTE_TYPE, 1>{CKA_CLASS})) == CKR_OK);
    BOOST_REQUIRE(rv(c.close_session(n.session)) == CKR_OK);
    BOOST_TEST(
        rv(c.get_attribute_value(*other, key, std::array<CK_ATTRIBUTE_TYPE, 1>{CKA_CLASS})) ==
        CKR_OBJECT_HANDLE_INVALID);

    // Another application never sees it.
    hsm::native_client b(n.layer, "app-a");
    auto bs = b.open_session(k_token, CKF_SERIAL_SESSION);
    BOOST_REQUIRE(bs.has_value());
    const auto again = n.client->generate_key(*other, k_aes_gen, aes_template(false));
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(
        rv(b.get_attribute_value(*bs, *again, std::array<CK_ATTRIBUTE_TYPE, 1>{CKA_CLASS})) ==
        CKR_OBJECT_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(private_objects_need_the_user_and_token_objects_a_rw_session) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    auto ro = c.open_session(k_token, CKF_SERIAL_SESSION);
    BOOST_REQUIRE(ro.has_value());
    BOOST_TEST(rv(c.generate_key(*ro, k_aes_gen, aes_template(true))) == CKR_SESSION_READ_ONLY);
    BOOST_TEST(rv(c.destroy_object(*ro, pub)) == CKR_SESSION_READ_ONLY);
    BOOST_TEST(c.generate_key(*ro, k_aes_gen, aes_template(false)).has_value());

    BOOST_REQUIRE(rv(c.logout(n.session)) == CKR_OK);
    // Public: the private key is invisible, the public key is not.
    BOOST_TEST(
        rv(c.get_attribute_value(n.session, priv, std::array<CK_ATTRIBUTE_TYPE, 1>{CKA_CLASS})) ==
        CKR_OBJECT_HANDLE_INVALID);
    BOOST_TEST(rv(c.get_attribute_value(n.session, pub,
                                        std::array<CK_ATTRIBUTE_TYPE, 1>{CKA_CLASS})) == CKR_OK);
    BOOST_TEST(rv(c.sign_init(n.session, k_ecdsa, priv)) == CKR_KEY_HANDLE_INVALID);
    BOOST_TEST(rv(c.generate_key(n.session, k_aes_gen, aes_template(true))) ==
               CKR_USER_NOT_LOGGED_IN);
    auto pub_only = aes_template(false);
    pub_only.set_bool(CKA_PRIVATE, false);
    BOOST_TEST(c.generate_key(n.session, k_aes_gen, pub_only).has_value());

    // A session logged out after C_SignInit cannot finish with the key.
    BOOST_REQUIRE(rv(c.login(n.session, CKU_USER, k_user_pin)) == CKR_OK);
    BOOST_REQUIRE(rv(c.sign_init(n.session, k_ecdsa, priv)) == CKR_OK);
    BOOST_REQUIRE(rv(c.logout(n.session)) == CKR_OK);
    BOOST_TEST(rv(c.sign(n.session, data("x"))) == CKR_KEY_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(find_objects_matches_templates_over_both_kinds) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    const auto aes = n.aes_key();
    const auto session_aes = n.aes_key(false);

    auto find = [&](const hsm::attribute_map& t) {
        BOOST_REQUIRE(rv(c.find_objects_init(n.session, t)) == CKR_OK);
        std::vector<CK_OBJECT_HANDLE> all;
        for (;;) {
            auto batch = c.find_objects(n.session, 2);
            BOOST_REQUIRE(batch.has_value());
            if (batch->empty()) {
                break;
            }
            all.insert(all.end(), batch->begin(), batch->end());
        }
        BOOST_REQUIRE(rv(c.find_objects_final(n.session)) == CKR_OK);
        std::ranges::sort(all);
        return all;
    };
    hsm::attribute_map secret;
    secret.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    auto expect = std::vector<CK_OBJECT_HANDLE>{aes, session_aes};
    std::ranges::sort(expect);
    BOOST_TEST(find(secret) == expect);
    hsm::attribute_map token;
    token.set_bool(CKA_TOKEN, true);
    expect = {pub, priv, aes};
    std::ranges::sort(expect);
    BOOST_TEST(find(token) == expect);
    BOOST_TEST(find(hsm::attribute_map{}).size() == 4U);

    BOOST_REQUIRE(rv(c.find_objects_init(n.session, secret)) == CKR_OK);
    BOOST_TEST(rv(c.find_objects_init(n.session, secret)) == CKR_OPERATION_ACTIVE);
    BOOST_REQUIRE(rv(c.find_objects_final(n.session)) == CKR_OK);
    BOOST_TEST(rv(c.find_objects(n.session, 1)) == CKR_OPERATION_NOT_INITIALIZED);
}

BOOST_AUTO_TEST_CASE(attributes_are_read_and_changed_under_the_rules) {
    node n;
    auto& c = *n.client;
    const auto sensitive = n.aes_key();
    auto open = aes_template(true, 16);
    open.set_bool(CKA_SENSITIVE, false);
    open.set_bool(CKA_EXTRACTABLE, true);
    auto readable = c.generate_key(n.session, k_aes_gen, open);
    BOOST_REQUIRE(readable.has_value());

    const std::array<CK_ATTRIBUTE_TYPE, 3> types{CKA_VALUE, CKA_KEY_TYPE, CKA_MODULUS};
    auto a = c.get_attribute_value(n.session, sensitive, types);
    BOOST_REQUIRE(a.has_value());
    BOOST_TEST((*a)[0].rv == CKR_ATTRIBUTE_SENSITIVE);
    BOOST_TEST(!(*a)[0].value.has_value());
    BOOST_TEST((*a)[1].rv == CKR_OK);
    BOOST_TEST((*a)[2].rv == CKR_ATTRIBUTE_TYPE_INVALID);
    auto b = c.get_attribute_value(n.session, *readable, types);
    BOOST_REQUIRE(b.has_value());
    BOOST_REQUIRE((*b)[0].value.has_value());
    BOOST_TEST((*b)[0].value->size() == 16U);

    hsm::attribute_map unsensitive;
    unsensitive.set_bool(CKA_SENSITIVE, false);
    BOOST_TEST(rv(c.set_attribute_value(n.session, sensitive, unsensitive)) ==
               CKR_ATTRIBUTE_READ_ONLY);
    hsm::attribute_map to_session;
    to_session.set_bool(CKA_TOKEN, false);
    BOOST_TEST(rv(c.set_attribute_value(n.session, sensitive, to_session)) ==
               CKR_ATTRIBUTE_READ_ONLY);
    auto ro = c.open_session(k_token, CKF_SERIAL_SESSION);
    BOOST_REQUIRE(ro.has_value());
    hsm::attribute_map label;
    const auto text = data("x");
    label.set_bytes(CKA_LABEL, text);
    BOOST_TEST(rv(c.set_attribute_value(*ro, sensitive, label)) == CKR_SESSION_READ_ONLY);
    BOOST_TEST(rv(c.set_attribute_value(n.session, sensitive, label)) == CKR_OK);
}

BOOST_AUTO_TEST_CASE(operation_state_follows_pkcs11) {
    node n;
    auto& c = *n.client;
    const auto [pub, priv] = n.ec_pair();
    BOOST_TEST(rv(c.sign(n.session, data("x"))) == CKR_OPERATION_NOT_INITIALIZED);
    BOOST_REQUIRE(rv(c.sign_init(n.session, k_ecdsa, priv)) == CKR_OK);
    BOOST_TEST(rv(c.sign_init(n.session, k_ecdsa, priv)) == CKR_OPERATION_ACTIVE);
    // A sign and a digest may run side by side.
    BOOST_REQUIRE(rv(c.digest_init(n.session, k_sha256)) == CKR_OK);
    BOOST_REQUIRE(rv(c.sign_update(n.session, data("x"))) == CKR_OK);
    // A single-part call after an update is refused and ends the operation.
    BOOST_TEST(rv(c.sign(n.session, data("x"))) == CKR_OPERATION_ACTIVE);
    BOOST_TEST(rv(c.sign_final(n.session)) == CKR_OPERATION_NOT_INITIALIZED);

    auto single = c.digest(n.session, data("abcdef"));
    BOOST_REQUIRE(single.has_value());
    BOOST_REQUIRE(rv(c.digest_init(n.session, k_sha256)) == CKR_OK);
    BOOST_REQUIRE(rv(c.digest_update(n.session, data("abc"))) == CKR_OK);
    BOOST_REQUIRE(rv(c.digest_update(n.session, data("def"))) == CKR_OK);
    auto multi = c.digest_final(n.session);
    BOOST_REQUIRE(multi.has_value());
    BOOST_TEST(*multi == *single);

    // Buffered input is bounded.
    BOOST_REQUIRE(rv(c.digest_init(n.session, k_sha256)) == CKR_OK);
    const std::vector<std::uint8_t> big(5000, 0x41);
    BOOST_TEST(rv(c.digest_update(n.session, big)) == CKR_DATA_LEN_RANGE);
    BOOST_TEST(rv(c.digest_final(n.session)) == CKR_OPERATION_NOT_INITIALIZED);

    // A mechanism that cannot do the operation.
    BOOST_TEST(rv(c.sign_init(n.session, k_sha256, priv)) == CKR_MECHANISM_INVALID);
    BOOST_TEST(rv(c.sign_init(n.session, k_ecdsa, 12345)) == CKR_KEY_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(init_token_needs_the_so_pin_and_no_sessions) {
    node n;
    auto& c = *n.client;
    const auto key = n.aes_key();
    BOOST_TEST(rv(c.init_token(k_token, k_so_pin, "again")) == CKR_SESSION_EXISTS);
    BOOST_REQUIRE(rv(c.close_all_sessions(k_token)) == CKR_OK);
    BOOST_TEST(rv(c.init_token(k_token, "not-the-pin", "again")) == CKR_PIN_INCORRECT);
    BOOST_TEST(rv(c.init_token(k_token, k_so_pin, "again   ")) == CKR_OK);
    BOOST_TEST(c.get_token_info(k_token)->label == "again");
    // Re-initializing destroys every object and the user PIN.
    BOOST_TEST(!n.store.object(k_token, key).has_value());
    BOOST_TEST((c.get_token_info(k_token)->flags & CKF_USER_PIN_INITIALIZED) == 0U);
}

BOOST_AUTO_TEST_CASE(a_failed_proposal_is_a_device_error) {
    node n;
    auto& c = *n.client;
    n.store.fail_proposals = true;
    BOOST_TEST(rv(c.generate_key(n.session, k_aes_gen, aes_template(true))) == CKR_DEVICE_ERROR);
    BOOST_REQUIRE(rv(c.logout(n.session)) == CKR_OK);
    BOOST_TEST(rv(c.login(n.session, CKU_USER, k_user_pin)) == CKR_DEVICE_ERROR);
    n.store.fail_proposals = false;
    BOOST_TEST(rv(c.login(n.session, CKU_USER, k_user_pin)) == CKR_OK);
}

BOOST_AUTO_TEST_CASE(no_plaintext_key_reaches_the_store) {
    node n;
    auto& c = *n.client;
    auto open = aes_template(true, 32);
    open.set_bool(CKA_SENSITIVE, false);
    open.set_bool(CKA_EXTRACTABLE, true);
    auto key = c.generate_key(n.session, k_aes_gen, open);
    BOOST_REQUIRE(key.has_value());
    auto value =
        c.get_attribute_value(n.session, *key, std::array<CK_ATTRIBUTE_TYPE, 1>{CKA_VALUE});
    BOOST_REQUIRE(value.has_value());
    BOOST_REQUIRE((*value)[0].value.has_value());
    const auto& secret = *(*value)[0].value;
    auto contains = [&](std::span<const std::uint8_t> hay) {
        return std::ranges::search(hay, secret).begin() != hay.end();
    };
    for (const auto& entry : n.store.log) {
        BOOST_TEST(!contains(
            std::span(reinterpret_cast<const std::uint8_t*>(entry.data()), entry.size())));
    }
    n.store.engine().scan(
        kythira::column_family::data, kythira::key_range{"", std::nullopt},
        kythira::scan_direction::forward, [&](std::string_view, std::string_view v) {
            BOOST_TEST(
                !contains(std::span(reinterpret_cast<const std::uint8_t*>(v.data()), v.size())));
            return true;
        });
}
