// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 5, requirements 3.1-3.3, 4.1, 4.5, 4.6, 7.1, 7.2, 7.4, 8.2 and 13.4:
// sealing and PIN verifiers, the catalog and token state machines on the
// persistent concept, leader-side generation, and a scan showing no
// plaintext key, token key, master key or PIN in the engine, the command
// log or a checkpoint.

#define BOOST_TEST_MODULE hsm_key_store_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/shamir.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <raft/memory_kv_engine.hpp>

#include <openssl/core_names.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <ostream>
#include <random>
#include <string>
#include <vector>

namespace hsm = kythira::hsm;

namespace {

// Low scrypt cost keeps the suite fast; the cost is stored per verifier.
constexpr std::uint8_t k_test_log2_n = 10;

auto random_key() -> hsm::secret_bytes {
    hsm::secret_bytes k(32);
    BOOST_REQUIRE(hsm::generate_random(k.span()).has_value());
    return k;
}

auto rv_of(const std::vector<std::byte>& reply) -> CK_RV {
    return hsm::token_reply::decode(reply).rv;
}

struct temp_dir {
    std::filesystem::path path;
    temp_dir() {
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("hsm_key_store_test_" + std::to_string(rd()) + "_" + std::to_string(::getpid()));
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

/// A token group on its own engine, with an index counter standing in for
/// the Raft log, and every command it was given (the "log").
struct token_fixture {
    kythira::memory_kv_engine engine;
    hsm::token_state_machine<> sm{"hsm/t/1/", 42};
    std::uint64_t index = 0;
    std::vector<std::vector<std::byte>> log;

    token_fixture() { sm.open(engine, sm.engine_range()); }

    auto apply(const std::vector<std::byte>& command) -> std::vector<std::byte> {
        log.push_back(command);
        return sm.apply(command, ++index);
    }
};

struct catalog_fixture {
    kythira::memory_kv_engine engine;
    hsm::hsm_catalog_state_machine<> sm{"hsm/c/"};
    std::uint64_t index = 0;
    std::vector<std::vector<std::byte>> log;

    catalog_fixture() { sm.open(engine, sm.engine_range()); }

    auto apply(const std::vector<std::byte>& command) -> CK_RV {
        log.push_back(command);
        return hsm::catalog_reply_rv(sm.apply(command, ++index));
    }
};

auto aes_template(CK_ULONG len) -> hsm::attribute_map {
    hsm::attribute_map t;
    t.set_ulong(CKA_VALUE_LEN, len);
    t.set_bool(CKA_ENCRYPT, true);
    t.set_bool(CKA_DECRYPT, true);
    return t;
}

auto contains(std::span<const std::uint8_t> hay, std::span<const std::uint8_t> needle) -> bool {
    return !needle.empty() &&
           std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}

auto as_u8(std::string_view s) -> std::span<const std::uint8_t> {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

auto as_u8(const std::vector<std::byte>& b) -> std::span<const std::uint8_t> {
    return {reinterpret_cast<const std::uint8_t*>(b.data()), b.size()};
}

}  // namespace

// --- Sealing and PINs ---------------------------------------------------------

BOOST_AUTO_TEST_CASE(sealed_values_open_only_with_their_key_and_binding) {
    auto key = random_key();
    hsm::attribute_map attrs;
    attrs.set_bool(CKA_SIGN, true);
    const std::vector<std::uint8_t> secret(32, 0x7E);
    const auto ad = hsm::object_ad(1, 100, attrs);
    auto sealed = hsm::seal(key.view(), ad, secret);
    BOOST_TEST(sealed.size() == secret.size() + hsm::seal_overhead);
    auto opened = hsm::unseal(key.view(), ad, sealed);
    BOOST_REQUIRE(opened.has_value());
    BOOST_TEST(hsm::constant_time_equal(opened->view(), secret));
    // Another key, token, handle or attribute set: nothing.
    BOOST_TEST(!hsm::unseal(random_key().view(), ad, sealed).has_value());
    BOOST_TEST(!hsm::unseal(key.view(), hsm::object_ad(2, 100, attrs), sealed).has_value());
    BOOST_TEST(!hsm::unseal(key.view(), hsm::object_ad(1, 101, attrs), sealed).has_value());
    auto widened = attrs;
    widened.set_bool(CKA_EXTRACTABLE, true);
    BOOST_TEST(!hsm::unseal(key.view(), hsm::object_ad(1, 100, widened), sealed).has_value());
    // Any flipped byte: nothing.
    for (std::size_t i = 0; i < sealed.size(); ++i) {
        auto bad = sealed;
        bad[i] ^= 0x01U;
        BOOST_TEST(!hsm::unseal(key.view(), ad, bad).has_value());
    }
    // Two seals of the same value differ (random nonce).
    BOOST_TEST(hsm::seal(key.view(), ad, secret) != sealed);
}

BOOST_AUTO_TEST_CASE(pin_verifiers_check_pins_and_round_trip) {
    auto v = hsm::make_pin_verifier("123456", k_test_log2_n);
    BOOST_TEST(hsm::check_pin(v, "123456"));
    BOOST_TEST(!hsm::check_pin(v, "123457"));
    BOOST_TEST(!hsm::check_pin(v, ""));
    auto back = hsm::pin_verifier::decode(v.encode());
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(hsm::check_pin(*back, "123456"));
    BOOST_TEST(hsm::make_pin_verifier("123456", k_test_log2_n).salt != v.salt);
    auto enc = v.encode();
    enc.pop_back();
    BOOST_TEST(!hsm::pin_verifier::decode(enc).has_value());
    BOOST_TEST(hsm::make_pin_verifier("x").log2_n == hsm::default_pin_log2_n);
}

// --- Catalog --------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(catalog_initializes_once_and_records_the_mode) {
    catalog_fixture c;
    std::array<std::uint8_t, 8> check{1, 2, 3, 4, 5, 6, 7, 8};
    BOOST_TEST(c.apply(hsm::make_initialize_command(hsm::unseal_mode::operator_shares, 3, 5,
                                                    check)) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_initialize_command(hsm::unseal_mode::node_shares, 2, 3, check)) ==
               CKR_FUNCTION_REJECTED);
    auto rec = c.sm.catalog();
    BOOST_REQUIRE(rec.has_value());
    BOOST_TEST(rec->k == 3);
    BOOST_TEST(rec->n == 5);
    BOOST_TEST(rec->generation == 1U);
    BOOST_TEST(rec->mk_check == check);
    BOOST_TEST(rec->seal_epoch == 0U);
    // A seal bumps the epoch every node compares its unseal against.
    BOOST_TEST(c.apply(hsm::make_seal_command()) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_seal_command()) == CKR_OK);
    BOOST_TEST(c.sm.catalog()->seal_epoch == 2U);
    BOOST_TEST(c.sm.catalog()->k == 3);
}

BOOST_AUTO_TEST_CASE(catalog_tokens_bindings_and_deletion) {
    catalog_fixture c;
    auto mk = random_key();
    std::array<std::uint8_t, 8> check{};
    BOOST_TEST(c.apply(hsm::make_initialize_command(hsm::unseal_mode::operator_shares, 2, 3,
                                                    check)) == CKR_OK);
    auto t1 = hsm::prepare_token(mk.view(), 1, 11, "ca");
    auto t2 = hsm::prepare_token(mk.view(), 1, 22, "kinesis");
    BOOST_TEST(c.apply(hsm::make_create_token_command(t1.entry)) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_create_token_command(t2.entry)) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_create_token_command(t1.entry)) == CKR_FUNCTION_REJECTED);
    auto stale = hsm::prepare_token(mk.view(), 7, 33, "stale generation");
    BOOST_TEST(c.apply(hsm::make_create_token_command(stale.entry)) == CKR_FUNCTION_REJECTED);
    BOOST_TEST(c.sm.tokens().size() == 2U);

    BOOST_TEST(c.apply(hsm::make_bind_command("CN=ca-node", 11)) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_bind_command("CN=ca-node", 22)) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_bind_command("CN=kinesis", 22)) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_bind_command("CN=ca-node", 99)) == CKR_TOKEN_NOT_PRESENT);
    BOOST_TEST(c.sm.bound_tokens("CN=ca-node") == (std::vector<std::uint64_t>{11, 22}),
               boost::test_tools::per_element());
    BOOST_TEST(c.sm.may_open("CN=kinesis", 22));
    BOOST_TEST(!c.sm.may_open("CN=kinesis", 11));
    // A prefix of an identity is a different identity.
    BOOST_TEST(c.sm.bound_tokens("CN=ca").empty());
    BOOST_TEST(c.apply(hsm::make_unbind_command("CN=ca-node", 22)) == CKR_OK);
    BOOST_TEST(c.sm.bound_tokens("CN=ca-node") == (std::vector<std::uint64_t>{11}),
               boost::test_tools::per_element());

    // The catalog's sealed TK opens under the MK, and the TK is what was made.
    auto tk = hsm::open_token_key(mk.view(), *c.sm.token(22));
    BOOST_REQUIRE(tk.has_value());
    BOOST_TEST(hsm::constant_time_equal(tk->view(), t2.tk.view()));

    // Deleting a token destroys its sealed key and every binding to it.
    BOOST_TEST(c.apply(hsm::make_delete_token_command(22)) == CKR_OK);
    BOOST_TEST(!c.sm.token(22).has_value());
    BOOST_TEST(!c.sm.may_open("CN=kinesis", 22));
    BOOST_TEST(c.sm.bound_tokens("CN=kinesis").empty());
    BOOST_TEST(c.apply(hsm::make_delete_token_command(22)) == CKR_TOKEN_NOT_PRESENT);
}

BOOST_AUTO_TEST_CASE(rekey_reseals_every_token_and_retires_the_old_mk) {
    catalog_fixture c;
    auto old_mk = random_key();
    std::array<std::uint8_t, 8> check{};
    BOOST_TEST(c.apply(hsm::make_initialize_command(hsm::unseal_mode::operator_shares, 2, 3,
                                                    check)) == CKR_OK);
    auto a = hsm::prepare_token(old_mk.view(), 1, 1, "a");
    auto b = hsm::prepare_token(old_mk.view(), 1, 2, "b");
    BOOST_TEST(c.apply(hsm::make_create_token_command(a.entry)) == CKR_OK);
    BOOST_TEST(c.apply(hsm::make_create_token_command(b.entry)) == CKR_OK);

    auto new_mk = random_key();
    std::array<std::uint8_t, 8> new_check{9, 9, 9, 9, 9, 9, 9, 9};
    // A wrong old MK cannot produce a rekey entry.
    // The new shares switch to node unseal, 3 of 4, in the same entry.
    const hsm::split_parameters split{hsm::unseal_mode::node_shares, 3, 4};
    BOOST_TEST(!hsm::prepare_rekey(random_key().view(), new_mk.view(), new_check, split,
                                   *c.sm.catalog(), c.sm.tokens())
                    .has_value());
    auto entry = hsm::prepare_rekey(old_mk.view(), new_mk.view(), new_check, split, *c.sm.catalog(),
                                    c.sm.tokens());
    BOOST_REQUIRE(entry.has_value());
    BOOST_TEST(c.apply(*entry) == CKR_OK);
    BOOST_TEST(c.sm.catalog()->generation == 2U);
    BOOST_TEST(c.sm.catalog()->mk_check == new_check);
    BOOST_TEST(static_cast<int>(c.sm.catalog()->mode) ==
               static_cast<int>(hsm::unseal_mode::node_shares));
    BOOST_TEST(c.sm.catalog()->k == 3);
    BOOST_TEST(c.sm.catalog()->n == 4);
    for (const auto* t : {&a, &b}) {
        auto e = c.sm.token(t->entry.token_id);
        BOOST_TEST(!hsm::open_token_key(old_mk.view(), *e).has_value());
        auto tk = hsm::open_token_key(new_mk.view(), *e);
        BOOST_REQUIRE(tk.has_value());
        BOOST_TEST(hsm::constant_time_equal(tk->view(),
                                            t->tk.view()));  // TK unchanged, objects stay valid
    }
    // Replaying the same rekey (stale generation) or leaving a token out fails.
    BOOST_TEST(c.apply(*entry) == CKR_FUNCTION_REJECTED);
    std::vector<std::pair<std::uint64_t, hsm::sealed_bytes>> partial{
        {1, hsm::seal(new_mk.view(), hsm::token_key_ad(1, 3), a.tk.view())}};
    BOOST_TEST(c.apply(hsm::make_rekey_command(3, new_check, split, partial)) ==
               CKR_FUNCTION_REJECTED);
}

// --- Token ----------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(token_init_pins_and_login_counters) {
    token_fixture t;
    const auto so = hsm::make_pin_verifier("so-pin", k_test_log2_n);
    BOOST_TEST(rv_of(t.apply(hsm::make_set_pin_command(hsm::pin_user::user, so))) ==
               CKR_TOKEN_NOT_RECOGNIZED);
    BOOST_TEST(rv_of(t.apply(hsm::make_init_token_command("token one", so, 3))) == CKR_OK);
    auto rec = t.sm.token();
    BOOST_REQUIRE(rec.has_value());
    BOOST_TEST(rec->label == "token one");
    BOOST_TEST(!rec->user_pin.has_value());
    BOOST_TEST((rec->pin_flags() & CKF_USER_PIN_INITIALIZED) == 0U);
    BOOST_TEST(hsm::check_pin(*rec->so_pin, "so-pin"));

    BOOST_TEST(rv_of(t.apply(hsm::make_set_pin_command(
                   hsm::pin_user::user, hsm::make_pin_verifier("user-pin", k_test_log2_n)))) ==
               CKR_OK);
    BOOST_TEST((t.sm.token()->pin_flags() & CKF_USER_PIN_INITIALIZED) != 0U);

    // Failures count, report COUNT_LOW then FINAL_TRY, then lock.
    auto r1 = hsm::token_reply::decode(
        t.apply(hsm::make_login_result_command(hsm::pin_user::user, false)));
    BOOST_TEST(r1.rv == CKR_PIN_INCORRECT);
    BOOST_TEST(r1.failures == 1U);
    BOOST_TEST((t.sm.token()->pin_flags() & CKF_USER_PIN_COUNT_LOW) != 0U);
    (void)t.apply(hsm::make_login_result_command(hsm::pin_user::user, false));
    BOOST_TEST((t.sm.token()->pin_flags() & CKF_USER_PIN_FINAL_TRY) != 0U);
    auto r3 = hsm::token_reply::decode(
        t.apply(hsm::make_login_result_command(hsm::pin_user::user, false)));
    BOOST_TEST(r3.rv == CKR_PIN_LOCKED);
    BOOST_TEST(r3.locked);
    BOOST_TEST((t.sm.token()->pin_flags() & CKF_USER_PIN_LOCKED) != 0U);
    // Locked: even a correct PIN is refused, until the SO sets a new PIN.
    BOOST_TEST(rv_of(t.apply(hsm::make_login_result_command(hsm::pin_user::user, true))) ==
               CKR_PIN_LOCKED);
    // The SO's counter is separate.
    BOOST_TEST(rv_of(t.apply(hsm::make_login_result_command(hsm::pin_user::so, true))) == CKR_OK);
    BOOST_TEST(rv_of(t.apply(hsm::make_set_pin_command(
                   hsm::pin_user::user, hsm::make_pin_verifier("new-pin", k_test_log2_n)))) ==
               CKR_OK);
    BOOST_TEST(!t.sm.token()->locked(hsm::pin_user::user));
    BOOST_TEST(rv_of(t.apply(hsm::make_login_result_command(hsm::pin_user::user, true))) == CKR_OK);
}

BOOST_AUTO_TEST_CASE(generated_keys_are_sealed_bound_and_usable) {
    token_fixture t;
    auto tk = random_key();
    BOOST_TEST(rv_of(t.apply(hsm::make_init_token_command(
                   "t", hsm::make_pin_verifier("so", k_test_log2_n)))) == CKR_OK);
    CK_MECHANISM gen{CKM_AES_KEY_GEN, nullptr, 0};
    auto cmd = hsm::prepare_generate_key(tk.view(), t.sm.token_id(), 1000, gen, aes_template(32));
    BOOST_REQUIRE(cmd.has_value());
    BOOST_TEST(rv_of(t.apply(*cmd)) == CKR_OK);
    auto o = t.sm.object(1000);
    BOOST_REQUIRE(o.has_value());
    BOOST_TEST(o->version == 1U);
    BOOST_TEST(o->attributes.flag(CKA_LOCAL));
    BOOST_TEST(o->attributes.flag(CKA_SENSITIVE));
    BOOST_TEST(o->attributes.flag(CKA_ALWAYS_SENSITIVE));
    BOOST_TEST(o->attributes.flag(CKA_NEVER_EXTRACTABLE));
    BOOST_TEST(o->attributes.get_ulong(CKA_KEY_GEN_MECHANISM).value().value() == CKM_AES_KEY_GEN);

    // The key works through the mechanisms...
    auto k = hsm::key_material_of(tk.view(), t.sm.token_id(), *o);
    BOOST_REQUIRE(k.has_value());
    BOOST_TEST(k->secret.size() == 32U);
    std::vector<std::uint8_t> iv(12, 1);
    CK_GCM_PARAMS gp{iv.data(), iv.size(), 96, nullptr, 0, 128};
    CK_MECHANISM gcm{CKM_AES_GCM, &gp, sizeof gp};
    const std::vector<std::uint8_t> plain{1, 2, 3};
    auto ct = hsm::encrypt(gcm, *k, plain);
    BOOST_TEST(hsm::constant_time_equal(hsm::decrypt(gcm, *k, *ct)->view(), plain));
    // ...and is bound to its token, handle and attributes.
    BOOST_TEST(!hsm::key_material_of(tk.view(), 43, *o).has_value());
    auto moved = *o;
    moved.handle = 1001;
    BOOST_TEST(hsm::key_material_of(tk.view(), t.sm.token_id(), moved).error() == CKR_DEVICE_ERROR);
    auto loosened = *o;
    loosened.attributes.set_bool(CKA_EXTRACTABLE, true);
    BOOST_TEST(!hsm::open_object(tk.view(), t.sm.token_id(), loosened).has_value());

    // A taken handle is a conflict; a missing CKA_VALUE_LEN is incomplete.
    BOOST_TEST(rv_of(t.apply(*hsm::prepare_generate_key(tk.view(), t.sm.token_id(), 1000, gen,
                                                        aes_template(16)))) ==
               CKR_FUNCTION_REJECTED);
    BOOST_TEST(
        hsm::prepare_generate_key(tk.view(), t.sm.token_id(), 1002, gen, hsm::attribute_map{})
            .error() == CKR_TEMPLATE_INCOMPLETE);
    // The caller cannot claim token-set attributes.
    auto claims_local = aes_template(16);
    claims_local.set_bool(CKA_LOCAL, true);
    BOOST_TEST(
        hsm::prepare_generate_key(tk.view(), t.sm.token_id(), 1003, gen, claims_local).error() ==
        CKR_ATTRIBUTE_READ_ONLY);
}

BOOST_AUTO_TEST_CASE(key_pairs_are_one_entry_and_sign) {
    token_fixture t;
    auto tk = random_key();
    (void)t.apply(hsm::make_init_token_command("t", hsm::make_pin_verifier("so", k_test_log2_n)));
    hsm::attribute_map pub;
    pub.set_bytes(CKA_EC_PARAMS, std::vector<std::uint8_t>{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                                           0x03, 0x01, 0x07});
    pub.set_bool(CKA_VERIFY, true);
    hsm::attribute_map priv;
    priv.set_bool(CKA_SIGN, true);
    CK_MECHANISM gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    auto cmd =
        hsm::prepare_generate_key_pair(tk.view(), t.sm.token_id(), 2000, 2001, gen, pub, priv);
    BOOST_REQUIRE(cmd.has_value());
    BOOST_TEST(rv_of(t.apply(*cmd)) == CKR_OK);
    BOOST_TEST(t.sm.object_count() == 2U);
    auto pub_obj = t.sm.object(2000);
    auto priv_obj = t.sm.object(2001);
    BOOST_TEST(pub_obj->sealed.empty());
    BOOST_TEST(!priv_obj->sealed.empty());
    BOOST_TEST(pub_obj->attributes.has(CKA_EC_POINT));
    BOOST_TEST(priv_obj->attributes.has(CKA_EC_PARAMS));
    BOOST_TEST(!priv_obj->attributes.has(CKA_EC_POINT));
    auto sk = hsm::key_material_of(tk.view(), t.sm.token_id(), *priv_obj);
    auto pk = hsm::key_material_of(tk.view(), t.sm.token_id(), *pub_obj);
    BOOST_REQUIRE(sk.has_value());
    BOOST_REQUIRE(pk.has_value());
    CK_MECHANISM ecdsa{CKM_ECDSA_SHA256, nullptr, 0};
    const std::vector<std::uint8_t> data{9, 8, 7};
    auto sig = hsm::sign(ecdsa, *sk, data);
    BOOST_REQUIRE(sig.has_value());
    BOOST_TEST(hsm::verify(ecdsa, *pk, data, *sig).has_value());
    // A pair is all or nothing: one taken handle and neither is created.
    auto again =
        hsm::prepare_generate_key_pair(tk.view(), t.sm.token_id(), 3000, 2001, gen, pub, priv);
    BOOST_TEST(rv_of(t.apply(*again)) == CKR_FUNCTION_REJECTED);
    BOOST_TEST(!t.sm.object(3000).has_value());
}

BOOST_AUTO_TEST_CASE(updates_reseal_and_name_the_version_they_read) {
    token_fixture t;
    auto tk = random_key();
    (void)t.apply(hsm::make_init_token_command("t", hsm::make_pin_verifier("so", k_test_log2_n)));
    CK_MECHANISM gen{CKM_AES_KEY_GEN, nullptr, 0};
    (void)t.apply(*hsm::prepare_generate_key(tk.view(), t.sm.token_id(), 7, gen, aes_template(16)));
    auto v1 = *t.sm.object(7);
    const auto before = hsm::key_material_of(tk.view(), t.sm.token_id(), v1);

    hsm::attribute_map label;
    label.set_bytes(CKA_LABEL, std::vector<std::uint8_t>{'k', 'e', 'y'});
    auto cmd =
        hsm::prepare_set_attributes(tk.view(), t.sm.token_id(), v1, label, hsm::session_user::user);
    BOOST_REQUIRE(cmd.has_value());
    auto reply = hsm::token_reply::decode(t.apply(*cmd));
    BOOST_TEST(reply.rv == CKR_OK);
    BOOST_TEST(reply.version == 2U);
    auto v2 = *t.sm.object(7);
    BOOST_TEST(v2.attributes.has(CKA_LABEL));
    // Same key, re-sealed under the new attributes.
    auto after = hsm::key_material_of(tk.view(), t.sm.token_id(), v2);
    BOOST_REQUIRE(after.has_value());
    BOOST_TEST(hsm::constant_time_equal(after->secret.view(), before->secret.view()));
    BOOST_TEST(
        !hsm::open_object(tk.view(), t.sm.token_id(),
                          hsm::object_record{v2.handle, v2.version, v1.attributes, {}, v2.sealed})
             .has_value());
    // A second update prepared from version 1 loses the race.
    BOOST_TEST(rv_of(t.apply(*cmd)) == CKR_FUNCTION_REJECTED);
    // Policy is applied before proposing.
    hsm::attribute_map unsensitive;
    unsensitive.set_bool(CKA_SENSITIVE, false);
    BOOST_TEST(hsm::prepare_set_attributes(tk.view(), t.sm.token_id(), v2, unsensitive,
                                           hsm::session_user::so)
                   .error() == CKR_ATTRIBUTE_READ_ONLY);
    // Destroy with a stale version is refused; with the current one it works.
    BOOST_TEST(rv_of(t.apply(hsm::make_destroy_object_command(7, 1))) == CKR_FUNCTION_REJECTED);
    BOOST_TEST(rv_of(t.apply(hsm::make_destroy_object_command(7, 2))) == CKR_OK);
    BOOST_TEST(!t.sm.object(7).has_value());
    BOOST_TEST(rv_of(t.apply(hsm::make_destroy_object_command(7))) == CKR_OBJECT_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(reinitializing_a_token_destroys_its_objects) {
    token_fixture t;
    auto tk = random_key();
    (void)t.apply(hsm::make_init_token_command("t", hsm::make_pin_verifier("so", k_test_log2_n)));
    CK_MECHANISM gen{CKM_AES_KEY_GEN, nullptr, 0};
    for (std::uint64_t h = 1; h <= 5; ++h) {
        (void)t.apply(
            *hsm::prepare_generate_key(tk.view(), t.sm.token_id(), h, gen, aes_template(16)));
    }
    BOOST_TEST(t.sm.object_count() == 5U);
    (void)t.apply(
        hsm::make_init_token_command("fresh", hsm::make_pin_verifier("so2", k_test_log2_n)));
    BOOST_TEST(t.sm.object_count() == 0U);
    BOOST_TEST(t.sm.token()->label == "fresh");
}

// --- Persistence ------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(replays_are_no_ops_and_state_survives_reopen) {
    token_fixture t;
    auto tk = random_key();
    (void)t.apply(hsm::make_init_token_command("t", hsm::make_pin_verifier("so", k_test_log2_n)));
    CK_MECHANISM gen{CKM_AES_KEY_GEN, nullptr, 0};
    const auto create =
        *hsm::prepare_generate_key(tk.view(), t.sm.token_id(), 5, gen, aes_template(16));
    (void)t.apply(create);
    BOOST_TEST(t.sm.applied_index() == 2U);
    // Replaying index 2 after a restart changes nothing and replies nothing.
    BOOST_TEST(t.sm.apply(hsm::make_destroy_object_command(5), 2).empty());
    BOOST_TEST(t.sm.object(5).has_value());

    hsm::token_state_machine<> reopened{"hsm/t/1/", 42};
    reopened.open(t.engine, reopened.engine_range());
    BOOST_TEST(reopened.applied_index() == 2U);
    BOOST_TEST(reopened.object(5)->attributes == t.sm.object(5)->attributes);
    t.sm.sync_durable();
    BOOST_TEST(t.sm.durable_applied_index() == 2U);
}

BOOST_AUTO_TEST_CASE(a_checkpoint_moves_a_token_to_another_node) {
    token_fixture leader;
    auto tk = random_key();
    (void)leader.apply(
        hsm::make_init_token_command("t", hsm::make_pin_verifier("so", k_test_log2_n)));
    CK_MECHANISM gen{CKM_AES_KEY_GEN, nullptr, 0};
    (void)leader.apply(
        *hsm::prepare_generate_key(tk.view(), leader.sm.token_id(), 9, gen, aes_template(32)));
    temp_dir dir;
    const auto manifest = leader.sm.checkpoint(dir.path);

    token_fixture follower;
    follower.sm.ingest(dir.path, manifest, leader.index);
    BOOST_TEST(follower.sm.applied_index() == leader.index);
    auto o = follower.sm.object(9);
    BOOST_REQUIRE(o.has_value());
    auto a = hsm::key_material_of(tk.view(), 42, *o);
    auto b = hsm::key_material_of(tk.view(), 42, *leader.sm.object(9));
    BOOST_TEST(hsm::constant_time_equal(a->secret.view(), b->secret.view()));
    follower.sm.drop();
    BOOST_TEST(follower.sm.object_count() == 0U);
}

BOOST_AUTO_TEST_CASE(two_groups_share_an_engine_without_touching_each_other) {
    kythira::memory_kv_engine engine;
    hsm::token_state_machine<> a{"hsm/t/1/", 1};
    hsm::token_state_machine<> b{"hsm/t/2/", 2};
    hsm::hsm_catalog_state_machine<> c{"hsm/c/"};
    a.open(engine, a.engine_range());
    b.open(engine, b.engine_range());
    c.open(engine, c.engine_range());
    (void)a.apply(hsm::make_init_token_command("a", hsm::make_pin_verifier("so", k_test_log2_n)),
                  1);
    (void)b.apply(hsm::make_init_token_command("b", hsm::make_pin_verifier("so", k_test_log2_n)),
                  1);
    auto tk = random_key();
    CK_MECHANISM gen{CKM_AES_KEY_GEN, nullptr, 0};
    (void)a.apply(*hsm::prepare_generate_key(tk.view(), 1, 5, gen, aes_template(16)), 2);
    BOOST_TEST(a.object_count() == 1U);
    BOOST_TEST(b.object_count() == 0U);
    (void)b.apply(hsm::make_init_token_command("b2", hsm::make_pin_verifier("so", k_test_log2_n)),
                  2);
    BOOST_TEST(a.object_count() == 1U);
    b.drop();
    BOOST_TEST(a.token()->label == "a");
    BOOST_TEST(!b.token().has_value());
    BOOST_TEST(!c.catalog().has_value());
}

// --- Requirement 13.4: no plaintext at rest -----------------------------------------

BOOST_AUTO_TEST_CASE(no_plaintext_key_material_in_the_engine_log_or_checkpoint) {
    // An HSM from scratch: MK split into shares, catalog, one token, an AES
    // key, an EC key pair and an RSA key pair, PINs set and used.
    auto mk = random_key();
    auto shares = hsm::shamir_split(mk.view(), 2, 3);
    BOOST_REQUIRE(shares.has_value());
    const auto check = (*shares)[0].check_value;

    kythira::memory_kv_engine engine;
    hsm::hsm_catalog_state_machine<> catalog{"hsm/c/"};
    hsm::token_state_machine<> token{"hsm/t/77/", 77};
    catalog.open(engine, catalog.engine_range());
    token.open(engine, token.engine_range());
    std::vector<std::vector<std::byte>> log;
    std::uint64_t ci = 0;
    std::uint64_t ti = 0;
    auto to_catalog = [&](std::vector<std::byte> cmd) {
        log.push_back(cmd);
        BOOST_TEST(hsm::catalog_reply_rv(catalog.apply(cmd, ++ci)) == CKR_OK);
    };
    auto to_token = [&](std::vector<std::byte> cmd) {
        log.push_back(cmd);
        BOOST_TEST(rv_of(token.apply(cmd, ++ti)) == CKR_OK);
    };

    const std::string so_pin = "so-secret-PIN-31337";
    const std::string user_pin = "user-secret-PIN-27182";
    to_catalog(hsm::make_initialize_command(hsm::unseal_mode::operator_shares, 2, 3, check));
    auto made = hsm::prepare_token(mk.view(), 1, 77, "scan");
    to_catalog(hsm::make_create_token_command(made.entry));
    to_catalog(hsm::make_bind_command("CN=client", 77));
    to_token(hsm::make_init_token_command("scan", hsm::make_pin_verifier(so_pin, k_test_log2_n)));
    to_token(hsm::make_set_pin_command(hsm::pin_user::user,
                                       hsm::make_pin_verifier(user_pin, k_test_log2_n)));
    to_token(hsm::make_login_result_command(hsm::pin_user::user, true));

    const auto& tk = made.tk;
    CK_MECHANISM aes_gen{CKM_AES_KEY_GEN, nullptr, 0};
    to_token(*hsm::prepare_generate_key(tk.view(), 77, 10, aes_gen, aes_template(32)));
    hsm::attribute_map ec_pub;
    ec_pub.set_bytes(CKA_EC_PARAMS,
                     std::vector<std::uint8_t>{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22});
    CK_MECHANISM ec_gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    to_token(*hsm::prepare_generate_key_pair(tk.view(), 77, 20, 21, ec_gen, ec_pub, {}));
    hsm::attribute_map rsa_pub;
    rsa_pub.set_ulong(CKA_MODULUS_BITS, 2048);
    CK_MECHANISM rsa_gen{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    to_token(*hsm::prepare_generate_key_pair(tk.view(), 77, 30, 31, rsa_gen, rsa_pub, {}));
    hsm::attribute_map relabel;
    relabel.set_bytes(CKA_LABEL, std::vector<std::uint8_t>{'x'});
    to_token(*hsm::prepare_set_attributes(tk.view(), 77, *token.object(10), relabel,
                                          hsm::session_user::user));

    // What must never appear: the MK, the TK, every share, every object's
    // secret value (whole and as raw private scalars), and the PINs.
    std::vector<std::vector<std::uint8_t>> needles;
    needles.emplace_back(mk.view().begin(), mk.view().end());
    needles.emplace_back(tk.view().begin(), tk.view().end());
    for (const auto& s : *shares) {
        needles.emplace_back(s.bytes.view().begin(), s.bytes.view().end());
    }
    needles.emplace_back(so_pin.begin(), so_pin.end());
    needles.emplace_back(user_pin.begin(), user_pin.end());
    token.for_each_object([&](const hsm::object_record& o) {
        if (o.sealed.empty()) {
            return true;
        }
        auto secret = hsm::open_object(tk.view(), 77, o);
        BOOST_REQUIRE(secret.has_value());
        needles.emplace_back(secret->view().begin(), secret->view().end());
        if (o.attributes.get_ulong(CKA_CLASS).value().value() == CKO_PRIVATE_KEY) {
            // The private scalar / exponent inside the PKCS#8.
            const unsigned char* p = secret->data();
            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
                d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(secret->size())), &EVP_PKEY_free);
            BOOST_REQUIRE(key);
            BIGNUM* raw = nullptr;
            const char* name = EVP_PKEY_is_a(key.get(), "RSA") == 1 ? OSSL_PKEY_PARAM_RSA_D
                                                                    : OSSL_PKEY_PARAM_PRIV_KEY;
            BOOST_REQUIRE(EVP_PKEY_get_bn_param(key.get(), name, &raw) == 1);
            std::vector<std::uint8_t> scalar(static_cast<std::size_t>(BN_num_bytes(raw)));
            BN_bn2bin(raw, scalar.data());
            BN_clear_free(raw);
            needles.push_back(std::move(scalar));
        }
        return true;
    });
    BOOST_TEST(needles.size() ==
               2U + 3U + 2U + 3U + 2U);  // MK, TK, shares, PINs, 3 values, 2 scalars

    // Haystacks: every engine key and value in every column family, every
    // command, and every file of a checkpoint of each group.
    std::vector<std::vector<std::uint8_t>> haystacks;
    for (auto cf : kythira::k_all_column_families) {
        engine.scan(cf, kythira::key_range{}, kythira::scan_direction::forward,
                    [&](std::string_view k, std::string_view v) {
                        haystacks.emplace_back(k.begin(), k.end());
                        haystacks.emplace_back(v.begin(), v.end());
                        return true;
                    });
    }
    for (const auto& cmd : log) {
        auto u = as_u8(cmd);
        haystacks.emplace_back(u.begin(), u.end());
    }
    temp_dir dir;
    std::filesystem::create_directories(dir.path);
    (void)catalog.checkpoint(dir.path / "catalog");
    (void)token.checkpoint(dir.path / "token");
    std::size_t files = 0;
    for (const auto& f : std::filesystem::recursive_directory_iterator(dir.path)) {
        if (f.is_regular_file()) {
            std::ifstream in(f.path(), std::ios::binary);
            haystacks.emplace_back(std::istreambuf_iterator<char>(in),
                                   std::istreambuf_iterator<char>());
            ++files;
        }
    }
    BOOST_TEST(files >= 2U);
    std::size_t bytes = 0;
    for (const auto& h : haystacks) {
        bytes += h.size();
        for (std::size_t i = 0; i < needles.size(); ++i) {
            BOOST_TEST_INFO("needle " << i);
            BOOST_TEST(!contains(h, needles[i]));
        }
    }
    BOOST_TEST_MESSAGE("scanned " << haystacks.size() << " blobs, " << bytes << " bytes, "
                                  << needles.size() << " needles");
    // The scan can see: the label, a known public value, is in the engine.
    bool saw_label = false;
    for (const auto& h : haystacks) {
        saw_label = saw_label || contains(h, as_u8("CN=client"));
    }
    BOOST_TEST(saw_label);
}
