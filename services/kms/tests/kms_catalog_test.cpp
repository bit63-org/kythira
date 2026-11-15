// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 4 (Requirements 3.3-3.5, 6.1, 6.2, 8.1, 9.4, 13.4): the KMS
// catalog's key lifecycle, versions, aliases, tags, grants, tombstones and
// quotas, one command at a time.

#define BOOST_TEST_MODULE kms_catalog_test

#include <boost/test/unit_test.hpp>

#include <kythira/kms/kms_catalog.hpp>

#include <raft/memory_kv_engine.hpp>

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace kms = kythira::kms;
using kms::catalog_status;
using kms::key_state;

namespace {

constexpr std::string_view account = "111122223333";
constexpr std::string_view other_account = "444455556666";
constexpr std::uint64_t day = kms::k_ms_per_day;

auto key_id(int n) -> std::string {
    char buf[37];
    std::snprintf(buf, sizeof buf, "%08x-0000-4000-8000-000000000000", n);
    return buf;
}

struct fixture {
    kythira::memory_kv_engine engine;
    kms::kms_catalog_state_machine<> sm{"kms/"};
    std::uint64_t index = 0;

    fixture() { sm.open(engine, sm.engine_range()); }

    auto apply(const std::vector<std::byte>& c) -> catalog_status {
        return kms::catalog_reply_status(sm.apply(c, ++index));
    }

    auto create(const std::string& id, kms::key_spec spec = kms::key_spec::symmetric_default,
                kms::key_usage usage = kms::key_usage::encrypt_decrypt,
                std::string_view acct = account, const kms::tag_map& tags = {},
                kms::key_manager manager = kms::key_manager::customer) -> catalog_status {
        kms::key_record k;
        k.key_id = id;
        k.account = std::string(acct);
        k.description = "test key";
        k.spec = spec;
        k.usage = usage;
        k.manager = manager;
        k.creation_ms = 1000;
        k.policy = R"({"Version":"2012-10-17","Statement":[]})";
        return apply(kms::make_create_key_command(k, tags));
    }

    /// A key that is Enabled with version 1 on HSM object `object`.
    auto enabled(const std::string& id, std::uint64_t object = 77,
                 kms::key_spec spec = kms::key_spec::symmetric_default,
                 kms::key_usage usage = kms::key_usage::encrypt_decrypt) -> void {
        BOOST_REQUIRE((create(id, spec, usage) == catalog_status::ok));
        BOOST_REQUIRE(
            (apply(kms::make_complete_key_command(id, object, 2000)) == catalog_status::ok));
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(a_key_is_created_then_completed_with_its_backing_key) {
    fixture f;
    const auto id = key_id(1);
    BOOST_TEST((f.create(id, kms::key_spec::symmetric_default, kms::key_usage::encrypt_decrypt,
                         account, {{"team", "pay"}}) == catalog_status::ok));
    auto k = f.sm.key(id);
    BOOST_REQUIRE(k.has_value());
    BOOST_TEST((k->state == key_state::creating));
    BOOST_TEST(k->current_version == 0U);
    BOOST_TEST(f.sm.versions(id).empty());
    BOOST_TEST(f.sm.creating_keys().size() == 1U);
    BOOST_TEST(f.sm.keys(account) == std::vector<std::string>{id});
    BOOST_TEST(f.sm.tags(id).at("team") == "pay");
    BOOST_TEST(f.sm.counts(account).keys == 1U);

    BOOST_TEST((f.apply(kms::make_complete_key_command(id, 4242, 5000)) == catalog_status::ok));
    k = f.sm.key(id);
    BOOST_TEST((k->state == key_state::enabled));
    BOOST_TEST(k->current_version == 1U);
    const auto v = f.sm.version(id, 1);
    BOOST_REQUIRE(v.has_value());
    BOOST_TEST(v->hsm_object == 4242U);
    BOOST_TEST((v->type == kms::rotation_type::initial));
    BOOST_TEST(f.sm.creating_keys().empty());
    // Completing twice is a state error, not a second version.
    BOOST_TEST(
        (f.apply(kms::make_complete_key_command(id, 1, 6000)) == catalog_status::invalid_state));
    BOOST_TEST(f.sm.versions(id).size() == 1U);

    // The same id again is refused.
    BOOST_TEST((f.create(id) == catalog_status::rejected));
}

BOOST_AUTO_TEST_CASE(enable_disable_and_description_follow_aws_states) {
    fixture f;
    const auto id = key_id(2);
    BOOST_REQUIRE((f.create(id) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_set_enabled_command(id, false)) ==
                catalog_status::invalid_state));  // still Creating
    BOOST_TEST(
        (f.apply(kms::make_update_description_command(id, "x")) == catalog_status::invalid_state));
    BOOST_REQUIRE((f.apply(kms::make_complete_key_command(id, 1, 2000)) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_set_enabled_command(id, false)) == catalog_status::ok));
    BOOST_TEST((f.sm.key(id)->state == key_state::disabled));
    BOOST_TEST((f.apply(kms::make_set_enabled_command(id, false)) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_set_enabled_command(id, true)) == catalog_status::ok));
    BOOST_TEST((f.sm.key(id)->state == key_state::enabled));
    BOOST_TEST(
        (f.apply(kms::make_update_description_command(id, "renamed")) == catalog_status::ok));
    BOOST_TEST(f.sm.key(id)->description == "renamed");
    BOOST_TEST((f.apply(kms::make_put_policy_command(id, "{}")) == catalog_status::ok));
    BOOST_TEST(f.sm.key(id)->policy == "{}");
    BOOST_TEST(
        (f.apply(kms::make_set_enabled_command(key_id(99), true)) == catalog_status::not_found));
}

BOOST_AUTO_TEST_CASE(deletion_waits_its_window_and_leaves_a_tombstone) {
    fixture f;
    const auto id = key_id(3);
    f.enabled(id);
    BOOST_REQUIRE((f.apply(kms::make_create_alias_command(account, "alias/app", id, false, 3000)) ==
                   catalog_status::ok));
    kms::grant_record g;
    g.grant_id = "g1";
    g.key_id = id;
    g.grantee_principal = "arn:aws:iam::111122223333:role/app";
    g.issuing_account = std::string(account);
    g.operations = {"Decrypt"};
    BOOST_REQUIRE((f.apply(kms::make_create_grant_command(g)) == catalog_status::ok));
    BOOST_REQUIRE((f.apply(kms::make_tag_key_command(id, {{"a", "1"}})) == catalog_status::ok));

    BOOST_TEST((f.apply(kms::make_destroy_key_command(id, 10 * day)) ==
                catalog_status::invalid_state));  // not scheduled
    BOOST_TEST(
        (f.apply(kms::make_schedule_deletion_command(id, 7, 10 * day)) == catalog_status::ok));
    auto k = f.sm.key(id);
    BOOST_TEST((k->state == key_state::pending_deletion));
    BOOST_TEST(k->deletion_ms == 17 * day);
    BOOST_TEST(k->pending_window_days == 7U);
    BOOST_TEST((f.apply(kms::make_schedule_deletion_command(id, 30, 11 * day)) ==
                catalog_status::invalid_state));
    BOOST_TEST((f.apply(kms::make_set_enabled_command(id, true)) == catalog_status::invalid_state));
    BOOST_TEST((f.apply(kms::make_create_alias_command(account, "alias/late", id, false, 0)) ==
                catalog_status::invalid_state));

    // Cancelled: back to Disabled, as AWS does.
    BOOST_TEST((f.apply(kms::make_cancel_deletion_command(id)) == catalog_status::ok));
    BOOST_TEST((f.sm.key(id)->state == key_state::disabled));
    BOOST_TEST(f.sm.key(id)->deletion_ms == 0U);
    BOOST_TEST((f.apply(kms::make_cancel_deletion_command(id)) == catalog_status::invalid_state));

    BOOST_REQUIRE(
        (f.apply(kms::make_schedule_deletion_command(id, 30, 20 * day)) == catalog_status::ok));
    BOOST_TEST(f.sm.due_deletions(49 * day).empty());
    BOOST_TEST(f.sm.due_deletions(50 * day).size() == 1U);
    BOOST_TEST((f.apply(kms::make_destroy_key_command(id, 49 * day)) ==
                catalog_status::invalid_state));  // window not over
    BOOST_TEST((f.apply(kms::make_destroy_key_command(id, 50 * day)) == catalog_status::ok));

    // Gone, with its aliases, grants, tags and versions; the id stays
    // taken.
    BOOST_TEST(!f.sm.key(id).has_value());
    BOOST_TEST(f.sm.tombstoned(id));
    BOOST_TEST(f.sm.keys(account).empty());
    BOOST_TEST(f.sm.versions(id).empty());
    BOOST_TEST(f.sm.grants(id).empty());
    BOOST_TEST(f.sm.tags(id).empty());
    BOOST_TEST(!f.sm.alias(account, "alias/app").has_value());
    BOOST_TEST((f.sm.counts(account) == kms::account_counts{}));
    BOOST_TEST((f.create(id) == catalog_status::rejected));
    BOOST_TEST(
        (f.apply(kms::make_schedule_deletion_command(id, 7, 0)) == catalog_status::not_found));
}

BOOST_AUTO_TEST_CASE(a_creating_key_can_be_swept) {
    fixture f;
    const auto id = key_id(4);
    BOOST_REQUIRE((f.create(id) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_destroy_key_command(id, 0)) == catalog_status::ok));
    BOOST_TEST(f.sm.tombstoned(id));
    BOOST_TEST(f.sm.counts(account).keys == 0U);
    BOOST_TEST((f.apply(kms::make_complete_key_command(id, 1, 0)) == catalog_status::not_found));
}

BOOST_AUTO_TEST_CASE(rotation_adds_exactly_the_next_version) {
    fixture f;
    const auto id = key_id(5);
    f.enabled(id, 10);
    BOOST_TEST(
        (f.apply(kms::make_set_rotation_command(id, true, 365, 100 * day)) == catalog_status::ok));
    auto k = f.sm.key(id);
    BOOST_TEST(k->rotation_enabled);
    BOOST_TEST(k->next_rotation_ms == 465 * day);
    BOOST_TEST(f.sm.due_rotations(464 * day).empty());
    BOOST_TEST(f.sm.due_rotations(465 * day).size() == 1U);

    BOOST_TEST((f.apply(kms::make_add_version_command(id, 2, 11, kms::rotation_type::automatic,
                                                      465 * day)) == catalog_status::ok));
    // A leader that retries the same rotation after a change of leader
    // does not add a third version (Requirement 9.3).
    BOOST_TEST((f.apply(kms::make_add_version_command(id, 2, 12, kms::rotation_type::automatic,
                                                      465 * day)) == catalog_status::rejected));
    k = f.sm.key(id);
    BOOST_TEST(k->current_version == 2U);
    BOOST_TEST(k->next_rotation_ms == 830 * day);
    BOOST_TEST(f.sm.version(id, 2)->hsm_object == 11U);
    BOOST_TEST(f.sm.version(id, 1)->hsm_object == 10U);  // old ciphertexts still open

    // On demand does not move the schedule.
    BOOST_TEST((f.apply(kms::make_add_version_command(id, 3, 13, kms::rotation_type::on_demand,
                                                      500 * day)) == catalog_status::ok));
    BOOST_TEST(f.sm.key(id)->next_rotation_ms == 830 * day);
    BOOST_TEST(f.sm.versions(id).size() == 3U);

    BOOST_TEST(
        (f.apply(kms::make_set_rotation_command(id, false, 0, 501 * day)) == catalog_status::ok));
    BOOST_TEST(f.sm.due_rotations(UINT64_MAX).empty());

    // Asymmetric and HMAC keys do not rotate.
    const auto rsa = key_id(6);
    f.enabled(rsa, 20, kms::key_spec::rsa_2048, kms::key_usage::sign_verify);
    BOOST_TEST(
        (f.apply(kms::make_set_rotation_command(rsa, true, 365, 0)) == catalog_status::rejected));
    BOOST_TEST((f.apply(kms::make_add_version_command(rsa, 2, 21, kms::rotation_type::on_demand,
                                                      0)) == catalog_status::rejected));
    // A disabled key is not rotated.
    BOOST_REQUIRE((f.apply(kms::make_set_enabled_command(id, false)) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_add_version_command(id, 4, 14, kms::rotation_type::on_demand,
                                                      0)) == catalog_status::invalid_state));
}

BOOST_AUTO_TEST_CASE(aliases_follow_aws_rules) {
    fixture f;
    const auto a = key_id(7);
    const auto b = key_id(8);
    f.enabled(a);
    f.enabled(b);
    BOOST_TEST((f.apply(kms::make_create_alias_command(account, "alias/app", a, false, 1)) ==
                catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_create_alias_command(account, "alias/app", b, false, 2)) ==
                catalog_status::already_exists));
    BOOST_TEST(f.sm.alias(account, "alias/app")->key_id == a);
    BOOST_TEST(f.sm.aliases(account, a).size() == 1U);
    BOOST_TEST(f.sm.counts(account).aliases == 1U);

    BOOST_TEST((f.apply(kms::make_update_alias_command(account, "alias/app", b, 5)) ==
                catalog_status::ok));
    const auto moved = f.sm.alias(account, "alias/app");
    BOOST_TEST(moved->key_id == b);
    BOOST_TEST(moved->created_ms == 1U);
    BOOST_TEST(moved->updated_ms == 5U);
    BOOST_TEST(f.sm.aliases(account, a).empty());
    BOOST_TEST(f.sm.aliases(account, b).size() == 1U);

    // Not to a key of another type or usage.
    const auto hmac = key_id(9);
    f.enabled(hmac, 5, kms::key_spec::hmac_256, kms::key_usage::generate_verify_mac);
    BOOST_TEST((f.apply(kms::make_update_alias_command(account, "alias/app", hmac, 6)) ==
                catalog_status::rejected));

    // Not to another account's key.
    const auto theirs = key_id(10);
    BOOST_REQUIRE((f.create(theirs, kms::key_spec::symmetric_default,
                            kms::key_usage::encrypt_decrypt, other_account) == catalog_status::ok));
    BOOST_REQUIRE((f.apply(kms::make_complete_key_command(theirs, 1, 0)) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_create_alias_command(account, "alias/x", theirs, false, 0)) ==
                catalog_status::rejected));
    // Alias names are per account.
    BOOST_TEST((f.apply(kms::make_create_alias_command(other_account, "alias/app", theirs, false,
                                                       0)) == catalog_status::ok));

    BOOST_TEST(
        (f.apply(kms::make_delete_alias_command(account, "alias/app")) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_delete_alias_command(account, "alias/app")) ==
                catalog_status::not_found));
    BOOST_TEST(f.sm.counts(account).aliases == 0U);
    BOOST_TEST(f.sm.alias(other_account, "alias/app").has_value());

    // alias/aws/ is an AWS managed key's alone, and customers cannot move
    // or delete one.
    BOOST_CHECK_THROW(
        (void)f.apply(kms::make_create_alias_command(account, "alias/aws/kinesis", a, false, 0)),
        std::invalid_argument);
    BOOST_TEST((f.apply(kms::make_create_alias_command(account, "alias/aws/kinesis", a, true, 0)) ==
                catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_delete_alias_command(account, "alias/aws/kinesis")) ==
                catalog_status::rejected));

    BOOST_TEST(kms::valid_alias_name("alias/a-b_c/d"));
    for (const auto* bad : {"alias/", "app", "alias/a b", "alias/ä", "Alias/app"}) {
        BOOST_TEST(!kms::valid_alias_name(bad), bad);
    }
    BOOST_TEST(!kms::valid_alias_name("alias/" + std::string(251, 'a')));
}

BOOST_AUTO_TEST_CASE(tags_and_grants_have_aws_limits) {
    fixture f;
    const auto id = key_id(11);
    f.enabled(id);
    kms::tag_map many;
    for (int i = 0; i < 50; ++i) {
        many["k" + std::to_string(i)] = "v";
    }
    BOOST_TEST((f.apply(kms::make_tag_key_command(id, many)) == catalog_status::ok));
    BOOST_TEST(
        (f.apply(kms::make_tag_key_command(id, {{"k0", "replaced"}})) == catalog_status::ok));
    BOOST_TEST(f.sm.tags(id).at("k0") == "replaced");
    BOOST_TEST((f.apply(kms::make_tag_key_command(id, {{"one-more", "v"}})) ==
                catalog_status::limit_exceeded));
    BOOST_TEST(
        (f.apply(kms::make_untag_key_command(id, {"k0", "k1", "absent"})) == catalog_status::ok));
    BOOST_TEST(f.sm.tags(id).size() == 48U);

    kms::grant_record g;
    g.grant_id = "0123456789abcdef";
    g.key_id = id;
    g.name = "for-lambda";
    g.grantee_principal = "arn:aws:iam::111122223333:role/lambda";
    g.retiring_principal = "arn:aws:iam::111122223333:role/admin";
    g.issuing_account = std::string(account);
    g.operations = {"Encrypt", "Decrypt"};
    g.constraint = kms::grant_constraint::context_subset;
    g.constraint_context = {{"Department", "IT"}};
    g.created_ms = 9;
    BOOST_TEST((f.apply(kms::make_create_grant_command(g)) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_create_grant_command(g)) == catalog_status::already_exists));
    BOOST_TEST((*f.sm.grant(id, g.grant_id) == g));
    BOOST_TEST((f.apply(kms::make_remove_grant_command(id, g.grant_id)) == catalog_status::ok));
    BOOST_TEST(
        (f.apply(kms::make_remove_grant_command(id, g.grant_id)) == catalog_status::not_found));
}

BOOST_AUTO_TEST_CASE(account_quotas_count_and_take_overrides) {
    fixture f;
    BOOST_REQUIRE(
        (f.apply(kms::make_set_account_limits_command(account, {2, 1})) == catalog_status::ok));
    BOOST_TEST((f.sm.limits(account) == kms::account_limits{2, 1}));
    f.enabled(key_id(20));
    f.enabled(key_id(21));
    BOOST_TEST((f.create(key_id(22)) == catalog_status::limit_exceeded));
    BOOST_TEST(!f.sm.key(key_id(22)).has_value());
    // AWS managed keys do not count toward the quota.
    BOOST_TEST(
        (f.create(key_id(23), kms::key_spec::symmetric_default, kms::key_usage::encrypt_decrypt,
                  account, {}, kms::key_manager::aws) == catalog_status::ok));
    BOOST_TEST(f.sm.counts(account).keys == 2U);
    // Other accounts keep AWS's defaults.
    BOOST_TEST((f.create(key_id(24), kms::key_spec::symmetric_default,
                         kms::key_usage::encrypt_decrypt, other_account) == catalog_status::ok));

    BOOST_TEST((f.apply(kms::make_create_alias_command(account, "alias/one", key_id(20), false,
                                                       0)) == catalog_status::ok));
    BOOST_TEST((f.apply(kms::make_create_alias_command(account, "alias/two", key_id(21), false,
                                                       0)) == catalog_status::limit_exceeded));
    // Back to the default.
    BOOST_REQUIRE(
        (f.apply(kms::make_set_account_limits_command(account, {})) == catalog_status::ok));
    BOOST_TEST((f.sm.limits(account) == kms::account_limits{}));
    BOOST_TEST((f.create(key_id(22)) == catalog_status::ok));
}

BOOST_AUTO_TEST_CASE(list_keys_pages_by_id) {
    fixture f;
    for (int i = 30; i < 35; ++i) {
        BOOST_REQUIRE((f.create(key_id(i)) == catalog_status::ok));
    }
    const auto first = f.sm.keys(account, {}, 2);
    BOOST_TEST(first == (std::vector<std::string>{key_id(30), key_id(31)}));
    const auto next = f.sm.keys(account, first.back(), 2);
    BOOST_TEST(next == (std::vector<std::string>{key_id(32), key_id(33)}));
    BOOST_TEST(f.sm.keys(account, next.back()) == std::vector<std::string>{key_id(34)});
    BOOST_TEST(f.sm.keys(other_account).empty());
}

BOOST_AUTO_TEST_CASE(key_specs_take_only_their_usages) {
    using kms::key_spec;
    using kms::key_usage;
    BOOST_TEST(kms::usage_allowed(key_spec::symmetric_default, key_usage::encrypt_decrypt));
    BOOST_TEST(!kms::usage_allowed(key_spec::symmetric_default, key_usage::sign_verify));
    BOOST_TEST(kms::usage_allowed(key_spec::rsa_4096, key_usage::sign_verify));
    BOOST_TEST(kms::usage_allowed(key_spec::rsa_4096, key_usage::encrypt_decrypt));
    BOOST_TEST(!kms::usage_allowed(key_spec::ecc_nist_p256, key_usage::encrypt_decrypt));
    BOOST_TEST(!kms::usage_allowed(key_spec::hmac_256, key_usage::sign_verify));
    BOOST_TEST(kms::find_key_spec(key_spec::ecc_secg_p256k1)->name == "ECC_SECG_P256K1");

    fixture f;
    BOOST_CHECK_THROW((void)f.create(key_id(40), key_spec::hmac_512, key_usage::encrypt_decrypt),
                      std::invalid_argument);
    BOOST_TEST(f.sm.applied_index() == 0U);
}

BOOST_AUTO_TEST_CASE(malformed_commands_throw_and_change_nothing) {
    fixture f;
    auto c = kms::make_set_enabled_command(key_id(1), true);
    c[0] = std::byte{2};  // another command format
    BOOST_CHECK_THROW((void)f.apply(c), std::invalid_argument);
    c = kms::make_set_enabled_command(key_id(1), true);
    c.push_back(std::byte{0});  // trailing byte
    BOOST_CHECK_THROW((void)f.apply(c), std::invalid_argument);
    c = kms::make_set_enabled_command(key_id(1), true);
    c[1] = std::byte{99};  // unknown command
    BOOST_CHECK_THROW((void)f.apply(c), std::invalid_argument);
    BOOST_CHECK_THROW((void)kms::make_update_description_command(key_id(1), "\xff\xfe"),
                      std::invalid_argument);
    BOOST_TEST(f.sm.applied_index() == 0U);
}
