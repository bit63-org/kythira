// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_acl_unit_test.cpp
/// @brief ACL tests (.kiro/specs/redis-compatible-kv/ task 4,
///        Requirements 10.1-10.7, 11.1-11.5).

#define BOOST_TEST_MODULE redis_acl_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_acl.hpp>

#include <string>
#include <vector>

using namespace kythira;

namespace {

// Small iteration counts keep the suite fast; the format is what is under
// test, not the cost.
constexpr std::uint32_t test_iters = 1000;

auto load_acl(redis_acl& acl) -> void {
    std::string text =
        "# comment line\n"
        "\n"
        "user farm " +
        redis_acl::hash_secret("farm-secret", test_iters) +
        " read_write sccache/ \n"
        "user reader " +
        redis_acl::hash_secret("reader-secret", test_iters) +
        " read_only sccache/\n"
        "user ops " +
        redis_acl::hash_secret("ops-secret", test_iters) +
        " admin * cert=CN=ops.example\n"
        "user nokeys " +
        redis_acl::hash_secret("nokeys-secret", test_iters) +
        " read_write\n"
        "user off disabled read_write sccache/\n"
        "user open nopass read_only public/ cert=CN=open.example\n";
    acl.reload(text);
}

}  // namespace

BOOST_AUTO_TEST_CASE(hash_and_verify_round_trip, *boost::unit_test::timeout(30)) {
    auto record = redis_acl::hash_secret("hunter2", test_iters);
    BOOST_CHECK(record.rfind("pbkdf2-sha256$1000$", 0) == 0);
    BOOST_CHECK(redis_acl::verify_secret(record, "hunter2"));
    BOOST_CHECK(!redis_acl::verify_secret(record, "hunter3"));
    BOOST_CHECK(!redis_acl::verify_secret(record, ""));
    // Two hashes of the same secret differ (fresh salt each time).
    BOOST_CHECK(record != redis_acl::hash_secret("hunter2", test_iters));
    // Malformed records never verify.
    BOOST_CHECK(!redis_acl::verify_secret("pbkdf2-sha256$0$abcd$abcd", "hunter2"));
    BOOST_CHECK(!redis_acl::verify_secret("plain:hunter2", "hunter2"));
    BOOST_CHECK(!redis_acl::verify_secret("pbkdf2-sha256$1000$!!!!$abcd", "hunter2"));
}

BOOST_AUTO_TEST_CASE(authenticate_accepts_only_correct_pairs, *boost::unit_test::timeout(30)) {
    redis_acl acl;
    load_acl(acl);
    auto id = acl.authenticate("farm", "farm-secret");
    BOOST_REQUIRE(id.has_value());
    BOOST_CHECK_EQUAL(id->_user, "farm");
    BOOST_CHECK(id->_role == redis_role::read_write);
    BOOST_CHECK(id->_key_prefixes == (std::vector<std::string>{"sccache/"}));

    BOOST_CHECK(!acl.authenticate("farm", "wrong").has_value());
    BOOST_CHECK(!acl.authenticate("nobody", "farm-secret").has_value());
    BOOST_CHECK(!acl.authenticate("off", "anything").has_value());
}

// Audit H1: a `nopass` user is certificate-only. AUTH with any password —
// empty, arbitrary, or the user's own name — must be refused, or anyone who
// can reach the plaintext listener gets that user's role.
BOOST_AUTO_TEST_CASE(nopass_user_rejects_password_auth, *boost::unit_test::timeout(30)) {
    redis_acl acl;
    acl.reload("user ops nopass admin * cert=CN=ops\n");
    BOOST_CHECK(!acl.authenticate("ops", "").has_value());
    BOOST_CHECK(!acl.authenticate("ops", "x").has_value());
    BOOST_CHECK(!acl.authenticate("ops", "ops").has_value());

    // The certificate path still works.
    auto id = acl.authenticate_certificate("CN=ops");
    BOOST_REQUIRE(id.has_value());
    BOOST_CHECK_EQUAL(id->_user, "ops");
    BOOST_CHECK(id->_role == redis_role::admin);

    // A table built directly (bypassing the parser) is held to the same rule.
    redis_acl direct({redis_acl_user{"raw", "", true, redis_role::admin, {""}, {}}});
    BOOST_CHECK(!direct.authenticate("raw", "").has_value());
    BOOST_CHECK(!direct.authenticate("raw", "anything").has_value());
}

BOOST_AUTO_TEST_CASE(parse_rejects_nopass_without_cert, *boost::unit_test::timeout(30)) {
    BOOST_CHECK_THROW(redis_acl::parse("user ops nopass admin *\n"), redis_acl_parse_error);
    BOOST_CHECK_NO_THROW(redis_acl::parse("user ops nopass admin * cert=CN=ops\n"));
    // `disabled` needs no certificate: nobody can authenticate as it anyway.
    BOOST_CHECK_NO_THROW(redis_acl::parse("user off disabled read_only\n"));
}

BOOST_AUTO_TEST_CASE(certificate_subject_maps_to_user, *boost::unit_test::timeout(30)) {
    redis_acl acl;
    load_acl(acl);
    auto id = acl.authenticate_certificate("CN=ops.example");
    BOOST_REQUIRE(id.has_value());
    BOOST_CHECK_EQUAL(id->_user, "ops");
    BOOST_CHECK(id->_role == redis_role::admin);
    BOOST_CHECK(!acl.authenticate_certificate("CN=stranger").has_value());
}

BOOST_AUTO_TEST_CASE(authorize_by_role_and_prefix, *boost::unit_test::timeout(30)) {
    redis_acl acl;
    load_acl(acl);
    auto farm = *acl.authenticate("farm", "farm-secret");
    auto reader = *acl.authenticate("reader", "reader-secret");
    auto ops = *acl.authenticate("ops", "ops-secret");
    auto nokeys = *acl.authenticate("nokeys", "nokeys-secret");

    BOOST_CHECK(redis_acl::authorize(farm, "SET", {"sccache/abc"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(farm, "GET", {"sccache/abc"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(farm, "SET", {"other/abc"}) == acl_decision::deny_key);
    BOOST_CHECK(redis_acl::authorize(farm, "INFO", {}) == acl_decision::deny_command);

    BOOST_CHECK(redis_acl::authorize(reader, "GET", {"sccache/abc"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(reader, "SET", {"sccache/abc"}) == acl_decision::deny_command);
    BOOST_CHECK(redis_acl::authorize(reader, "DEL", {"sccache/abc"}) == acl_decision::deny_command);
    BOOST_CHECK(redis_acl::authorize(reader, "PING", {}) == acl_decision::allow);

    BOOST_CHECK(redis_acl::authorize(ops, "INFO", {}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(ops, "SET", {"anything"}) == acl_decision::allow);

    // A user with no prefixes may run key-less commands but reach no key.
    BOOST_CHECK(redis_acl::authorize(nokeys, "PING", {}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(nokeys, "GET", {"sccache/abc"}) == acl_decision::deny_key);
    BOOST_CHECK(redis_acl::authorize(nokeys, "GET", {""}) == acl_decision::deny_key);

    // Commands outside the closure are command denials.
    BOOST_CHECK(redis_acl::authorize(ops, "FLUSHALL", {}) == acl_decision::deny_command);
}

BOOST_AUTO_TEST_CASE(parse_rejects_malformed_lines, *boost::unit_test::timeout(30)) {
    BOOST_CHECK_THROW(redis_acl::parse("user\n"), redis_acl_parse_error);
    BOOST_CHECK_THROW(redis_acl::parse("account a nopass read_only\n"), redis_acl_parse_error);
    BOOST_CHECK_THROW(redis_acl::parse("user a plaintext read_only\n"), redis_acl_parse_error);
    BOOST_CHECK_THROW(redis_acl::parse("user a nopass god\n"), redis_acl_parse_error);
    BOOST_CHECK_THROW(redis_acl::parse("user a nopass read_only cert=\n"), redis_acl_parse_error);
    BOOST_CHECK_THROW(redis_acl::parse("user a disabled read_only\nuser a disabled admin\n"),
                      redis_acl_parse_error);
    // The error names the line.
    try {
        (void)redis_acl::parse("user a disabled read_only\n\nuser b disabled nope\n");
        BOOST_FAIL("expected parse error");
    } catch (const redis_acl_parse_error& e) {
        BOOST_CHECK(std::string(e.what()).find("line 3") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(reload_failure_keeps_prior_table, *boost::unit_test::timeout(30)) {
    redis_acl acl;
    load_acl(acl);
    BOOST_CHECK_THROW(acl.reload("user broken\n"), redis_acl_parse_error);
    BOOST_CHECK(acl.authenticate("farm", "farm-secret").has_value());

    // A successful reload swaps in the new table wholesale.
    acl.reload("user solo nopass read_only x/ cert=CN=solo\n");
    BOOST_CHECK(!acl.authenticate("farm", "farm-secret").has_value());
    BOOST_CHECK(acl.authenticate_certificate("CN=solo").has_value());
}

BOOST_AUTO_TEST_CASE(empty_acl_denies_everyone, *boost::unit_test::timeout(30)) {
    redis_acl acl;
    BOOST_CHECK(acl.empty());
    BOOST_CHECK(!acl.authenticate("anyone", "anything").has_value());
}

BOOST_AUTO_TEST_CASE(role_names_round_trip, *boost::unit_test::timeout(30)) {
    BOOST_CHECK(parse_redis_role("read_only") == redis_role::read_only);
    BOOST_CHECK(parse_redis_role("rw") == redis_role::read_write);
    BOOST_CHECK(parse_redis_role("admin") == redis_role::admin);
    BOOST_CHECK(!parse_redis_role("root").has_value());
    BOOST_CHECK_EQUAL(redis_role_name(redis_role::read_write), "read_write");
}

// IAM task 21 (Requirement 13.1): `auth=` is a reserved attribute, like
// `cert=`, not the key prefix it was before (redis-gateway-module task 1
// pinned that reading here). An `auth=iam` user has no password, whatever
// its record says; `auth=both` keeps it.
BOOST_AUTO_TEST_CASE(auth_attribute_is_reserved_not_a_key_prefix, *boost::unit_test::timeout(30)) {
    redis_acl acl;
    acl.reload("user farm " + redis_acl::hash_secret("farm-secret", test_iters) +
               " read_write auth=iam sccache/\n" + "user both " +
               redis_acl::hash_secret("both-secret", test_iters) +
               " read_only sccache/ auth=both\n" + "user plain " +
               redis_acl::hash_secret("plain-secret", test_iters) + " read_only sccache/\n" +
               "user explicit " + redis_acl::hash_secret("explicit-secret", test_iters) +
               " read_only sccache/ auth=password\n");

    const auto users =
        redis_acl::parse("user farm " + redis_acl::hash_secret("farm-secret", test_iters) +
                         " read_write auth=iam sccache/\n");
    BOOST_REQUIRE_EQUAL(users.size(), 1U);
    BOOST_CHECK(users[0]._key_prefixes == (std::vector<std::string>{"sccache/"}));
    BOOST_CHECK(users[0]._auth == kythira::redis_auth_mode::iam);

    BOOST_CHECK(!acl.authenticate("farm", "farm-secret").has_value());
    BOOST_CHECK(acl.auth_mode_of("farm") == kythira::redis_auth_mode::iam);
    auto farm = acl.identity_of("farm");
    BOOST_REQUIRE(farm.has_value());
    BOOST_CHECK(farm->_key_prefixes == (std::vector<std::string>{"sccache/"}));

    BOOST_CHECK(acl.authenticate("both", "both-secret").has_value());
    BOOST_CHECK(acl.auth_mode_of("both") == kythira::redis_auth_mode::both);
    BOOST_CHECK(acl.authenticate("plain", "plain-secret").has_value());
    BOOST_CHECK(acl.auth_mode_of("plain") == kythira::redis_auth_mode::password);
    BOOST_CHECK(acl.auth_mode_of("explicit") == kythira::redis_auth_mode::password);
    BOOST_CHECK(!acl.auth_mode_of("nobody").has_value());
}

BOOST_AUTO_TEST_CASE(auth_attribute_rejects_repeated_and_unknown_values,
                     *boost::unit_test::timeout(30)) {
    const auto secret = redis_acl::hash_secret("s", test_iters);
    BOOST_CHECK_THROW(
        (void)redis_acl::parse("user u " + secret + " read_only p/ auth=iam auth=iam"),
        kythira::redis_acl_parse_error);
    BOOST_CHECK_THROW(
        (void)redis_acl::parse("user u " + secret + " read_only p/ auth=iam auth=password"),
        kythira::redis_acl_parse_error);
    BOOST_CHECK_THROW((void)redis_acl::parse("user u " + secret + " read_only p/ auth=IAM"),
                      kythira::redis_acl_parse_error);
    BOOST_CHECK_THROW((void)redis_acl::parse("user u " + secret + " read_only p/ auth="),
                      kythira::redis_acl_parse_error);
    BOOST_CHECK_THROW((void)redis_acl::parse("user u " + secret + " read_only p/ auth=token"),
                      kythira::redis_acl_parse_error);
    // A bad edit keeps the table in force.
    redis_acl acl;
    acl.reload("user u " + secret + " read_only p/\n");
    BOOST_CHECK_THROW(acl.reload("user u " + secret + " read_only p/ auth=nope\n"),
                      kythira::redis_acl_parse_error);
    BOOST_CHECK(acl.authenticate("u", "s").has_value());
}

// `nopass` and `disabled` for a user that is not `password`: no `cert=` is
// needed, and `disabled` means no password rather than no login. An older
// gateway refuses a `disabled` user outright, which is how an IAM-only user
// stays IAM-only while the gateways roll (Requirement 13.1).
BOOST_AUTO_TEST_CASE(an_iam_user_needs_no_password_and_disabled_keeps_it_iam_only,
                     *boost::unit_test::timeout(30)) {
    redis_acl acl;
    acl.reload(
        "user a nopass read_only p/ auth=iam\nuser b disabled read_write p/ auth=iam\n"
        "user c disabled read_only p/\nuser d disabled read_only p/ auth=both\n");
    BOOST_CHECK(acl.identity_of("a").has_value());
    BOOST_CHECK(acl.identity_of("b").has_value());
    BOOST_CHECK(acl.auth_mode_of("b") == kythira::redis_auth_mode::iam);
    BOOST_CHECK(!acl.authenticate("b", "disabled").has_value());
    BOOST_CHECK(!acl.identity_of("c").has_value());
    BOOST_CHECK(!acl.auth_mode_of("c").has_value());
    BOOST_CHECK(acl.identity_of("d").has_value());
    BOOST_CHECK(!acl.authenticate("d", "").has_value());
    // A password user with `nopass` still needs a certificate.
    BOOST_CHECK_THROW((void)redis_acl::parse("user e nopass read_only p/\n"),
                      kythira::redis_acl_parse_error);
}

// ── categories, single commands, scopes, mutable prefixes ──────────────────
// (.kiro/specs/redis-general-data-types/ task 5, Requirements 5.2, 15.1-15.3)

namespace {
auto only_user(const std::string& rest) -> redis_identity {
    auto users = redis_acl::parse("user u disabled " + rest + "\n");
    BOOST_REQUIRE_EQUAL(users.size(), 1U);
    return redis_identity_of(users[0]);
}
}  // namespace

BOOST_AUTO_TEST_CASE(roles_are_category_sets, *boost::unit_test::timeout(30)) {
    // Every shipped command: the role grants it exactly when the category
    // set the documentation gives for the role does.
    const auto ro = only_user("read_only *");
    const auto rw = only_user("read_write *");
    const auto ad = only_user("admin *");
    const auto ro_rules = only_user("admin * +@all -@write -@admin -@dangerous");
    const auto rw_rules = only_user("admin * +@all -@admin -@dangerous");
    for (const auto& c : k_redis_commands) {
        if (c.status != redis_command_status::shipped || c.name == "KYTHIRA.ADVISE" ||
            c.name == "KYTHIRA.INSTALL" || c.name == "KYTHIRA.TXN") {
            continue;
        }
        BOOST_TEST_CONTEXT(c.name) {
            BOOST_CHECK_EQUAL(redis_acl::command_allowed(ro, c.name),
                              redis_acl::command_allowed(ro_rules, c.name));
            BOOST_CHECK_EQUAL(redis_acl::command_allowed(rw, c.name),
                              redis_acl::command_allowed(rw_rules, c.name));
            BOOST_CHECK(redis_acl::command_allowed(ad, c.name));
        }
    }
    // The internal hop is in the read_write set whatever its categories.
    BOOST_CHECK(redis_acl::command_allowed(rw, "KYTHIRA.TXN"));
    BOOST_CHECK(!redis_acl::command_allowed(ro, "KYTHIRA.TXN"));
}

BOOST_AUTO_TEST_CASE(later_command_rules_win, *boost::unit_test::timeout(30)) {
    const auto u = only_user("read_only app: +@write -set -SETEX +incr");
    BOOST_CHECK(redis_acl::authorize(u, "INCR", {"app:n"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "APPEND", {"app:n"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "SET", {"app:n"}) == acl_decision::deny_command);
    BOOST_CHECK(redis_acl::authorize(u, "SETEX", {"app:n"}) == acl_decision::deny_command);
    BOOST_CHECK(redis_acl::authorize(u, "GET", {"app:n"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "INFO", {}) == acl_decision::deny_command);

    const auto v = only_user("admin * nocommands +@read +@connection");
    BOOST_CHECK(redis_acl::authorize(v, "GET", {"k"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(v, "PING", {}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(v, "SET", {"k"}) == acl_decision::deny_command);
    BOOST_CHECK(redis_acl::authorize(v, "INFO", {}) == acl_decision::deny_command);

    // A rule never reaches a command this build does not ship.
    const auto w = only_user("admin * allcommands +flushall");
    BOOST_CHECK(redis_acl::authorize(w, "FLUSHALL", {}) == acl_decision::deny_command);
    // Categories with no command yet are accepted and match nothing.
    const auto x = only_user("read_only * -@pubsub -@sortedset");
    BOOST_CHECK(redis_acl::authorize(x, "GET", {"k"}) == acl_decision::allow);
}

BOOST_AUTO_TEST_CASE(read_and_write_scopes, *boost::unit_test::timeout(30)) {
    const auto u = only_user("read_write %R~shared:* %W~inbox: ~own:");
    // Reads need a read scope, writes a write scope, and a write that
    // returns the old value needs both.
    BOOST_CHECK(redis_acl::authorize(u, "GET", {"shared:a"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "SET", {"shared:a"}) == acl_decision::deny_key);
    BOOST_CHECK(redis_acl::authorize(u, "SET", {"inbox:a"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "GET", {"inbox:a"}) == acl_decision::deny_key);
    BOOST_CHECK(redis_acl::authorize(u, "INCR", {"inbox:a"}) == acl_decision::deny_key);
    BOOST_CHECK(redis_acl::authorize(u, "GETDEL", {"own:a"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "EXPIRE", {"inbox:a"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "SET", {"inbox:a"},
                                     redis_key_access::read | redis_key_access::write) ==
                acl_decision::deny_key);
    // Metadata reads accept either scope.
    BOOST_CHECK(redis_acl::authorize(u, "TTL", {"inbox:a"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "EXISTS", {"shared:a"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "EXISTS", {"other:a"}) == acl_decision::deny_key);
    BOOST_CHECK(redis_acl::authorize(u, "MGET", {"shared:a", "own:b"}) == acl_decision::allow);
    BOOST_CHECK(redis_acl::authorize(u, "MGET", {"shared:a", "inbox:b"}) == acl_decision::deny_key);

    const auto all = only_user("read_only allkeys");
    BOOST_CHECK(redis_acl::authorize(all, "GET", {"anything"}) == acl_decision::allow);
    const auto rw = only_user("read_only %RW~a:");
    BOOST_CHECK(redis_acl::authorize(rw, "GET", {"a:1"}) == acl_decision::allow);
}

BOOST_AUTO_TEST_CASE(mutable_prefixes, *boost::unit_test::timeout(30)) {
    const auto u = only_user("read_write * mutable~counters:* mutable~app:");
    BOOST_CHECK(redis_acl::key_is_mutable(u, "counters:x"));
    BOOST_CHECK(redis_acl::key_is_mutable(u, "app:"));
    BOOST_CHECK(!redis_acl::key_is_mutable(u, "sccache/x"));
    BOOST_CHECK(!redis_acl::key_is_mutable(only_user("admin *"), "x"));
    // A mutable prefix grants no access by itself.
    const auto v = only_user("read_write mutable~app:");
    BOOST_CHECK(redis_acl::authorize(v, "SET", {"app:x"}) == acl_decision::deny_key);
}

BOOST_AUTO_TEST_CASE(new_syntax_refuses_what_it_cannot_honour, *boost::unit_test::timeout(30)) {
    for (const auto* bad : {"read_only ~a*b", "read_only %R~a?", "read_only %X~a", "read_only %R",
                            "read_only +@nosuch", "read_only +nosuch", "read_only +client|list",
                            "read_only mutable~[ab]"}) {
        BOOST_TEST_CONTEXT(bad) {
            BOOST_CHECK_THROW((void)redis_acl::parse(std::string("user u disabled ") + bad + "\n"),
                              redis_acl_parse_error);
        }
    }
}
