// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/kms-independent-layers/ task 1 (Requirements 3.1-3.3): the
// catalog seam handlers and jobs are built over. The local reader answers
// exactly what the replica does; the local access's barrier, reader and
// proposals are the host's; and a catalog that cannot answer fails the
// request with KMSInternalException, never "not found". Every API test
// (kms_api_fixture.hpp) also runs through the seam.

#define BOOST_TEST_MODULE kms_catalog_access_test

#include "kms_api_fixture.hpp"

#include <atomic>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

/// Every query of `r` and of the replica `sm` agrees for `account` and
/// `key_id`.
void require_same(const reader_t& r, const catalog_t& sm, std::string_view account,
                  std::string_view key_id, std::uint64_t now) {
    BOOST_TEST_CONTEXT("account " << account << ", key " << key_id) {
        BOOST_TEST((r.key(key_id) == sm.key(key_id)));
        BOOST_TEST(r.tombstoned(key_id) == sm.tombstoned(key_id));
        BOOST_TEST((r.keys(account) == sm.keys(account)));
        BOOST_TEST((r.keys(account, key_id, 2) == sm.keys(account, key_id, 2)));
        BOOST_TEST((r.versions(key_id) == sm.versions(key_id)));
        for (std::uint32_t v = 0; v <= 3; ++v) {
            BOOST_TEST((r.version(key_id, v) == sm.version(key_id, v)));
        }
        BOOST_TEST((r.tags(key_id) == sm.tags(key_id)));
        BOOST_TEST((r.aliases(account) == sm.aliases(account)));
        BOOST_TEST((r.aliases(account, key_id) == sm.aliases(account, key_id)));
        for (const auto& a : sm.aliases(account)) {
            BOOST_TEST((r.alias(account, a.name) == sm.alias(account, a.name)));
        }
        BOOST_TEST(!r.alias(account, "alias/none").has_value());
        BOOST_TEST((r.grants(key_id) == sm.grants(key_id)));
        for (const auto& g : sm.grants(key_id)) {
            BOOST_TEST((r.grant(key_id, g.grant_id) == sm.grant(key_id, g.grant_id)));
        }
        BOOST_TEST((r.counts(account) == sm.counts(account)));
        BOOST_TEST((r.limits(account) == sm.limits(account)));
        BOOST_TEST((r.creating_keys() == sm.creating_keys()));
        BOOST_TEST((r.due_deletions(now) == sm.due_deletions(now)));
        BOOST_TEST((r.due_rotations(now) == sm.due_rotations(now)));
    }
}

auto grant(std::string_view key_id, std::string_view grant_id, std::string_view grantee)
    -> kms::grant_record {
    kms::grant_record g;
    g.grant_id = std::string(grant_id);
    g.key_id = std::string(key_id);
    g.grantee_principal = std::string(grantee);
    g.issuing_account = std::string(k_account);
    g.operations = {"Decrypt"};
    g.created_ms = 1;
    return g;
}

/// A reader over another that throws kms_catalog_unreachable while
/// `down`, as a remote reader that lost the data layer does.
class flaky_reader final : public reader_t {
public:
    flaky_reader(std::shared_ptr<const reader_t> inner, const std::atomic<bool>& down)
        : _inner(std::move(inner)), _down(&down) {}

    [[nodiscard]] auto key(std::string_view id) const -> std::optional<kms::key_record> override {
        check();
        return _inner->key(id);
    }
    [[nodiscard]] auto tombstoned(std::string_view id) const -> bool override {
        check();
        return _inner->tombstoned(id);
    }
    [[nodiscard]] auto keys(std::string_view a, std::string_view after, std::size_t limit) const
        -> std::vector<std::string> override {
        check();
        return _inner->keys(a, after, limit);
    }
    [[nodiscard]] auto versions(std::string_view id) const
        -> std::vector<kms::key_version> override {
        check();
        return _inner->versions(id);
    }
    [[nodiscard]] auto version(std::string_view id, std::uint32_t v) const
        -> std::optional<kms::key_version> override {
        check();
        return _inner->version(id, v);
    }
    [[nodiscard]] auto tags(std::string_view id) const -> kms::tag_map override {
        check();
        return _inner->tags(id);
    }
    [[nodiscard]] auto alias(std::string_view a, std::string_view n) const
        -> std::optional<kms::alias_record> override {
        check();
        return _inner->alias(a, n);
    }
    [[nodiscard]] auto aliases(std::string_view a, std::string_view id) const
        -> std::vector<kms::alias_record> override {
        check();
        return _inner->aliases(a, id);
    }
    [[nodiscard]] auto grant(std::string_view id, std::string_view g) const
        -> std::optional<kms::grant_record> override {
        check();
        return _inner->grant(id, g);
    }
    [[nodiscard]] auto grants(std::string_view id) const
        -> std::vector<kms::grant_record> override {
        check();
        return _inner->grants(id);
    }
    [[nodiscard]] auto counts(std::string_view a) const -> kms::account_counts override {
        check();
        return _inner->counts(a);
    }
    [[nodiscard]] auto limits(std::string_view a) const -> kms::account_limits override {
        check();
        return _inner->limits(a);
    }
    [[nodiscard]] auto creating_keys() const -> std::vector<kms::key_record> override {
        check();
        return _inner->creating_keys();
    }
    [[nodiscard]] auto due_deletions(std::uint64_t now) const
        -> std::vector<kms::key_record> override {
        check();
        return _inner->due_deletions(now);
    }
    [[nodiscard]] auto due_rotations(std::uint64_t now) const
        -> std::vector<kms::key_record> override {
        check();
        return _inner->due_rotations(now);
    }

private:
    void check() const {
        if (_down->load()) {
            throw kms::kms_catalog_unreachable("the data layer did not answer");
        }
    }
    std::shared_ptr<const reader_t> _inner;
    const std::atomic<bool>* _down;
};

class flaky_access final : public kms::kms_catalog_access {
public:
    explicit flaky_access(kms::kms_catalog_access& inner) : _inner(&inner) {}
    std::atomic<bool> down{false};

    auto barrier() -> bool override { return _inner->barrier(); }
    [[nodiscard]] auto reader() const -> std::shared_ptr<const reader_t> override {
        auto r = _inner->reader();
        return r ? std::make_shared<const flaky_reader>(std::move(r), down) : nullptr;
    }
    auto propose(const std::vector<std::byte>& c) -> kms::catalog_status override {
        return _inner->propose(c);
    }

private:
    kms::kms_catalog_access* _inner;
};

}  // namespace

// Requirement 3.3: the seam changes no answer.
BOOST_AUTO_TEST_CASE(the_local_reader_answers_what_the_replica_does) {
    fixture f;
    const auto a = f.create(R"({"Description":"a","Tags":[{"TagKey":"t","TagValue":"1"}]})");
    const auto b = f.create(R"({"Description":"b"})");
    const auto c = f.create(R"({"Description":"c"})");
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/a","TargetKeyId":")" + a + R"("})").status ==
        200U);
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/b","TargetKeyId":")" + a + R"("})").status ==
        200U);
    BOOST_REQUIRE(f.call("EnableKeyRotation", kid(b)).status == 200U);
    BOOST_REQUIRE(f.call("RotateKeyOnDemand", kid(b)).status == 200U);
    BOOST_REQUIRE(f.call("DisableKey", kid(c)).status == 200U);
    BOOST_REQUIRE(
        f.call("ScheduleKeyDeletion", R"({"KeyId":")" + c + R"(","PendingWindowInDays":7})")
            .status == 200U);
    BOOST_REQUIRE(f.propose(kms::make_create_grant_command(grant(
                      a, "g1", "arn:aws:iam::111122223333:role/r"))) == kms::catalog_status::ok);
    BOOST_REQUIRE(f.propose(kms::make_create_grant_command(grant(
                      a, "g2", "arn:aws:iam::111122223333:role/s"))) == kms::catalog_status::ok);
    BOOST_REQUIRE(f.propose(kms::make_set_account_limits_command(std::string(k_account), {9, 9})) ==
                  kms::catalog_status::ok);

    const auto r = f.access.reader();
    BOOST_REQUIRE(r != nullptr);
    for (const auto now : {f.now, f.now + (400 * kms::k_ms_per_day)}) {
        for (const auto& id : {a, b, c, std::string("00000000-0000-4000-8000-000000000000")}) {
            require_same(*r, f.sm, k_account, id, now);
            require_same(*r, f.sm, k_other, id, now);
        }
    }

    // A key destroyed at the end of its window is tombstoned in both.
    f.now += 8 * kms::k_ms_per_day;
    std::ignore = f.jobs.run_once();
    BOOST_TEST(f.sm.tombstoned(c));
    require_same(*r, f.sm, k_account, c, f.now);
}

BOOST_AUTO_TEST_CASE(conveniences_resolve_by_id_and_alias_and_filter_grants) {
    fixture f;
    const auto a = f.create();
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/a","TargetKeyId":")" + a + R"("})").status ==
        200U);
    BOOST_REQUIRE(f.propose(kms::make_create_grant_command(grant(a, "g1", "role/r"))) ==
                  kms::catalog_status::ok);
    BOOST_REQUIRE(f.propose(kms::make_create_grant_command(grant(a, "g2", "role/s"))) ==
                  kms::catalog_status::ok);
    const auto r = f.access.reader();

    BOOST_TEST(r->resolve(k_account, a)->key_id == a);
    BOOST_TEST(r->resolve(k_account, "alias/a")->key_id == a);
    BOOST_TEST(!r->resolve(k_other, "alias/a").has_value());  // aliases are per account
    BOOST_TEST(!r->resolve(k_account, "alias/none").has_value());

    const auto mine = r->grants_for(a, "role/r");
    BOOST_REQUIRE(mine.size() == 1U);
    BOOST_TEST(mine[0].grant_id == "g1");
    BOOST_TEST(r->grants_for(a, "role/t").empty());

    BOOST_TEST((r->policy(a) == f.sm.key(a)->policy));
    BOOST_TEST(!r->policy("00000000-0000-4000-8000-000000000000").has_value());
}

BOOST_AUTO_TEST_CASE(the_local_access_is_the_hosts_barrier_reader_and_proposals) {
    kythira::memory_kv_engine engine;
    auto first = std::make_shared<catalog_t>("kms/");
    first->open(engine, first->engine_range());
    std::shared_ptr<const catalog_t> replica;  // not open yet
    bool barrier_ok = true;
    std::vector<std::vector<std::byte>> proposed;
    kms::local_catalog_access<catalog_t> access{{
        .replica = [&] { return replica; },
        .barrier = [&] { return barrier_ok; },
        .propose =
            [&](const std::vector<std::byte>& c) {
                if (c.empty()) {
                    throw std::runtime_error("no leader");
                }
                proposed.push_back(c);
                return kms::catalog_status::ok;
            },
    }};

    // Before the catalog opens there is nothing to read.
    BOOST_TEST(access.reader() == nullptr);
    BOOST_TEST(access.consistent() == nullptr);

    // One reader serves while the replica stays; a reopened replica gets
    // a new one.
    replica = first;
    const auto r1 = access.reader();
    BOOST_REQUIRE(r1 != nullptr);
    BOOST_TEST(access.reader() == r1);
    BOOST_TEST(access.consistent() == r1);
    kythira::memory_kv_engine engine2;
    auto second = std::make_shared<catalog_t>("kms/");
    second->open(engine2, second->engine_range());
    replica = second;
    const auto r2 = access.reader();
    BOOST_TEST(r2 != r1);
    BOOST_TEST(access.reader() == r2);

    // No read-index point, no reader.
    barrier_ok = false;
    BOOST_TEST(!access.barrier());
    BOOST_TEST(access.consistent() == nullptr);

    // Proposals are the host's, failures included.
    const auto cmd = kms::make_set_enabled_command("00000000-0000-4000-8000-000000000000", true);
    BOOST_TEST((access.propose(cmd) == kms::catalog_status::ok));
    BOOST_REQUIRE(proposed.size() == 1U);
    BOOST_TEST((proposed[0] == cmd));
    BOOST_CHECK_THROW(std::ignore = access.propose({}), std::runtime_error);

    // Every function is required.
    BOOST_CHECK_THROW((kms::local_catalog_access<catalog_t>{{}}), std::invalid_argument);
    BOOST_CHECK_THROW(kms::local_catalog_reader<catalog_t>{nullptr}, std::invalid_argument);
}

// independent-layers Requirement 4.3: a catalog that cannot answer is an
// internal error, not an absent key, and no answer is made from it.
BOOST_AUTO_TEST_CASE(an_unreachable_catalog_answers_internal_error_not_not_found) {
    fixture f;
    const auto id = f.create();
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/a","TargetKeyId":")" + id + R"("})").status ==
        200U);

    flaky_access flaky(f.access);
    kms::front_end<test_authorizer> fe{fixture::config(), f.auth};
    auto deps = kms::api_deps<reader_t>{.clock_ms = [&f] { return f.now; }};
    kms::fill_catalog_deps(deps, flaky);
    kms::key_management_api<reader_t> api{deps};
    kms::crypto_deps<reader_t> cdeps{.hsm = [&f] { return f.hsm; }};
    kms::fill_catalog_deps(cdeps, flaky);
    kms::crypto_api<reader_t> crypto{cdeps};
    api.register_on(fe);
    crypto.register_on(fe);
    const auto call = [&](std::string_view op, const std::string& body) {
        return fixture::answer(fe.handle(sign(request(op, body), "AKIDADMIN")));
    };

    // Up: the same answers as the fixture's own front end.
    BOOST_TEST(call("DescribeKey", kid("alias/a")).str("KeyMetadata", "KeyId") == id);
    BOOST_TEST(call("DescribeKey", kid("alias/none")).type() == "NotFoundException");
    const auto enc = call("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"aGVsbG8="})");
    BOOST_REQUIRE(enc.status == 200U);

    // Down: every read fails as internal, and nothing is said about the key.
    flaky.down = true;
    for (const auto& [op, body] : std::vector<std::pair<std::string, std::string>>{
             {"DescribeKey", kid(id)},
             {"DescribeKey", kid("alias/none")},
             {"ListKeys", "{}"},
             {"ListAliases", "{}"},
             {"Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"aGVsbG8="})"},
             {"Decrypt", R"({"CiphertextBlob":")" + enc.str("CiphertextBlob") + R"("})"},
         }) {
        const auto r = call(op, body);
        BOOST_TEST(r.status == 500U, op);
        BOOST_TEST(r.type() == "KMSInternalException", op);
    }

    flaky.down = false;
    BOOST_TEST(call("DescribeKey", kid(id)).status == 200U);
}
