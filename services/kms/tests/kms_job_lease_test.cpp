// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/kms-independent-layers/ task 2 (Requirements 5.1-5.3): the
// job lease in the catalog. One holder at a time, renewals keep the token,
// a new holder gets the next one; fenced job commands apply only under the
// current token, so a holder that stalled past its lease cannot commit a
// step after another took over, as the jobs themselves show.

#define BOOST_TEST_MODULE kms_job_lease_test

#include "kms_api_fixture.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

constexpr std::uint64_t k_lease_ms = 30'000;

auto status(fixture& f, const std::vector<std::byte>& cmd) -> kms::catalog_status {
    return f.propose(cmd);
}

auto acquire(fixture& f, std::string_view who, std::uint64_t now) -> kms::catalog_status {
    return status(f, kms::make_acquire_lease_command(who, now, k_lease_ms));
}

}  // namespace

BOOST_AUTO_TEST_CASE(one_holder_at_a_time_and_each_new_holder_gets_a_new_token) {
    fixture f;
    const std::uint64_t t = 1'000'000;
    BOOST_TEST((f.sm.lease() == kms::job_lease{}));

    // Free: taken, token 1.
    BOOST_TEST((acquire(f, "a", t) == kms::catalog_status::ok));
    auto l = f.sm.lease();
    BOOST_TEST(l.holder == "a");
    BOOST_TEST(l.token == 1U);
    BOOST_TEST(l.expiry_ms == t + k_lease_ms);
    BOOST_TEST(l.held_by("a", t));
    BOOST_TEST(!l.held_by("a", t + k_lease_ms));
    BOOST_TEST(!l.held_by("b", t));

    // Renewed by its holder: same token, later expiry.
    BOOST_TEST((acquire(f, "a", t + 10'000) == kms::catalog_status::ok));
    l = f.sm.lease();
    BOOST_TEST(l.token == 1U);
    BOOST_TEST(l.expiry_ms == t + 10'000 + k_lease_ms);

    // Another member while it is live: refused, nothing changes.
    BOOST_TEST((acquire(f, "b", t + 20'000) == kms::catalog_status::stale_lease));
    BOOST_TEST((f.sm.lease() == l));

    // Once it has expired: the other member takes it, with token 2.
    BOOST_TEST((acquire(f, "b", l.expiry_ms) == kms::catalog_status::ok));
    l = f.sm.lease();
    BOOST_TEST(l.holder == "b");
    BOOST_TEST(l.token == 2U);

    // Released by a member that does not hold it, or with an old token:
    // refused.
    BOOST_TEST(
        (status(f, kms::make_release_lease_command("a", 2)) == kms::catalog_status::stale_lease));
    BOOST_TEST(
        (status(f, kms::make_release_lease_command("b", 1)) == kms::catalog_status::stale_lease));
    BOOST_TEST(f.sm.lease().holder == "b");

    // Released by its holder: free at once, the token kept so the next
    // holder's is new.
    BOOST_TEST((status(f, kms::make_release_lease_command("b", 2)) == kms::catalog_status::ok));
    l = f.sm.lease();
    BOOST_TEST(l.holder.empty());
    BOOST_TEST(l.token == 2U);
    BOOST_TEST(
        (status(f, kms::make_release_lease_command("b", 2)) == kms::catalog_status::stale_lease));
    BOOST_TEST((acquire(f, "a", t + 50'000) == kms::catalog_status::ok));
    BOOST_TEST(f.sm.lease().token == 3U);

    // Malformed lease requests are bugs.
    BOOST_CHECK_THROW(std::ignore = acquire(f, "", t), std::invalid_argument);
    BOOST_CHECK_THROW(std::ignore = status(f, kms::make_acquire_lease_command("a", t, 0)),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(fenced_commands_apply_only_under_the_current_token) {
    fixture f;
    const auto id = f.create();
    const std::uint64_t t = 1'000'000;
    BOOST_REQUIRE((acquire(f, "a", t) == kms::catalog_status::ok));
    const auto disable = kms::make_set_enabled_command(id, false);
    const auto enable = kms::make_set_enabled_command(id, true);

    // Token 1 is current: the command applies, and answers its own status.
    BOOST_TEST((status(f, kms::make_fenced_command(1, disable)) == kms::catalog_status::ok));
    BOOST_TEST((f.sm.key(id)->state == kms::key_state::disabled));
    BOOST_TEST((
        status(f, kms::make_fenced_command(1, kms::make_set_enabled_command(
                                                  "00000000-0000-4000-8000-000000000000", true))) ==
        kms::catalog_status::not_found));

    // Another member takes over (token 2): token 1's commands change
    // nothing, and neither does token 0 or a token from the future.
    BOOST_REQUIRE((acquire(f, "b", t + k_lease_ms) == kms::catalog_status::ok));
    for (const std::uint64_t token : {std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{3}}) {
        BOOST_TEST((status(f, kms::make_fenced_command(token, enable)) ==
                    kms::catalog_status::stale_lease),
                   token);
        BOOST_TEST((f.sm.key(id)->state == kms::key_state::disabled), token);
    }
    BOOST_TEST((status(f, kms::make_fenced_command(2, enable)) == kms::catalog_status::ok));
    BOOST_TEST((f.sm.key(id)->state == kms::key_state::enabled));

    // A released lease fences everything until it is taken again.
    BOOST_REQUIRE((status(f, kms::make_release_lease_command("b", 2)) == kms::catalog_status::ok));
    BOOST_TEST(
        (status(f, kms::make_fenced_command(2, disable)) == kms::catalog_status::stale_lease));

    // Lease commands are never fenced, and only commands are.
    BOOST_CHECK_THROW(std::ignore = kms::make_fenced_command(
                          2, kms::make_acquire_lease_command("a", t, k_lease_ms)),
                      std::invalid_argument);
    BOOST_CHECK_THROW(
        std::ignore = kms::make_fenced_command(2, kms::make_fenced_command(2, enable)),
        std::invalid_argument);
    BOOST_CHECK_THROW(std::ignore = kms::make_fenced_command(2, {}), std::invalid_argument);
}

// Requirement 5.2 through the jobs: a holder that stalled past its lease
// runs a pass after another member took over; its deletion step is
// refused, and the new holder's goes through.
BOOST_AUTO_TEST_CASE(a_stalled_holders_jobs_cannot_act_after_a_takeover) {
    fixture f;
    const auto id = f.create();
    BOOST_REQUIRE(
        f.call("ScheduleKeyDeletion", R"({"KeyId":")" + id + R"(","PendingWindowInDays":7})")
            .status == 200U);

    BOOST_REQUIRE((acquire(f, "a", f.now) == kms::catalog_status::ok));
    const std::uint64_t token_a = f.sm.lease().token;
    const auto fenced = [&f](const std::uint64_t& token) {
        return [&f, &token](const std::vector<std::byte>& c) {
            return f.propose(kms::make_fenced_command(token, c));
        };
    };
    const auto reader = f.access.reader();
    kms::key_jobs<reader_t> jobs_a{*reader, *f.hsm, fenced(token_a), [&f] { return f.now; },
                                   std::chrono::minutes(5)};

    // The deletion falls due; "a" has stalled and "b" takes over.
    f.now += 8 * kms::k_ms_per_day;
    BOOST_REQUIRE((acquire(f, "b", f.now) == kms::catalog_status::ok));
    const std::uint64_t token_b = f.sm.lease().token;
    BOOST_REQUIRE(token_b == token_a + 1);

    // "a" wakes and runs its pass: the HSM objects may go (destroying them
    // twice is harmless), but the catalog step is refused.
    const auto ra = jobs_a.run_once();
    BOOST_TEST(ra.deleted == 0U);
    BOOST_TEST(ra.failures > 0U);
    BOOST_TEST(!f.sm.tombstoned(id));
    BOOST_TEST((f.sm.key(id)->state == kms::key_state::pending_deletion));

    // "b" completes it.
    kms::key_jobs<reader_t> jobs_b{*reader, *f.hsm, fenced(token_b), [&f] { return f.now; },
                                   std::chrono::minutes(5)};
    const auto rb = jobs_b.run_once();
    BOOST_TEST(rb.deleted == 1U);
    BOOST_TEST(f.sm.tombstoned(id));
}

// Requirement 5.3: a single co-located member holds the lease alone and
// the jobs run as they did on the catalog's leader.
BOOST_AUTO_TEST_CASE(a_single_member_holds_the_lease_and_runs_every_job) {
    fixture f;
    const auto id = f.create();
    BOOST_REQUIRE(f.call("EnableKeyRotation", kid(id)).status == 200U);
    BOOST_REQUIRE((acquire(f, "only", f.now) == kms::catalog_status::ok));
    const std::uint64_t token = f.sm.lease().token;
    const auto reader = f.access.reader();  // kept: a remote reader is not cached
    kms::key_jobs<reader_t> jobs{*reader, *f.hsm,
                                 [&f, token](const std::vector<std::byte>& c) {
                                     return f.propose(kms::make_fenced_command(token, c));
                                 },
                                 [&f] { return f.now; }, std::chrono::minutes(5)};
    f.now += 400 * kms::k_ms_per_day;
    BOOST_REQUIRE((acquire(f, "only", f.now) == kms::catalog_status::ok));  // renewed
    BOOST_REQUIRE(f.sm.lease().token == token);
    const auto r = jobs.run_once();
    BOOST_TEST(r.rotated == 1U);
    BOOST_TEST(r.failures == 0U);
    BOOST_TEST(f.sm.versions(id).size() == 2U);
}
