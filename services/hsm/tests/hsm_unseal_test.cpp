// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Operator unseal and the vault's seal enforcement (.kiro/specs/virtual-hsm/
// task 7, requirements 4.3, 4.6 and 4.7): k shares unseal and fewer do
// not, shares are checked on arrival (encoding, split, duplicates), held
// shares expire, and a vault seals itself once the catalog it unsealed
// under is sealed or rekeyed.

#define BOOST_TEST_MODULE hsm_unseal_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/shamir.hpp>
#include <kythira/hsm/unseal.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace kythira::hsm {
inline auto operator<<(std::ostream& os, share_outcome o) -> std::ostream& {
    return os << share_outcome_message(o);
}
}  // namespace kythira::hsm

namespace {

namespace hsm = kythira::hsm;
using namespace std::chrono_literals;

struct split_key {
    hsm::secret_bytes mk{32};
    std::vector<std::string> shares;
    hsm::catalog_record catalog;

    split_key(std::uint8_t k, std::uint8_t n) {
        BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value());
        auto s = hsm::shamir_split(mk.view(), k, n);
        BOOST_REQUIRE(s.has_value());
        for (const auto& share : *s) {
            shares.push_back(hsm::shamir_encode_text(share));
        }
        catalog.k = k;
        catalog.n = n;
        catalog.mk_check = hsm::key_check_value(mk.view());
    }
};

struct fixture {
    hsm::key_vault vault;
    std::chrono::steady_clock::time_point now{};
    hsm::operator_unseal unseal{vault, 60s, [this] { return now; }};
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(k_shares_unseal_and_fewer_do_not, fixture) {
    split_key key(3, 5);
    const std::optional<hsm::catalog_record> c = key.catalog;
    BOOST_TEST(unseal.submit(key.shares[4], c) == hsm::share_outcome::accepted);
    BOOST_TEST(unseal.submit(key.shares[1], c) == hsm::share_outcome::accepted);
    BOOST_TEST(vault.sealed());
    const auto p = unseal.progress(c);
    BOOST_TEST(p.received == 2U);
    BOOST_TEST(p.needed == 3U);
    BOOST_TEST(unseal.submit(key.shares[2], c) == hsm::share_outcome::unsealed);
    BOOST_TEST(!vault.sealed());
    BOOST_TEST(unseal.progress(c).received == 0U);
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::already_unsealed);
}

BOOST_FIXTURE_TEST_CASE(shares_are_checked_on_arrival, fixture) {
    split_key key(2, 3);
    split_key other(2, 3);
    const std::optional<hsm::catalog_record> c = key.catalog;
    BOOST_TEST(unseal.submit("khs1-00", c) == hsm::share_outcome::malformed);
    std::string typo = key.shares[0];
    typo[10] = typo[10] == 'a' ? 'b' : 'a';
    BOOST_TEST(unseal.submit(typo, c) == hsm::share_outcome::malformed);
    // A real share of another master key, or of the same key split with
    // another threshold, is refused before it is kept.
    BOOST_TEST(unseal.submit(other.shares[0], c) == hsm::share_outcome::wrong_split);
    split_key wider(3, 3);
    BOOST_TEST(unseal.submit(wider.shares[0], c) == hsm::share_outcome::wrong_split);
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::accepted);
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::duplicate);
    BOOST_TEST(unseal.progress(c).received == 1U);
    BOOST_TEST(unseal.submit(key.shares[0], std::nullopt) == hsm::share_outcome::not_initialized);
    BOOST_TEST(unseal.submit(key.shares[2], c) == hsm::share_outcome::unsealed);
}

BOOST_FIXTURE_TEST_CASE(held_shares_expire_and_can_be_discarded, fixture) {
    split_key key(2, 3);
    const std::optional<hsm::catalog_record> c = key.catalog;
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::accepted);
    now += 59s;
    BOOST_TEST(unseal.progress(c).received == 1U);
    now += 1s;
    BOOST_TEST(unseal.progress(c).received == 0U);
    // The share expired, so one more is not enough.
    BOOST_TEST(unseal.submit(key.shares[1], c) == hsm::share_outcome::accepted);
    unseal.reset();
    BOOST_TEST(unseal.progress(c).received == 0U);
    BOOST_TEST(unseal.submit(key.shares[2], c) == hsm::share_outcome::accepted);
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::unsealed);
}

BOOST_FIXTURE_TEST_CASE(a_vault_seals_when_the_catalog_moves_on, fixture) {
    split_key key(2, 3);
    std::optional<hsm::catalog_record> c = key.catalog;
    BOOST_TEST(!vault.enforce(c));  // already sealed: nothing to do
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::accepted);
    BOOST_TEST(unseal.submit(key.shares[1], c) == hsm::share_outcome::unsealed);
    BOOST_TEST(!vault.enforce(c));
    BOOST_TEST(!vault.sealed());
    // A seal command applied: the epoch moved.
    c->seal_epoch = 1;
    BOOST_TEST(vault.enforce(c));
    BOOST_TEST(vault.sealed());
    // Unsealed again under the new epoch, it stays unsealed.
    BOOST_TEST(unseal.submit(key.shares[2], c) == hsm::share_outcome::accepted);
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::unsealed);
    BOOST_TEST(!vault.enforce(c));
    // A rekey applied: another generation, so the old MK opens nothing.
    c->generation = 2;
    BOOST_TEST(vault.enforce(c));
    BOOST_TEST(vault.sealed());
    // Old shares no longer match a rekeyed catalog's check value.
    split_key next(2, 3);
    c->mk_check = next.catalog.mk_check;
    BOOST_TEST(unseal.submit(key.shares[0], c) == hsm::share_outcome::wrong_split);
}
