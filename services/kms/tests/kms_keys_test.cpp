// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 5 (Requirements 3.4, 4.1, 4.4, 4.5, 9.2-9.4): key creation's two
// steps, the leader's jobs (settling Creating keys, rotation, deletion,
// orphaned backing keys) across a leader dying between steps, the sealed
// HSM path, and a scan of the catalog's log, engine and checkpoint for
// every generated key's material.

#define BOOST_TEST_MODULE kms_keys_test

#include <boost/test/unit_test.hpp>

#include "kms_fake_pkcs11.hpp"

#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <raft/memory_kv_engine.hpp>

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace kms = kythira::kms;
namespace kt = kythira::kms::test;
using kms::catalog_status;
using kms::key_outcome;
using kms::key_state;

namespace {

constexpr std::string_view account = "111122223333";
constexpr std::uint64_t minute = 60000;

auto key_id(int n) -> std::string {
    char buf[37];
    std::snprintf(buf, sizeof buf, "%08x-1111-4000-8000-000000000000", n);
    return buf;
}

struct fixture {
    kythira::memory_kv_engine engine;
    kms::kms_catalog_state_machine<> sm{"kms/"};
    std::shared_ptr<kt::fake_backend> hsm_backend = std::make_shared<kt::fake_backend>();
    kms::backing_store hsm{hsm_backend, 1, "1234"};
    std::uint64_t index = 0;
    std::uint64_t now = 1000000;
    bool leaderless = false;
    std::vector<std::vector<std::byte>> log;  // every committed command
    kms::key_jobs<kms::kms_catalog_state_machine<>> jobs{
        sm, hsm,
        [this](const std::vector<std::byte>& c) {
            if (leaderless) {
                throw std::runtime_error("no leader");
            }
            log.push_back(c);
            return kms::catalog_reply_status(sm.apply(c, ++index));
        },
        [this] { return now; }, std::chrono::minutes(5)};

    fixture() { sm.open(engine, sm.engine_range()); }

    auto propose(const std::vector<std::byte>& c) -> catalog_status {
        log.push_back(c);
        return kms::catalog_reply_status(sm.apply(c, ++index));
    }

    static auto record(const std::string& id, kms::key_spec spec = kms::key_spec::symmetric_default,
                       kms::key_usage usage = kms::key_usage::encrypt_decrypt) -> kms::key_record {
        kms::key_record k;
        k.key_id = id;
        k.account = std::string(account);
        k.spec = spec;
        k.usage = usage;
        k.policy = "{}";
        return k;
    }
};

auto attr(const kt::fake_backend::object& o, CK_ATTRIBUTE_TYPE t) -> kythira::pkcs11::bytes {
    return o.attrs.at(t);
}

}  // namespace

BOOST_AUTO_TEST_CASE(create_key_makes_a_non_extractable_backing_key_then_enables) {
    fixture f;
    const auto id = key_id(1);
    const auto r = f.jobs.create_key(fixture::record(id), {{"t", "v"}});
    BOOST_TEST(r.ok());
    const auto k = f.sm.key(id);
    BOOST_REQUIRE(k.has_value());
    BOOST_TEST((k->state == key_state::enabled));
    BOOST_TEST(k->creation_ms == f.now);
    const auto v = f.sm.version(id, 1);
    BOOST_REQUIRE(v.has_value());

    const auto objects = f.hsm_backend->objects();
    BOOST_REQUIRE(objects.size() == 1U);
    const auto& [handle, o] = *objects.begin();
    BOOST_TEST(v->hsm_object == handle);
    const auto label = kms::backing_label(id, 1);
    BOOST_TEST((attr(o, CKA_LABEL) == kythira::pkcs11::bytes(label.begin(), label.end())));
    BOOST_TEST((attr(o, CKA_TOKEN) == kythira::pkcs11::bytes{CK_TRUE}));
    BOOST_TEST((attr(o, CKA_SENSITIVE) == kythira::pkcs11::bytes{CK_TRUE}));
    BOOST_TEST((attr(o, CKA_EXTRACTABLE) == kythira::pkcs11::bytes{CK_FALSE}));
    BOOST_TEST((attr(o, CKA_ENCRYPT) == kythira::pkcs11::bytes{CK_TRUE}));
    BOOST_TEST((attr(o, CKA_SIGN) == kythira::pkcs11::bytes{CK_FALSE}));

    // An asymmetric key: both halves carry the label, and the catalog
    // records the private half.
    const auto rsa = key_id(2);
    BOOST_TEST(
        f.jobs
            .create_key(fixture::record(rsa, kms::key_spec::rsa_3072, kms::key_usage::sign_verify),
                        {})
            .ok());
    BOOST_TEST(f.hsm_backend->objects().size() == 3U);
    BOOST_TEST(
        (f.hsm.find(rsa, 1) == std::optional<std::uint64_t>(f.sm.version(rsa, 1)->hsm_object)));
}

BOOST_AUTO_TEST_CASE(a_sealed_hsm_fails_creation_cleanly_and_spares_management) {
    fixture f;
    const auto kept = key_id(3);
    BOOST_REQUIRE(f.jobs.create_key(fixture::record(kept), {}).ok());
    f.hsm_backend->sealed = true;

    const auto id = key_id(4);
    const auto r = f.jobs.create_key(fixture::record(id), {});
    BOOST_TEST((r.outcome == key_outcome::unavailable));
    // Nothing half-made is left: the entry is tombstoned at once.
    BOOST_TEST(!f.sm.key(id).has_value());
    BOOST_TEST(f.sm.tombstoned(id));
    BOOST_TEST(f.sm.creating_keys().empty());

    // Management needs no material (Requirement 4.5).
    BOOST_TEST((f.propose(kms::make_set_enabled_command(kept, false)) == catalog_status::ok));
    BOOST_TEST((f.propose(kms::make_update_description_command(kept, "still here")) ==
                catalog_status::ok));
    // Rotation needs the HSM.
    BOOST_REQUIRE((f.propose(kms::make_set_enabled_command(kept, true)) == catalog_status::ok));
    BOOST_TEST(
        (f.jobs.rotate(kept, kms::rotation_type::on_demand).outcome == key_outcome::unavailable));
    BOOST_TEST(f.sm.key(kept)->current_version == 1U);

    // A module without a mechanism is told apart from a sealed one.
    BOOST_TEST((kms::classify_rv(CKR_MECHANISM_INVALID) == kms::backing_error::kind::unsupported));
    BOOST_TEST((kms::classify_rv(CKR_DEVICE_ERROR) == kms::backing_error::kind::unavailable));
}

BOOST_AUTO_TEST_CASE(the_sweep_settles_keys_a_dead_leader_left_creating) {
    fixture f;
    // Leader A recorded both keys as Creating, made the backing key for
    // the first only, and died.
    const auto made = key_id(5);
    const auto never = key_id(6);
    for (const auto& id : {made, never}) {
        auto k = fixture::record(id);
        k.creation_ms = f.now;
        BOOST_REQUIRE((f.propose(kms::make_create_key_command(k, {})) == catalog_status::ok));
    }
    const auto handle =
        f.hsm.generate(made, 1, kms::key_spec::symmetric_default, kms::key_usage::encrypt_decrypt);

    // Within the grace period the next leader leaves them alone.
    f.now += 4 * minute;
    auto r = f.jobs.run_once();
    BOOST_TEST(r.completed + r.abandoned == 0U);
    BOOST_TEST(f.hsm_backend->objects().size() == 1U);  // Creating's v1 is accounted for

    f.now += 2 * minute;
    r = f.jobs.run_once();
    BOOST_TEST(r.completed == 1U);
    BOOST_TEST(r.abandoned == 1U);
    BOOST_TEST((f.sm.key(made)->state == key_state::enabled));
    BOOST_TEST(f.sm.version(made, 1)->hsm_object == handle);
    BOOST_TEST(f.sm.tombstoned(never));
    BOOST_TEST(f.hsm_backend->generated == 1);  // nothing made twice
}

BOOST_AUTO_TEST_CASE(rotation_is_idempotent_across_a_leader_change) {
    fixture f;
    const auto id = key_id(7);
    BOOST_REQUIRE(f.jobs.create_key(fixture::record(id), {}).ok());
    BOOST_REQUIRE(
        (f.propose(kms::make_set_rotation_command(id, true, 90, f.now)) == catalog_status::ok));

    // Leader A made version 2 on the HSM and died before committing it.
    const auto v2 =
        f.hsm.generate(id, 2, kms::key_spec::symmetric_default, kms::key_usage::encrypt_decrypt);
    f.now += 90 * kms::k_ms_per_day;
    const auto r = f.jobs.run_once();
    BOOST_TEST(r.rotated == 1U);
    BOOST_TEST(f.sm.key(id)->current_version == 2U);
    BOOST_TEST(f.sm.version(id, 2)->hsm_object == v2);
    BOOST_TEST(f.hsm_backend->generated == 2);  // v1 and A's v2; no third
    BOOST_TEST(f.sm.due_rotations(f.now).empty());

    // On demand makes version 3 and leaves the schedule.
    const auto next = f.sm.key(id)->next_rotation_ms;
    BOOST_TEST(f.jobs.rotate(id, kms::rotation_type::on_demand).ok());
    BOOST_TEST(f.sm.key(id)->current_version == 3U);
    BOOST_TEST(f.sm.key(id)->next_rotation_ms == next);
}

BOOST_AUTO_TEST_CASE(deletion_destroys_every_backing_key_then_tombstones) {
    fixture f;
    const auto id = key_id(8);
    BOOST_REQUIRE(f.jobs.create_key(fixture::record(id), {}).ok());
    BOOST_REQUIRE(f.jobs.rotate(id, kms::rotation_type::on_demand).ok());
    BOOST_REQUIRE(
        (f.propose(kms::make_schedule_deletion_command(id, 7, f.now)) == catalog_status::ok));
    BOOST_TEST(f.hsm_backend->objects().size() == 2U);

    f.now += 7 * kms::k_ms_per_day;
    f.hsm_backend->sealed = true;
    auto r = f.jobs.run_once();
    BOOST_TEST(r.deleted == 0U);
    BOOST_TEST(r.failures > 0U);
    BOOST_TEST((f.sm.key(id)->state == key_state::pending_deletion));  // retried later

    f.hsm_backend->sealed = false;
    // The commit fails (no leader) after the HSM step: the next pass
    // finds nothing left to destroy and commits.
    f.leaderless = true;
    r = f.jobs.run_once();
    BOOST_TEST(r.deleted == 0U);
    BOOST_TEST(f.hsm_backend->objects().empty());
    f.leaderless = false;
    r = f.jobs.run_once();
    BOOST_TEST(r.deleted == 1U);
    BOOST_TEST(f.sm.tombstoned(id));
}

BOOST_AUTO_TEST_CASE(orphaned_backing_keys_are_destroyed_after_the_grace_period) {
    fixture f;
    const auto live = key_id(9);
    BOOST_REQUIRE(f.jobs.create_key(fixture::record(live), {}).ok());
    const auto dead = key_id(10);
    BOOST_REQUIRE(f.jobs.create_key(fixture::record(dead), {}).ok());
    BOOST_REQUIRE(
        (f.propose(kms::make_schedule_deletion_command(dead, 7, f.now)) == catalog_status::ok));
    f.now += 7 * kms::k_ms_per_day;
    f.leaderless = false;
    // Destroy the catalog entry without the HSM step (a deletion whose HSM
    // half was lost), leaving its backing key behind.
    BOOST_REQUIRE((f.propose(kms::make_destroy_key_command(dead, f.now)) == catalog_status::ok));
    // A rotation in flight: v2 exists, uncommitted.
    (void)f.hsm.generate(live, 2, kms::key_spec::symmetric_default,
                         kms::key_usage::encrypt_decrypt);
    // Not ours: left alone whatever happens.
    (void)f.hsm_backend->plant("other-application-key");
    (void)f.hsm_backend->plant("kms:not-a-version");

    auto r = f.jobs.run_once();
    BOOST_TEST(r.orphans_destroyed == 1U);  // the tombstoned key's, at once
    BOOST_TEST(!f.hsm.find(dead, 1).has_value());
    BOOST_TEST(f.hsm.find(live, 2).has_value());

    f.now += 6 * minute;
    r = f.jobs.run_once();
    BOOST_TEST(r.orphans_destroyed == 1U);  // the rotation that never committed
    BOOST_TEST(!f.hsm.find(live, 2).has_value());
    BOOST_TEST(f.hsm.find(live, 1).has_value());
    BOOST_TEST(f.hsm_backend->objects().size() == 3U);
    BOOST_TEST((f.hsm.list() == std::vector<kms::backing_ref>{{live, 1}}));
}

BOOST_AUTO_TEST_CASE(no_generated_material_reaches_the_log_engine_or_checkpoint) {
    fixture f;
    int n = 0;
    for (const auto& [spec, info] : std::vector<std::pair<kms::key_spec, kms::key_usage>>{
             {kms::key_spec::symmetric_default, kms::key_usage::encrypt_decrypt},
             {kms::key_spec::rsa_2048, kms::key_usage::encrypt_decrypt},
             {kms::key_spec::ecc_nist_p256, kms::key_usage::sign_verify},
             {kms::key_spec::hmac_256, kms::key_usage::generate_verify_mac}}) {
        BOOST_REQUIRE(f.jobs.create_key(fixture::record(key_id(100 + n++), spec, info), {}).ok());
    }
    BOOST_REQUIRE(f.jobs.rotate(key_id(100), kms::rotation_type::on_demand).ok());

    // Everything the catalog holds: the log, the engine and a checkpoint.
    std::string haystack;
    for (const auto& c : f.log) {
        haystack.append(reinterpret_cast<const char*>(c.data()), c.size());
    }
    for (const auto cf : {kythira::column_family::data, kythira::column_family::meta}) {
        f.engine.scan(cf, f.sm.engine_range(), kythira::scan_direction::forward,
                      [&](std::string_view k, std::string_view v) {
                          haystack.append(k);
                          haystack.append(v);
                          return true;
                      });
    }
    const auto dir =
        std::filesystem::temp_directory_path() / ("kms_keys_scan_" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    (void)f.sm.checkpoint(dir);
    for (const auto& e : std::filesystem::recursive_directory_iterator(dir)) {
        if (e.is_regular_file()) {
            std::ifstream in(e.path(), std::ios::binary);
            haystack.append(std::istreambuf_iterator<char>(in), {});
        }
    }
    std::filesystem::remove_all(dir);
    BOOST_TEST(haystack.size() > 1000U);

    int secrets = 0;
    for (const auto& [h, o] : f.hsm_backend->objects()) {
        if (o.material.empty()) {
            continue;  // a public half
        }
        ++secrets;
        // The whole material and every 8-byte window of it.
        const std::string m(o.material.begin(), o.material.end());
        BOOST_TEST(haystack.find(m) == std::string::npos);
        for (std::size_t i = 0; i + 8 <= m.size(); ++i) {
            BOOST_TEST_INFO("handle " << h << " offset " << i);
            BOOST_TEST(haystack.find(m.substr(i, 8)) == std::string::npos);
        }
    }
    BOOST_TEST(secrets == 5);
}
