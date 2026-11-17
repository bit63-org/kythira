// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 11 (Requirements 9.1-9.4): EnableKeyRotation, DisableKeyRotation,
// GetKeyRotationStatus, RotateKeyOnDemand and ListKeyRotations through
// signed requests; old ciphertexts decrypting after rotation; the leader's
// scheduled rotation, idempotent when retried; and deletion at the end of
// the window destroying every backing key and leaving a tombstone.

#define BOOST_TEST_MODULE kms_rotation_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <cstdint>
#include <string>
#include <string_view>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

constexpr std::uint64_t k_day_ms = 86'400'000;

auto encrypt(fixture& f, std::string_view id) -> std::string {
    const auto r =
        f.call("Encrypt", R"({"KeyId":")" + std::string(id) + R"(","Plaintext":"c2VjcmV0"})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    return r.str("CiphertextBlob");
}

auto decrypts(fixture& f, const std::string& blob) -> bool {
    const auto r = f.call("Decrypt", R"({"CiphertextBlob":")" + blob + R"("})");
    return r.status == 200U && r.str("Plaintext") == "c2VjcmV0";
}

/// The backing objects the fake token holds for `id`.
auto backing_objects(fixture& f, std::string_view id) -> std::size_t {
    std::size_t n = 0;
    for (const auto& [h, o] : f.hsm_backend->objects()) {
        const auto it = o.attrs.find(CKA_LABEL);
        if (it != o.attrs.end() &&
            std::string(reinterpret_cast<const char*>(it->second.data()),  // NOLINT
                        it->second.size())
                    .find(id) != std::string::npos) {
            ++n;
        }
    }
    return n;
}

}  // namespace

BOOST_AUTO_TEST_CASE(enable_disable_and_status) {
    fixture f;
    const auto id = f.create();
    auto st = f.call("GetKeyRotationStatus", kid(id));
    BOOST_REQUIRE_MESSAGE(st.status == 200U, st.type() + ": " + st.message());
    BOOST_TEST(st.body.at("KeyRotationEnabled").as_bool() == false);
    BOOST_TEST(st.str("KeyId") == fixture::arn(id));
    BOOST_TEST(!st.body.contains("RotationPeriodInDays"));

    BOOST_REQUIRE(f.call("EnableKeyRotation", kid(id)).status == 200U);
    st = f.call("GetKeyRotationStatus", kid(id));
    BOOST_TEST(st.body.at("KeyRotationEnabled").as_bool());
    BOOST_TEST(st.body.at("RotationPeriodInDays").as_int64() == 365);
    BOOST_TEST(st.body.at("NextRotationDate").as_double() ==
               static_cast<double>(f.now + 365 * k_day_ms) / 1000.0);

    BOOST_REQUIRE(
        f.call("EnableKeyRotation", R"({"KeyId":")" + id + R"(","RotationPeriodInDays":90})")
            .status == 200U);
    BOOST_TEST(f.call("GetKeyRotationStatus", kid(id)).body.at("RotationPeriodInDays").as_int64() ==
               90);
    for (const int bad : {89, 2561}) {
        BOOST_TEST(f.call("EnableKeyRotation", R"({"KeyId":")" + id +
                                                   R"(","RotationPeriodInDays":)" +
                                                   std::to_string(bad) + "}")
                       .type() == "ValidationException");
    }
    BOOST_REQUIRE(f.call("DisableKeyRotation", kid(id)).status == 200U);
    BOOST_TEST(f.auth.asked.back().action == "kms:DisableKeyRotation");
    BOOST_TEST(f.call("GetKeyRotationStatus", kid(id)).body.at("KeyRotationEnabled").as_bool() ==
               false);

    // The request IAM sees, and who may: reading is read-only's, changing
    // is not.
    BOOST_TEST(f.call("GetKeyRotationStatus", kid(id), "AKIDREAD").status == 200U);
    BOOST_TEST(f.call("EnableKeyRotation", kid(id), "AKIDREAD").type() == "AccessDeniedException");
    BOOST_TEST(f.call("EnableKeyRotation", kid("alias/none")).type() == "NotFoundException");
}

BOOST_AUTO_TEST_CASE(only_symmetric_keys_rotate_and_states_matter) {
    fixture f;
    for (const std::string spec : {R"({"KeySpec":"RSA_2048","KeyUsage":"ENCRYPT_DECRYPT"})",
                                   R"({"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY"})",
                                   R"({"KeySpec":"HMAC_256","KeyUsage":"GENERATE_VERIFY_MAC"})"}) {
        const auto id = f.create(spec);
        for (const char* op : {"EnableKeyRotation", "RotateKeyOnDemand"}) {
            BOOST_TEST(f.call(op, kid(id)).type() == "UnsupportedOperationException", op);
        }
        // What AWS answers for a key that cannot rotate (the differential
        // recording): not rotating, nothing to turn off, no rotations.
        const auto status = f.call("GetKeyRotationStatus", kid(id));
        BOOST_TEST(status.status == 200U);
        BOOST_TEST(!status.body.at("KeyRotationEnabled").as_bool());
        BOOST_TEST(f.call("DisableKeyRotation", kid(id)).status == 200U);
        const auto listed = f.call("ListKeyRotations", kid(id));
        BOOST_TEST(listed.status == 200U);
        BOOST_TEST(listed.body.at("Rotations").as_array().empty());
    }
    const auto id = f.create();
    BOOST_REQUIRE(f.call("DisableKey", kid(id)).status == 200U);
    BOOST_TEST(f.call("EnableKeyRotation", kid(id)).type() == "DisabledException");
    BOOST_TEST(f.call("RotateKeyOnDemand", kid(id)).type() == "DisabledException");
    BOOST_TEST(f.call("GetKeyRotationStatus", kid(id)).status == 200U);
    BOOST_REQUIRE(f.call("EnableKey", kid(id)).status == 200U);
    BOOST_REQUIRE(f.call("ScheduleKeyDeletion", kid(id)).status == 200U);
    BOOST_TEST(f.call("EnableKeyRotation", kid(id)).type() == "KMSInvalidStateException");
    BOOST_TEST(f.call("RotateKeyOnDemand", kid(id)).type() == "KMSInvalidStateException");
}

BOOST_AUTO_TEST_CASE(on_demand_rotation_keeps_old_ciphertexts) {
    fixture f;
    const auto id = f.create();
    const auto before = encrypt(f, id);
    const auto r = f.call("RotateKeyOnDemand", kid(id));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.str("KeyId") == fixture::arn(id));
    BOOST_TEST(f.sm.key(id)->current_version == 2U);
    BOOST_TEST(backing_objects(f, id) == 2U);
    const auto after = encrypt(f, id);
    BOOST_TEST(after != before);
    BOOST_TEST(decrypts(f, before));
    BOOST_TEST(decrypts(f, after));

    const auto l = f.call("ListKeyRotations", kid(id));
    BOOST_REQUIRE_MESSAGE(l.status == 200U, l.type() + ": " + l.message());
    const auto& rot = l.body.at("Rotations").as_array();
    BOOST_REQUIRE(rot.size() == 1U);  // the initial key is not a rotation
    BOOST_TEST(rot[0].as_object().at("RotationType").as_string() == "ON_DEMAND");
    BOOST_TEST(rot[0].as_object().at("KeyId").as_string() == fixture::arn(id));
    BOOST_TEST(rot[0].as_object().at("RotationDate").as_double() ==
               static_cast<double>(f.now) / 1000.0);

    // Ten on-demand rotations in a key's life, as on AWS.
    for (int i = 1; i < 10; ++i) {
        BOOST_REQUIRE(f.call("RotateKeyOnDemand", kid(id)).status == 200U);
    }
    BOOST_TEST(f.call("RotateKeyOnDemand", kid(id)).type() == "LimitExceededException");
    BOOST_TEST(decrypts(f, before));

    // Paging.
    const auto p1 = f.call("ListKeyRotations", R"({"KeyId":")" + id + R"(","Limit":4})");
    BOOST_TEST(p1.body.at("Rotations").as_array().size() == 4U);
    BOOST_REQUIRE(p1.body.at("Truncated").as_bool());
    const auto p2 =
        f.call("ListKeyRotations", R"({"KeyId":")" + id + R"(","Limit":100,"Marker":")" +
                                       p1.str("NextMarker") + R"("})");
    BOOST_TEST(p2.body.at("Rotations").as_array().size() == 6U);
    BOOST_TEST(f.call("ListKeyRotations", R"({"KeyId":")" + id + R"(","Marker":"x"})").type() ==
               "InvalidMarkerException");

    // The HSM away: the rotation fails and nothing commits.
    const auto id2 = f.create();
    f.hsm_backend->sealed = true;
    BOOST_TEST(f.call("RotateKeyOnDemand", kid(id2)).status != 200U);
    f.hsm_backend->sealed = false;
    BOOST_TEST(f.sm.key(id2)->current_version == 1U);
}

BOOST_AUTO_TEST_CASE(scheduled_rotation_runs_once_per_period) {
    fixture f;
    const auto id = f.create();
    const auto before = encrypt(f, id);
    BOOST_REQUIRE(
        f.call("EnableKeyRotation", R"({"KeyId":")" + id + R"(","RotationPeriodInDays":90})")
            .status == 200U);
    // Not due yet.
    f.now += 89 * k_day_ms;
    BOOST_TEST(f.jobs.run_once().rotated == 0U);
    // Due: one rotation, and running the jobs again (a new leader's first
    // pass) adds no second one.
    f.now += 1 * k_day_ms;
    BOOST_TEST(f.jobs.run_once().rotated == 1U);
    BOOST_TEST(f.jobs.run_once().rotated == 0U);
    BOOST_TEST(f.sm.key(id)->current_version == 2U);
    BOOST_TEST(f.sm.key(id)->next_rotation_ms == f.now + 90 * k_day_ms);
    const auto l = f.call("ListKeyRotations", kid(id));
    BOOST_TEST(l.body.at("Rotations").as_array()[0].as_object().at("RotationType").as_string() ==
               "AUTOMATIC");
    BOOST_TEST(decrypts(f, before));

    // A rotation an earlier leader generated on the HSM and never
    // committed is reused, not doubled.
    f.now += 90 * k_day_ms;
    f.leaderless = true;
    const auto lost = f.jobs.run_once();
    BOOST_TEST(lost.rotated == 0U);
    BOOST_TEST(lost.failures == 1U);
    BOOST_TEST(backing_objects(f, id) == 3U);  // version 3 made, not committed
    f.leaderless = false;
    BOOST_TEST(f.jobs.run_once().rotated == 1U);
    BOOST_TEST(f.sm.key(id)->current_version == 3U);
    BOOST_TEST(backing_objects(f, id) == 3U);
}

BOOST_AUTO_TEST_CASE(deletion_destroys_every_backing_key_and_leaves_a_tombstone) {
    fixture f;
    // Keys named predictably, so the same id can be offered again.
    const auto id = f.create();
    BOOST_REQUIRE(f.call("RotateKeyOnDemand", kid(id)).status == 200U);
    BOOST_TEST(backing_objects(f, id) == 2U);
    BOOST_REQUIRE(
        f.call("ScheduleKeyDeletion", R"({"KeyId":")" + id + R"(","PendingWindowInDays":7})")
            .status == 200U);
    f.now += 6 * k_day_ms;
    BOOST_TEST(f.jobs.run_once().deleted == 0U);
    BOOST_TEST(f.call("DescribeKey", kid(id)).status == 200U);
    f.now += 1 * k_day_ms;
    BOOST_TEST(f.jobs.run_once().deleted == 1U);
    BOOST_TEST(backing_objects(f, id) == 0U);
    BOOST_TEST(f.call("DescribeKey", kid(id)).type() == "NotFoundException");
    BOOST_TEST(f.sm.tombstoned(id));
    // The id is never reused.
    f.next_id = 0;
    BOOST_TEST(f.call("CreateKey", "{}").status != 200U);
    BOOST_TEST(f.jobs.run_once().deleted == 0U);
}
