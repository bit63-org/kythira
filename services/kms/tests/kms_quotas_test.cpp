// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 14 (Requirement 13.3): AWS's per-account request quotas. The shared
// cryptographic quotas by key type, GenerateDataKeyPair by pair spec and
// each other operation's own rate; the requesting account is throttled,
// not the key's owner; operator overrides; the rate split over members;
// and ThrottlingException through the front end.

#define BOOST_TEST_MODULE kms_quotas_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_quotas.hpp>

#include <cstdint>
#include <memory>
#include <string>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

/// A clock the test moves.
struct fake_clock {
    std::int64_t ms = 1'000'000;
    [[nodiscard]] auto fn() -> kms::request_quotas::clock_ms {
        return [this] { return ms; };
    }
};

/// How many of `n` uses of a `spec` key by `account` are admitted.
auto admitted(kms::request_quotas& q, std::string_view account, std::string_view op,
              kms::key_spec spec, int n) -> int {
    int ok = 0;
    for (int i = 0; i < n; ++i) {
        ok += q.admit_key_use(account, op, spec) ? 1 : 0;
    }
    return ok;
}

}  // namespace

BOOST_AUTO_TEST_CASE(shared_quotas_follow_the_keys_type) {
    fake_clock t;
    kms::quota_config c;
    c.defaults = {10, 4, 2};
    kms::request_quotas q(c, t.fn());
    BOOST_TEST(admitted(q, "a", "Encrypt", kms::key_spec::symmetric_default, 20) == 10);
    // HMAC keys share the symmetric quota, already spent.
    BOOST_TEST(admitted(q, "a", "GenerateMac", kms::key_spec::hmac_256, 1) == 0);
    // RSA and ECC are their own.
    BOOST_TEST(admitted(q, "a", "Sign", kms::key_spec::rsa_2048, 10) == 4);
    BOOST_TEST(admitted(q, "a", "Verify", kms::key_spec::ecc_nist_p256, 10) == 2);
    // Another account has its own.
    BOOST_TEST(admitted(q, "b", "Decrypt", kms::key_spec::symmetric_default, 20) == 10);
    // Operations outside the shared quotas are not counted there.
    BOOST_TEST(admitted(q, "a", "GetPublicKey", kms::key_spec::rsa_2048, 10) == 10);
    // A second refills a second's worth.
    t.ms += 500;
    BOOST_TEST(admitted(q, "a", "Encrypt", kms::key_spec::symmetric_default, 20) == 5);
    t.ms += 10'000;
    BOOST_TEST(admitted(q, "a", "Encrypt", kms::key_spec::symmetric_default, 20) == 10);

    const auto ms = q.metrics();
    bool found = false;
    for (const auto& m : ms) {
        if (m.name == "throttled_requests" &&
            m.labels == std::vector<std::pair<std::string, std::string>>{{"account", "a"},
                                                                         {"quota", "rsa"}}) {
            found = true;
            BOOST_TEST(m.value == 6.0);
        }
    }
    BOOST_TEST(found);
}

BOOST_AUTO_TEST_CASE(other_operations_have_their_own_rates) {
    fake_clock t;
    kms::request_quotas q(kms::quota_config{}, t.fn());
    const boost::json::object none;
    int ok = 0;
    for (int i = 0; i < 10; ++i) {
        ok += q.admit_operation("a", "CreateKey", none) ? 1 : 0;
    }
    BOOST_TEST(ok == 5);  // AWS's 5 per second
    // Shared crypto operations wait for their key.
    for (int i = 0; i < 10; ++i) {
        BOOST_TEST(q.admit_operation("a", "Encrypt", none));
    }
    // GenerateDataKeyPair by spec.
    boost::json::object rsa4096{{"KeyPairSpec", "RSA_4096"}};
    BOOST_TEST(q.admit_operation("a", "GenerateDataKeyPair", rsa4096));
    BOOST_TEST(!q.admit_operation("a", "GenerateDataKeyPairWithoutPlaintext", rsa4096));
    boost::json::object ecc{{"KeyPairSpec", "ECC_NIST_P256"}};
    BOOST_TEST(q.admit_operation("a", "GenerateDataKeyPair", ecc));
    // An operation AWS gives no rate is not limited.
    for (int i = 0; i < 100; ++i) {
        BOOST_TEST(q.admit_operation("a", "ListAliasesSomethingNew", none));
    }
}

BOOST_AUTO_TEST_CASE(overrides_and_members) {
    fake_clock t;
    kms::quota_config c;
    c.defaults = {6, 6, 6};
    c.accounts["big"] = {60, 6, 6};
    c.members = 3;
    kms::request_quotas q(c, t.fn());
    // The bucket holds a second of the account's whole rate...
    BOOST_TEST(admitted(q, "big", "Encrypt", kms::key_spec::symmetric_default, 100) == 60);
    BOOST_TEST(admitted(q, "small", "Encrypt", kms::key_spec::symmetric_default, 100) == 6);
    // ...and refills at this member's share of it.
    t.ms += 1000;
    BOOST_TEST(admitted(q, "big", "Encrypt", kms::key_spec::symmetric_default, 100) == 20);
    BOOST_TEST(admitted(q, "small", "Encrypt", kms::key_spec::symmetric_default, 100) == 2);

    BOOST_TEST((kms::parse_shared_quotas("5500:500:300") == kms::shared_quotas{5500, 500, 300}));
    for (const char* bad : {"", "1:2", "1:2:3:4", "a:2:3", "0:1:1", "1::1", "-1:1:1", "1:2:3x"}) {
        BOOST_TEST(!kms::parse_shared_quotas(bad).has_value(), bad);
    }
}

BOOST_AUTO_TEST_CASE(the_front_end_answers_throttling_exception) {
    fixture f;
    const auto id = f.create();
    fake_clock t;
    kms::quota_config c;
    c.defaults = {3, 1, 1};
    f.fe.set_quotas(std::make_shared<kms::request_quotas>(c, t.fn()));
    const auto body = R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})";
    for (int i = 0; i < 3; ++i) {
        const auto r = f.call("Encrypt", body);
        BOOST_TEST(r.status == 200U, r.type());
    }
    const auto r = f.call("Encrypt", body);
    BOOST_TEST(r.status == 400U);
    BOOST_TEST(r.type() == "ThrottlingException");
    // GenerateRandom shares the symmetric quota.
    BOOST_TEST(f.call("GenerateRandom", R"({"NumberOfBytes":16})").type() == "ThrottlingException");
    // The requesting account is throttled, not the key's owner: the other
    // account's own (refused) use does not count against this one.
    t.ms += 1000;
    BOOST_TEST(f.call("Encrypt", body, "AKIDOTHER").type() != "ThrottlingException");
    BOOST_TEST(f.call("Encrypt", body).status == 200U);
    // Other operations have their own rates.
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(f.call("CreateKey", "{}").status == 200U);
    }
    BOOST_TEST(f.call("CreateKey", "{}").type() == "ThrottlingException");
    BOOST_TEST(f.call("DescribeKey", kid(id)).status == 200U);
}
