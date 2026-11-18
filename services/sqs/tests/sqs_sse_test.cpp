// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/sqs-compatible-queues/ task 7: sealing message bodies and
// attributes (sqs_sse.hpp).

#define BOOST_TEST_MODULE sqs_sse_test
#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_sse.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace sqs = kythira::sqs;

namespace {

auto keys(std::optional<std::string> passphrase = "a passphrase of some length")
    -> std::shared_ptr<sqs::sse_keys> {
    return sqs::node_sse_keys("", "forwarding-secret-0123456789", std::move(passphrase));
}

const sqs::sse_keys::target k_managed{"arn:aws:sqs:us-east-1:1:q", "", 300};
const sqs::sse_keys::target k_kms{"arn:aws:sqs:us-east-1:1:q", "alias/app", 60};

}  // namespace

BOOST_AUTO_TEST_CASE(sealed_bodies_open_on_any_node_with_the_same_secret) {
    auto a = keys();
    auto b = keys();
    for (const auto& t : {k_managed, k_kms}) {
        const auto sealed = a->seal(t, "mid-1", "hello", "\x01attrs", 1000);
        BOOST_TEST(sqs::is_sealed(sealed));
        BOOST_TEST(sealed.find("hello") == std::string::npos);
        const auto o = b->open("mid-1", sealed, 2000);
        BOOST_TEST(o._body == "hello");
        BOOST_TEST(o._attributes == "\x01attrs");
    }
    BOOST_TEST(!sqs::is_sealed("plain body"));
    // Another cluster's secret does not unwrap the key.
    auto other = sqs::node_sse_keys("another-secret-of-16+", "", std::nullopt);
    BOOST_CHECK_THROW((void)other->open("mid-1", a->seal(k_managed, "mid-1", "x", "", 0), 0),
                      sqs::kms_error);
}

BOOST_AUTO_TEST_CASE(a_sealed_body_is_bound_to_its_message_and_intact) {
    auto k = keys();
    auto sealed = k->seal(k_managed, "mid-1", "hello", "", 1000);
    // Pasted onto another message.
    BOOST_CHECK_THROW((void)k->open("mid-2", sealed, 1000), sqs::sealed_body_error);
    // A flipped ciphertext bit, and a truncation.
    auto flipped = sealed;
    flipped[flipped.size() - 20] = static_cast<char>(flipped[flipped.size() - 20] ^ 1);
    BOOST_CHECK_THROW((void)k->open("mid-1", flipped, 1000), sqs::sealed_body_error);
    BOOST_CHECK_THROW((void)k->open("mid-1", sealed.substr(0, 8), 1000), sqs::sealed_body_error);
}

BOOST_AUTO_TEST_CASE(data_keys_are_reused_then_replaced) {
    auto k = keys();
    (void)k->seal(k_kms, "m1", "a", "", 0);
    (void)k->seal(k_kms, "m2", "b", "", 59'999);
    BOOST_TEST(k->provider_calls() == 1U);
    (void)k->seal(k_kms, "m3", "c", "", 60'000);
    BOOST_TEST(k->provider_calls() == 2U);
    // Each queue has its own key.
    auto other_queue = k_kms;
    other_queue._queue_arn = "arn:aws:sqs:us-east-1:1:r";
    (void)k->seal(other_queue, "m4", "d", "", 60'000);
    BOOST_TEST(k->provider_calls() == 3U);
}

BOOST_AUTO_TEST_CASE(without_a_kms_provider_kms_queues_refuse) {
    auto k = keys(std::nullopt);
    try {
        (void)k->seal(k_kms, "m1", "a", "", 0);
        BOOST_FAIL("sealed without a provider");
    } catch (const sqs::kms_error& e) {
        BOOST_TEST((e.failure() == sqs::kms_failure::unavailable));
    }
    // SSE-SQS still works.
    BOOST_TEST(sqs::is_sealed(k->seal(k_managed, "m1", "a", "", 0)));
}

BOOST_AUTO_TEST_CASE(wrapped_keys_are_bound_to_their_key_id_and_context) {
    sqs::wrapping_provider p(sqs::derived_key("secret", "label"));
    const auto g = p.generate_data_key("alias/a", {{"aws:sqs:arn", "q"}});
    BOOST_TEST((p.decrypt_data_key("alias/a", g._wrapped, {{"aws:sqs:arn", "q"}}) == g._plaintext));
    BOOST_CHECK_THROW((void)p.decrypt_data_key("alias/b", g._wrapped, {{"aws:sqs:arn", "q"}}),
                      sqs::kms_error);
    BOOST_CHECK_THROW((void)p.decrypt_data_key("alias/a", g._wrapped, {{"aws:sqs:arn", "r"}}),
                      sqs::kms_error);
    BOOST_CHECK_THROW((void)sqs::node_sse_keys("short", "", std::nullopt), std::invalid_argument);
}
