// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 1 (Requirement 3.1): the shape tables generated from the pinned
// botocore model are the KMS's JSON 1.1 service, every operation the model
// has, and they validate requests the way the front end (task 12) will.

#define BOOST_TEST_MODULE kms_model_test

#include <boost/test/unit_test.hpp>

#include <kythira/kms/model/kms_model.hpp>

#include <raft/aws_json_protocol.hpp>

#include <boost/json.hpp>

#include <string>
#include <vector>

namespace aj = kythira::aws_json;
namespace km = kythira::kms::kms_model;

BOOST_AUTO_TEST_CASE(the_model_is_kms_json_1_1) {
    BOOST_TEST(km::k_model.target_prefix == "TrentService");
    BOOST_TEST((km::k_model.version == aj::json_version::v1_1));
    BOOST_TEST(km::k_model.operations.size() == 54U);
    for (const auto* name : {"CreateKey", "Encrypt", "Decrypt", "GenerateDataKey", "Sign",
                             "CreateGrant", "PutKeyPolicy", "RotateKeyOnDemand"}) {
        const auto* op = km::k_model.find_operation(name);
        BOOST_REQUIRE_MESSAGE(op != nullptr, name);
        BOOST_TEST(op->input != aj::no_shape, name);
    }
    BOOST_TEST(km::k_model.find_operation("PutRecord") == nullptr);
}

BOOST_AUTO_TEST_CASE(requests_are_validated_against_the_model) {
    const aj::shape_validator v(km::k_model);
    // Every pattern std::regex cannot compile is named, so a model upgrade
    // that adds one shows up here.
    std::vector<std::string> skipped(v.skipped_patterns().begin(), v.skipped_patterns().end());
    BOOST_TEST_MESSAGE("patterns not checked: " << skipped.size());
    const auto style = aj::error_style::bare();
    const auto create = km::k_model.find_operation("CreateKey")->input;

    BOOST_TEST(!v.validate(create, boost::json::parse(R"({})"), style).has_value());
    BOOST_TEST(
        !v.validate(create,
                    boost::json::parse(R"({"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY",)"
                                       R"("Description":"signer"})"),
                    style)
             .has_value());
    const auto bad_spec = v.validate(create, boost::json::parse(R"({"KeySpec":"AES_128"})"), style);
    BOOST_REQUIRE(bad_spec.has_value());
    BOOST_TEST(bad_spec->type == "ValidationException");
    const auto unknown = v.validate(create, boost::json::parse(R"({"Colour":"blue"})"), style);
    BOOST_TEST(unknown.has_value());

    const auto encrypt = km::k_model.find_operation("Encrypt")->input;
    // KeyId and Plaintext are required.
    BOOST_TEST(
        v.validate(encrypt, boost::json::parse(R"({"KeyId":"alias/app"})"), style).has_value());
    BOOST_TEST(!v.validate(encrypt,
                           boost::json::parse(R"({"KeyId":"alias/app","Plaintext":"aGk="})"), style)
                    .has_value());
}
