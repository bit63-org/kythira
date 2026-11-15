// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Table keys (`.kiro/specs/kms-compatible-api/` task 16, Requirements
// 12.1, 12.2, 12.5, 12.7, 12.11 and 12.12), through the handlers over a
// fake key provider that keeps keys as a KMS does: every table gets a
// 256-bit key under the owned key by default, the AWS managed key for
// `Enabled` without a key, or the key it names; the key is bound to the
// table by its encryption context and asked for the right principal;
// `SSEDescription` appears only for a KMS key; `UpdateTable` re-wraps the
// same table key under another key; a table keeps opening after the
// provider changes when the old one is kept as the previous provider; the
// local provider takes only the owned key; a restored table gets a key of
// its own; the catalog writes format 13 only for an encrypted table; and
// the settings make the providers they name.

#define BOOST_TEST_MODULE dynamodb_table_keys_test

#include <boost/test/unit_test.hpp>

#include "dynamodb_test_fixture.hpp"

#include <kythira/dynamodb/backup.hpp>
#include <kythira/dynamodb/bucket_sse.hpp>
#include <kythira/dynamodb/catalog.hpp>
#include <kythira/dynamodb/export_formats.hpp>
#include <kythira/dynamodb/export_import.hpp>
#include <kythira/dynamodb/pitr.hpp>
#include <kythira/dynamodb/item_sealing.hpp>
#include <kythira/dynamodb/table_key_providers.hpp>
#include <kythira/dynamodb/table_key_refresh.hpp>
#include <kythira/dynamodb/table_keys.hpp>

#include <raft/kms_key_provider.hpp>

#include <boost/json.hpp>

#include <openssl/rand.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace dynamodb_test;  // NOLINT(google-build-using-namespace)

namespace kp = kythira::kms_provider;

namespace {

constexpr std::string_view k_arn_prefix = "arn:aws:kms:us-east-1:111122223333:key/";

/// A KMS that knows three keys by name and ARN, wraps a data key as
/// "<key arn>|<context>|<key bytes>", and records what it was asked.
struct fake_kms {
    struct seen {
        std::string op;
        std::string key;
        kp::encryption_context context;
        std::string principal;
    };

    std::mutex mu;
    std::set<std::string> disabled;
    std::vector<seen> calls;

    [[nodiscard]] static auto arn_of(const std::string& key) -> std::optional<std::string> {
        static const std::map<std::string, std::string> names = {
            {"alias/aws/dynamodb/owned", "owned"},
            {"alias/aws/dynamodb", "managed"},
            {"alias/mine", "mine"},
            {"alias/other", "other"},
            {"alias/aws/s3", "s3"},
        };
        if (const auto it = names.find(key); it != names.end()) {
            return std::string(k_arn_prefix) + it->second;
        }
        if (key.starts_with(k_arn_prefix)) {
            return key;
        }
        return std::nullopt;
    }

    auto record(std::string op, const std::string& key, const kp::encryption_context& c,
                const kp::kms_caller& who) -> std::string {
        const std::scoped_lock lock(mu);
        calls.push_back(
            {std::move(op), key, c, who._principal != nullptr ? who._principal->arn : ""});
        const auto arn = arn_of(key);
        if (!arn) {
            throw kp::kms_error(kp::kms_failure::not_found, "no key " + key);
        }
        if (disabled.contains(*arn)) {
            throw kp::kms_error(kp::kms_failure::disabled, *arn + " is disabled");
        }
        return *arn;
    }

    [[nodiscard]] static auto context_text(const kp::encryption_context& c) -> std::string {
        std::string out;
        for (const auto& [k, v] : c) {
            out += k + "=" + v + ";";
        }
        return out;
    }

    [[nodiscard]] static auto wrap(const std::string& arn, const kp::encryption_context& c,
                                   const kp::data_key_bytes& key) -> std::string {
        return arn + "|" + context_text(c) + "|" +
               std::string(reinterpret_cast<const char*>(key.data()), key.size());
    }
};

/// The provider over a shared fake_kms.
class fake_provider {
public:
    explicit fake_provider(std::shared_ptr<fake_kms> kms) : _kms(std::move(kms)) {}

    [[nodiscard]] auto generate_data_key(const std::string& key, const kp::encryption_context& c,
                                         const kp::kms_caller& who) const
        -> kp::generated_data_key {
        const auto arn = _kms->record("GenerateDataKey", key, c, who);
        kp::generated_data_key out;
        BOOST_REQUIRE(RAND_bytes(out._plaintext.data(), static_cast<int>(out._plaintext.size())) ==
                      1);
        out._wrapped = fake_kms::wrap(arn, c, out._plaintext);
        out._key_id = arn;
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key, const std::string& wrapped,
                                        const kp::encryption_context& c,
                                        const kp::kms_caller& who) const -> kp::data_key_bytes {
        const auto arn = _kms->record("Decrypt", key, c, who);
        const auto head = arn + "|" + fake_kms::context_text(c) + "|";
        if (!wrapped.starts_with(head) || wrapped.size() != head.size() + 32) {
            throw kp::kms_error(kp::kms_failure::invalid_state, "wrong key or context");
        }
        kp::data_key_bytes out{};
        std::memcpy(out.data(), wrapped.data() + head.size(), out.size());
        return out;
    }

    [[nodiscard]] auto wrap_data_key(const std::string& key, const kp::data_key_bytes& plain,
                                     const kp::encryption_context& c,
                                     const kp::kms_caller& who) const -> kp::generated_data_key {
        const auto arn = _kms->record("Encrypt", key, c, who);
        kp::generated_data_key out;
        out._plaintext = plain;
        out._wrapped = fake_kms::wrap(arn, c, plain);
        out._key_id = arn;
        return out;
    }

private:
    std::shared_ptr<fake_kms> _kms;
};

static_assert(kp::per_caller_kms_key_provider<fake_provider>);
static_assert(kp::wrapping_kms_key_provider<fake_provider>);

auto kythira_config(const std::shared_ptr<fake_kms>& kms) -> ddb::table_key_config {
    ddb::table_key_config c;
    c.provider_name = "kythira";
    c.provider = kp::key_provider(fake_provider(kms));
    c.owned_key_id = "alias/aws/dynamodb/owned";
    return c;
}

auto create_body(std::string_view name, std::string_view sse = "") -> std::string {
    std::string body = R"({"TableName":")" + std::string(name) +
                       R"(","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],)"
                       R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],)"
                       R"("BillingMode":"PAY_PER_REQUEST")";
    if (!sse.empty()) {
        body += R"(,"SSESpecification":)" + std::string(sse);
    }
    return body + "}";
}

struct keyed_fixture : fixture {
    std::shared_ptr<fake_kms> kms = std::make_shared<fake_kms>();
    ddb::table_keys keys{kythira_config(kms)};

    keyed_fixture() { tables.set_table_keys(&keys); }

    auto sse_of(std::string_view name) -> ddb::table_sse {
        const auto d = backend.describe(std::string(name));
        BOOST_REQUIRE(d.has_value());
        return d->sse;
    }

    /// The table key, unwrapped as a replica will unwrap it.
    auto table_key(std::string_view name) -> kp::data_key_bytes {
        const auto s = sse_of(name);
        aws_principal root;
        return fake_provider(kms).decrypt_data_key(s.key_arn, s.wrapped,
                                                   ddb::table_key_context(name, s.account),
                                                   kp::kms_caller{._principal = &root.p});
    }

    /// Archive keys as the gateway makes them (KMS task 17).
    [[nodiscard]] auto archive_keys() -> ddb::archive_key_source {
        return [this](const ddb::table_descriptor& d) {
            return std::make_shared<const ddb::archive_key>(keys.open(d));
        };
    }

    struct aws_principal {
        az::principal_context p;
        aws_principal() { p.arn = "arn:aws:iam::111122223333:root"; }
    };
};

}  // namespace

BOOST_AUTO_TEST_CASE(a_table_naming_no_key_gets_the_owned_key) {
    keyed_fixture f;
    const auto r = f.call("CreateTable", create_body("plain"));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    // As on AWS, a table under an AWS owned key shows no SSEDescription.
    BOOST_TEST(!r.body.at("TableDescription").as_object().contains("SSEDescription"));
    const auto s = f.sse_of("plain");
    BOOST_TEST((s.kind == ddb::sse_kind::owned));
    BOOST_TEST(s.key_arn == std::string(k_arn_prefix) + "owned");
    BOOST_TEST(s.provider == "kythira");
    BOOST_TEST(s.account == std::string(k_account));
    BOOST_TEST(!s.wrapped.empty());

    // Made once, for the table's account, bound to the table.
    BOOST_REQUIRE(f.kms->calls.size() == 1U);
    const auto& call = f.kms->calls.front();
    BOOST_TEST(call.op == "GenerateDataKey");
    BOOST_TEST(call.key == "alias/aws/dynamodb/owned");
    BOOST_TEST(call.principal == "arn:aws:iam::111122223333:root");
    BOOST_TEST(call.context.at("aws:dynamodb:tableName") == "plain");
    BOOST_TEST(call.context.at("aws:dynamodb:subscriberId") == std::string(k_account));
    (void)f.table_key("plain");

    // Enabled false is the owned key too.
    BOOST_TEST(f.call("CreateTable", create_body("off", R"({"Enabled":false})")).status == 200U);
    BOOST_TEST((f.sse_of("off").kind == ddb::sse_kind::owned));
}

BOOST_AUTO_TEST_CASE(a_kms_key_is_used_for_the_caller_and_described) {
    keyed_fixture f;
    const auto r = f.call("CreateTable", create_body("mine", R"({"Enabled":true,"SSEType":"KMS",)"
                                                             R"("KMSMasterKeyId":"alias/mine"})"));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    const auto& sse = r.body.at("TableDescription").at("SSEDescription").as_object();
    BOOST_TEST(sse.at("Status").as_string() == "ENABLED");
    BOOST_TEST(sse.at("SSEType").as_string() == "KMS");
    BOOST_TEST(sse.at("KMSMasterKeyArn").as_string() == std::string(k_arn_prefix) + "mine");
    BOOST_TEST(!sse.contains("InaccessibleEncryptionDateTime"));
    BOOST_TEST(f.kms->calls.back().principal == "arn:aws:iam::111122223333:user/admin");
    BOOST_TEST((f.sse_of("mine").kind == ddb::sse_kind::kms));

    // DescribeTable says the same.
    const auto d = f.call("DescribeTable", R"({"TableName":"mine"})");
    BOOST_TEST(d.body.at("Table").at("SSEDescription").at("KMSMasterKeyArn").as_string() ==
               std::string(k_arn_prefix) + "mine");

    // Enabled without a key: the AWS managed key.
    BOOST_TEST(f.call("CreateTable", create_body("managed", R"({"Enabled":true})")).status == 200U);
    BOOST_TEST(f.sse_of("managed").key_arn == std::string(k_arn_prefix) + "managed");
    BOOST_TEST(f.kms->calls.back().key == "alias/aws/dynamodb");
}

BOOST_AUTO_TEST_CASE(bad_specifications_are_refused_before_a_table_exists) {
    keyed_fixture f;
    for (const auto& [sse, type] : std::initializer_list<std::pair<std::string, std::string>>{
             {R"({"Enabled":true,"KMSMasterKeyId":"alias/none"})", "ValidationException"},
             {R"({"Enabled":false,"KMSMasterKeyId":"alias/mine"})", "ValidationException"},
             {R"({"Enabled":false,"SSEType":"KMS"})", "ValidationException"},
             {R"({"Enabled":true,"SSEType":"AES256"})", "ValidationException"},
         }) {
        const auto r = f.call("CreateTable", create_body("tab", sse));
        BOOST_TEST(r.status == 400U, sse);
        BOOST_TEST(r.type() == type, sse << ": " << r.message());
        BOOST_TEST(!f.backend.describe("tab").has_value());
    }
    f.kms->disabled.insert(std::string(k_arn_prefix) + "mine");
    const auto r = f.call("CreateTable",
                          create_body("tab", R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"})"));
    BOOST_TEST(r.type() == "ValidationException");
    BOOST_TEST(r.message().find("disabled") != std::string::npos);
    BOOST_TEST(!f.backend.describe("tab").has_value());
}

BOOST_AUTO_TEST_CASE(without_a_provider_or_with_off_tables_stay_clear) {
    fixture f;
    BOOST_TEST(f.call("CreateTable", create_body("clear")).status == 200U);
    BOOST_TEST((f.backend.describe("clear")->sse == ddb::table_sse{}));
    const auto r = f.call("CreateTable", create_body("tab", R"({"Enabled":true})"));
    BOOST_TEST(r.type() == "ValidationException");
    BOOST_TEST(r.message().find("KYTHIRA_DYNAMODB_KMS") != std::string::npos);
    // Enabled false asks for nothing a cluster without keys lacks.
    BOOST_TEST(f.call("CreateTable", create_body("tab2", R"({"Enabled":false})")).status == 200U);

    keyed_fixture k;
    auto off = kythira_config(k.kms);
    off.at_rest = ddb::at_rest_mode::off;
    const ddb::table_keys keys(off);
    k.tables.set_table_keys(&keys);
    BOOST_TEST(k.call("CreateTable", create_body("clear")).status == 200U);
    BOOST_TEST((k.sse_of("clear").kind == ddb::sse_kind::none));
    BOOST_TEST(k.kms->calls.empty());
    // A key asked for is still honoured.
    BOOST_TEST(k.call("CreateTable", create_body("asked", R"({"Enabled":true})")).status == 200U);
    BOOST_TEST((k.sse_of("asked").kind == ddb::sse_kind::kms));
}

BOOST_AUTO_TEST_CASE(update_table_rewraps_the_same_table_key) {
    keyed_fixture f;
    BOOST_REQUIRE(f.call("CreateTable", create_body("tab")).status == 200U);
    const auto before = f.table_key("tab");

    auto r = f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":)"
                                   R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(
        r.body.at("TableDescription").at("SSEDescription").at("KMSMasterKeyArn").as_string() ==
        std::string(k_arn_prefix) + "mine");
    BOOST_TEST(f.sse_of("tab").key_arn == std::string(k_arn_prefix) + "mine");
    // Unwrapped as the owned key's account, wrapped as the caller.
    const auto n = f.kms->calls.size();
    BOOST_TEST(f.kms->calls[n - 2].op == "Decrypt");
    BOOST_TEST(f.kms->calls[n - 2].principal == "arn:aws:iam::111122223333:root");
    BOOST_TEST(f.kms->calls[n - 1].op == "Encrypt");
    BOOST_TEST(f.kms->calls[n - 1].principal == "arn:aws:iam::111122223333:user/admin");
    BOOST_TEST((f.table_key("tab") == before));  // no data to rewrite

    // The same key again is refused; another moves it on; back to owned.
    r = f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":)"
                              R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"}})");
    BOOST_TEST(r.type() == "ValidationException");
    BOOST_TEST(f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":)"
                                     R"({"Enabled":true,"KMSMasterKeyId":"alias/other"}})")
                   .status == 200U);
    BOOST_TEST((f.table_key("tab") == before));
    r = f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":{"Enabled":false}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.message());
    BOOST_TEST(!r.body.at("TableDescription").as_object().contains("SSEDescription"));
    BOOST_TEST((f.sse_of("tab").kind == ddb::sse_kind::owned));
    BOOST_TEST((f.table_key("tab") == before));
    r = f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":{"Enabled":false}})");
    BOOST_TEST(r.type() == "ValidationException");

    // Alone in its request, on a table that exists.
    r = f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":{"Enabled":true},)"
                              R"("DeletionProtectionEnabled":true})");
    BOOST_TEST(r.type() == "ValidationException");
    r = f.call("UpdateTable", R"({"TableName":"none","SSESpecification":{"Enabled":true}})");
    BOOST_TEST(r.type() == "ResourceNotFoundException");
}

BOOST_AUTO_TEST_CASE(a_clear_table_gets_a_key_from_update_table) {
    fixture f;
    BOOST_REQUIRE(f.call("CreateTable", create_body("old")).status == 200U);
    // The node now has a provider (an upgrade).
    auto kms = std::make_shared<fake_kms>();
    const ddb::table_keys keys(kythira_config(kms));
    f.tables.set_table_keys(&keys);
    const auto r = f.call("UpdateTable", R"({"TableName":"old","SSESpecification":)"
                                         R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST((f.backend.describe("old")->sse.kind == ddb::sse_kind::kms));
    BOOST_TEST(kms->calls.back().op == "GenerateDataKey");
}

BOOST_AUTO_TEST_CASE(a_table_keeps_opening_after_the_provider_changes) {
    keyed_fixture f;
    // Made under local, the provider before this one.
    const kp::key_provider local(kp::local_kms_provider("correct horse battery staple"));
    ddb::table_key_config lc;
    lc.provider_name = "local";
    lc.provider = local;
    lc.owned_key_id = "dynamodb-owned";
    lc.customer_keys = false;
    const ddb::table_keys local_keys(lc);
    f.tables.set_table_keys(&local_keys);
    BOOST_REQUIRE(f.call("CreateTable", create_body("tab")).status == 200U);
    const auto s = f.sse_of("tab");
    BOOST_TEST(s.provider == "local");
    BOOST_TEST(s.key_arn == "dynamodb-owned");
    const auto key =
        local.decrypt_data_key(s.key_arn, s.wrapped, ddb::table_key_context("tab", s.account));

    // The local provider takes only the owned key.
    auto r = f.call("CreateTable", create_body("kms", R"({"Enabled":true})"));
    BOOST_TEST(r.type() == "ValidationException");
    BOOST_TEST(r.message().find("owned key") != std::string::npos);

    // Moved to kythira without keeping local: the table cannot move.
    f.tables.set_table_keys(&f.keys);
    r = f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":)"
                              R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"}})");
    BOOST_TEST(r.type() == "ValidationException");
    BOOST_TEST(r.message().find("KYTHIRA_DYNAMODB_KMS_PREVIOUS=local") != std::string::npos);

    // With local as the previous provider it re-wraps the same key.
    auto moved = kythira_config(f.kms);
    moved.previous.emplace("local", local);
    const ddb::table_keys keys(moved);
    f.tables.set_table_keys(&keys);
    r = f.call("UpdateTable", R"({"TableName":"tab","SSESpecification":)"
                              R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(f.sse_of("tab").provider == "kythira");
    BOOST_TEST((f.table_key("tab") == key));
}

BOOST_AUTO_TEST_CASE(the_catalog_writes_format_13_only_for_an_encrypted_table) {
    ddb::table_descriptor d;
    d.name = "t";
    d.table_id = 7;
    d.schema.partition_name = "pk";
    const auto clear = ddb::encode_table_descriptor(d);
    BOOST_TEST(static_cast<int>(clear[0]) < 13);

    d.sse.kind = ddb::sse_kind::kms;
    d.sse.key_arn = std::string(k_arn_prefix) + "mine";
    d.sse.wrapped = std::string("\0\1wrapped", 9);
    d.sse.provider = "kythira";
    d.sse.account = std::string(k_account);
    d.sse.status = ddb::sse_status::inaccessible;
    d.sse.inaccessible_ms = 1794300000123ULL;
    const auto sealed = ddb::encode_table_descriptor(d);
    BOOST_TEST(static_cast<int>(sealed[0]) == 13);
    const auto back = ddb::decode_table_descriptor(sealed);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->sse == d.sse));

    // A node that predates format 13 refuses it: here, a version above
    // what this one knows is refused the same way.
    auto newer = sealed;
    newer[0] = static_cast<char>(ddb::catalog_detail::k_descriptor_format_version + 1);
    BOOST_TEST(!ddb::decode_table_descriptor(newer).has_value());

    // set_sse is a format-13 command.
    ddb::catalog_command c;
    c.op = ddb::catalog_command::kind::set_sse;
    c.table = d;
    const auto bytes = ddb::encode_catalog_command(c);
    BOOST_TEST(static_cast<int>(bytes[0]) == 13);
    bool newer_cmd = false;
    const auto again = ddb::decode_catalog_command(bytes, newer_cmd);
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST((again->op == ddb::catalog_command::kind::set_sse));
    BOOST_TEST((again->table.sse == d.sse));
}

BOOST_AUTO_TEST_CASE(an_inaccessible_table_says_so) {
    keyed_fixture f;
    BOOST_REQUIRE(f.call("CreateTable",
                         create_body("tab", R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"})"))
                      .status == 200U);
    auto d = *f.backend.describe("tab");
    ddb::catalog_command c;
    c.op = ddb::catalog_command::kind::set_sse;
    c.table = d;
    c.table.sse.status = ddb::sse_status::inaccessible;
    c.table.sse.inaccessible_ms = 1794300000000ULL;
    BOOST_REQUIRE(f.backend.catalog(c).ok());
    const auto r = f.call("DescribeTable", R"({"TableName":"tab"})");
    const auto& t = r.body.at("Table").as_object();
    BOOST_TEST(t.at("TableStatus").as_string() == "INACCESSIBLE_ENCRYPTION_CREDENTIALS");
    BOOST_TEST(t.at("SSEDescription").at("InaccessibleEncryptionDateTime").to_number<double>() ==
               1794300000.0);
}

BOOST_AUTO_TEST_CASE(a_restored_table_gets_a_key_of_its_own) {
    keyed_fixture f;
    f.without_throttling();
    auto store = std::make_shared<ddb::memory_backup_store>();
    ddb::backup_api<ddb::local_backend<>> backups{f.backend, store};
    ddb::backup_worker<ddb::local_backend<>> worker{f.backend, store};
    worker.set_archive_keys(f.archive_keys());
    backups.set_table_keys(&f.keys);
    backups.register_with(*f.fe);
    BOOST_REQUIRE(f.call("CreateTable",
                         create_body("src", R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"})"))
                      .status == 200U);
    const auto b = f.ok("CreateBackup", R"({"TableName":"src","BackupName":"nightly"})");
    const std::string arn(b.at("BackupDetails").at("BackupArn").as_string());
    BOOST_REQUIRE(worker.pass() == 1U);

    // No override: the owned key, bound to the new table's name.
    auto r = f.call("RestoreTableFromBackup",
                    R"({"TargetTableName":"dst","BackupArn":")" + arn + R"("})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST((f.sse_of("dst").kind == ddb::sse_kind::owned));
    BOOST_TEST(f.kms->calls.back().context.at("aws:dynamodb:tableName") == "dst");
    (void)f.table_key("dst");

    // SSESpecificationOverride names the key.
    r = f.call(
        "RestoreTableFromBackup",
        R"({"TargetTableName":"dst2","BackupArn":")" + arn +
            R"(","SSESpecificationOverride":{"Enabled":true,"KMSMasterKeyId":"alias/other"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(f.sse_of("dst2").key_arn == std::string(k_arn_prefix) + "other");
    BOOST_TEST((f.table_key("dst2") != f.table_key("src")));

    // A bad override makes no table.
    r = f.call(
        "RestoreTableFromBackup",
        R"({"TargetTableName":"dst3","BackupArn":")" + arn +
            R"(","SSESpecificationOverride":{"Enabled":true,"KMSMasterKeyId":"alias/none"}})");
    BOOST_TEST(r.type() == "ValidationException");
    BOOST_TEST(!f.backend.describe("dst3").has_value());
}

namespace {

auto settings(std::map<std::string, std::string> vars)
    -> std::variant<ddb::encryption_settings, std::string> {
    return ddb::encryption_settings_from_env(
        [vars = std::move(vars)](std::string_view k) -> std::optional<std::string> {
            const auto it = vars.find(std::string(k));
            return it == vars.end() ? std::nullopt : std::optional<std::string>(it->second);
        });
}

auto refusal(std::map<std::string, std::string> vars) -> std::string {
    auto r = settings(std::move(vars));
    const auto* e = std::get_if<std::string>(&r);
    return e != nullptr ? *e : std::string();
}

}  // namespace

BOOST_AUTO_TEST_CASE(items_of_an_encrypted_table_are_sealed_on_disk) {
    keyed_fixture f;
    auto ring = std::make_shared<ddb::table_key_ring>();
    f.backend.set_sealer(ddb::item_sealer(ring));
    ddb::table_key_refresher<ddb::local_backend<>> refresher(f.backend, f.keys, ring);
    BOOST_REQUIRE(f.call("CreateTable", create_body("vault")).status == 200U);
    {
        // The table's key is not on the node yet: the write fails with
        // nothing written, and the key is now wanted.
        const auto r = f.call("PutItem", R"({"TableName":"vault","Item":{"pk":{"S":"a"},)"
                                         R"("secret":{"S":"hunter2"}}})");
        BOOST_TEST(r.status == 500U);
        BOOST_TEST(!ring->wanted().empty());
    }
    // A pass with nothing asked for fetches nothing; one with a key wanted
    // fetches it, as the table's account.
    BOOST_TEST(refresher.pass(false, 1) == 1U);
    BOOST_TEST(ring->wanted().empty());
    BOOST_TEST(refresher.pass(false, 2) == 0U);
    BOOST_TEST(f.kms->calls.back().op == "Decrypt");
    BOOST_TEST(f.kms->calls.back().principal == "arn:aws:iam::111122223333:root");

    auto r = f.call("PutItem", R"({"TableName":"vault","Item":{"pk":{"S":"a"},)"
                               R"("secret":{"S":"hunter2"}}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    std::size_t sealed = 0;
    f.engine.scan(kythira::column_family::data, ddb::prefix_range("t/"),
                  kythira::scan_direction::forward, [&](std::string_view, std::string_view v) {
                      BOOST_TEST(v.find("hunter2") == std::string_view::npos);
                      sealed += ddb::is_sealed_value(v) ? 1 : 0;
                      return true;
                  });
    BOOST_TEST(sealed == 1U);
    r = f.call("GetItem", R"({"TableName":"vault","Key":{"pk":{"S":"a"}}})");
    BOOST_TEST(r.body.at("Item").at("secret").at("S").as_string() == "hunter2");
    r = f.call("Scan", R"({"TableName":"vault"})");
    BOOST_TEST(r.body.at("Count").as_int64() == 1);

    // A table with no key stays clear.
    const ddb::table_keys none;
    f.tables.set_table_keys(&none);
    BOOST_REQUIRE(f.call("CreateTable", create_body("open")).status == 200U);
    BOOST_REQUIRE(f.call("PutItem", R"({"TableName":"open","Item":{"pk":{"S":"b"},)"
                                    R"("note":{"S":"in the clear"}}})")
                      .status == 200U);
    bool clear = false;
    f.engine.scan(kythira::column_family::data, ddb::prefix_range("t/"),
                  kythira::scan_direction::forward, [&](std::string_view, std::string_view v) {
                      clear = clear || v.find("in the clear") != std::string_view::npos;
                      return true;
                  });
    BOOST_TEST(clear);

    // A provider that refuses: the table is reported as failing from the
    // first refusal on, until a pass opens it.
    auto other = std::make_shared<ddb::table_key_ring>();
    ddb::table_key_refresher<ddb::local_backend<>> second(f.backend, f.keys, other);
    f.kms->disabled.insert(std::string(k_arn_prefix) + "owned");
    BOOST_TEST(second.pass(true, 100) == 0U);
    BOOST_TEST(second.failing().at(f.backend.describe("vault")->table_id) == 100U);
    BOOST_TEST(second.pass(true, 200) == 0U);
    BOOST_TEST(second.failing().at(f.backend.describe("vault")->table_id) == 100U);
    BOOST_TEST(second.last_error(f.backend.describe("vault")->table_id).find("disabled") !=
               std::string::npos);
    f.kms->disabled.clear();
    BOOST_TEST(second.pass(true, 300) == 1U);
    BOOST_TEST(second.failing().empty());
}

BOOST_AUTO_TEST_CASE(a_table_whose_key_stays_unusable_goes_inaccessible_and_back) {
    keyed_fixture f;
    auto ring = std::make_shared<ddb::table_key_ring>();
    f.backend.set_sealer(ddb::item_sealer(ring));
    ddb::table_key_watch<ddb::local_backend<>> watch(f.backend, f.keys, ring);
    watch.check_interval_ms = 0;
    watch.inaccessible_after_ms = 1000;
    BOOST_REQUIRE(f.call("CreateTable",
                         create_body("tab", R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"})"))
                      .status == 200U);
    // A pass puts the key on the node, so the table serves.
    BOOST_TEST(watch.pass(1) == 0U);
    BOOST_REQUIRE(f.call("PutItem", R"({"TableName":"tab","Item":{"pk":{"S":"a"}}})").status ==
                  200U);

    f.kms->disabled.insert(std::string(k_arn_prefix) + "mine");
    BOOST_TEST(watch.pass(10) == 0U);  // failing, not for long enough
    BOOST_TEST((f.sse_of("tab").status == ddb::sse_status::enabled));
    BOOST_TEST(watch.pass(1010) == 1U);
    BOOST_TEST((f.sse_of("tab").status == ddb::sse_status::inaccessible));
    BOOST_TEST(f.sse_of("tab").inaccessible_ms == 1010U);
    auto r = f.call("GetItem", R"({"TableName":"tab","Key":{"pk":{"S":"a"}}})");
    BOOST_TEST(r.status == 400U);
    BOOST_TEST(r.type().find("ValidationException") != std::string::npos);
    BOOST_TEST(r.message().find("KMS key access denied") != std::string::npos);
    BOOST_TEST(watch.pass(2000) == 0U);  // stays so, no new date

    f.kms->disabled.clear();
    BOOST_TEST(watch.pass(3000) == 1U);
    BOOST_TEST((f.sse_of("tab").status == ddb::sse_status::enabled));
    BOOST_TEST(f.sse_of("tab").inaccessible_ms == 0U);
    r = f.call("GetItem", R"({"TableName":"tab","Key":{"pk":{"S":"a"}}})");
    BOOST_TEST(r.status == 200U);

    // A verdict on a key the table has left changes nothing.
    auto d = *f.backend.describe("tab");
    ddb::catalog_command c;
    c.op = ddb::catalog_command::kind::set_sse;
    c.table = d;
    c.table.sse.wrapped = "another wrapped key";
    c.table.sse.status = ddb::sse_status::inaccessible;
    c.done = true;
    BOOST_REQUIRE(f.backend.catalog(c).ok());
    BOOST_TEST((f.sse_of("tab") == d.sse));
}

BOOST_AUTO_TEST_CASE(a_clear_table_that_gains_a_key_is_resealed) {
    keyed_fixture f;
    auto ring = std::make_shared<ddb::table_key_ring>();
    f.backend.set_sealer(ddb::item_sealer(ring));
    const ddb::table_keys none;
    f.tables.set_table_keys(&none);
    BOOST_REQUIRE(f.call("CreateTable", create_body("old")).status == 200U);
    for (const auto* pk : {"a", "b", "c"}) {
        BOOST_REQUIRE(f.call("PutItem", std::string(R"({"TableName":"old","Item":{"pk":{"S":")") +
                                            pk + R"("},"v":{"S":"plain-)" + pk + R"("}}})")
                          .status == 200U);
    }
    const auto clear_values = [&] {
        std::size_t n = 0;
        f.engine.scan(kythira::column_family::data, ddb::prefix_range("t/"),
                      kythira::scan_direction::forward, [&](std::string_view, std::string_view v) {
                          n += ddb::is_sealed_value(v) ? 0 : 1;
                          return true;
                      });
        return n;
    };
    BOOST_TEST(clear_values() == 3U);

    f.tables.set_table_keys(&f.keys);
    auto r = f.call("UpdateTable", R"({"TableName":"old","SSESpecification":)"
                                   R"({"Enabled":true,"KMSMasterKeyId":"alias/mine"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.body.at("TableDescription").at("SSEDescription").at("Status").as_string() ==
               "UPDATING");
    BOOST_TEST(clear_values() == 3U);  // nothing rewritten yet

    ddb::table_key_watch<ddb::local_backend<>> watch(f.backend, f.keys, ring);
    BOOST_TEST(watch.pass(1) == 1U);
    BOOST_TEST(clear_values() == 0U);
    BOOST_TEST((f.sse_of("old").status == ddb::sse_status::enabled));
    r = f.call("GetItem", R"({"TableName":"old","Key":{"pk":{"S":"b"}}})");
    BOOST_TEST(r.body.at("Item").at("v").at("S").as_string() == "plain-b");
    r = f.call("DescribeTable", R"({"TableName":"old"})");
    BOOST_TEST(r.body.at("Table").at("SSEDescription").at("Status").as_string() == "ENABLED");
}

BOOST_AUTO_TEST_CASE(change_records_of_an_encrypted_table_are_sealed) {
    keyed_fixture f;
    auto ring = std::make_shared<ddb::table_key_ring>();
    f.backend.set_sealer(ddb::item_sealer(ring));
    ddb::table_key_refresher<ddb::local_backend<>> refresher(f.backend, f.keys, ring);
    auto body = create_body("logged");
    body.pop_back();
    body += R"(,"StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_IMAGE"}})";
    auto r = f.call("CreateTable", body);
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    const std::string arn(r.body.at("TableDescription").at("LatestStreamArn").as_string());
    BOOST_TEST(refresher.pass(true, 1) == 1U);
    BOOST_REQUIRE(f.call("PutItem", R"({"TableName":"logged","Item":{"pk":{"S":"a"},)"
                                    R"("secret":{"S":"hunter2"}}})")
                      .status == 200U);

    // The stream reads the record back clear...
    r = f.call("DescribeStream", R"({"StreamArn":")" + arn + R"("})");
    const std::string shard(
        r.body.at("StreamDescription").at("Shards").as_array().at(0).at("ShardId").as_string());
    r = f.call("GetShardIterator", R"({"StreamArn":")" + arn + R"(","ShardId":")" + shard +
                                       R"(","ShardIteratorType":"TRIM_HORIZON"})");
    const std::string it(r.body.at("ShardIterator").as_string());
    r = f.call("GetRecords", R"({"ShardIterator":")" + it + R"("})");
    const auto& records = r.body.at("Records").as_array();
    BOOST_REQUIRE(records.size() == 1U);
    BOOST_TEST(records[0].at("dynamodb").at("NewImage").at("secret").at("S").as_string() ==
               "hunter2");

    // ...and nothing the change log keeps on disk holds it.
    std::size_t files = 0;
    for (const auto& e : std::filesystem::recursive_directory_iterator(f.log_dir.path)) {
        if (!e.is_regular_file()) {
            continue;
        }
        ++files;
        std::ifstream in(e.path(), std::ios::binary);
        const std::string bytes((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
        BOOST_TEST(bytes.find("hunter2") == std::string::npos, e.path());
    }
    BOOST_TEST(files > 0U);
}

BOOST_AUTO_TEST_CASE(backups_of_an_encrypted_table_are_sealed) {
    keyed_fixture f;
    f.without_throttling();
    auto ring = std::make_shared<ddb::table_key_ring>();
    f.backend.set_sealer(ddb::item_sealer(ring));
    ddb::table_key_refresher<ddb::local_backend<>> refresher(f.backend, f.keys, ring);
    auto store = std::make_shared<ddb::memory_backup_store>();
    ddb::backup_api<ddb::local_backend<>> backups{f.backend, store};
    ddb::backup_worker<ddb::local_backend<>> worker{f.backend, store};
    backups.set_table_keys(&f.keys);
    backups.register_with(*f.fe);
    BOOST_REQUIRE(f.call("CreateTable", create_body("src")).status == 200U);
    BOOST_TEST(refresher.pass(true, 1) == 1U);
    BOOST_REQUIRE(f.call("PutItem", R"({"TableName":"src","Item":{"pk":{"S":"a"},)"
                                    R"("secret":{"S":"hunter2"}}})")
                      .status == 200U);
    const auto b = f.ok("CreateBackup", R"({"TableName":"src","BackupName":"nightly"})");
    const std::string arn(b.at("BackupDetails").at("BackupArn").as_string());

    // Without a way to open the table key, nothing is written in the clear.
    BOOST_CHECK_THROW((void)worker.pass(), std::runtime_error);
    worker.set_archive_keys(f.archive_keys());
    worker.poke();
    BOOST_REQUIRE(worker.pass() == 1U);
    std::size_t sealed = 0;
    for (const auto& key : store->list("backups/")) {
        if (key.find("/data/") == std::string::npos) {
            continue;
        }
        const auto body = store->get(key);
        BOOST_REQUIRE(body.has_value());
        BOOST_TEST(body->find("hunter2") == std::string::npos);
        sealed += ddb::is_sealed_archive(*body) ? 1 : 0;
    }
    BOOST_TEST(sealed == 1U);

    // A restore opens it, also after the source table is gone.
    BOOST_REQUIRE(f.call("DeleteTable", R"({"TableName":"src"})").status == 200U);
    auto r = f.call("RestoreTableFromBackup",
                    R"({"TargetTableName":"dst","BackupArn":")" + arn + R"("})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(refresher.pass(true, 2) == 1U);
    (void)worker.pass();
    r = f.call("GetItem", R"({"TableName":"dst","Key":{"pk":{"S":"a"}}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.body.at("Item").at("secret").at("S").as_string() == "hunter2");
}

BOOST_AUTO_TEST_CASE(point_in_time_archives_of_an_encrypted_table_are_sealed) {
    keyed_fixture f;
    f.without_throttling();
    auto ring = std::make_shared<ddb::table_key_ring>();
    f.backend.set_sealer(ddb::item_sealer(ring));
    ddb::table_key_refresher<ddb::local_backend<>> refresher(f.backend, f.keys, ring);
    auto store = std::make_shared<ddb::memory_backup_store>();
    ddb::pitr_api<ddb::local_backend<>> pitr{f.backend, store};
    ddb::pitr_worker_options options;
    options.latest_lag_ms = 0;
    ddb::pitr_worker<ddb::local_backend<>> worker{f.backend, store, options};
    worker.set_archive_keys(f.archive_keys());
    pitr.set_table_keys(&f.keys);
    pitr.register_with(*f.fe);
    pitr.on_changed([&] { worker.poke(); });
    BOOST_REQUIRE(f.call("CreateTable", create_body("src")).status == 200U);
    BOOST_TEST(refresher.pass(true, 1) == 1U);
    BOOST_REQUIRE(f.call("PutItem", R"({"TableName":"src","Item":{"pk":{"S":"a"},)"
                                    R"("secret":{"S":"in-the-base"}}})")
                      .status == 200U);
    BOOST_REQUIRE(f.call("UpdateContinuousBackups",
                         R"({"TableName":"src","PointInTimeRecoverySpecification":)"
                         R"({"PointInTimeRecoveryEnabled":true}})")
                      .status == 200U);
    f.clock_ms += 1000;
    (void)worker.pass();
    f.clock_ms += 1000;
    BOOST_REQUIRE(f.call("PutItem", R"({"TableName":"src","Item":{"pk":{"S":"b"},)"
                                    R"("secret":{"S":"in-the-log"}}})")
                      .status == 200U);
    f.clock_ms += 1000;
    worker.poke();
    (void)worker.pass();

    std::size_t sealed = 0;
    for (const auto& key : store->list("")) {
        const auto body = store->get(key);
        BOOST_REQUIRE(body.has_value());
        BOOST_TEST(body->find("in-the-") == std::string::npos, key);
        sealed += ddb::is_sealed_archive(*body) ? 1 : 0;
    }
    BOOST_TEST(sealed >= 2U);  // the base's data and a log object

    auto r =
        f.call("RestoreTableToPointInTime", R"({"SourceTableName":"src","TargetTableName":"dst",)"
                                            R"("UseLatestRestorableTime":true})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(refresher.pass(true, 2) == 1U);
    (void)worker.pass();
    for (const auto& [pk, v] : std::initializer_list<std::pair<const char*, const char*>>{
             {"a", "in-the-base"}, {"b", "in-the-log"}}) {
        r = f.call("GetItem",
                   std::string(R"({"TableName":"dst","Key":{"pk":{"S":")") + pk + R"("}}})");
        BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
        BOOST_TEST(r.body.at("Item").at("secret").at("S").as_string() == v);
    }
}

namespace {

/// A store with server-side encryption of its own, as an AWS S3 bucket.
class native_sse_store final : public ddb::backup_store {
public:
    void put(const std::string& key, std::string_view bytes) override {
        objects[key] = std::string(bytes);
    }
    [[nodiscard]] auto get(const std::string& key) -> std::optional<std::string> override {
        const auto it = objects.find(key);
        return it == objects.end() ? std::nullopt : std::optional<std::string>(it->second);
    }
    void remove(const std::string& key) override { objects.erase(key); }
    [[nodiscard]] auto list(const std::string& /*prefix*/) -> std::vector<std::string> override {
        return {};
    }
    [[nodiscard]] auto put_sse_kms(const std::string& key, std::string_view bytes,
                                   const std::string& kms_key_id) -> bool override {
        objects[key] = std::string(bytes);
        kms_keys[key] = kms_key_id;
        return true;
    }

    std::map<std::string, std::string> objects;
    std::map<std::string, std::string> kms_keys;
};

}  // namespace

BOOST_AUTO_TEST_CASE(a_bucket_under_a_kms_key_seals_objects_bound_to_their_names) {
    keyed_fixture f;
    auto inner = std::make_shared<ddb::memory_backup_store>();
    const auto keys = ddb::object_keys_of(f.keys, std::string(k_account), "aws");
    ddb::kms_sealed_bucket sealed(inner, "exp", "alias/mine", keys);
    sealed.put("a/1", "hunter2");
    const auto stored = inner->get("a/1");
    BOOST_REQUIRE(stored.has_value());
    BOOST_TEST(ddb::is_sse_sealed(*stored));
    BOOST_TEST(stored->find("hunter2") == std::string::npos);
    {
        const std::scoped_lock lock(f.kms->mu);
        const auto& last = f.kms->calls.back();
        BOOST_TEST(last.op == "GenerateDataKey");
        BOOST_TEST(last.key == "alias/mine");
        BOOST_TEST(last.context.at("aws:s3:arn") == "arn:aws:s3:::exp/a/1");
        BOOST_TEST(last.principal == "arn:aws:iam::111122223333:root");
    }

    // A reader with no key of its own opens it; clear objects pass through.
    ddb::kms_sealed_bucket reader(inner, "exp", "", keys);
    BOOST_TEST(reader.get("a/1").value_or("") == "hunter2");
    inner->put("a/2", "plain");
    BOOST_TEST(reader.get("a/2").value_or("") == "plain");

    // Moved to another name or bucket, or tampered with, it does not open.
    inner->put("a/3", *stored);
    BOOST_CHECK_THROW((void)reader.get("a/3"), ddb::bucket_sse_error);
    ddb::kms_sealed_bucket other_bucket(inner, "elsewhere", "", keys);
    BOOST_CHECK_THROW((void)other_bucket.get("a/1"), ddb::bucket_sse_error);
    auto bent = *stored;
    bent.back() = static_cast<char>(bent.back() ^ 1);
    inner->put("a/1", bent);
    BOOST_CHECK_THROW((void)reader.get("a/1"), ddb::bucket_sse_error);
    inner->put("a/4", std::string(ddb::k_sse_magic) + "x");
    BOOST_CHECK_THROW((void)reader.get("a/4"), ddb::bucket_sse_error);

    // A key the provider does not have, a disabled key, and no provider.
    ddb::kms_sealed_bucket unknown(inner, "exp", "alias/none", keys);
    BOOST_CHECK_THROW(unknown.put("b", "x"), ddb::bucket_sse_error);
    BOOST_CHECK_THROW(ddb::kms_sealed_bucket(inner, "exp", "alias/mine", {}).put("b", "x"),
                      ddb::bucket_sse_error);
    sealed.put("c", "later");
    f.kms->disabled.insert(std::string(k_arn_prefix) + "mine");
    BOOST_CHECK_THROW((void)reader.get("c"), ddb::bucket_sse_error);
    BOOST_TEST(!inner->get("b").has_value());

    // A store that encrypts itself is asked to, and nothing is sealed.
    auto native = std::make_shared<native_sse_store>();
    ddb::kms_sealed_bucket on_s3(native, "exp", "alias/other", {});
    on_s3.put("n", "clear");
    BOOST_TEST(native->objects.at("n") == "clear");
    BOOST_TEST(native->kms_keys.at("n") == "alias/other");
}

BOOST_AUTO_TEST_CASE(an_export_under_a_kms_key_is_sealed_and_imports_back) {
    keyed_fixture f;
    f.without_throttling();
    auto store = std::make_shared<ddb::memory_backup_store>();
    ddb::memory_buckets buckets;
    ddb::pitr_api<ddb::local_backend<>> pitr{f.backend, store};
    pitr.register_with(*f.fe);
    const auto resolver = buckets.resolver();
    ddb::export_import_api<ddb::local_backend<>> jobs{f.backend, store, resolver};
    ddb::export_import_worker<ddb::local_backend<>> worker{f.backend, store, resolver};
    jobs.set_table_keys(&f.keys);
    jobs.register_with(*f.fe);
    jobs.on_started([&] { worker.poke(); });
    worker.set_object_keys([&](const std::string& account, const std::string& partition) {
        return ddb::object_keys_of(f.keys, account, partition);
    });

    auto ring = std::make_shared<ddb::table_key_ring>();
    f.backend.set_sealer(ddb::item_sealer(ring));
    ddb::table_key_refresher<ddb::local_backend<>> refresher(f.backend, f.keys, ring);
    BOOST_REQUIRE(f.call("CreateTable", create_body("src")).status == 200U);
    BOOST_TEST(refresher.pass(true, 1) == 1U);
    (void)f.ok("UpdateContinuousBackups",
               R"({"TableName":"src","PointInTimeRecoverySpecification":)"
               R"({"PointInTimeRecoveryEnabled":true}})");
    (void)f.ok("PutItem", R"({"TableName":"src","Item":{"pk":{"S":"a"},)"
                          R"("secret":{"S":"hunter2"}}})");
    const std::string table_arn =
        "arn:aws:dynamodb:us-east-1:" + std::string(k_account) + ":table/src";
    const auto run_export = [&](const std::string& sse) {
        const auto started = f.ok(
            "ExportTableToPointInTime",
            R"({"TableArn":")" + table_arn + R"(","S3Bucket":"exp",)" + sse + R"("S3Prefix":"p"})");
        (void)worker.pass();
        return f
            .ok("DescribeExport",
                R"({"ExportArn":")" +
                    std::string(started.at("ExportDescription").at("ExportArn").as_string()) +
                    R"("})")
            .at("ExportDescription")
            .as_object();
    };

    // The default key is the account's aws/s3, and every object is sealed.
    auto d = run_export(R"("S3SseAlgorithm":"KMS",)");
    BOOST_REQUIRE_MESSAGE(d.at("ExportStatus").as_string() == "COMPLETED",
                          boost::json::serialize(d));
    std::string data_prefix;
    std::size_t objects = 0;
    for (const auto& key : buckets.store("exp")->list("p/")) {
        const auto body = buckets.store("exp")->get(key);
        BOOST_REQUIRE(body.has_value());
        BOOST_TEST(ddb::is_sse_sealed(*body), key);
        BOOST_TEST(body->find("hunter2") == std::string::npos);
        if (key.find("/data/") != std::string::npos) {
            data_prefix = key.substr(0, key.rfind('/') + 1);
        }
        ++objects;
    }
    BOOST_TEST(objects >= 4U);
    BOOST_REQUIRE(!data_prefix.empty());
    {
        const std::scoped_lock lock(f.kms->mu);
        BOOST_TEST(std::any_of(f.kms->calls.begin(), f.kms->calls.end(),
                               [](const fake_kms::seen& s) { return s.key == "alias/aws/s3"; }));
    }

    // An import from the bucket opens what the export sealed.
    const auto* const compression = ddb::export_formats::has_gzip() ? "GZIP" : "NONE";
    auto r =
        f.call("ImportTable",
               R"({"S3BucketSource":{"S3Bucket":"exp","S3KeyPrefix":")" + data_prefix +
                   R"("},"InputFormat":"DYNAMODB_JSON","InputCompressionType":")" + compression +
                   R"(","TableCreationParameters":{"TableName":"dst",)"
                   R"("AttributeDefinitions":[{"AttributeName":"pk",)"
                   R"("AttributeType":"S"}],"KeySchema":[{"AttributeName":)"
                   R"("pk","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(refresher.pass(true, 2) == 1U);
    (void)worker.pass();
    r = f.call("GetItem", R"({"TableName":"dst","Key":{"pk":{"S":"a"}}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.body.at("Item").at("secret").at("S").as_string() == "hunter2");

    // A key the provider refuses fails the export, saying why.
    d = run_export(R"("S3SseAlgorithm":"KMS","S3SseKmsKeyId":"alias/none",)");
    BOOST_TEST(d.at("ExportStatus").as_string() == "FAILED");
    BOOST_TEST(d.at("FailureCode").as_string() == "KMSAccessDenied");
    BOOST_TEST(std::string(d.at("FailureMessage").as_string()).find("alias/none") !=
               std::string::npos);
}

BOOST_AUTO_TEST_CASE(the_settings_are_checked) {
    const auto none = std::get<ddb::encryption_settings>(settings({}));
    BOOST_TEST(none.kms.empty());
    BOOST_TEST(refusal({{"KYTHIRA_DYNAMODB_KMS", "vault"}}).find("expected kythira") !=
               std::string::npos);
    BOOST_TEST(!refusal({{"KYTHIRA_DYNAMODB_KMS", "kythira"},
                         {"KYTHIRA_DYNAMODB_KMS_PREVIOUS", "kythira"}})
                    .empty());
    BOOST_TEST(refusal({{"KYTHIRA_DYNAMODB_KMS", "local"}}).find("PASSPHRASE") !=
               std::string::npos);
    BOOST_TEST(refusal({{"KYTHIRA_DYNAMODB_KMS", "aws"}}).find("OWNED_KEY") != std::string::npos);
    BOOST_TEST(
        refusal({{"KYTHIRA_DYNAMODB_KMS", "aws"}, {"KYTHIRA_DYNAMODB_ENCRYPT_AT_REST", "off"}})
            .empty());
    BOOST_TEST(refusal({{"KYTHIRA_DYNAMODB_ENCRYPT_AT_REST", "sometimes"}}).find("owned or off") !=
               std::string::npos);
    BOOST_TEST(!refusal({{"KYTHIRA_DYNAMODB_KMS", "aws"},
                         {"KYTHIRA_DYNAMODB_KMS_OWNED_KEY", "alias/k"},
                         {"KYTHIRA_DYNAMODB_KMS_PREVIOUS", "kythira"},
                         {"KYTHIRA_DYNAMODB_KMS_ENDPOINT", "kms.example:443"}})
                    .empty());
}

BOOST_AUTO_TEST_CASE(the_settings_make_the_providers_they_name) {
    BOOST_TEST(!ddb::table_keys(ddb::make_table_key_config({}, "off", "us-east-1")).configured());

    const auto local = std::get<ddb::encryption_settings>(
        settings({{"KYTHIRA_DYNAMODB_KMS", "local"},
                  {"KYTHIRA_DYNAMODB_KMS_PASSPHRASE", "correct horse battery staple"}}));
    const auto lc = ddb::make_table_key_config(local, "local", "us-east-1");
    BOOST_TEST(lc.provider_name == "local");
    BOOST_TEST(!lc.customer_keys);
    BOOST_TEST(!lc.owned_key_id.empty());
    BOOST_TEST((lc.at_rest == ddb::at_rest_mode::owned));

    const auto aws = std::get<ddb::encryption_settings>(
        settings({{"KYTHIRA_DYNAMODB_KMS", "aws"},
                  {"KYTHIRA_DYNAMODB_KMS_OWNED_KEY", "alias/kythira-owned"},
                  {"KYTHIRA_DYNAMODB_KMS_PREVIOUS", "local"},
                  {"KYTHIRA_DYNAMODB_KMS_PASSPHRASE", "correct horse battery staple"}}));
    const auto ac = ddb::make_table_key_config(aws, "aws", "eu-west-1");
    BOOST_TEST(ac.owned_key_id == "alias/kythira-owned");
    BOOST_TEST(ac.customer_keys);
    BOOST_TEST(ac.previous.contains("local"));

    // kythira in the node: the module's slot, read on each call; empty
    // until the KMS module has started, which a table creation reports.
    auto slot = std::make_shared<std::shared_ptr<kythira::service_node::kms_endpoint>>();
    const auto kc = ddb::make_table_key_config({}, "kythira", "us-east-1", slot);
    BOOST_TEST(kc.owned_key_id == "alias/aws/dynamodb/owned");
    BOOST_TEST(kc.provider.per_caller());
    const ddb::table_keys keys(kc);
    fixture f;
    f.tables.set_table_keys(&keys);
    const auto r = f.call("CreateTable", create_body("tab"));
    BOOST_TEST(r.status == 500U);
    BOOST_TEST(r.message().find("unavailable") != std::string::npos);
    BOOST_TEST(!f.backend.describe("tab").has_value());
}
