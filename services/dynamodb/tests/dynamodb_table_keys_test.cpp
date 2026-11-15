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
#include <kythira/dynamodb/catalog.hpp>
#include <kythira/dynamodb/table_key_providers.hpp>
#include <kythira/dynamodb/table_keys.hpp>

#include <raft/kms_key_provider.hpp>

#include <boost/json.hpp>

#include <openssl/rand.h>

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
