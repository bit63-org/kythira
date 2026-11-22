// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Kinesis on Kythira's KMS inside kythira_node (.kiro/specs/
// kms-compatible-api/ task 15, Requirements 11.1-11.5), as a process: one
// member runs IAM, Kinesis and the KMS (over SoftHSM2, standing in for an
// external PKCS#11 module). Kinesis encrypts with the KMS by default and
// asks it for each caller, so the KMS judges the Kinesis request's own
// principal: a role that the stream's policy lets write and read is still
// refused when the key's policy denies it, while a role the key allows
// writes and reads the same stream.
//
// The source lives with IAM's tests because IAM issues the test PKI and
// the roles; a module test may include no other module, so the Kinesis
// and KMS calls speak each wire directly.

#define BOOST_TEST_MODULE kythira_node_kms_kinesis_test

#include <boost/test/unit_test.hpp>

#include "iam_node_test_support.hpp"

#ifndef KYTHIRA_NODE_PATH
#error "KYTHIRA_NODE_PATH must be defined"
#endif
#ifndef KYTHIRA_SOFTHSM2_LIBRARY
#error "KYTHIRA_SOFTHSM2_LIBRARY must be defined"
#endif
#ifndef KYTHIRA_SOFTHSM2_UTIL
#error "KYTHIRA_SOFTHSM2_UTIL must be defined"
#endif

#include <raft/private_file.hpp>

#include <boost/json.hpp>

#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

using namespace iam_node_testing;  // NOLINT(google-build-using-namespace)
namespace sigv4 = kythira::sigv4;

constexpr std::string_view k_account = "111122223333";

/// Access key, secret and (for a role) session token.
struct credentials {
    std::string id;
    std::string secret;
    std::string token;
};

/// Percent-encodes `s` for a Query body.
auto enc(std::string_view s) -> std::string {
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : s) {
        if ((std::isalnum(c) != 0) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex.at(c >> 4U);
            out += hex.at(c & 15U);
        }
    }
    return out;
}

auto form_value(const std::string& xml, const std::string& tag) -> std::string {
    const auto open = "<" + tag + ">";
    const auto at = xml.find(open);
    if (at == std::string::npos) {
        return {};
    }
    const auto start = at + open.size();
    return xml.substr(start, xml.find("</" + tag + ">", start) - start);
}

/// A SigV4-signed AWS JSON call: `X-Amz-Target: <target>`, signed for
/// `service`, with the session token when there is one.
auto json_call(std::uint16_t port, const kythira::iam::testing::test_pki_paths& pki,
               const credentials& who, const std::string& service, const std::string& target,
               const std::string& content_type, const std::string& body)
    -> std::optional<http_result> {
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    const auto amz = sigv4::detail::format_amz_date(now);
    const std::string signed_headers =
        who.token.empty() ? "content-type;host;x-amz-date;x-amz-target"
                          : "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";
    const auto auth = [&](std::string_view sig) {
        return "AWS4-HMAC-SHA256 Credential=" + who.id + "/" + amz.substr(0, 8) + "/us-east-1/" +
               service + "/aws4_request, SignedHeaders=" + signed_headers +
               ", Signature=" + std::string(sig);
    };
    sigv4::request r;
    r.method = "POST";
    r.raw_path = "/";
    r.body = std::string_view(body);
    r.headers = {{"Host", "localhost"},
                 {"Content-Type", content_type},
                 {"X-Amz-Date", amz},
                 {"X-Amz-Target", target},
                 {"Authorization", auth(std::string(64, '0'))}};
    std::vector<std::pair<std::string, std::string>> headers{
        {"Content-Type", content_type}, {"X-Amz-Date", amz}, {"X-Amz-Target", target}};
    if (!who.token.empty()) {
        r.headers.emplace_back("X-Amz-Security-Token", who.token);
        headers.emplace_back("X-Amz-Security-Token", who.token);
    }
    const auto parsed = sigv4::parse(r, {.service = service}, now);
    if (!parsed) {
        return std::nullopt;
    }
    const auto sig =
        sigv4::compute_signature(*parsed, sigv4::derive_signing_key(who.secret, parsed->scope));
    return https_call(port, pki, http::verb::post, "/", {}, {}, auth(sig), headers, body);
}

/// The member's ports.
struct ports {
    std::uint16_t raft = 0;
    std::uint16_t metrics = 0;
    std::uint16_t iam = 0;
    std::uint16_t kinesis = 0;
    std::uint16_t kms = 0;
};

/// One kythira_node running `services` (of iam, kinesis and kms), the KMS
/// over its own SoftHSM2 token store, with its own test PKI.
class node {
public:
    explicit node(std::string services, std::vector<std::string> extra = {})
        : _services(std::move(services)), _extra(std::move(extra)) {
        _dir = raft::make_private_temp_directory(fs::temp_directory_path(), "kythira-node-kmsk-");
        const auto base = kythira::testing::free_port_block(5);
        _ports = {.raft = static_cast<std::uint16_t>(base),
                  .metrics = static_cast<std::uint16_t>(base + 1),
                  .iam = static_cast<std::uint16_t>(base + 2),
                  .kinesis = static_cast<std::uint16_t>(base + 3),
                  .kms = static_cast<std::uint16_t>(base + 4)};
        kythira::iam::testing::test_pki_options o;
        o.dir = _dir;
        o.nodes.push_back(make_id(1));
        pki = kythira::iam::testing::write_test_pki(o);

        fs::create_directories(_dir / "tokens");
        _conf = _dir / "softhsm2.conf";
        std::ofstream(_conf) << "directories.tokendir = " << (_dir / "tokens").string() << "\n"
                             << "objectstore.backend = file\nlog.level = ERROR\n";
        const std::string init = "SOFTHSM2_CONF=" + _conf.string() + " " + KYTHIRA_SOFTHSM2_UTIL +
                                 " --init-token --free --label kms --so-pin 5678 --pin 1234"
                                 " > /dev/null";
        BOOST_REQUIRE(std::system(init.c_str()) == 0);  // NOLINT(concurrency-mt-unsafe)
        raft::write_private_file(_dir / "pin", "1234\n");
    }

    node(const node&) = delete;
    auto operator=(const node&) -> node& = delete;
    node(node&&) = delete;
    auto operator=(node&&) -> node& = delete;

    ~node() {
        stop();
        if (std::getenv("KYTHIRA_NODE_KMS_TEST_KEEP") == nullptr) {
            std::error_code ec;
            fs::remove_all(_dir, ec);
        }
    }

    void start() {
        const auto dir = _dir / "node";
        fs::create_directories(dir);
        const auto raft = std::to_string(_ports.raft);
        const auto has = [this](std::string_view m) {
            return ("," + _services + ",").find("," + std::string(m) + ",") != std::string::npos;
        };
        std::vector<std::string> env{
            "KYTHIRA_SERVICES=" + _services,
            "KYTHIRA_NODE_ID=1",
            "KYTHIRA_NODE_DATA_DIR=" + dir.string(),
            "KYTHIRA_NODE_PEERS=1=127.0.0.1:" + raft,
            "KYTHIRA_NODE_RAFT_BIND=127.0.0.1",
            "KYTHIRA_NODE_RAFT_PORT=" + raft,
            "KYTHIRA_NODE_TLS_CERT=" + pki.node_cert(make_id(1)).string(),
            "KYTHIRA_NODE_TLS_KEY=" + pki.node_key(make_id(1)).string(),
            "KYTHIRA_NODE_TLS_CA=" + pki.ca.string(),
            "KYTHIRA_NODE_METRICS_BIND=127.0.0.1",
            "KYTHIRA_NODE_METRICS_PORT=" + std::to_string(_ports.metrics),
            "SOFTHSM2_CONF=" + _conf.string(),
            // No cloud here: without this the AWS SDK looks up its region from
            // EC2 instance metadata, which off EC2 can hold up module start until
            // connections to 169.254.169.254 time out.
            "AWS_EC2_METADATA_DISABLED=true",
            "PATH=/usr/bin:/bin",
        };
        if (has("iam")) {
            env.insert(
                env.end(),
                {"KYTHIRA_IAM_UNSEAL_KEY_FILE=" + pki.unseal.string(),
                 "KYTHIRA_IAM_HTTP_BIND=127.0.0.1",
                 "KYTHIRA_IAM_HTTP_PORT=" + std::to_string(_ports.iam),
                 "KYTHIRA_IAM_PEER_URLS=1=https://localhost:" + std::to_string(_ports.iam),
                 std::string("KYTHIRA_IAM_ADMIN_URI_SANS=") + kythira::iam::testing::k_admin_uri});
        }
        if (has("kinesis")) {
            env.insert(env.end(),
                       {"KINESIS_LISTEN=127.0.0.1:" + std::to_string(_ports.kinesis),
                        "KINESIS_REGION=us-east-1",
                        "KINESIS_FORWARD_SECRET=kythira-node-kms-test-forward-secret",
                        "KINESIS_PEER_GATEWAYS=1=localhost:" + std::to_string(_ports.kinesis),
                        // A short caller TTL, so a policy change shows within the test.
                        "KINESIS_KMS_CALLER_TTL_MS=1000"});
        }
        if (has("kms")) {
            env.insert(env.end(),
                       {"KYTHIRA_KMS_API_URLS=1=https://localhost:" + std::to_string(_ports.kms),
                        "KYTHIRA_KMS_API_LISTEN=127.0.0.1:" + std::to_string(_ports.kms),
                        "KYTHIRA_KMS_AUTH=iam",
                        std::string("KYTHIRA_KMS_PKCS11=") + KYTHIRA_SOFTHSM2_LIBRARY,
                        "KYTHIRA_KMS_PIN_FILE=" + (_dir / "pin").string(),
                        "KYTHIRA_KMS_JOB_INTERVAL_MS=200"});
        }
        env.insert(env.end(), _extra.begin(), _extra.end());
        const auto log = (dir / "node.log").string();
        const pid_t pid = ::fork();
        BOOST_REQUIRE(pid >= 0);
        if (pid == 0) {
            const int fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
            ::dup2(fd, 1);
            ::dup2(fd, 2);
            std::vector<char*> envp;
            envp.reserve(env.size() + 1);
            for (const auto& e : env) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                envp.push_back(const_cast<char*>(e.c_str()));
            }
            envp.push_back(nullptr);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            std::array<char*, 2> argv{const_cast<char*>(KYTHIRA_NODE_PATH), nullptr};
            ::execve(argv[0], argv.data(), envp.data());
            ::_exit(127);
        }
        _pid = pid;
    }

    void stop() {
        if (_pid <= 0) {
            return;
        }
        ::kill(_pid, SIGTERM);
        const auto deadline = std::chrono::steady_clock::now() + 30s;
        int status = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            if (::waitpid(_pid, &status, WNOHANG) == _pid) {
                _pid = -1;
                BOOST_TEST(WIFEXITED(status));
                return;
            }
            std::this_thread::sleep_for(20ms);
        }
        BOOST_ERROR("kythira_node " << _pid << " ignored SIGTERM; killing it");
        ::kill(_pid, SIGKILL);
        ::waitpid(_pid, &status, 0);
        _pid = -1;
    }

    /// Waits until IAM leads (or, without IAM, Kinesis answers).
    auto wait_ready(std::chrono::seconds timeout = 90s) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (_services.find("iam") == std::string::npos) {
                auto r = https_call(_ports.kinesis, pki, http::verb::get, "/healthz");
                if (r && r->status == 200) {
                    return true;
                }
            } else if (auto r = https_call(_ports.iam, pki, http::verb::get, "/healthz");
                       r && r->status == 200 &&
                       json_of(r->body).at("role").as_string() == "leader") {
                return true;
            }
            std::this_thread::sleep_for(200ms);
        }
        return false;
    }

    [[nodiscard]] auto log() const -> std::string {
        std::ifstream in(_dir / "node" / "node.log");
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    auto iam(const credentials& who, const std::string& body) -> std::optional<http_result> {
        return signed_call(_ports.iam, pki, who.id, who.secret, body + "&Version=2010-05-08", "iam",
                           who.token);
    }
    auto sts(const credentials& who, const std::string& body) -> std::optional<http_result> {
        return signed_call(_ports.iam, pki, who.id, who.secret, body + "&Version=2011-06-15", "sts",
                           who.token);
    }
    auto kinesis(const credentials& who, const std::string& action, const boost::json::object& body)
        -> std::optional<http_result> {
        return json_call(_ports.kinesis, pki, who, "kinesis", "Kinesis_20131202." + action,
                         "application/x-amz-json-1.1", boost::json::serialize(body));
    }
    auto kms(const credentials& who, const std::string& action, const boost::json::object& body)
        -> std::optional<http_result> {
        return json_call(_ports.kms, pki, who, "kms", "TrentService." + action,
                         "application/x-amz-json-1.1", boost::json::serialize(body));
    }

    /// A new account through IAM's admin route; its root key.
    auto make_account() -> credentials {
        auto r = https_call(_ports.iam, pki, http::verb::post, "/v1/admin/accounts",
                            pki.admin_cert.string(), pki.admin_key.string(), {},
                            {{"Content-Type", "application/json"}},
                            R"({"account_id":")" + std::string(k_account) + R"("})");
        BOOST_REQUIRE(r.has_value());
        BOOST_REQUIRE_MESSAGE(r->status == 201U, r->body);
        const auto o = json_of(r->body);
        // STS signs its session tokens with a key the admin makes.
        auto sts = https_call(_ports.iam, pki, http::verb::post, "/v1/admin/sts-keys/rotate",
                              pki.admin_cert.string(), pki.admin_key.string(), {},
                              {{"Content-Type", "application/json"}}, "{}");
        BOOST_REQUIRE(sts.has_value());
        BOOST_REQUIRE_MESSAGE(sts->status / 100 == 2U, sts->body);
        return {std::string(o.at("access_key_id").as_string()),
                std::string(o.at("secret_access_key").as_string()),
                {}};
    }

    /// One more variable for `start`.
    void add_env(std::string var) { _extra.push_back(std::move(var)); }

    [[nodiscard]] auto kms_port() const -> std::uint16_t { return _ports.kms; }
    [[nodiscard]] auto dir() const -> const fs::path& { return _dir; }

    kythira::iam::testing::test_pki_paths pki;

private:
    std::string _services;
    std::vector<std::string> _extra;
    fs::path _dir;
    fs::path _conf;
    ports _ports;
    pid_t _pid = -1;
};

/// Repeats `call` until it answers `status` with `marker` in the body:
/// IAM's and the KMS's state reach their applied logs a moment after the
/// write was acknowledged.
template<typename Call>
auto until_status(unsigned status, Call call, std::string_view marker = {},
                  std::chrono::seconds timeout = 30s) -> std::optional<http_result> {
    std::optional<http_result> r;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        r = call();
        if (r && r->status == status && r->body.find(marker) != std::string::npos) {
            return r;
        }
        std::this_thread::sleep_for(250ms);
    }
    return r;
}

auto ok(const std::optional<http_result>& r, std::string_view what) -> std::string {
    BOOST_REQUIRE_MESSAGE(r.has_value(), std::string(what) + ": no answer");
    BOOST_REQUIRE_MESSAGE(r->status == 200U,
                          std::string(what) + ": " + std::to_string(r->status) + " " + r->body);
    return r->body;
}

auto policy_of(const boost::json::array& statements) -> std::string {
    return boost::json::serialize(
        boost::json::object{{"Version", "2012-10-17"}, {"Statement", statements}});
}

auto role_arn(std::string_view name) -> std::string {
    return "arn:aws:iam::" + std::string(k_account) + ":role/" + std::string(name);
}

/// A role `name` that `trusted` may assume, with `identity` attached.
void make_role(node& n, const credentials& root, std::string_view name, const std::string& trusted,
               const std::string& identity) {
    const auto trust = policy_of(
        boost::json::array{boost::json::object{{"Effect", "Allow"},
                                               {"Principal", boost::json::object{{"AWS", trusted}}},
                                               {"Action", "sts:AssumeRole"}}});
    (void)ok(n.iam(root, "Action=CreateRole&RoleName=" + std::string(name) +
                             "&AssumeRolePolicyDocument=" + enc(trust)),
             "CreateRole");
    (void)ok(n.iam(root, "Action=PutRolePolicy&RoleName=" + std::string(name) +
                             "&PolicyName=identity&PolicyDocument=" + enc(identity)),
             "PutRolePolicy");
}

/// `who`'s session in role `name`.
auto assume(node& n, const credentials& who, std::string_view name) -> credentials {
    const auto r = until_status(200U, [&] {
        return n.sts(who, "Action=AssumeRole&RoleSessionName=test&RoleArn=" + enc(role_arn(name)));
    });
    const auto body = ok(r, "AssumeRole " + std::string(name));
    return {form_value(body, "AccessKeyId"), form_value(body, "SecretAccessKey"),
            form_value(body, "SessionToken")};
}

auto type_of(const http_result& r) -> std::string {
    const auto o = json_of(r.body);
    const auto* t = o.if_contains("__type");
    return t != nullptr && t->is_string() ? std::string(t->as_string()) : std::string();
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_key_policy_that_denies_a_role_denies_it_through_kinesis,
                     *boost::unit_test::timeout(600)) {
    node n("iam,kinesis,kms", {"KINESIS_AUTH=iam"});
    n.start();
    BOOST_REQUIRE_MESSAGE(n.wait_ready(), "IAM elected no leader:\n" + n.log());
    const auto root = n.make_account();

    // alice may assume the roles; each role may use any KMS key as far as
    // its own policy goes, and nothing in Kinesis: the stream's policy
    // grants that.
    (void)ok(n.iam(root, "Action=CreateUser&UserName=alice"), "CreateUser");
    const auto key = ok(n.iam(root, "Action=CreateAccessKey&UserName=alice"), "CreateAccessKey");
    const credentials alice{form_value(key, "AccessKeyId"), form_value(key, "SecretAccessKey"), {}};
    (void)ok(
        n.iam(root,
              "Action=PutUserPolicy&UserName=alice&PolicyName=assume&PolicyDocument=" +
                  enc(policy_of(boost::json::array{boost::json::object{
                      {"Effect", "Allow"}, {"Action", "sts:AssumeRole"}, {"Resource", "*"}}}))),
        "PutUserPolicy");
    const auto alice_arn = "arn:aws:iam::" + std::string(k_account) + ":user/alice";
    const auto kms_use = policy_of(boost::json::array{
        boost::json::object{{"Effect", "Allow"},
                            {"Action", boost::json::array{"kms:GenerateDataKey", "kms:Decrypt"}},
                            {"Resource", "*"}}});
    make_role(n, root, "writer", alice_arn, kms_use);
    make_role(n, root, "blocked", alice_arn, kms_use);

    // A customer managed key whose policy defers to IAM for the account
    // and denies the blocked role outright.
    const auto made =
        json_of(ok(until_status(200U, [&] { return n.kms(root, "CreateKey", {}); }), "CreateKey"));
    const std::string key_arn(made.at("KeyMetadata").as_object().at("Arn").as_string());
    const auto key_policy = policy_of(boost::json::array{
        boost::json::object{
            {"Sid", "account"},
            {"Effect", "Allow"},
            {"Principal",
             boost::json::object{{"AWS", "arn:aws:iam::" + std::string(k_account) + ":root"}}},
            {"Action", "kms:*"},
            {"Resource", "*"}},
        boost::json::object{{"Sid", "not-blocked"},
                            {"Effect", "Deny"},
                            {"Principal", boost::json::object{{"AWS", role_arn("blocked")}}},
                            {"Action", "kms:*"},
                            {"Resource", "*"}}});
    (void)ok(n.kms(root, "PutKeyPolicy",
                   {{"KeyId", key_arn}, {"PolicyName", "default"}, {"Policy", key_policy}}),
             "PutKeyPolicy");

    // The stream, its policy letting both roles write and read, and
    // encryption under the key.
    (void)ok(n.kinesis(root, "CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}}),
             "CreateStream");
    const auto stream_arn =
        "arn:aws:kinesis:us-east-1:" + std::string(k_account) + ":stream/orders";
    (void)ok(
        until_status(
            200U,
            [&] { return n.kinesis(root, "DescribeStreamSummary", {{"StreamName", "orders"}}); },
            "ACTIVE"),
        "DescribeStreamSummary");
    const auto stream_policy = policy_of(boost::json::array{boost::json::object{
        {"Effect", "Allow"},
        {"Principal",
         boost::json::object{
             {"AWS", boost::json::array{role_arn("writer").c_str(), role_arn("blocked").c_str()}}}},
        {"Action", boost::json::array{"kinesis:PutRecord", "kinesis:GetShardIterator",
                                      "kinesis:GetRecords", "kinesis:DescribeStreamSummary"}},
        {"Resource", stream_arn}}});
    (void)ok(n.kinesis(root, "PutResourcePolicy",
                       {{"ResourceARN", stream_arn}, {"Policy", stream_policy}}),
             "PutResourcePolicy");
    (void)ok(n.kinesis(root, "StartStreamEncryption",
                       {{"StreamName", "orders"}, {"EncryptionType", "KMS"}, {"KeyId", key_arn}}),
             "StartStreamEncryption");

    const auto writer = assume(n, alice, "writer");
    const auto blocked = assume(n, alice, "blocked");
    const boost::json::object put{
        {"StreamName", "orders"}, {"PartitionKey", "pk"}, {"Data", "c2VjcmV0"}};

    // The writer's record is sealed under the stream's key.
    const auto written =
        json_of(ok(until_status(200U, [&] { return n.kinesis(writer, "PutRecord", put); }),
                   "PutRecord as writer"));
    BOOST_TEST(written.at("EncryptionType").as_string() == "KMS");

    // The blocked role passes the stream's policy and is refused by the
    // key's, although this node holds the stream's data key.
    const auto refused = n.kinesis(blocked, "PutRecord", put);
    BOOST_REQUIRE(refused.has_value());
    BOOST_TEST(refused->status == 400U, refused->body);
    BOOST_TEST(type_of(*refused) == "KMSAccessDeniedException", refused->body);
    // It may describe the stream: that needs no key.
    (void)ok(n.kinesis(blocked, "DescribeStreamSummary", {{"StreamName", "orders"}}),
             "DescribeStreamSummary as blocked");

    // Reading: the writer decrypts, the blocked role is refused.
    const auto iterator = [&](const credentials& who) {
        const auto it = json_of(ok(n.kinesis(who, "GetShardIterator",
                                             {{"StreamName", "orders"},
                                              {"ShardId", "shardId-000000000000"},
                                              {"ShardIteratorType", "TRIM_HORIZON"}}),
                                   "GetShardIterator"));
        return std::string(it.at("ShardIterator").as_string());
    };
    const auto read =
        json_of(ok(n.kinesis(writer, "GetRecords", {{"ShardIterator", iterator(writer)}}),
                   "GetRecords as writer"));
    const auto& records = read.at("Records").as_array();
    BOOST_REQUIRE_EQUAL(records.size(), 1U);
    BOOST_TEST(records.at(0).as_object().at("Data").as_string() == "c2VjcmV0");
    const auto denied_read =
        n.kinesis(blocked, "GetRecords", {{"ShardIterator", iterator(blocked)}});
    BOOST_REQUIRE(denied_read.has_value());
    BOOST_TEST(type_of(*denied_read) == "KMSAccessDeniedException", denied_read->body);

    // Lifting the deny lets the blocked role in once its last answer has
    // expired (KINESIS_KMS_CALLER_TTL_MS).
    const auto open_policy = policy_of(boost::json::array{boost::json::object{
        {"Sid", "account"},
        {"Effect", "Allow"},
        {"Principal",
         boost::json::object{{"AWS", "arn:aws:iam::" + std::string(k_account) + ":root"}}},
        {"Action", "kms:*"},
        {"Resource", "*"}}});
    (void)ok(n.kms(root, "PutKeyPolicy",
                   {{"KeyId", key_arn}, {"PolicyName", "default"}, {"Policy", open_policy}}),
             "PutKeyPolicy (open)");
    (void)ok(until_status(200U, [&] { return n.kinesis(blocked, "PutRecord", put); }),
             "PutRecord as blocked once allowed");

    // And the KMS recorded the calls Kinesis made for its callers.
    const auto log = n.log();
    BOOST_TEST(log.find("\"invokedBy\":\"kinesis.amazonaws.com\"") != std::string::npos);
    BOOST_TEST(log.find("assumed-role/blocked/") != std::string::npos);
}

// Stand-alone (Requirement 11.1): Kinesis on one cluster reaches the KMS
// on another over HTTPS (KINESIS_KMS_ENDPOINT), signing as a principal the
// KMS trusts as a service (KYTHIRA_KMS_TRUSTED_SERVICES) and naming each
// Kinesis caller. Kinesis authenticates its callers with static keys here,
// so the key policy names them; it allows one and denies the other.
BOOST_AUTO_TEST_CASE(kinesis_on_another_cluster_reaches_the_kms_over_https,
                     *boost::unit_test::timeout(600)) {
    const auto gateway_arn = "arn:aws:iam::" + std::string(k_account) + ":user/kinesis-gw";
    node k("iam,kms", {"KYTHIRA_KMS_TRUSTED_SERVICES=" + gateway_arn});
    k.start();
    BOOST_REQUIRE_MESSAGE(k.wait_ready(), "IAM elected no leader:\n" + k.log());
    const auto root = k.make_account();

    // The gateway's own identity in the KMS's account.
    (void)ok(k.iam(root, "Action=CreateUser&UserName=kinesis-gw"), "CreateUser");
    const auto gw_key =
        ok(k.iam(root, "Action=CreateAccessKey&UserName=kinesis-gw"), "CreateAccessKey");

    const auto user = [](std::string_view name) {
        return "arn:aws:iam::" + std::string(k_account) + ":user/" + std::string(name);
    };
    const auto made =
        json_of(ok(until_status(200U, [&] { return k.kms(root, "CreateKey", {}); }), "CreateKey"));
    const std::string key_arn(made.at("KeyMetadata").as_object().at("Arn").as_string());
    const auto key_policy = policy_of(boost::json::array{
        boost::json::object{
            {"Sid", "users"},
            {"Effect", "Allow"},
            {"Principal",
             boost::json::object{
                 {"AWS", boost::json::array{("arn:aws:iam::" + std::string(k_account) + ":root"),
                                            user("admin"), user("writer")}}}},
            {"Action", "kms:*"},
            {"Resource", "*"}},
        boost::json::object{{"Sid", "not-blocked"},
                            {"Effect", "Deny"},
                            {"Principal", boost::json::object{{"AWS", user("blocked")}}},
                            {"Action", "kms:*"},
                            {"Resource", "*"}}});
    (void)ok(k.kms(root, "PutKeyPolicy",
                   {{"KeyId", key_arn}, {"PolicyName", "default"}, {"Policy", key_policy}}),
             "PutKeyPolicy");

    // The Kinesis cluster: no KMS of its own, static callers.
    node g("kinesis", {"KINESIS_AUTH=static", "KINESIS_KMS=kythira",
                       "KINESIS_KMS_ENDPOINT=localhost:" + std::to_string(k.kms_port()),
                       "KINESIS_KMS_CA=" + k.pki.ca.string(),
                       "AWS_ACCESS_KEY_ID=" + form_value(gw_key, "AccessKeyId"),
                       "AWS_SECRET_ACCESS_KEY=" + form_value(gw_key, "SecretAccessKey")});
    {
        const auto keys = g.dir() / "kinesis-keys";
        raft::write_private_file(keys, "AKIDADMIN00000000001 admin-secret " +
                                           std::string(k_account) +
                                           " admin admin\n"
                                           "AKIDWRITER0000000001 writer-secret " +
                                           std::string(k_account) +
                                           " writer read-write\n"
                                           "AKIDBLOCKED000000001 blocked-secret " +
                                           std::string(k_account) + " blocked read-write\n");
        g.add_env("KINESIS_STATIC_KEYS_FILE=" + keys.string());
    }
    g.start();
    BOOST_REQUIRE_MESSAGE(g.wait_ready(), "Kinesis did not start:\n" + g.log());
    const credentials admin{"AKIDADMIN00000000001", "admin-secret", {}};
    const credentials writer{"AKIDWRITER0000000001", "writer-secret", {}};
    const credentials blocked{"AKIDBLOCKED000000001", "blocked-secret", {}};

    (void)ok(until_status(200U,
                          [&] {
                              return g.kinesis(admin, "CreateStream",
                                               {{"StreamName", "orders"}, {"ShardCount", 1}});
                          }),
             "CreateStream");
    (void)ok(
        until_status(
            200U,
            [&] { return g.kinesis(admin, "DescribeStreamSummary", {{"StreamName", "orders"}}); },
            "ACTIVE"),
        "DescribeStreamSummary");
    (void)ok(g.kinesis(admin, "StartStreamEncryption",
                       {{"StreamName", "orders"}, {"EncryptionType", "KMS"}, {"KeyId", key_arn}}),
             "StartStreamEncryption");

    const boost::json::object put{
        {"StreamName", "orders"}, {"PartitionKey", "pk"}, {"Data", "c2VjcmV0"}};
    const auto written = json_of(ok(g.kinesis(writer, "PutRecord", put), "PutRecord as writer"));
    BOOST_TEST(written.at("EncryptionType").as_string() == "KMS");
    const auto refused = g.kinesis(blocked, "PutRecord", put);
    BOOST_REQUIRE(refused.has_value());
    BOOST_TEST(type_of(*refused) == "KMSAccessDeniedException", refused->body);

    const auto it = json_of(ok(g.kinesis(writer, "GetShardIterator",
                                         {{"StreamName", "orders"},
                                          {"ShardId", "shardId-000000000000"},
                                          {"ShardIteratorType", "TRIM_HORIZON"}}),
                               "GetShardIterator"));
    const auto read =
        json_of(ok(g.kinesis(writer, "GetRecords", {{"ShardIterator", it.at("ShardIterator")}}),
                   "GetRecords as writer"));
    BOOST_REQUIRE_EQUAL(read.at("Records").as_array().size(), 1U);
    BOOST_TEST(read.at("Records").as_array().at(0).as_object().at("Data").as_string() ==
               "c2VjcmV0");

    // The KMS's record names the Kinesis caller, not the gateway.
    const auto log = k.log();
    BOOST_TEST(log.find(user("blocked")) != std::string::npos);
    BOOST_TEST(log.find("\"invokedBy\":\"kinesis.amazonaws.com\"") != std::string::npos);
}
