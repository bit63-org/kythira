// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Every module together (.kiro/specs/service-colocation/ task 11,
// Requirement 10.1): three kythira_node processes on loopback, each running
// every service the binary has compiled in on one mutual-TLS Raft listener,
// and each service's own smoke test driven against that one cluster:
//
//   * iam       an account through the admin route, then a user through
//               the Query API, on the leader;
//   * kinesis   CreateStream, PutRecord and GetRecords, signed with the
//               account's key and authorized by the co-located IAM module;
//   * dynamodb  CreateTable, PutItem and a strongly consistent GetItem, the
//               same way;
//   * redis     SET on whichever node takes the write, then GET;
//   * ledger    a ledger, a table and a document over its HTTPS API (Ion
//               text bodies) with an admin client certificate, read back;
//   * hsm       every node's operator API answers the operator (a fresh,
//               sealed HSM), the peer routes answer a member's certificate
//               and refuse the operator's, and an outsider gets nothing;
//               then init on one node, two of three shares on each node
//               unseal it, a token is created on a follower, and one seal
//               reaches every node.
//
// The services come from `kythira_node --help`, so a build with only some
// modules runs only their checks (ci.yml's full builds have no ledger;
// composite-node.yml's all-modules leg has every one). IAM is required: it
// issues the test PKI and authorizes Kinesis and DynamoDB.

#define BOOST_TEST_MODULE kythira_node_cluster_test

#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include "iam_node_test_support.hpp"

#ifndef KYTHIRA_NODE_PATH
#error "KYTHIRA_NODE_PATH must be defined"
#endif

#include <raft/private_file.hpp>

#include <boost/json.hpp>

#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

namespace {

using namespace iam_node_testing;
namespace sigv4 = kythira::sigv4;

constexpr const char* k_account = "111122223333";

/// The services `kythira_node --help` lists as compiled in.
auto compiled_in() -> std::set<std::string> {
    const auto help = run_capture({KYTHIRA_NODE_PATH, "--help"}).second;
    std::set<std::string> out;
    const auto at = help.find("Compiled-in services");
    if (at == std::string::npos) {
        return out;
    }
    std::size_t pos = help.find('\n', at);
    while (pos != std::string::npos && pos + 1 < help.size()) {
        const auto end = help.find('\n', pos + 1);
        const auto line = help.substr(pos + 1, end == std::string::npos ? end : end - pos - 1);
        // "  <name>  (<prefix>*)"
        if (line.size() > 2 && line.starts_with("  ") && line[2] != ' ') {
            out.insert(line.substr(2, line.find(' ', 2) - 2));
        }
        pos = end;
    }
    return out;
}

struct node_proc {
    int n = 0;
    std::uint16_t raft = 0;
    std::uint16_t metrics = 0;
    std::uint16_t iam = 0;
    std::uint16_t kinesis = 0;
    std::uint16_t dynamodb = 0;
    std::uint16_t redis = 0;
    std::uint16_t ledger = 0;
    std::uint16_t hsm = 0;
    pid_t pid = -1;
};

class node_cluster {
public:
    explicit node_cluster(std::set<std::string> services) : services(std::move(services)) {
        _dir = raft::make_private_temp_directory(fs::temp_directory_path(), "kythira-node-all-");
        const auto base = kythira::testing::free_port_block(24);
        for (int i = 0; i < 3; ++i) {
            node_proc p;
            p.n = i + 1;
            const auto b = static_cast<std::uint16_t>(base + 8 * i);
            p.raft = b;
            p.metrics = b + 1;
            p.iam = b + 2;
            p.kinesis = b + 3;
            p.dynamodb = b + 4;
            p.redis = b + 5;
            p.ledger = b + 6;
            p.hsm = b + 7;
            nodes.push_back(p);
        }
        kythira::iam::testing::test_pki_options o;
        o.dir = _dir;
        for (const auto& p : nodes) {
            o.nodes.push_back(make_id(p.n));
        }
        pki = kythira::iam::testing::write_test_pki(o);
        _roles = _dir / "ledger-roles.txt";
        raft::write_private_file(_roles.string(),
                                 std::string(kythira::iam::testing::k_admin_uri) + " * admin\n");
    }

    node_cluster(const node_cluster&) = delete;
    auto operator=(const node_cluster&) -> node_cluster& = delete;
    node_cluster(node_cluster&&) = delete;
    auto operator=(node_cluster&&) -> node_cluster& = delete;

    ~node_cluster() {
        for (auto& p : nodes) {
            stop(p);
        }
        if (std::getenv("IAM_NODE_TEST_KEEP") == nullptr) {
            std::error_code ec;
            fs::remove_all(_dir, ec);
        }
    }

    [[nodiscard]] auto has(const std::string& s) const -> bool { return services.contains(s); }

    /// Every node's Raft peer identity, comma separated.
    [[nodiscard]] auto peer_identities() const -> std::string {
        std::string out;
        for (const auto& q : nodes) {
            out += (out.empty() ? "" : ",") + raft::testing::peer_identity_name(make_id(q.n));
        }
        return out;
    }

    void start(node_proc& p) {
        const auto map = [&](const std::string& prefix, auto port_of) {
            std::string out;
            for (const auto& q : nodes) {
                out += (out.empty() ? "" : ",") + std::to_string(q.n) + "=" + prefix +
                       std::to_string(port_of(q));
            }
            return out;
        };
        std::string list;
        for (const auto& s : services) {
            list += (list.empty() ? "" : ",") + s;
        }
        const auto dir = _dir / ("node-" + std::to_string(p.n));
        fs::create_directories(dir);
        std::vector<std::string> env{
            "KYTHIRA_SERVICES=" + list,
            "KYTHIRA_NODE_ID=" + std::to_string(p.n),
            "KYTHIRA_NODE_DATA_DIR=" + dir.string(),
            "KYTHIRA_NODE_PEERS=" + map("127.0.0.1:", [](const auto& q) { return q.raft; }),
            "KYTHIRA_NODE_RAFT_BIND=127.0.0.1",
            "KYTHIRA_NODE_RAFT_PORT=" + std::to_string(p.raft),
            "KYTHIRA_NODE_TLS_CERT=" + pki.node_cert(make_id(p.n)).string(),
            "KYTHIRA_NODE_TLS_KEY=" + pki.node_key(make_id(p.n)).string(),
            "KYTHIRA_NODE_TLS_CA=" + pki.ca.string(),
            "KYTHIRA_NODE_METRICS_BIND=127.0.0.1",
            "KYTHIRA_NODE_METRICS_PORT=" + std::to_string(p.metrics),
            // IAM
            "KYTHIRA_IAM_UNSEAL_KEY_FILE=" + pki.unseal.string(),
            "KYTHIRA_IAM_HTTP_BIND=127.0.0.1",
            "KYTHIRA_IAM_HTTP_PORT=" + std::to_string(p.iam),
            "KYTHIRA_IAM_PEER_URLS=" +
                map("https://localhost:", [](const auto& q) { return q.iam; }),
            std::string("KYTHIRA_IAM_ADMIN_URI_SANS=") + kythira::iam::testing::k_admin_uri,
            // Kinesis
            "KINESIS_LISTEN=127.0.0.1:" + std::to_string(p.kinesis),
            "KINESIS_AUTH=iam",
            "KINESIS_REGION=us-east-1",
            "KINESIS_FORWARD_SECRET=kythira-node-cluster-test-kinesis",
            "KINESIS_PEER_GATEWAYS=" + map("localhost:", [](const auto& q) { return q.kinesis; }),
            // DynamoDB
            "KYTHIRA_DYNAMODB_BIND=127.0.0.1",
            "KYTHIRA_DYNAMODB_PORT=" + std::to_string(p.dynamodb),
            "KYTHIRA_DYNAMODB_AUTH=iam",
            std::string("KYTHIRA_DYNAMODB_ACCOUNT_ID=") + k_account,
            "KYTHIRA_DYNAMODB_FORWARD_SECRET=kythira-node-cluster-test-dynamodb",
            "KYTHIRA_DYNAMODB_PEER_GATEWAYS=" +
                map("localhost:", [](const auto& q) { return q.dynamodb; }),
            "KYTHIRA_DYNAMODB_DISK_FLOOR_BYTES=0",
            "KYTHIRA_DYNAMODB_COMPAT=throttling=off",
            // Redis: plaintext RESP for the smoke test's own client, no
            // ACL, memory storage.
            "KYTHIRA_REDIS_LISTEN=127.0.0.1:" + std::to_string(p.redis),
            "KYTHIRA_REDIS_ALLOW_ANONYMOUS=1",
            "KYTHIRA_CACHE_PERSISTENCE=memory",
            // Ledger: HTTPS with the test CA's client certificates, the
            // IAM admin certificate as the ledger's admin.
            "KYTHIRA_LEDGER_API_LISTEN=127.0.0.1:" + std::to_string(p.ledger),
            "KYTHIRA_LEDGER_API_URLS=" +
                map("https://localhost:", [](const auto& q) { return q.ledger; }),
            "KYTHIRA_LEDGER_TLS_CERT=" + pki.node_cert(make_id(p.n)).string(),
            "KYTHIRA_LEDGER_TLS_KEY=" + pki.node_key(make_id(p.n)).string(),
            "KYTHIRA_LEDGER_CLIENT_CA=" + pki.ca.string(),
            "KYTHIRA_LEDGER_ROLES_FILE=" + _roles.string(),
            // The HSM on the node's certificate (its TLS defaults), the
            // members named by their Raft peer identities, and the IAM
            // admin certificate as its operator. CI runners cap
            // RLIMIT_MEMLOCK, so key memory may stay unlocked here.
            "KYTHIRA_HSM_API_LISTEN=127.0.0.1:" + std::to_string(p.hsm),
            "KYTHIRA_HSM_API_URLS=" +
                map("https://localhost:", [](const auto& q) { return q.hsm; }),
            "KYTHIRA_HSM_PEER_IDENTITIES=" + peer_identities(),
            std::string("KYTHIRA_HSM_OPERATORS=") + kythira::iam::testing::k_admin_uri,
            "KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY=true",
            "PATH=/usr/bin:/bin",
        };
        const auto log = (dir / "node.log").string();
        const pid_t pid = ::fork();
        BOOST_REQUIRE(pid >= 0);
        if (pid == 0) {
            const int fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
            ::dup2(fd, 1);
            ::dup2(fd, 2);
            std::vector<char*> envp;
            for (const auto& e : env) {
                envp.push_back(const_cast<char*>(e.c_str()));
            }
            envp.push_back(nullptr);
            char* argv[] = {const_cast<char*>(KYTHIRA_NODE_PATH), nullptr};
            ::execve(argv[0], argv, envp.data());
            ::_exit(127);
        }
        p.pid = pid;
    }

    static void stop(node_proc& p) {
        if (p.pid <= 0) {
            return;
        }
        ::kill(p.pid, SIGTERM);
        const auto deadline = std::chrono::steady_clock::now() + 30s;
        int status = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            if (::waitpid(p.pid, &status, WNOHANG) == p.pid) {
                p.pid = -1;
                BOOST_TEST(WIFEXITED(status));
                return;
            }
            std::this_thread::sleep_for(20ms);
        }
        BOOST_ERROR("kythira_node " << p.pid << " ignored SIGTERM; killing it");
        ::kill(p.pid, SIGKILL);
        ::waitpid(p.pid, &status, 0);
        p.pid = -1;
    }

    /// The node IAM's group elected, once one reports itself leader.
    auto wait_iam_leader(std::chrono::seconds timeout = 120s) -> node_proc* {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            for (auto& p : nodes) {
                auto r = https_call(p.iam, pki, http::verb::get, "/healthz");
                if (r && r->status == 200 && json_of(r->body).contains("role") &&
                    json_of(r->body).at("role").as_string() == "leader") {
                    return &p;
                }
            }
            std::this_thread::sleep_for(200ms);
        }
        return nullptr;
    }

    void dump_logs() const {
        for (const auto& p : nodes) {
            const auto log = slurp(_dir / ("node-" + std::to_string(p.n)) / "node.log");
            BOOST_TEST_MESSAGE("---- node "
                               << p.n << " ----\n"
                               << log.substr(log.size() > 6000 ? log.size() - 6000 : 0));
        }
    }

    std::set<std::string> services;
    std::vector<node_proc> nodes;
    kythira::iam::testing::test_pki_paths pki;

private:
    fs::path _dir;
    fs::path _roles;
};

/// A SigV4-signed AWS JSON call (`<target_prefix>.<action>`) to `service`.
auto aws_json_call(std::uint16_t port, const kythira::iam::testing::test_pki_paths& pki,
                   const std::string& key_id, const std::string& secret, const std::string& service,
                   const std::string& content_type, const std::string& target,
                   const std::string& body) -> std::optional<http_result> {
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    const auto amz = sigv4::detail::format_amz_date(now);
    const std::string signed_headers = "content-type;host;x-amz-date;x-amz-target";
    const auto auth = [&](std::string_view sig) {
        return "AWS4-HMAC-SHA256 Credential=" + key_id + "/" + amz.substr(0, 8) + "/us-east-1/" +
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
    const auto parsed = sigv4::parse(r, {.service = service}, now);
    if (!parsed) {
        return std::nullopt;
    }
    const auto sig =
        sigv4::compute_signature(*parsed, sigv4::derive_signing_key(secret, parsed->scope));
    return https_call(
        port, pki, http::verb::post, "/", {}, {}, auth(sig),
        {{"Content-Type", content_type}, {"X-Amz-Date", amz}, {"X-Amz-Target", target}}, body);
}

/// `call` until it answers `status` (and `marker` in the body), or the
/// budget passes; the last answer either way.
auto until(unsigned status, const std::function<std::optional<http_result>()>& call,
           std::string_view marker = {}, std::chrono::seconds budget = 60s)
    -> std::optional<http_result> {
    std::optional<http_result> r;
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        r = call();
        if (r && r->status == status && r->body.find(marker) != std::string::npos) {
            return r;
        }
        std::this_thread::sleep_for(250ms);
    }
    return r;
}

/// One RESP command on a fresh plaintext connection; the raw reply, or ""
/// if the node did not answer.
auto resp(std::uint16_t port, const std::vector<std::string>& args) -> std::string {
    try {
        asio::io_context ioc;
        beast::tcp_stream s(ioc);
        s.expires_after(5s);
        s.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));
        std::string cmd = "*" + std::to_string(args.size()) + "\r\n";
        for (const auto& a : args) {
            cmd += "$" + std::to_string(a.size()) + "\r\n" + a + "\r\n";
        }
        asio::write(s, asio::buffer(cmd));
        std::string reply;
        std::array<char, 512> buf{};
        // A simple string, an error, or a bulk string: enough for SET/GET.
        while (true) {
            const auto n = s.socket().read_some(asio::buffer(buf));
            reply.append(buf.data(), n);
            if (reply.size() >= 3 && reply.ends_with("\r\n")) {
                if (reply[0] != '$') {
                    return reply;
                }
                const auto len = std::stol(reply.substr(1, reply.find("\r\n") - 1));
                const auto head = reply.find("\r\n") + 2;
                if (len < 0 || reply.size() >= head + static_cast<std::size_t>(len) + 2) {
                    return reply;
                }
            }
        }
    } catch (const std::exception&) {
        return {};
    }
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_compiled_in_service_on_one_cluster, *boost::unit_test::timeout(900)) {
    const auto services = compiled_in();
    BOOST_TEST_MESSAGE("compiled in:" << [&] {
        std::string s;
        for (const auto& x : services) {
            s += " " + x;
        }
        return s;
    }());
    BOOST_REQUIRE_MESSAGE(services.contains("iam"), "the cluster test needs the IAM module");
    node_cluster c(services);
    for (auto& p : c.nodes) {
        c.start(p);
    }
    struct dump_on_failure {
        node_cluster& c;
        ~dump_on_failure() {
            const auto& r = boost::unit_test::results_collector.results(
                boost::unit_test::framework::current_test_case().p_id);
            if (!r.passed()) {
                c.dump_logs();
            }
        }
    } dump{c};

    // iam: an account, and a user through the Query API.
    auto* leader = c.wait_iam_leader();
    BOOST_REQUIRE_MESSAGE(leader != nullptr, "IAM elected no leader");
    auto created = https_call(leader->iam, c.pki, http::verb::post, "/v1/admin/accounts",
                              c.pki.admin_cert.string(), c.pki.admin_key.string(), {},
                              {{"Content-Type", "application/json"}},
                              std::string(R"({"account_id":")") + k_account + R"("})");
    BOOST_REQUIRE(created.has_value());
    BOOST_REQUIRE_EQUAL(created->status, 201U);
    const auto account = json_of(created->body);
    const std::string key(account.at("access_key_id").as_string());
    const std::string secret(account.at("secret_access_key").as_string());
    auto user = until(200U, [&] {
        return signed_iam_call(leader->iam, c.pki, key, secret,
                               "Action=CreateUser&UserName=smoke&Version=2010-05-08");
    });
    BOOST_REQUIRE(user.has_value());
    BOOST_TEST(user->status == 200U, user->body);
    BOOST_TEST_MESSAGE("iam: account and user created");

    if (c.has("kinesis")) {
        BOOST_TEST_CHECKPOINT("kinesis");
        const auto call = [&](const node_proc& p, const std::string& action,
                              const std::string& body) {
            return aws_json_call(p.kinesis, c.pki, key, secret, "kinesis",
                                 "application/x-amz-json-1.1", "Kinesis_20131202." + action, body);
        };
        auto made = until(200U, [&] {
            return call(c.nodes[0], "CreateStream", R"({"StreamName":"smoke","ShardCount":1})");
        });
        BOOST_REQUIRE(made.has_value());
        BOOST_TEST(made->status == 200U, made->body);
        BOOST_TEST(until(
                       200U,
                       [&] {
                           return call(c.nodes[1], "DescribeStreamSummary",
                                       R"({"StreamName":"smoke"})");
                       },
                       "ACTIVE")
                       .has_value());
        auto put = until(200U, [&] {
            return call(c.nodes[1], "PutRecord",
                        R"({"StreamName":"smoke","PartitionKey":"k","Data":"aGVsbG8="})");
        });
        BOOST_REQUIRE(put.has_value());
        BOOST_TEST(put->status == 200U, put->body);
        const auto shard = std::string(json_of(put->body).at("ShardId").as_string());
        auto it = until(200U, [&] {
            return call(c.nodes[2], "GetShardIterator",
                        R"({"StreamName":"smoke","ShardId":")" + shard +
                            R"(","ShardIteratorType":"TRIM_HORIZON"})");
        });
        BOOST_REQUIRE(it.has_value() && it->status == 200U);
        const auto iterator = std::string(json_of(it->body).at("ShardIterator").as_string());
        auto got = until(
            200U,
            [&] {
                return call(c.nodes[2], "GetRecords", R"({"ShardIterator":")" + iterator + R"("})");
            },
            "aGVsbG8=");
        BOOST_REQUIRE(got.has_value());
        BOOST_TEST(got->body.find("aGVsbG8=") != std::string::npos, got->body);
        BOOST_TEST_MESSAGE("kinesis: a record written on node 2 read back on node 3");
    }

    if (c.has("dynamodb")) {
        BOOST_TEST_CHECKPOINT("dynamodb");
        const auto call = [&](const node_proc& p, const std::string& action,
                              const std::string& body) {
            return aws_json_call(p.dynamodb, c.pki, key, secret, "dynamodb",
                                 "application/x-amz-json-1.0", "DynamoDB_20120810." + action, body);
        };
        auto made = until(200U, [&] {
            return call(c.nodes[0], "CreateTable",
                        R"({"TableName":"smoke","BillingMode":"PAY_PER_REQUEST",)"
                        R"("KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],)"
                        R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}]})");
        });
        BOOST_REQUIRE(made.has_value());
        BOOST_TEST(made->status == 200U, made->body);
        BOOST_TEST(
            until(
                200U, [&] { return call(c.nodes[1], "DescribeTable", R"({"TableName":"smoke"})"); },
                R"("TableStatus":"ACTIVE")")
                .has_value());
        auto put = until(200U, [&] {
            return call(c.nodes[1], "PutItem",
                        R"({"TableName":"smoke","Item":{"pk":{"S":"a"},"v":{"S":"hello"}}})");
        });
        BOOST_REQUIRE(put.has_value());
        BOOST_TEST(put->status == 200U, put->body);
        auto got = until(
            200U,
            [&] {
                return call(
                    c.nodes[2], "GetItem",
                    R"({"TableName":"smoke","Key":{"pk":{"S":"a"}},"ConsistentRead":true})");
            },
            "hello");
        BOOST_REQUIRE(got.has_value());
        BOOST_TEST(got->body.find("hello") != std::string::npos, got->body);
        BOOST_TEST_MESSAGE("dynamodb: an item written on node 2 read back on node 3");
    }

    if (c.has("redis")) {
        BOOST_TEST_CHECKPOINT("redis");
        // SET on whichever node takes it (a follower may refuse or
        // forward), then GET there.
        std::optional<std::uint16_t> wrote;
        const auto deadline = std::chrono::steady_clock::now() + 60s;
        while (!wrote && std::chrono::steady_clock::now() < deadline) {
            for (const auto& p : c.nodes) {
                if (resp(p.redis, {"SET", "smoke", "hello"}).starts_with("+OK")) {
                    wrote = p.redis;
                    break;
                }
            }
            std::this_thread::sleep_for(250ms);
        }
        BOOST_REQUIRE_MESSAGE(wrote.has_value(), "no Redis node took the SET");
        const auto got = resp(*wrote, {"GET", "smoke"});
        BOOST_TEST(got == "$5\r\nhello\r\n", got);
        BOOST_TEST_MESSAGE("redis: SET and GET on port " << *wrote);
    }

    if (c.has("ledger")) {
        BOOST_TEST_CHECKPOINT("ledger");
        // Ion text bodies (application/ion), JSON answers; a follower
        // answers 503 not_leader, so each call tries every node until one
        // succeeds or answers `ok_code` (an earlier attempt landed).
        const auto call = [&](http::verb verb, const std::string& target, const std::string& body,
                              std::string_view ok_code) {
            return until(200U, [&]() -> std::optional<http_result> {
                std::optional<http_result> last;
                for (const auto& p : c.nodes) {
                    last = https_call(p.ledger, c.pki, verb, target, c.pki.admin_cert.string(),
                                      c.pki.admin_key.string(), {},
                                      {{"Content-Type", "application/ion"}}, body);
                    if (last && !ok_code.empty() && last->body.find(ok_code) != std::string::npos) {
                        last->status = 200;
                    }
                    if (last && last->status == 200) {
                        return last;
                    }
                }
                return last;
            });
        };
        const std::string id = std::string(22 - 5, '0') + "smoke";
        for (const auto& [verb, target, body, ok] :
             std::vector<std::tuple<http::verb, std::string, std::string, std::string>>{
                 {http::verb::post, "/v1/ledgers", R"({name: "smoke", deletionProtection: false})",
                  "ledger_exists"},
                 {http::verb::post, "/v1/ledgers/smoke/execute",
                  R"({statements: [{op: create_table, table: "t"}]})", "table_exists"},
                 {http::verb::post, "/v1/ledgers/smoke/execute",
                  R"({statements: [{op: insert, table: "t", id: ")" + id +
                      R"(", value: {v: "hello"}}]})",
                  "document_exists"},
             }) {
            auto r = call(verb, target, body, ok);
            BOOST_REQUIRE(r.has_value());
            BOOST_TEST(r->status == 200U, target << ": " << r->body);
        }
        auto got = call(http::verb::get, "/v1/ledgers/smoke/tables/t/documents/" + id, {}, {});
        BOOST_REQUIRE(got.has_value());
        BOOST_TEST(got->status == 200U, got->body);
        BOOST_TEST(got->body.find("hello") != std::string::npos, got->body);
        BOOST_TEST_MESSAGE("ledger: a document inserted and read back");
    }

    if (c.has("hsm")) {
        BOOST_TEST_CHECKPOINT("hsm");
        // A fresh HSM: initialized and unsealed by an operator later (its
        // own tests cover that). Each node's listener is up and answers
        // the operator.
        for (const auto& p : c.nodes) {
            auto st = until(200U, [&] {
                return https_call(p.hsm, c.pki, http::verb::get, "/v1/status",
                                  c.pki.admin_cert.string(), c.pki.admin_key.string());
            });
            BOOST_REQUIRE(st.has_value());
            BOOST_TEST(st->status == 200U, st->body);
            const auto status = json_of(st->body);
            BOOST_TEST(status.at("initialized").as_bool() == false, st->body);
            BOOST_TEST(status.at("sealed").as_bool() == true, st->body);
            // An outsider's certificate is no operator.
            auto outsider = https_call(p.hsm, c.pki, http::verb::get, "/v1/status",
                                       c.pki.outsider_cert.string(), c.pki.outsider_key.string());
            BOOST_REQUIRE(outsider.has_value());
            BOOST_TEST(outsider->status == 403U, outsider->body);
        }
        // The forwarding routes take a member's certificate, not the
        // operator's: a read-index round on the catalog, answered by the
        // leader or with a not_leader reply, is 200 either way.
        auto& first = c.nodes.front();
        auto& second = c.nodes.at(1);
        auto refused = https_call(second.hsm, c.pki, http::verb::post, "/v1/peer/read-index/0",
                                  c.pki.admin_cert.string(), c.pki.admin_key.string());
        BOOST_REQUIRE(refused.has_value());
        BOOST_TEST(refused->status == 403U, refused->body);
        auto member = https_call(second.hsm, c.pki, http::verb::post, "/v1/peer/read-index/0",
                                 c.pki.node_cert(make_id(first.n)).string(),
                                 c.pki.node_key(make_id(first.n)).string());
        BOOST_REQUIRE(member.has_value());
        BOOST_TEST(member->status == 200U, member->body);
        BOOST_TEST_MESSAGE("hsm: operator API on every node, peer routes for members only");

        // Init on one node hands out the shares once, and leaves every node
        // sealed; two shares unseal each node.
        const auto admin = [&](const node_proc& p, http::verb verb, const std::string& target,
                               const std::string& body = {}) {
            return https_call(p.hsm, c.pki, verb, target, c.pki.admin_cert.string(),
                              c.pki.admin_key.string(), {}, {{"Content-Type", "application/json"}},
                              body);
        };
        auto init =
            admin(first, http::verb::post, "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})");
        BOOST_REQUIRE(init.has_value());
        BOOST_REQUIRE_MESSAGE(init->status == 200U, init->body);
        std::vector<std::string> shares;
        // Held: a range-for does not extend json_of's temporary (C++20).
        const auto init_body = json_of(init->body);
        for (const auto& v : init_body.at("shares").as_array()) {
            shares.emplace_back(v.as_string());
        }
        BOOST_REQUIRE(shares.size() == 3U);
        for (const auto& p : c.nodes) {
            for (const auto& share : {shares[p.n % 3], shares[(p.n + 1) % 3]}) {
                auto r = admin(p, http::verb::post, "/v1/unseal",
                               boost::json::serialize(boost::json::object{{"share", share}}));
                BOOST_REQUIRE(r.has_value());
                BOOST_TEST(r->status == 200U, r->body);
            }
            auto st = admin(p, http::verb::get, "/v1/status");
            BOOST_REQUIRE(st.has_value());
            BOOST_TEST(json_of(st->body).at("sealed").as_bool() == false, st->body);
        }
        // A token created through a follower is forwarded to the leader.
        auto token = admin(second, http::verb::post, "/v1/tokens", R"({"id": 1, "label": "ca"})");
        BOOST_REQUIRE(token.has_value());
        BOOST_TEST(token->status == 201U, token->body);
        // One seal reaches every node within a maintenance pass.
        auto sealed = admin(c.nodes.back(), http::verb::post, "/v1/seal");
        BOOST_REQUIRE(sealed.has_value());
        BOOST_TEST(sealed->status == 200U, sealed->body);
        for (const auto& p : c.nodes) {
            auto st = until(
                200U, [&] { return admin(p, http::verb::get, "/v1/status"); }, R"("sealed":true)",
                20s);
            BOOST_REQUIRE(st.has_value());
            BOOST_TEST(st->body.find(R"("sealed":true)") != std::string::npos, st->body);
        }
        BOOST_TEST_MESSAGE("hsm: init, unseal on every node, a token, and a cluster-wide seal");
    }
}
