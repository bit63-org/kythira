// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Three kms_node processes (.kiro/specs/kms-compatible-api/ task 12):
// the daemon with mutual TLS between members, static authentication, and
// SoftHSM2 standing in for the HSM (one token directory, as members would
// share one HSM). AWS clients' signed JSON requests reach any member:
//
//   * a key created through any member is described by every member, so
//     a follower forwards the proposal to the catalog's leader and reads
//     behind a read barrier;
//   * a ciphertext made by one member decrypts on another;
//   * the peer paths answer only a verified certificate naming a member:
//     a client with no certificate, or with one the CA signed for someone
//     else, is refused with 403 before anything is proposed;
//   * a member the others cannot reach is not needed: with one member
//     stopped the other two still create keys, and the stopped member
//     catches up when it is back.
//   * boto3, the AWS CLI v2 and the AWS Encryption SDK work against the
//     cluster, their calls spread over its members (task 18,
//     clients/kms_clients.py).
//   * independent layers (.kiro/specs/kms-independent-layers/ task 3):
//     three data nodes and two front ends with gateways, where only the
//     front ends serve the API, hold the HSM PIN and run the jobs, and
//     only the data nodes serve the catalog.

#define BOOST_TEST_MODULE kms_node_cluster_test

#include "kms_test_pki.hpp"
#include "test_ports.hpp"

#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>
#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include <httplib.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#ifndef KMS_NODE_PATH
#define KMS_NODE_PATH "kms_node"
#endif
#ifndef KYTHIRA_SOFTHSM2_LIBRARY
#define KYTHIRA_SOFTHSM2_LIBRARY "/usr/lib/softhsm/libsofthsm2.so"
#endif
#ifndef KYTHIRA_PYTHON3
#define KYTHIRA_PYTHON3 "python3"
#endif
#ifndef KMS_CLIENTS_SCRIPT
#define KMS_CLIENTS_SCRIPT "kms_clients.py"
#endif
#ifndef KMS_DIFFERENTIAL_DIR
#define KMS_DIFFERENTIAL_DIR "differential"
#endif
#ifndef KYTHIRA_SOFTHSM2_UTIL
#define KYTHIRA_SOFTHSM2_UTIL "softhsm2-util"
#endif

namespace fs = std::filesystem;
namespace json = boost::json;
namespace sv4 = kythira::sigv4;
using namespace std::chrono_literals;

namespace {

constexpr std::string_view k_akid = "AKIDKMSNODE";
constexpr std::string_view k_secret = "kms-node-cluster-test-secret";
constexpr std::string_view k_account = "111122223333";

auto slurp(const fs::path& p) -> std::string {
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

auto identity(std::size_t i) -> std::string {
    return "spiffe://kms/node-" + std::to_string(i + 1);
}

struct member {
    /// KYTHIRA_KMS_ROLES; empty for the default (every layer).
    std::string roles;
    std::uint16_t raft = 0;
    std::uint16_t api = 0;
    std::uint16_t metrics = 0;
    pid_t pid = -1;
    int starts = 0;
    kythira::kms::test::test_pki::files tls;
};

struct answer {
    int status = 0;
    json::object body;

    [[nodiscard]] auto str(std::string_view k) const -> std::string {
        const auto* v = body.if_contains(k);
        return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string();
    }
};

/// Whether a member with KYTHIRA_KMS_ROLES `roles` runs `role`.
auto runs(const std::string& roles, std::string_view role) -> bool {
    if (roles.empty()) {
        return true;
    }
    std::string padded = "," + roles + ",";
    return padded.find("," + std::string(role) + ",") != std::string::npos;
}

/// kms_node processes on loopback: three co-located members unless
/// `roles` says otherwise (one entry per member).
class process_cluster {
public:
    explicit process_cluster(std::vector<std::string> roles = {"", "", ""}) {
        std::random_device rd;
        _dir = fs::temp_directory_path() / ("kythira-kms-cluster-" + std::to_string(rd()));
        fs::create_directories(_dir / "tokens");
        {
            std::ofstream conf(_dir / "softhsm2.conf");
            conf << "directories.tokendir = " << (_dir / "tokens").string()
                 << "\nobjectstore.backend = file\nlog.level = ERROR\n";
        }
        std::ofstream(_dir / "pin") << "5678\n";
        std::ofstream(_dir / "keys")
            << k_akid << ' ' << k_secret << ' ' << k_account << " tester admin\n";
        const auto init = std::string("SOFTHSM2_CONF=") + (_dir / "softhsm2.conf").string() + " " +
                          KYTHIRA_SOFTHSM2_UTIL +
                          " --init-token --free --label kms --so-pin 1234 --pin 5678 >/dev/null";
        BOOST_REQUIRE_EQUAL(std::system(init.c_str()), 0);  // NOLINT(concurrency-mt-unsafe)

        const auto base = kythira::testing::free_port_block(3 * roles.size());
        for (std::size_t i = 0; i < roles.size(); ++i) {
            member m;
            m.roles = roles[i];
            const auto b = static_cast<std::uint16_t>(base + 3 * i);
            m.raft = b;
            m.api = b + 1;
            m.metrics = b + 2;
            m.tls = pki.issue("node-" + std::to_string(i + 1),
                              "DNS:localhost,IP:127.0.0.1,URI:" + identity(i));
            _members.push_back(m);
        }
        _stranger = pki.issue("stranger", "DNS:localhost,URI:spiffe://kms/stranger");
        for (std::size_t i = 0; i < _members.size(); ++i) {
            start(i);
        }
        for (std::size_t i = 0; i < _members.size(); ++i) {
            wait_serving(i);
        }
    }

    process_cluster(const process_cluster&) = delete;
    auto operator=(const process_cluster&) -> process_cluster& = delete;
    process_cluster(process_cluster&&) = delete;
    auto operator=(process_cluster&&) -> process_cluster& = delete;

    ~process_cluster() {
        const auto id = boost::unit_test::framework::current_test_case().p_id;
        if (!boost::unit_test::results_collector.results(id).passed()) {
            dump_logs();
        }
        for (auto& m : _members) {
            stop(m);
        }
        std::error_code ec;
        fs::remove_all(_dir, ec);
    }

    void start(std::size_t i) {
        auto& m = _members[i];
        std::string peers;
        std::string urls;
        std::string identities;
        for (std::size_t q = 0; q < _members.size(); ++q) {
            const auto* const sep = q == 0 ? "" : ",";
            const auto id = std::to_string(q + 1);
            peers += sep + id + "=127.0.0.1:" + std::to_string(_members[q].raft);
            // The catalog's members: the data nodes. Every node's identity
            // is admitted, so data nodes serve the front ends.
            if (runs(_members[q].roles, "data")) {
                urls += std::string(urls.empty() ? "" : ",") + id +
                        "=https://localhost:" + std::to_string(_members[q].api);
            }
            identities += sep + identity(q);
        }
        const auto dir = _dir / ("node-" + std::to_string(i + 1));
        fs::create_directories(dir);
        std::vector<std::string> env{
            "KYTHIRA_NODE_ID=" + std::to_string(i + 1),
            "KYTHIRA_NODE_DATA_DIR=" + (dir / "data").string(),
            "KYTHIRA_NODE_PEERS=" + peers,
            "KYTHIRA_NODE_RAFT_BIND=127.0.0.1",
            "KYTHIRA_NODE_RAFT_PORT=" + std::to_string(m.raft),
            "KYTHIRA_NODE_TLS_CERT=" + m.tls.cert,
            "KYTHIRA_NODE_TLS_KEY=" + m.tls.key,
            "KYTHIRA_NODE_TLS_CA=" + pki.ca_path(),
            "KYTHIRA_NODE_METRICS_BIND=127.0.0.1",
            "KYTHIRA_NODE_METRICS_PORT=" + std::to_string(m.metrics),
            "KYTHIRA_SERVICES=kms",
            "KYTHIRA_KMS_API_LISTEN=127.0.0.1:" + std::to_string(m.api),
            "KYTHIRA_KMS_API_URLS=" + urls,
            "KYTHIRA_KMS_PEER_IDENTITIES=" + identities,
            "KYTHIRA_KMS_AUTH=static",
            "KYTHIRA_KMS_STATIC_KEYS_FILE=" + (_dir / "keys").string(),
            std::string("KYTHIRA_KMS_PKCS11=") + KYTHIRA_SOFTHSM2_LIBRARY,
            // Task 14: an operator's alias limit, written by the leader.
            "KYTHIRA_KMS_ACCOUNT_LIMITS=" + std::string(k_account) + "=100:3",
            "KYTHIRA_KMS_JOB_INTERVAL_MS=200",
            "SOFTHSM2_CONF=" + (_dir / "softhsm2.conf").string(),
            "PATH=/usr/bin:/bin",
        };
        if (!m.roles.empty()) {
            env.push_back("KYTHIRA_KMS_ROLES=" + m.roles);
        }
        if (runs(m.roles, "front_end")) {  // the only layer holding the PIN
            env.push_back("KYTHIRA_KMS_PIN_FILE=" + (_dir / "pin").string());
        }
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
                envp.push_back(
                    const_cast<char*>(e.c_str()));  // NOLINT(cppcoreguidelines-pro-type-const-cast)
            }
            envp.push_back(nullptr);
            std::array<char*, 2> argv{
                const_cast<char*>(KMS_NODE_PATH),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                nullptr};
            ::execve(argv[0], argv.data(), envp.data());
            ::_exit(127);
        }
        m.pid = pid;
        ++m.starts;
    }

    void stop(std::size_t i) { stop(_members[i]); }

    /// Member i's /metrics, served over TLS with the node's certificate
    /// like the rest of its endpoint; nullopt when it does not answer.
    [[nodiscard]] auto metrics_text(std::size_t i) const -> std::optional<std::string> {
        httplib::SSLClient c("localhost", _members[i].metrics);
        c.set_ca_cert_path(pki.ca_path());
        c.enable_server_certificate_verification(true);
        c.set_connection_timeout(2s);
        c.set_read_timeout(5s);
        const auto r = c.Get("/metrics");
        if (!r || r->status != 200) {
            return std::nullopt;
        }
        return r->body;
    }

    /// The running members whose /metrics say they hold the job lease.
    [[nodiscard]] auto lease_holders() const -> std::vector<std::size_t> {
        std::vector<std::size_t> out;
        for (std::size_t i = 0; i < _members.size(); ++i) {
            if (_members[i].pid <= 0) {
                continue;
            }
            const auto text = metrics_text(i);
            if (!text) {
                continue;
            }
            std::istringstream in(*text);
            for (std::string line; std::getline(in, line);) {
                if (line == "kythira_kms_job_lease_holder 1") {
                    out.push_back(i);
                }
            }
        }
        return out;
    }

    /// Waits until exactly one running member holds the job lease, and
    /// answers which; nullopt after 30 s.
    [[nodiscard]] auto await_one_lease_holder() const -> std::optional<std::size_t> {
        const auto deadline = std::chrono::steady_clock::now() + 30s;
        while (std::chrono::steady_clock::now() < deadline) {
            if (const auto h = lease_holders(); h.size() == 1) {
                return h[0];
            }
            std::this_thread::sleep_for(100ms);
        }
        return std::nullopt;
    }

    /// Member i's log so far.
    [[nodiscard]] auto log_of(std::size_t i) const -> std::string {
        return slurp(_dir / ("node-" + std::to_string(i + 1)) / "node.log");
    }

    /// Waits until member i logs that it serves, once for each start (the
    /// log is appended to across restarts).
    void wait_serving(std::size_t i) const {
        const auto log = _dir / ("node-" + std::to_string(i + 1)) / "node.log";
        const auto deadline = std::chrono::steady_clock::now() + 60s;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto text = slurp(log);
            int seen = 0;
            for (auto at = text.find("service=node serving"); at != std::string::npos;
                 at = text.find("service=node serving", at + 1)) {
                ++seen;
            }
            if (seen >= _members[i].starts) {
                return;
            }
            std::this_thread::sleep_for(50ms);
        }
        BOOST_FAIL("kms_node " << i + 1 << " did not start");
    }

    /// A KMS API call on member i, signed as an AWS client signs (no
    /// client certificate), retried while the catalog has no leader yet.
    auto call(std::size_t i, std::string_view op, const std::string& body) -> answer {
        answer out;
        const auto deadline = std::chrono::steady_clock::now() + 30s;
        bool retried = false;
        do {
            out = call_once(i, op, body);
            // Each attempt spends a token of the operation's quota before
            // the catalog answers, so retrying through an election can
            // drain a slow quota (CreateKey's 5/s over three members) and
            // turn the call into a ThrottlingException the test never
            // asked about. Only a first attempt's throttle is the answer.
            if (retried && out.str("__type") == "ThrottlingException") {
                std::this_thread::sleep_for(1s);
                continue;
            }
            if (out.status == 200 || (out.status >= 400 && out.status < 500 &&
                                      out.str("__type") != "DependencyTimeoutException")) {
                return out;
            }
            retried = true;
            std::this_thread::sleep_for(200ms);
        } while (std::chrono::steady_clock::now() < deadline);
        return out;
    }

    /// A peer request on member i presenting `cert` (none when null).
    auto peer(std::size_t i, const kythira::kms::test::test_pki::files* cert,
              const std::string& path = "/v1/kms/peer/read-index", const std::string& body = {})
        -> int {
        auto cli = client(i, cert);
        const auto res = cli->Post(path, body, "application/octet-stream");
        return res ? res->status : -1;
    }

    /// Member i's metric `name` from /metrics; nullopt when the member
    /// does not report it (an endpoint that does not answer fails the test).
    [[nodiscard]] auto metric(std::size_t i, std::string_view name) const -> std::optional<double> {
        const auto text = metrics_text(i);
        BOOST_REQUIRE_MESSAGE(text.has_value(), "member " << i + 1 << ": no /metrics");
        std::istringstream in(*text);
        const auto prefix = "kythira_kms_" + std::string(name) + " ";
        for (std::string line; std::getline(in, line);) {
            if (line.starts_with(prefix)) {
                return std::stod(line.substr(prefix.size()));
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto stranger() const -> const kythira::kms::test::test_pki::files& {
        return _stranger;
    }
    [[nodiscard]] auto tls(std::size_t i) const -> const kythira::kms::test::test_pki::files& {
        return _members[i].tls;
    }
    /// Member i's KMS API, as an AWS client is pointed at it.
    [[nodiscard]] auto api_url(std::size_t i) const -> std::string {
        return "https://localhost:" + std::to_string(_members[i].api);
    }
    [[nodiscard]] auto dir() const -> const fs::path& { return _dir; }
    [[nodiscard]] auto ca_path() const -> std::string { return pki.ca_path(); }

private:
    auto client(std::size_t i, const kythira::kms::test::test_pki::files* cert) const
        -> std::unique_ptr<httplib::SSLClient> {
        auto cli = cert != nullptr
                       ? std::make_unique<httplib::SSLClient>("localhost", _members[i].api,
                                                              cert->cert, cert->key)
                       : std::make_unique<httplib::SSLClient>("localhost", _members[i].api);
        cli->set_ca_cert_path(pki.ca_path());
        cli->enable_server_certificate_verification(true);
        cli->set_connection_timeout(5s);
        cli->set_read_timeout(15s);
        return cli;
    }

    auto call_once(std::size_t i, std::string_view op, const std::string& body) -> answer {
        const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        const auto date = sv4::detail::format_amz_date(now);
        const auto host = "localhost:" + std::to_string(_members[i].api);
        std::vector<std::pair<std::string, std::string>> headers{
            {"Host", host},
            {"Content-Type", "application/x-amz-json-1.1"},
            {"X-Amz-Date", date},
            {"X-Amz-Target", "TrentService." + std::string(op)}};
        const sv4::credential_scope scope{date.substr(0, 8), "us-east-1", "kms"};
        headers.emplace_back("Authorization",
                             "AWS4-HMAC-SHA256 Credential=" + std::string(k_akid) + "/" +
                                 scope.text() +
                                 ", SignedHeaders=content-type;host;x-amz-date;x-amz-target"
                                 ", Signature=" +
                                 std::string(64, '0'));
        sv4::service_rules rules;
        rules.service = "kms";
        rules.protocol = sv4::error_protocol::json;
        const auto parsed = sv4::parse(sv4::request{"POST", "/", "", headers, body}, rules, now);
        BOOST_REQUIRE(parsed.has_value());
        const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
        headers.back().second.replace(headers.back().second.size() - 64, 64, sig);

        httplib::Headers h;
        for (const auto& [k, v] : headers) {
            if (k != "Host" && k != "Content-Type") {
                h.emplace(k, v);
            }
        }
        auto cli = client(i, nullptr);
        const auto res = cli->Post("/", h, body, "application/x-amz-json-1.1");
        answer out;
        if (!res) {
            out.status = -1;
            return out;
        }
        out.status = res->status;
        boost::system::error_code ec;
        auto v = json::parse(res->body, ec);
        if (!ec && v.is_object()) {
            out.body = std::move(v.as_object());
        }
        return out;
    }

    void stop(member& m) {
        if (m.pid <= 0) {
            return;
        }
        ::kill(m.pid, SIGTERM);
        const auto deadline = std::chrono::steady_clock::now() + 30s;
        int status = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            if (::waitpid(m.pid, &status, WNOHANG) == m.pid) {
                m.pid = -1;
                return;
            }
            std::this_thread::sleep_for(20ms);
        }
        BOOST_ERROR("a kms_node ignored SIGTERM; killing it");
        dump_stuck(m);
        ::kill(m.pid, SIGKILL);
        ::waitpid(m.pid, &status, 0);
        m.pid = -1;
    }

    /// What a kms_node that did not stop was doing, on stderr: its log's
    /// tail (the directory is removed afterwards) and every thread's stack
    /// through gdb when installed (the test is the node's parent, so it may
    /// attach), else each thread's name and wait channel. A hang at
    /// shutdown otherwise leaves nothing to go on.
    void dump_stuck(const member& m) const {
        for (std::size_t i = 0; i < _members.size(); ++i) {
            if (&_members[i] != &m) {
                continue;
            }
            const auto log = slurp(_dir / ("node-" + std::to_string(i + 1)) / "node.log");
            std::cerr << "---- kms_node " << i + 1 << " (pid " << m.pid << ") log tail ----\n"
                      << (log.size() > 6000 ? log.substr(log.size() - 6000) : log) << '\n';
        }
        const auto pid = std::to_string(m.pid);
        const auto cmd = "if command -v gdb >/dev/null 2>&1; then gdb -p " + pid +
                         " -batch -nx -ex 'thread apply all bt' 1>&2 2>/dev/null; else for t in "
                         "/proc/" +
                         pid +
                         "/task/*; do echo \"$t $(cat $t/comm) $(cat $t/wchan)\" "
                         "1>&2; done; fi";
        std::ignore = std::system(cmd.c_str());  // NOLINT(cert-env33-c): diagnostics only
    }

    void dump_logs() const {
        for (std::size_t i = 0; i < _members.size(); ++i) {
            const auto log = slurp(_dir / ("node-" + std::to_string(i + 1)) / "node.log");
            const auto tail = log.size() > 6000 ? log.substr(log.size() - 6000) : log;
            BOOST_TEST_MESSAGE("---- kms_node " << i + 1 << " log tail ----\n" << tail);
        }
    }

    kythira::kms::test::test_pki pki;
    fs::path _dir;
    std::vector<member> _members;
    kythira::kms::test::test_pki::files _stranger;
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(keys_made_through_any_member_are_seen_by_all, process_cluster) {
    for (std::size_t via = 0; via < 3; ++via) {
        const auto desc = "via member " + std::to_string(via + 1);
        const auto r = call(via, "CreateKey", R"({"Description":")" + desc + R"("})");
        BOOST_REQUIRE_MESSAGE(r.status == 200, r.status << " " << r.str("__type"));
        const auto id = std::string(r.body.at("KeyMetadata").as_object().at("KeyId").as_string());
        for (std::size_t on = 0; on < 3; ++on) {
            const auto d = call(on, "DescribeKey", R"({"KeyId":")" + id + R"("})");
            BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
            BOOST_TEST(d.body.at("KeyMetadata").as_object().at("Description").as_string() == desc);
        }
    }

    // A ciphertext made on one member decrypts on another.
    const auto k = call(1, "CreateKey", "{}");
    BOOST_REQUIRE(k.status == 200);
    const auto id = std::string(k.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    const auto e = call(0, "Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})");
    BOOST_REQUIRE_MESSAGE(e.status == 200, e.status << " " << e.str("__type"));
    const auto d = call(2, "Decrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
    BOOST_TEST(d.str("Plaintext") == "c2VjcmV0");

    // Task 14: the member that answered wrote the request's audit record
    // (on stderr by default), naming the key.
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    std::string record;
    while (record.empty() && std::chrono::steady_clock::now() < deadline) {
        const auto log = log_of(2);
        for (auto at = log.find(R"("eventName":"Decrypt")"); at != std::string::npos;
             at = log.find(R"("eventName":"Decrypt")", at + 1)) {
            const auto begin = log.rfind('\n', at);
            const auto end = log.find('\n', at);
            record = log.substr(begin == std::string::npos ? 0 : begin + 1,
                                end == std::string::npos ? std::string::npos : end - begin - 1);
        }
        if (record.empty()) {
            std::this_thread::sleep_for(50ms);
        }
    }
    BOOST_REQUIRE_MESSAGE(!record.empty(), "no Decrypt record in member 3's log");
    BOOST_TEST(record.find(R"("eventSource":"kms.amazonaws.com")") != std::string::npos);
    BOOST_TEST(record.find("key/" + id) != std::string::npos);
    BOOST_TEST(record.find("c2VjcmV0") == std::string::npos);
}

// Task 13: an AWS managed key made on first use through any member is one
// key, seen by all.
BOOST_FIXTURE_TEST_CASE(a_managed_key_is_made_once_through_any_member, process_cluster) {
    const auto first = call(1, "DescribeKey", R"({"KeyId":"alias/aws/kinesis"})");
    BOOST_REQUIRE_MESSAGE(first.status == 200, first.status << " " << first.str("__type"));
    const auto& md = first.body.at("KeyMetadata").as_object();
    BOOST_TEST(md.at("KeyManager").as_string() == "AWS");
    const auto id = std::string(md.at("KeyId").as_string());
    for (std::size_t on = 0; on < 3; ++on) {
        const auto d = call(on, "DescribeKey", R"({"KeyId":"alias/aws/kinesis"})");
        BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
        BOOST_TEST(d.body.at("KeyMetadata").as_object().at("KeyId").as_string() == id);
    }
    const auto keys = call(2, "ListKeys", "{}");
    BOOST_REQUIRE(keys.status == 200);
    BOOST_TEST(keys.body.at("Keys").as_array().size() == 1U);
}

// Task 18 (Requirement 14.2): boto3, the AWS CLI v2 and the AWS
// Encryption SDK against the cluster, spread over its members
// (clients/kms_clients.py). CI installs all three;
// KYTHIRA_KMS_CLIENTS_SKIP=cli (say) leaves one out on a machine without it.
BOOST_FIXTURE_TEST_CASE(aws_clients_work_against_the_cluster, process_cluster) {
    // Ready: the catalog has a leader that takes writes.
    BOOST_REQUIRE_EQUAL(call(0, "ListKeys", "{}").status, 200);
    std::string endpoints;
    for (std::size_t i = 0; i < 3; ++i) {
        endpoints += (i == 0 ? "" : ",") + api_url(i);
    }
    const char* skip = std::getenv("KYTHIRA_KMS_CLIENTS_SKIP");  // NOLINT(concurrency-mt-unsafe)
    const auto out = dir() / "clients.log";
    const auto command =
        std::string("AWS_ACCESS_KEY_ID=") + std::string(k_akid) +
        " AWS_SECRET_ACCESS_KEY=" + std::string(k_secret) +
        " AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null " + KYTHIRA_PYTHON3 +
        " " + KMS_CLIENTS_SCRIPT + " --endpoints " + endpoints + " --ca " + ca_path() +
        (skip != nullptr && *skip != '\0' ? " --skip " + std::string(skip) : std::string()) + " >" +
        out.string() + " 2>&1";
    const int rc = std::system(command.c_str());  // NOLINT(concurrency-mt-unsafe)
    BOOST_TEST_MESSAGE(slurp(out));
    BOOST_TEST(rc == 0, "the client suites failed:\n" << slurp(out));
}

// Task 18 (Requirement 14.3): the cases recorded against real AWS KMS
// (differential/recordings/) answer alike here: each error's type and
// status, each success's fields, apart from what allow.json lists. Needs
// boto3, as the client suites do.
BOOST_FIXTURE_TEST_CASE(differential_replay_matches_the_aws_recording, process_cluster) {
    BOOST_REQUIRE_EQUAL(call(0, "ListKeys", "{}").status, 200);
    const std::string dir_name = KMS_DIFFERENTIAL_DIR;
    const auto out = dir() / "differential.log";
    const auto command =
        std::string("AWS_ACCESS_KEY_ID=") + std::string(k_akid) +
        " AWS_SECRET_ACCESS_KEY=" + std::string(k_secret) +
        " AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null " + KYTHIRA_PYTHON3 +
        " " + dir_name + "/kms_differential.py compare --endpoint " + api_url(1) + " --ca " +
        ca_path() + " --recording " + dir_name + "/recordings/aws-us-east-1.json --allow " +
        dir_name + "/recordings/allow.json >" + out.string() + " 2>&1";
    const int rc = std::system(command.c_str());  // NOLINT(concurrency-mt-unsafe)
    BOOST_TEST_MESSAGE(slurp(out));
    BOOST_TEST(rc == 0, "the replay differs from AWS:\n" << slurp(out));
}

BOOST_FIXTURE_TEST_CASE(only_members_reach_the_peer_paths, process_cluster) {
    for (std::size_t i = 0; i < 3; ++i) {
        BOOST_TEST(peer(i, nullptr) == 403, "member " << i + 1 << ", no certificate");
        BOOST_TEST(peer(i, &stranger()) == 403, "member " << i + 1 << ", a stranger");
        BOOST_TEST(peer(i, &tls((i + 1) % 3)) == 200, "member " << i + 1 << ", a member");
    }
}

BOOST_FIXTURE_TEST_CASE(two_members_carry_on_without_the_third, process_cluster) {
    stop(2);
    const auto r = call(1, "CreateKey", R"({"Description":"while 3 was away"})");
    BOOST_REQUIRE_MESSAGE(r.status == 200, r.status << " " << r.str("__type"));
    const auto id = std::string(r.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    start(2);
    wait_serving(2);
    const auto d = call(2, "DescribeKey", R"({"KeyId":")" + id + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
    BOOST_TEST(d.body.at("KeyMetadata").as_object().at("Description").as_string() ==
               "while 3 was away");
}

// kms-independent-layers task 2 (Requirements 5.1, 5.2 and 10.2): one
// member holds the job lease, whichever leads the catalog; a member that
// stops releases it and another takes it at its next pass, well before the
// lease would have expired.
BOOST_FIXTURE_TEST_CASE(one_member_runs_the_jobs_and_hands_them_over_on_stop, process_cluster) {
    const auto first = await_one_lease_holder();
    BOOST_REQUIRE_MESSAGE(first.has_value(), "no single job lease holder");
    BOOST_TEST_MESSAGE("job lease holder: member " << *first + 1);
    stop(*first);
    const auto t0 = std::chrono::steady_clock::now();
    const auto second = await_one_lease_holder();
    BOOST_REQUIRE_MESSAGE(second.has_value(), "the job lease was not taken over");
    BOOST_TEST(*second != *first);
    // Released, not expired: the default lease is 30 s.
    BOOST_TEST((std::chrono::steady_clock::now() - t0 < 20s));
    start(*first);
    wait_serving(*first);
    // The member that came back does not take the lease from the holder.
    std::this_thread::sleep_for(1s);
    const auto now = lease_holders();
    BOOST_TEST(now.size() == 1U);
    BOOST_TEST((now.size() == 1U && now[0] == *second));
}

// Task 14: the operator's key and alias limits reach every member's
// catalog, and AWS's quotas answer ThrottlingException.
BOOST_FIXTURE_TEST_CASE(account_limits_and_quotas_apply, process_cluster) {
    const auto k = call(0, "CreateKey", "{}");
    BOOST_REQUIRE_MESSAGE(k.status == 200, k.status << " " << k.str("__type"));
    const auto id = std::string(k.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    const auto alias = [&](std::size_t on, int n) {
        return call(
            on, "CreateAlias",
            R"({"AliasName":"alias/a)" + std::to_string(n) + R"(","TargetKeyId":")" + id + R"("})");
    };
    // The leader writes the limit at a job pass (every 200 ms here).
    std::this_thread::sleep_for(3s);
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    int made = 0;
    std::string refused;
    while (refused.empty() && std::chrono::steady_clock::now() < deadline) {
        const auto r = alias(static_cast<std::size_t>(made) % 3, made);
        if (r.status == 200) {
            ++made;
        } else if (r.str("__type") == "ThrottlingException") {
            std::this_thread::sleep_for(1s);
        } else {
            refused = r.str("__type");
        }
    }
    BOOST_TEST(refused == "LimitExceededException");
    BOOST_TEST(made == 3);

    // DescribeKey's 2000 per second is far away; CreateKey's 5 is not.
    std::size_t throttled = 0;
    for (int i = 0; i < 20; ++i) {
        throttled += call(1, "CreateKey", "{}").str("__type") == "ThrottlingException" ? 1U : 0U;
    }
    BOOST_TEST(throttled > 0U);
    BOOST_TEST(call(1, "DescribeKey", R"({"KeyId":")" + id + R"("})").status == 200);
}

namespace {

/// kms-independent-layers task 3: three data nodes and two front ends
/// with gateways (members 4 and 5), none of them co-located.
struct split_cluster : process_cluster {
    split_cluster()
        : process_cluster({"data", "data", "data", "gateway,front_end", "gateway,front_end"}) {}
};

constexpr std::size_t k_front_end_a = 3;
constexpr std::size_t k_front_end_b = 4;

}  // namespace

// Requirements 2.1-2.3 and 3.3: front ends without a replica answer as
// co-located members do; only data nodes hold the catalog, and only front
// ends serve clients, hold the PIN and run the jobs.
BOOST_FIXTURE_TEST_CASE(front_ends_without_a_replica_serve_the_api, split_cluster) {
    const auto r = call(k_front_end_a, "CreateKey", R"({"Description":"split"})");
    BOOST_REQUIRE_MESSAGE(r.status == 200, r.status << " " << r.str("__type"));
    const auto id = std::string(r.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    const auto d = call(k_front_end_b, "DescribeKey", R"({"KeyId":")" + id + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
    BOOST_TEST(d.body.at("KeyMetadata").as_object().at("Description").as_string() == "split");
    const auto e =
        call(k_front_end_a, "Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})");
    BOOST_REQUIRE_MESSAGE(e.status == 200, e.status << " " << e.str("__type"));
    const auto p = call(k_front_end_b, "Decrypt",
                        R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})");
    BOOST_REQUIRE_MESSAGE(p.status == 200, p.status << " " << p.str("__type"));
    BOOST_TEST(p.str("Plaintext") == "c2VjcmV0");

    // Data nodes run no gateway; front ends hold no catalog.
    const std::string read_index(1, '\x01');  // catalog API version 1
    for (std::size_t i = 0; i < 3; ++i) {
        BOOST_TEST(call(i, "ListKeys", "{}").status == 404, "data node " << i + 1);
        BOOST_TEST(peer(i, &tls(k_front_end_a), "/v1/kms/catalog/read-index", read_index) == 200,
                   "data node " << i + 1 << ", a front end");
        BOOST_TEST(peer(i, &stranger(), "/v1/kms/catalog/read-index", read_index) == 403,
                   "data node " << i + 1 << ", a stranger");
    }
    for (const auto f : {k_front_end_a, k_front_end_b}) {
        BOOST_TEST(peer(f, &tls(0), "/v1/kms/catalog/read-index", read_index) == 404);
        BOOST_TEST(peer(f, &tls(0)) == 404);
        BOOST_TEST(log_of(f).find("roles=gateway,front_end data_nodes=3") != std::string::npos);
    }

    // The job lease goes to a front end; data nodes report no jobs, and
    // front ends no catalog leadership.
    const auto holder = await_one_lease_holder();
    BOOST_REQUIRE_MESSAGE(holder.has_value(), "no single job lease holder");
    BOOST_TEST(*holder >= k_front_end_a);
    for (std::size_t i = 0; i < 3; ++i) {
        BOOST_TEST(!metric(i, "job_lease_holder").has_value(), "data node " << i + 1);
        BOOST_TEST(metric(i, "leader").has_value(), "data node " << i + 1);
        BOOST_TEST(log_of(i).find("roles=data members=3") != std::string::npos);
        BOOST_TEST(log_of(i).find("pkcs11=") == std::string::npos);
    }
    BOOST_TEST(!metric(k_front_end_a, "leader").has_value());

    // A data node away: the front ends reach the other two.
    stop(0);
    const auto k = call(k_front_end_b, "CreateKey", R"({"Description":"while 1 was away"})");
    BOOST_REQUIRE_MESSAGE(k.status == 200, k.status << " " << k.str("__type"));
    const auto kid = std::string(k.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    BOOST_TEST(call(k_front_end_a, "DescribeKey", R"({"KeyId":")" + kid + R"("})").status == 200);
    start(0);
    wait_serving(0);
}
