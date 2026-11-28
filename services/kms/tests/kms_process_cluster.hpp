// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// KMS nodes as processes on loopback, for the process tests
// (kms_node_cluster_test, kythira_node_kms_consumers_test): kms_node or
// kythira_node members with mutual TLS from one test CA, static
// authentication, SoftHSM2 standing in for the shared HSM (one token
// directory), and per-member KYTHIRA_KMS_ROLES. The KMS lists
// (KYTHIRA_KMS_API_URLS, _FRONT_END_URLS, _PEER_IDENTITIES) are worked out
// from the members' roles; a member may run other services beside the
// KMS, or none, and may keep a Raft peer set of its own, as a consumer on
// another cluster does.
//
// Every test that includes this defines BOOST_TEST_MODULE first and links
// Boost.Test, Boost.JSON, OpenSSL and httplib.

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

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
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

namespace kms_process_testing {

namespace fs = std::filesystem;
namespace json = boost::json;
namespace sv4 = kythira::sigv4;
using namespace std::chrono_literals;

constexpr std::string_view k_akid = "AKIDKMSNODE";
constexpr std::string_view k_secret = "kms-node-cluster-test-secret";
constexpr std::string_view k_account = "111122223333";

inline auto slurp(const fs::path& p) -> std::string {
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

inline auto identity(std::size_t i) -> std::string {
    return "spiffe://kms/node-" + std::to_string(i + 1);
}

/// What a member runs, as the test asks for it.
struct member_spec {
    /// KYTHIRA_KMS_ROLES; empty for the default (every layer).
    std::string roles;
    /// KYTHIRA_SERVICES. A member without "kms" in it is left out of the
    /// KMS's lists and given no KMS settings.
    std::string services = "kms";
    /// The binary: kms_node, or kythira_node for other services beside
    /// (or instead of) the KMS.
    std::string binary = KMS_NODE_PATH;
    /// A Raft peer set of its own (KYTHIRA_NODE_PEERS names only this
    /// member), as a node of another cluster has; the others' peer set
    /// leaves it out.
    bool own_cluster = false;
    /// More environment; an entry replaces the harness's own setting of
    /// the same name.
    std::vector<std::string> env;
};

struct member {
    member_spec spec;
    std::uint16_t raft = 0;
    std::uint16_t api = 0;
    std::uint16_t metrics = 0;
    /// Two more ports for the member's other services (say, Kinesis and
    /// DynamoDB listeners); the harness itself does not use them.
    std::uint16_t aux_a = 0;
    std::uint16_t aux_b = 0;
    pid_t pid = -1;
    int starts = 0;
    kythira::kms::test::test_pki::files tls;

    [[nodiscard]] auto runs_kms() const -> bool {
        const std::string padded = "," + spec.services + ",";
        return padded.find(",kms,") != std::string::npos;
    }
};

/// Access keys a call is signed with.
struct credentials {
    std::string akid;
    std::string secret;
};

struct answer {
    int status = 0;
    json::object body;
    std::string raw;

    [[nodiscard]] auto str(std::string_view k) const -> std::string {
        const auto* v = body.if_contains(k);
        return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string();
    }
};

/// Whether a member with KYTHIRA_KMS_ROLES `roles` runs `role`.
inline auto runs(const std::string& roles, std::string_view role) -> bool {
    if (roles.empty()) {
        return true;
    }
    std::string padded = "," + roles + ",";
    return padded.find("," + std::string(role) + ",") != std::string::npos;
}

/// kms_node processes on loopback: three co-located members unless
/// `roles` says otherwise (one entry per member), or the members `specs`
/// describes. Each member's /metrics, its KMS API and its other services
/// share the member's certificate (identity(i), localhost and 127.0.0.1).
class process_cluster {
public:
    /// What a test may add before the members start.
    struct options {
        /// More lines of the static keys file every member reads
        /// ("AKID secret account name role"), beside the harness's own
        /// admin key.
        std::vector<std::string> key_lines;
        /// Start the members and wait until each serves; a test that
        /// expects a member to refuse to start passes false and starts
        /// them itself.
        bool start = true;
    };

    explicit process_cluster(const std::vector<std::string>& roles = {"", "", ""})
        : process_cluster(specs_of(roles), options{}) {}

    process_cluster(std::vector<member_spec> specs, options o) {
        std::random_device rd;
        _dir = fs::temp_directory_path() / ("kythira-kms-cluster-" + std::to_string(rd()));
        fs::create_directories(_dir / "tokens");
        {
            std::ofstream conf(_dir / "softhsm2.conf");
            conf << "directories.tokendir = " << (_dir / "tokens").string()
                 << "\nobjectstore.backend = file\nlog.level = ERROR\n";
        }
        std::ofstream(_dir / "pin") << "5678\n";
        {
            std::ofstream keys(_dir / "keys");
            keys << k_akid << ' ' << k_secret << ' ' << k_account << " tester admin\n";
            for (const auto& line : o.key_lines) {
                keys << line << '\n';
            }
        }
        const auto init = std::string("SOFTHSM2_CONF=") + (_dir / "softhsm2.conf").string() + " " +
                          KYTHIRA_SOFTHSM2_UTIL +
                          " --init-token --free --label kms --so-pin 1234 --pin 5678 >/dev/null";
        BOOST_REQUIRE_EQUAL(std::system(init.c_str()), 0);  // NOLINT(concurrency-mt-unsafe)

        const auto base = kythira::testing::free_port_block(k_ports * specs.size());
        for (std::size_t i = 0; i < specs.size(); ++i) {
            member m;
            m.spec = std::move(specs[i]);
            const auto b = static_cast<std::uint16_t>(base + k_ports * i);
            m.raft = b;
            m.api = b + 1;
            m.metrics = b + 2;
            m.aux_a = b + 3;
            m.aux_b = b + 4;
            m.tls = pki.issue("node-" + std::to_string(i + 1),
                              "DNS:localhost,IP:127.0.0.1,URI:" + identity(i));
            _members.push_back(std::move(m));
        }
        _stranger = pki.issue("stranger", "DNS:localhost,URI:spiffe://kms/stranger");
        if (!o.start) {
            return;
        }
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
        std::string front_ends;
        // Members with every layer count as front ends once any member
        // names its roles (a split layout, or one part-way through a
        // migration); a cluster of co-located members alone lists none.
        const bool split = std::any_of(_members.begin(), _members.end(), [](const member& o) {
            return o.runs_kms() && !o.spec.roles.empty();
        });
        for (std::size_t q = 0; q < _members.size(); ++q) {
            const auto& o = _members[q];
            const auto id = std::to_string(q + 1);
            const auto add = [](std::string& list, const std::string& entry) {
                list += (list.empty() ? "" : ",") + entry;
            };
            if (q == i || (!m.spec.own_cluster && !o.spec.own_cluster)) {
                add(peers, id + "=127.0.0.1:" + std::to_string(o.raft));
            }
            // Every node's identity is admitted, so data nodes serve the
            // front ends and front ends the gateways.
            add(identities, identity(q));
            if (!o.runs_kms()) {
                continue;
            }
            // The catalog's members: the data nodes.
            if (runs(o.spec.roles, "data")) {
                add(urls, id + "=https://localhost:" + std::to_string(o.api));
            }
            // A split layout lists its front ends (task 4): where gateways
            // hand calls, and who shares the quotas.
            if (split && runs(o.spec.roles, "front_end")) {
                add(front_ends, id + "=https://localhost:" + std::to_string(o.api));
            }
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
            "KYTHIRA_SERVICES=" + m.spec.services,
            "SOFTHSM2_CONF=" + (_dir / "softhsm2.conf").string(),
            "PATH=/usr/bin:/bin",
        };
        if (m.runs_kms()) {
            for (auto& e : std::vector<std::string>{
                     "KYTHIRA_KMS_API_LISTEN=127.0.0.1:" + std::to_string(m.api),
                     "KYTHIRA_KMS_API_URLS=" + urls,
                     "KYTHIRA_KMS_PEER_IDENTITIES=" + identities,
                     "KYTHIRA_KMS_AUTH=static",
                     "KYTHIRA_KMS_STATIC_KEYS_FILE=" + (_dir / "keys").string(),
                     std::string("KYTHIRA_KMS_PKCS11=") + KYTHIRA_SOFTHSM2_LIBRARY,
                     // Task 14: an operator's alias limit, written by the leader.
                     "KYTHIRA_KMS_ACCOUNT_LIMITS=" + std::string(k_account) + "=100:3",
                     "KYTHIRA_KMS_JOB_INTERVAL_MS=200",
                 }) {
                env.push_back(std::move(e));
            }
            if (!m.spec.roles.empty()) {
                env.push_back("KYTHIRA_KMS_ROLES=" + m.spec.roles);
            }
            if (!front_ends.empty() &&
                (runs(m.spec.roles, "front_end") || runs(m.spec.roles, "gateway"))) {
                env.push_back("KYTHIRA_KMS_FRONT_END_URLS=" + front_ends);
                env.push_back("KYTHIRA_KMS_FRONT_END_PROBE_MS=200");
            }
            if (runs(m.spec.roles, "front_end")) {  // the only layer holding the PIN
                env.push_back("KYTHIRA_KMS_PIN_FILE=" + (_dir / "pin").string());
            }
        }
        for (const auto& e : m.spec.env) {
            // getenv answers the first entry of a name, so replace it.
            const auto name = e.substr(0, e.find('=') + 1);
            std::erase_if(env, [&](const std::string& have) { return have.starts_with(name); });
            env.push_back(e);
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
                const_cast<char*>(  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                    m.spec.binary.c_str()),
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
        BOOST_FAIL("member " << i + 1 << " did not start:\n" << log_of(i));
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

    /// A call on member i's listener presenting member i's own
    /// certificate (a listed peer, so trusted as every layer): the
    /// membership routes an operator uses (task 6).
    [[nodiscard]] auto as_member(std::size_t i, std::string_view method, std::string_view path,
                                 const std::string& body = {}) const -> answer {
        auto cli = client(i, &_members[i].tls);
        const auto res = method == "GET" ? cli->Get(std::string(path))
                                         : cli->Post(std::string(path), body, "application/json");
        answer out;
        if (!res) {
            out.status = -1;
            return out;
        }
        out.status = res->status;
        out.raw = res->body;
        boost::system::error_code ec;
        auto v = json::parse(res->body, ec);
        if (!ec && v.is_object()) {
            out.body = std::move(v.as_object());
        }
        return out;
    }

    /// Whether member i is running.
    [[nodiscard]] auto running(std::size_t i) const -> bool { return _members[i].pid > 0; }

    /// Member i, with its ports.
    [[nodiscard]] auto at(std::size_t i) const -> const member& { return _members[i]; }
    [[nodiscard]] auto size() const -> std::size_t { return _members.size(); }
    /// Member i's spec, which the next start(i) reads.
    auto spec(std::size_t i) -> member_spec& { return _members[i].spec; }

    /// Waits up to `timeout` for member i to exit on its own (say, after
    /// refusing its configuration); its wait status, or nullopt while it
    /// still runs.
    auto await_exit(std::size_t i, std::chrono::milliseconds timeout) -> std::optional<int> {
        auto& m = _members[i];
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (m.pid > 0 && std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            if (::waitpid(m.pid, &status, WNOHANG) == m.pid) {
                m.pid = -1;
                return status;
            }
            std::this_thread::sleep_for(20ms);
        }
        return std::nullopt;
    }

    /// An AWS JSON call to `port` on loopback (one of member i's
    /// listeners, over TLS with the test CA), signed for `service` with
    /// `who`: `X-Amz-Target: <target>`. One attempt.
    [[nodiscard]] auto aws_call(std::uint16_t port, std::string_view service,
                                std::string_view target, std::string_view content_type,
                                const std::string& body, const credentials& who) const -> answer {
        const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        const auto date = sv4::detail::format_amz_date(now);
        const auto host = "localhost:" + std::to_string(port);
        std::vector<std::pair<std::string, std::string>> headers{
            {"Host", host},
            {"Content-Type", std::string(content_type)},
            {"X-Amz-Date", date},
            {"X-Amz-Target", std::string(target)}};
        const sv4::credential_scope scope{date.substr(0, 8), "us-east-1", std::string(service)};
        headers.emplace_back("Authorization",
                             "AWS4-HMAC-SHA256 Credential=" + who.akid + "/" + scope.text() +
                                 ", SignedHeaders=content-type;host;x-amz-date;x-amz-target"
                                 ", Signature=" +
                                 std::string(64, '0'));
        sv4::service_rules rules;
        rules.service = std::string(service);
        rules.protocol = sv4::error_protocol::json;
        const auto parsed = sv4::parse(sv4::request{"POST", "/", "", headers, body}, rules, now);
        BOOST_REQUIRE(parsed.has_value());
        const auto sig =
            sv4::compute_signature(*parsed, sv4::derive_signing_key(who.secret, scope));
        headers.back().second.replace(headers.back().second.size() - 64, 64, sig);

        httplib::Headers h;
        for (const auto& [k, v] : headers) {
            if (k != "Host" && k != "Content-Type") {
                h.emplace(k, v);
            }
        }
        httplib::SSLClient cli("localhost", port);
        cli.set_ca_cert_path(pki.ca_path());
        cli.enable_server_certificate_verification(true);
        cli.set_connection_timeout(5s);
        cli.set_read_timeout(30s);
        const auto res = cli.Post("/", h, body, std::string(content_type));
        answer out;
        if (!res) {
            out.status = -1;
            return out;
        }
        out.status = res->status;
        out.raw = res->body;
        boost::system::error_code ec;
        auto v = json::parse(res->body, ec);
        if (!ec && v.is_object()) {
            out.body = std::move(v.as_object());
        }
        return out;
    }

private:
    static constexpr std::size_t k_ports = 5;

    static auto specs_of(const std::vector<std::string>& roles) -> std::vector<member_spec> {
        std::vector<member_spec> out;
        out.reserve(roles.size());
        for (const auto& r : roles) {
            member_spec m;
            m.roles = r;
            out.push_back(std::move(m));
        }
        return out;
    }

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
        return aws_call(_members[i].api, "kms", "TrentService." + std::string(op),
                        "application/x-amz-json-1.1", body,
                        credentials{std::string(k_akid), std::string(k_secret)});
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
        BOOST_ERROR("a member ignored SIGTERM; killing it");
        dump_stuck(m);
        ::kill(m.pid, SIGKILL);
        ::waitpid(m.pid, &status, 0);
        m.pid = -1;
    }

    /// What a member that did not stop was doing, on stderr: its log's
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
            std::cerr << "---- member " << i + 1 << " (pid " << m.pid << ") log tail ----\n"
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
            BOOST_TEST_MESSAGE("---- member " << i + 1 << " log tail ----\n" << tail);
        }
    }

    kythira::kms::test::test_pki pki;
    fs::path _dir;
    std::vector<member> _members;
    kythira::kms::test::test_pki::files _stranger;
};

}  // namespace kms_process_testing
