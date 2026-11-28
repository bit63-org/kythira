// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The virtual HSM under kills and partitions, in containers
// (.kiro/specs/virtual-hsm/ task 11b, Requirement 13.6).
// services/hsm/docker/hsm-chaos-compose.yml starts three members addressed
// by service name, with Raft, the operator API and the PKCS#11 listener
// all on mutual TLS, in each layout:
//
//   * stand-alone: `hsm_node`, the HSM module alone;
//   * co-located: `kythira_node` running the HSM beside the Redis module,
//     sharing each node's process, Raft listener and data directory;
//   * encrypted services (.kiro/specs/kms-compatible-api/ task 19,
//     Requirement 14.5): `kythira_node` running the HSM, the KMS (its
//     backing keys on the HSM's token), DynamoDB and Kinesis (encrypting
//     through the co-located KMS).
//
// In each layout, as an operator and an application would from outside
// (hsm_test_cluster.hpp, the scenarios hsm_node_cluster_test runs on
// processes):
//
//   * the token group's leader is SIGKILLed while two clients generate key
//     pairs through the followers, then started and unsealed;
//   * the token group's leader is cut off the network while they generate,
//     then joined again (it must step down and catch up, keeping nothing
//     the new leader overwrote);
//   * the catalog's leader is SIGKILLed while a follower rekeys the master
//     key, at two moments;
//
// and after each, every member lists the same whole key pairs, every
// acknowledged generation is among them, and every pair signs on one
// member and verifies on another.
//
// In the encrypted-services layout, an encrypted table and an encrypted
// stream take writes, and the KMS hands out data keys, while one member is
// SIGKILLed (the HSM catalog's leader; started and unsealed again) and
// another is cut off the network and joined again. Every acknowledged
// item and record must then read back, and once the members stop, no data
// key the KMS returned and no plaintext the test encrypted may appear in
// any member's data directory. Item and record values are searched for
// too, in every file. DynamoDB seals a value only when it applies the
// write (an UpdateItem's result is known only then), so this layout seals
// every module's Raft logs at rest (KYTHIRA_RAFT_LOG_KMS=local,
// .kiro/specs/raft-log-encryption/): without that, the log entry carrying
// a write would hold its value in the clear until compaction. Item keys
// stay in the clear by design (the engine orders by them), so only values
// carry the searched-for text.
//
// A case whose kythira_node modules are missing (KYTHIRA_HSM_CHAOS_MODULES)
// is skipped, naming the module.
//
// Not registered in CTest: it needs Docker or rootless Podman and runs
// through the docker-hsm-chaos-tests target.

#define BOOST_TEST_MODULE hsm_chaos_test
#include "hsm_test_cluster.hpp"
#include "hsm_test_pki.hpp"
#include "os_faults.hpp"
#include "test_ports.hpp"

#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>
#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <functional>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

namespace hsm = kythira::hsm;
namespace os = docker_chaos::os;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

constexpr std::array<const char*, 3> k_containers{"kythira-hsm-chaos-1", "kythira-hsm-chaos-2",
                                                  "kythira-hsm-chaos-3"};
constexpr std::array<const char*, 3> k_services{"hsm-1", "hsm-2", "hsm-3"};
constexpr const char* k_network = "kythira_hsm_chaos_net";

auto compose_file() -> std::string {
    const char* env = std::getenv("KYTHIRA_HSM_CHAOS_COMPOSE_FILE");
    if (env != nullptr && *env != 0) {
        return env;
    }
    return "services/hsm/docker/hsm-chaos-compose.yml";
}

auto compose_cmd(std::initializer_list<std::string> args) -> std::vector<std::string> {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", compose_file()});
    cmd.insert(cmd.end(), args);
    return cmd;
}

/// The other module of the co-located layout (the docker-hsm-chaos-tests
/// target passes it); "none" runs the HSM alone in kythira_node, for a
/// kythira_node built with no other module.
auto colocated_with() -> std::string {
    const char* env = std::getenv("KYTHIRA_HSM_CHAOS_COLOCATE");
    return env != nullptr && *env != 0 ? std::string(env) : std::string("redis");
}

/// A Boost.Test precondition: kythira_node has every module in `needed`
/// (KYTHIRA_HSM_CHAOS_MODULES, the docker-hsm-chaos-tests target's list;
/// unset runs every case).
auto has_modules(std::initializer_list<std::string_view> needed)
    -> std::function<boost::test_tools::assertion_result(boost::unit_test::test_unit_id)> {
    std::vector<std::string> want(needed.begin(), needed.end());
    return [want](boost::unit_test::test_unit_id) -> boost::test_tools::assertion_result {
        const char* env = std::getenv("KYTHIRA_HSM_CHAOS_MODULES");
        if (env == nullptr) {
            return true;
        }
        const auto list = "," + std::string(env) + ",";
        for (const auto& m : want) {
            if (list.find("," + m + ",") == std::string::npos) {
                boost::test_tools::assertion_result r(false);
                r.message() << "kythira_node has no " << m << " module (has: " << env << ")";
                return r;
            }
        }
        return true;
    };
}

enum class layout {
    stand_alone,
    co_located,
    encrypted_services
};

/// The one static key the KMS, DynamoDB and Kinesis accept, an
/// administrator of the account the scenario works in.
constexpr const char* k_access_key = "AKIAHSMCHAOS00000001";
constexpr const char* k_secret_key = "hsm-chaos-static-secret-0001";
constexpr const char* k_account = "111122223333";
constexpr const char* k_region = "us-east-1";

/// The PKI, as a base so it exists before cluster_driver issues from it.
struct pki_holder {
    hsm::test::test_pki pki;
};

/// Three members from the compose file, in one layout.
class container_cluster : private pki_holder, public hsm::test::cluster_driver {
public:
    explicit container_cluster(layout l) : cluster_driver(pki) {
        for (std::size_t i = 0; i < 3; ++i) {
            (void)pki.issue("node-" + std::to_string(i + 1),
                            std::string("DNS:") + k_services[i] +
                                ",DNS:localhost,IP:127.0.0.1,URI:" + hsm::test::member_identity(i));
        }
        // The services' static key (the KMS and Kinesis read blank-separated
        // fields, DynamoDB ':'-separated ones) and the token's user PIN, for
        // the KMS's session on the co-located HSM.
        std::ofstream(pki.dir() / "keys")
            << k_access_key << ' ' << k_secret_key << ' ' << k_account << " tester admin\n";
        std::ofstream(pki.dir() / "ddb-keys")
            << k_access_key << ':' << k_secret_key << ':' << k_account << ":tester:admin\n";
        std::ofstream(pki.dir() / "kms-pin") << hsm::test::k_cluster_user_pin;
        // uid 10001 reads the PKI in every container, which owns none of it
        // under Docker or rootless Podman. Throwaway test keys.
        fs::permissions(pki.dir(), fs::perms::owner_all | fs::perms::group_read |
                                       fs::perms::group_exec | fs::perms::others_read |
                                       fs::perms::others_exec);
        for (const auto& f : fs::directory_iterator(pki.dir())) {
            fs::permissions(f.path(), fs::perms::owner_read | fs::perms::owner_write |
                                          fs::perms::group_read | fs::perms::others_read);
        }
        // Every layout publishes all five ports; only the encrypted-services
        // layout serves the last three.
        const auto base = kythira::testing::free_port_block(15);
        const std::array<std::array<std::uint16_t, 3>*, 5> ports{&_api, &_clients, &_kms, &_ddb,
                                                                 &_kinesis};
        const std::array<const char*, 5> names{"API", "CLIENTS", "KMS", "DDB", "KINESIS"};
        for (std::size_t p = 0; p < ports.size(); ++p) {
            for (std::size_t i = 0; i < 3; ++i) {
                (*ports[p])[i] = static_cast<std::uint16_t>(base + (3 * p) + i);
                ::setenv(std::format("KYTHIRA_HSM_CHAOS_{}_{}", names[p], i + 1).c_str(),
                         std::to_string((*ports[p])[i]).c_str(), 1);
            }
        }
        ::setenv("KYTHIRA_HSM_CHAOS_PKI_DIR", pki.dir().c_str(), 1);
        if (l == layout::co_located) {
            ::setenv("KYTHIRA_HSM_CHAOS_DAEMON", "/usr/local/bin/kythira_node", 1);
            const auto other = colocated_with();
            ::setenv("KYTHIRA_HSM_CHAOS_SERVICES",
                     (other == "none" ? std::string("hsm") : "hsm," + other).c_str(), 1);
        } else if (l == layout::encrypted_services) {
            ::setenv("KYTHIRA_HSM_CHAOS_DAEMON", "/usr/local/bin/kythira_node", 1);
            ::setenv("KYTHIRA_HSM_CHAOS_SERVICES", "hsm,kms,dynamodb,kinesis", 1);
        } else {
            ::unsetenv("KYTHIRA_HSM_CHAOS_DAEMON");
            ::unsetenv("KYTHIRA_HSM_CHAOS_SERVICES");
        }
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        os::checked_exec(os::real_exec, compose_cmd({"up", "-d"}));
        _up = {true, true, true};
        initialize(180s);
    }

    container_cluster(const container_cluster&) = delete;
    auto operator=(const container_cluster&) -> container_cluster& = delete;
    container_cluster(container_cluster&&) = delete;
    auto operator=(container_cluster&&) -> container_cluster& = delete;

    ~container_cluster() override {
        const auto id = boost::unit_test::framework::current_test_case().p_id;
        if (!boost::unit_test::results_collector.results(id).passed()) {
            for (const auto* c : k_containers) {
                std::cerr << "── " << c << " ──\n"
                          << os::real_exec(os::docker_logs_cmd(c, 300)).out;
            }
        }
        try {
            os::real_exec(compose_cmd({"down", "-v", "--remove-orphans"}));
        } catch (...) {
        }
    }

    [[nodiscard]] auto size() const -> std::size_t override { return 3; }

    [[nodiscard]] auto api_url(std::size_t i) const -> std::string override {
        return "https://localhost:" + std::to_string(_api.at(i));
    }

    [[nodiscard]] auto client_at(std::size_t i) const -> endpoint override {
        return {"127.0.0.1", _clients.at(i)};
    }

    [[nodiscard]] auto running(std::size_t i) const -> bool override { return _up.at(i); }

    [[nodiscard]] auto kms_port(std::size_t i) const -> std::uint16_t { return _kms.at(i); }
    [[nodiscard]] auto ddb_port(std::size_t i) const -> std::uint16_t { return _ddb.at(i); }
    [[nodiscard]] auto kinesis_port(std::size_t i) const -> std::uint16_t { return _kinesis.at(i); }
    [[nodiscard]] auto ca_path() const -> const std::string& { return pki.ca_path(); }

    /// Stops every member, keeping its data, and copies each one's data
    /// directory out to `into`/<container>.
    void stop_and_copy_data(const fs::path& into) {
        os::checked_exec(os::real_exec, compose_cmd({"stop"}));
        _up = {false, false, false};
        for (const auto* c : k_containers) {
            // Into a directory made first, by "/data/.": Docker and
            // Podman differ on what a copy to a missing path makes.
            const auto dest = into / c;
            fs::create_directories(dest);
            os::checked_exec(os::real_exec,
                             std::vector<std::string>{os::container_runtime(), "cp",
                                                      std::string(c) + ":/data/.", dest.string()});
        }
    }

    // A kill that fails means the container was not running: it exited on
    // its own, which is the failure worth reporting.
    void kill(std::size_t i) override {
        BOOST_TEST_MESSAGE("SIGKILL " << k_containers.at(i));
        const auto r = os::real_exec(os::docker_kill_cmd(k_containers.at(i)));
        BOOST_REQUIRE_MESSAGE(r.code == 0, k_containers.at(i) << " was not running: " << r.out);
        _up.at(i) = false;
    }

    void start(std::size_t i) override {
        BOOST_TEST_MESSAGE("start " << k_containers.at(i));
        const auto r = os::real_exec(os::docker_start_cmd(k_containers.at(i)));
        BOOST_REQUIRE_MESSAGE(r.code == 0, "start " << k_containers.at(i) << " failed: " << r.out);
        _up.at(i) = true;
    }

    void isolate(std::size_t i) {
        BOOST_TEST_MESSAGE("isolate " << k_containers.at(i));
        os::checked_exec(os::real_exec, os::network_disconnect_cmd(k_network, k_containers.at(i)));
        _up.at(i) = false;  // its published ports go with the network
    }

    void rejoin(std::size_t i) {
        BOOST_TEST_MESSAGE("rejoin " << k_containers.at(i));
        os::checked_exec(os::real_exec,
                         os::network_connect_cmd(k_network, k_containers.at(i), k_services.at(i)));
        _up.at(i) = true;
    }

private:
    std::array<std::uint16_t, 3> _api{};
    std::array<std::uint16_t, 3> _clients{};
    std::array<std::uint16_t, 3> _kms{};
    std::array<std::uint16_t, 3> _ddb{};
    std::array<std::uint16_t, 3> _kinesis{};
    std::array<bool, 3> _up{};
};

void run_scenarios(container_cluster& cl) {
    BOOST_TEST_CHECKPOINT("kill the token leader during key generation");
    hsm::test::keygen_under_leader_kill(cl);
    BOOST_TEST_CHECKPOINT("cut the token leader off during key generation");
    hsm::test::keygen_under_leader_fault(
        cl, [&](std::size_t i) { cl.isolate(i); }, [&](std::size_t i) { cl.rejoin(i); }, 5s);
    BOOST_TEST_CHECKPOINT("kill the catalog leader during rekey");
    hsm::test::rekey_under_leader_kill(cl, {15ms, 120ms});
}

// ---- the encrypted-services layout (KMS task 19) ---------------------------

namespace json = boost::json;
namespace sv4 = kythira::sigv4;

auto base64(std::string_view in) -> std::string {
    std::string out(4 * ((in.size() + 2) / 3), '\0');
    const auto n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                   reinterpret_cast<const unsigned char*>(in.data()),
                                   static_cast<int>(in.size()));
    out.resize(static_cast<std::size_t>(n));
    return out;
}

auto unbase64(std::string_view in) -> std::string {
    std::string out(3 * (in.size() / 4), '\0');
    const auto n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                   reinterpret_cast<const unsigned char*>(in.data()),
                                   static_cast<int>(in.size()));
    if (n < 0) {
        return {};
    }
    out.resize(static_cast<std::size_t>(n));
    // EVP_DecodeBlock counts the '=' padding as zero bytes.
    for (auto it = in.rbegin(); it != in.rend() && *it == '='; ++it) {
        out.pop_back();
    }
    return out;
}

auto random_bytes(std::size_t n) -> std::string {
    std::string out(n, '\0');
    BOOST_REQUIRE(RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(n)) ==
                  1);
    return out;
}

struct aws_reply {
    int status = 0;
    json::object body;
};

/// One AWS JSON protocol (X-Amz-Target) service on the members' published
/// ports, signed with SigV4 under the static key, over TLS checked against
/// the scenario's CA (each member's certificate names localhost).
class aws_service {
public:
    aws_service(std::string service, std::string target_prefix, std::string content_type,
                std::string ca)
        : _service(std::move(service)),
          _prefix(std::move(target_prefix)),
          _content_type(std::move(content_type)),
          _ca(std::move(ca)) {}

    [[nodiscard]] auto call(std::uint16_t port, std::string_view op, const json::object& in) const
        -> std::optional<aws_reply> {
        const auto body = json::serialize(in);
        const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        const auto amz_date = std::format("{:%Y%m%dT%H%M%SZ}", now);
        const auto host = "localhost:" + std::to_string(port);
        const auto target = _prefix + "." + std::string(op);
        const sv4::credential_scope scope{amz_date.substr(0, 8), k_region, _service};
        const auto canonical = "POST\n/\n\ncontent-type:" + _content_type + "\nhost:" + host +
                               "\nx-amz-date:" + amz_date + "\nx-amz-target:" + target +
                               "\n\ncontent-type;host;x-amz-date;x-amz-target\n" +
                               sv4::detail::sha256_hex(body);
        const auto to_sign = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope.text() + "\n" +
                             sv4::detail::sha256_hex(canonical);
        const auto key = sv4::derive_signing_key(k_secret_key, scope);
        const auto sig = sv4::detail::to_hex(sv4::detail::hmac_sha256(key, to_sign));

        httplib::SSLClient cli("localhost", port);
        cli.set_ca_cert_path(_ca);
        cli.enable_server_certificate_verification(true);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(20, 0);
        cli.set_write_timeout(10, 0);
        const httplib::Headers headers{
            {"X-Amz-Date", amz_date},
            {"X-Amz-Target", target},
            {"Authorization", "AWS4-HMAC-SHA256 Credential=" + std::string(k_access_key) + "/" +
                                  scope.text() +
                                  ", SignedHeaders=content-type;host;x-amz-date;x-amz-target, "
                                  "Signature=" +
                                  sig}};
        auto r = cli.Post("/", headers, body, _content_type);
        if (!r) {
            return std::nullopt;
        }
        aws_reply out;
        out.status = r->status;
        try {
            auto v = json::parse(r->body);
            if (v.is_object()) {
                out.body = std::move(v.as_object());
            }
        } catch (const std::exception&) {
            out.body["raw"] = r->body;
        }
        return out;
    }

private:
    std::string _service;
    std::string _prefix;
    std::string _content_type;
    std::string _ca;
};

/// The three services, each called on any running member, retried until
/// one answers 200 or `timeout` passes.
struct encrypted_services {
    container_cluster& cl;
    aws_service kms{"kms", "TrentService", "application/x-amz-json-1.1", cl.ca_path()};
    aws_service ddb{"dynamodb", "DynamoDB_20120810", "application/x-amz-json-1.0", cl.ca_path()};
    aws_service kinesis{"kinesis", "Kinesis_20131202", "application/x-amz-json-1.1", cl.ca_path()};

    using port_of = std::uint16_t (container_cluster::*)(std::size_t) const;

    [[nodiscard]] auto until_ok(const aws_service& svc, port_of port, std::string_view op,
                                const json::object& in, std::chrono::seconds timeout = 120s) const
        -> json::object {
        std::optional<aws_reply> last;
        const bool ok = hsm::test::eventually(
            [&] {
                for (std::size_t i = 0; i < cl.size(); ++i) {
                    if (!cl.running(i)) {
                        continue;
                    }
                    last = svc.call((cl.*port)(i), op, in);
                    if (last && last->status == 200) {
                        return true;
                    }
                }
                return false;
            },
            timeout);
        BOOST_REQUIRE_MESSAGE(
            ok, op << " never succeeded; last answer "
                   << (last ? std::to_string(last->status) + " " + json::serialize(last->body)
                            : std::string("none")));
        return last->body;
    }
};

auto str(const json::object& o, std::string_view k) -> std::string {
    const auto* v = o.if_contains(k);
    return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string();
}

/// Every file under `root`, read whole.
auto files_under(const fs::path& root) -> std::vector<std::pair<fs::path, std::string>> {
    std::vector<std::pair<fs::path, std::string>> out;
    for (const auto& e : fs::recursive_directory_iterator(root)) {
        if (!e.is_regular_file()) {
            continue;
        }
        std::ifstream in(e.path(), std::ios::binary);
        out.emplace_back(e.path(), std::string(std::istreambuf_iterator<char>(in), {}));
    }
    return out;
}

void run_encrypted_writes(container_cluster& cl) {
    // A TLS write to a member killed mid-request must fail the call, not
    // end the test with SIGPIPE.
    (void)std::signal(SIGPIPE, SIG_IGN);
    encrypted_services s{cl};
    auto kms_port = &container_cluster::kms_port;
    auto ddb_port = &container_cluster::ddb_port;
    auto kinesis_port = &container_cluster::kinesis_port;

    BOOST_TEST_CHECKPOINT("a KMS key on the HSM's token");
    const auto key =
        s.until_ok(s.kms, kms_port, "CreateKey",
                   {{"Description", "hsm chaos"}, {"KeyUsage", "ENCRYPT_DECRYPT"}}, 180s);
    const auto key_arn = str(key.at("KeyMetadata").as_object(), "Arn");
    BOOST_REQUIRE(!key_arn.empty());

    BOOST_TEST_CHECKPOINT("an encrypted table and an encrypted stream");
    (void)s.until_ok(
        s.ddb, ddb_port, "CreateTable",
        {{"TableName", "chaos"},
         {"AttributeDefinitions", json::array{{{"AttributeName", "pk"}, {"AttributeType", "S"}}}},
         {"KeySchema", json::array{{{"AttributeName", "pk"}, {"KeyType", "HASH"}}}},
         {"BillingMode", "PAY_PER_REQUEST"},
         {"SSESpecification",
          {{"Enabled", true}, {"SSEType", "KMS"}, {"KMSMasterKeyId", key_arn}}}});
    BOOST_REQUIRE(hsm::test::eventually(
        [&] {
            const auto d = s.until_ok(s.ddb, ddb_port, "DescribeTable", {{"TableName", "chaos"}});
            const auto& t = d.at("Table").as_object();
            const auto* sse = t.if_contains("SSEDescription");
            return str(t, "TableStatus") == "ACTIVE" && sse != nullptr &&
                   str(sse->as_object(), "Status") == "ENABLED";
        },
        120s));
    (void)s.until_ok(s.kinesis, kinesis_port, "CreateStream",
                     {{"StreamName", "chaos"}, {"ShardCount", 2}});
    const auto stream_status = [&] {
        const auto d =
            s.until_ok(s.kinesis, kinesis_port, "DescribeStreamSummary", {{"StreamName", "chaos"}});
        return d.at("StreamDescriptionSummary").as_object();
    };
    BOOST_REQUIRE(hsm::test::eventually(
        [&] { return str(stream_status(), "StreamStatus") == "ACTIVE"; }, 120s));
    (void)s.until_ok(s.kinesis, kinesis_port, "StartStreamEncryption",
                     {{"StreamName", "chaos"}, {"EncryptionType", "KMS"}, {"KeyId", key_arn}});
    BOOST_REQUIRE(hsm::test::eventually(
        [&] {
            const auto d = stream_status();
            return str(d, "StreamStatus") == "ACTIVE" && str(d, "EncryptionType") == "KMS";
        },
        120s));

    // Values carry a random tag so that a match on disk can only be this
    // run's write.
    const auto nonce = random_bytes(8);
    const auto tag = sv4::detail::to_hex(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size()));
    std::atomic<bool> stop{false};
    std::mutex mu;
    const auto item_value = [&](const std::string& k) { return "hsm-chaos-item-" + tag + "-" + k; };
    std::set<std::string> items;       // acknowledged PutItem keys
    std::set<std::string> records;     // acknowledged PutRecord data
    std::vector<std::string> secrets;  // data keys and encrypted plaintexts
    std::atomic<unsigned> uncertain{0};

    const auto writer = [&](auto&& one) {
        return std::thread([&, one] {
            for (unsigned n = 0; !stop.load(); ++n) {
                bool done = false;
                for (std::size_t i = 0; i < cl.size() && !done; ++i) {
                    const auto m = (n + i) % cl.size();
                    if (cl.running(m)) {
                        done = one(m, n);
                    }
                }
                if (!done) {
                    uncertain.fetch_add(1);
                    std::this_thread::sleep_for(100ms);
                }
            }
        });
    };
    std::vector<std::thread> writers;
    writers.push_back(writer([&](std::size_t m, unsigned n) {
        // Keys stay in the clear (the engine orders by them; doc/kms.md),
        // so only the value carries the searched-for prefix.
        const auto k = std::format("item-{:06}", n);
        const auto r = s.ddb.call(cl.ddb_port(m), "PutItem",
                                  {{"TableName", "chaos"},
                                   {"Item", {{"pk", {{"S", k}}}, {"v", {{"S", item_value(k)}}}}}});
        if (r && r->status == 200) {
            const std::lock_guard lock(mu);
            items.insert(k);
            return true;
        }
        return false;
    }));
    writers.push_back(writer([&](std::size_t m, unsigned n) {
        const auto v = std::format("hsm-chaos-record-{}-{:06}", tag, n);
        const auto r = s.kinesis.call(
            cl.kinesis_port(m), "PutRecord",
            {{"StreamName", "chaos"}, {"Data", base64(v)}, {"PartitionKey", std::to_string(n)}});
        if (r && r->status == 200) {
            const std::lock_guard lock(mu);
            records.insert(v);
            return true;
        }
        return false;
    }));
    writers.push_back(writer([&](std::size_t m, unsigned n) {
        std::optional<aws_reply> r;
        std::string secret;
        if (n % 2 == 0) {
            r = s.kms.call(cl.kms_port(m), "GenerateDataKey",
                           {{"KeyId", key_arn}, {"KeySpec", "AES_256"}});
            if (r && r->status == 200) {
                secret = unbase64(str(r->body, "Plaintext"));
            }
        } else {
            secret = random_bytes(32);
            r = s.kms.call(cl.kms_port(m), "Encrypt",
                           {{"KeyId", key_arn}, {"Plaintext", base64(secret)}});
        }
        if (r && r->status == 200 && secret.size() == 32) {
            const std::lock_guard lock(mu);
            secrets.push_back(secret);
            return true;
        }
        return false;
    }));

    std::this_thread::sleep_for(3s);
    const auto killed = cl.leader();
    BOOST_REQUIRE(killed.has_value());
    BOOST_TEST_CHECKPOINT("kill the HSM catalog leader under encrypted writes");
    cl.kill(*killed);
    std::this_thread::sleep_for(4s);
    cl.start(*killed);
    BOOST_REQUIRE(hsm::test::eventually([&] { return cl.status(*killed).has_value(); }, 90s));
    BOOST_REQUIRE(cl.unseal(*killed, cl.current));
    std::this_thread::sleep_for(4s);
    const auto cut = (*killed + 1) % cl.size();
    BOOST_TEST_CHECKPOINT("cut a member off under encrypted writes");
    cl.isolate(cut);
    std::this_thread::sleep_for(6s);
    cl.rejoin(cut);
    std::this_thread::sleep_for(4s);
    stop.store(true);
    for (auto& t : writers) {
        t.join();
    }
    BOOST_TEST_MESSAGE(items.size() << " items, " << records.size() << " records, "
                                    << secrets.size() << " data keys and plaintexts acknowledged, "
                                    << uncertain.load() << " uncertain");
    BOOST_TEST(items.size() >= 20U, "DynamoDB wrote around the faults");
    BOOST_TEST(records.size() >= 20U, "Kinesis wrote around the faults");
    BOOST_TEST(secrets.size() >= 20U, "the KMS answered around the faults");

    BOOST_TEST_CHECKPOINT("every acknowledged item reads back");
    std::size_t missing_items = 0;
    for (const auto& k : items) {
        const auto r = s.until_ok(
            s.ddb, ddb_port, "GetItem",
            {{"TableName", "chaos"}, {"Key", {{"pk", {{"S", k}}}}}, {"ConsistentRead", true}});
        const auto* item = r.if_contains("Item");
        if (item == nullptr || str(item->as_object().at("v").as_object(), "S") != item_value(k)) {
            ++missing_items;
            BOOST_TEST_MESSAGE("lost item " << k);
        }
    }
    BOOST_TEST(missing_items == 0U);

    BOOST_TEST_CHECKPOINT("every acknowledged record reads back");
    std::set<std::string> read;
    const auto shards =
        s.until_ok(s.kinesis, kinesis_port, "ListShards", {{"StreamName", "chaos"}});
    for (const auto& sh : shards.at("Shards").as_array()) {
        auto it = str(s.until_ok(s.kinesis, kinesis_port, "GetShardIterator",
                                 {{"StreamName", "chaos"},
                                  {"ShardId", str(sh.as_object(), "ShardId")},
                                  {"ShardIteratorType", "TRIM_HORIZON"}}),
                      "ShardIterator");
        for (unsigned empty = 0; !it.empty() && empty < 3;) {
            const auto g = s.until_ok(s.kinesis, kinesis_port, "GetRecords",
                                      {{"ShardIterator", it}, {"Limit", 1000}});
            const auto& recs = g.at("Records").as_array();
            empty = recs.empty() ? empty + 1 : 0;
            for (const auto& rec : recs) {
                BOOST_TEST(str(rec.as_object(), "EncryptionType") == "KMS");
                read.insert(unbase64(str(rec.as_object(), "Data")));
            }
            it = str(g, "NextShardIterator");
        }
    }
    std::size_t missing_records = 0;
    for (const auto& v : records) {
        if (!read.contains(v)) {
            ++missing_records;
            BOOST_TEST_MESSAGE("lost record " << v);
        }
    }
    BOOST_TEST(missing_records == 0U);

    BOOST_TEST_CHECKPOINT("no key material or value on disk");
    const auto scan =
        fs::temp_directory_path() / ("kythira-hsm-chaos-scan-" + std::to_string(::getpid()));
    fs::remove_all(scan);
    fs::create_directories(scan);
    cl.stop_and_copy_data(scan);
    const auto files = files_under(scan);
    BOOST_TEST_MESSAGE("scanning " << files.size() << " files");
    BOOST_TEST(!files.empty());
    std::size_t leaked_secrets = 0;
    std::size_t leaked_values = 0;
    std::vector<std::string> needles;
    for (const std::string prefix : {"hsm-chaos-item-", "hsm-chaos-record-"}) {
        const auto value = prefix + tag;
        needles.push_back(value);
        needles.push_back(base64(value.substr(0, value.size() / 3 * 3)));
    }
    for (const auto& [path, bytes] : files) {
        for (const auto& secret : secrets) {
            if (bytes.find(secret) != std::string::npos) {
                ++leaked_secrets;
                BOOST_TEST_MESSAGE("a data key or plaintext is in " << path);
                break;
            }
        }
        // Every value written starts with this run's prefix; a JSON
        // encoding carries it in base64, whose first 44 characters encode
        // the first 33 bytes whatever follows.
        for (const auto& needle : needles) {
            if (bytes.find(needle) == std::string::npos) {
                continue;
            }
            ++leaked_values;
            BOOST_TEST_MESSAGE("a written value is in " << path);
            break;
        }
    }
    BOOST_TEST(leaked_secrets == 0U);
    BOOST_TEST(leaked_values == 0U);
    fs::remove_all(scan);
}

}  // namespace

BOOST_AUTO_TEST_CASE(stand_alone_hsm_node) {
    container_cluster cl(layout::stand_alone);
    run_scenarios(cl);
}

BOOST_AUTO_TEST_CASE(co_located_in_kythira_node) {
    container_cluster cl(layout::co_located);
    run_scenarios(cl);
}

BOOST_AUTO_TEST_CASE(encrypted_services_in_kythira_node,
                     *boost::unit_test::precondition(has_modules({"kms", "dynamodb", "kinesis"}))) {
    container_cluster cl(layout::encrypted_services);
    run_encrypted_writes(cl);
}
