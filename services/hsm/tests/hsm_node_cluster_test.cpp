// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Three hsm_node processes (.kiro/specs/virtual-hsm/ task 11, requirements
// 2.1 and 13.5): the stand-alone daemon, mutual TLS everywhere, an operator
// who initializes, unseals and rekeys over the HTTPS API, and an
// application on the PKCS#11 wire protocol.
//
//   * kills during key generation: two clients generate token key pairs
//     through the followers while the token group's leader is SIGKILLed
//     and started again. Afterwards every replica lists the same keys,
//     every generation that answered CKR_OK is among them, every key is a
//     whole pair, and every pair signs on one node and verifies on another.
//
//   * kills during rekey: a rekey is sent to a follower and the catalog's
//     leader is SIGKILLed as it runs, at a different moment each round.
//     The follower's answer carries the new shares whether or not the
//     commit was certain; once the cluster settles every node agrees on one
//     generation, the shares of that generation unseal every node, and
//     every key still works.
//
// (Node unseal staying sealed with only k - 1 reachable members is
// hsm_node_unseal_test's.)

#define BOOST_TEST_MODULE hsm_node_cluster_test
#include "hsm_test_pki.hpp"
#include "test_ports.hpp"

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/mtls_client.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/wire_client.hpp>

#include <boost/json.hpp>
#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef HSM_NODE_PATH
#define HSM_NODE_PATH "hsm_node"
#endif

namespace hsm = kythira::hsm;
namespace fs = std::filesystem;
namespace json = boost::json;
using namespace std::chrono_literals;

namespace {

constexpr const char* k_operator = "spiffe://test/operator";
constexpr const char* k_app = "spiffe://test/app";
constexpr const char* k_app_escaped = "spiffe%3A%2F%2Ftest%2Fapp";
constexpr CK_SLOT_ID k_token = 1;
const std::string k_so_pin = "so-secret";
const std::string k_user_pin = "user-1234";

// P-256's OID, DER encoded: the EC parameters of every generated pair.
const std::vector<std::uint8_t> k_p256{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
const CK_MECHANISM k_ec_gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
const CK_MECHANISM k_ecdsa{CKM_ECDSA_SHA256, nullptr, 0};

auto rv(const auto& result) -> CK_RV {
    return result.has_value() ? CKR_OK : result.error();
}

auto bytes_of(std::string_view s) -> std::vector<std::uint8_t> {
    return {s.begin(), s.end()};
}

/// A key pair's id: the CKA_ID both halves carry.
auto key_id(unsigned client, unsigned n) -> std::string {
    return "c" + std::to_string(client) + "-" + std::to_string(n);
}

auto slurp(const fs::path& p) -> std::string {
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

struct member {
    int n = 0;
    std::uint16_t raft = 0;
    std::uint16_t api = 0;
    std::uint16_t clients = 0;
    std::uint16_t metrics = 0;
    pid_t pid = -1;
    hsm::test::test_pki::files tls;

    [[nodiscard]] auto api_url() const -> std::string {
        return "https://localhost:" + std::to_string(api);
    }
};

/// The operator's answer: status and parsed body.
struct answer {
    unsigned status = 0;
    json::value body;

    [[nodiscard]] auto obj() const -> const json::object& { return body.as_object(); }
    [[nodiscard]] auto flag(std::string_view key) const -> bool {
        const auto* v = body.is_object() ? body.as_object().if_contains(key) : nullptr;
        return v != nullptr && v->is_bool() && v->as_bool();
    }
};

/// The current master key's shares and the generation they belong to.
struct share_set {
    std::uint64_t generation = 0;
    std::vector<std::string> shares;
};

auto shares_of(const answer& a) -> std::optional<share_set> {
    if (!a.body.is_object()) {
        return std::nullopt;
    }
    const auto* list = a.obj().if_contains("shares");
    const auto* gen = a.obj().if_contains("generation");
    if (list == nullptr || gen == nullptr || !list->is_array()) {
        return std::nullopt;
    }
    share_set out;
    out.generation = gen->to_number<std::uint64_t>();
    for (const auto& s : list->as_array()) {
        out.shares.emplace_back(s.as_string());
    }
    return out;
}

class cluster {
public:
    cluster() {
        std::random_device rd;
        _dir = fs::temp_directory_path() / ("kythira-hsm-cluster-" + std::to_string(rd()));
        fs::create_directories(_dir);
        const auto base = kythira::testing::free_port_block(12);
        for (int i = 0; i < 3; ++i) {
            member m;
            m.n = i + 1;
            const auto b = static_cast<std::uint16_t>(base + 4 * i);
            m.raft = b;
            m.api = b + 1;
            m.clients = b + 2;
            m.metrics = b + 3;
            m.tls = _pki.issue("node-" + std::to_string(m.n),
                               "DNS:localhost,IP:127.0.0.1,URI:" + identity(m.n));
            members.push_back(m);
        }
        _operator = _pki.issue("operator", std::string("URI:") + k_operator);
        _app = _pki.issue("app", std::string("URI:") + k_app);
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;
    cluster(cluster&&) = delete;
    auto operator=(cluster&&) -> cluster& = delete;

    ~cluster() {
        for (auto& m : members) {
            stop(m);
        }
        if (std::getenv("KYTHIRA_HSM_CLUSTER_TEST_KEEP") == nullptr) {
            std::error_code ec;
            fs::remove_all(_dir, ec);
        }
    }

    static auto identity(int n) -> std::string { return "spiffe://hsm/node-" + std::to_string(n); }

    void start(member& m) {
        const auto list = [&](const std::string& prefix, auto port_of) {
            std::string out;
            for (const auto& q : members) {
                out += (out.empty() ? "" : ",") + std::to_string(q.n) + "=" + prefix +
                       std::to_string(port_of(q));
            }
            return out;
        };
        std::string peers;
        for (const auto& q : members) {
            peers += (peers.empty() ? "" : ",") + identity(q.n);
        }
        const auto dir = _dir / ("node-" + std::to_string(m.n));
        fs::create_directories(dir);
        const std::vector<std::string> env{
            "KYTHIRA_NODE_ID=" + std::to_string(m.n),
            "KYTHIRA_NODE_DATA_DIR=" + (dir / "data").string(),
            "KYTHIRA_NODE_PEERS=" + list("127.0.0.1:", [](const auto& q) { return q.raft; }),
            "KYTHIRA_NODE_RAFT_BIND=127.0.0.1",
            "KYTHIRA_NODE_RAFT_PORT=" + std::to_string(m.raft),
            "KYTHIRA_NODE_TLS_CERT=" + m.tls.cert,
            "KYTHIRA_NODE_TLS_KEY=" + m.tls.key,
            "KYTHIRA_NODE_TLS_CA=" + _pki.ca_path(),
            "KYTHIRA_NODE_METRICS_BIND=127.0.0.1",
            "KYTHIRA_NODE_METRICS_PORT=" + std::to_string(m.metrics),
            "KYTHIRA_HSM_API_LISTEN=127.0.0.1:" + std::to_string(m.api),
            "KYTHIRA_HSM_API_URLS=" +
                list("https://localhost:", [](const auto& q) { return q.api; }),
            "KYTHIRA_HSM_PEER_IDENTITIES=" + peers,
            std::string("KYTHIRA_HSM_OPERATORS=") + k_operator,
            "KYTHIRA_HSM_CLIENT_LISTEN=127.0.0.1:" + std::to_string(m.clients),
            // CI runners cap RLIMIT_MEMLOCK; cheap PIN verifiers keep the
            // logins of many short sessions fast.
            "KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY=true",
            "KYTHIRA_HSM_PIN_COST_LOG2=10",
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
            envp.reserve(env.size() + 1);
            for (const auto& e : env) {
                envp.push_back(
                    const_cast<char*>(e.c_str()));  // NOLINT(cppcoreguidelines-pro-type-const-cast)
            }
            envp.push_back(nullptr);
            std::array<char*, 2> argv{const_cast<char*>(HSM_NODE_PATH),
                                      nullptr};  // NOLINT(cppcoreguidelines-pro-type-const-cast)
            ::execve(argv[0], argv.data(), envp.data());
            ::_exit(127);
        }
        m.pid = pid;
    }

    static void stop(member& m) {
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
        BOOST_ERROR("hsm_node " << m.n << " ignored SIGTERM; killing it");
        kill(m);
    }

    static void kill(member& m) {
        if (m.pid <= 0) {
            return;
        }
        ::kill(m.pid, SIGKILL);
        int status = 0;
        ::waitpid(m.pid, &status, 0);
        m.pid = -1;
    }

    /// One operator request to `m`; nothing when the exchange failed.
    [[nodiscard]] auto admin(const member& m, std::string_view method, const std::string& target,
                             std::string body = {}) const -> std::optional<answer> {
        hsm::peer_client_config cfg;
        cfg.cert_path = _operator.cert;
        cfg.key_path = _operator.key;
        cfg.ca_path = _pki.ca_path();
        cfg.timeout = 15s;
        const hsm::mtls_client client(cfg);
        auto r = client.request(method, m.api_url(), target, std::move(body), "application/json",
                                "hsm_node_cluster_test");
        if (!r) {
            return std::nullopt;
        }
        answer a;
        a.status = r->first;
        try {
            a.body = json::parse(r->second);
        } catch (const std::exception&) {
            a.body = json::string(r->second);
        }
        return a;
    }

    [[nodiscard]] auto status(const member& m) const -> std::optional<answer> {
        auto a = admin(m, "GET", "/v1/status");
        return a && a->status == 200 && a->body.is_object() ? a : std::nullopt;
    }

    /// Polls `ready` until it holds or `timeout` passes.
    static auto eventually(const std::function<bool()>& ready, std::chrono::seconds timeout)
        -> bool {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (ready()) {
                return true;
            }
            std::this_thread::sleep_for(100ms);
        }
        return ready();
    }

    /// The member leading the catalog (or token `token`'s group), once one
    /// says so.
    auto leader(std::optional<std::uint64_t> token = std::nullopt,
                std::chrono::seconds timeout = 60s) -> member* {
        member* found = nullptr;
        eventually(
            [&] {
                for (auto& m : members) {
                    if (m.pid <= 0) {
                        continue;
                    }
                    if (!token) {
                        if (auto s = status(m); s && s->flag("catalog_leader")) {
                            found = &m;
                            return true;
                        }
                        continue;
                    }
                    auto t = admin(m, "GET", "/v1/tokens");
                    if (!t || t->status != 200) {
                        continue;
                    }
                    for (const auto& e : t->obj().at("tokens").as_array()) {
                        const auto& o = e.as_object();
                        if (o.at("id").to_number<std::uint64_t>() == *token &&
                            o.at("leader").as_bool()) {
                            found = &m;
                            return true;
                        }
                    }
                }
                return false;
            },
            timeout);
        return found;
    }

    /// Unseals `m` with the first k of `set`, retrying while it catches up
    /// to the generation the shares belong to.
    auto unseal(const member& m, const share_set& set, std::chrono::seconds timeout = 60s) -> bool {
        return eventually(
            [&] {
                auto s = status(m);
                if (!s) {
                    return false;
                }
                if (!s->flag("sealed")) {
                    return true;
                }
                const auto* gen = s->obj().if_contains("generation");
                if (gen == nullptr || gen->to_number<std::uint64_t>() != set.generation) {
                    return false;  // not yet applied the entry these shares are for
                }
                (void)admin(m, "DELETE", "/v1/unseal");
                for (std::size_t i = 0; i < 2 && i < set.shares.size(); ++i) {
                    json::object body;
                    body["share"] = set.shares[i];
                    auto r = admin(m, "POST", "/v1/unseal", json::serialize(body));
                    if (r && r->status == 200 && !r->flag("sealed")) {
                        return true;
                    }
                }
                return false;
            },
            timeout);
    }

    /// A PKCS#11 client on `m`'s mutual TLS listener, as the application.
    [[nodiscard]] auto client(const member& m) const -> std::unique_ptr<hsm::wire_client> {
        hsm::wire::tls_client_config tc;
        tc.host = "127.0.0.1";
        tc.port = m.clients;
        tc.cert_path = _app.cert;
        tc.key_path = _app.key;
        tc.ca_path = _pki.ca_path();
        auto conn = hsm::wire::connection::tls(tc, 10s);
        if (!conn) {
            return nullptr;
        }
        return std::make_unique<hsm::wire_client>(std::move(conn));
    }

    /// Starts every member, initializes the HSM in operator mode (k = 2,
    /// n = 3), unseals every member, creates token 1 for the application
    /// and sets its PINs. The shares are kept in `current`.
    void bring_up() {
        for (auto& m : members) {
            start(m);
        }
        for (const auto& m : members) {
            BOOST_REQUIRE_MESSAGE(eventually([&] { return status(m).has_value(); }, 60s),
                                  "member " << m.n << " never answered");
        }
        BOOST_REQUIRE(leader() != nullptr);
        std::optional<share_set> shares;
        BOOST_REQUIRE(eventually(
            [&] {
                auto r =
                    admin(members[0], "POST", "/v1/init", R"({"mode":"operator","k":2,"n":3})");
                if (r && (r->status == 200 || r->status == 201)) {
                    shares = shares_of(*r);
                }
                return shares.has_value();
            },
            60s));
        current = *shares;
        for (const auto& m : members) {
            BOOST_REQUIRE_MESSAGE(unseal(m, current), "member " << m.n << " stayed sealed");
        }
        BOOST_REQUIRE(eventually(
            [&] {
                auto r = admin(members[0], "POST", "/v1/tokens", R"({"id":1,"label":"alpha"})");
                return r && (r->status == 200 || r->status == 201);
            },
            60s));
        BOOST_REQUIRE(eventually(
            [&] {
                auto r =
                    admin(members[0], "PUT", std::string("/v1/tokens/1/bindings/") + k_app_escaped);
                return r && (r->status == 200 || r->status == 201 || r->status == 204);
            },
            60s));
        BOOST_REQUIRE(eventually(
            [&] {
                auto c = client(members[0]);
                if (!c || rv(c->init_token(k_token, k_so_pin, "alpha")) != CKR_OK) {
                    return false;
                }
                auto s = c->open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
                return s && rv(c->login(*s, CKU_SO, k_so_pin)) == CKR_OK &&
                       rv(c->init_pin(*s, k_user_pin)) == CKR_OK;
            },
            60s));
    }

    void dump_logs() const {
        for (const auto& m : members) {
            const auto log = slurp(_dir / ("node-" + std::to_string(m.n)) / "node.log");
            const auto tail = log.size() > 6000 ? log.substr(log.size() - 6000) : log;
            BOOST_TEST_MESSAGE("---- hsm_node " << m.n << " log tail ----\n" << tail);
        }
    }

    std::vector<member> members;
    share_set current;

private:
    fs::path _dir;
    hsm::test::test_pki _pki;
    hsm::test::test_pki::files _operator;
    hsm::test::test_pki::files _app;
};

/// A logged-in user session on one member.
struct user_session {
    std::unique_ptr<hsm::wire_client> c;
    CK_SESSION_HANDLE s = 0;

    static auto open(const cluster& cl, const member& m) -> std::optional<user_session> {
        user_session u;
        u.c = cl.client(m);
        if (!u.c) {
            return std::nullopt;
        }
        auto s = u.c->open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        if (!s) {
            return std::nullopt;
        }
        u.s = *s;
        const auto login = rv(u.c->login(u.s, CKU_USER, k_user_pin));
        if (login != CKR_OK && login != CKR_USER_ALREADY_LOGGED_IN) {
            return std::nullopt;
        }
        return u;
    }

    /// A token key pair whose halves carry `id`.
    auto generate(const std::string& id) -> CK_RV {
        hsm::attribute_map pub;
        pub.set_bool(CKA_TOKEN, true);
        pub.set_bytes(CKA_EC_PARAMS, k_p256);
        pub.set_bool(CKA_VERIFY, true);
        pub.set_bytes(CKA_ID, bytes_of(id));
        hsm::attribute_map priv;
        priv.set_bool(CKA_TOKEN, true);
        priv.set_bool(CKA_SIGN, true);
        priv.set_bool(CKA_PRIVATE, true);
        priv.set_bool(CKA_SENSITIVE, true);
        priv.set_bytes(CKA_ID, bytes_of(id));
        return rv(c->generate_key_pair(s, k_ec_gen, pub, priv));
    }

    /// Every object of `cls`, by CKA_ID; nothing when a call failed.
    auto by_id(CK_OBJECT_CLASS cls) -> std::optional<std::map<std::string, CK_OBJECT_HANDLE>> {
        hsm::attribute_map tmpl;
        tmpl.set_ulong(CKA_CLASS, cls);
        if (rv(c->find_objects_init(s, tmpl)) != CKR_OK) {
            return std::nullopt;
        }
        std::vector<CK_OBJECT_HANDLE> handles;
        for (;;) {
            auto batch = c->find_objects(s, 64);
            if (!batch) {
                return std::nullopt;
            }
            if (batch->empty()) {
                break;
            }
            handles.insert(handles.end(), batch->begin(), batch->end());
        }
        (void)c->find_objects_final(s);
        std::map<std::string, CK_OBJECT_HANDLE> out;
        for (const auto h : handles) {
            const std::array<CK_ATTRIBUTE_TYPE, 1> types{CKA_ID};
            auto attrs = c->get_attribute_value(s, h, types);
            if (!attrs || attrs->size() != 1 || attrs->front().rv != CKR_OK ||
                !attrs->front().value) {
                return std::nullopt;
            }
            const auto& id = *attrs->front().value;
            if (!out.emplace(std::string(id.begin(), id.end()), h).second) {
                return std::nullopt;  // two objects of one class with one id
            }
        }
        return out;
    }

    auto sign(CK_OBJECT_HANDLE key, const std::vector<std::uint8_t>& data)
        -> std::optional<std::vector<std::uint8_t>> {
        if (rv(c->sign_init(s, k_ecdsa, key)) != CKR_OK) {
            return std::nullopt;
        }
        auto sig = c->sign(s, data);
        return sig ? std::optional(*sig) : std::nullopt;
    }

    auto verify(CK_OBJECT_HANDLE key, const std::vector<std::uint8_t>& data,
                const std::vector<std::uint8_t>& sig) -> CK_RV {
        if (auto r = rv(c->verify_init(s, k_ecdsa, key)); r != CKR_OK) {
            return r;
        }
        return rv(c->verify(s, data, sig));
    }
};

/// What every member holds: the ids of its private and public keys.
struct replica_view {
    std::map<std::string, CK_OBJECT_HANDLE> priv;
    std::map<std::string, CK_OBJECT_HANDLE> pub;
};

auto ids(const std::map<std::string, CK_OBJECT_HANDLE>& m) -> std::set<std::string> {
    std::set<std::string> out;
    for (const auto& [id, h] : m) {
        out.insert(id);
    }
    return out;
}

/// Checks that every member lists the same whole pairs, that `confirmed`
/// are all among them, and that each pair signs on one member and
/// verifies on the next. Returns the number of pairs.
auto check_keys(cluster& cl, const std::set<std::string>& confirmed) -> std::size_t {
    std::vector<replica_view> views(cl.members.size());
    std::vector<std::optional<user_session>> sessions(cl.members.size());
    const bool agreed = cluster::eventually(
        [&] {
            for (std::size_t i = 0; i < cl.members.size(); ++i) {
                sessions[i] = user_session::open(cl, cl.members[i]);
                if (!sessions[i]) {
                    return false;
                }
                auto priv = sessions[i]->by_id(CKO_PRIVATE_KEY);
                auto pub = sessions[i]->by_id(CKO_PUBLIC_KEY);
                if (!priv || !pub) {
                    return false;
                }
                views[i] = {std::move(*priv), std::move(*pub)};
            }
            for (std::size_t i = 1; i < views.size(); ++i) {
                if (ids(views[i].priv) != ids(views[0].priv) ||
                    ids(views[i].pub) != ids(views[0].pub)) {
                    return false;
                }
            }
            return true;
        },
        60s);
    BOOST_REQUIRE_MESSAGE(agreed, "the replicas never agreed on the token's keys");
    const auto priv_ids = ids(views[0].priv);
    BOOST_TEST((priv_ids == ids(views[0].pub)), "every key is a whole pair");
    for (const auto& id : confirmed) {
        BOOST_TEST(priv_ids.contains(id), "acknowledged key " << id << " is on every replica");
    }
    std::size_t i = 0;
    for (const auto& id : priv_ids) {
        auto& signer = *sessions[i % sessions.size()];
        auto& verifier = *sessions[(i + 1) % sessions.size()];
        const auto data = bytes_of("signed by " + id);
        const auto sig = signer.sign(views[i % views.size()].priv.at(id), data);
        BOOST_TEST(sig.has_value(), "key " << id << " signs");
        if (sig) {
            BOOST_TEST(
                verifier.verify(views[(i + 1) % views.size()].pub.at(id), data, *sig) == CKR_OK,
                "key " << id << "'s signature verifies on another member");
        }
        ++i;
    }
    return priv_ids.size();
}

struct fixture : cluster {
    fixture() { bring_up(); }
    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;
    fixture(fixture&&) = delete;
    auto operator=(fixture&&) -> fixture& = delete;
    ~fixture() {
        const auto id = boost::unit_test::framework::current_test_case().p_id;
        if (!boost::unit_test::results_collector.results(id).passed()) {
            dump_logs();
        }
    }
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(the_token_leader_killed_during_key_generation, fixture) {
    member* leader = this->leader(k_token);
    BOOST_REQUIRE(leader != nullptr);
    std::vector<member*> followers;
    for (auto& m : members) {
        if (&m != leader) {
            followers.push_back(&m);
        }
    }

    // Two clients, one on each follower, generate until told to stop.
    std::atomic<bool> stop{false};
    std::mutex mu;
    std::set<std::string> confirmed;
    std::atomic<unsigned> failed{0};
    std::vector<std::thread> clients;
    for (unsigned c = 0; c < followers.size(); ++c) {
        clients.emplace_back([&, c] {
            std::optional<user_session> u;
            for (unsigned n = 0; !stop.load() && n < 60; ++n) {
                if (!u || u->c->transport_failed()) {
                    u = user_session::open(*this, *followers[c]);
                    if (!u) {
                        std::this_thread::sleep_for(100ms);
                        continue;
                    }
                }
                const auto id = key_id(c, n);
                if (u->generate(id) == CKR_OK) {
                    const std::lock_guard lock(mu);
                    confirmed.insert(id);
                } else {
                    failed.fetch_add(1);  // uncertain: the pair may or may not exist
                }
            }
        });
    }

    std::this_thread::sleep_for(400ms);
    BOOST_TEST_MESSAGE("killing token leader " << leader->n);
    cluster::kill(*leader);
    std::this_thread::sleep_for(1500ms);
    start(*leader);
    BOOST_REQUIRE(eventually([&] { return status(*leader).has_value(); }, 60s));
    // Operator mode: a restarted member is sealed until it gets k shares.
    BOOST_REQUIRE(unseal(*leader, current));
    std::this_thread::sleep_for(500ms);
    stop.store(true);
    for (auto& t : clients) {
        t.join();
    }

    BOOST_TEST_MESSAGE(confirmed.size()
                       << " generations acknowledged, " << failed.load() << " uncertain");
    BOOST_TEST(confirmed.size() >= 4U, "generation went on around the kill");
    const auto pairs = check_keys(*this, confirmed);
    BOOST_TEST(pairs >= confirmed.size());
}

BOOST_FIXTURE_TEST_CASE(the_catalog_leader_killed_during_rekey, fixture) {
    // A few keys under the first master key.
    std::set<std::string> confirmed;
    {
        auto u = user_session::open(*this, members[0]);
        BOOST_REQUIRE(u.has_value());
        for (unsigned n = 0; n < 3; ++n) {
            BOOST_REQUIRE(u->generate(key_id(9, n)) == CKR_OK);
            confirmed.insert(key_id(9, n));
        }
    }

    // A different moment each round: before the request reaches the
    // leader, as it proposes, and around the commit.
    for (const auto delay : {0ms, 15ms, 40ms, 120ms}) {
        BOOST_TEST_CONTEXT("kill after " << delay.count() << " ms") {
            member* leader = this->leader();
            BOOST_REQUIRE(leader != nullptr);
            member* via = &members[(leader - members.data() + 1) % members.size()];
            const auto before = current.generation;

            std::optional<answer> reply;
            std::thread rekey([&] { reply = admin(*via, "POST", "/v1/rekey", "{}"); });
            std::this_thread::sleep_for(delay);
            cluster::kill(*leader);
            rekey.join();
            start(*leader);

            // The follower's answer: 200 (committed) or 503 with shares
            // (uncertain) carry the new set; anything else means no rekey.
            std::optional<share_set> offered;
            if (reply && (reply->status == 200 || reply->status == 503)) {
                offered = shares_of(*reply);
            }
            BOOST_TEST_MESSAGE("rekey via " << via->n << " answered "
                                            << (reply ? reply->status : 0U)
                                            << (offered ? " with shares" : ""));
            if (reply && reply->status == 200) {
                BOOST_TEST(offered.has_value());
            }

            // A catalog write through the follower that took the rekey: once
            // it commits under the new leader, every entry before it is
            // decided, the rekey included if it reached the log (an entry of
            // the old term may commit only after the election, so a quiet
            // status read is not enough). The follower has applied the write,
            // so its generation is the settled one.
            BOOST_REQUIRE(eventually(
                [&] {
                    auto r =
                        admin(*via, "PUT", std::string("/v1/tokens/1/bindings/") + k_app_escaped);
                    return r && r->status == 200;
                },
                90s));
            const auto settled = status(*via);
            BOOST_REQUIRE(settled.has_value());
            const auto agreed = settled->obj().at("generation").to_number<std::uint64_t>();
            BOOST_TEST_MESSAGE("generation " << before << " -> " << agreed);
            BOOST_REQUIRE((agreed == before || agreed == before + 1));
            if (agreed == before + 1) {
                BOOST_REQUIRE_MESSAGE(offered && offered->generation == agreed,
                                      "the rekey committed and its shares were handed out");
                current = *offered;
            }
            // Every member reaches that generation and opens with its shares.
            for (const auto& m : members) {
                BOOST_REQUIRE_MESSAGE(unseal(m, current), "member " << m.n
                                                                    << " unsealed with generation "
                                                                    << current.generation);
            }
            check_keys(*this, confirmed);
        }
    }
}
