// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// A three-member HSM cluster driven from outside, as an operator and an
// application would (.kiro/specs/virtual-hsm/ task 11): the operator API
// over HTTPS with the operator's certificate, PKCS#11 over the wire
// protocol with the application's. How members run, die and restart is
// the subclass's: processes for hsm_node_cluster_test, containers for the
// docker-chaos scenario. The scenarios both share live here too:
//
//   * keygen_under_leader_fault: two clients generate token key pairs
//     through the followers while the token group's leader is killed and
//     started again (keygen_under_leader_kill) or, in containers, cut off
//     the network and joined again;
//   * rekey_under_leader_kill: a rekey through a follower while the
//     catalog's leader is killed, at several moments;
//
// and check_keys, which each ends with: every replica lists the same whole
// key pairs, every acknowledged generation is among them, and each pair
// signs on one member and verifies on another.

#include "hsm_test_pki.hpp"

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/mtls_client.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/wire_client.hpp>

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::hsm::test {

inline constexpr const char* k_cluster_operator = "spiffe://test/operator";
inline constexpr const char* k_cluster_app = "spiffe://test/app";
inline constexpr const char* k_cluster_app_escaped = "spiffe%3A%2F%2Ftest%2Fapp";
inline constexpr CK_SLOT_ID k_cluster_token = 1;
inline const std::string k_cluster_so_pin = "so-secret";
inline const std::string k_cluster_user_pin = "user-1234";

/// A member's identity: the first URI SAN of its certificate.
inline auto member_identity(std::size_t i) -> std::string {
    return "spiffe://hsm/node-" + std::to_string(i + 1);
}

/// The operator's answer: status and parsed body.
struct answer {
    unsigned status = 0;
    boost::json::value body;

    [[nodiscard]] auto obj() const -> const boost::json::object& { return body.as_object(); }
    [[nodiscard]] auto flag(std::string_view key) const -> bool {
        const auto* v = body.is_object() ? body.as_object().if_contains(key) : nullptr;
        return v != nullptr && v->is_bool() && v->as_bool();
    }
};

/// A master key's shares and the generation they belong to.
struct share_set {
    std::uint64_t generation = 0;
    std::vector<std::string> shares;
};

inline auto shares_of(const answer& a) -> std::optional<share_set> {
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

inline auto cluster_rv(const auto& result) -> CK_RV {
    return result.has_value() ? CKR_OK : result.error();
}

/// Polls `ready` until it holds or `timeout` passes.
inline auto eventually(const std::function<bool()>& ready, std::chrono::seconds timeout) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (ready()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    return ready();
}

class cluster_driver {
public:
    struct endpoint {
        std::string host;
        std::uint16_t port = 0;
    };

    /// The operator's and the application's certificates come from `pki`,
    /// which must outlive the driver.
    explicit cluster_driver(test_pki& pki)
        : _pki(&pki),
          _operator(pki.issue("operator", std::string("URI:") + k_cluster_operator)),
          _app(pki.issue("app", std::string("URI:") + k_cluster_app)) {}

    cluster_driver(const cluster_driver&) = delete;
    auto operator=(const cluster_driver&) -> cluster_driver& = delete;
    cluster_driver(cluster_driver&&) = delete;
    auto operator=(cluster_driver&&) -> cluster_driver& = delete;
    virtual ~cluster_driver() = default;

    [[nodiscard]] virtual auto size() const -> std::size_t = 0;
    /// "https://host:port" of member i's operator API, as this side dials it.
    [[nodiscard]] virtual auto api_url(std::size_t i) const -> std::string = 0;
    /// Member i's PKCS#11 client listener, as this side dials it; the
    /// member's certificate names `host`.
    [[nodiscard]] virtual auto client_at(std::size_t i) const -> endpoint = 0;
    /// SIGKILL member i (its data stays) and start it again.
    virtual void kill(std::size_t i) = 0;
    virtual void start(std::size_t i) = 0;
    [[nodiscard]] virtual auto running(std::size_t i) const -> bool = 0;
    /// Whether member i has the crypto role (hsm-independent-layers): a
    /// store-only member is never unsealed and serves no client.
    [[nodiscard]] virtual auto crypto(std::size_t /*i*/) const -> bool { return true; }

    /// One operator request to member i; nothing when the exchange failed.
    [[nodiscard]] auto admin(std::size_t i, std::string_view method, const std::string& target,
                             std::string body = {}) const -> std::optional<answer> {
        peer_client_config cfg;
        cfg.cert_path = _operator.cert;
        cfg.key_path = _operator.key;
        cfg.ca_path = _pki->ca_path();
        cfg.timeout = std::chrono::seconds{15};
        const mtls_client client(cfg);
        auto r = client.request(method, api_url(i), target, std::move(body), "application/json",
                                "hsm_test_cluster");
        if (!r) {
            return std::nullopt;
        }
        answer a;
        a.status = r->first;
        try {
            a.body = boost::json::parse(r->second);
        } catch (const std::exception&) {
            a.body = boost::json::string(r->second);
        }
        return a;
    }

    [[nodiscard]] auto status(std::size_t i) const -> std::optional<answer> {
        auto a = admin(i, "GET", "/v1/status");
        return a && a->status == 200 && a->body.is_object() ? a : std::nullopt;
    }

    /// The member leading the catalog (or token `token`'s group), once one
    /// says so.
    [[nodiscard]] auto leader(std::optional<std::uint64_t> token = std::nullopt,
                              std::chrono::seconds timeout = std::chrono::seconds{60}) const
        -> std::optional<std::size_t> {
        std::optional<std::size_t> found;
        eventually(
            [&] {
                for (std::size_t i = 0; i < size(); ++i) {
                    if (!running(i)) {
                        continue;
                    }
                    if (!token) {
                        if (auto s = status(i); s && s->flag("catalog_leader")) {
                            found = i;
                            return true;
                        }
                        continue;
                    }
                    auto t = admin(i, "GET", "/v1/tokens");
                    if (!t || t->status != 200 || !t->body.is_object()) {
                        continue;
                    }
                    for (const auto& e : t->obj().at("tokens").as_array()) {
                        const auto& o = e.as_object();
                        if (o.at("id").to_number<std::uint64_t>() == *token &&
                            o.at("leader").as_bool()) {
                            found = i;
                            return true;
                        }
                    }
                }
                return false;
            },
            timeout);
        return found;
    }

    /// Unseals member i with the first k of `set`, retrying while it
    /// catches up to the generation the shares belong to.
    [[nodiscard]] auto unseal(std::size_t i, const share_set& set,
                              std::chrono::seconds timeout = std::chrono::seconds{60}) const
        -> bool {
        return eventually(
            [&] {
                auto s = status(i);
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
                (void)admin(i, "DELETE", "/v1/unseal");
                for (std::size_t k = 0; k < 2 && k < set.shares.size(); ++k) {
                    boost::json::object body;
                    body["share"] = set.shares[k];
                    auto r = admin(i, "POST", "/v1/unseal", boost::json::serialize(body));
                    if (r && r->status == 200 && !r->flag("sealed")) {
                        return true;
                    }
                }
                return false;
            },
            timeout);
    }

    /// A PKCS#11 client on member i's mutual TLS listener, as the
    /// application.
    [[nodiscard]] auto client(std::size_t i) const -> std::unique_ptr<wire_client> {
        const auto at = client_at(i);
        wire::tls_client_config tc;
        tc.host = at.host;
        tc.port = at.port;
        tc.cert_path = _app.cert;
        tc.key_path = _app.key;
        tc.ca_path = _pki->ca_path();
        auto conn = wire::connection::tls(tc, std::chrono::seconds{10});
        if (!conn) {
            return nullptr;
        }
        return std::make_unique<wire_client>(std::move(conn));
    }

    /// With every member running: initializes the HSM in operator mode
    /// (k = 2, n = 3) through member 0, unseals every crypto member, creates
    /// token 1 for the application and sets its PINs. The shares are kept
    /// in `current`.
    void initialize(std::chrono::seconds timeout = std::chrono::seconds{120}) {
        for (std::size_t i = 0; i < size(); ++i) {
            BOOST_REQUIRE_MESSAGE(eventually([&] { return status(i).has_value(); }, timeout),
                                  "member " << i + 1 << " never answered");
        }
        BOOST_REQUIRE(leader(std::nullopt, timeout).has_value());
        std::optional<share_set> shares;
        BOOST_REQUIRE(eventually(
            [&] {
                auto r = admin(0, "POST", "/v1/init", R"({"mode":"operator","k":2,"n":3})");
                if (r && (r->status == 200 || r->status == 201)) {
                    shares = shares_of(*r);
                }
                return shares.has_value();
            },
            timeout));
        current = *shares;
        for (std::size_t i = 0; i < size(); ++i) {
            if (crypto(i)) {
                BOOST_REQUIRE_MESSAGE(unseal(i, current), "member " << i + 1 << " stayed sealed");
            }
        }
        BOOST_REQUIRE(eventually(
            [&] {
                auto r = admin(0, "POST", "/v1/tokens", R"({"id":1,"label":"alpha"})");
                return r && (r->status == 200 || r->status == 201);
            },
            timeout));
        BOOST_REQUIRE(bind_app(0, timeout));
        BOOST_REQUIRE(eventually(
            [&] {
                auto c = client(0);
                if (!c || cluster_rv(c->init_token(k_cluster_token, k_cluster_so_pin, "alpha")) !=
                              CKR_OK) {
                    return false;
                }
                auto s = c->open_session(k_cluster_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
                return s && cluster_rv(c->login(*s, CKU_SO, k_cluster_so_pin)) == CKR_OK &&
                       cluster_rv(c->init_pin(*s, k_cluster_user_pin)) == CKR_OK;
            },
            timeout));
    }

    /// Binds the application to token 1 through member i: a catalog write,
    /// so once it answers every entry before it has been decided.
    [[nodiscard]] auto bind_app(std::size_t i, std::chrono::seconds timeout) const -> bool {
        return eventually(
            [&] {
                auto r =
                    admin(i, "PUT", std::string("/v1/tokens/1/bindings/") + k_cluster_app_escaped);
                return r && r->status == 200;
            },
            timeout);
    }

    share_set current;

private:
    test_pki* _pki;
    test_pki::files _operator;
    test_pki::files _app;
};

/// A logged-in user session on one member.
struct user_session {
    std::unique_ptr<wire_client> c;
    CK_SESSION_HANDLE s = 0;

    static auto open(const cluster_driver& cl, std::size_t i) -> std::optional<user_session> {
        user_session u;
        u.c = cl.client(i);
        if (!u.c) {
            return std::nullopt;
        }
        auto s = u.c->open_session(k_cluster_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        if (!s) {
            return std::nullopt;
        }
        u.s = *s;
        const auto login = cluster_rv(u.c->login(u.s, CKU_USER, k_cluster_user_pin));
        if (login != CKR_OK && login != CKR_USER_ALREADY_LOGGED_IN) {
            return std::nullopt;
        }
        return u;
    }

    /// A token key pair on P-256 whose halves carry `id`.
    auto generate(const std::string& id) -> CK_RV {
        static const std::vector<std::uint8_t> p256{0x06, 0x08, 0x2a, 0x86, 0x48,
                                                    0xce, 0x3d, 0x03, 0x01, 0x07};
        static const CK_MECHANISM ec_gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
        const std::vector<std::uint8_t> id_bytes(id.begin(), id.end());
        attribute_map pub;
        pub.set_bool(CKA_TOKEN, true);
        pub.set_bytes(CKA_EC_PARAMS, p256);
        pub.set_bool(CKA_VERIFY, true);
        pub.set_bytes(CKA_ID, id_bytes);
        attribute_map priv;
        priv.set_bool(CKA_TOKEN, true);
        priv.set_bool(CKA_SIGN, true);
        priv.set_bool(CKA_PRIVATE, true);
        priv.set_bool(CKA_SENSITIVE, true);
        priv.set_bytes(CKA_ID, id_bytes);
        return cluster_rv(c->generate_key_pair(s, ec_gen, pub, priv));
    }

    /// Every object of `cls`, by CKA_ID; nothing when a call failed.
    auto by_id(CK_OBJECT_CLASS cls) -> std::optional<std::map<std::string, CK_OBJECT_HANDLE>> {
        attribute_map tmpl;
        tmpl.set_ulong(CKA_CLASS, cls);
        if (cluster_rv(c->find_objects_init(s, tmpl)) != CKR_OK) {
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
        static const CK_MECHANISM ecdsa{CKM_ECDSA_SHA256, nullptr, 0};
        if (cluster_rv(c->sign_init(s, ecdsa, key)) != CKR_OK) {
            return std::nullopt;
        }
        auto sig = c->sign(s, data);
        return sig ? std::optional(*sig) : std::nullopt;
    }

    auto verify(CK_OBJECT_HANDLE key, const std::vector<std::uint8_t>& data,
                const std::vector<std::uint8_t>& sig) -> CK_RV {
        static const CK_MECHANISM ecdsa{CKM_ECDSA_SHA256, nullptr, 0};
        if (auto r = cluster_rv(c->verify_init(s, ecdsa, key)); r != CKR_OK) {
            return r;
        }
        return cluster_rv(c->verify(s, data, sig));
    }
};

/// A key pair's id: the CKA_ID both halves carry.
inline auto cluster_key_id(unsigned client, unsigned n) -> std::string {
    return "c" + std::to_string(client) + "-" + std::to_string(n);
}

inline auto ids_of(const std::map<std::string, CK_OBJECT_HANDLE>& m) -> std::set<std::string> {
    std::set<std::string> out;
    for (const auto& [id, h] : m) {
        out.insert(id);
    }
    return out;
}

/// Checks that every crypto member lists the same whole pairs, that
/// `confirmed` are all among them, and that each pair signs on one crypto
/// member and verifies on the next. Returns the number of pairs.
inline auto check_keys(const cluster_driver& cl, const std::set<std::string>& confirmed)
    -> std::size_t {
    struct view {
        std::map<std::string, CK_OBJECT_HANDLE> priv;
        std::map<std::string, CK_OBJECT_HANDLE> pub;
    };
    std::vector<std::size_t> members;  // the ones that answer PKCS#11 calls
    for (std::size_t i = 0; i < cl.size(); ++i) {
        if (cl.crypto(i)) {
            members.push_back(i);
        }
    }
    BOOST_REQUIRE(!members.empty());
    std::vector<view> views(members.size());
    std::vector<std::optional<user_session>> sessions(members.size());
    const bool agreed = eventually(
        [&] {
            for (std::size_t m = 0; m < members.size(); ++m) {
                sessions[m] = user_session::open(cl, members[m]);
                if (!sessions[m]) {
                    return false;
                }
                auto priv = sessions[m]->by_id(CKO_PRIVATE_KEY);
                auto pub = sessions[m]->by_id(CKO_PUBLIC_KEY);
                if (!priv || !pub) {
                    return false;
                }
                views[m] = {std::move(*priv), std::move(*pub)};
            }
            for (std::size_t m = 1; m < views.size(); ++m) {
                if (ids_of(views[m].priv) != ids_of(views[0].priv) ||
                    ids_of(views[m].pub) != ids_of(views[0].pub)) {
                    return false;
                }
            }
            return true;
        },
        std::chrono::seconds{90});
    BOOST_REQUIRE_MESSAGE(agreed, "the replicas never agreed on the token's keys");
    const auto priv_ids = ids_of(views[0].priv);
    BOOST_TEST((priv_ids == ids_of(views[0].pub)), "every key is a whole pair");
    for (const auto& id : confirmed) {
        BOOST_TEST(priv_ids.contains(id), "acknowledged key " << id << " is on every replica");
    }
    std::size_t n = 0;
    for (const auto& id : priv_ids) {
        const auto a = n % members.size();
        const auto b = (n + 1) % members.size();
        const std::string text = "signed by " + id;
        const std::vector<std::uint8_t> data(text.begin(), text.end());
        const auto sig = sessions[a]->sign(views[a].priv.at(id), data);
        BOOST_TEST(sig.has_value(), "key " << id << " signs on member " << members[a] + 1);
        if (sig) {
            BOOST_TEST(sessions[b]->verify(views[b].pub.at(id), data, *sig) == CKR_OK,
                       "key " << id << "'s signature verifies on member " << members[b] + 1);
        }
        ++n;
    }
    return priv_ids.size();
}

/// Two clients, one on each follower, generate token key pairs while
/// `fault` strikes the token group's leader and `heal` undoes it. Every
/// replica then agrees and every key works.
inline void keygen_under_leader_fault(cluster_driver& cl,
                                      const std::function<void(std::size_t)>& fault,
                                      const std::function<void(std::size_t)>& heal,
                                      std::chrono::milliseconds faulted_for) {
    const auto leader = cl.leader(k_cluster_token);
    BOOST_REQUIRE(leader.has_value());
    std::vector<std::size_t> followers;
    for (std::size_t i = 0; i < cl.size(); ++i) {
        if (i != *leader) {
            followers.push_back(i);
        }
    }

    std::atomic<bool> stop{false};
    std::mutex mu;
    std::set<std::string> confirmed;
    std::atomic<unsigned> uncertain{0};
    std::vector<std::thread> clients;
    // Ids from a counter that outlives one call, so a second scenario on
    // the same cluster names new pairs.
    static std::atomic<unsigned> round{0};
    const auto r = round.fetch_add(1);
    for (unsigned c = 0; c < followers.size(); ++c) {
        clients.emplace_back([&, c] {
            std::optional<user_session> u;
            for (unsigned n = 0; !stop.load() && n < 60; ++n) {
                if (!u || u->c->transport_failed()) {
                    u = user_session::open(cl, followers[c]);
                    if (!u) {
                        std::this_thread::sleep_for(std::chrono::milliseconds{100});
                        continue;
                    }
                }
                const auto id = "r" + std::to_string(r) + "-" + cluster_key_id(c, n);
                if (u->generate(id) == CKR_OK) {
                    const std::lock_guard lock(mu);
                    confirmed.insert(id);
                } else {
                    uncertain.fetch_add(1);  // the pair may or may not exist
                }
            }
        });
    }

    std::this_thread::sleep_for(std::chrono::milliseconds{400});
    BOOST_TEST_MESSAGE("fault on token leader " << *leader + 1);
    fault(*leader);
    std::this_thread::sleep_for(faulted_for);
    heal(*leader);
    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    stop.store(true);
    for (auto& t : clients) {
        t.join();
    }

    BOOST_TEST_MESSAGE(confirmed.size()
                       << " generations acknowledged, " << uncertain.load() << " uncertain");
    BOOST_TEST(confirmed.size() >= 4U, "generation went on around the fault");
    const auto pairs = check_keys(cl, confirmed);
    BOOST_TEST(pairs >= confirmed.size());
}

/// keygen_under_leader_fault with a SIGKILL: the leader is started again
/// and, sealed as after any restart, unsealed with the current shares.
inline void keygen_under_leader_kill(cluster_driver& cl) {
    keygen_under_leader_fault(
        cl, [&](std::size_t i) { cl.kill(i); },
        [&](std::size_t i) {
            cl.start(i);
            BOOST_REQUIRE(
                eventually([&] { return cl.status(i).has_value(); }, std::chrono::seconds{90}));
            BOOST_REQUIRE(cl.unseal(i, cl.current));
        },
        std::chrono::milliseconds{1500});
}

/// For each delay: a rekey through a follower, the catalog's leader killed
/// `delay` after it was sent, and the leader started again. The generation
/// the cluster settles on is read after a catalog write commits through
/// the new leader (an old-term rekey entry can commit only after the
/// election); the follower's answer must have carried that generation's
/// shares if it moved, and they unseal every member. Every key still works.
inline void rekey_under_leader_kill(cluster_driver& cl,
                                    std::initializer_list<std::chrono::milliseconds> delays) {
    std::set<std::string> confirmed;
    {
        auto u = user_session::open(cl, 0);
        BOOST_REQUIRE(u.has_value());
        for (unsigned n = 0; n < 3; ++n) {
            BOOST_REQUIRE(u->generate(cluster_key_id(9, n)) == CKR_OK);
            confirmed.insert(cluster_key_id(9, n));
        }
    }

    for (const auto delay : delays) {
        BOOST_TEST_CONTEXT("kill after " << delay.count() << " ms") {
            const auto leader = cl.leader();
            BOOST_REQUIRE(leader.has_value());
            const auto via = (*leader + 1) % cl.size();
            const auto before = cl.current.generation;

            std::optional<answer> reply;
            std::thread rekey([&] { reply = cl.admin(via, "POST", "/v1/rekey", "{}"); });
            std::this_thread::sleep_for(delay);
            cl.kill(*leader);
            rekey.join();
            cl.start(*leader);

            // 200 (committed) or 503 with shares (uncertain) carry the new
            // set; anything else means no rekey.
            std::optional<share_set> offered;
            if (reply && (reply->status == 200 || reply->status == 503)) {
                offered = shares_of(*reply);
            }
            BOOST_TEST_MESSAGE("rekey via " << via + 1 << " answered "
                                            << (reply ? reply->status : 0U)
                                            << (offered ? " with shares" : ""));
            if (reply && reply->status == 200) {
                BOOST_TEST(offered.has_value());
            }

            BOOST_REQUIRE(cl.bind_app(via, std::chrono::seconds{90}));
            const auto settled = cl.status(via);
            BOOST_REQUIRE(settled.has_value());
            const auto agreed = settled->obj().at("generation").to_number<std::uint64_t>();
            BOOST_TEST_MESSAGE("generation " << before << " -> " << agreed);
            BOOST_REQUIRE((agreed == before || agreed == before + 1));
            if (agreed == before + 1) {
                BOOST_REQUIRE_MESSAGE(offered && offered->generation == agreed,
                                      "the rekey committed and its shares were handed out");
                cl.current = *offered;
            }
            for (std::size_t i = 0; i < cl.size(); ++i) {
                BOOST_REQUIRE_MESSAGE(
                    cl.unseal(i, cl.current, std::chrono::seconds{90}),
                    "member " << i + 1 << " unsealed with generation " << cl.current.generation);
            }
            check_keys(cl, confirmed);
        }
    }
}

}  // namespace kythira::hsm::test
