// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// A crypto node outside the HSM's groups (.kiro/specs/hsm-independent-layers/
// task 3, Requirements 3, 4 and 7.2): its session layer runs over
// remote_hsm_store, which reaches three store members through the store
// API (store_api.hpp, served by serve_peer). The members keep their own
// session layers, so each case can compare the crypto node with a
// co-located one:
//
//  - the store API's wire format refuses anything malformed;
//  - only members and store clients may use it, and a store client is no
//    member, so the share routes stay closed to it;
//  - a key generated on the crypto node signs on a member and back;
//  - a destroy, and a seal, committed between two uses take effect on the
//    crypto node's very next use, and an idle crypto node drops its keys
//    after a seal through its watch;
//  - operators init, unseal, add tokens, seed the crypto member list and
//    seal through admin_api on the crypto node (remote_admin_host), and
//    the store members apply each of it;
//  - held objects are not fetched again; proposals reach the leader from
//    any member through not_leader hints; a crypto node cut off from every
//    store member answers CKR_DEVICE_ERROR, never a stale result.

#define BOOST_TEST_MODULE hsm_remote_store_test
#include <boost/test/unit_test.hpp>

#include "hsm_raft_cluster.hpp"

#include <kythira/hsm/hsm_admin.hpp>
#include <kythira/hsm/hsm_peer.hpp>
#include <kythira/hsm/remote_hsm_store.hpp>
#include <kythira/hsm/store_api.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <boost/json.hpp>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("hsm_remote_store_test"), nullptr};
        char** argv = argv_data;
        init_ = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> init_;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

namespace hsm = kythira::hsm;
using hsm::raft_test::cluster;
using hsm::raft_test::k_members;
using hsm::raft_test::k_token;
using hsm::raft_test::member;
using hsm::raft_test::rv;

const std::string k_crypto_identity = "spiffe://hsm/crypto-1";

auto member_url(std::uint64_t id) -> std::string {
    return "member-" + std::to_string(id);
}

auto id_of(std::string_view url) -> std::uint64_t {
    std::uint64_t id = 0;
    const auto digits = url.substr(url.find('-') + 1);
    std::from_chars(digits.data(), digits.data() + digits.size(), id);
    return id;
}

auto store_policy() -> hsm::peer_policy {
    hsm::peer_policy p;
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        p.identities.insert("spiffe://hsm/node-" + std::to_string(id));
    }
    p.store_clients.insert(k_crypto_identity);
    return p;
}

auto crypto_caller() -> hsm::peer_caller {
    return {true, true, {k_crypto_identity}, {}};
}

/// A crypto-only node: a remote store over direct calls into the
/// members' serve_peer, a vault, a session layer and a client.
class crypto_node {
public:
    explicit crypto_node(cluster& c, std::uint64_t first_member = 1) : _c(&c) {
        hsm::remote_store_options opts;
        for (std::uint64_t i = 0; i < k_members; ++i) {
            opts.store_urls.push_back(member_url((first_member - 1 + i) % k_members + 1));
        }
        opts.url_of = [](std::string_view leader) -> std::optional<std::string> {
            return "member-" + std::string(leader);
        };
        opts.timeout = std::chrono::milliseconds{3000};
        opts.maintenance_interval = std::chrono::milliseconds{50};
        hsm::store_link link;
        link.read = [this](std::string_view url, std::uint64_t group,
                           std::string request) -> std::optional<std::string> {
            const auto a =
                serve(url, std::string(hsm::peer_store_read_path) + std::to_string(group), request);
            if (!a || a->status != 200) {
                return std::nullopt;
            }
            return a->body;
        };
        link.propose = [this](std::string_view url, std::uint64_t group,
                              const std::vector<std::byte>& command) {
            const std::string body(reinterpret_cast<const char*>(command.data()), command.size());
            const auto a =
                serve(url, std::string(hsm::peer_propose_path) + std::to_string(group), body);
            if (!a || a->status != 200) {
                return hsm::forward_reply<std::string>{};
            }
            return hsm::decode_forward_reply(a->body);
        };
        store = std::make_unique<hsm::remote_hsm_store>(std::move(link), opts, &vault);
        layer =
            std::make_unique<hsm::session_layer>(*store, vault, hsm::raft_test::session_options());
        store->set_on_seal([this] { layer->seal(); });
        client = std::make_unique<hsm::native_client>(*layer, "app-a");
    }

    ~crypto_node() {
        store->stop();
        client.reset();
    }

    crypto_node(const crypto_node&) = delete;
    auto operator=(const crypto_node&) -> crypto_node& = delete;
    crypto_node(crypto_node&&) = delete;
    auto operator=(crypto_node&&) -> crypto_node& = delete;

    /// Unseal with the cluster's master key, against the catalog as the
    /// store members have it.
    auto unseal() -> void {
        BOOST_REQUIRE(store->refresh_catalog().has_value());
        BOOST_REQUIRE(vault.unseal(_c->master_key().clone(), store->catalog()) ==
                      hsm::unseal_result::unsealed);
    }

    /// The node cannot reach any store member while set.
    std::atomic<bool> cut{false};

    hsm::key_vault vault;
    std::unique_ptr<hsm::remote_hsm_store> store;
    std::unique_ptr<hsm::session_layer> layer;
    std::unique_ptr<hsm::native_client> client;

private:
    auto serve(std::string_view url, const std::string& target, std::string_view body)
        -> std::optional<hsm::peer_answer> {
        if (cut.load()) {
            return std::nullopt;
        }
        auto& m = _c->at(id_of(url));
        return hsm::serve_peer(*m.host, _policy, crypto_caller(), "POST", target, body,
                               [](const std::uint64_t& id) { return std::to_string(id); });
    }

    cluster* _c;
    hsm::peer_policy _policy = store_policy();
};

/// A logged-in read-write session on the crypto node, retried while the
/// store has no leader to answer the login's barrier.
auto user_session(crypto_node& n) -> CK_SESSION_HANDLE {
    CK_SESSION_HANDLE out = 0;
    BOOST_REQUIRE(cluster::await([&] {
        auto s = n.client->open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        if (!s.has_value()) {
            return false;
        }
        if (rv(n.client->login(*s, CKU_USER, hsm::raft_test::k_user_pin)) == CKR_OK) {
            out = *s;
            return true;
        }
        (void)n.client->close_session(*s);
        return false;
    }));
    return out;
}

auto ec_pair(hsm::native_client& client, CK_SESSION_HANDLE s)
    -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> {
    hsm::attribute_map pub;
    pub.set_bool(CKA_TOKEN, true);
    pub.set_bytes(CKA_EC_PARAMS, hsm::raft_test::k_p256);
    pub.set_bool(CKA_VERIFY, true);
    hsm::attribute_map priv;
    priv.set_bool(CKA_TOKEN, true);
    priv.set_bool(CKA_SIGN, true);
    auto pair = client.generate_key_pair(s, hsm::raft_test::k_ec_gen, pub, priv);
    BOOST_REQUIRE(pair.has_value());
    return *pair;
}

auto sign(hsm::native_client& client, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE key,
          std::string_view msg) -> hsm::ck_result<hsm::bytes> {
    if (auto r = client.sign_init(s, hsm::raft_test::k_ecdsa, key); !r) {
        return hsm::unexpected(r.error());
    }
    return client.sign(s, hsm::raft_test::data(msg));
}

auto verify(hsm::native_client& client, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE key,
            std::string_view msg, const hsm::bytes& sig) -> CK_RV {
    if (auto r = client.verify_init(s, hsm::raft_test::k_ecdsa, key); !r) {
        return r.error();
    }
    return rv(client.verify(s, hsm::raft_test::data(msg), sig));
}

}  // namespace

BOOST_AUTO_TEST_CASE(store_reads_round_trip_and_anything_malformed_is_refused) {
    hsm::store_read_request req;
    req.have = {{1, 3}, {7, 1}};
    const auto back = hsm::store_read_request::decode(req.encode());
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->have == req.have));
    const auto encoded = req.encode();
    for (const auto& bad : {std::string(), std::string("\x02") + encoded.substr(1), encoded + "x",
                            encoded.substr(0, encoded.size() - 1)}) {
        BOOST_TEST(!hsm::store_read_request::decode(bad).has_value());
    }
    // A count the body cannot hold is refused before anything is reserved.
    BOOST_TEST(!hsm::store_read_request::decode(std::string("\x01\xff\xff\xff\xff", 5)));

    hsm::store_read_answer a;
    a.status = hsm::store_read_status::ok;
    hsm::catalog_record cat;
    cat.k = 2;
    cat.n = 3;
    cat.generation = 4;
    cat.seal_epoch = 9;
    a.seal_state = cat;
    a.catalog.record = cat;
    a.catalog.tokens.push_back({5, "alpha", 4, {1, 2, 3}});
    a.catalog.bindings.emplace_back("app-a", 5);
    a.catalog.crypto_members = {"spiffe://hsm/crypto-1", "spiffe://hsm/crypto-2"};
    hsm::token_record t;
    t.label = "alpha";
    t.user_failures = 2;
    a.token.record = t;
    a.token.live = {{1, 1}, {2, 4}};
    hsm::object_record o;
    o.handle = 2;
    o.version = 4;
    o.attributes.set_bool(CKA_TOKEN, true);
    o.sealed = {9, 9, 9};
    a.token.changed.push_back(o);
    const auto wire = hsm::encode_store_read_answer(a);
    const auto got = hsm::decode_store_read_answer(wire);
    BOOST_TEST((got.status == hsm::store_read_status::ok));
    BOOST_REQUIRE(got.seal_state.has_value());
    BOOST_TEST(got.seal_state->seal_epoch == 9U);
    BOOST_TEST(got.seal_state->generation == 4U);
    BOOST_REQUIRE(got.catalog.tokens.size() == 1U);
    BOOST_TEST(got.catalog.tokens[0].label == "alpha");
    BOOST_TEST((got.catalog.tokens[0].sealed_tk == hsm::sealed_bytes{1, 2, 3}));
    BOOST_TEST(got.catalog.bindings.at(0).first == "app-a");
    BOOST_TEST((got.catalog.crypto_members == a.catalog.crypto_members));
    BOOST_TEST(got.token.record.value_or(hsm::token_record{}).user_failures == 2U);
    BOOST_TEST((got.token.live == a.token.live));
    BOOST_REQUIRE(got.token.changed.size() == 1U);
    BOOST_TEST((got.token.changed[0].sealed == o.sealed));
    for (const auto& bad : {std::string(), std::string("\x01") + wire.substr(1), wire + "x",
                            wire.substr(0, wire.size() - 1)}) {
        BOOST_TEST(
            (hsm::decode_store_read_answer(bad).status == hsm::store_read_status::unavailable));
    }
}

BOOST_AUTO_TEST_CASE(only_members_and_store_clients_use_the_store_api) {
    cluster c;
    c.initialize();
    const auto policy = store_policy();
    const auto to_text = [](const std::uint64_t& id) { return std::to_string(id); };
    const hsm::peer_caller outsider{true, true, {"spiffe://hsm/intruder"}, {}};
    const hsm::peer_caller unverified{true, false, {k_crypto_identity}, {}};
    const hsm::peer_caller member_caller{true, true, {"spiffe://hsm/node-2"}, {}};
    auto& m = c.at(1);
    const auto read = hsm::store_read_request{}.encode();
    for (const auto& who : {outsider, unverified}) {
        const auto a =
            hsm::serve_peer(*m.host, policy, who, "POST", "/v1/peer/store-read/0", read, to_text);
        BOOST_TEST(a.value_or(hsm::peer_answer{}).status == 403U);
    }
    for (const auto& who : {crypto_caller(), member_caller}) {
        const auto a =
            hsm::serve_peer(*m.host, policy, who, "POST", "/v1/peer/store-read/0", read, to_text);
        BOOST_REQUIRE(a.has_value());
        BOOST_TEST(a->status == 200U);
        const auto answer = hsm::decode_store_read_answer(a->body);
        BOOST_TEST((answer.status == hsm::store_read_status::ok));
        BOOST_TEST(answer.catalog.tokens.size() == 1U);
        BOOST_TEST(answer.seal_state.has_value());
    }
    const auto junk = hsm::serve_peer(*m.host, policy, crypto_caller(), "POST",
                                      "/v1/peer/store-read/1", "junk", to_text);
    BOOST_TEST(junk.value_or(hsm::peer_answer{}).status == 400U);
    const auto unknown = hsm::serve_peer(*m.host, policy, crypto_caller(), "POST",
                                         "/v1/peer/store-read/99", read, to_text);
    BOOST_REQUIRE(unknown.has_value());
    BOOST_TEST(
        (hsm::decode_store_read_answer(unknown->body).status == hsm::store_read_status::absent));
    // A store client is not a member: no share route answers it.
    BOOST_TEST(!hsm::is_member(policy, crypto_caller()));
    BOOST_TEST(hsm::may_use_store(policy, crypto_caller()));
}

BOOST_AUTO_TEST_CASE(a_key_generated_on_the_crypto_node_signs_on_a_member_and_back) {
    cluster c;
    c.initialize();
    crypto_node n(c);
    n.unseal();
    const auto s = user_session(n);
    const auto [pub, priv] = ec_pair(*n.client, s);
    const auto sig = sign(*n.client, s, priv, "from the crypto node");
    BOOST_REQUIRE(sig.has_value());
    auto& m = c.at(2);
    const auto sm = cluster::user_session(m);
    BOOST_TEST(verify(*m.client, sm, pub, "from the crypto node", *sig) == CKR_OK);
    const auto back = sign(*m.client, sm, priv, "from a member");
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(verify(*n.client, s, pub, "from a member", *back) == CKR_OK);
    // A key a member generates is used on the crypto node after a barrier.
    const auto [pub2, priv2] = ec_pair(*m.client, sm);
    const auto sig2 = sign(*n.client, s, priv2, "member key");
    BOOST_REQUIRE(sig2.has_value());
    BOOST_TEST(verify(*m.client, sm, pub2, "member key", *sig2) == CKR_OK);
    // The crypto node hosts no group: every member still has the same
    // objects, and nothing was proposed except through the store API.
    BOOST_TEST(n.store->stats().proposals > 0U);
    BOOST_TEST(n.store->stats().reads > 0U);
}

BOOST_AUTO_TEST_CASE(a_destroy_committed_between_two_uses_stops_the_next_one) {
    cluster c;
    c.initialize();
    crypto_node n(c);
    n.unseal();
    const auto s = user_session(n);
    auto& m = c.at(3);
    const auto sm = cluster::user_session(m);
    const auto [pub, priv] = ec_pair(*m.client, sm);
    BOOST_REQUIRE(sign(*n.client, s, priv, "first use").has_value());
    BOOST_REQUIRE(rv(m.client->destroy_object(sm, priv)) == CKR_OK);
    BOOST_TEST(rv(sign(*n.client, s, priv, "second use")) == CKR_KEY_HANDLE_INVALID);
    // And the other way: destroyed on the crypto node, gone on the member.
    const auto [pub2, priv2] = ec_pair(*n.client, s);
    BOOST_REQUIRE(sign(*m.client, sm, priv2, "first use").has_value());
    BOOST_REQUIRE(rv(n.client->destroy_object(s, priv2)) == CKR_OK);
    BOOST_TEST(rv(sign(*m.client, sm, priv2, "second use")) == CKR_KEY_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(a_seal_committed_between_two_uses_seals_the_crypto_node_first) {
    cluster c;
    c.initialize();
    crypto_node n(c);
    n.unseal();
    const auto s = user_session(n);
    const auto [pub, priv] = ec_pair(*n.client, s);
    BOOST_REQUIRE(sign(*n.client, s, priv, "first use").has_value());
    // The watch is not running: only the next call's barrier can see it.
    BOOST_REQUIRE(cluster::propose_catalog(c.at(1), hsm::make_seal_command()) == CKR_OK);
    BOOST_TEST(rv(sign(*n.client, s, priv, "second use")) == CKR_DEVICE_ERROR);
    BOOST_TEST(n.vault.sealed());
    BOOST_TEST(n.store->stats().seals_enforced == 1U);
    // Unsealed again under the new seal epoch, the open session (still
    // logged in, as on a co-located node) serves again.
    n.unseal();
    BOOST_TEST(sign(*n.client, s, priv, "after unseal").has_value());
}

BOOST_AUTO_TEST_CASE(an_idle_crypto_node_drops_its_keys_after_a_seal) {
    cluster c;
    c.initialize();
    crypto_node n(c);
    n.unseal();
    n.store->start();
    BOOST_REQUIRE(cluster::propose_catalog(c.at(2), hsm::make_seal_command()) == CKR_OK);
    // No call is made: the watch alone seals it within a few intervals.
    BOOST_TEST(cluster::await([&] { return n.vault.sealed(); }, std::chrono::seconds{5}));
    BOOST_TEST(n.store->stats().seals_enforced == 1U);
}

BOOST_AUTO_TEST_CASE(held_objects_are_not_fetched_again) {
    cluster c;
    c.initialize();
    crypto_node n(c);
    n.unseal();
    const auto s = user_session(n);
    auto& m = c.at(1);
    const auto sm = cluster::user_session(m);
    std::vector<CK_OBJECT_HANDLE> keys;
    for (int i = 0; i < 3; ++i) {
        keys.push_back(ec_pair(*m.client, sm).second);
    }
    for (const auto k : keys) {
        BOOST_REQUIRE(sign(*n.client, s, k, "warm").has_value());
    }
    const auto before = n.store->stats();
    for (const auto k : keys) {
        BOOST_REQUIRE(sign(*n.client, s, k, "again").has_value());
    }
    const auto after = n.store->stats();
    // Every barrier since resent nothing: all six objects were held.
    BOOST_TEST(after.objects_fetched == before.objects_fetched);
    BOOST_TEST(after.objects_reused > before.objects_reused);
}

BOOST_AUTO_TEST_CASE(proposals_reach_the_leader_from_any_member) {
    cluster c;
    c.initialize();
    // Start the crypto node at a follower of the token group, so its first
    // proposal is answered not_leader with a hint.
    const auto f = c.follower_of(k_token);
    crypto_node n(c, f);
    n.unseal();
    const auto s = user_session(n);
    const auto pair = ec_pair(*n.client, s);
    BOOST_TEST(sign(*n.client, s, pair.second, "redirected").has_value());
    BOOST_TEST(n.store->stats().proposals_redirected > 0U);
}

BOOST_AUTO_TEST_CASE(a_crypto_node_cut_off_from_the_store_answers_device_error) {
    cluster c;
    c.initialize();
    crypto_node n(c);
    n.unseal();
    const auto s = user_session(n);
    const auto [pub, priv] = ec_pair(*n.client, s);
    BOOST_REQUIRE(sign(*n.client, s, priv, "connected").has_value());
    n.cut = true;
    BOOST_TEST(rv(sign(*n.client, s, priv, "alone")) == CKR_DEVICE_ERROR);
    BOOST_TEST(n.store->stats().read_failures > 0U);
    n.cut = false;
    BOOST_TEST(cluster::await([&] { return sign(*n.client, s, priv, "back").has_value(); }));
}

BOOST_AUTO_TEST_CASE(operators_run_the_hsm_through_a_crypto_only_node) {
    cluster c;  // not initialized: the crypto node's operators do it
    crypto_node n(c);
    const std::string op = "spiffe://ops/alice";
    hsm::remote_admin_host host(*n.store, 64);
    hsm::admin_policy policy;
    policy.operators = {op};
    policy.store_members = {k_crypto_identity};
    hsm::admin_api<hsm::remote_admin_host> admin(host, n.vault, policy);
    admin.set_seal_hook([&n] { n.layer->seal(); });
    const auto call = [&](const std::string& method, const std::string& path,
                          const std::string& body = "") {
        return admin.handle({method, path, body, {op}});
    };
    const auto json = [](const hsm::admin_response& r) {
        return boost::json::parse(r.body).as_object();
    };

    // Init generates and splits the master key here; the members keep
    // only its check value.
    hsm::admin_response init;
    BOOST_REQUIRE(cluster::await([&] {
        init = call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 3})");
        return init.status == 200U;
    }));
    std::vector<std::string> shares;
    const auto answer = json(init);
    for (const auto& v : answer.at("shares").as_array()) {
        shares.emplace_back(v.as_string());
    }
    BOOST_REQUIRE(shares.size() == 3U);
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        BOOST_TEST(cluster::await([&] { return c.at(id).host->catalog().has_value(); }));
        BOOST_TEST(c.at(id).vault.sealed());
    }
    BOOST_TEST(json(call("GET", "/v1/status")).at("catalog_leader") == false);

    for (const auto& share : {shares[0], shares[2]}) {
        BOOST_REQUIRE(call("POST", "/v1/unseal",
                           boost::json::serialize(boost::json::object{{"share", share}}))
                          .status == 200U);
    }
    BOOST_REQUIRE(!n.vault.sealed());

    // A token made here is created on every member; one outside the
    // store's group space is refused before anything is proposed.
    BOOST_TEST(call("POST", "/v1/tokens", R"({"id": 65, "label": "far"})").status == 400U);
    BOOST_REQUIRE(call("POST", "/v1/tokens", R"({"id": 2, "label": "split"})").status == 201U);
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        BOOST_TEST(cluster::await([&] { return c.at(id).host->hosts(2); }));
    }
    BOOST_TEST(json(call("GET", "/v1/tokens")).at("tokens").as_array().size() == 1U);

    // The crypto member list reaches the crypto node through the store
    // API, as share delivery and share requests read it.
    BOOST_REQUIRE(call("POST", "/v1/crypto-members/seed").status == 200U);
    BOOST_TEST((c.at(1).host->crypto_members() == std::vector<std::string>{k_crypto_identity}));
    BOOST_TEST(cluster::await(
        [&] { return host.crypto_members() == std::vector<std::string>{k_crypto_identity}; }));

    // A seal is committed through the store and seals this node.
    BOOST_REQUIRE(call("POST", "/v1/seal").status == 200U);
    BOOST_TEST(n.vault.sealed());
    BOOST_TEST(cluster::await(
        [&] { return c.at(2).host->catalog().value_or(hsm::catalog_record{}).seal_epoch == 1U; }));
}
