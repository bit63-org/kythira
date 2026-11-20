// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Forwarding between HSM members over the network
// (.kiro/specs/virtual-hsm/ task 6d): the forward_reply wire format, who
// counts as a member, the peer routes, and the client against a real
// HTTPS listener with client certificates. A proposal can change any
// token, so everything that is not a verified member's certificate must
// be refused before the host is asked.

#define BOOST_TEST_MODULE hsm_peer_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_pki.hpp"

#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/hsm_peer.hpp>
#include <kythira/hsm/store_api.hpp>

#include <raft/beast_https_server.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace hsm = kythira::hsm;
using reply = hsm::forward_reply<std::uint64_t>;
using wire = hsm::forward_reply<std::string>;

auto bytes_of(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<std::byte>(s[i]);
    }
    return out;
}

auto id_text(const std::uint64_t& id) -> std::string {
    return std::to_string(id);
}

/// Records what it is asked and answers what the test set.
struct fake_host {
    auto serve_propose(std::uint64_t group, const std::vector<std::byte>& cmd) -> reply {
        const std::lock_guard lock(mutex);
        ++proposals;
        last_group = group;
        last_command = cmd;
        return propose_answer;
    }
    auto serve_read_index(std::uint64_t group) -> reply {
        const std::lock_guard lock(mutex);
        ++read_indexes;
        last_group = group;
        return read_answer;
    }

    // The store API's reads (store_api.hpp): a catalog with one token.
    auto catalog_barrier() -> hsm::ck_result<void> {
        const std::lock_guard lock(mutex);
        ++store_reads;
        return {};
    }
    auto read_barrier(std::uint64_t) -> hsm::ck_result<void> { return {}; }
    [[nodiscard]] auto catalog() const -> std::optional<hsm::catalog_record> {
        hsm::catalog_record c;
        c.seal_epoch = 3;
        return c;
    }
    [[nodiscard]] auto tokens() const -> std::vector<hsm::token_entry> {
        return {hsm::token_entry{1, "alpha", 1, {}}};
    }
    [[nodiscard]] auto token(std::uint64_t id) const -> std::optional<hsm::token_entry> {
        return id == 1 ? std::optional(tokens().front()) : std::nullopt;
    }
    [[nodiscard]] auto bindings() const -> std::vector<std::pair<std::string, std::uint64_t>> {
        return {{"app-a", 1}};
    }
    [[nodiscard]] auto crypto_members() const -> std::vector<std::string> {
        return {"spiffe://hsm/crypto-1"};
    }
    [[nodiscard]] auto token_record_of(std::uint64_t) const -> std::optional<hsm::token_record> {
        return hsm::token_record{};
    }
    [[nodiscard]] auto objects(std::uint64_t) const -> std::vector<hsm::object_record> {
        return {};
    }

    std::mutex mutex;
    int store_reads = 0;
    reply propose_answer;
    reply read_answer;
    int proposals = 0;
    int read_indexes = 0;
    std::uint64_t last_group = 0;
    std::vector<std::byte> last_command;
};

const std::string k_member = "spiffe://hsm/node-1";
const std::string k_server_sans = "DNS:localhost,IP:127.0.0.1,URI:spiffe://hsm/node-2";

/// A member's listener: peer routes only, on loopback.
class listener {
public:
    listener(fake_host& host, hsm::peer_policy policy, const hsm::test::test_pki::files& cert,
             const std::string& client_ca, bool plaintext = false)
        : _host(&host), _policy(std::move(policy)) {
        kythira::https::server_config cfg;
        cfg.bind_address = "127.0.0.1";
        cfg.tls_cert_path = cert.cert;
        cfg.tls_key_path = cert.key;
        cfg.client_ca_path = client_ca;
        cfg.insecure_plaintext = plaintext;
        _server = std::make_unique<kythira::https::server>(
            cfg, [this](const kythira::https::request& req,
                        const kythira::https::request_context& ctx) { return handle(req, ctx); });
        _server->start();
    }

    [[nodiscard]] auto url(bool tls = true) const -> std::string {
        return std::string(tls ? "https" : "http") +
               "://127.0.0.1:" + std::to_string(_server->port());
    }

private:
    auto handle(const kythira::https::request& req, const kythira::https::request_context& ctx)
        -> kythira::https::response {
        namespace http = boost::beast::http;
        const hsm::peer_caller caller{ctx.tls, ctx.client_verified, ctx.client_uri_sans,
                                      ctx.client_dns_sans};
        const auto answer =
            hsm::serve_peer(*_host, _policy, caller, std::string_view(req.method_string()),
                            std::string_view(req.target()), req.body(), id_text);
        kythira::https::response res{http::status::not_found, req.version()};
        if (answer) {
            res.result(answer->status);
            res.body() = answer->body;
        }
        res.prepare_payload();
        return res;
    }

    fake_host* _host;
    hsm::peer_policy _policy;
    std::unique_ptr<kythira::https::server> _server;
};

auto policy() -> hsm::peer_policy {
    hsm::peer_policy p;
    p.identities = {k_member, "spiffe://hsm/node-2", "spiffe://hsm/node-3"};
    return p;
}

}  // namespace

BOOST_AUTO_TEST_CASE(replies_round_trip_and_anything_malformed_is_unavailable) {
    wire r;
    r.result = wire::status::ok;
    r.index = 42;
    r.leader = "node-3";
    r.reply = bytes_of("state machine reply");
    const auto back = hsm::decode_forward_reply(hsm::encode_forward_reply(r));
    BOOST_TEST((back.result == wire::status::ok));
    BOOST_TEST(back.index == 42U);
    BOOST_TEST(back.leader.value_or("") == "node-3");
    BOOST_TEST((back.reply == r.reply));

    wire nl;
    nl.result = wire::status::not_leader;
    const auto nl_back = hsm::decode_forward_reply(hsm::encode_forward_reply(nl));
    BOOST_TEST((nl_back.result == wire::status::not_leader));
    BOOST_TEST(!nl_back.leader.has_value());

    const auto encoded = hsm::encode_forward_reply(r);
    for (const auto& bad : {std::string(), std::string("\x02") + encoded.substr(1), encoded + "x",
                            encoded.substr(0, encoded.size() - 1)}) {
        BOOST_TEST((hsm::decode_forward_reply(bad).result == wire::status::unavailable));
    }
    auto bad_status = encoded;
    bad_status[1] = '\x07';
    BOOST_TEST((hsm::decode_forward_reply(bad_status).result == wire::status::unavailable));
}

BOOST_AUTO_TEST_CASE(group_ids_are_plain_decimal) {
    BOOST_TEST(hsm::peer_group_of("/v1/peer/propose/0", hsm::peer_propose_path).value_or(9) == 0U);
    BOOST_TEST(hsm::peer_group_of("/v1/peer/propose/17", hsm::peer_propose_path).value_or(0) ==
               17U);
    for (const auto* bad : {"/v1/peer/propose/", "/v1/peer/propose/1x", "/v1/peer/propose/-1",
                            "/v1/peer/propose/1/2", "/v1/peer/read-index/1"}) {
        BOOST_TEST(!hsm::peer_group_of(bad, hsm::peer_propose_path).has_value());
    }
}

BOOST_AUTO_TEST_CASE(only_a_verified_member_certificate_is_a_member) {
    const auto p = policy();
    BOOST_TEST(hsm::is_member(p, {true, true, {k_member}, {}}));
    BOOST_TEST(hsm::is_member(p, {true, true, {}, {"spiffe://hsm/node-3"}}));
    BOOST_TEST(!hsm::is_member(p, {true, false, {k_member}, {}}));  // not verified
    BOOST_TEST(!hsm::is_member(p, {true, true, {"spiffe://hsm/intruder"}, {"localhost"}}));
    BOOST_TEST(!hsm::is_member(p, {false, false, {}, {}}));  // plaintext, not allowed
    auto open = p;
    open.allow_plaintext = true;
    BOOST_TEST(hsm::is_member(open, {false, false, {}, {}}));
}

BOOST_AUTO_TEST_CASE(peer_routes_refuse_before_asking_the_host) {
    fake_host host;
    const auto p = policy();
    const hsm::peer_caller member{true, true, {k_member}, {}};
    const hsm::peer_caller outsider{true, true, {"spiffe://hsm/intruder"}, {}};
    BOOST_TEST(!hsm::serve_peer(host, p, member, "GET", "/v1/status", "", id_text).has_value());
    const auto forbidden =
        hsm::serve_peer(host, p, outsider, "POST", "/v1/peer/propose/1", "cmd", id_text);
    BOOST_REQUIRE(forbidden.has_value());
    BOOST_TEST(forbidden->status == 403U);
    const auto get = hsm::serve_peer(host, p, member, "GET", "/v1/peer/propose/1", "", id_text);
    BOOST_TEST(get.value_or(hsm::peer_answer{}).status == 400U);
    const auto junk = hsm::serve_peer(host, p, member, "POST", "/v1/peer/propose/x", "", id_text);
    BOOST_TEST(junk.value_or(hsm::peer_answer{}).status == 400U);
    BOOST_TEST(host.proposals == 0);

    host.propose_answer.result = reply::status::not_leader;
    host.propose_answer.leader = 3;
    const auto ok = hsm::serve_peer(host, p, member, "POST", "/v1/peer/propose/5", "cmd", id_text);
    BOOST_REQUIRE(ok.has_value());
    BOOST_TEST(ok->status == 200U);
    BOOST_TEST(host.last_group == 5U);
    BOOST_TEST((host.last_command == bytes_of("cmd")));
    const auto decoded = hsm::decode_forward_reply(ok->body);
    BOOST_TEST((decoded.result == wire::status::not_leader));
    BOOST_TEST(decoded.leader.value_or("") == "3");
}

BOOST_AUTO_TEST_CASE(a_member_forwards_over_mutual_tls) {
    hsm::test::test_pki pki;
    const auto server_cert = pki.issue("node-2", k_server_sans);
    const auto client_cert = pki.issue("node-1", "DNS:node-1,URI:" + k_member);
    fake_host host;
    host.propose_answer.result = reply::status::ok;
    host.propose_answer.index = 9;
    host.propose_answer.reply = bytes_of("applied");
    host.read_answer.result = reply::status::ok;
    host.read_answer.index = 11;
    listener l(host, policy(), server_cert, pki.ca_path());

    const hsm::peer_client client({client_cert.cert, client_cert.key, pki.ca_path()});
    const auto r = client.propose(l.url(), 4, bytes_of("set pin"));
    BOOST_TEST((r.result == wire::status::ok));
    BOOST_TEST(r.index == 9U);
    BOOST_TEST((r.reply == bytes_of("applied")));
    BOOST_TEST(host.last_group == 4U);
    BOOST_TEST((host.last_command == bytes_of("set pin")));
    const auto ri = client.read_index(l.url(), 0);
    BOOST_TEST((ri.result == wire::status::ok));
    BOOST_TEST(ri.index == 11U);
    BOOST_TEST(host.read_indexes == 1);
}

BOOST_AUTO_TEST_CASE(a_store_client_reads_and_proposes_but_is_no_member) {
    hsm::test::test_pki pki;
    const auto server_cert = pki.issue("node-2", k_server_sans);
    const std::string crypto = "spiffe://hsm/crypto-1";
    const auto crypto_cert = pki.issue("crypto-1", "URI:" + crypto);
    fake_host host;
    host.propose_answer.result = reply::status::ok;
    auto p = policy();
    p.store_clients.insert(crypto);
    BOOST_TEST(!hsm::is_member(p, {true, true, {crypto}, {}}));
    BOOST_TEST(hsm::may_use_store(p, {true, true, {crypto}, {}}));
    listener l(host, p, server_cert, pki.ca_path());
    const hsm::peer_client client({crypto_cert.cert, crypto_cert.key, pki.ca_path()});
    const auto raw = client.store_read(l.url(), 0, hsm::store_read_request{}.encode());
    BOOST_REQUIRE(raw.has_value());
    const auto a = hsm::decode_store_read_answer(*raw);
    BOOST_TEST((a.status == hsm::store_read_status::ok));
    BOOST_TEST(a.seal_state.value_or(hsm::catalog_record{}).seal_epoch == 3U);
    BOOST_TEST(a.catalog.tokens.size() == 1U);
    BOOST_TEST(a.catalog.crypto_members.size() == 1U);
    BOOST_TEST((client.propose(l.url(), 1, bytes_of("cmd")).result == wire::status::ok));
    // Without the store-client entry it is a stranger: refused before the
    // host is asked.
    listener closed(host, policy(), server_cert, pki.ca_path());
    const auto before = host.store_reads;
    BOOST_TEST(!client.store_read(closed.url(), 0, hsm::store_read_request{}.encode()));
    BOOST_TEST(host.store_reads == before);
}

BOOST_AUTO_TEST_CASE(strangers_and_wrong_schemes_never_reach_the_host) {
    hsm::test::test_pki pki;
    hsm::test::test_pki other;
    const auto server_cert = pki.issue("node-2", k_server_sans);
    fake_host host;
    host.propose_answer.result = reply::status::ok;
    listener l(host, policy(), server_cert, pki.ca_path());
    const auto expect_refused = [&](const hsm::peer_client& c, const std::string& url) {
        BOOST_TEST((c.propose(url, 1, bytes_of("cmd")).result == wire::status::unavailable));
    };
    // The members' CA, but an identity that is not a member: 403.
    const auto intruder = pki.issue("intruder", "URI:spiffe://hsm/intruder");
    expect_refused(hsm::peer_client({intruder.cert, intruder.key, pki.ca_path()}), l.url());
    // Another CA's certificate does not verify, so it is no member either.
    const auto stranger = other.issue("node-1", "URI:" + k_member);
    expect_refused(hsm::peer_client({stranger.cert, stranger.key, pki.ca_path()}), l.url());
    // A client that trusts another CA refuses the listener's certificate.
    const auto member = pki.issue("node-1", "URI:" + k_member);
    expect_refused(hsm::peer_client({member.cert, member.key, other.ca_path()}), l.url());
    // No client certificate at all is refused before dialling.
    expect_refused(hsm::peer_client({"", "", pki.ca_path()}), l.url());
    // http:// is dialled only by a client asked to use plaintext.
    expect_refused(hsm::peer_client({member.cert, member.key, pki.ca_path()}), l.url(false));
    BOOST_TEST(host.proposals == 0);
}

BOOST_AUTO_TEST_CASE(plaintext_works_only_when_both_sides_ask_for_it) {
    hsm::test::test_pki pki;
    const auto unused = pki.issue("node-2", k_server_sans);
    fake_host host;
    host.propose_answer.result = reply::status::ok;
    auto open = policy();
    open.allow_plaintext = true;
    listener plain(host, open, unused, "", true);
    hsm::peer_client_config cfg;
    cfg.plaintext = true;
    const hsm::peer_client client(cfg);
    BOOST_TEST((client.propose(plain.url(false), 1, bytes_of("cmd")).result == wire::status::ok));
    BOOST_TEST(
        (client.propose(plain.url(true), 1, bytes_of("cmd")).result == wire::status::unavailable));
    listener closed(host, policy(), unused, "", true);
    BOOST_TEST((client.propose(closed.url(false), 1, bytes_of("cmd")).result ==
                wire::status::unavailable));
    BOOST_TEST(host.proposals == 1);
}

BOOST_AUTO_TEST_CASE(the_health_route_tells_a_verified_caller_the_seal_state) {
    const auto p = policy();
    const hsm::peer_caller relay{true, true, {"spiffe://hsm/endpoint"}, {}};
    BOOST_TEST(!hsm::serve_health_peer(p, relay, "GET", "/v1/status", true).has_value());
    const auto sealed = hsm::serve_health_peer(p, relay, "GET", hsm::peer_health_route, true);
    BOOST_REQUIRE(sealed.has_value());
    BOOST_TEST(sealed->status == 200U);
    BOOST_TEST(sealed->body == "sealed");
    BOOST_TEST(hsm::serve_health_peer(p, relay, "GET", hsm::peer_health_route, false)->body ==
               "unsealed");
    BOOST_TEST(hsm::serve_health_peer(p, relay, "POST", hsm::peer_health_route, false)->status ==
               405U);
    // No member list is needed, but a certificate from the CA is, and
    // plaintext only where the policy allows it.
    const hsm::peer_caller unverified{true, false, {"spiffe://hsm/endpoint"}, {}};
    BOOST_TEST(
        hsm::serve_health_peer(p, unverified, "GET", hsm::peer_health_route, false)->status ==
        403U);
    const hsm::peer_caller plain{false, false, {}, {}};
    BOOST_TEST(hsm::serve_health_peer(p, plain, "GET", hsm::peer_health_route, false)->status ==
               403U);
    auto open = p;
    open.allow_plaintext = true;
    BOOST_TEST(hsm::serve_health_peer(open, plain, "GET", hsm::peer_health_route, false)->body ==
               "unsealed");
}
