// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Layer identities and per-route role checks
// (include/raft/layer_identity.hpp, .kiro/specs/kinesis-independent-layers/
// task 3, Requirement 7), and certificate rotation on the Beast HTTPS server
// without a restart (Requirement 7.5). Certificates come from the test CA.

#define BOOST_TEST_MODULE layer_identity_test

#include <boost/test/unit_test.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/certificate_authority.hpp>
#include <raft/certificate_provider.hpp>
#include <raft/layer_identity.hpp>
#include <raft/tls_material_source.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/x509.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
namespace layers = kythira::layers;
using namespace std::chrono_literals;
using layers::role;
using layers::role_set;

auto id(std::string node, role_set roles, std::string cluster = "c1") -> layers::identity {
    return layers::identity{.service = "kinesis",
                            .cluster = std::move(cluster),
                            .node_id = std::move(node),
                            .roles = roles};
}

// ---------------------------------------------------------------------------
// Guard inputs without a network.
// ---------------------------------------------------------------------------

auto req(const std::string& target) -> kythira::https::request {
    kythira::https::request r{http::verb::post, target, 11};
    return r;
}

auto tls_ctx(const std::vector<layers::identity>& ids, std::string serial = "1a")
    -> kythira::https::request_context {
    kythira::https::request_context c;
    c.peer_address = "127.0.0.1";
    c.tls = true;
    c.client_verified = !ids.empty();
    for (const auto& i : ids) {
        c.client_uri_sans.push_back(i.to_uri());
    }
    c.client_serial_hex = std::move(serial);
    return c;
}

auto plain_ctx() -> kythira::https::request_context {
    kythira::https::request_context c;
    c.peer_address = "127.0.0.1";
    return c;
}

auto kinesis_rules() -> std::vector<layers::route_rule> {
    return {
        {.path_prefix = "/_kythira/kinesis/v2/", .allowed = {role::front_end, role::data}},
        {.path_prefix = "/_kythira/kinesis/v2/call/", .allowed = {role::gateway}},
        {.path_prefix = "/_kythira/volumes/", .allowed = {role::data}},
    };
}

auto guard_with(std::function<bool(const kythira::https::request&)> secret = {},
                std::function<bool(std::string_view)> revoked = {}) -> layers::route_guard {
    return layers::route_guard({.service = "kinesis",
                                .cluster = "c1",
                                .rules = kinesis_rules(),
                                .forward_secret = std::move(secret),
                                .revoked = std::move(revoked)});
}

// ---------------------------------------------------------------------------
// TLS plumbing for the server cases.
// ---------------------------------------------------------------------------

/// A material source a test publishes to by hand.
class manual_source final : public kythira::basic_tls_material_source {
public:
    auto set(kythira::tls_material m) -> std::uint64_t {
        return publish(std::move(m), "manual_source");
    }
    auto refresh() -> void override {}
    [[nodiscard]] auto self_refreshing() const -> bool override { return true; }
};

/// A certificate for `who`, issued the way a node gets one: a CSR signed
/// with `add_layer_identity`'s options.
auto issue_layer_cert(raft::testing::certificate_authority& ca, const layers::identity& who)
    -> raft::testing::pem_material {
    raft::testing::leaf_certificate_options leaf;
    leaf.subject.common_name = "node-" + who.node_id;
    auto csr = raft::testing::generate_key_and_csr(leaf);
    raft::testing::csr_signing_options o;
    o.dns_names = {"localhost"};
    o.ip_addresses = {"127.0.0.1"};
    layers::add_layer_identity(o, who);
    auto pem = ca.sign_csr(csr.csr_pem, o);
    pem.private_key_pem = csr.private_key_pem;
    return pem;
}

auto material_for(raft::testing::certificate_authority& ca, const layers::identity& who)
    -> kythira::tls_material {
    auto pem = issue_layer_cert(ca, who);
    return kythira::tls_material{.certificate_chain_pem = pem.chain_pem,
                                 .private_key_pem = pem.private_key_pem,
                                 .root_certificates_pem = ca.root_certificate_pem()};
}

/// The common name of the leaf `s` was shown.
auto peer_common_name(SSL* s) -> std::string {
    X509* cert = SSL_get1_peer_certificate(s);
    if (cert == nullptr) {
        return {};
    }
    std::string out(256, '\0');
    const int n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, out.data(),
                                            static_cast<int>(out.size()));
    X509_free(cert);
    out.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
    return out;
}

/// One TLS connection presenting `client` (or nothing), trusting `roots`.
class client {
public:
    client(std::uint16_t port, const std::string& roots,
           const std::optional<raft::testing::pem_material>& cert)
        : _ctx(ssl::context::tls_client) {
        _ctx.add_certificate_authority(asio::buffer(roots.data(), roots.size()));
        _ctx.set_verify_mode(ssl::verify_peer);
        if (cert) {
            _ctx.use_certificate_chain(
                asio::buffer(cert->chain_pem.data(), cert->chain_pem.size()));
            _ctx.use_private_key(
                asio::buffer(cert->private_key_pem.data(), cert->private_key_pem.size()),
                ssl::context::pem);
        }
        _tls.emplace(_ioc, _ctx);
        beast::get_lowest_layer(*_tls).expires_after(5s);
        beast::get_lowest_layer(*_tls).connect(
            asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));
        _tls->handshake(ssl::stream_base::client);
    }

    auto post(const std::string& target) -> kythira::https::response {
        http::request<http::string_body> r{http::verb::post, target, 11};
        r.set(http::field::host, "localhost");
        r.prepare_payload();
        beast::get_lowest_layer(*_tls).expires_after(5s);
        http::write(*_tls, r);
        kythira::https::response res;
        http::read(*_tls, _buf, res);
        return res;
    }

    auto server_common_name() -> std::string { return peer_common_name(_tls->native_handle()); }

private:
    asio::io_context _ioc;
    ssl::context _ctx;
    std::optional<beast::ssl_stream<beast::tcp_stream>> _tls;
    beast::flat_buffer _buf;
};

/// Whether a handshake presenting `cert` completes and its first request
/// gets an answer. TLS 1.3 servers report a refused client certificate after
/// the client's handshake returns, so the request is part of the check.
auto handshake_ok(std::uint16_t port, const std::string& roots,
                  const std::optional<raft::testing::pem_material>& cert) -> bool {
    try {
        client c(port, roots, cert);
        (void)c.post("/public");
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

auto ok(const kythira::https::request& r, const kythira::https::request_context&)
    -> kythira::https::response {
    kythira::https::response res{http::status::ok, r.version()};
    res.body() = "reached " + std::string(r.target());
    res.keep_alive(r.keep_alive());
    return res;
}

auto server_config(std::shared_ptr<kythira::tls_material_source> source)
    -> kythira::https::server_config {
    kythira::https::server_config cfg;
    cfg.bind_address = "127.0.0.1";
    cfg.tls_source = std::move(source);
    return cfg;
}

}  // namespace

namespace kythira::layers {
// For Boost.Test failure messages.
inline auto operator<<(std::ostream& os, role_set s) -> std::ostream& {
    return os << "{" << s.to_string() << "}";
}
}  // namespace kythira::layers

BOOST_AUTO_TEST_SUITE(roles)

BOOST_AUTO_TEST_CASE(role_sets_print_in_a_fixed_order_and_parse_back) {
    const role_set s{role::data, role::gateway};
    BOOST_TEST(s.to_string() == "gateway,data");
    BOOST_TEST(role_set::parse("data,gateway") == s);
    BOOST_TEST(role_set::parse("") == role_set{});
    BOOST_TEST(role_set::all().to_string() == "gateway,front_end,data,segments");
    BOOST_TEST(role_set::all().contains(s));
    BOOST_TEST(!s.contains(role_set{role::segments}));
    BOOST_TEST(s.intersects(role_set{role::data, role::segments}));
}

BOOST_AUTO_TEST_CASE(unknown_repeated_or_empty_roles_are_refused) {
    BOOST_CHECK_THROW((void)role_set::parse("gateway,frontend"), std::invalid_argument);
    BOOST_CHECK_THROW((void)role_set::parse("data,data"), std::invalid_argument);
    BOOST_CHECK_THROW((void)role_set::parse("data,"), std::invalid_argument);
    BOOST_CHECK_THROW((void)role_set::parse("Data"), std::invalid_argument);
    BOOST_CHECK_THROW((void)role_set::parse("data, gateway"), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(identity_uri)

BOOST_AUTO_TEST_CASE(an_identity_round_trips_through_its_san_uri) {
    const auto me = id("7", {role::front_end, role::data}, "prod-east");
    BOOST_TEST(me.to_uri() == "kythira://kinesis/prod-east/7?roles=front_end,data");
    const auto back = layers::identity::parse_uri(me.to_uri());
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == me));
}

BOOST_AUTO_TEST_CASE(anything_not_written_by_to_uri_parses_to_nothing) {
    for (const char* bad : {
             "spiffe://kinesis/c1/7?roles=data",         // another scheme
             "kythira://kinesis/c1/7",                   // no roles
             "kythira://kinesis/c1/7?roles=",            // empty roles
             "kythira://kinesis/c1/7?roles=data&x=1",    // extra parameter
             "kythira://kinesis/c1/7?roles=data,owner",  // unknown role
             "kythira://kinesis/c1/7/8?roles=data",      // extra path segment
             "kythira://kinesis/c1?roles=data",          // missing node id
             "kythira://kinesis//7?roles=data",          // empty cluster
             "kythira://kinesis/c%201/7?roles=data",     // escaping
             "kythira://kinesis/c1/7?other=data",        // wrong key
         }) {
        BOOST_TEST_INFO(bad);
        BOOST_TEST(!layers::identity::parse_uri(bad).has_value());
    }
}

BOOST_AUTO_TEST_CASE(to_uri_refuses_parts_that_would_need_escaping) {
    BOOST_CHECK_THROW((void)id("7/8", {role::data}).to_uri(), std::invalid_argument);
    BOOST_CHECK_THROW((void)id("7", {role::data}, "a?b").to_uri(), std::invalid_argument);
    BOOST_CHECK_THROW((void)id("", {role::data}).to_uri(), std::invalid_argument);
    BOOST_CHECK_THROW((void)id("7", {}).to_uri(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(the_ca_issues_an_identity_a_node_can_read_back) {
    raft::testing::certificate_authority ca;
    const auto me = id("3", {role::gateway});
    const auto pem = issue_layer_cert(ca, me);
    const auto read = layers::identity_of_certificate(pem.chain_pem, "kinesis", "c1");
    BOOST_REQUIRE(read.has_value());
    BOOST_TEST((*read == me));
    BOOST_TEST(!layers::identity_of_certificate(pem.chain_pem, "kinesis", "c2").has_value());
    BOOST_TEST(!layers::identity_of_certificate(pem.chain_pem, "dynamodb", "c1").has_value());
    BOOST_TEST(!layers::identity_of_certificate("not a pem", "kinesis", "c1").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(route_guard)

BOOST_AUTO_TEST_CASE(a_path_no_rule_matches_is_not_internal_and_passes) {
    const auto g = guard_with();
    const auto v = g.check(req("/?Action=PutRecord"), plain_ctx());
    BOOST_TEST((v.kind == layers::verdict_kind::not_internal));
    BOOST_TEST(v.permitted());
}

BOOST_AUTO_TEST_CASE(a_caller_needs_one_of_the_routes_roles) {
    const auto g = guard_with();
    const auto fe = tls_ctx({id("2", {role::front_end})});
    auto v = g.check(req("/_kythira/kinesis/v2/propose"), fe);
    BOOST_TEST((v.kind == layers::verdict_kind::allowed));
    BOOST_REQUIRE(v.caller.has_value());
    BOOST_TEST(v.caller->node_id == "2");

    v = g.check(req("/_kythira/volumes/9/append"), fe);
    BOOST_TEST((v.kind == layers::verdict_kind::wrong_role));
    BOOST_TEST(v.reason.find("needs data") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(the_longest_matching_prefix_decides) {
    const auto g = guard_with();
    // /v2/call/ needs gateway even though /v2/ allows front_end and data.
    const auto data = tls_ctx({id("4", {role::data})});
    BOOST_TEST((g.check(req("/_kythira/kinesis/v2/call/x"), data).kind ==
                layers::verdict_kind::wrong_role));
    const auto gw = tls_ctx({id("1", {role::gateway})});
    BOOST_TEST((g.check(req("/_kythira/kinesis/v2/call/x?a=b"), gw).kind ==
                layers::verdict_kind::allowed));
}

BOOST_AUTO_TEST_CASE(identities_of_other_clusters_or_ambiguous_certificates_grant_nothing) {
    const auto g = guard_with();
    const auto other = tls_ctx({id("2", role_set::all(), "c2")});
    BOOST_TEST(
        (g.check(req("/_kythira/kinesis/v2/x"), other).kind == layers::verdict_kind::no_identity));
    const auto twice = tls_ctx({id("2", {role::front_end}), id("3", {role::data})});
    BOOST_TEST(
        (g.check(req("/_kythira/kinesis/v2/x"), twice).kind == layers::verdict_kind::no_identity));
    auto unverified = tls_ctx({id("2", {role::front_end})});
    unverified.client_verified = false;
    BOOST_TEST((g.check(req("/_kythira/kinesis/v2/x"), unverified).kind ==
                layers::verdict_kind::no_identity));
}

BOOST_AUTO_TEST_CASE(a_revoked_certificate_is_refused) {
    const auto g = guard_with({}, [](std::string_view serial) { return serial == "dead"; });
    BOOST_TEST(
        (g.check(req("/_kythira/kinesis/v2/x"), tls_ctx({id("2", {role::data})}, "dead")).kind ==
         layers::verdict_kind::revoked));
    BOOST_TEST(
        (g.check(req("/_kythira/kinesis/v2/x"), tls_ctx({id("2", {role::data})}, "beef")).kind ==
         layers::verdict_kind::allowed));
}

BOOST_AUTO_TEST_CASE(the_forward_secret_holds_data_only_and_only_without_tls) {
    auto secret = [](const kythira::https::request& r) {
        return r.find("X-Kythira-Forward") != r.end() && r["X-Kythira-Forward"] == "good";
    };
    const auto g = guard_with(secret);
    auto r = req("/_kythira/kinesis/v2/propose");
    r.set("X-Kythira-Forward", "good");
    auto v = g.check(r, plain_ctx());
    BOOST_TEST((v.kind == layers::verdict_kind::allowed_forward_secret));
    BOOST_TEST((v.roles == role_set{role::data}));

    // Not a route data nodes call.
    auto call = req("/_kythira/kinesis/v2/call/put");
    call.set("X-Kythira-Forward", "good");
    BOOST_TEST((g.check(call, plain_ctx()).kind == layers::verdict_kind::wrong_role));

    // Not accepted on a TLS connection, where identities are required.
    auto on_tls = tls_ctx({});
    BOOST_TEST((g.check(r, on_tls).kind == layers::verdict_kind::no_identity));

    // A wrong proof is no proof.
    r.set("X-Kythira-Forward", "bad");
    BOOST_TEST((g.check(r, plain_ctx()).kind == layers::verdict_kind::no_identity));
}

BOOST_AUTO_TEST_CASE(bad_rules_are_refused_at_construction) {
    BOOST_CHECK_THROW(
        layers::route_guard({.service = "kinesis",
                             .cluster = "c1",
                             .rules = {{.path_prefix = "nope", .allowed = {role::data}}},
                             .forward_secret = {},
                             .revoked = {}}),
        std::invalid_argument);
    BOOST_CHECK_THROW(layers::route_guard({.service = "kinesis",
                                           .cluster = "c1",
                                           .rules = {{.path_prefix = "/x", .allowed = {}}},
                                           .forward_secret = {},
                                           .revoked = {}}),
                      std::invalid_argument);
    BOOST_CHECK_THROW(layers::route_guard({.service = "kinesis",
                                           .cluster = "c/1",
                                           .rules = {},
                                           .forward_secret = {},
                                           .revoked = {}}),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(over_tls)

BOOST_AUTO_TEST_CASE(the_server_checks_each_internal_route_against_the_callers_roles) {
    raft::testing::certificate_authority ca;
    auto source = std::make_shared<manual_source>();
    source->set(material_for(ca, id("1", role_set::all())));
    const auto guard = guard_with();
    kythira::https::server srv(server_config(source), guard.wrap(ok));
    srv.start();

    const auto fe = issue_layer_cert(ca, id("2", {role::front_end}));
    client front_end(srv.port(), ca.root_certificate_pem(), fe);
    BOOST_TEST(front_end.post("/_kythira/kinesis/v2/propose").result_int() == 200U);
    const auto refused = front_end.post("/_kythira/volumes/1/append");
    BOOST_TEST(refused.result_int() == 403U);
    BOOST_TEST(refused.body().find("needs data") != std::string::npos);

    client anonymous(srv.port(), ca.root_certificate_pem(), std::nullopt);
    BOOST_TEST(anonymous.post("/public").result_int() == 200U);
    BOOST_TEST(anonymous.post("/_kythira/kinesis/v2/propose").result_int() == 403U);
}

BOOST_AUTO_TEST_CASE(a_new_certificate_is_served_from_the_next_handshake_without_a_restart) {
    raft::testing::certificate_authority ca;
    auto source = std::make_shared<manual_source>();
    source->set(material_for(ca, id("1", role_set::all())));
    kythira::https::server srv(server_config(source), ok);
    srv.start();

    client before(srv.port(), ca.root_certificate_pem(), std::nullopt);
    BOOST_TEST(before.server_common_name() == "node-1");

    // Rotate: same node, a fresh key and certificate.
    auto next = material_for(ca, id("1", role_set::all()));
    raft::testing::leaf_certificate_options renamed;
    renamed.subject.common_name = "node-1-renewed";
    auto csr = raft::testing::generate_key_and_csr(renamed);
    raft::testing::csr_signing_options o;
    o.dns_names = {"localhost"};
    layers::add_layer_identity(o, id("1", role_set::all()));
    auto pem = ca.sign_csr(csr.csr_pem, o);
    next.certificate_chain_pem = pem.chain_pem;
    next.private_key_pem = csr.private_key_pem;
    source->set(next);
    BOOST_TEST(srv.stats().tls_reloads.load() == 1U);

    client after(srv.port(), ca.root_certificate_pem(), std::nullopt);
    BOOST_TEST(after.server_common_name() == "node-1-renewed");
    // The connection opened before the rotation keeps working.
    BOOST_TEST(before.post("/still-here").result_int() == 200U);
}

BOOST_AUTO_TEST_CASE(a_rotated_trust_bundle_stops_accepting_old_identities_at_the_next_handshake) {
    raft::testing::certificate_authority old_ca;
    raft::testing::certificate_authority new_ca;
    auto source = std::make_shared<manual_source>();
    source->set(material_for(old_ca, id("1", role_set::all())));
    kythira::https::server srv(server_config(source), ok);
    srv.start();

    const auto old_client = issue_layer_cert(old_ca, id("2", {role::front_end}));
    const auto new_client = issue_layer_cert(new_ca, id("2", {role::front_end}));
    BOOST_TEST(handshake_ok(srv.port(), old_ca.root_certificate_pem(), old_client));
    BOOST_TEST(!handshake_ok(srv.port(), old_ca.root_certificate_pem(), new_client));

    // The cluster moves to the new CA: the server now presents a new-CA
    // certificate and trusts only new-CA clients.
    source->set(material_for(new_ca, id("1", role_set::all())));
    BOOST_TEST(!handshake_ok(srv.port(), new_ca.root_certificate_pem(), old_client));
    BOOST_TEST(handshake_ok(srv.port(), new_ca.root_certificate_pem(), new_client));
}

BOOST_AUTO_TEST_CASE(an_expired_client_certificate_fails_the_handshake) {
    raft::testing::certificate_authority ca;
    auto source = std::make_shared<manual_source>();
    source->set(material_for(ca, id("1", role_set::all())));
    kythira::https::server srv(server_config(source), ok);
    srv.start();

    raft::testing::leaf_certificate_options leaf;
    leaf.subject.common_name = "expired";
    leaf.uri_names = {id("2", {role::front_end}).to_uri()};
    leaf.client_auth = true;
    const auto expired = ca.issue_expired(leaf);
    BOOST_TEST(!handshake_ok(srv.port(), ca.root_certificate_pem(), expired));
}

BOOST_AUTO_TEST_CASE(a_file_backed_server_reloads_on_request) {
    raft::testing::certificate_authority ca;
    // With no source, reload_tls() re-reads the files; a broken file keeps
    // the current context.
    const auto dir = std::filesystem::temp_directory_path() /
                     ("layer-identity-test-" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    auto write = [&](const std::string& name, const std::string& pem) {
        std::ofstream(dir / name) << pem;
        return (dir / name).string();
    };
    auto first = issue_layer_cert(ca, id("1", role_set::all()));
    kythira::https::server_config cfg;
    cfg.bind_address = "127.0.0.1";
    cfg.tls_cert_path = write("cert.pem", first.chain_pem);
    cfg.tls_key_path = write("key.pem", first.private_key_pem);
    kythira::https::server srv(cfg, ok);
    srv.start();

    write("cert.pem", "garbage");
    BOOST_CHECK_THROW(srv.reload_tls(), std::exception);
    BOOST_TEST(srv.stats().tls_reload_failures.load() == 1U);
    BOOST_TEST(handshake_ok(srv.port(), ca.root_certificate_pem(), std::nullopt));

    raft::testing::leaf_certificate_options leaf;
    leaf.subject.common_name = "reloaded";
    leaf.dns_names = {"localhost"};
    auto second = ca.issue(leaf);
    write("cert.pem", second.chain_pem);
    write("key.pem", second.private_key_pem);
    srv.reload_tls();
    client c(srv.port(), ca.root_certificate_pem(), std::nullopt);
    BOOST_TEST(c.server_common_name() == "reloaded");
    srv.stop();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

BOOST_AUTO_TEST_SUITE_END()
