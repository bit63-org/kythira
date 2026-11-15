// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The client wire protocol (.kiro/specs/virtual-hsm/ task 9, requirements
// 2.4 and 8.1-8.3): every call through the encoder and the dispatcher,
// mechanism parameters field by field, refusals of malformed requests and
// of raw parameters a structure with pointers would be read from, and the
// Unix socket and mutual TLS listeners with their identities.

#define BOOST_TEST_MODULE hsm_wire_test
#include "hsm_test_node.hpp"
#include "hsm_test_pki.hpp"

#include <kythira/hsm/wire.hpp>
#include <kythira/hsm/wire_client.hpp>
#include <kythira/hsm/wire_server.hpp>

#include <boost/test/unit_test.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace hsm = kythira::hsm;
using namespace kythira::hsm::test;  // NOLINT(google-build-using-namespace)

namespace {

/// A wire_client whose requests go straight to the dispatcher, for an
/// application acting as `identity`.
struct loopback {
    hsm::native_client app;
    std::string identity;
    hsm::wire_client client;

    loopback(hsm::session_layer& layer, std::string id)
        : app(layer, id), identity(std::move(id)), client([this](std::span<const std::byte> req) {
              return std::optional(
                  hsm::wire_dispatch(app, identity, req, hsm::wire::default_max_frame_bytes));
          }) {}
};

/// The CK_RV a hand-built request answers.
auto dispatch_rv(hsm::native_client& app, const std::vector<std::byte>& request) -> CK_RV {
    const auto res = hsm::wire_dispatch(app, "x", request, hsm::wire::default_max_frame_bytes);
    hsm::byte_reader r(res);
    return static_cast<CK_RV>(r.u64());
}

auto non_owning(hsm::session_layer& layer) -> std::shared_ptr<hsm::session_layer> {
    return {&layer, [](hsm::session_layer*) {}};
}

auto temp_socket_path() -> std::string {
    std::random_device rd;
    return (std::filesystem::temp_directory_path() /
            ("kythira-hsm-wire-" + std::to_string(rd()) + ".sock"))
        .string();
}

/// Signs and verifies with a fresh EC pair over `c`, logging in as the
/// user unless the application already is.
void sign_round_trip(hsm::wire_client& c) {
    auto s = c.open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    BOOST_REQUIRE(s.has_value());
    const auto login = rv(c.login(*s, CKU_USER, k_user_pin));
    BOOST_REQUIRE((login == CKR_OK || login == CKR_USER_ALREADY_LOGGED_IN));
    hsm::attribute_map pub;
    pub.set_bool(CKA_TOKEN, false);
    pub.set_bytes(CKA_EC_PARAMS, k_p256);
    pub.set_bool(CKA_VERIFY, true);
    hsm::attribute_map priv;
    priv.set_bool(CKA_TOKEN, false);
    priv.set_bool(CKA_SIGN, true);
    auto pair = c.generate_key_pair(*s, k_ec_gen, pub, priv);
    BOOST_REQUIRE(pair.has_value());
    BOOST_REQUIRE(rv(c.sign_init(*s, k_ecdsa, pair->second)) == CKR_OK);
    auto sig = c.sign(*s, data("over the wire"));
    BOOST_REQUIRE(sig.has_value());
    BOOST_REQUIRE(rv(c.verify_init(*s, k_ecdsa, pair->first)) == CKR_OK);
    BOOST_TEST(rv(c.verify(*s, data("over the wire"), *sig)) == CKR_OK);
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_call_goes_through_the_dispatcher) {
    node n;
    loopback lb(n.layer, "app-a");
    auto& c = lb.client;

    auto hello = c.hello();
    BOOST_REQUIRE(hello.has_value());
    BOOST_TEST(hello->version == hsm::wire::protocol_version);
    BOOST_TEST(hello->identity == "app-a");

    // Only the bound token is there; the other answers as absent.
    BOOST_TEST(*c.get_slot_list() == std::vector<CK_SLOT_ID>{k_token});
    BOOST_TEST(rv(c.get_token_info(k_other_token)) == CKR_TOKEN_NOT_PRESENT);
    auto info = c.get_token_info(k_token);
    BOOST_REQUIRE(info.has_value());
    BOOST_TEST(info->label == "alpha");

    auto s = c.open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST(c.get_session_info(*s)->state == CKS_RW_PUBLIC_SESSION);
    BOOST_TEST(rv(c.login(*s, CKU_USER, "wrong-pin")) == CKR_PIN_INCORRECT);
    BOOST_REQUIRE(rv(c.login(*s, CKU_USER, k_user_pin)) == CKR_OK);
    BOOST_TEST(c.get_session_info(*s)->state == CKS_RW_USER_FUNCTIONS);

    // AES-GCM: the parameter structure travels field by field.
    auto key = c.generate_key(*s, k_aes_gen, aes_template(false));
    BOOST_REQUIRE(key.has_value());
    std::vector<std::uint8_t> iv(12, 0x11);
    std::vector<std::uint8_t> aad = data("header");
    CK_GCM_PARAMS gcm{iv.data(), iv.size(), 96, aad.data(), aad.size(), 128};
    const CK_MECHANISM aes_gcm{CKM_AES_GCM, &gcm, sizeof gcm};
    BOOST_REQUIRE(rv(c.encrypt_init(*s, aes_gcm, *key)) == CKR_OK);
    auto sealed = c.encrypt(*s, data("plaintext"));
    BOOST_REQUIRE(sealed.has_value());
    BOOST_TEST(sealed->size() == 9U + 16U);
    BOOST_REQUIRE(rv(c.decrypt_init(*s, aes_gcm, *key)) == CKR_OK);
    auto opened = c.decrypt(*s, *sealed);
    BOOST_REQUIRE(opened.has_value());
    BOOST_TEST(*opened == data("plaintext"));
    // Other AAD: the tag fails.
    aad = data("HEADER");
    gcm.pAAD = aad.data();
    BOOST_REQUIRE(rv(c.decrypt_init(*s, aes_gcm, *key)) == CKR_OK);
    BOOST_TEST(rv(c.decrypt(*s, *sealed)) == CKR_ENCRYPTED_DATA_INVALID);

    // A secret value is not returned; the class is.
    const std::vector<CK_ATTRIBUTE_TYPE> types{CKA_CLASS, CKA_VALUE, 0x7fff0000UL};
    auto attrs = c.get_attribute_value(*s, *key, types);
    BOOST_REQUIRE(attrs.has_value());
    BOOST_REQUIRE(attrs->size() == 3U);
    BOOST_TEST((*attrs)[0].rv == CKR_OK);
    BOOST_TEST((*attrs)[0].value.has_value());
    BOOST_TEST((*attrs)[1].rv == CKR_ATTRIBUTE_SENSITIVE);
    BOOST_TEST(!(*attrs)[1].value.has_value());
    BOOST_TEST((*attrs)[2].rv == CKR_ATTRIBUTE_TYPE_INVALID);

    sign_round_trip(c);

    // Multi-part digest, find, random and the mechanism queries.
    BOOST_REQUIRE(rv(c.digest_init(*s, k_sha256)) == CKR_OK);
    BOOST_REQUIRE(rv(c.digest_update(*s, data("ab"))) == CKR_OK);
    BOOST_REQUIRE(rv(c.digest_update(*s, data("c"))) == CKR_OK);
    auto digest = c.digest_final(*s);
    BOOST_REQUIRE(digest.has_value());
    BOOST_TEST(digest->size() == 32U);
    BOOST_TEST(digest->front() == 0xBAU);  // SHA-256("abc") = ba7816bf...

    hsm::attribute_map secret_keys;
    secret_keys.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    BOOST_REQUIRE(rv(c.find_objects_init(*s, secret_keys)) == CKR_OK);
    auto found = c.find_objects(*s, 10);
    BOOST_REQUIRE(found.has_value());
    BOOST_TEST(found->size() == 1U);
    BOOST_TEST(found->front() == *key);
    BOOST_REQUIRE(rv(c.find_objects_final(*s)) == CKR_OK);

    auto random = c.generate_random(*s, 48);
    BOOST_REQUIRE(random.has_value());
    BOOST_TEST(random->size() == 48U);

    auto mechs = c.get_mechanism_list(k_token);
    BOOST_REQUIRE(mechs.has_value());
    BOOST_TEST(mechs->size() == hsm::supported_mechanisms().size());
    auto mi = c.get_mechanism_info(k_token, CKM_AES_GCM);
    BOOST_REQUIRE(mi.has_value());
    BOOST_TEST(mi->ulMaxKeySize == 32U);
    BOOST_TEST(rv(c.get_mechanism_info(k_token, CKM_DES_CBC)) == CKR_MECHANISM_INVALID);

    BOOST_REQUIRE(rv(c.destroy_object(*s, *key)) == CKR_OK);
    BOOST_REQUIRE(rv(c.logout(*s)) == CKR_OK);
    BOOST_REQUIRE(rv(c.close_session(*s)) == CKR_OK);
    BOOST_TEST(rv(c.get_session_info(*s)) == CKR_SESSION_HANDLE_INVALID);
    BOOST_TEST(!c.transport_failed());
}

BOOST_AUTO_TEST_CASE(a_connection_sees_only_its_identitys_tokens) {
    node n;
    loopback stranger(n.layer, "nobody");
    BOOST_TEST(stranger.client.get_slot_list()->empty());
    BOOST_TEST(rv(stranger.client.open_session(k_token, CKF_SERIAL_SESSION)) ==
               CKR_TOKEN_NOT_PRESENT);
    BOOST_TEST(rv(stranger.client.open_session(99, CKF_SERIAL_SESSION)) == CKR_TOKEN_NOT_PRESENT);
    // Nor can it use another application's session.
    BOOST_TEST(rv(stranger.client.get_session_info(n.session)) == CKR_SESSION_HANDLE_INVALID);
    loopback b(n.layer, "app-b");
    BOOST_TEST(*b.client.get_slot_list() == std::vector<CK_SLOT_ID>{k_other_token});
}

BOOST_AUTO_TEST_CASE(mechanism_parameters_travel_field_by_field) {
    const auto round_trip = [](const CK_MECHANISM& m, auto check) {
        hsm::byte_writer w;
        BOOST_REQUIRE(hsm::wire::put_mechanism(w, m) == CKR_OK);
        const auto bytes = w.take();
        hsm::byte_reader r(bytes);
        hsm::wire::mechanism_params p;
        BOOST_REQUIRE(p.read(r) == CKR_OK);
        BOOST_TEST(r.done());
        BOOST_TEST(p.get().mechanism == m.mechanism);
        BOOST_TEST(p.get().ulParameterLen == m.ulParameterLen);
        check(p.get());
    };
    std::vector<std::uint8_t> a = data("first");
    std::vector<std::uint8_t> b = data("second buffer");

    CK_RSA_PKCS_OAEP_PARAMS oaep{CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, a.data(),
                                 a.size()};
    round_trip({CKM_RSA_PKCS_OAEP, &oaep, sizeof oaep}, [&](const CK_MECHANISM& m) {
        const auto& o = *static_cast<const CK_RSA_PKCS_OAEP_PARAMS*>(m.pParameter);
        BOOST_TEST(o.hashAlg == CKM_SHA256);
        BOOST_TEST(o.mgf == CKG_MGF1_SHA256);
        const auto* src = static_cast<const char*>(o.pSourceData);
        BOOST_TEST(std::string(src, src + o.ulSourceDataLen) == "first");
        BOOST_TEST(o.pSourceData != a.data());  // its own buffer
    });
    CK_RSA_PKCS_PSS_PARAMS pss{CKM_SHA384, CKG_MGF1_SHA384, 48};
    round_trip({CKM_SHA384_RSA_PKCS_PSS, &pss, sizeof pss}, [](const CK_MECHANISM& m) {
        const auto& p = *static_cast<const CK_RSA_PKCS_PSS_PARAMS*>(m.pParameter);
        BOOST_TEST(p.hashAlg == CKM_SHA384);
        BOOST_TEST(p.sLen == 48U);
    });
    CK_EDDSA_PARAMS ed{CK_TRUE, a.size(), a.data()};
    round_trip({CKM_EDDSA, &ed, sizeof ed}, [](const CK_MECHANISM& m) {
        const auto& e = *static_cast<const CK_EDDSA_PARAMS*>(m.pParameter);
        BOOST_TEST(e.phFlag == CK_TRUE);
        BOOST_TEST(e.ulContextDataLen == 5U);
    });
    CK_ECDH1_DERIVE_PARAMS ecdh{CKD_NULL, 0, nullptr, b.size(), b.data()};
    round_trip({CKM_ECDH1_DERIVE, &ecdh, sizeof ecdh}, [](const CK_MECHANISM& m) {
        const auto& e = *static_cast<const CK_ECDH1_DERIVE_PARAMS*>(m.pParameter);
        BOOST_TEST(e.pSharedData == nullptr);
        BOOST_TEST(e.ulSharedDataLen == 0U);
        BOOST_TEST(std::string(e.pPublicData, e.pPublicData + e.ulPublicDataLen) ==
                   "second buffer");
    });
    CK_HKDF_PARAMS hkdf{CK_TRUE, CK_TRUE,  CKM_SHA256, CKF_HKDF_SALT_DATA, a.data(), a.size(),
                        0,       b.data(), b.size()};
    round_trip({CKM_HKDF_DERIVE, &hkdf, sizeof hkdf}, [](const CK_MECHANISM& m) {
        const auto& h = *static_cast<const CK_HKDF_PARAMS*>(m.pParameter);
        BOOST_TEST(h.bExtract == CK_TRUE);
        BOOST_TEST(h.prfHashMechanism == CKM_SHA256);
        BOOST_TEST(h.ulSaltType == CKF_HKDF_SALT_DATA);
        BOOST_TEST(h.ulSaltLen == 5U);
        BOOST_TEST(h.ulInfoLen == 13U);
    });
    std::vector<std::uint8_t> iv(16, 0x22);
    round_trip({CKM_AES_CBC_PAD, iv.data(), iv.size()}, [&](const CK_MECHANISM& m) {
        BOOST_TEST(std::memcmp(m.pParameter, iv.data(), iv.size()) == 0);
    });
    round_trip({CKM_SHA256, nullptr, 0},
               [](const CK_MECHANISM& m) { BOOST_TEST(m.pParameter == nullptr); });

    // The client refuses what it cannot send faithfully.
    hsm::byte_writer w;
    BOOST_TEST(hsm::wire::put_mechanism(w, {CKM_AES_GCM, &oaep, sizeof oaep}) ==
               CKR_MECHANISM_PARAM_INVALID);
    BOOST_TEST(hsm::wire::put_mechanism(w, {CKM_SHA256, iv.data(), iv.size()}) ==
               CKR_MECHANISM_PARAM_INVALID);
    BOOST_TEST(hsm::wire::put_mechanism(w, {CKM_AES_CBC_PAD, nullptr, 16}) ==
               CKR_MECHANISM_PARAM_INVALID);
    CK_GCM_PARAMS bad_gcm{nullptr, 12, 96, nullptr, 0, 128};
    BOOST_TEST(hsm::wire::put_mechanism(w, {CKM_AES_GCM, &bad_gcm, sizeof bad_gcm}) ==
               CKR_MECHANISM_PARAM_INVALID);
    BOOST_TEST(w.take().empty());
}

BOOST_AUTO_TEST_CASE(malformed_requests_are_refused_before_any_call) {
    node n;
    hsm::native_client app(n.layer, "app-a");
    auto req = [](hsm::wire::op o) { return hsm::wire::request(o); };

    // Truncated, trailing bytes, an unknown op, another version.
    auto truncated = req(hsm::wire::op::open_session);
    truncated.u32(1);
    BOOST_TEST(dispatch_rv(app, truncated.take()) == CKR_ARGUMENTS_BAD);
    auto trailing = req(hsm::wire::op::open_session);
    trailing.u64(k_token).u64(CKF_SERIAL_SESSION).u8(0);
    BOOST_TEST(dispatch_rv(app, trailing.take()) == CKR_ARGUMENTS_BAD);
    BOOST_TEST(n.layer.slots(app.app()).size() == 1U);
    BOOST_TEST(rv(app.get_token_info(k_token)) == CKR_OK);
    BOOST_TEST(app.get_token_info(k_token)->session_count == 1U);  // the fixture's only
    hsm::byte_writer unknown;
    unknown.u8(hsm::wire::protocol_version).u32(9999);
    BOOST_TEST(dispatch_rv(app, unknown.take()) == CKR_FUNCTION_NOT_SUPPORTED);
    hsm::byte_writer version;
    version.u8(2).u32(static_cast<std::uint32_t>(hsm::wire::op::hello));
    BOOST_TEST(dispatch_rv(app, version.take()) == CKR_DEVICE_ERROR);

    // A GCM parameter sent as raw bytes would be read as a structure
    // holding pointers: it is refused, whatever its length.
    auto s = app.open_session(k_token, CKF_SERIAL_SESSION);
    BOOST_REQUIRE(s.has_value());
    std::vector<std::uint8_t> forged(sizeof(CK_GCM_PARAMS), 0x41);
    auto raw = req(hsm::wire::op::encrypt_init);
    raw.u64(*s).u64(CKM_AES_GCM).u8(static_cast<std::uint8_t>(hsm::wire::param_kind::raw));
    raw.bytes(forged).u64(1);
    BOOST_TEST(dispatch_rv(app, raw.take()) == CKR_MECHANISM_PARAM_INVALID);
    // Nor may a structured kind be claimed for another mechanism.
    auto mismatched = req(hsm::wire::op::sign_init);
    mismatched.u64(*s).u64(CKM_ECDSA).u8(static_cast<std::uint8_t>(hsm::wire::param_kind::pss));
    mismatched.u64(CKM_SHA256).u64(CKG_MGF1_SHA256).u64(32).u64(1);
    BOOST_TEST(dispatch_rv(app, mismatched.take()) == CKR_MECHANISM_PARAM_INVALID);

    // A reply larger than a frame is not asked for.
    auto huge = req(hsm::wire::op::generate_random);
    huge.u64(*s).u64(std::uint64_t{1} << 40U);
    BOOST_TEST(dispatch_rv(app, huge.take()) == CKR_ARGUMENTS_BAD);
    // A template that does not decode.
    auto bad_template = req(hsm::wire::op::create_object);
    bad_template.u64(*s).bytes(data("not a template"));
    BOOST_TEST(dispatch_rv(app, bad_template.take()) == CKR_ATTRIBUTE_VALUE_INVALID);
}

BOOST_AUTO_TEST_CASE(the_unix_socket_serves_only_allowed_uids) {
    node n;
    hsm::wire_server_config cfg;
    cfg.tls_port.reset();
    cfg.socket_path = temp_socket_path();
    cfg.socket_allow = {{static_cast<std::uint32_t>(::getuid()), "app-a"}};
    {
        hsm::wire_server server(non_owning(n.layer), cfg);
        server.start();
        BOOST_TEST(std::filesystem::is_socket(cfg.socket_path));
        hsm::wire_client c(hsm::wire::connection::unix_socket(cfg.socket_path));
        auto hello = c.hello();
        BOOST_REQUIRE(hello.has_value());
        BOOST_TEST(hello->identity == "app-a");
        sign_round_trip(c);
        BOOST_TEST(server.stats().accepted == 1U);
        BOOST_TEST(server.stats().requests > 5U);
    }
    BOOST_TEST(!std::filesystem::exists(cfg.socket_path));

    // This uid is not in the list: the connection is closed unanswered.
    cfg.socket_allow = {{static_cast<std::uint32_t>(::getuid()) + 1, "app-a"}};
    hsm::wire_server server(non_owning(n.layer), cfg);
    server.start();
    hsm::wire_client c(hsm::wire::connection::unix_socket(cfg.socket_path));
    BOOST_TEST(rv(c.hello()) == CKR_DEVICE_ERROR);
    BOOST_TEST(c.transport_failed());
    BOOST_TEST(rv(c.get_slot_list()) == CKR_DEVICE_ERROR);
    for (int i = 0; i < 100 && server.stats().refused == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    BOOST_TEST(server.stats().refused == 1U);
}

BOOST_AUTO_TEST_CASE(a_frame_over_the_limit_ends_the_connection) {
    node n;
    hsm::wire_server_config cfg;
    cfg.tls_port.reset();
    cfg.socket_path = temp_socket_path();
    cfg.socket_allow = {{static_cast<std::uint32_t>(::getuid()), "app-a"}};
    cfg.max_frame_bytes = 1024;
    hsm::wire_server server(non_owning(n.layer), cfg);
    server.start();
    hsm::wire_client c(hsm::wire::connection::unix_socket(cfg.socket_path));
    auto s = c.open_session(k_token, CKF_SERIAL_SESSION);
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST(rv(c.digest_init(*s, k_sha256)) == CKR_OK);
    BOOST_TEST(rv(c.digest(*s, std::vector<std::uint8_t>(4096, 1))) == CKR_DEVICE_ERROR);
    BOOST_TEST(c.transport_failed());
}

BOOST_AUTO_TEST_CASE(mutual_tls_names_the_client_by_its_certificate) {
    node n;
    test_pki pki;
    const auto server_files = pki.issue("server", "DNS:localhost,IP:127.0.0.1");
    const auto uri_client = pki.issue("app", "URI:spiffe://test/app,DNS:app.example");
    const auto dns_client = pki.issue("dnsonly", "DNS:dns.example");
    BOOST_REQUIRE(n.propose_catalog(hsm::make_bind_command("spiffe://test/app", k_token)) ==
                  CKR_OK);

    hsm::wire_server_config cfg;
    cfg.tls_port = 0;
    cfg.bind_address = "127.0.0.1";
    cfg.cert_path = server_files.cert;
    cfg.key_path = server_files.key;
    cfg.ca_path = pki.ca_path();
    cfg.max_connections = 2;
    hsm::wire_server server(non_owning(n.layer), cfg);
    server.start();
    BOOST_REQUIRE(server.tls_port() != 0);

    const auto dial = [&](const test_pki::files& f, const std::string& host,
                          const std::string& ca) {
        hsm::wire::tls_client_config tc;
        tc.host = host;
        tc.port = server.tls_port();
        tc.cert_path = f.cert;
        tc.key_path = f.key;
        tc.ca_path = ca;
        return hsm::wire::connection::tls(tc, std::chrono::seconds{5});
    };

    // The first URI SAN is the identity; the bound token is there.
    auto conn = dial(uri_client, "127.0.0.1", pki.ca_path());
    BOOST_REQUIRE(conn != nullptr);
    hsm::wire_client c(std::move(conn));
    BOOST_TEST(c.hello()->identity == "spiffe://test/app");
    sign_round_trip(c);

    // With no URI SAN, the first DNS SAN; nothing is bound to it.
    auto dconn = dial(dns_client, "localhost", pki.ca_path());
    BOOST_REQUIRE(dconn != nullptr);
    hsm::wire_client d(std::move(dconn));
    BOOST_TEST(d.hello()->identity == "dns.example");
    BOOST_TEST(d.get_slot_list()->empty());

    // max_connections is 2: a third is closed at once.
    auto third = dial(uri_client, "127.0.0.1", pki.ca_path());
    if (third != nullptr) {
        hsm::wire_client t(std::move(third));
        BOOST_TEST(rv(t.hello()) == CKR_DEVICE_ERROR);
    }
    BOOST_TEST(server.stats().refused == 1U);

    // A certificate from another CA is refused in the handshake, and a
    // client that does not trust the node's CA does not connect.
    test_pki other;
    const auto stranger = other.issue("stranger", "URI:spiffe://test/app");
    auto refused = dial(stranger, "127.0.0.1", pki.ca_path());
    if (refused != nullptr) {
        // TLS 1.3 finishes the client's handshake before the server has
        // checked its certificate; the first exchange fails instead.
        hsm::wire_client r(std::move(refused));
        BOOST_TEST(rv(r.hello()) == CKR_DEVICE_ERROR);
    }
    BOOST_TEST(dial(uri_client, "127.0.0.1", other.ca_path()) == nullptr);
}

BOOST_AUTO_TEST_CASE(the_client_checks_the_node_names_the_host_dialled) {
    node n;
    test_pki pki;
    const auto server_files = pki.issue("server", "DNS:hsm.example");
    const auto client_files = pki.issue("app", "URI:app-a");
    hsm::wire_server_config cfg;
    cfg.tls_port = 0;
    cfg.bind_address = "127.0.0.1";
    cfg.cert_path = server_files.cert;
    cfg.key_path = server_files.key;
    cfg.ca_path = pki.ca_path();
    hsm::wire_server server(non_owning(n.layer), cfg);
    server.start();
    hsm::wire::tls_client_config tc;
    tc.host = "127.0.0.1";
    tc.port = server.tls_port();
    tc.cert_path = client_files.cert;
    tc.key_path = client_files.key;
    tc.ca_path = pki.ca_path();
    BOOST_TEST(hsm::wire::connection::tls(tc, std::chrono::seconds{5}) == nullptr);
}
