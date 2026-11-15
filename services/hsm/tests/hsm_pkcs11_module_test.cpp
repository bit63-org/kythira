// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// core's consumer wrapper, kythira::pkcs11::module (raft/pkcs11_module.hpp;
// .kiro/specs/virtual-hsm/ task 12, Requirements 9.1, 9.2 and 9.4), run
// the same way on three backends a consumer could be pointed at with
// nothing but a different URI:
//
//   * in process, over this node's session layer (pkcs11_native_backend);
//   * libkythira_pkcs11.so, dlopen'd, over a wire server's socket;
//   * SoftHSM2, standing in for an external module (when the build found
//     it; hsm-module.yml installs it).
//
// On each: key pairs of every common-subset spec generated on the token,
// found again by URI (object, id, type), signatures of every scheme and
// hash verified with OpenSSL from public_key(), RSA-OAEP decryption of
// what OpenSSL encrypted, and the refusals (wrong PIN, no token, an
// ambiguous URI, EC keys for decryption).

#define BOOST_TEST_MODULE hsm_pkcs11_module_test
#include "hsm_test_node.hpp"

#include <kythira/hsm/migrate.hpp>
#include <kythira/hsm/pkcs11_native_backend.hpp>
#include <kythira/hsm/wire_server.hpp>

#include <raft/pkcs11_envelope.hpp>
#include <raft/pkcs11_module.hpp>
#include <raft/pkcs11_uri.hpp>

#include <boost/test/unit_test.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <utility>
#include <vector>

#ifndef KYTHIRA_PKCS11_LIBRARY
#define KYTHIRA_PKCS11_LIBRARY "libkythira_pkcs11.so"
#endif

namespace hsm = kythira::hsm;
namespace p11 = kythira::pkcs11;
using namespace kythira::hsm::test;  // NOLINT(google-build-using-namespace)

namespace {

auto temp_path(const std::string& what) -> std::filesystem::path {
    std::random_device rd;
    return std::filesystem::temp_directory_path() / ("kythira-p11m-" + std::to_string(rd()) + what);
}

// ── OpenSSL: the software half of the common subset ─────────────────────

struct pkey_free {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct ctx_free {
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, ctx_free>;

auto to_pkey(const p11::public_key_info& k) -> pkey_ptr {
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> bld(OSSL_PARAM_BLD_new(),
                                                                        &OSSL_PARAM_BLD_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n(nullptr, &BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e(nullptr, &BN_free);
    const char* type = "RSA";
    if (k.key_type == CKK_RSA) {
        n.reset(BN_bin2bn(k.modulus.data(), static_cast<int>(k.modulus.size()), nullptr));
        e.reset(BN_bin2bn(k.public_exponent.data(), static_cast<int>(k.public_exponent.size()),
                          nullptr));
        BOOST_REQUIRE(OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n.get()) == 1);
        BOOST_REQUIRE(OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e.get()) == 1);
    } else {
        type = "EC";
        const bool p256 = std::ranges::equal(k.ec_params, p11::detail::p256_params);
        BOOST_REQUIRE(OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                                      p256 ? "P-256" : "P-384", 0) == 1);
        BOOST_REQUIRE(OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                                       k.ec_point.data(), k.ec_point.size()) == 1);
    }
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
        OSSL_PARAM_BLD_to_param(bld.get()), &OSSL_PARAM_free);
    ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr));
    EVP_PKEY* raw = nullptr;
    BOOST_REQUIRE(EVP_PKEY_fromdata_init(ctx.get()) == 1);
    BOOST_REQUIRE(EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) == 1);
    return pkey_ptr(raw);
}

auto md_of(p11::hash_algorithm h) -> const EVP_MD* {
    switch (h) {
        case p11::hash_algorithm::sha1:
            return EVP_sha1();
        case p11::hash_algorithm::sha256:
            return EVP_sha256();
        case p11::hash_algorithm::sha384:
            return EVP_sha384();
        case p11::hash_algorithm::sha512:
            return EVP_sha512();
    }
    return EVP_sha256();
}

auto digest(p11::hash_algorithm h, std::string_view msg) -> p11::bytes {
    p11::bytes out(EVP_MAX_MD_SIZE);
    unsigned n = 0;
    BOOST_REQUIRE(EVP_Digest(msg.data(), msg.size(), out.data(), &n, md_of(h), nullptr) == 1);
    out.resize(n);
    return out;
}

auto verifies(const p11::public_key_info& k, p11::signature_scheme scheme, p11::hash_algorithm h,
              std::span<const std::uint8_t> dgst, std::span<const std::uint8_t> sig) -> bool {
    auto key = to_pkey(k);
    ctx_ptr ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
    BOOST_REQUIRE(EVP_PKEY_verify_init(ctx.get()) == 1);
    BOOST_REQUIRE(EVP_PKEY_CTX_set_signature_md(ctx.get(), md_of(h)) == 1);
    p11::bytes der;
    if (scheme == p11::signature_scheme::ecdsa) {
        der = p11::ecdsa_der(sig);
        sig = der;
    } else if (scheme == p11::signature_scheme::rsa_pss) {
        BOOST_REQUIRE(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) == 1);
        BOOST_REQUIRE(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md_of(h)) == 1);
        BOOST_REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(
                          ctx.get(), static_cast<int>(p11::digest_length(h))) == 1);
    } else {
        BOOST_REQUIRE(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) == 1);
    }
    return EVP_PKEY_verify(ctx.get(), sig.data(), sig.size(), dgst.data(), dgst.size()) == 1;
}

auto oaep_encrypt(const p11::public_key_info& k, p11::hash_algorithm h,
                  std::span<const std::uint8_t> plain) -> p11::bytes {
    auto key = to_pkey(k);
    ctx_ptr ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
    BOOST_REQUIRE(EVP_PKEY_encrypt_init(ctx.get()) == 1);
    BOOST_REQUIRE(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) == 1);
    BOOST_REQUIRE(EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), md_of(h)) == 1);
    BOOST_REQUIRE(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md_of(h)) == 1);
    std::size_t n = 0;
    BOOST_REQUIRE(EVP_PKEY_encrypt(ctx.get(), nullptr, &n, plain.data(), plain.size()) == 1);
    p11::bytes out(n);
    BOOST_REQUIRE(EVP_PKEY_encrypt(ctx.get(), out.data(), &n, plain.data(), plain.size()) == 1);
    out.resize(n);
    return out;
}

auto rv_of(const std::function<void()>& f) -> CK_RV {
    try {
        f();
    } catch (const p11::error& e) {
        return e.rv();
    }
    return CKR_OK;
}

// ── the scenario every backend runs ─────────────────────────────────────

using hashes = std::vector<p11::hash_algorithm>;
const hashes k_all_oaep{p11::hash_algorithm::sha1, p11::hash_algorithm::sha256,
                        p11::hash_algorithm::sha384, p11::hash_algorithm::sha512};

/// `token_uri` names a token whose user PIN is `pin`; `oaep` are the
/// hashes its RSA-OAEP takes.
void consumer_scenario(const p11::module& m, const std::string& token_uri, const std::string& pin,
                       std::string_view tag, const hashes& oaep = k_all_oaep) {
    BOOST_TEST_CONTEXT(tag) {
        const auto base = p11::uri::parse(token_uri);
        auto s = m.open(base, pin);

        struct pair_case {
            p11::key_spec spec;
            p11::key_usage usage;
            std::string label;
            std::uint8_t id;
        };
        const std::array<pair_case, 6> cases{{
            {p11::key_spec::ec_p256, p11::key_usage::sign, "ec256", 0x11},
            {p11::key_spec::ec_p384, p11::key_usage::sign, "ec384", 0x12},
            {p11::key_spec::rsa_2048, p11::key_usage::sign, "rsa2048", 0x21},
            {p11::key_spec::rsa_3072, p11::key_usage::sign, "rsa3072", 0x22},
            {p11::key_spec::rsa_2048, p11::key_usage::decrypt, "rsa-dec", 0x31},
            {p11::key_spec::rsa_4096, p11::key_usage::decrypt, "rsa4096-dec", 0x32},
        }};
        for (const auto& c : cases) {
            BOOST_TEST_CONTEXT(c.label) {
                const std::array<std::uint8_t, 2> id{0x4b, c.id};
                (void)s.generate_key_pair(c.spec, c.usage, c.label, id);

                // Found by label, by id, and by both, as a private key.
                auto by_label = base;
                by_label.object = c.label;
                auto by_id = base;
                by_id.id = p11::bytes(id.begin(), id.end());
                by_id.type = p11::object_type::private_key;
                auto both = by_label;
                both.id = by_id.id;
                const auto key = s.find(by_label);
                BOOST_TEST(s.find(by_id) == key);
                BOOST_TEST(s.find(both) == key);
                auto public_uri = by_label;
                public_uri.type = p11::object_type::public_key;
                const auto pub_obj = s.find(public_uri);
                BOOST_TEST(pub_obj != key);

                const auto pub = s.public_key(key);
                const bool ec =
                    c.spec == p11::key_spec::ec_p256 || c.spec == p11::key_spec::ec_p384;
                BOOST_TEST(pub.key_type == (ec ? CKK_EC : CKK_RSA));
                BOOST_TEST(s.public_key(pub_obj).key_type == pub.key_type);

                if (c.usage == p11::key_usage::sign) {
                    const std::vector<p11::signature_scheme> schemes =
                        ec ? std::vector{p11::signature_scheme::ecdsa}
                           : std::vector{p11::signature_scheme::rsa_pkcs1,
                                         p11::signature_scheme::rsa_pss};
                    for (const auto scheme : schemes) {
                        for (const auto h :
                             {p11::hash_algorithm::sha256, p11::hash_algorithm::sha384,
                              p11::hash_algorithm::sha512}) {
                            const auto d = digest(h, "message for " + c.label);
                            const auto sig = s.sign_digest(key, scheme, h, d);
                            BOOST_TEST(verifies(pub, scheme, h, d, sig));
                            auto other = digest(h, "another message");
                            BOOST_TEST(!verifies(pub, scheme, h, other, sig));
                        }
                    }
                    // A digest of the wrong length never reaches the token.
                    const auto short_digest = digest(p11::hash_algorithm::sha256, "x");
                    BOOST_TEST(rv_of([&] {
                                   (void)s.sign_digest(key, schemes.front(),
                                                       p11::hash_algorithm::sha384, short_digest);
                               }) == CKR_DATA_LEN_RANGE);
                    // SHA-1 never signs.
                    const auto sha1 = digest(p11::hash_algorithm::sha1, "x");
                    BOOST_TEST(rv_of([&] {
                                   (void)s.sign_digest(key, schemes.front(),
                                                       p11::hash_algorithm::sha1, sha1);
                               }) == CKR_MECHANISM_INVALID);
                    if (!ec) {
                        // Not a decryption key.
                        const std::array<std::uint8_t, 4> plain{1, 2, 3, 4};
                        const auto ct = oaep_encrypt(pub, oaep.front(), plain);
                        BOOST_TEST(rv_of([&] { (void)s.decrypt_oaep(key, oaep.front(), ct); }) !=
                                   CKR_OK);
                    }
                } else {
                    for (const auto h : oaep) {
                        std::array<std::uint8_t, 32> data_key{};
                        BOOST_REQUIRE(RAND_bytes(data_key.data(), data_key.size()) == 1);
                        const auto ct = oaep_encrypt(pub, h, data_key);
                        const auto back = s.decrypt_oaep(key, h, ct);
                        BOOST_TEST(back == p11::bytes(data_key.begin(), data_key.end()),
                                   boost::test_tools::per_element());
                    }
                    // Envelope encryption (pkcs11_envelope.hpp) with this key: a
                    // data key sealed in software opens on the token, and only
                    // for the binding it was sealed for.
                    const auto env_hash =
                        oaep.size() == 1 ? oaep.front() : p11::hash_algorithm::sha256;
                    const p11::envelope_key env(s, key, env_hash);
                    std::array<std::uint8_t, 32> data_key{};
                    BOOST_REQUIRE(RAND_bytes(data_key.data(), data_key.size()) == 1);
                    const std::string ctx = "stream=orders";
                    const std::string other_ctx = "stream=billing";
                    const auto as_bytes = [](const std::string& t) {
                        return std::span(reinterpret_cast<const std::uint8_t*>(t.data()), t.size());
                    };
                    auto sealed = env.seal(data_key, as_bytes(ctx));
                    BOOST_TEST(env.open(sealed, as_bytes(ctx)) ==
                                   p11::bytes(data_key.begin(), data_key.end()),
                               boost::test_tools::per_element());
                    BOOST_TEST(rv_of([&] { (void)env.open(sealed, as_bytes(other_ctx)); }) ==
                               CKR_ENCRYPTED_DATA_INVALID);
                    auto tampered = sealed;
                    tampered.back() ^= 0x01U;
                    // Refused by the token's OAEP check (SoftHSM2 answers
                    // CKR_GENERAL_ERROR rather than CKR_ENCRYPTED_DATA_INVALID).
                    BOOST_TEST(rv_of([&] { (void)env.open(tampered, as_bytes(ctx)); }) != CKR_OK);
                    BOOST_TEST(rv_of([&] {
                                   (void)env.open(std::span(sealed).first(3), as_bytes(ctx));
                               }) == CKR_ENCRYPTED_DATA_INVALID);
                    BOOST_TEST(rv_of([&] {
                                   const std::vector<std::uint8_t> big(env.max_secret() + 1, 7);
                                   (void)env.seal(big, as_bytes(ctx));
                               }) == CKR_DATA_LEN_RANGE);
                    if (c.label == "rsa4096-dec") {
                        // Sealed for the other decryption key: refused here.
                        auto other_key = base;
                        other_key.object = "rsa-dec";
                        const p11::envelope_key other(s, s.find(other_key), env_hash);
                        BOOST_TEST(rv_of([&] {
                                       (void)env.open(other.seal(data_key, as_bytes(ctx)),
                                                      as_bytes(ctx));
                                   }) != CKR_OK);
                    }

                    // Not a signing key.
                    const auto d = digest(p11::hash_algorithm::sha256, "m");
                    BOOST_TEST(rv_of([&] {
                                   (void)s.sign_digest(key, p11::signature_scheme::rsa_pkcs1,
                                                       p11::hash_algorithm::sha256, d);
                               }) != CKR_OK);
                }
            }
        }

        // The keys are sensitive: no private value leaves the token.
        auto rsa = base;
        rsa.object = "rsa2048";
        const std::array<CK_ATTRIBUTE_TYPE, 2> secret{CKA_PRIVATE_EXPONENT, CKA_PRIME_1};
        const auto values =
            s.unrestricted().b.get_attributes(s.unrestricted().handle, s.find(rsa), secret);
        BOOST_TEST(!values[0].has_value());
        BOOST_TEST(!values[1].has_value());

        // EC keys in the subset only sign.
        const std::array<std::uint8_t, 2> id{0x4b, 0x99};
        BOOST_TEST(rv_of([&] {
                       (void)s.generate_key_pair(p11::key_spec::ec_p256, p11::key_usage::decrypt,
                                                 "ec-dec", id);
                   }) == CKR_KEY_FUNCTION_NOT_PERMITTED);

        // Two keys under one label: the URI is ambiguous, and saying which
        // by id settles it.
        const std::array<std::uint8_t, 2> id_a{0x4b, 0x41};
        const std::array<std::uint8_t, 2> id_b{0x4b, 0x42};
        (void)s.generate_key_pair(p11::key_spec::ec_p256, p11::key_usage::sign, "twice", id_a);
        (void)s.generate_key_pair(p11::key_spec::ec_p256, p11::key_usage::sign, "twice", id_b);
        auto twice = base;
        twice.object = "twice";
        BOOST_TEST(rv_of([&] { (void)s.find(twice); }) == CKR_TEMPLATE_INCONSISTENT);
        twice.id = p11::bytes(id_b.begin(), id_b.end());
        BOOST_TEST(rv_of([&] { (void)s.find(twice); }) == CKR_OK);

        // No such object; a URI naming no object at all.
        auto missing = base;
        missing.object = "no-such-key";
        BOOST_TEST(rv_of([&] { (void)s.find(missing); }) == CKR_OBJECT_HANDLE_INVALID);
        BOOST_TEST(rv_of([&] { (void)s.find(base); }) == CKR_ARGUMENTS_BAD);

        // A second session of the same application is logged in already.
        auto again = m.open(base, pin);
        auto ec_uri = base;
        ec_uri.object = "ec256";
        const auto d = digest(p11::hash_algorithm::sha256, "second session");
        const auto key = again.find(ec_uri);
        BOOST_TEST(verifies(
            again.public_key(key), p11::signature_scheme::ecdsa, p11::hash_algorithm::sha256, d,
            again.sign_digest(key, p11::signature_scheme::ecdsa, p11::hash_algorithm::sha256, d)));

        // No token by that name; a library that is not this one.
        BOOST_TEST(rv_of([&] { (void)m.open(p11::uri::parse("pkcs11:token=nobody"), pin); }) ==
                   CKR_TOKEN_NOT_PRESENT);
        auto other_lib = base;
        other_lib.library_manufacturer = "Somebody Else";
        BOOST_TEST(rv_of([&] { (void)m.open(other_lib, pin); }) == CKR_TOKEN_NOT_PRESENT);
    }
}

/// A URI naming the token by every attribute the module reports for it,
/// so the lookup is checked against the real CK_*_INFO strings.
auto full_token_uri(const p11::module& m, const std::string& label) -> std::string {
    const auto tokens = m.matching_tokens(p11::uri::parse("pkcs11:token=" + label));
    BOOST_REQUIRE_EQUAL(tokens.size(), 1U);
    const auto lib = m.library();
    p11::uri u;
    u.library_manufacturer = lib.manufacturer;
    u.library_description = lib.description;
    u.library_version = p11::version_number{lib.version.major, lib.version.minor};
    u.slot_id = tokens[0].slot;
    u.slot_description = tokens[0].slot_description;
    u.slot_manufacturer = tokens[0].slot_manufacturer;
    u.token = tokens[0].label;
    u.manufacturer = tokens[0].manufacturer;
    u.model = tokens[0].model;
    u.serial = tokens[0].serial;
    // And the text form reads back the same.
    BOOST_TEST((p11::uri::parse(u.to_string()) == u));
    return u.to_string();
}

}  // namespace

BOOST_AUTO_TEST_CASE(in_process_over_the_session_layer) {
    node n;
    const p11::module m(std::make_shared<hsm::pkcs11_native_backend>(n.layer, "app-a"));
    BOOST_TEST(m.library().manufacturer == "Kythira");
    consumer_scenario(m, full_token_uri(m, "alpha"), k_user_pin, "native");

    // A wrong PIN is the token's answer, not the wrapper's.
    const p11::module fresh(std::make_shared<hsm::pkcs11_native_backend>(n.layer, "app-a"));
    BOOST_TEST(rv_of([&] { (void)fresh.open(p11::uri::parse("pkcs11:token=alpha"), "wrong"); }) ==
               CKR_PIN_INCORRECT);
    // An identity the catalog binds to no token sees none.
    const p11::module stranger(std::make_shared<hsm::pkcs11_native_backend>(n.layer, "app-z"));
    BOOST_TEST(stranger.matching_tokens(p11::uri::parse("pkcs11:")).empty());
}

BOOST_AUTO_TEST_CASE(libkythira_pkcs11_through_dlopen) {
    node n;
    hsm::wire_server_config cfg;
    cfg.tls_port.reset();
    cfg.socket_path = temp_path(".sock").string();
    cfg.socket_allow = {{static_cast<std::uint32_t>(::getuid()), "app-a"}};
    hsm::wire_server server(
        std::shared_ptr<hsm::session_layer>(&n.layer, [](hsm::session_layer*) {}), cfg);
    server.start();
    const auto conf = temp_path(".conf");
    std::ofstream(conf) << "socket = " << cfg.socket_path << "\n";
    ::setenv("KYTHIRA_PKCS11_CONF", conf.c_str(), 1);  // NOLINT(concurrency-mt-unsafe)

    // The module path in the URI, as a consumer's configuration gives it,
    // and the PIN from a file.
    const auto pin_file = temp_path(".pin");
    std::ofstream(pin_file) << k_user_pin << "\n";
    const auto uri = p11::uri::parse(std::string("pkcs11:token=alpha?pin-source=") +
                                     pin_file.string() + "&module-path=" + KYTHIRA_PKCS11_LIBRARY);
    {
        const auto m = p11::module::load(uri);
        BOOST_TEST(m.library().description == "Kythira virtual HSM client");
        (void)m.open(uri);  // logs in with the pin-source
        consumer_scenario(m, full_token_uri(m, "alpha"), k_user_pin, "libkythira_pkcs11.so");
    }
    std::filesystem::remove(conf);
    std::filesystem::remove(pin_file);
}

#if defined(KYTHIRA_SOFTHSM2_LIBRARY) && defined(KYTHIRA_SOFTHSM2_UTIL)
namespace {

/// A SoftHSM2 token store of its own, with one token initialized.
struct softhsm_token {
    std::filesystem::path dir = temp_path("-softhsm");

    explicit softhsm_token(const std::string& label) {
        std::filesystem::create_directories(dir / "tokens");
        const auto conf = dir / "softhsm2.conf";
        std::ofstream(conf) << "directories.tokendir = " << (dir / "tokens").string() << "\n"
                            << "objectstore.backend = file\nlog.level = ERROR\n";
        ::setenv("SOFTHSM2_CONF", conf.c_str(), 1);  // NOLINT(concurrency-mt-unsafe)
        const std::string init = std::string(KYTHIRA_SOFTHSM2_UTIL) +
                                 " --init-token --free --label " + label + " --so-pin " + k_so_pin +
                                 " --pin " + k_user_pin + " > /dev/null";
        BOOST_REQUIRE(std::system(init.c_str()) ==
                      0);  // NOLINT(cert-env33-c,concurrency-mt-unsafe)
    }
    softhsm_token(const softhsm_token&) = delete;
    auto operator=(const softhsm_token&) -> softhsm_token& = delete;
    softhsm_token(softhsm_token&&) = delete;
    auto operator=(softhsm_token&&) -> softhsm_token& = delete;
    ~softhsm_token() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

/// A self-signed X.509 certificate's DER and its subject's DER.
auto self_signed() -> std::pair<p11::bytes, p11::bytes> {
    EVP_PKEY* key = EVP_EC_gen("P-256");
    BOOST_REQUIRE(key != nullptr);
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("migrated"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    BOOST_REQUIRE(X509_sign(x, key, EVP_sha256()) > 0);
    unsigned char* der = nullptr;
    const int n = i2d_X509(x, &der);
    p11::bytes cert(der, der + n);
    OPENSSL_free(der);
    unsigned char* sder = nullptr;
    const int sn = i2d_X509_NAME(name, &sder);
    p11::bytes subject(sder, sder + sn);
    OPENSSL_free(sder);
    X509_free(x);
    EVP_PKEY_free(key);
    return {cert, subject};
}

auto by_label(std::string_view label, p11::object_type t) -> p11::uri {
    p11::uri u;
    u.object = std::string(label);
    u.type = t;
    return u;
}

auto outcome_of(const hsm::migrate_report& r, CK_OBJECT_CLASS cls, std::string_view label)
    -> std::optional<hsm::migrate_outcome> {
    for (const auto& e : r.entries) {
        if (e.object_class == cls && e.label == label) {
            return e.outcome;
        }
    }
    return std::nullopt;
}

}  // namespace

BOOST_AUTO_TEST_CASE(softhsm2_as_an_external_module) {
    const softhsm_token token("external");
    const auto m = p11::module::load(KYTHIRA_SOFTHSM2_LIBRARY);
    // SoftHSM2 2.6's RSA-OAEP takes SHA-1 only (the hash and MGF1).
    consumer_scenario(m, full_token_uri(m, "external"), k_user_pin, "SoftHSM2",
                      {p11::hash_algorithm::sha1});
    BOOST_TEST(rv_of([&] { (void)m.open(p11::uri::parse("pkcs11:token=external"), "wrong"); }) ==
               CKR_PIN_INCORRECT);
}

// Requirement 9.3: hsm_ctl migrate's copy, from the virtual HSM to
// SoftHSM2 standing in for hardware.
BOOST_AUTO_TEST_CASE(migrate_to_softhsm2) {
    node n;
    const softhsm_token token("hardware");
    const p11::module source(std::make_shared<hsm::pkcs11_native_backend>(n.layer, "app-a"));
    const auto target = p11::module::load(KYTHIRA_SOFTHSM2_LIBRARY);
    auto from = source.open(p11::uri::parse("pkcs11:token=alpha"), k_user_pin);
    auto to = target.open(p11::uri::parse("pkcs11:token=hardware"), k_user_pin);
    auto raw = from.unrestricted();
    using p11::attribute;

    // On the virtual HSM: an extractable AES key, extractable EC and RSA
    // pairs, a pair that is not extractable, a certificate and a data
    // object.
    CK_MECHANISM aes_gen{CKM_AES_KEY_GEN, nullptr, 0};
    const std::array<std::uint8_t, 2> aes_id{0x4b, 0x01};
    const std::array<attribute, 9> aes_tmpl{attribute::of_ulong(CKA_CLASS, CKO_SECRET_KEY),
                                            attribute::of_ulong(CKA_KEY_TYPE, CKK_AES),
                                            attribute::of_ulong(CKA_VALUE_LEN, 32),
                                            attribute::of_bool(CKA_TOKEN, true),
                                            attribute::of_bool(CKA_EXTRACTABLE, true),
                                            attribute::of_bool(CKA_ENCRYPT, true),
                                            attribute::of_bool(CKA_DECRYPT, true),
                                            attribute::of_string(CKA_LABEL, "aes-ext"),
                                            attribute::of_bytes(CKA_ID, aes_id)};
    const auto aes = raw.b.generate_key(raw.handle, aes_gen, aes_tmpl);
    const std::array<std::uint8_t, 2> ec_id{0x4b, 0x02};
    const std::array<std::uint8_t, 2> rsa_id{0x4b, 0x03};
    const std::array<std::uint8_t, 2> fixed_id{0x4b, 0x04};
    (void)from.generate_key_pair(p11::key_spec::ec_p256, p11::key_usage::sign, "ec-ext", ec_id,
                                 true);
    (void)from.generate_key_pair(p11::key_spec::rsa_2048, p11::key_usage::decrypt, "rsa-ext",
                                 rsa_id, true);
    (void)from.generate_key_pair(p11::key_spec::ec_p256, p11::key_usage::sign, "ec-fixed",
                                 fixed_id);
    const auto [cert_der, subject] = self_signed();
    const std::array<std::uint8_t, 2> cert_id{0x4b, 0x05};
    const std::array<attribute, 7> cert_tmpl{attribute::of_ulong(CKA_CLASS, CKO_CERTIFICATE),
                                             attribute::of_ulong(CKA_CERTIFICATE_TYPE, CKC_X_509),
                                             attribute::of_bool(CKA_TOKEN, true),
                                             attribute::of_string(CKA_LABEL, "cert"),
                                             attribute::of_bytes(CKA_ID, cert_id),
                                             attribute::of_bytes(CKA_SUBJECT, subject),
                                             attribute::of_bytes(CKA_VALUE, cert_der)};
    (void)raw.b.create_object(raw.handle, cert_tmpl);
    const std::array<attribute, 4> data_tmpl{
        attribute::of_ulong(CKA_CLASS, CKO_DATA), attribute::of_bool(CKA_TOKEN, true),
        attribute::of_string(CKA_LABEL, "notes"), attribute::of_string(CKA_VALUE, "kept here")};
    (void)raw.b.create_object(raw.handle, data_tmpl);

    // A dry run says what would happen and changes nothing.
    hsm::migrate_options dry;
    dry.dry_run = true;
    const auto plan = hsm::migrate(from, to, dry);
    BOOST_TEST(plan.dry_run);
    BOOST_TEST((outcome_of(plan, CKO_PRIVATE_KEY, "ec-ext") == hsm::migrate_outcome::copied));
    BOOST_TEST(
        (outcome_of(plan, CKO_PRIVATE_KEY, "ec-fixed") == hsm::migrate_outcome::needs_reissue));
    BOOST_TEST((outcome_of(plan, CKO_DATA, "notes") == hsm::migrate_outcome::skipped));
    BOOST_TEST(rv_of([&] { (void)to.find(by_label("ec-ext", p11::object_type::private_key)); }) ==
               CKR_OBJECT_HANDLE_INVALID);

    // The copy.
    const auto report = hsm::migrate(from, to);
    BOOST_TEST(report.ok());
    BOOST_TEST(report.unwrap_mechanism == CKM_AES_KEY_WRAP_PAD);  // SoftHSM2's name for RFC 5649
    BOOST_TEST(report.oaep_hash == "SHA-1");
    for (const auto& [cls, label] :
         std::vector<std::pair<CK_OBJECT_CLASS, std::string>>{{CKO_SECRET_KEY, "aes-ext"},
                                                              {CKO_PRIVATE_KEY, "ec-ext"},
                                                              {CKO_PUBLIC_KEY, "ec-ext"},
                                                              {CKO_PRIVATE_KEY, "rsa-ext"},
                                                              {CKO_PUBLIC_KEY, "rsa-ext"},
                                                              {CKO_CERTIFICATE, "cert"}}) {
        BOOST_TEST_CONTEXT(label << " class " << cls) {
            BOOST_TEST((outcome_of(report, cls, label) == hsm::migrate_outcome::copied));
        }
    }
    BOOST_TEST(
        (outcome_of(report, CKO_PRIVATE_KEY, "ec-fixed") == hsm::migrate_outcome::needs_reissue));
    BOOST_TEST(rv_of([&] { (void)to.find(by_label("ec-fixed", p11::object_type::private_key)); }) ==
               CKR_OBJECT_HANDLE_INVALID);

    // The same keys: the target signs what the source's public key
    // verifies, decrypts what was encrypted to the source's key, and
    // decrypts what the source's AES key encrypted.
    const auto ec_on_target = to.find(by_label("ec-ext", p11::object_type::private_key));
    const auto ec_pub =
        from.public_key(from.find(by_label("ec-ext", p11::object_type::private_key)));
    const auto d = digest(p11::hash_algorithm::sha256, "signed on the hardware");
    BOOST_TEST(verifies(ec_pub, p11::signature_scheme::ecdsa, p11::hash_algorithm::sha256, d,
                        to.sign_digest(ec_on_target, p11::signature_scheme::ecdsa,
                                       p11::hash_algorithm::sha256, d)));
    BOOST_TEST((to.public_key(ec_on_target).ec_point == ec_pub.ec_point));
    const auto rsa_pub =
        from.public_key(from.find(by_label("rsa-ext", p11::object_type::private_key)));
    const std::array<std::uint8_t, 5> secret{9, 8, 7, 6, 5};
    BOOST_TEST(to.decrypt_oaep(to.find(by_label("rsa-ext", p11::object_type::private_key)),
                               p11::hash_algorithm::sha1,
                               oaep_encrypt(rsa_pub, p11::hash_algorithm::sha1, secret)) ==
                   p11::bytes(secret.begin(), secret.end()),
               boost::test_tools::per_element());
    std::array<std::uint8_t, 16> iv{};
    CK_MECHANISM cbc{CKM_AES_CBC_PAD, iv.data(), iv.size()};
    const std::string plain = "carried under the transport key";
    const auto ct = raw.b.encrypt(
        raw.handle, cbc, aes, {reinterpret_cast<const std::uint8_t*>(plain.data()), plain.size()});
    auto dst = to.unrestricted();
    const auto aes_on_target = to.find(by_label("aes-ext", p11::object_type::secret_key));
    const auto back = dst.b.decrypt(dst.handle, cbc, aes_on_target, ct);
    BOOST_TEST(std::string(back.begin(), back.end()) == plain);

    // On the target the keys are sensitive and no longer extractable.
    const std::array<CK_ATTRIBUTE_TYPE, 3> flags{CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_TOKEN};
    for (const auto h : {ec_on_target, aes_on_target}) {
        const auto v = dst.b.get_attributes(dst.handle, h, flags);
        BOOST_TEST((v[0] && v[0]->at(0) == CK_TRUE));
        BOOST_TEST((v[1] && v[1]->at(0) == CK_FALSE));
        BOOST_TEST((v[2] && v[2]->at(0) == CK_TRUE));
    }
    // The certificate is the same certificate.
    const std::array<CK_ATTRIBUTE_TYPE, 1> value{CKA_VALUE};
    BOOST_TEST(
        *dst.b.get_attributes(dst.handle, to.find(by_label("cert", p11::object_type::certificate)),
                              value)[0] == cert_der,
        boost::test_tools::per_element());

    // A second run finds everything there and copies nothing.
    const auto again = hsm::migrate(from, to);
    BOOST_TEST(again.ok());
    BOOST_TEST(again.count(hsm::migrate_outcome::copied) == 0U);
    BOOST_TEST(again.count(hsm::migrate_outcome::exists) ==
               report.count(hsm::migrate_outcome::copied) - 2U);

    // SoftHSM2 cannot wrap with CKM_AES_KEY_WRAP_KWP, so it cannot be a
    // source; refused before anything is touched.
    BOOST_TEST(rv_of([&] { (void)hsm::migrate(to, from); }) == CKR_MECHANISM_INVALID);

#if defined(KYTHIRA_HSM_CTL)
    // hsm_ctl migrate as an operator runs it: both modules dlopen'd from
    // their URIs (the virtual HSM through libkythira_pkcs11.so over a
    // socket), PINs from a file, the report as JSON on stdout.
    hsm::wire_server_config cfg;
    cfg.tls_port.reset();
    cfg.socket_path = temp_path(".sock").string();
    cfg.socket_allow = {{static_cast<std::uint32_t>(::getuid()), "app-a"}};
    hsm::wire_server server(
        std::shared_ptr<hsm::session_layer>(&n.layer, [](hsm::session_layer*) {}), cfg);
    server.start();
    const auto conf = token.dir / "kythira-pkcs11.conf";
    std::ofstream(conf) << "socket = " << cfg.socket_path << "\n";
    ::setenv("KYTHIRA_PKCS11_CONF", conf.c_str(), 1);  // NOLINT(concurrency-mt-unsafe)
    const auto pin = token.dir / "pin";
    std::ofstream(pin) << k_user_pin << "\n";
    const std::string cmd =
        std::string(KYTHIRA_HSM_CTL) +
        " migrate --from 'pkcs11:token=alpha?module-path=" + KYTHIRA_PKCS11_LIBRARY +
        "&pin-source=" + pin.string() +
        "' --to 'pkcs11:token=hardware?module-path=" + KYTHIRA_SOFTHSM2_LIBRARY +
        "&pin-source=" + pin.string() + "' 2>/dev/null";
    FILE* out = ::popen(cmd.c_str(), "r");  // NOLINT(cert-env33-c)
    BOOST_REQUIRE(out != nullptr);
    std::string json;
    std::array<char, 4096> buf{};
    while (const auto got = std::fread(buf.data(), 1, buf.size(), out)) {
        json.append(buf.data(), got);
    }
    const int status = ::pclose(out);
    BOOST_TEST_INFO("hsm_ctl printed: " << json);
    BOOST_TEST(WIFEXITED(status));
    BOOST_TEST(WEXITSTATUS(status) == 0);
    BOOST_TEST(json.find("\"copied\":0") != std::string::npos);
    BOOST_TEST(json.find("\"exists\":4") != std::string::npos);
    BOOST_TEST(json.find("\"needs_reissue\":1") != std::string::npos);
    BOOST_TEST(json.find(k_user_pin) == std::string::npos);
#endif
}
#endif
