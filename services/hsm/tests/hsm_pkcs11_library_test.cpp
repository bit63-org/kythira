// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// libkythira_pkcs11.so (.kiro/specs/virtual-hsm/ task 10, requirements
// 5.1-5.7), loaded with dlopen as any consumer loads it, against wire
// servers over Unix sockets in front of one node: the 3.0 interfaces,
// slot and token info, login, key generation, signing with the length
// query and a short buffer, AES-GCM, the attribute rules, find, wrap and
// unwrap, failover to a second server, calls from many threads, and the
// configuration file.

#define BOOST_TEST_MODULE hsm_pkcs11_library_test
#include "hsm_test_node.hpp"
#include "pkcs11_config.hpp"

#include <kythira/hsm/wire_server.hpp>

#include <boost/test/unit_test.hpp>

#include <dlfcn.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifndef KYTHIRA_PKCS11_LIBRARY
#define KYTHIRA_PKCS11_LIBRARY "libkythira_pkcs11.so"
#endif

namespace hsm = kythira::hsm;
using namespace kythira::hsm::test;  // NOLINT(google-build-using-namespace)

namespace {

/// The library's 3.0 function list, from C_GetInterface.
auto functions() -> CK_FUNCTION_LIST_3_0& {
    static CK_FUNCTION_LIST_3_0* list = [] {
        // Throws rather than BOOST_REQUIRE, which the analyzer does not see
        // as leaving the lambda.
        void* so = ::dlopen(KYTHIRA_PKCS11_LIBRARY, RTLD_NOW | RTLD_LOCAL);
        if (so == nullptr) {
            throw std::runtime_error(std::string("dlopen: ") + ::dlerror());
        }
        auto* get = reinterpret_cast<CK_C_GetInterface>(::dlsym(so, "C_GetInterface"));
        if (get == nullptr) {
            throw std::runtime_error("the library has no C_GetInterface");
        }
        CK_VERSION v{3, 0};
        CK_INTERFACE_PTR i = nullptr;
        std::string name = "PKCS 11";
        if (get(reinterpret_cast<CK_UTF8CHAR_PTR>(name.data()), &v, &i, 0) != CKR_OK ||
            i == nullptr) {
            throw std::runtime_error("C_GetInterface returned no PKCS 11 3.0 interface");
        }
        return static_cast<CK_FUNCTION_LIST_3_0*>(i->pFunctionList);
    }();
    return *list;
}

auto temp_path(const std::string& what) -> std::string {
    std::random_device rd;
    return (std::filesystem::temp_directory_path() / ("kythira-p11-" + std::to_string(rd()) + what))
        .string();
}

auto non_owning(hsm::session_layer& layer) -> std::shared_ptr<hsm::session_layer> {
    return {&layer, [](hsm::session_layer*) {}};
}

/// A wire server on its own socket, serving this uid as "app-a".
struct socket_server {
    hsm::wire_server_config cfg;
    std::unique_ptr<hsm::wire_server> server;

    explicit socket_server(hsm::session_layer& layer) {
        cfg.tls_port.reset();
        cfg.socket_path = temp_path(".sock");
        cfg.socket_allow = {{static_cast<std::uint32_t>(::getuid()), "app-a"}};
        server = std::make_unique<hsm::wire_server>(non_owning(layer), cfg);
        server->start();
    }
    void stop() { server.reset(); }
};

/// KYTHIRA_PKCS11_CONF naming `sockets`, the library initialized, and
/// finalized at the end.
struct loaded {
    std::string conf = temp_path(".conf");

    explicit loaded(const std::vector<std::string>& sockets) {
        {
            std::ofstream f(conf);
            f << "# test\ntimeout_s = 10\n";
            for (const auto& s : sockets) {
                f << "socket = " << s << "\n";
            }
        }
        ::setenv("KYTHIRA_PKCS11_CONF", conf.c_str(), 1);  // NOLINT(concurrency-mt-unsafe)
        BOOST_REQUIRE(functions().C_Initialize(nullptr) == CKR_OK);
    }
    loaded(const loaded&) = delete;
    auto operator=(const loaded&) -> loaded& = delete;
    loaded(loaded&&) = delete;
    auto operator=(loaded&&) -> loaded& = delete;
    ~loaded() {
        functions().C_Finalize(nullptr);
        std::filesystem::remove(conf);
    }
};

auto& f() {
    return functions();
}

auto open_rw() -> CK_SESSION_HANDLE {
    CK_SESSION_HANDLE h = 0;
    BOOST_REQUIRE(f().C_OpenSession(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                    &h) == CKR_OK);
    return h;
}

void login_user(CK_SESSION_HANDLE h) {
    std::string pin = k_user_pin;
    const auto r =
        f().C_Login(h, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(pin.data()), pin.size());
    BOOST_REQUIRE((r == CKR_OK || r == CKR_USER_ALREADY_LOGGED_IN));
}

CK_BBOOL yes = CK_TRUE;
CK_BBOOL no = CK_FALSE;

/// An EC P-256 pair, on the token or in the session.
auto ec_pair(CK_SESSION_HANDLE h, bool token) -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> {
    auto params = k_p256;
    CK_BBOOL tok = token ? CK_TRUE : CK_FALSE;
    std::array<CK_ATTRIBUTE, 3> pub{{
        {CKA_TOKEN, &tok, sizeof tok},
        {CKA_EC_PARAMS, params.data(), params.size()},
        {CKA_VERIFY, &yes, sizeof yes},
    }};
    std::string label = "p11-ec";
    std::array<CK_ATTRIBUTE, 3> priv{{
        {CKA_TOKEN, &tok, sizeof tok},
        {CKA_SIGN, &yes, sizeof yes},
        {CKA_LABEL, label.data(), label.size()},
    }};
    CK_MECHANISM gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE pu = 0;
    CK_OBJECT_HANDLE pr = 0;
    BOOST_REQUIRE(f().C_GenerateKeyPair(h, &gen, pub.data(), pub.size(), priv.data(), priv.size(),
                                        &pu, &pr) == CKR_OK);
    return {pu, pr};
}

/// A 256-bit AES key with the given extra flags.
auto aes_key(CK_SESSION_HANDLE h, bool token, bool extractable, bool wraps = false)
    -> CK_OBJECT_HANDLE {
    CK_BBOOL tok = token ? CK_TRUE : CK_FALSE;
    CK_BBOOL ext = extractable ? CK_TRUE : CK_FALSE;
    CK_BBOOL w = wraps ? CK_TRUE : CK_FALSE;
    CK_ULONG len = 32;
    std::array<CK_ATTRIBUTE, 7> t{{
        {CKA_TOKEN, &tok, sizeof tok},
        {CKA_VALUE_LEN, &len, sizeof len},
        {CKA_ENCRYPT, &yes, sizeof yes},
        {CKA_DECRYPT, &yes, sizeof yes},
        {CKA_EXTRACTABLE, &ext, sizeof ext},
        {CKA_WRAP, &w, sizeof w},
        {CKA_UNWRAP, &w, sizeof w},
    }};
    CK_MECHANISM gen{CKM_AES_KEY_GEN, nullptr, 0};
    CK_OBJECT_HANDLE k = 0;
    BOOST_REQUIRE(f().C_GenerateKey(h, &gen, t.data(), t.size(), &k) == CKR_OK);
    return k;
}

auto bytes_of(std::string_view s) -> std::vector<CK_BYTE> {
    return {s.begin(), s.end()};
}

/// ECDSA-SHA256 over `msg` with `key`, through the length query.
auto sign(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE key, std::string_view msg) -> std::vector<CK_BYTE> {
    CK_MECHANISM m{CKM_ECDSA_SHA256, nullptr, 0};
    BOOST_REQUIRE(f().C_SignInit(h, &m, key) == CKR_OK);
    auto data = bytes_of(msg);
    CK_ULONG len = 0;
    BOOST_REQUIRE(f().C_Sign(h, data.data(), data.size(), nullptr, &len) == CKR_OK);
    std::vector<CK_BYTE> sig(len);
    BOOST_REQUIRE(f().C_Sign(h, data.data(), data.size(), sig.data(), &len) == CKR_OK);
    sig.resize(len);
    return sig;
}

auto verify(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE key, std::string_view msg,
            std::vector<CK_BYTE> sig) -> CK_RV {
    CK_MECHANISM m{CKM_ECDSA_SHA256, nullptr, 0};
    BOOST_REQUIRE(f().C_VerifyInit(h, &m, key) == CKR_OK);
    auto data = bytes_of(msg);
    return f().C_Verify(h, data.data(), data.size(), sig.data(), sig.size());
}

auto padded(const CK_UTF8CHAR* p, std::size_t n) -> std::string {
    std::string s(reinterpret_cast<const char*>(p), n);
    s.erase(s.find_last_not_of(' ') + 1);
    return s;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_library_exports_the_3_0_and_2_40_interfaces) {
    void* so = ::dlopen(KYTHIRA_PKCS11_LIBRARY, RTLD_NOW | RTLD_LOCAL);
    BOOST_REQUIRE(so != nullptr);
    auto* list_fn = reinterpret_cast<CK_C_GetInterfaceList>(::dlsym(so, "C_GetInterfaceList"));
    auto* get_list = reinterpret_cast<CK_C_GetFunctionList>(::dlsym(so, "C_GetFunctionList"));
    BOOST_REQUIRE(list_fn != nullptr);
    BOOST_REQUIRE(get_list != nullptr);
    // Every other function is reached through a list, never by name.
    BOOST_TEST(::dlsym(so, "C_Initialize") == nullptr);

    CK_ULONG n = 0;
    BOOST_REQUIRE(list_fn(nullptr, &n) == CKR_OK);
    BOOST_REQUIRE(n == 2U);
    std::array<CK_INTERFACE, 2> all{};
    CK_ULONG one = 1;
    BOOST_TEST(list_fn(all.data(), &one) == CKR_BUFFER_TOO_SMALL);
    BOOST_REQUIRE(list_fn(all.data(), &n) == CKR_OK);
    const auto* v0 = static_cast<const CK_VERSION*>(all[0].pFunctionList);
    const auto* v1 = static_cast<const CK_VERSION*>(all[1].pFunctionList);
    BOOST_TEST((v0->major == 3 && v0->minor == 0));
    BOOST_TEST((v1->major == 2 && v1->minor == 40));

    CK_FUNCTION_LIST_PTR legacy = nullptr;
    BOOST_REQUIRE(get_list(&legacy) == CKR_OK);
    BOOST_TEST((legacy->version.major == 2 && legacy->version.minor == 40));
    BOOST_TEST((legacy->C_Initialize == f().C_Initialize));

    CK_VERSION four{4, 0};
    CK_INTERFACE_PTR none = nullptr;
    auto* get = reinterpret_cast<CK_C_GetInterface>(::dlsym(so, "C_GetInterface"));
    BOOST_TEST(get(nullptr, &four, &none, 0) == CKR_ARGUMENTS_BAD);
    std::string other = "Vendor";
    BOOST_TEST(get(reinterpret_cast<CK_UTF8CHAR_PTR>(other.data()), nullptr, &none, 0) ==
               CKR_ARGUMENTS_BAD);
    BOOST_REQUIRE(get(nullptr, nullptr, &none, 0) == CKR_OK);
    BOOST_TEST(none->pFunctionList == static_cast<void*>(&f()));
}

BOOST_AUTO_TEST_CASE(initialize_needs_a_configuration_and_answers_once) {
    ::unsetenv("KYTHIRA_PKCS11_CONF");  // NOLINT(concurrency-mt-unsafe)
    BOOST_TEST(f().C_Initialize(nullptr) == CKR_GENERAL_ERROR);
    BOOST_TEST(f().C_Finalize(nullptr) == CKR_CRYPTOKI_NOT_INITIALIZED);
    CK_ULONG n = 0;
    BOOST_TEST(f().C_GetSlotList(CK_FALSE, nullptr, &n) == CKR_CRYPTOKI_NOT_INITIALIZED);

    // Mutex callbacks without all four are refused.
    CK_C_INITIALIZE_ARGS half{};
    half.CreateMutex = [](CK_VOID_PTR_PTR) -> CK_RV { return CKR_OK; };
    BOOST_TEST(f().C_Initialize(&half) == CKR_ARGUMENTS_BAD);

    node n_;
    socket_server a(n_.layer);
    loaded lib({a.cfg.socket_path});
    BOOST_TEST(f().C_Initialize(nullptr) == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    CK_INFO info{};
    BOOST_REQUIRE(f().C_GetInfo(&info) == CKR_OK);
    BOOST_TEST((info.cryptokiVersion.major == 3 && info.cryptokiVersion.minor == 0));
    BOOST_TEST(padded(info.manufacturerID, sizeof info.manufacturerID) == "Kythira");
}

BOOST_AUTO_TEST_CASE(slots_tokens_and_sessions_follow_the_bindings) {
    node n;
    socket_server a(n.layer);
    loaded lib({a.cfg.socket_path});

    // app-a is bound to the first token only.
    CK_ULONG count = 0;
    BOOST_REQUIRE(f().C_GetSlotList(CK_TRUE, nullptr, &count) == CKR_OK);
    BOOST_REQUIRE(count == 1U);
    CK_SLOT_ID slot = 0;
    BOOST_REQUIRE(f().C_GetSlotList(CK_TRUE, &slot, &count) == CKR_OK);
    BOOST_TEST(slot == k_token);
    CK_TOKEN_INFO t{};
    BOOST_REQUIRE(f().C_GetTokenInfo(slot, &t) == CKR_OK);
    BOOST_TEST(padded(t.label, sizeof t.label) == "alpha");
    BOOST_TEST(padded(t.manufacturerID, sizeof t.manufacturerID) == "Kythira");
    BOOST_TEST(padded(t.model, sizeof t.model) == "virtual HSM");
    BOOST_TEST((t.flags & CKF_TOKEN_INITIALIZED) != 0U);
    BOOST_TEST((t.flags & CKF_USER_PIN_INITIALIZED) != 0U);
    BOOST_TEST((t.flags & CKF_LOGIN_REQUIRED) != 0U);
    CK_SLOT_INFO si{};
    BOOST_REQUIRE(f().C_GetSlotInfo(slot, &si) == CKR_OK);
    BOOST_TEST((si.flags & CKF_TOKEN_PRESENT) != 0U);
    BOOST_TEST((si.flags & CKF_HW_SLOT) == 0U);
    BOOST_TEST(f().C_GetTokenInfo(k_other_token, &t) != CKR_OK);

    CK_ULONG mechs = 0;
    BOOST_REQUIRE(f().C_GetMechanismList(slot, nullptr, &mechs) == CKR_OK);
    std::vector<CK_MECHANISM_TYPE> list(mechs);
    BOOST_REQUIRE(f().C_GetMechanismList(slot, list.data(), &mechs) == CKR_OK);
    BOOST_TEST((std::find(list.begin(), list.end(), CKM_AES_GCM) != list.end()));
    CK_MECHANISM_INFO mi{};
    BOOST_REQUIRE(f().C_GetMechanismInfo(slot, CKM_ECDSA_SHA256, &mi) == CKR_OK);
    BOOST_TEST((mi.flags & CKF_SIGN) != 0U);

    const auto h = open_rw();
    CK_SESSION_INFO info{};
    BOOST_REQUIRE(f().C_GetSessionInfo(h, &info) == CKR_OK);
    BOOST_TEST(info.state == CKS_RW_PUBLIC_SESSION);
    std::string wrong = "nope";
    BOOST_TEST(f().C_Login(h, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(wrong.data()),
                           wrong.size()) == CKR_PIN_INCORRECT);
    login_user(h);
    BOOST_REQUIRE(f().C_GetSessionInfo(h, &info) == CKR_OK);
    BOOST_TEST(info.state == CKS_RW_USER_FUNCTIONS);
    // A second session of the application shares the login.
    const auto h2 = open_rw();
    BOOST_REQUIRE(f().C_GetSessionInfo(h2, &info) == CKR_OK);
    BOOST_TEST(info.state == CKS_RW_USER_FUNCTIONS);
    BOOST_TEST(f().C_CloseSession(h2) == CKR_OK);
    BOOST_TEST(f().C_GetSessionInfo(h2, &info) == CKR_SESSION_HANDLE_INVALID);
    BOOST_TEST(f().C_Logout(h) == CKR_OK);
    BOOST_REQUIRE(f().C_GetSessionInfo(h, &info) == CKR_OK);
    BOOST_TEST(info.state == CKS_RW_PUBLIC_SESSION);
    BOOST_TEST(f().C_CloseAllSessions(slot) == CKR_OK);
    BOOST_TEST(f().C_GetSessionInfo(h, &info) == CKR_SESSION_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(sign_keeps_its_output_through_the_length_query) {
    node n;
    socket_server a(n.layer);
    loaded lib({a.cfg.socket_path});
    const auto h = open_rw();
    login_user(h);
    const auto [pub, priv] = ec_pair(h, false);

    CK_MECHANISM m{CKM_ECDSA_SHA256, nullptr, 0};
    BOOST_REQUIRE(f().C_SignInit(h, &m, priv) == CKR_OK);
    BOOST_TEST(f().C_SignInit(h, &m, priv) == CKR_OPERATION_ACTIVE);
    auto data = bytes_of("hello");
    CK_ULONG len = 0;
    BOOST_REQUIRE(f().C_Sign(h, data.data(), data.size(), nullptr, &len) == CKR_OK);
    BOOST_TEST(len == 64U);
    std::vector<CK_BYTE> sig(len);
    CK_ULONG small = 10;
    BOOST_TEST(f().C_Sign(h, data.data(), data.size(), sig.data(), &small) == CKR_BUFFER_TOO_SMALL);
    BOOST_TEST(small == 64U);
    // The operation is still active: the same signature arrives.
    BOOST_REQUIRE(f().C_Sign(h, data.data(), data.size(), sig.data(), &len) == CKR_OK);
    BOOST_TEST(f().C_Sign(h, data.data(), data.size(), sig.data(), &len) ==
               CKR_OPERATION_NOT_INITIALIZED);
    BOOST_TEST(verify(h, pub, "hello", sig) == CKR_OK);
    sig[5] ^= 1U;
    BOOST_TEST(verify(h, pub, "hello", sig) == CKR_SIGNATURE_INVALID);

    // Multi-part sign and verify.
    BOOST_REQUIRE(f().C_SignInit(h, &m, priv) == CKR_OK);
    auto part1 = bytes_of("hel");
    auto part2 = bytes_of("lo");
    BOOST_REQUIRE(f().C_SignUpdate(h, part1.data(), part1.size()) == CKR_OK);
    BOOST_REQUIRE(f().C_SignUpdate(h, part2.data(), part2.size()) == CKR_OK);
    len = 0;
    BOOST_REQUIRE(f().C_SignFinal(h, nullptr, &len) == CKR_OK);
    std::vector<CK_BYTE> sig2(len);
    BOOST_REQUIRE(f().C_SignFinal(h, sig2.data(), &len) == CKR_OK);
    BOOST_REQUIRE(f().C_VerifyInit(h, &m, pub) == CKR_OK);
    BOOST_REQUIRE(f().C_VerifyUpdate(h, part1.data(), part1.size()) == CKR_OK);
    BOOST_REQUIRE(f().C_VerifyUpdate(h, part2.data(), part2.size()) == CKR_OK);
    BOOST_TEST(f().C_VerifyFinal(h, sig2.data(), sig2.size()) == CKR_OK);

    // Digest, one-shot and in parts, agree.
    CK_MECHANISM sha{CKM_SHA256, nullptr, 0};
    BOOST_REQUIRE(f().C_DigestInit(h, &sha) == CKR_OK);
    std::array<CK_BYTE, 32> d1{};
    len = d1.size();
    BOOST_REQUIRE(f().C_Digest(h, data.data(), data.size(), d1.data(), &len) == CKR_OK);
    BOOST_REQUIRE(f().C_DigestInit(h, &sha) == CKR_OK);
    BOOST_REQUIRE(f().C_DigestUpdate(h, part1.data(), part1.size()) == CKR_OK);
    BOOST_REQUIRE(f().C_DigestUpdate(h, part2.data(), part2.size()) == CKR_OK);
    std::array<CK_BYTE, 32> d2{};
    len = d2.size();
    BOOST_REQUIRE(f().C_DigestFinal(h, d2.data(), &len) == CKR_OK);
    BOOST_TEST(d1 == d2);

    std::array<CK_BYTE, 16> rnd{};
    BOOST_TEST(f().C_GenerateRandom(h, rnd.data(), rnd.size()) == CKR_OK);
    BOOST_TEST(rnd != (std::array<CK_BYTE, 16>{}));
}

BOOST_AUTO_TEST_CASE(aes_gcm_attributes_and_find) {
    node n;
    socket_server a(n.layer);
    loaded lib({a.cfg.socket_path});
    const auto h = open_rw();
    login_user(h);
    const auto key = aes_key(h, true, false);

    // A sensitive value is unavailable; the other attributes are not.
    std::array<CK_BYTE, 32> value{};
    CK_ULONG len = 0;
    CK_BBOOL sensitive = CK_FALSE;
    std::array<CK_ATTRIBUTE, 3> get{{
        {CKA_VALUE, value.data(), value.size()},
        {CKA_VALUE_LEN, &len, sizeof len},
        {CKA_SENSITIVE, &sensitive, sizeof sensitive},
    }};
    BOOST_TEST(f().C_GetAttributeValue(h, key, get.data(), get.size()) == CKR_ATTRIBUTE_SENSITIVE);
    BOOST_TEST(get[0].ulValueLen == CK_UNAVAILABLE_INFORMATION);
    BOOST_TEST(len == 32U);
    BOOST_TEST(sensitive == CK_TRUE);
    // The length query fills lengths only.
    CK_ATTRIBUTE q{CKA_VALUE_LEN, nullptr, 0};
    BOOST_REQUIRE(f().C_GetAttributeValue(h, key, &q, 1) == CKR_OK);
    BOOST_TEST(q.ulValueLen == sizeof(CK_ULONG));
    // CKA_SENSITIVE cannot go back to false.
    std::array<CK_ATTRIBUTE, 1> unset{{{CKA_SENSITIVE, &no, sizeof no}}};
    BOOST_TEST(f().C_SetAttributeValue(h, key, unset.data(), 1) == CKR_ATTRIBUTE_READ_ONLY);
    std::string label = "gcm-key";
    std::array<CK_ATTRIBUTE, 1> named{{{CKA_LABEL, label.data(), label.size()}}};
    BOOST_REQUIRE(f().C_SetAttributeValue(h, key, named.data(), 1) == CKR_OK);

    std::array<CK_BYTE, 12> iv{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    auto aad = bytes_of("header");
    CK_GCM_PARAMS gcm{iv.data(), iv.size(), iv.size() * 8, aad.data(), aad.size(), 128};
    CK_MECHANISM m{CKM_AES_GCM, &gcm, sizeof gcm};
    auto plain = bytes_of("the quick brown fox");
    BOOST_REQUIRE(f().C_EncryptInit(h, &m, key) == CKR_OK);
    CK_ULONG clen = 0;
    BOOST_REQUIRE(f().C_Encrypt(h, plain.data(), plain.size(), nullptr, &clen) == CKR_OK);
    BOOST_TEST(clen == plain.size() + 16);
    std::vector<CK_BYTE> cipher(clen);
    BOOST_REQUIRE(f().C_Encrypt(h, plain.data(), plain.size(), cipher.data(), &clen) == CKR_OK);
    BOOST_REQUIRE(f().C_DecryptInit(h, &m, key) == CKR_OK);
    CK_ULONG plen = 0;
    BOOST_REQUIRE(f().C_Decrypt(h, cipher.data(), cipher.size(), nullptr, &plen) == CKR_OK);
    std::vector<CK_BYTE> back(plen);
    BOOST_REQUIRE(f().C_Decrypt(h, cipher.data(), cipher.size(), back.data(), &plen) == CKR_OK);
    back.resize(plen);
    BOOST_TEST(back == plain);
    cipher[0] ^= 1U;
    BOOST_REQUIRE(f().C_DecryptInit(h, &m, key) == CKR_OK);
    plen = back.size() + 16;
    back.resize(plen);
    BOOST_TEST(f().C_Decrypt(h, cipher.data(), cipher.size(), back.data(), &plen) ==
               CKR_ENCRYPTED_DATA_INVALID);

    // Multi-part encryption produces the same bytes at the final call.
    BOOST_REQUIRE(f().C_EncryptInit(h, &m, key) == CKR_OK);
    CK_ULONG none = 99;
    BOOST_REQUIRE(f().C_EncryptUpdate(h, plain.data(), 4, nullptr, &none) == CKR_OK);
    BOOST_TEST(none == 0U);
    BOOST_REQUIRE(f().C_EncryptUpdate(h, plain.data() + 4, plain.size() - 4, nullptr, &none) ==
                  CKR_OK);
    clen = 0;
    BOOST_REQUIRE(f().C_EncryptFinal(h, nullptr, &clen) == CKR_OK);
    std::vector<CK_BYTE> cipher2(clen);
    BOOST_REQUIRE(f().C_EncryptFinal(h, cipher2.data(), &clen) == CKR_OK);
    cipher[0] ^= 1U;
    BOOST_TEST(cipher2 == cipher);

    // Find by label, in pages.
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    std::array<CK_ATTRIBUTE, 2> want{{
        {CKA_CLASS, &cls, sizeof cls},
        {CKA_LABEL, label.data(), label.size()},
    }};
    BOOST_REQUIRE(f().C_FindObjectsInit(h, want.data(), want.size()) == CKR_OK);
    BOOST_TEST(f().C_FindObjectsInit(h, want.data(), want.size()) == CKR_OPERATION_ACTIVE);
    std::array<CK_OBJECT_HANDLE, 4> found{};
    CK_ULONG got = 0;
    BOOST_REQUIRE(f().C_FindObjects(h, found.data(), found.size(), &got) == CKR_OK);
    BOOST_TEST(got == 1U);
    BOOST_TEST(found[0] == key);
    BOOST_REQUIRE(f().C_FindObjects(h, found.data(), found.size(), &got) == CKR_OK);
    BOOST_TEST(got == 0U);
    BOOST_TEST(f().C_FindObjectsFinal(h) == CKR_OK);

    BOOST_TEST(f().C_DestroyObject(h, key) == CKR_OK);
    BOOST_TEST(f().C_EncryptInit(h, &m, key) == CKR_KEY_HANDLE_INVALID);
}

BOOST_AUTO_TEST_CASE(wrap_and_unwrap_move_a_key) {
    node n;
    socket_server a(n.layer);
    loaded lib({a.cfg.socket_path});
    const auto h = open_rw();
    login_user(h);
    const auto kek = aes_key(h, true, false, true);
    const auto movable = aes_key(h, true, true);
    const auto stuck = aes_key(h, true, false);

    CK_MECHANISM kwp{CKM_AES_KEY_WRAP_KWP, nullptr, 0};
    CK_ULONG len = 0;
    BOOST_REQUIRE(f().C_WrapKey(h, &kwp, kek, movable, nullptr, &len) == CKR_OK);
    std::vector<CK_BYTE> wrapped(len);
    CK_ULONG small = 8;
    BOOST_TEST(f().C_WrapKey(h, &kwp, kek, movable, wrapped.data(), &small) ==
               CKR_BUFFER_TOO_SMALL);
    BOOST_REQUIRE(f().C_WrapKey(h, &kwp, kek, movable, wrapped.data(), &len) == CKR_OK);
    BOOST_TEST(f().C_WrapKey(h, &kwp, kek, stuck, nullptr, &len) == CKR_KEY_UNEXTRACTABLE);

    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_AES;
    std::array<CK_ATTRIBUTE, 5> t{{
        {CKA_CLASS, &cls, sizeof cls},
        {CKA_KEY_TYPE, &type, sizeof type},
        {CKA_TOKEN, &no, sizeof no},
        {CKA_ENCRYPT, &yes, sizeof yes},
        {CKA_DECRYPT, &yes, sizeof yes},
    }};
    CK_OBJECT_HANDLE unwrapped = 0;
    BOOST_REQUIRE(f().C_UnwrapKey(h, &kwp, kek, wrapped.data(), wrapped.size(), t.data(), t.size(),
                                  &unwrapped) == CKR_OK);

    // Both keys encrypt alike.
    std::array<CK_BYTE, 12> iv{};
    CK_GCM_PARAMS gcm{iv.data(), iv.size(), 96, nullptr, 0, 128};
    CK_MECHANISM m{CKM_AES_GCM, &gcm, sizeof gcm};
    auto plain = bytes_of("moved");
    const auto enc = [&](CK_OBJECT_HANDLE k) {
        BOOST_REQUIRE(f().C_EncryptInit(h, &m, k) == CKR_OK);
        std::vector<CK_BYTE> out(plain.size() + 16);
        CK_ULONG l = out.size();
        BOOST_REQUIRE(f().C_Encrypt(h, plain.data(), plain.size(), out.data(), &l) == CKR_OK);
        return out;
    };
    BOOST_TEST(enc(unwrapped) == enc(movable));
    wrapped[3] ^= 1U;
    BOOST_TEST(f().C_UnwrapKey(h, &kwp, kek, wrapped.data(), wrapped.size(), t.data(), t.size(),
                               &unwrapped) == CKR_WRAPPED_KEY_INVALID);
}

BOOST_AUTO_TEST_CASE(failover_restores_sessions_logins_and_unstarted_operations) {
    node n;
    socket_server a(n.layer);
    socket_server b(n.layer);
    loaded lib({a.cfg.socket_path, b.cfg.socket_path});

    const auto s1 = open_rw();
    login_user(s1);
    const auto [pub, priv] = ec_pair(s1, true);
    BOOST_TEST(verify(s1, pub, "before", sign(s1, priv, "before")) == CKR_OK);
    // s2 made a session object: it lives on the server that goes away.
    const auto s2 = open_rw();
    (void)aes_key(s2, false, false);
    // s3 is part way through a digest.
    const auto s3 = open_rw();
    CK_MECHANISM sha{CKM_SHA256, nullptr, 0};
    BOOST_REQUIRE(f().C_DigestInit(s3, &sha) == CKR_OK);
    auto part = bytes_of("abc");
    BOOST_REQUIRE(f().C_DigestUpdate(s3, part.data(), part.size()) == CKR_OK);
    // s1 has a signature initialized and no data sent.
    CK_MECHANISM ecdsa{CKM_ECDSA_SHA256, nullptr, 0};
    BOOST_REQUIRE(f().C_SignInit(s1, &ecdsa, priv) == CKR_OK);
    // s4 has its signature already here, after a length query.
    const auto s4 = open_rw();
    BOOST_REQUIRE(f().C_SignInit(s4, &ecdsa, priv) == CKR_OK);
    auto msg = bytes_of("kept");
    CK_ULONG len4 = 0;
    BOOST_REQUIRE(f().C_Sign(s4, msg.data(), msg.size(), nullptr, &len4) == CKR_OK);
    BOOST_TEST(a.server->stats().accepted == 1U);

    a.stop();

    // The sign is initialized again on b, after logging in there, and
    // runs once more.
    auto data = bytes_of("after");
    CK_ULONG len = 64;
    std::vector<CK_BYTE> sig(len);
    BOOST_REQUIRE(f().C_Sign(s1, data.data(), data.size(), sig.data(), &len) == CKR_OK);
    BOOST_TEST(b.server->stats().accepted == 1U);
    BOOST_TEST(verify(s1, pub, "after", sig) == CKR_OK);
    CK_SESSION_INFO info{};
    BOOST_REQUIRE(f().C_GetSessionInfo(s1, &info) == CKR_OK);
    BOOST_TEST(info.state == CKS_RW_USER_FUNCTIONS);

    BOOST_TEST(f().C_GetSessionInfo(s2, &info) == CKR_SESSION_HANDLE_INVALID);
    BOOST_TEST(f().C_DigestInit(s2, &sha) == CKR_SESSION_HANDLE_INVALID);

    std::array<CK_BYTE, 32> digest{};
    CK_ULONG dlen = digest.size();
    BOOST_TEST(f().C_DigestFinal(s3, digest.data(), &dlen) == CKR_DEVICE_ERROR);
    BOOST_TEST(f().C_DigestFinal(s3, digest.data(), &dlen) == CKR_OPERATION_NOT_INITIALIZED);
    BOOST_REQUIRE(f().C_DigestInit(s3, &sha) == CKR_OK);
    BOOST_TEST(f().C_Digest(s3, part.data(), part.size(), digest.data(), &dlen) == CKR_OK);

    std::vector<CK_BYTE> sig4(len4);
    BOOST_REQUIRE(f().C_Sign(s4, msg.data(), msg.size(), sig4.data(), &len4) == CKR_OK);
    BOOST_TEST(verify(s4, pub, "kept", sig4) == CKR_OK);

    // With no server left, a call answers CKR_DEVICE_ERROR, and the
    // library connects again once one answers.
    b.stop();
    CK_TOKEN_INFO t{};
    BOOST_TEST(f().C_GetTokenInfo(k_token, &t) == CKR_DEVICE_ERROR);
    socket_server c(n.layer);
    std::filesystem::rename(c.cfg.socket_path, a.cfg.socket_path);
    BOOST_TEST(f().C_GetTokenInfo(k_token, &t) == CKR_OK);
    std::filesystem::rename(a.cfg.socket_path, c.cfg.socket_path);
}

BOOST_AUTO_TEST_CASE(many_threads_share_the_connection) {
    node n;
    socket_server a(n.layer);
    loaded lib({a.cfg.socket_path});
    const auto h = open_rw();
    login_user(h);
    const auto [pub, priv] = ec_pair(h, true);

    constexpr int threads = 6;
    constexpr int rounds = 15;
    std::atomic<int> ok{0};
    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i) {
        pool.emplace_back([&, i] {
            CK_SESSION_HANDLE s = 0;
            if (f().C_OpenSession(k_token, CKF_SERIAL_SESSION, nullptr, nullptr, &s) != CKR_OK) {
                return;
            }
            for (int r = 0; r < rounds; ++r) {
                const std::string msg = "t" + std::to_string(i) + "r" + std::to_string(r);
                CK_MECHANISM m{CKM_ECDSA_SHA256, nullptr, 0};
                auto data = bytes_of(msg);
                std::array<CK_BYTE, 64> sig{};
                CK_ULONG len = sig.size();
                if (f().C_SignInit(s, &m, priv) != CKR_OK ||
                    f().C_Sign(s, data.data(), data.size(), sig.data(), &len) != CKR_OK ||
                    f().C_VerifyInit(s, &m, pub) != CKR_OK ||
                    f().C_Verify(s, data.data(), data.size(), sig.data(), len) != CKR_OK) {
                    return;
                }
                ok.fetch_add(1);
            }
            f().C_CloseSession(s);
        });
    }
    for (auto& t : pool) {
        t.join();
    }
    BOOST_TEST(ok.load() == threads * rounds);
    BOOST_TEST(a.server->stats().accepted == 1U);
}

BOOST_AUTO_TEST_CASE(the_configuration_file) {
    namespace p = hsm::pkcs11lib;
    std::string error;
    auto c = p::parse_config(
        "# nodes\n"
        "endpoint = hsm-1.example:9444, [::1]:9445\n"
        "socket = /run/kythira/hsm.sock  # local first\n"
        "endpoint=hsm-2.example:1\n"
        "cert = /c.pem\nkey = /k.pem\nca = /ca.pem\n"
        "timeout_s = 7\n",
        &error);
    BOOST_REQUIRE_MESSAGE(c.has_value(), error);
    BOOST_REQUIRE(c->endpoints.size() == 4U);
    BOOST_TEST(c->endpoints[0].socket_path == "/run/kythira/hsm.sock");
    BOOST_TEST(c->endpoints[1].host == "hsm-1.example");
    BOOST_TEST(c->endpoints[1].port == 9444U);
    BOOST_TEST(c->endpoints[2].host == "::1");
    BOOST_TEST(c->endpoints[2].port == 9445U);
    BOOST_TEST(c->endpoints[3].host == "hsm-2.example");
    BOOST_TEST(c->cert_path == "/c.pem");
    BOOST_TEST(c->ca_path == "/ca.pem");
    BOOST_TEST(c->timeout_s == 7U);

    const auto refused = [&](std::string_view text, std::string_view why) {
        error.clear();
        BOOST_TEST(!p::parse_config(text, &error).has_value());
        BOOST_TEST(error.find(why) != std::string::npos, error);
    };
    refused("", "no socket and no endpoint");
    refused("endpoint = h:1\n", "needs cert, key and ca");
    refused("socket = /s\nbogus = 1\n", "line 2: unknown setting bogus");
    refused("socket\n", "line 1: expected name = value");
    refused("socket =\n", "socket has no value");
    refused("endpoint = h\ncert=a\nkey=b\nca=c\n", "is not host:port");
    refused("endpoint = h:0\ncert=a\nkey=b\nca=c\n", "is not host:port");
    refused("endpoint = h:65536\ncert=a\nkey=b\nca=c\n", "is not host:port");
    refused("socket = /s\ntimeout_s = 0\n", "timeout_s is a positive");
    refused("socket = /s\ntimeout_s = -3\n", "timeout_s is a positive");
    BOOST_TEST(!p::load_config("/nonexistent/kythira.conf", &error).has_value());
    BOOST_TEST(error == "cannot read /nonexistent/kythira.conf");
}
