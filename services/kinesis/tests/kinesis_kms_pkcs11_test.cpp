// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// `KINESIS_KMS=pkcs11` (`.kiro/specs/virtual-hsm/` task 13, Requirement
// 10.2): the PKCS#11 key provider against a software token, through the
// same pkcs11::backend seam the co-located virtual HSM and a dlopen'd
// module plug into. Data keys round-trip, are bound to the key id and the
// encryption context, refuse key ids naming another token or library, map
// a wrong PIN to access_denied, and survive the token dropping every
// session (a restarted module, a failover).

#define BOOST_TEST_MODULE kinesis_kms_pkcs11_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_kms_pkcs11.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kin = kythira::kinesis;
namespace p11 = kythira::pkcs11;

namespace {

constexpr std::string_view k_token = "kinesis-keys";
constexpr std::string_view k_pin = "1234";

struct pkey_free {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
using pkey_ptr = std::shared_ptr<EVP_PKEY>;

auto make_rsa() -> pkey_ptr {
    EVP_PKEY* raw = EVP_RSA_gen(2048);
    BOOST_REQUIRE(raw != nullptr);
    return {raw, pkey_free{}};
}

auto bn_param(EVP_PKEY* k, const char* name) -> p11::bytes {
    BIGNUM* bn = nullptr;
    BOOST_REQUIRE(EVP_PKEY_get_bn_param(k, name, &bn) == 1);
    p11::bytes out(static_cast<std::size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, out.data());
    BN_free(bn);
    return out;
}

/// A token in software: RSA private keys that decrypt RSA-OAEP, a PIN,
/// sessions that `drop_sessions` invalidates as a restarted module would.
class soft_token final : public p11::backend {
public:
    struct key {
        std::string label;
        CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
        pkey_ptr pkey;
    };

    soft_token() {
        _objects[1] = {"stream-key", CKO_PRIVATE_KEY, make_rsa()};
        _objects[2] = {"other-key", CKO_PRIVATE_KEY, make_rsa()};
        _objects[3] = {"stream-key", CKO_PUBLIC_KEY, _objects[1].pkey};
    }

    void drop_sessions() { _sessions.clear(); }
    [[nodiscard]] auto sessions_opened() const -> int { return _opened; }

    auto library() -> p11::library_info override { return {"Test", "soft token", {1, 0}}; }
    auto tokens() -> std::vector<p11::token_info> override {
        p11::token_info t;
        t.slot = 7;
        t.label = std::string(k_token);
        t.serial = "0001";
        t.flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED;
        return {t};
    }
    auto mechanisms(CK_SLOT_ID /*slot*/) -> std::vector<CK_MECHANISM_TYPE> override {
        return {CKM_RSA_PKCS_OAEP};
    }
    auto open_session(CK_SLOT_ID slot) -> CK_SESSION_HANDLE override {
        if (slot != 7) {
            throw p11::error("open_session", CKR_SLOT_ID_INVALID);
        }
        ++_opened;
        _sessions[++_next] = false;
        return _next;
    }
    void close_session(CK_SESSION_HANDLE s) override { _sessions.erase(s); }
    void login(CK_SESSION_HANDLE s, std::string_view pin) override {
        live(s, false);
        if (pin != k_pin) {
            throw p11::error("login", CKR_PIN_INCORRECT);
        }
        _sessions[s] = true;
    }
    auto find_objects(CK_SESSION_HANDLE s, std::span<const p11::attribute> tmpl)
        -> std::vector<CK_OBJECT_HANDLE> override {
        live(s, true);
        std::vector<CK_OBJECT_HANDLE> out;
        for (const auto& [h, k] : _objects) {
            bool match = true;
            for (const auto& a : tmpl) {
                if (a.type == CKA_CLASS) {
                    match = match && p11::attribute::of_ulong(CKA_CLASS, k.cls).value == a.value;
                } else if (a.type == CKA_LABEL) {
                    match = match && std::string(a.value.begin(), a.value.end()) == k.label;
                } else {
                    match = false;
                }
            }
            if (match) {
                out.push_back(h);
            }
        }
        return out;
    }
    auto get_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                        std::span<const CK_ATTRIBUTE_TYPE> types)
        -> std::vector<std::optional<p11::bytes>> override {
        live(s, true);
        const auto& k = object(o);
        std::vector<std::optional<p11::bytes>> out;
        for (const auto t : types) {
            if (t == CKA_KEY_TYPE) {
                out.emplace_back(p11::attribute::of_ulong(t, CKK_RSA).value);
            } else if (t == CKA_MODULUS) {
                out.emplace_back(bn_param(k.pkey.get(), "n"));
            } else if (t == CKA_PUBLIC_EXPONENT) {
                out.emplace_back(bn_param(k.pkey.get(), "e"));
            } else {
                out.emplace_back(std::nullopt);
            }
        }
        return out;
    }
    auto decrypt(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE o,
                 std::span<const std::uint8_t> data) -> p11::bytes override {
        live(s, true);
        const auto& k = object(o);
        if (m.mechanism != CKM_RSA_PKCS_OAEP || k.cls != CKO_PRIVATE_KEY) {
            throw p11::error("decrypt", CKR_MECHANISM_INVALID);
        }
        const auto* p = static_cast<const CK_RSA_PKCS_OAEP_PARAMS*>(m.pParameter);
        const EVP_MD* md = p->hashAlg == CKM_SHA_1 ? EVP_sha1() : EVP_sha256();
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
            EVP_PKEY_CTX_new(k.pkey.get(), nullptr), &EVP_PKEY_CTX_free);
        std::size_t n = 0;
        if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), md) != 1 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md) != 1 ||
            EVP_PKEY_decrypt(ctx.get(), nullptr, &n, data.data(), data.size()) != 1) {
            throw p11::error("decrypt", CKR_ENCRYPTED_DATA_INVALID);
        }
        p11::bytes out(n);
        if (EVP_PKEY_decrypt(ctx.get(), out.data(), &n, data.data(), data.size()) != 1) {
            throw p11::error("decrypt", CKR_ENCRYPTED_DATA_INVALID);
        }
        out.resize(n);
        return out;
    }

    // Not used by the provider.
    auto generate_key(CK_SESSION_HANDLE /*s*/, const CK_MECHANISM& /*m*/,
                      std::span<const p11::attribute> /*t*/) -> CK_OBJECT_HANDLE override {
        throw p11::error("generate_key", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto generate_key_pair(CK_SESSION_HANDLE /*s*/, const CK_MECHANISM& /*m*/,
                           std::span<const p11::attribute> /*pub*/,
                           std::span<const p11::attribute> /*priv*/)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> override {
        throw p11::error("generate_key_pair", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto create_object(CK_SESSION_HANDLE /*s*/, std::span<const p11::attribute> /*t*/)
        -> CK_OBJECT_HANDLE override {
        throw p11::error("create_object", CKR_FUNCTION_NOT_SUPPORTED);
    }
    void destroy_object(CK_SESSION_HANDLE /*s*/, CK_OBJECT_HANDLE /*o*/) override {
        throw p11::error("destroy_object", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto sign(CK_SESSION_HANDLE /*s*/, const CK_MECHANISM& /*m*/, CK_OBJECT_HANDLE /*k*/,
              std::span<const std::uint8_t> /*d*/) -> p11::bytes override {
        throw p11::error("sign", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto verify(CK_SESSION_HANDLE /*s*/, const CK_MECHANISM& /*m*/, CK_OBJECT_HANDLE /*k*/,
                std::span<const std::uint8_t> /*d*/, std::span<const std::uint8_t> /*sig*/)
        -> bool override {
        throw p11::error("verify", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto encrypt(CK_SESSION_HANDLE /*s*/, const CK_MECHANISM& /*m*/, CK_OBJECT_HANDLE /*k*/,
                 std::span<const std::uint8_t> /*d*/) -> p11::bytes override {
        throw p11::error("encrypt", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto generate_random(CK_SESSION_HANDLE /*s*/, std::size_t /*length*/) -> p11::bytes override {
        throw p11::error("generate_random", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto wrap_key(CK_SESSION_HANDLE /*s*/, const CK_MECHANISM& /*m*/, CK_OBJECT_HANDLE /*w*/,
                  CK_OBJECT_HANDLE /*k*/) -> p11::bytes override {
        throw p11::error("wrap_key", CKR_FUNCTION_NOT_SUPPORTED);
    }
    auto unwrap_key(CK_SESSION_HANDLE /*s*/, const CK_MECHANISM& /*m*/, CK_OBJECT_HANDLE /*u*/,
                    std::span<const std::uint8_t> /*w*/, std::span<const p11::attribute> /*t*/)
        -> CK_OBJECT_HANDLE override {
        throw p11::error("unwrap_key", CKR_FUNCTION_NOT_SUPPORTED);
    }

private:
    void live(CK_SESSION_HANDLE s, bool logged_in) const {
        const auto it = _sessions.find(s);
        if (it == _sessions.end()) {
            throw p11::error("session", CKR_SESSION_HANDLE_INVALID);
        }
        if (logged_in && !it->second) {
            throw p11::error("session", CKR_USER_NOT_LOGGED_IN);
        }
    }
    [[nodiscard]] auto object(CK_OBJECT_HANDLE o) const -> const key& {
        const auto it = _objects.find(o);
        if (it == _objects.end()) {
            throw p11::error("object", CKR_OBJECT_HANDLE_INVALID);
        }
        return it->second;
    }

    std::map<CK_OBJECT_HANDLE, key> _objects;
    std::map<CK_SESSION_HANDLE, bool> _sessions;
    CK_SESSION_HANDLE _next = 100;
    int _opened = 0;
};

struct fixture {
    std::shared_ptr<soft_token> token = std::make_shared<soft_token>();
    int loads = 0;

    auto provider(std::string_view pin = k_pin,
                  p11::hash_algorithm oaep = p11::hash_algorithm::sha256)
        -> kin::pkcs11_kms_provider {
        kin::pkcs11_kms_config c;
        c.token = p11::uri::parse("pkcs11:token=" + std::string(k_token) +
                                  "?pin-value=" + std::string(pin));
        c.oaep = oaep;
        return {std::move(c), [this] {
                    ++loads;
                    return p11::module(token);
                }};
    }
};

const kin::encryption_context k_context{{"aws:kinesis:arn", "arn:aws:kinesis:x:1:stream/s"}};

auto failure_of(const std::function<void()>& f) -> std::optional<kin::kms_failure> {
    try {
        f();
    } catch (const kin::kms_error& e) {
        return e.failure();
    }
    return std::nullopt;
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(data_keys_round_trip_bound_to_key_and_context, fixture) {
    const auto kms = provider();
    const auto made = kms.generate_data_key("stream-key", k_context);
    BOOST_TEST(made._key_id == "stream-key");
    BOOST_TEST(made._wrapped.substr(0, 2) == "KP");
    BOOST_TEST(static_cast<int>(made._wrapped[3]) == 2);  // SHA-256
    const auto opened = kms.decrypt_data_key("stream-key", made._wrapped, k_context);
    BOOST_TEST((opened == made._plaintext));

    // A second key is fresh.
    BOOST_TEST((kms.generate_data_key("stream-key", k_context)._plaintext != made._plaintext));

    using enum kin::kms_failure;
    auto other_context = k_context;
    other_context["aws:kinesis:arn"] = "arn:aws:kinesis:x:1:stream/t";
    BOOST_TEST((failure_of([&] {
                    (void)kms.decrypt_data_key("stream-key", made._wrapped, other_context);
                }) == invalid_state));
    // The same key under its URI is another binding; another key fails OAEP.
    BOOST_TEST((failure_of([&] {
                    (void)kms.decrypt_data_key("pkcs11:object=stream-key", made._wrapped,
                                               k_context);
                }) == invalid_state));
    BOOST_TEST((failure_of([&] {
                    (void)kms.decrypt_data_key("other-key", made._wrapped, k_context);
                }) == invalid_state));
    auto tampered = made._wrapped;
    tampered.back() = static_cast<char>(tampered.back() ^ 1);
    BOOST_TEST((failure_of([&] {
                    (void)kms.decrypt_data_key("stream-key", tampered, k_context);
                }) == invalid_state));
    BOOST_TEST((failure_of([&] {
                    (void)kms.decrypt_data_key("stream-key", "not sealed", k_context);
                }) == invalid_state));

    // A URI key id works in its own right.
    const auto by_uri =
        kms.generate_data_key("pkcs11:token=kinesis-keys;object=stream-key", k_context);
    BOOST_TEST((kms.decrypt_data_key("pkcs11:token=kinesis-keys;object=stream-key", by_uri._wrapped,
                                     k_context) == by_uri._plaintext));
    BOOST_TEST(loads == 1);
}

BOOST_FIXTURE_TEST_CASE(key_ids_name_only_private_keys_on_the_configured_token, fixture) {
    const auto kms = provider();
    using enum kin::kms_failure;
    for (const std::string& id :
         {std::string(), std::string("missing-key"), std::string("pkcs11:token=other;object=k"),
          std::string("pkcs11:object=stream-key?module-path=/tmp/evil.so"),
          std::string("pkcs11:object=stream-key?pin-value=1234"),
          std::string("pkcs11:object=stream-key;type=public"), std::string("pkcs11:token"),
          std::string(kin::pkcs11_kms_provider::k_max_key_id + 1, 'k')}) {
        BOOST_TEST_CONTEXT("key id '" << id.substr(0, 60) << "'") {
            BOOST_TEST(
                (failure_of([&] { (void)kms.generate_data_key(id, k_context); }) == not_found));
        }
    }
}

BOOST_FIXTURE_TEST_CASE(a_wrong_pin_is_access_denied, fixture) {
    const auto kms = provider("9999");
    BOOST_TEST((failure_of([&] { (void)kms.generate_data_key("stream-key", k_context); }) ==
                kin::kms_failure::access_denied));
}

BOOST_FIXTURE_TEST_CASE(a_dropped_session_is_reopened_once, fixture) {
    const auto kms = provider();
    const auto made = kms.generate_data_key("stream-key", k_context);
    BOOST_TEST(token->sessions_opened() == 1);
    token->drop_sessions();
    BOOST_TEST((kms.decrypt_data_key("stream-key", made._wrapped, k_context) == made._plaintext));
    BOOST_TEST(token->sessions_opened() == 2);
    BOOST_TEST(loads == 1);
}

BOOST_FIXTURE_TEST_CASE(sha1_seals_record_their_hash_and_open_anywhere, fixture) {
    const auto sha1 = provider(k_pin, p11::hash_algorithm::sha1);
    const auto made = sha1.generate_data_key("stream-key", k_context);
    BOOST_TEST(static_cast<int>(made._wrapped[3]) == 1);
    // A provider configured for SHA-256 still opens it.
    fixture& self = *this;
    kin::pkcs11_kms_config c;
    c.token = p11::uri::parse("pkcs11:token=kinesis-keys?pin-value=1234");
    const kin::pkcs11_kms_provider sha256(std::move(c),
                                          [&self] { return p11::module(self.token); });
    BOOST_TEST(
        (sha256.decrypt_data_key("stream-key", made._wrapped, k_context) == made._plaintext));
}
