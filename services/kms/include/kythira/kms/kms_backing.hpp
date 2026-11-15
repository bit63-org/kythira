// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS's backing keys on a PKCS#11 token (.kiro/specs/kms-compatible-api/
// task 5, Requirements 4.1-4.5): the virtual HSM's `kms` token when
// co-located ("hsm.pkcs11"), the virtual HSM's client library, or any
// other PKCS#11 module, all through core's pkcs11::backend.
//
// Every backing key is a token object, private, sensitive and not
// extractable, generated on the token and labelled `kms:<key-id>:<version>`
// (with the same bytes as CKA_ID, which pairs an asymmetric key's halves).
// The catalog records the handle the token gave; the label is how the
// orphan sweep and a module whose handles change across sessions find it
// again. Key material never leaves the token, so nothing here can log or
// return it.
//
// Failures are backing_error. `unavailable` is a sealed or unreachable
// HSM (the virtual HSM answers CKR_DEVICE_ERROR while sealed): the API
// answers KMSInternalException (4.5). `unsupported` is a mechanism the
// module lacks: UnsupportedOperationException (4.3).

#include <kythira/kms/kms_catalog.hpp>

#include <raft/pkcs11_module.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::kms {

class backing_error : public std::runtime_error {
public:
    enum class kind : std::uint8_t {
        unavailable,  // sealed, unreachable, not logged in
        unsupported,  // the module lacks the mechanism
        failed,       // anything else
    };

    backing_error(kind k, CK_RV rv, const std::string& what)
        : std::runtime_error(what), _kind(k), _rv(rv) {}

    [[nodiscard]] auto which() const noexcept -> kind { return _kind; }
    [[nodiscard]] auto rv() const noexcept -> CK_RV { return _rv; }

private:
    kind _kind;
    CK_RV _rv;
};

[[nodiscard]] inline auto classify_rv(CK_RV rv) -> backing_error::kind {
    if (kythira::pkcs11::session_lost(rv) || rv == CKR_GENERAL_ERROR || rv == CKR_PIN_INCORRECT ||
        rv == CKR_PIN_LOCKED) {
        return backing_error::kind::unavailable;
    }
    if (rv == CKR_MECHANISM_INVALID || rv == CKR_MECHANISM_PARAM_INVALID ||
        rv == CKR_FUNCTION_NOT_SUPPORTED || rv == CKR_CURVE_NOT_SUPPORTED ||
        rv == CKR_KEY_SIZE_RANGE) {
        return backing_error::kind::unsupported;
    }
    return backing_error::kind::failed;
}

/// A backing key's label, `kms:<key-id>:<version>`.
[[nodiscard]] inline auto backing_label(std::string_view key_id, std::uint32_t version)
    -> std::string {
    return "kms:" + std::string(key_id) + ":" + std::to_string(version);
}

struct backing_ref {
    std::string key_id;
    std::uint32_t version = 0;

    auto operator<=>(const backing_ref&) const = default;
};

/// The key id and version a label names, or nullopt for a label that is
/// not a KMS backing key's.
[[nodiscard]] inline auto parse_backing_label(std::string_view label)
    -> std::optional<backing_ref> {
    if (!label.starts_with("kms:")) {
        return std::nullopt;
    }
    label.remove_prefix(4);
    const auto colon = label.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == label.size()) {
        return std::nullopt;
    }
    backing_ref r;
    r.key_id = std::string(label.substr(0, colon));
    const auto digits = label.substr(colon + 1);
    const auto [p, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), r.version);
    if (ec != std::errc{} || p != digits.data() + digits.size() || r.version == 0) {
        return std::nullopt;
    }
    return r;
}

namespace detail {

// DER ECParameters: the named curve's OID.
inline constexpr std::array<std::uint8_t, 10> ec_p256{0x06, 0x08, 0x2A, 0x86, 0x48,
                                                      0xCE, 0x3D, 0x03, 0x01, 0x07};
inline constexpr std::array<std::uint8_t, 7> ec_p384{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
inline constexpr std::array<std::uint8_t, 7> ec_p521{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
inline constexpr std::array<std::uint8_t, 7> ec_secp256k1{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};

[[nodiscard]] inline auto label_bytes(const std::string& label) -> std::span<const std::uint8_t> {
    return {reinterpret_cast<const std::uint8_t*>(label.data()), label.size()};
}

}  // namespace detail

/// The HMAC key length AWS uses for an HMAC spec, in bytes.
[[nodiscard]] constexpr auto hmac_key_bytes(key_spec s) -> CK_ULONG {
    switch (s) {
        case key_spec::hmac_224:
            return 28;
        case key_spec::hmac_256:
            return 32;
        case key_spec::hmac_384:
            return 48;
        case key_spec::hmac_512:
            return 64;
        default:
            return 0;
    }
}

/// The KMS's backing keys on one token, through one logged-in session.
/// Thread-safe: calls are serialized on the session, which is reopened
/// (and the call retried once) when the module lost it.
class backing_store {
public:
    backing_store(std::shared_ptr<kythira::pkcs11::backend> backend, CK_SLOT_ID slot,
                  std::string pin)
        : _b(std::move(backend)), _slot(slot), _pin(std::move(pin)) {
        if (!_b) {
            throw std::invalid_argument("kms backing_store: no backend");
        }
    }

    backing_store(const backing_store&) = delete;
    auto operator=(const backing_store&) -> backing_store& = delete;
    backing_store(backing_store&&) = delete;
    auto operator=(backing_store&&) -> backing_store& = delete;
    ~backing_store() {
        if (_session) {
            try {
                _b->close_session(*_session);
            } catch (...) {  // NOLINT(bugprone-empty-catch): closing is best effort
            }
        }
    }

    /// Generates the backing key for `key_id`'s `version` (Requirement
    /// 4.1). Returns the handle of the secret or private key.
    auto generate(std::string_view key_id, std::uint32_t version, key_spec spec, key_usage usage)
        -> std::uint64_t {
        if (!usage_allowed(spec, usage)) {
            throw std::invalid_argument("kms backing_store: usage not allowed for the key spec");
        }
        const auto label = backing_label(key_id, version);
        return call([&](CK_SESSION_HANDLE s) -> std::uint64_t {
            using kythira::pkcs11::attribute;
            const auto id = detail::label_bytes(label);
            std::vector<attribute> priv{
                attribute::of_bool(CKA_TOKEN, true),     attribute::of_bool(CKA_PRIVATE, true),
                attribute::of_bool(CKA_SENSITIVE, true), attribute::of_bool(CKA_EXTRACTABLE, false),
                attribute::of_string(CKA_LABEL, label),  attribute::of_bytes(CKA_ID, id),
                attribute::of_bool(CKA_DERIVE, false)};
            if (is_symmetric(spec) || hmac_key_bytes(spec) != 0) {
                const bool aes = is_symmetric(spec);
                priv.push_back(attribute::of_ulong(CKA_CLASS, CKO_SECRET_KEY));
                priv.push_back(
                    attribute::of_ulong(CKA_KEY_TYPE, aes ? CKK_AES : CKK_GENERIC_SECRET));
                priv.push_back(attribute::of_ulong(CKA_VALUE_LEN, aes ? 32 : hmac_key_bytes(spec)));
                priv.push_back(attribute::of_bool(CKA_ENCRYPT, aes));
                priv.push_back(attribute::of_bool(CKA_DECRYPT, aes));
                priv.push_back(attribute::of_bool(CKA_SIGN, !aes));
                priv.push_back(attribute::of_bool(CKA_VERIFY, !aes));
                priv.push_back(attribute::of_bool(CKA_WRAP, false));
                priv.push_back(attribute::of_bool(CKA_UNWRAP, false));
                CK_MECHANISM m{aes ? CKM_AES_KEY_GEN : CKM_GENERIC_SECRET_KEY_GEN, nullptr, 0};
                return _b->generate_key(s, m, priv);
            }
            const bool rsa = spec == key_spec::rsa_2048 || spec == key_spec::rsa_3072 ||
                             spec == key_spec::rsa_4096;
            const bool sign = usage == key_usage::sign_verify;
            std::vector<attribute> pub{
                attribute::of_bool(CKA_TOKEN, true), attribute::of_string(CKA_LABEL, label),
                attribute::of_bytes(CKA_ID, id), attribute::of_bool(CKA_VERIFY, sign)};
            priv.push_back(attribute::of_bool(CKA_SIGN, sign));
            if (rsa) {
                pub.push_back(attribute::of_bool(CKA_ENCRYPT, !sign));
                pub.push_back(attribute::of_bool(CKA_WRAP, false));
                priv.push_back(attribute::of_bool(CKA_DECRYPT, !sign));
                priv.push_back(attribute::of_bool(CKA_UNWRAP, false));
                const CK_ULONG bits = spec == key_spec::rsa_2048   ? 2048
                                      : spec == key_spec::rsa_3072 ? 3072
                                                                   : 4096;
                pub.push_back(attribute::of_ulong(CKA_MODULUS_BITS, bits));
                pub.push_back(
                    attribute::of_bytes(CKA_PUBLIC_EXPONENT, std::array<std::uint8_t, 3>{1, 0, 1}));
            } else {
                std::span<const std::uint8_t> curve;
                switch (spec) {
                    case key_spec::ecc_nist_p256:
                        curve = detail::ec_p256;
                        break;
                    case key_spec::ecc_nist_p384:
                        curve = detail::ec_p384;
                        break;
                    case key_spec::ecc_nist_p521:
                        curve = detail::ec_p521;
                        break;
                    default:
                        curve = detail::ec_secp256k1;
                        break;
                }
                pub.push_back(attribute::of_bytes(CKA_EC_PARAMS, curve));
            }
            CK_MECHANISM m{rsa ? CKM_RSA_PKCS_KEY_PAIR_GEN : CKM_EC_KEY_PAIR_GEN, nullptr, 0};
            return _b->generate_key_pair(s, m, pub, priv).second;
        });
    }

    /// The secret or private key `key_id`'s `version` has on the token.
    [[nodiscard]] auto find(std::string_view key_id, std::uint32_t version)
        -> std::optional<std::uint64_t> {
        const auto label = backing_label(key_id, version);
        return call([&](CK_SESSION_HANDLE s) -> std::optional<std::uint64_t> {
            using kythira::pkcs11::attribute;
            for (const CK_OBJECT_CLASS cls : {CKO_SECRET_KEY, CKO_PRIVATE_KEY}) {
                const std::array tmpl{attribute::of_ulong(CKA_CLASS, cls),
                                      attribute::of_string(CKA_LABEL, label)};
                const auto found = _b->find_objects(s, tmpl);
                if (!found.empty()) {
                    return found.front();
                }
            }
            return std::nullopt;
        });
    }

    /// Every KMS backing key on the token, for the orphan sweep: the
    /// secret and private keys whose label is a backing label.
    [[nodiscard]] auto list() -> std::vector<backing_ref> {
        return call([&](CK_SESSION_HANDLE s) {
            using kythira::pkcs11::attribute;
            std::vector<backing_ref> out;
            for (const CK_OBJECT_CLASS cls : {CKO_SECRET_KEY, CKO_PRIVATE_KEY}) {
                const std::array tmpl{attribute::of_ulong(CKA_CLASS, cls)};
                for (const auto o : _b->find_objects(s, tmpl)) {
                    const std::array<CK_ATTRIBUTE_TYPE, 1> types{CKA_LABEL};
                    const auto v = _b->get_attributes(s, o, types);
                    if (!v.empty() && v[0]) {
                        const std::string label(v[0]->begin(), v[0]->end());
                        if (auto r = parse_backing_label(label)) {
                            out.push_back(std::move(*r));
                        }
                    }
                }
            }
            std::ranges::sort(out);
            return out;
        });
    }

    /// Destroys every object labelled for `key_id`'s `version` (both halves
    /// of a pair). Destroying what is already gone is not an error, so the
    /// deletion job can retry after a leader change (Requirement 9.4).
    auto destroy(std::string_view key_id, std::uint32_t version) -> void {
        const auto label = backing_label(key_id, version);
        call([&](CK_SESSION_HANDLE s) {
            using kythira::pkcs11::attribute;
            const std::array tmpl{attribute::of_string(CKA_LABEL, label)};
            for (const auto o : _b->find_objects(s, tmpl)) {
                _b->destroy_object(s, o);
            }
            return 0;
        });
    }

    [[nodiscard]] auto backend() const -> kythira::pkcs11::backend& { return *_b; }

    /// Runs `f` on the logged-in session; for the cryptographic calls of
    /// later tasks.
    template<typename F> auto with_session(F&& f) -> std::invoke_result_t<F&, CK_SESSION_HANDLE> {
        return call(std::forward<F>(f));
    }

private:
    template<typename F> auto call(F&& f) -> std::invoke_result_t<F&, CK_SESSION_HANDLE> {
        const std::lock_guard lock(_mu);
        for (int attempt = 0;; ++attempt) {
            try {
                return f(session());
            } catch (const kythira::pkcs11::error& e) {
                if (attempt == 0 && kythira::pkcs11::session_lost(e.rv())) {
                    drop_session();
                    continue;
                }
                throw backing_error(classify_rv(e.rv()), e.rv(),
                                    std::string("kms backing store: ") + e.what());
            }
        }
    }

    auto session() -> CK_SESSION_HANDLE {
        if (!_session) {
            const auto s = _b->open_session(_slot);
            try {
                _b->login(s, _pin);
            } catch (...) {
                _b->close_session(s);
                throw;
            }
            _session = s;
        }
        return *_session;
    }

    auto drop_session() -> void {
        if (_session) {
            try {
                _b->close_session(*_session);
            } catch (...) {  // NOLINT(bugprone-empty-catch): the session is gone already
            }
            _session.reset();
        }
    }

    std::shared_ptr<kythira::pkcs11::backend> _b;
    CK_SLOT_ID _slot;
    std::string _pin;
    std::mutex _mu;
    std::optional<CK_SESSION_HANDLE> _session;
};

}  // namespace kythira::kms
