// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// kythira::pkcs11::module, the one way Kythira's key consumers (the cluster
// CA, Kinesis, IAM; .kiro/specs/virtual-hsm/ Requirements 9 and 10) use a
// key they do not hold: a PKCS#11 module found by an RFC 7512 URI
// (raft/pkcs11_uri.hpp).
//
// Two bindings, one interface (design "PKCS#11 is the only boundary
// consumers see"):
//
//   * module::load(path) dlopens any PKCS#11 library: the virtual HSM's
//     libkythira_pkcs11.so, yubihsm_pkcs11.so, CloudHSM's library, a
//     network HSM's or SoftHSM2's;
//   * module(std::shared_ptr<backend>) takes a backend made in process,
//     which is how a module co-located with the virtual HSM reaches it
//     without a network hop (services/hsm's pkcs11_native_backend.hpp).
//
// So moving a consumer to real hardware is a change of URI, never of code.
//
// The common subset (Requirement 9.2). A session's consumer calls accept
// only what both the YubiHSM 2 and the AWS CloudHSM (Client SDK 5) PKCS#11
// libraries implement, so a consumer that works on the virtual HSM works on
// either. Checked against their published documentation in 2026-11:
//
//   | Operation        | Mechanism            | Keys                          |
//   |------------------|----------------------|-------------------------------|
//   | generate         | CKM_EC_KEY_PAIR_GEN  | P-256, P-384                  |
//   | generate         | CKM_RSA_PKCS_KEY_PAIR_GEN | 2048, 3072, 4096 bits, e = 65537 |
//   | sign a digest    | CKM_ECDSA            | EC                            |
//   | sign a digest    | CKM_RSA_PKCS (DigestInfo built here) | RSA           |
//   | sign a digest    | CKM_RSA_PKCS_PSS (salt = hash length) | RSA          |
//   | decrypt          | CKM_RSA_PKCS_OAEP (MGF1 with the same hash) | RSA    |
//
// with SHA-256, SHA-384 or SHA-512 computed by the caller (and SHA-1 for
// OAEP only, which is all SoftHSM2 2.6 takes there). Verification and
// encryption use the public key in software (public_key()): the YubiHSM 2
// does both in software anyway and has no public-key objects of its own.
// Left out on purpose: AES-GCM (the YubiHSM 2 has none; CloudHSM chooses
// the IV itself), standard AES key wrap (neither lists CKM_AES_KEY_WRAP or
// _KWP; each has its own vendor wrap), HMAC (their secret-key types
// differ), and the hashing sign mechanisms (CKM_ECDSA_SHA256 and friends,
// not in the YubiHSM 2's documentation). Keep labels to 40 bytes and ids
// to 2 bytes: beyond that the YubiHSM 2 stores them in a separate, clear
// "meta object".
//
// session::unrestricted() reaches the whole backend for operator tooling
// (hsm_ctl migrate), never for consumers.
//
// Every failure throws pkcs11::error with the CK_RV.

#include <raft/pkcs11.hpp>
#include <raft/pkcs11_uri.hpp>

#include <dlfcn.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::pkcs11 {

using bytes = std::vector<std::uint8_t>;

/// The name of a CK_RV, for messages.
[[nodiscard]] inline auto rv_name(CK_RV rv) -> std::string {
    switch (rv) {
#define KYTHIRA_P11_RV(x) \
    case x:               \
        return #x;
        KYTHIRA_P11_RV(CKR_OK)
        KYTHIRA_P11_RV(CKR_GENERAL_ERROR)
        KYTHIRA_P11_RV(CKR_ARGUMENTS_BAD)
        KYTHIRA_P11_RV(CKR_ATTRIBUTE_SENSITIVE)
        KYTHIRA_P11_RV(CKR_ATTRIBUTE_TYPE_INVALID)
        KYTHIRA_P11_RV(CKR_ATTRIBUTE_VALUE_INVALID)
        KYTHIRA_P11_RV(CKR_DATA_LEN_RANGE)
        KYTHIRA_P11_RV(CKR_DEVICE_ERROR)
        KYTHIRA_P11_RV(CKR_ENCRYPTED_DATA_INVALID)
        KYTHIRA_P11_RV(CKR_FUNCTION_FAILED)
        KYTHIRA_P11_RV(CKR_FUNCTION_NOT_SUPPORTED)
        KYTHIRA_P11_RV(CKR_KEY_HANDLE_INVALID)
        KYTHIRA_P11_RV(CKR_KEY_TYPE_INCONSISTENT)
        KYTHIRA_P11_RV(CKR_KEY_FUNCTION_NOT_PERMITTED)
        KYTHIRA_P11_RV(CKR_KEY_UNEXTRACTABLE)
        KYTHIRA_P11_RV(CKR_MECHANISM_INVALID)
        KYTHIRA_P11_RV(CKR_MECHANISM_PARAM_INVALID)
        KYTHIRA_P11_RV(CKR_OBJECT_HANDLE_INVALID)
        KYTHIRA_P11_RV(CKR_PIN_INCORRECT)
        KYTHIRA_P11_RV(CKR_PIN_LOCKED)
        KYTHIRA_P11_RV(CKR_SESSION_HANDLE_INVALID)
        KYTHIRA_P11_RV(CKR_SIGNATURE_INVALID)
        KYTHIRA_P11_RV(CKR_SLOT_ID_INVALID)
        KYTHIRA_P11_RV(CKR_TEMPLATE_INCOMPLETE)
        KYTHIRA_P11_RV(CKR_TEMPLATE_INCONSISTENT)
        KYTHIRA_P11_RV(CKR_TOKEN_NOT_PRESENT)
        KYTHIRA_P11_RV(CKR_USER_NOT_LOGGED_IN)
        KYTHIRA_P11_RV(CKR_WRAPPED_KEY_INVALID)
        KYTHIRA_P11_RV(CKR_BUFFER_TOO_SMALL)
        KYTHIRA_P11_RV(CKR_CRYPTOKI_NOT_INITIALIZED)
        KYTHIRA_P11_RV(CKR_FUNCTION_REJECTED)
#undef KYTHIRA_P11_RV
        default:
            break;
    }
    std::array<char, 24> buf{};
    std::snprintf(buf.data(), buf.size(), "CKR 0x%08lx", static_cast<unsigned long>(rv));
    return buf.data();
}

/// A PKCS#11 call that failed, or a request outside what this wrapper does.
class error : public std::runtime_error {
public:
    error(std::string_view what, CK_RV rv)
        : std::runtime_error(std::string(what) + ": " + rv_name(rv)), _rv(rv) {}

    [[nodiscard]] auto rv() const noexcept -> CK_RV { return _rv; }

private:
    CK_RV _rv;
};

/// The failures a new session may cure: the session or the module's
/// state is gone (the module restarted, the token was replaced, an HSM
/// failed over), not a refusal.
[[nodiscard]] inline auto session_lost(CK_RV rv) -> bool {
    return rv == CKR_SESSION_HANDLE_INVALID || rv == CKR_SESSION_CLOSED || rv == CKR_DEVICE_ERROR ||
           rv == CKR_DEVICE_REMOVED || rv == CKR_TOKEN_NOT_PRESENT ||
           rv == CKR_USER_NOT_LOGGED_IN || rv == CKR_CRYPTOKI_NOT_INITIALIZED ||
           rv == CKR_KEY_HANDLE_INVALID || rv == CKR_OBJECT_HANDLE_INVALID;
}

inline void check(CK_RV rv, std::string_view what) {
    if (rv != CKR_OK) {
        throw error(what, rv);
    }
}

/// One attribute of a template, its value in bytes.
struct attribute {
    CK_ATTRIBUTE_TYPE type = 0;
    bytes value;

    [[nodiscard]] static auto of_bool(CK_ATTRIBUTE_TYPE t, bool v) -> attribute {
        return {t, bytes{static_cast<std::uint8_t>(v ? CK_TRUE : CK_FALSE)}};
    }
    [[nodiscard]] static auto of_ulong(CK_ATTRIBUTE_TYPE t, CK_ULONG v) -> attribute {
        bytes b(sizeof v);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&v), sizeof v, b.begin());
        return {t, std::move(b)};
    }
    [[nodiscard]] static auto of_bytes(CK_ATTRIBUTE_TYPE t, std::span<const std::uint8_t> v)
        -> attribute {
        return {t, bytes(v.begin(), v.end())};
    }
    [[nodiscard]] static auto of_string(CK_ATTRIBUTE_TYPE t, std::string_view v) -> attribute {
        return {t, bytes(v.begin(), v.end())};
    }
};

/// A CK_ULONG attribute value, or none when the size is wrong.
[[nodiscard]] inline auto as_ulong(const std::optional<bytes>& v) -> std::optional<CK_ULONG> {
    if (!v || v->size() != sizeof(CK_ULONG)) {
        return std::nullopt;
    }
    CK_ULONG out = 0;
    std::copy_n(v->begin(), sizeof out, reinterpret_cast<std::uint8_t*>(&out));
    return out;
}

/// CK_INFO, with the blank padding trimmed.
struct library_info {
    std::string manufacturer;
    std::string description;
    CK_VERSION version{};
};

/// A slot with a token, from CK_SLOT_INFO and CK_TOKEN_INFO, blank padding
/// trimmed.
struct token_info {
    CK_SLOT_ID slot = 0;
    std::string slot_description;
    std::string slot_manufacturer;
    std::string label;
    std::string manufacturer;
    std::string model;
    std::string serial;
    CK_FLAGS flags = 0;
};

/// PKCS#11 in C++ form: the calls the wrapper makes, buffers as vectors.
/// Every call throws pkcs11::error on failure. Implementations must be safe
/// to call from several threads on different sessions.
class backend {
public:
    backend() = default;
    backend(const backend&) = delete;
    auto operator=(const backend&) -> backend& = delete;
    backend(backend&&) = delete;
    auto operator=(backend&&) -> backend& = delete;
    virtual ~backend() = default;

    [[nodiscard]] virtual auto library() -> library_info = 0;
    [[nodiscard]] virtual auto tokens() -> std::vector<token_info> = 0;
    [[nodiscard]] virtual auto mechanisms(CK_SLOT_ID slot) -> std::vector<CK_MECHANISM_TYPE> = 0;

    /// A read-write serial session.
    [[nodiscard]] virtual auto open_session(CK_SLOT_ID slot) -> CK_SESSION_HANDLE = 0;
    virtual void close_session(CK_SESSION_HANDLE s) = 0;
    /// CKU_USER; already logged in (by another session of this
    /// application) is success.
    virtual void login(CK_SESSION_HANDLE s, std::string_view pin) = 0;

    [[nodiscard]] virtual auto find_objects(CK_SESSION_HANDLE s, std::span<const attribute> tmpl)
        -> std::vector<CK_OBJECT_HANDLE> = 0;
    /// One entry per type: the value, or none when it is sensitive, invalid
    /// for the object or unavailable.
    [[nodiscard]] virtual auto get_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                                              std::span<const CK_ATTRIBUTE_TYPE> types)
        -> std::vector<std::optional<bytes>> = 0;

    [[nodiscard]] virtual auto generate_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                            std::span<const attribute> tmpl)
        -> CK_OBJECT_HANDLE = 0;
    [[nodiscard]] virtual auto generate_key_pair(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                                 std::span<const attribute> public_tmpl,
                                                 std::span<const attribute> private_tmpl)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> = 0;
    [[nodiscard]] virtual auto create_object(CK_SESSION_HANDLE s, std::span<const attribute> tmpl)
        -> CK_OBJECT_HANDLE = 0;
    virtual void destroy_object(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o) = 0;

    [[nodiscard]] virtual auto sign(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                    CK_OBJECT_HANDLE key, std::span<const std::uint8_t> data)
        -> bytes = 0;
    /// False for a signature that does not verify; other failures throw.
    [[nodiscard]] virtual auto verify(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                      CK_OBJECT_HANDLE key, std::span<const std::uint8_t> data,
                                      std::span<const std::uint8_t> signature) -> bool = 0;
    [[nodiscard]] virtual auto encrypt(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                       CK_OBJECT_HANDLE key, std::span<const std::uint8_t> data)
        -> bytes = 0;
    [[nodiscard]] virtual auto decrypt(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                       CK_OBJECT_HANDLE key, std::span<const std::uint8_t> data)
        -> bytes = 0;
    [[nodiscard]] virtual auto wrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                        CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key)
        -> bytes = 0;
    [[nodiscard]] virtual auto unwrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                          CK_OBJECT_HANDLE unwrapping_key,
                                          std::span<const std::uint8_t> wrapped,
                                          std::span<const attribute> tmpl) -> CK_OBJECT_HANDLE = 0;
    /// `length` bytes from the module's random number generator
    /// (C_GenerateRandom).
    [[nodiscard]] virtual auto generate_random(CK_SESSION_HANDLE s, std::size_t length)
        -> bytes = 0;
};

namespace detail {

[[nodiscard]] inline auto trimmed(const CK_UTF8CHAR* p, std::size_t n) -> std::string {
    std::string s(reinterpret_cast<const char*>(p), n);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\0')) {
        s.pop_back();
    }
    return s;
}

/// A template as CK_ATTRIBUTEs pointing into `tmpl`, which must outlive it.
[[nodiscard]] inline auto ck_template(std::span<const attribute> tmpl)
    -> std::vector<CK_ATTRIBUTE> {
    std::vector<CK_ATTRIBUTE> out;
    out.reserve(tmpl.size());
    for (const auto& a : tmpl) {
        // PKCS#11 takes templates through non-const pointers it never
        // writes through.
        out.push_back(
            {a.type,
             a.value.empty() ? nullptr : const_cast<std::uint8_t*>(a.value.data()),  // NOLINT
             static_cast<CK_ULONG>(a.value.size())});
    }
    return out;
}

[[nodiscard]] inline auto mutable_ptr(std::span<const std::uint8_t> s) -> CK_BYTE_PTR {
    return const_cast<CK_BYTE_PTR>(s.data());  // NOLINT(cppcoreguidelines-pro-type-const-cast)
}

[[nodiscard]] inline auto mutable_mech(const CK_MECHANISM& m) -> CK_MECHANISM_PTR {
    return const_cast<CK_MECHANISM_PTR>(&m);  // NOLINT(cppcoreguidelines-pro-type-const-cast)
}

}  // namespace detail

/// A backend over a CK_FUNCTION_LIST: a dlopen'd library, or one linked in.
class function_list_backend final : public backend {
public:
    /// dlopens `path`, takes its C_GetFunctionList and initializes it with
    /// OS locking. A library some other part of the process initialized
    /// already is used as it is and not finalized here.
    explicit function_list_backend(const std::string& path)
        : _handle(::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL)) {
        if (_handle == nullptr) {
            const char* why = ::dlerror();
            throw error("dlopen " + path + ": " + (why != nullptr ? why : "failed"),
                        CKR_GENERAL_ERROR);
        }
        using get_list_fn = CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR);
        auto* sym = ::dlsym(_handle, "C_GetFunctionList");
        if (sym == nullptr) {
            ::dlclose(_handle);
            throw error(path + " has no C_GetFunctionList", CKR_GENERAL_ERROR);
        }
        CK_FUNCTION_LIST_PTR list = nullptr;
        const auto rv = reinterpret_cast<get_list_fn>(sym)(&list);  // NOLINT
        if (rv != CKR_OK || list == nullptr) {
            ::dlclose(_handle);
            throw error(path + " C_GetFunctionList", rv == CKR_OK ? CKR_GENERAL_ERROR : rv);
        }
        _f = list;
        initialize();
    }

    /// A function list linked into the process (it is not unloaded).
    explicit function_list_backend(CK_FUNCTION_LIST_PTR list) : _f(list) {
        if (list == nullptr) {
            throw error("function_list_backend: no function list", CKR_ARGUMENTS_BAD);
        }
        initialize();
    }

    function_list_backend(const function_list_backend&) = delete;
    auto operator=(const function_list_backend&) -> function_list_backend& = delete;
    function_list_backend(function_list_backend&&) = delete;
    auto operator=(function_list_backend&&) -> function_list_backend& = delete;

    ~function_list_backend() override {
        if (_finalize) {
            (void)_f->C_Finalize(nullptr);
        }
        if (_handle != nullptr) {
            ::dlclose(_handle);
        }
    }

    [[nodiscard]] auto library() -> library_info override {
        CK_INFO info{};
        check(_f->C_GetInfo(&info), "C_GetInfo");
        return {detail::trimmed(info.manufacturerID, sizeof info.manufacturerID),
                detail::trimmed(info.libraryDescription, sizeof info.libraryDescription),
                info.libraryVersion};
    }

    [[nodiscard]] auto tokens() -> std::vector<token_info> override {
        std::vector<CK_SLOT_ID> slots;
        while (true) {
            CK_ULONG n = 0;
            check(_f->C_GetSlotList(CK_TRUE, nullptr, &n), "C_GetSlotList");
            slots.resize(n);
            const auto rv = _f->C_GetSlotList(CK_TRUE, slots.data(), &n);
            if (rv == CKR_BUFFER_TOO_SMALL) {
                continue;  // a slot appeared between the calls
            }
            check(rv, "C_GetSlotList");
            slots.resize(n);
            break;
        }
        std::vector<token_info> out;
        for (const auto slot : slots) {
            CK_SLOT_INFO si{};
            CK_TOKEN_INFO ti{};
            if (_f->C_GetSlotInfo(slot, &si) != CKR_OK || _f->C_GetTokenInfo(slot, &ti) != CKR_OK) {
                continue;  // removed meanwhile
            }
            out.push_back({slot, detail::trimmed(si.slotDescription, sizeof si.slotDescription),
                           detail::trimmed(si.manufacturerID, sizeof si.manufacturerID),
                           detail::trimmed(ti.label, sizeof ti.label),
                           detail::trimmed(ti.manufacturerID, sizeof ti.manufacturerID),
                           detail::trimmed(ti.model, sizeof ti.model),
                           detail::trimmed(ti.serialNumber, sizeof ti.serialNumber), ti.flags});
        }
        return out;
    }

    [[nodiscard]] auto mechanisms(CK_SLOT_ID slot) -> std::vector<CK_MECHANISM_TYPE> override {
        CK_ULONG n = 0;
        check(_f->C_GetMechanismList(slot, nullptr, &n), "C_GetMechanismList");
        std::vector<CK_MECHANISM_TYPE> out(n);
        check(_f->C_GetMechanismList(slot, out.data(), &n), "C_GetMechanismList");
        out.resize(n);
        return out;
    }

    [[nodiscard]] auto open_session(CK_SLOT_ID slot) -> CK_SESSION_HANDLE override {
        CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
        check(_f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &s),
              "C_OpenSession");
        return s;
    }

    void close_session(CK_SESSION_HANDLE s) override {
        check(_f->C_CloseSession(s), "C_CloseSession");
    }

    void login(CK_SESSION_HANDLE s, std::string_view pin) override {
        std::string copy(pin);
        const auto rv = _f->C_Login(s, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(copy.data()),
                                    static_cast<CK_ULONG>(copy.size()));
        std::fill(copy.begin(), copy.end(), '\0');
        if (rv != CKR_USER_ALREADY_LOGGED_IN) {
            check(rv, "C_Login");
        }
    }

    [[nodiscard]] auto find_objects(CK_SESSION_HANDLE s, std::span<const attribute> tmpl)
        -> std::vector<CK_OBJECT_HANDLE> override {
        auto t = detail::ck_template(tmpl);
        check(_f->C_FindObjectsInit(s, t.data(), static_cast<CK_ULONG>(t.size())),
              "C_FindObjectsInit");
        std::vector<CK_OBJECT_HANDLE> out;
        CK_RV rv = CKR_OK;
        while (true) {
            std::array<CK_OBJECT_HANDLE, 64> batch{};
            CK_ULONG n = 0;
            rv = _f->C_FindObjects(s, batch.data(), batch.size(), &n);
            if (rv != CKR_OK || n == 0) {
                break;
            }
            out.insert(out.end(), batch.begin(), batch.begin() + static_cast<std::ptrdiff_t>(n));
        }
        const auto final_rv = _f->C_FindObjectsFinal(s);
        check(rv, "C_FindObjects");
        check(final_rv, "C_FindObjectsFinal");
        return out;
    }

    [[nodiscard]] auto get_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                                      std::span<const CK_ATTRIBUTE_TYPE> types)
        -> std::vector<std::optional<bytes>> override {
        std::vector<std::optional<bytes>> out;
        out.reserve(types.size());
        // One attribute per call: how a library reports one sensitive or
        // unknown attribute among several differs between libraries.
        for (const auto type : types) {
            CK_ATTRIBUTE a{type, nullptr, 0};
            auto rv = _f->C_GetAttributeValue(s, o, &a, 1);
            if (rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID ||
                (rv == CKR_OK && a.ulValueLen == CK_UNAVAILABLE_INFORMATION)) {
                out.emplace_back(std::nullopt);
                continue;
            }
            check(rv, "C_GetAttributeValue");
            bytes v(a.ulValueLen);
            a.pValue = v.data();
            rv = _f->C_GetAttributeValue(s, o, &a, 1);
            check(rv, "C_GetAttributeValue");
            v.resize(a.ulValueLen);
            out.emplace_back(std::move(v));
        }
        return out;
    }

    [[nodiscard]] auto generate_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                    std::span<const attribute> tmpl) -> CK_OBJECT_HANDLE override {
        auto t = detail::ck_template(tmpl);
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        check(_f->C_GenerateKey(s, detail::mutable_mech(m), t.data(),
                                static_cast<CK_ULONG>(t.size()), &h),
              "C_GenerateKey");
        return h;
    }

    [[nodiscard]] auto generate_key_pair(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                         std::span<const attribute> public_tmpl,
                                         std::span<const attribute> private_tmpl)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> override {
        auto pub = detail::ck_template(public_tmpl);
        auto priv = detail::ck_template(private_tmpl);
        CK_OBJECT_HANDLE hpub = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hpriv = CK_INVALID_HANDLE;
        check(_f->C_GenerateKeyPair(s, detail::mutable_mech(m), pub.data(),
                                    static_cast<CK_ULONG>(pub.size()), priv.data(),
                                    static_cast<CK_ULONG>(priv.size()), &hpub, &hpriv),
              "C_GenerateKeyPair");
        return {hpub, hpriv};
    }

    [[nodiscard]] auto create_object(CK_SESSION_HANDLE s, std::span<const attribute> tmpl)
        -> CK_OBJECT_HANDLE override {
        auto t = detail::ck_template(tmpl);
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        check(_f->C_CreateObject(s, t.data(), static_cast<CK_ULONG>(t.size()), &h),
              "C_CreateObject");
        return h;
    }

    void destroy_object(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o) override {
        check(_f->C_DestroyObject(s, o), "C_DestroyObject");
    }

    [[nodiscard]] auto sign(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                            std::span<const std::uint8_t> data) -> bytes override {
        check(_f->C_SignInit(s, detail::mutable_mech(m), key), "C_SignInit");
        return two_call("C_Sign", [&](CK_BYTE_PTR out, CK_ULONG_PTR n) {
            return _f->C_Sign(s, detail::mutable_ptr(data), static_cast<CK_ULONG>(data.size()), out,
                              n);
        });
    }

    [[nodiscard]] auto verify(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                              std::span<const std::uint8_t> data,
                              std::span<const std::uint8_t> signature) -> bool override {
        check(_f->C_VerifyInit(s, detail::mutable_mech(m), key), "C_VerifyInit");
        const auto rv =
            _f->C_Verify(s, detail::mutable_ptr(data), static_cast<CK_ULONG>(data.size()),
                         detail::mutable_ptr(signature), static_cast<CK_ULONG>(signature.size()));
        if (rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE) {
            return false;
        }
        check(rv, "C_Verify");
        return true;
    }

    [[nodiscard]] auto encrypt(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                               std::span<const std::uint8_t> data) -> bytes override {
        check(_f->C_EncryptInit(s, detail::mutable_mech(m), key), "C_EncryptInit");
        return two_call("C_Encrypt", [&](CK_BYTE_PTR out, CK_ULONG_PTR n) {
            return _f->C_Encrypt(s, detail::mutable_ptr(data), static_cast<CK_ULONG>(data.size()),
                                 out, n);
        });
    }

    [[nodiscard]] auto decrypt(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                               std::span<const std::uint8_t> data) -> bytes override {
        check(_f->C_DecryptInit(s, detail::mutable_mech(m), key), "C_DecryptInit");
        return two_call("C_Decrypt", [&](CK_BYTE_PTR out, CK_ULONG_PTR n) {
            return _f->C_Decrypt(s, detail::mutable_ptr(data), static_cast<CK_ULONG>(data.size()),
                                 out, n);
        });
    }

    [[nodiscard]] auto generate_random(CK_SESSION_HANDLE s, std::size_t length) -> bytes override {
        bytes out(length);
        check(_f->C_GenerateRandom(s, out.data(), static_cast<CK_ULONG>(out.size())),
              "C_GenerateRandom");
        return out;
    }

    [[nodiscard]] auto wrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key)
        -> bytes override {
        return two_call("C_WrapKey", [&](CK_BYTE_PTR out, CK_ULONG_PTR n) {
            return _f->C_WrapKey(s, detail::mutable_mech(m), wrapping_key, key, out, n);
        });
    }

    [[nodiscard]] auto unwrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                  CK_OBJECT_HANDLE unwrapping_key,
                                  std::span<const std::uint8_t> wrapped,
                                  std::span<const attribute> tmpl) -> CK_OBJECT_HANDLE override {
        auto t = detail::ck_template(tmpl);
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        check(_f->C_UnwrapKey(s, detail::mutable_mech(m), unwrapping_key,
                              detail::mutable_ptr(wrapped), static_cast<CK_ULONG>(wrapped.size()),
                              t.data(), static_cast<CK_ULONG>(t.size()), &h),
              "C_UnwrapKey");
        return h;
    }

private:
    void initialize() {
        CK_C_INITIALIZE_ARGS args{};
        args.flags = CKF_OS_LOCKING_OK;
        const auto rv = _f->C_Initialize(&args);
        if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            return;
        }
        if (rv != CKR_OK) {
            if (_handle != nullptr) {
                ::dlclose(_handle);
            }
            throw error("C_Initialize", rv);
        }
        _finalize = true;
    }

    /// A single-part call with PKCS#11's length query: the length first,
    /// then the output. The operation stays active after the query, as the
    /// specification requires.
    template<class Call> static auto two_call(std::string_view what, Call call) -> bytes {
        CK_ULONG n = 0;
        check(call(nullptr, &n), what);
        bytes out(n);
        check(call(out.data(), &n), what);
        out.resize(n);
        return out;
    }

    void* _handle = nullptr;
    CK_FUNCTION_LIST_PTR _f = nullptr;
    bool _finalize = false;
};

// ── the common subset ────────────────────────────────────────────────────

/// SHA-1 only for RSA-OAEP, where it is still sound (OAEP does not rest
/// on collision resistance) and the one hash SoftHSM2 2.6 accepts there;
/// sign_digest refuses it.
enum class hash_algorithm : std::uint8_t {
    sha1,
    sha256,
    sha384,
    sha512
};

[[nodiscard]] constexpr auto digest_length(hash_algorithm h) noexcept -> std::size_t {
    switch (h) {
        case hash_algorithm::sha1:
            return 20;
        case hash_algorithm::sha256:
            return 32;
        case hash_algorithm::sha384:
            return 48;
        case hash_algorithm::sha512:
            return 64;
    }
    return 0;
}

enum class signature_scheme : std::uint8_t {
    ecdsa,      ///< CKM_ECDSA: r || s, each the curve's size (ecdsa_der() converts)
    rsa_pkcs1,  ///< CKM_RSA_PKCS over the DigestInfo
    rsa_pss     ///< CKM_RSA_PKCS_PSS, MGF1 with the same hash, salt = hash length
};

enum class key_spec : std::uint8_t {
    ec_p256,
    ec_p384,
    rsa_2048,
    rsa_3072,
    rsa_4096
};

enum class key_usage : std::uint8_t {
    sign,
    decrypt
};

namespace detail {

[[nodiscard]] inline auto hash_mechanism(hash_algorithm h) -> CK_MECHANISM_TYPE {
    switch (h) {
        case hash_algorithm::sha1:
            return CKM_SHA_1;
        case hash_algorithm::sha256:
            return CKM_SHA256;
        case hash_algorithm::sha384:
            return CKM_SHA384;
        case hash_algorithm::sha512:
            return CKM_SHA512;
    }
    return CKM_SHA256;
}

[[nodiscard]] inline auto mgf(hash_algorithm h) -> CK_RSA_PKCS_MGF_TYPE {
    switch (h) {
        case hash_algorithm::sha1:
            return CKG_MGF1_SHA1;
        case hash_algorithm::sha256:
            return CKG_MGF1_SHA256;
        case hash_algorithm::sha384:
            return CKG_MGF1_SHA384;
        case hash_algorithm::sha512:
            return CKG_MGF1_SHA512;
    }
    return CKG_MGF1_SHA256;
}

/// RFC 8017 section 9.2 note 1: the DER DigestInfo prefixes.
[[nodiscard]] inline auto digest_info_prefix(hash_algorithm h) -> std::span<const std::uint8_t> {
    static constexpr std::array<std::uint8_t, 19> sha256{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                                         0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                         0x01, 0x05, 0x00, 0x04, 0x20};
    static constexpr std::array<std::uint8_t, 19> sha384{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                                         0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                         0x02, 0x05, 0x00, 0x04, 0x30};
    static constexpr std::array<std::uint8_t, 19> sha512{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                                         0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                         0x03, 0x05, 0x00, 0x04, 0x40};
    switch (h) {
        case hash_algorithm::sha1:
            break;  // never signs
        case hash_algorithm::sha256:
            return sha256;
        case hash_algorithm::sha384:
            return sha384;
        case hash_algorithm::sha512:
            return sha512;
    }
    return sha256;
}

/// DER ECParameters (a named curve OID) for the subset's curves.
inline constexpr std::array<std::uint8_t, 10> p256_params{0x06, 0x08, 0x2a, 0x86, 0x48,
                                                          0xce, 0x3d, 0x03, 0x01, 0x07};
inline constexpr std::array<std::uint8_t, 7> p384_params{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};

[[nodiscard]] inline auto der_length(std::size_t n) -> bytes {
    if (n < 0x80) {
        return {static_cast<std::uint8_t>(n)};
    }
    if (n <= 0xFF) {
        return {0x81, static_cast<std::uint8_t>(n)};
    }
    return {0x82, static_cast<std::uint8_t>(n >> 8U), static_cast<std::uint8_t>(n & 0xFFU)};
}

[[nodiscard]] inline auto der_integer(std::span<const std::uint8_t> big_endian) -> bytes {
    std::size_t i = 0;
    while (i + 1 < big_endian.size() && big_endian[i] == 0) {
        ++i;
    }
    bytes v(big_endian.begin() + static_cast<std::ptrdiff_t>(i), big_endian.end());
    if (v.empty()) {
        v.push_back(0);
    }
    if ((v.front() & 0x80U) != 0) {
        v.insert(v.begin(), 0);
    }
    bytes out{0x02};
    const auto len = der_length(v.size());
    out.insert(out.end(), len.begin(), len.end());
    out.insert(out.end(), v.begin(), v.end());
    return out;
}

}  // namespace detail

/// A PKCS#11 ECDSA signature (r || s) as the DER Ecdsa-Sig-Value X.509 and
/// TLS want.
[[nodiscard]] inline auto ecdsa_der(std::span<const std::uint8_t> raw) -> bytes {
    if (raw.empty() || raw.size() % 2 != 0) {
        throw error("ecdsa_der: not r || s", CKR_ARGUMENTS_BAD);
    }
    const auto half = raw.size() / 2;
    auto body = detail::der_integer(raw.first(half));
    const auto s = detail::der_integer(raw.subspan(half));
    body.insert(body.end(), s.begin(), s.end());
    bytes out{0x30};
    const auto len = detail::der_length(body.size());
    out.insert(out.end(), len.begin(), len.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

/// The public half of a key pair, as the token stores it.
struct public_key_info {
    CK_KEY_TYPE key_type = CKK_RSA;
    bytes modulus;          ///< RSA, big-endian
    bytes public_exponent;  ///< RSA, big-endian
    bytes ec_params;        ///< EC: DER ECParameters (the curve's OID)
    bytes ec_point;         ///< EC: the uncompressed point 04 || X || Y, unwrapped
};

class module;

/// One logged-in read-write session on a token. Calls are serialized; make
/// one session per thread for parallel use.
class session {
public:
    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;
    session(session&& o) noexcept
        : _b(std::move(o._b)),
          _slot(o._slot),
          _s(std::exchange(o._s, CK_INVALID_HANDLE)),
          _mutex(std::move(o._mutex)) {}
    auto operator=(session&&) -> session& = delete;
    ~session() {
        if (_b && _s != CK_INVALID_HANDLE) {
            try {
                _b->close_session(_s);
            } catch (...) {  // NOLINT(bugprone-empty-catch): nothing to do in a destructor
            }
        }
    }

    [[nodiscard]] auto slot() const noexcept -> CK_SLOT_ID { return _slot; }

    /// The object a URI's object, type and id attributes name; exactly one
    /// must match (CKR_OBJECT_HANDLE_INVALID for none, CKR_TEMPLATE_INCONSISTENT
    /// for several). With no type, a private key is meant.
    [[nodiscard]] auto find(const uri& u) -> CK_OBJECT_HANDLE {
        std::vector<attribute> tmpl;
        tmpl.push_back(attribute::of_ulong(
            CKA_CLASS, object_class(u.type.value_or(object_type::private_key))));
        if (u.object) {
            tmpl.push_back(attribute::of_string(CKA_LABEL, *u.object));
        }
        if (u.id) {
            tmpl.push_back(attribute::of_bytes(CKA_ID, *u.id));
        }
        if (!u.object && !u.id) {
            throw error("pkcs11 URI " + u.to_string() + " names no object (object= or id=)",
                        CKR_ARGUMENTS_BAD);
        }
        const std::lock_guard lock(*_mutex);
        const auto found = _b->find_objects(_s, tmpl);
        if (found.empty()) {
            throw error("no object matches " + u.to_string(), CKR_OBJECT_HANDLE_INVALID);
        }
        if (found.size() > 1) {
            throw error(std::to_string(found.size()) + " objects match " + u.to_string(),
                        CKR_TEMPLATE_INCONSISTENT);
        }
        return found.front();
    }

    /// Generates a token key pair in the common subset: sensitive and
    /// private, not extractable unless asked (only migration to another
    /// module ever needs that), usable only for `usage` (every other usage
    /// attribute set false). Returns
    /// {public, private}.
    auto generate_key_pair(key_spec spec, key_usage usage, std::string_view label,
                           std::span<const std::uint8_t> id, bool extractable = false)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> {
        const bool ec = spec == key_spec::ec_p256 || spec == key_spec::ec_p384;
        if (ec && usage != key_usage::sign) {
            throw error("EC keys in the common subset only sign", CKR_KEY_FUNCTION_NOT_PERMITTED);
        }
        CK_MECHANISM m{ec ? CKM_EC_KEY_PAIR_GEN : CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        std::vector<attribute> pub{attribute::of_bool(CKA_TOKEN, true),
                                   attribute::of_string(CKA_LABEL, label),
                                   attribute::of_bytes(CKA_ID, id)};
        std::vector<attribute> priv{attribute::of_bool(CKA_TOKEN, true),
                                    attribute::of_bool(CKA_PRIVATE, true),
                                    attribute::of_bool(CKA_SENSITIVE, true),
                                    attribute::of_bool(CKA_EXTRACTABLE, extractable),
                                    attribute::of_string(CKA_LABEL, label),
                                    attribute::of_bytes(CKA_ID, id)};
        // Every usage stated, the unwanted ones false: libraries default
        // the ones left out differently (SoftHSM2 turns them all on).
        const bool sign = usage == key_usage::sign;
        pub.push_back(attribute::of_bool(CKA_VERIFY, sign));
        priv.push_back(attribute::of_bool(CKA_SIGN, sign));
        priv.push_back(attribute::of_bool(CKA_DERIVE, false));
        if (!ec) {
            pub.push_back(attribute::of_bool(CKA_ENCRYPT, !sign));
            pub.push_back(attribute::of_bool(CKA_WRAP, false));
            priv.push_back(attribute::of_bool(CKA_DECRYPT, !sign));
            priv.push_back(attribute::of_bool(CKA_UNWRAP, false));
        }
        switch (spec) {
            case key_spec::ec_p256:
                pub.push_back(attribute::of_bytes(CKA_EC_PARAMS, detail::p256_params));
                break;
            case key_spec::ec_p384:
                pub.push_back(attribute::of_bytes(CKA_EC_PARAMS, detail::p384_params));
                break;
            case key_spec::rsa_2048:
            case key_spec::rsa_3072:
            case key_spec::rsa_4096: {
                const CK_ULONG bits = spec == key_spec::rsa_2048   ? 2048
                                      : spec == key_spec::rsa_3072 ? 3072
                                                                   : 4096;
                pub.push_back(attribute::of_ulong(CKA_MODULUS_BITS, bits));
                pub.push_back(
                    attribute::of_bytes(CKA_PUBLIC_EXPONENT, std::array<std::uint8_t, 3>{1, 0, 1}));
                break;
            }
        }
        const std::lock_guard lock(*_mutex);
        return _b->generate_key_pair(_s, m, pub, priv);
    }

    /// Signs a digest the caller computed with `hash`.
    [[nodiscard]] auto sign_digest(CK_OBJECT_HANDLE key, signature_scheme scheme,
                                   hash_algorithm hash, std::span<const std::uint8_t> digest)
        -> bytes {
        if (hash == hash_algorithm::sha1) {
            throw error("sign_digest: SHA-1 does not sign", CKR_MECHANISM_INVALID);
        }
        if (digest.size() != digest_length(hash)) {
            throw error("sign_digest: the digest is not the hash's length", CKR_DATA_LEN_RANGE);
        }
        const std::lock_guard lock(*_mutex);
        switch (scheme) {
            case signature_scheme::ecdsa: {
                CK_MECHANISM m{CKM_ECDSA, nullptr, 0};
                return _b->sign(_s, m, key, digest);
            }
            case signature_scheme::rsa_pkcs1: {
                const auto prefix = detail::digest_info_prefix(hash);
                bytes info(prefix.begin(), prefix.end());
                info.insert(info.end(), digest.begin(), digest.end());
                CK_MECHANISM m{CKM_RSA_PKCS, nullptr, 0};
                return _b->sign(_s, m, key, info);
            }
            case signature_scheme::rsa_pss: {
                CK_RSA_PKCS_PSS_PARAMS p{detail::hash_mechanism(hash), detail::mgf(hash),
                                         static_cast<CK_ULONG>(digest_length(hash))};
                CK_MECHANISM m{CKM_RSA_PKCS_PSS, &p, sizeof p};
                return _b->sign(_s, m, key, digest);
            }
        }
        throw error("sign_digest: unknown scheme", CKR_MECHANISM_INVALID);
    }

    /// RSA-OAEP decryption, MGF1 with `hash`, no label.
    [[nodiscard]] auto decrypt_oaep(CK_OBJECT_HANDLE key, hash_algorithm hash,
                                    std::span<const std::uint8_t> ciphertext) -> bytes {
        CK_RSA_PKCS_OAEP_PARAMS p{detail::hash_mechanism(hash), detail::mgf(hash),
                                  CKZ_DATA_SPECIFIED, nullptr, 0};
        CK_MECHANISM m{CKM_RSA_PKCS_OAEP, &p, sizeof p};
        const std::lock_guard lock(*_mutex);
        return _b->decrypt(_s, m, key, ciphertext);
    }

    /// The public half of a key pair, given either half: RSA from the key's
    /// own modulus and exponent; EC from the public-key object with the
    /// same CKA_ID (PKCS#11 2.40 private keys carry no point).
    [[nodiscard]] auto public_key(CK_OBJECT_HANDLE key) -> public_key_info {
        const std::lock_guard lock(*_mutex);
        static constexpr std::array<CK_ATTRIBUTE_TYPE, 6> types{
            CKA_KEY_TYPE, CKA_ID, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_EC_PARAMS, CKA_EC_POINT};
        auto v = _b->get_attributes(_s, key, types);
        const auto key_type = as_ulong(v[0]);
        if (!key_type) {
            throw error("public_key: the object is not a key", CKR_KEY_HANDLE_INVALID);
        }
        public_key_info out;
        out.key_type = *key_type;
        if (*key_type == CKK_RSA) {
            if (!v[2] || !v[3]) {
                throw error("public_key: RSA key without modulus or exponent",
                            CKR_KEY_TYPE_INCONSISTENT);
            }
            out.modulus = std::move(*v[2]);
            out.public_exponent = std::move(*v[3]);
            return out;
        }
        if (*key_type != CKK_EC) {
            throw error("public_key: neither RSA nor EC", CKR_KEY_TYPE_INCONSISTENT);
        }
        if (!v[5] && v[1]) {
            const std::array<attribute, 3> tmpl{attribute::of_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
                                                attribute::of_ulong(CKA_KEY_TYPE, CKK_EC),
                                                attribute::of_bytes(CKA_ID, *v[1])};
            const auto found = _b->find_objects(_s, tmpl);
            if (found.size() == 1) {
                static constexpr std::array<CK_ATTRIBUTE_TYPE, 2> pub_types{CKA_EC_PARAMS,
                                                                            CKA_EC_POINT};
                auto pv = _b->get_attributes(_s, found.front(), pub_types);
                v[4] = std::move(pv[0]);
                v[5] = std::move(pv[1]);
            }
        }
        if (!v[4] || !v[5]) {
            throw error("public_key: no EC public key with this key's id",
                        CKR_KEY_TYPE_INCONSISTENT);
        }
        out.ec_params = std::move(*v[4]);
        out.ec_point = unwrap_point(out.ec_params, std::move(*v[5]));
        return out;
    }

    /// The whole backend and this session's handle, for operator tooling
    /// (hsm_ctl migrate). Consumers stay on the calls above. Not
    /// serialized: the caller must not use this session from another
    /// thread meanwhile.
    struct raw_access {
        backend& b;
        CK_SESSION_HANDLE handle;
    };
    [[nodiscard]] auto unrestricted() -> raw_access { return {*_b, _s}; }

private:
    friend class module;

    session(std::shared_ptr<backend> b, CK_SLOT_ID slot, CK_SESSION_HANDLE s)
        : _b(std::move(b)), _slot(slot), _s(s), _mutex(std::make_unique<std::mutex>()) {}

    [[nodiscard]] static auto object_class(object_type t) -> CK_OBJECT_CLASS {
        switch (t) {
            case object_type::public_key:
                return CKO_PUBLIC_KEY;
            case object_type::private_key:
                return CKO_PRIVATE_KEY;
            case object_type::certificate:
                return CKO_CERTIFICATE;
            case object_type::secret_key:
                return CKO_SECRET_KEY;
            case object_type::data:
                return CKO_DATA;
        }
        return CKO_DATA;
    }

    /// CKA_EC_POINT is a DER OCTET STRING around the point; some libraries
    /// return the bare point. The curve's size tells them apart.
    [[nodiscard]] static auto unwrap_point(std::span<const std::uint8_t> params, bytes point)
        -> bytes {
        std::size_t field = 0;
        if (std::ranges::equal(params, detail::p256_params)) {
            field = 32;
        } else if (std::ranges::equal(params, detail::p384_params)) {
            field = 48;
        }
        if (field != 0 && point.size() == (2 * field) + 1 && point.front() == 0x04) {
            return point;
        }
        if (field != 0 && point.size() == (2 * field) + 3 && point[0] == 0x04 &&
            point[1] == (2 * field) + 1) {
            return {point.begin() + 2, point.end()};
        }
        if (field == 0 && point.size() > 2 && point[0] == 0x04 && point[1] < 0x80 &&
            point[1] == point.size() - 2) {
            return {point.begin() + 2, point.end()};
        }
        return point;
    }

    std::shared_ptr<backend> _b;
    CK_SLOT_ID _slot = 0;
    CK_SESSION_HANDLE _s = CK_INVALID_HANDLE;
    std::unique_ptr<std::mutex> _mutex;
};

/// A PKCS#11 module: a backend, and the URI lookup on top.
class module {
public:
    explicit module(std::shared_ptr<backend> b) : _b(std::move(b)) {
        if (!_b) {
            throw error("pkcs11::module: no backend", CKR_ARGUMENTS_BAD);
        }
    }

    /// dlopens the PKCS#11 library at `path`.
    [[nodiscard]] static auto load(const std::string& path) -> module {
        return module(std::make_shared<function_list_backend>(path));
    }

    /// The library a URI's module-path names. module-name is not looked up
    /// (that needs p11-kit's configuration); give module-path.
    [[nodiscard]] static auto load(const uri& u) -> module {
        if (!u.module_path) {
            throw error("pkcs11 URI " + u.to_string() + " has no module-path", CKR_ARGUMENTS_BAD);
        }
        return load(*u.module_path);
    }

    [[nodiscard]] auto library() const -> library_info { return _b->library(); }

    /// The tokens whose slot and token attributes match the URI's (none
    /// when its library attributes do not match this library).
    [[nodiscard]] auto matching_tokens(const uri& u) const -> std::vector<token_info> {
        const auto lib = _b->library();
        if ((u.library_manufacturer && *u.library_manufacturer != lib.manufacturer) ||
            (u.library_description && *u.library_description != lib.description) ||
            (u.library_version && (u.library_version->major != lib.version.major ||
                                   u.library_version->minor != lib.version.minor))) {
            return {};
        }
        std::vector<token_info> out;
        for (auto& t : _b->tokens()) {
            if ((u.slot_id && *u.slot_id != t.slot) ||
                (u.slot_description && *u.slot_description != t.slot_description) ||
                (u.slot_manufacturer && *u.slot_manufacturer != t.slot_manufacturer) ||
                (u.token && *u.token != t.label) ||
                (u.manufacturer && *u.manufacturer != t.manufacturer) ||
                (u.model && *u.model != t.model) || (u.serial && *u.serial != t.serial)) {
                continue;
            }
            out.push_back(std::move(t));
        }
        return out;
    }

    /// Opens a session on the one token the URI matches and logs in with
    /// `pin`, else the URI's pin-value or pin-source.
    [[nodiscard]] auto open(const uri& u, std::optional<std::string> pin = std::nullopt) const
        -> session {
        const auto tokens = matching_tokens(u);
        if (tokens.empty()) {
            throw error("no token matches " + u.to_string(), CKR_TOKEN_NOT_PRESENT);
        }
        if (tokens.size() > 1) {
            throw error(std::to_string(tokens.size()) + " tokens match " + u.to_string() +
                            "; add token= or serial=",
                        CKR_SLOT_ID_INVALID);
        }
        if (!pin) {
            pin = u.pin();
        }
        session s(_b, tokens.front().slot, _b->open_session(tokens.front().slot));
        if (pin) {
            _b->login(s._s, *pin);
            std::fill(pin->begin(), pin->end(), '\0');
        }
        return s;
    }

    [[nodiscard]] auto backend_ptr() const -> const std::shared_ptr<backend>& { return _b; }

private:
    std::shared_ptr<backend> _b;
};

}  // namespace kythira::pkcs11
