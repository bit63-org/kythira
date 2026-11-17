// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// libkythira_pkcs11.so (.kiro/specs/virtual-hsm/ task 10, requirements
// 5.1-5.7): the PKCS#11 v3.0 library any consumer loads to reach the
// virtual HSM. It keeps no key material; every call is one request over
// the wire (wire_client.hpp) to a node named in KYTHIRA_PKCS11_CONF
// (pkcs11_config.hpp).
//
// One connection per process. A PKCS#11 application's login is shared by
// all of its sessions, and on the node one connection is one application,
// so every thread's calls go over the same connection, one at a time
// under one lock: the application's mutex callbacks when it supplies them
// without CKF_OS_LOCKING_OK, a std::mutex otherwise.
//
// Failover (requirement 5.5). When an exchange fails, the library connects
// to the next node and restores what it can: every session is reopened
// with its flags, every slot's login is repeated (the PIN is kept, in this
// process only, for exactly this), and an operation that has been
// initialized but has sent no data is initialized again. The call that
// failed is then tried once more, unless it was part of a multi-part
// operation already under way: that operation is lost and its next call
// answers CKR_DEVICE_ERROR. Session objects live on the node that made
// them, so a session that made any is gone: it answers
// CKR_SESSION_HANDLE_INVALID.
//
// Output lengths. PKCS#11 lets a caller ask for an output's length (a
// null buffer) or offer one too small (CKR_BUFFER_TOO_SMALL) without
// ending the operation, but the node produces the output when it runs the
// operation. The library keeps the output it got until a buffer large
// enough takes it, so the operation runs once.
//
// After fork() the child must call C_Initialize again, as PKCS#11 says;
// until it does, every call answers CKR_CRYPTOKI_NOT_INITIALIZED.

#include "pkcs11_config.hpp"

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/wire.hpp>
#include <kythira/hsm/wire_client.hpp>

#include <openssl/crypto.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace hsm = kythira::hsm;
namespace wire = kythira::hsm::wire;
using hsm::attribute_map;
using hsm::ck_result;
using hsm::unexpected;
using hsm::wire_client;
using bytes = std::vector<std::uint8_t>;

constexpr CK_VERSION library_version{1, 0};
constexpr std::string_view manufacturer = "Kythira";
// CK_TOKEN_INFO's model is 16 bytes: with the manufacturer "Kythira",
// "virtual HSM" says the token is software (requirement 5.7).
constexpr std::string_view model = "virtual HSM";

/// Blank-padded, as PKCS#11 info strings are.
void pad(CK_UTF8CHAR* dst, std::size_t n, std::string_view s) {
    std::memset(dst, ' ', n);
    std::memcpy(dst, s.data(), std::min(n, s.size()));
}

template<class T> auto rv_of(const ck_result<T>& r) -> CK_RV {
    return r ? CKR_OK : r.error();
}

/// The caller's buffer convention: a null buffer asks for the length, a
/// short one is CKR_BUFFER_TOO_SMALL with the length set.
auto give(std::span<const std::uint8_t> out, CK_BYTE_PTR buf, CK_ULONG_PTR len) -> CK_RV {
    if (buf == nullptr) {
        *len = static_cast<CK_ULONG>(out.size());
        return CKR_OK;
    }
    if (*len < out.size()) {
        *len = static_cast<CK_ULONG>(out.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    if (!out.empty()) {
        std::memcpy(buf, out.data(), out.size());
    }
    *len = static_cast<CK_ULONG>(out.size());
    return CKR_OK;
}

auto span_of(CK_BYTE_PTR p, CK_ULONG n) -> std::optional<std::span<const std::uint8_t>> {
    if (p == nullptr) {
        if (n != 0) {
            return std::nullopt;
        }
        return std::span<const std::uint8_t>{};
    }
    return std::span<const std::uint8_t>(p, n);
}

auto template_of(CK_ATTRIBUTE_PTR t, CK_ULONG n) -> ck_result<attribute_map> {
    if (t == nullptr && n != 0) {
        return unexpected(CKR_ARGUMENTS_BAD);
    }
    return attribute_map::from_template(std::span<const CK_ATTRIBUTE>(t, t == nullptr ? 0 : n));
}

auto pin_of(CK_UTF8CHAR_PTR p, CK_ULONG n) -> std::optional<std::string_view> {
    if (p == nullptr) {
        if (n != 0) {
            return std::nullopt;
        }
        return std::string_view{};
    }
    return std::string_view(reinterpret_cast<const char*>(p), n);
}

/// The lock calls take: the application's mutex callbacks, or a std::mutex.
class call_lock {
public:
    void use_os() {
        _create = nullptr;
        _app_mutex = nullptr;
    }
    auto use_app(const CK_C_INITIALIZE_ARGS& a) -> CK_RV {
        _create = a.CreateMutex;
        _destroy = a.DestroyMutex;
        _lock = a.LockMutex;
        _unlock = a.UnlockMutex;
        return _create(&_app_mutex);
    }
    void release() {
        if (_app_mutex != nullptr) {
            _destroy(_app_mutex);
            _app_mutex = nullptr;
        }
        _create = nullptr;
    }
    void lock() {
        if (_app_mutex != nullptr) {
            _lock(_app_mutex);
        } else {
            _os.lock();
        }
    }
    void unlock() {
        if (_app_mutex != nullptr) {
            _unlock(_app_mutex);
        } else {
            _os.unlock();
        }
    }

private:
    std::mutex _os;
    CK_CREATEMUTEX _create = nullptr;
    CK_DESTROYMUTEX _destroy = nullptr;
    CK_LOCKMUTEX _lock = nullptr;
    CK_UNLOCKMUTEX _unlock = nullptr;
    CK_VOID_PTR _app_mutex = nullptr;
};

enum class op_kind : std::uint8_t {
    sign,
    verify,
    encrypt,
    decrypt,
    digest,
    find
};

struct operation {
    /// The mechanism as put_mechanism wrote it, to initialize again on
    /// another node.
    std::vector<std::byte> mechanism;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    attribute_map find_template;
    /// Data (or a find) has reached the node: the operation cannot be
    /// started again elsewhere.
    bool advanced = false;
    /// A failover lost it.
    bool lost = false;
    /// The output the node produced, waiting for a buffer large enough.
    std::optional<bytes> output;
    /// Whether a single-part call (C_Encrypt, ...) produced `output`, not
    /// a final call: the other kind may not collect it.
    bool output_single = false;

    operation() = default;
    operation(const operation&) = delete;
    auto operator=(const operation&) -> operation& = delete;
    operation(operation&&) = default;
    auto operator=(operation&&) -> operation& = default;
    ~operation() {
        if (output) {
            wire::wipe(*output);
        }
    }
};

struct session {
    CK_SLOT_ID slot = 0;
    CK_FLAGS flags = 0;
    CK_SESSION_HANDLE remote = CK_INVALID_HANDLE;
    bool made_session_objects = false;
    bool dead = false;
    std::map<op_kind, operation> ops;
    /// C_WrapKey's output for a length query, with what it was asked for.
    struct wrapped {
        std::vector<std::byte> mechanism;
        CK_OBJECT_HANDLE wrapping = 0;
        CK_OBJECT_HANDLE key = 0;
        bytes value;
    };
    std::optional<wrapped> wrap;
};

struct login {
    CK_USER_TYPE user = CKU_USER;
    std::string pin;
    login() = default;
    login(CK_USER_TYPE u, std::string_view p) : user(u), pin(p) {}
    login(const login&) = delete;
    auto operator=(const login&) -> login& = delete;
    login(login&& o) noexcept : user(o.user), pin(std::move(o.pin)) {}
    auto operator=(login&& o) noexcept -> login& {
        wipe();
        user = o.user;
        pin = std::move(o.pin);
        return *this;
    }
    ~login() { wipe(); }
    void wipe() {
        if (!pin.empty()) {
            OPENSSL_cleanse(pin.data(), pin.size());
        }
    }
};

auto encode_mechanism(const CK_MECHANISM& m) -> ck_result<std::vector<std::byte>> {
    kythira::hsm::byte_writer w;
    if (const auto rv = wire::put_mechanism(w, m); rv != CKR_OK) {
        return unexpected(rv);
    }
    return w.take();
}

class library {
public:
    // -- Life ------------------------------------------------------------------

    auto initialize(CK_VOID_PTR args) -> CK_RV {
        const std::scoped_lock life(_life);
        if (_initialized && _pid == ::getpid()) {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        // A child after fork(): the parent's connection and sessions are
        // not this process's; drop them without closing anything.
        if (_initialized) {
            reset_state(false);
        }
        if (args != nullptr) {
            const auto& a = *static_cast<const CK_C_INITIALIZE_ARGS*>(args);
            if (a.pReserved != nullptr) {
                return CKR_ARGUMENTS_BAD;
            }
            const std::array<bool, 4> callbacks{a.CreateMutex != nullptr, a.DestroyMutex != nullptr,
                                                a.LockMutex != nullptr, a.UnlockMutex != nullptr};
            const auto given = std::ranges::count(callbacks, true);
            if (given != 0 && given != 4) {
                return CKR_ARGUMENTS_BAD;
            }
            if (given == 4 && (a.flags & CKF_OS_LOCKING_OK) == 0) {
                if (const auto rv = _lock.use_app(a); rv != CKR_OK) {
                    return rv;
                }
            } else {
                _lock.use_os();
            }
        } else {
            _lock.use_os();
        }
        const char* path = std::getenv("KYTHIRA_PKCS11_CONF");  // NOLINT(concurrency-mt-unsafe)
        if (path == nullptr || *path == '\0') {
            std::fprintf(stderr, "libkythira_pkcs11: KYTHIRA_PKCS11_CONF is not set\n");
            _lock.release();
            return CKR_GENERAL_ERROR;
        }
        std::string error;
        auto config = hsm::pkcs11lib::load_config(path, &error);
        if (!config) {
            // PKCS#11 has no way to say why; the application's stderr does.
            std::fprintf(stderr, "libkythira_pkcs11: %s: %s\n", path, error.c_str());
            _lock.release();
            return CKR_GENERAL_ERROR;
        }
        _config = std::move(*config);
        _pid = ::getpid();
        _initialized = true;
        return CKR_OK;
    }

    auto finalize(CK_VOID_PTR reserved) -> CK_RV {
        if (reserved != nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        const std::scoped_lock life(_life);
        if (!_initialized || _pid != ::getpid()) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        _lock.lock();
        reset_state(true);
        _lock.unlock();
        _lock.release();
        _initialized = false;
        return CKR_OK;
    }

    /// Holds the call lock for one call, or answers why there is none.
    class guard {
    public:
        explicit guard(library& l) : _l(&l) {
            if (!l._initialized || l._pid != ::getpid()) {
                _rv = CKR_CRYPTOKI_NOT_INITIALIZED;
                return;
            }
            l._lock.lock();
            _held = true;
        }
        guard(const guard&) = delete;
        auto operator=(const guard&) -> guard& = delete;
        guard(guard&&) = delete;
        auto operator=(guard&&) -> guard& = delete;
        ~guard() {
            if (_held) {
                _l->_lock.unlock();
            }
        }
        [[nodiscard]] auto rv() const -> CK_RV { return _rv; }

    private:
        library* _l;
        CK_RV _rv = CKR_OK;
        bool _held = false;
    };

    /// `fn(client, remote handle)` for session `s`, refusing once a
    /// failover has made the session invalid.
    template<class Fn> static auto on(session& s, Fn fn) {
        return [&s, fn = std::move(fn)](wire_client& c) mutable {
            using R = std::invoke_result_t<Fn&, wire_client&, CK_SESSION_HANDLE>;
            if (s.dead) {
                return R(unexpected(CKR_SESSION_HANDLE_INVALID));
            }
            return fn(c, s.remote);
        };
    }

    /// Runs `fn` on the connection, connecting first if there is none.
    /// After a failed exchange: fail over, and run it once more when
    /// `retry`.
    template<class Fn> auto call(Fn&& fn, bool retry) {
        using R = std::invoke_result_t<Fn&, wire_client&>;
        if (!ensure_connected()) {
            return R(unexpected(CKR_DEVICE_ERROR));
        }
        auto r = fn(*_client);
        if (_client->transport_failed()) {
            const bool again = fail_over();
            if (retry && again) {
                r = fn(*_client);
            }
        }
        return r;
    }

    // -- Slots and tokens --------------------------------------------------------

    auto get_slot_list(CK_SLOT_ID_PTR list, CK_ULONG_PTR count) -> CK_RV {
        if (count == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto slots = call([](wire_client& c) { return c.get_slot_list(); }, true);
        if (!slots) {
            return slots.error();
        }
        if (list == nullptr) {
            *count = static_cast<CK_ULONG>(slots->size());
            return CKR_OK;
        }
        if (*count < slots->size()) {
            *count = static_cast<CK_ULONG>(slots->size());
            return CKR_BUFFER_TOO_SMALL;
        }
        std::copy(slots->begin(), slots->end(), list);
        *count = static_cast<CK_ULONG>(slots->size());
        return CKR_OK;
    }

    auto get_slot_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info) -> CK_RV {
        if (info == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        if (const auto rv = check_slot(slot); rv != CKR_OK) {
            return rv;
        }
        pad(info->slotDescription, sizeof info->slotDescription,
            std::string(model) + " slot " + std::to_string(slot));
        pad(info->manufacturerID, sizeof info->manufacturerID, manufacturer);
        // Not CKF_HW_SLOT: this is software (requirement 5.7).
        info->flags = CKF_TOKEN_PRESENT;
        info->hardwareVersion = library_version;
        info->firmwareVersion = library_version;
        return CKR_OK;
    }

    auto get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) -> CK_RV {
        if (info == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto t = call([&](wire_client& c) { return c.get_token_info(slot); }, true);
        if (!t) {
            return t.error() == CKR_TOKEN_NOT_PRESENT ? CKR_SLOT_ID_INVALID : t.error();
        }
        pad(info->label, sizeof info->label, t->label);
        pad(info->manufacturerID, sizeof info->manufacturerID, manufacturer);
        pad(info->model, sizeof info->model, model);
        std::array<char, 17> serial{};
        std::snprintf(serial.data(), serial.size(), "%016llx",
                      static_cast<unsigned long long>(slot));
        pad(info->serialNumber, sizeof info->serialNumber, serial.data());
        info->flags = t->flags | CKF_RNG | CKF_LOGIN_REQUIRED;
        info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
        info->ulSessionCount = t->session_count;
        info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
        info->ulRwSessionCount = t->rw_session_count;
        info->ulMaxPinLen = 255;
        info->ulMinPinLen = 4;
        info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
        info->hardwareVersion = library_version;
        info->firmwareVersion = library_version;
        pad(info->utcTime, sizeof info->utcTime, "");
        return CKR_OK;
    }

    auto get_mechanism_list(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count)
        -> CK_RV {
        if (count == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        if (const auto rv = check_slot(slot); rv != CKR_OK) {
            return rv;
        }
        auto m = call([&](wire_client& c) { return c.get_mechanism_list(slot); }, true);
        if (!m) {
            return m.error();
        }
        if (list == nullptr) {
            *count = static_cast<CK_ULONG>(m->size());
            return CKR_OK;
        }
        if (*count < m->size()) {
            *count = static_cast<CK_ULONG>(m->size());
            return CKR_BUFFER_TOO_SMALL;
        }
        std::copy(m->begin(), m->end(), list);
        *count = static_cast<CK_ULONG>(m->size());
        return CKR_OK;
    }

    auto get_mechanism_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
        -> CK_RV {
        if (info == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        if (const auto rv = check_slot(slot); rv != CKR_OK) {
            return rv;
        }
        auto i = call([&](wire_client& c) { return c.get_mechanism_info(slot, type); }, true);
        if (!i) {
            return i.error();
        }
        *info = *i;
        return CKR_OK;
    }

    auto init_token(CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
        -> CK_RV {
        const auto p = pin_of(pin, pin_len);
        if (!p || label == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        // The label is 32 blank-padded bytes.
        std::string_view l(reinterpret_cast<const char*>(label), 32);
        l = l.substr(0, l.find_last_not_of(' ') + 1);
        for (const auto& [h, s] : _sessions) {
            if (s.slot == slot) {
                return CKR_SESSION_EXISTS;
            }
        }
        return rv_of(call([&](wire_client& c) { return c.init_token(slot, *p, l); }, true));
    }

    // -- Sessions and logins -----------------------------------------------------

    auto open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_SESSION_HANDLE_PTR out) -> CK_RV {
        if (out == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto r = call([&](wire_client& c) { return c.open_session(slot, flags); }, true);
        if (!r) {
            // A token this client is not bound to is not in its slot list.
            return r.error() == CKR_TOKEN_NOT_PRESENT ? CKR_SLOT_ID_INVALID : r.error();
        }
        const CK_SESSION_HANDLE h = ++_next_session;
        session s;
        s.slot = slot;
        s.flags = flags;
        s.remote = *r;
        _sessions.emplace(h, std::move(s));
        *out = h;
        return CKR_OK;
    }

    auto close_session(CK_SESSION_HANDLE h) -> CK_RV {
        auto* s = find(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (!s->dead) {
            // A failure here still closes the session for the caller.
            (void)call(
                on(*s, [](wire_client& c, CK_SESSION_HANDLE r) { return c.close_session(r); }),
                true);
        }
        const auto slot = s->slot;
        _sessions.erase(h);
        forget_login_if_no_session(slot);
        return CKR_OK;
    }

    auto close_all_sessions(CK_SLOT_ID slot) -> CK_RV {
        auto r = call([&](wire_client& c) { return c.close_all_sessions(slot); }, true);
        if (!r && r.error() != CKR_DEVICE_ERROR) {
            return r.error() == CKR_TOKEN_NOT_PRESENT ? CKR_SLOT_ID_INVALID : r.error();
        }
        std::erase_if(_sessions, [&](const auto& e) { return e.second.slot == slot; });
        _logins.erase(slot);
        return CKR_OK;
    }

    auto get_session_info(CK_SESSION_HANDLE h, CK_SESSION_INFO_PTR info) -> CK_RV {
        if (info == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        auto r = call(
            on(*s, [](wire_client& c, CK_SESSION_HANDLE rh) { return c.get_session_info(rh); }),
            true);
        if (!r) {
            return r.error();
        }
        info->slotID = s->slot;
        info->state = r->state;
        info->flags = r->flags;
        info->ulDeviceError = 0;
        return CKR_OK;
    }

    auto do_login(CK_SESSION_HANDLE h, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG len)
        -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        const auto p = pin_of(pin, len);
        if (!p) {
            return CKR_ARGUMENTS_BAD;
        }
        const auto rv = rv_of(call(
            on(*s, [&](wire_client& c, CK_SESSION_HANDLE rh) { return c.login(rh, user, *p); }),
            true));
        if (rv == CKR_OK && user != CKU_CONTEXT_SPECIFIC) {
            _logins.insert_or_assign(s->slot, login(user, *p));
        }
        return rv;
    }

    auto do_logout(CK_SESSION_HANDLE h) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        const auto rv = rv_of(
            call(on(*s, [](wire_client& c, CK_SESSION_HANDLE rh) { return c.logout(rh); }), true));
        if (rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN) {
            _logins.erase(s->slot);
        }
        return rv;
    }

    auto init_pin(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR pin, CK_ULONG len) -> CK_RV {
        auto* s = live(h);
        const auto p = pin_of(pin, len);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (!p) {
            return CKR_ARGUMENTS_BAD;
        }
        return rv_of(
            call(on(*s, [&](wire_client& c, CK_SESSION_HANDLE rh) { return c.init_pin(rh, *p); }),
                 true));
    }

    auto set_pin(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_len,
                 CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len) -> CK_RV {
        auto* s = live(h);
        const auto o = pin_of(old_pin, old_len);
        const auto n = pin_of(new_pin, new_len);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (!o || !n) {
            return CKR_ARGUMENTS_BAD;
        }
        const auto rv = rv_of(call(
            on(*s, [&](wire_client& c, CK_SESSION_HANDLE rh) { return c.set_pin(rh, *o, *n); }),
            true));
        // The PIN a failover would log in with changes too.
        if (rv == CKR_OK) {
            if (auto it = _logins.find(s->slot); it != _logins.end()) {
                it->second = login(it->second.user, *n);
            }
        }
        return rv;
    }

    // -- Objects -----------------------------------------------------------------

    auto create_object(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                       CK_OBJECT_HANDLE_PTR out) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (out == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto tmpl = template_of(t, n);
        if (!tmpl) {
            return tmpl.error();
        }
        auto r = call(on(*s, [&](wire_client& c,
                                 CK_SESSION_HANDLE rh) { return c.create_object(rh, *tmpl); }),
                      true);
        return made(*s, r, !tmpl->flag(CKA_TOKEN), out);
    }

    auto copy_object(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                     CK_OBJECT_HANDLE_PTR out) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (out == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto tmpl = template_of(t, n);
        if (!tmpl) {
            return tmpl.error();
        }
        auto r = call(on(*s, [&](wire_client& c,
                                 CK_SESSION_HANDLE rh) { return c.copy_object(rh, o, *tmpl); }),
                      true);
        if (!r) {
            return r.error();
        }
        // A copy keeps the original's CKA_TOKEN unless the template says;
        // ask the node which it made.
        const std::array<CK_ATTRIBUTE_TYPE, 1> token{CKA_TOKEN};
        auto a =
            call(on(*s, [&](wire_client& c,
                            CK_SESSION_HANDLE rh) { return c.get_attribute_value(rh, *r, token); }),
                 true);
        const bool is_token = a && a->size() == 1 && (*a)[0].value && (*a)[0].value->size() == 1 &&
                              (*a)[0].value->front() != CK_FALSE;
        return made(*s, r, !is_token, out);
    }

    auto destroy_object(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        return rv_of(call(
            on(*s, [&](wire_client& c, CK_SESSION_HANDLE rh) { return c.destroy_object(rh, o); }),
            true));
    }

    /// The size is not known, but the object must be one the session can
    /// see: an unknown handle answers CKR_OBJECT_HANDLE_INVALID.
    auto get_object_size(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ULONG_PTR size) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (size == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        const std::vector<CK_ATTRIBUTE_TYPE> types{CKA_CLASS};
        auto r =
            call(on(*s, [&](wire_client& c,
                            CK_SESSION_HANDLE rh) { return c.get_attribute_value(rh, o, types); }),
                 true);
        if (!r) {
            return r.error();
        }
        *size = CK_UNAVAILABLE_INFORMATION;
        return CKR_OK;
    }

    auto get_attribute_value(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t,
                             CK_ULONG n) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (t == nullptr && n != 0) {
            return CKR_ARGUMENTS_BAD;
        }
        std::vector<CK_ATTRIBUTE_TYPE> types;
        types.reserve(n);
        for (CK_ULONG i = 0; i < n; ++i) {
            types.push_back(t[i].type);
        }
        auto r =
            call(on(*s, [&](wire_client& c,
                            CK_SESSION_HANDLE rh) { return c.get_attribute_value(rh, o, types); }),
                 true);
        if (!r) {
            return r.error();
        }
        if (r->size() != n) {
            return CKR_DEVICE_ERROR;
        }
        CK_RV rv = CKR_OK;
        for (CK_ULONG i = 0; i < n; ++i) {
            auto& v = (*r)[i];
            const auto one = fill(t[i], v);
            if (one != CKR_OK) {
                rv = one;
            }
            if (v.value) {
                wire::wipe(*v.value);
            }
        }
        return rv;
    }

    auto set_attribute_value(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t,
                             CK_ULONG n) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        auto tmpl = template_of(t, n);
        if (!tmpl) {
            return tmpl.error();
        }
        return rv_of(
            call(on(*s, [&](wire_client& c,
                            CK_SESSION_HANDLE rh) { return c.set_attribute_value(rh, o, *tmpl); }),
                 true));
    }

    auto find_objects_init(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR t, CK_ULONG n) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        auto tmpl = template_of(t, n);
        if (!tmpl) {
            return tmpl.error();
        }
        if (s->ops.contains(op_kind::find)) {
            return CKR_OPERATION_ACTIVE;
        }
        auto r = call(on(*s, [&](wire_client& c,
                                 CK_SESSION_HANDLE rh) { return c.find_objects_init(rh, *tmpl); }),
                      true);
        if (!r) {
            return r.error();
        }
        operation op;
        op.find_template = std::move(*tmpl);
        s->ops.emplace(op_kind::find, std::move(op));
        return CKR_OK;
    }

    auto find_objects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR out, CK_ULONG max,
                      CK_ULONG_PTR count) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (out == nullptr || count == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto* op = active(*s, op_kind::find);
        if (op == nullptr) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if (op->lost) {
            s->ops.erase(op_kind::find);
            return CKR_DEVICE_ERROR;
        }
        op->advanced = true;
        auto r = call(
            on(*s, [&](wire_client& c, CK_SESSION_HANDLE rh) { return c.find_objects(rh, max); }),
            false);
        if (!r) {
            s->ops.erase(op_kind::find);
            return r.error();
        }
        const auto n = std::min<std::size_t>(r->size(), max);
        std::copy_n(r->begin(), n, out);
        *count = static_cast<CK_ULONG>(n);
        return CKR_OK;
    }

    auto find_objects_final(CK_SESSION_HANDLE h) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        auto* op = active(*s, op_kind::find);
        if (op == nullptr) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        const bool lost = op->lost;
        s->ops.erase(op_kind::find);
        if (lost) {
            return CKR_OK;  // nothing is left on any node to finish
        }
        auto r = call(
            on(*s, [](wire_client& c, CK_SESSION_HANDLE rh) { return c.find_objects_final(rh); }),
            false);
        return !r && r.error() == CKR_OPERATION_NOT_INITIALIZED ? CKR_OK : rv_of(r);
    }

    // -- Keys ----------------------------------------------------------------------

    auto generate_key(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                      CK_OBJECT_HANDLE_PTR out) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (m == nullptr || out == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto tmpl = template_of(t, n);
        if (!tmpl) {
            return tmpl.error();
        }
        auto r = call(on(*s, [&](wire_client& c,
                                 CK_SESSION_HANDLE rh) { return c.generate_key(rh, *m, *tmpl); }),
                      true);
        return made(*s, r, !tmpl->flag(CKA_TOKEN), out);
    }

    auto generate_key_pair(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR pt,
                           CK_ULONG pn, CK_ATTRIBUTE_PTR vt, CK_ULONG vn, CK_OBJECT_HANDLE_PTR pub,
                           CK_OBJECT_HANDLE_PTR priv) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (m == nullptr || pub == nullptr || priv == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto public_tmpl = template_of(pt, pn);
        auto private_tmpl = template_of(vt, vn);
        if (!public_tmpl || !private_tmpl) {
            return !public_tmpl ? public_tmpl.error() : private_tmpl.error();
        }
        auto r = call(on(*s,
                         [&](wire_client& c, CK_SESSION_HANDLE rh) {
                             return c.generate_key_pair(rh, *m, *public_tmpl, *private_tmpl);
                         }),
                      true);
        if (!r) {
            return r.error();
        }
        if (!public_tmpl->flag(CKA_TOKEN) || !private_tmpl->flag(CKA_TOKEN)) {
            s->made_session_objects = true;
        }
        *pub = r->first;
        *priv = r->second;
        return CKR_OK;
    }

    auto wrap_key(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE wrapping,
                  CK_OBJECT_HANDLE key, CK_BYTE_PTR out, CK_ULONG_PTR len) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (m == nullptr || len == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto mech = encode_mechanism(*m);
        if (!mech) {
            return mech.error();
        }
        // A length query earlier for the same wrap: hand over its output.
        if (!s->wrap || s->wrap->mechanism != *mech || s->wrap->wrapping != wrapping ||
            s->wrap->key != key) {
            s->wrap.reset();
            auto r = call(
                on(*s, [&](wire_client& c,
                           CK_SESSION_HANDLE rh) { return c.wrap_key(rh, *m, wrapping, key); }),
                true);
            if (!r) {
                return r.error();
            }
            s->wrap = session::wrapped{std::move(*mech), wrapping, key, std::move(*r)};
        }
        const auto rv = give(s->wrap->value, out, len);
        if (out != nullptr && rv == CKR_OK) {
            s->wrap.reset();
        }
        return rv;
    }

    auto unwrap_key(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE unwrapping,
                    CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                    CK_OBJECT_HANDLE_PTR out) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        const auto w = span_of(wrapped, wrapped_len);
        if (m == nullptr || out == nullptr || !w) {
            return CKR_ARGUMENTS_BAD;
        }
        auto tmpl = template_of(t, n);
        if (!tmpl) {
            return tmpl.error();
        }
        auto r = call(on(*s,
                         [&](wire_client& c, CK_SESSION_HANDLE rh) {
                             return c.unwrap_key(rh, *m, unwrapping, *w, *tmpl);
                         }),
                      true);
        return made(*s, r, !tmpl->flag(CKA_TOKEN), out);
    }

    auto derive_key(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE base,
                    CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR out) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (m == nullptr || out == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        auto tmpl = template_of(t, n);
        if (!tmpl) {
            return tmpl.error();
        }
        auto r =
            call(on(*s, [&](wire_client& c,
                            CK_SESSION_HANDLE rh) { return c.derive_key(rh, *m, base, *tmpl); }),
                 true);
        return made(*s, r, !tmpl->flag(CKA_TOKEN), out);
    }

    /// The node keeps its own entropy; a seed is refused, after the
    /// session and argument checks every call makes first.
    auto seed_random(CK_SESSION_HANDLE h, const CK_BYTE* seed, CK_ULONG len) -> CK_RV {
        if (live(h) == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (seed == nullptr && len != 0) {
            return CKR_ARGUMENTS_BAD;
        }
        return CKR_RANDOM_SEED_NOT_SUPPORTED;
    }

    auto generate_random(CK_SESSION_HANDLE h, CK_BYTE_PTR out, CK_ULONG len) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (out == nullptr && len != 0) {
            return CKR_ARGUMENTS_BAD;
        }
        auto r = call(on(*s, [&](wire_client& c,
                                 CK_SESSION_HANDLE rh) { return c.generate_random(rh, len); }),
                      true);
        if (!r) {
            return r.error();
        }
        if (r->size() != len) {
            return CKR_DEVICE_ERROR;
        }
        if (len != 0) {
            std::memcpy(out, r->data(), len);
        }
        return CKR_OK;
    }

    // -- Operations ------------------------------------------------------------------

    auto op_init(CK_SESSION_HANDLE h, op_kind kind, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE key)
        -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if (m == nullptr) {
            return CKR_ARGUMENTS_BAD;
        }
        if (s->ops.contains(kind)) {
            return CKR_OPERATION_ACTIVE;
        }
        auto mech = encode_mechanism(*m);
        if (!mech) {
            return mech.error();
        }
        auto r = call(on(*s, [&](wire_client& c,
                                 CK_SESSION_HANDLE rh) { return init_on(c, rh, kind, *m, key); }),
                      true);
        if (!r) {
            return r.error();
        }
        operation op;
        op.mechanism = std::move(*mech);
        op.key = key;
        s->ops.emplace(kind, std::move(op));
        return CKR_OK;
    }

    /// A one-shot call or a final call with output: run once, keep the
    /// output until a buffer large enough takes it.
    ///
    /// PKCS#11 ends the operation on any answer but CKR_OK and
    /// CKR_BUFFER_TOO_SMALL, a missing length included, and refuses to mix
    /// a single-part call (`single`) with a multi-part one: an update
    /// followed by C_Digest, or a length query by C_Digest followed by
    /// C_DigestFinal, answers CKR_OPERATION_ACTIVE and ends it too.
    template<class Run>
    auto output_call(CK_SESSION_HANDLE h, op_kind kind, bool single, CK_BYTE_PTR out,
                     CK_ULONG_PTR len, Run run) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        auto* op = active(*s, kind);
        if (op == nullptr) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if (len == nullptr) {
            end_operation(*s, kind);
            return CKR_ARGUMENTS_BAD;
        }
        if (op->lost) {
            s->ops.erase(kind);
            return CKR_DEVICE_ERROR;
        }
        if (op->output && op->output_single != single) {
            // The node ended the operation when it produced the output.
            s->ops.erase(kind);
            return CKR_OPERATION_ACTIVE;
        }
        if (!op->output) {
            // A one-shot call, or a final call no update came before, can
            // be run again elsewhere: the failover has initialized the
            // operation there again. A final call after updates cannot.
            const bool retry = !op->advanced;
            auto r = call(on(*s, run), retry);
            if (!r) {
                s->ops.erase(kind);
                return r.error();
            }
            op = active(*s, kind);
            op->output = std::move(*r);
            op->output_single = single;
        }
        const auto rv = give(*op->output, out, len);
        if (out != nullptr && rv == CKR_OK) {
            s->ops.erase(kind);
        }
        return rv;
    }

    /// An update: the data goes to the node, which buffers it.
    template<class Run> auto update_call(CK_SESSION_HANDLE h, op_kind kind, Run run) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        auto* op = active(*s, kind);
        if (op == nullptr) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if (op->lost) {
            s->ops.erase(kind);
            return CKR_DEVICE_ERROR;
        }
        op->advanced = true;
        auto r = call(on(*s, run), false);
        if (!r) {
            s->ops.erase(kind);
            return r.error();
        }
        return CKR_OK;
    }

    /// Verify and verify-final: no output.
    template<class Run> auto verify_call(CK_SESSION_HANDLE h, Run run) -> CK_RV {
        auto* s = live(h);
        if (s == nullptr) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        auto* op = active(*s, op_kind::verify);
        if (op == nullptr) {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if (op->lost) {
            s->ops.erase(op_kind::verify);
            return CKR_DEVICE_ERROR;
        }
        const bool retry = !op->advanced;
        auto r = call(on(*s, run), retry);
        s->ops.erase(op_kind::verify);
        return rv_of(r);
    }

    // -- Plumbing ----------------------------------------------------------------------

private:
    friend class guard;

    static auto init_on(wire_client& c, CK_SESSION_HANDLE rh, op_kind kind, const CK_MECHANISM& m,
                        CK_OBJECT_HANDLE key) -> ck_result<void> {
        switch (kind) {
            case op_kind::sign:
                return c.sign_init(rh, m, key);
            case op_kind::verify:
                return c.verify_init(rh, m, key);
            case op_kind::encrypt:
                return c.encrypt_init(rh, m, key);
            case op_kind::decrypt:
                return c.decrypt_init(rh, m, key);
            case op_kind::digest:
                return c.digest_init(rh, m);
            case op_kind::find:
                break;
        }
        return unexpected(CKR_GENERAL_ERROR);
    }

    auto find(CK_SESSION_HANDLE h) -> session* {
        auto it = _sessions.find(h);
        return it == _sessions.end() ? nullptr : &it->second;
    }

    auto live(CK_SESSION_HANDLE h) -> session* {
        auto* s = find(h);
        return s == nullptr || s->dead ? nullptr : s;
    }

    static auto active(session& s, op_kind kind) -> operation* {
        auto it = s.ops.find(kind);
        return it == s.ops.end() ? nullptr : &it->second;
    }

    /// Ends an operation a local check refused, here and, unless the node
    /// already ended it by producing its output, on the node.
    void end_operation(session& s, op_kind kind) {
        auto* op = active(s, kind);
        if (op == nullptr) {
            return;
        }
        const bool on_node = !op->output && !op->lost;
        s.ops.erase(kind);
        if (!on_node) {
            return;
        }
        const CK_FLAGS flag = flag_of(kind);
        // A failure leaves the operation on the node until the session
        // closes; the caller is told about its own mistake either way.
        (void)call(on(s, [flag](wire_client& c,
                                CK_SESSION_HANDLE rh) { return c.session_cancel(rh, flag); }),
                   true);
    }

    static constexpr auto flag_of(op_kind kind) -> CK_FLAGS {
        switch (kind) {
            case op_kind::sign:
                return CKF_SIGN;
            case op_kind::verify:
                return CKF_VERIFY;
            case op_kind::encrypt:
                return CKF_ENCRYPT;
            case op_kind::decrypt:
                return CKF_DECRYPT;
            case op_kind::digest:
                return CKF_DIGEST;
            case op_kind::find:
                return CKF_FIND_OBJECTS;
        }
        return 0;
    }

    /// A slot the node shows this client.
    auto check_slot(CK_SLOT_ID slot) -> CK_RV {
        auto slots = call([](wire_client& c) { return c.get_slot_list(); }, true);
        if (!slots) {
            return slots.error();
        }
        return std::find(slots->begin(), slots->end(), slot) == slots->end() ? CKR_SLOT_ID_INVALID
                                                                             : CKR_OK;
    }

    /// The result of a call that made an object.
    static auto made(session& s, const ck_result<CK_OBJECT_HANDLE>& r, bool session_object,
                     CK_OBJECT_HANDLE_PTR out) -> CK_RV {
        if (!r) {
            return r.error();
        }
        if (session_object) {
            s.made_session_objects = true;
        }
        *out = *r;
        return CKR_OK;
    }

    void forget_login_if_no_session(CK_SLOT_ID slot) {
        const bool any = std::any_of(_sessions.begin(), _sessions.end(),
                                     [&](const auto& e) { return e.second.slot == slot; });
        if (!any) {
            _logins.erase(slot);
        }
    }

    /// Fills one caller attribute from the node's answer.
    static auto fill(CK_ATTRIBUTE& a, const hsm::attribute_value& v) -> CK_RV {
        if (v.rv != CKR_OK || !v.value) {
            a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return v.rv != CKR_OK ? v.rv : CKR_DEVICE_ERROR;
        }
        if (!hsm::is_template_attribute(a.type)) {
            if (a.pValue == nullptr) {
                a.ulValueLen = static_cast<CK_ULONG>(v.value->size());
                return CKR_OK;
            }
            if (a.ulValueLen < v.value->size()) {
                a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                return CKR_BUFFER_TOO_SMALL;
            }
            if (!v.value->empty()) {
                std::memcpy(a.pValue, v.value->data(), v.value->size());
            }
            a.ulValueLen = static_cast<CK_ULONG>(v.value->size());
            return CKR_OK;
        }
        // An array of attributes: its length is in CK_ATTRIBUTEs, and each
        // element is filled by the same rules.
        auto inner = attribute_map::decode(*v.value);
        if (!inner) {
            a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_DEVICE_ERROR;
        }
        const auto need = static_cast<CK_ULONG>(inner->size() * sizeof(CK_ATTRIBUTE));
        if (a.pValue == nullptr) {
            a.ulValueLen = need;
            return CKR_OK;
        }
        if (a.ulValueLen < need) {
            a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_BUFFER_TOO_SMALL;
        }
        auto* items = static_cast<CK_ATTRIBUTE*>(a.pValue);
        CK_RV rv = CKR_OK;
        std::size_t i = 0;
        for (const auto& [type, value] : *inner) {
            CK_ATTRIBUTE& e = items[i++];
            e.type = type;
            if (e.pValue == nullptr) {
                e.ulValueLen = static_cast<CK_ULONG>(value.size());
            } else if (e.ulValueLen < value.size()) {
                e.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            } else {
                if (!value.empty()) {
                    std::memcpy(e.pValue, value.data(), value.size());
                }
                e.ulValueLen = static_cast<CK_ULONG>(value.size());
            }
        }
        a.ulValueLen = need;
        return rv;
    }

    auto ensure_connected() -> bool {
        if (_client && !_client->transport_failed()) {
            return true;
        }
        return fail_over();
    }

    [[nodiscard]] auto connect(const hsm::pkcs11lib::endpoint& e) const
        -> std::unique_ptr<wire::connection> {
        const std::chrono::seconds timeout{_config.timeout_s};
        if (!e.socket_path.empty()) {
            return wire::connection::unix_socket(e.socket_path, timeout);
        }
        wire::tls_client_config t;
        t.host = e.host;
        t.port = e.port;
        t.cert_path = _config.cert_path;
        t.key_path = _config.key_path;
        t.ca_path = _config.ca_path;
        return wire::connection::tls(t, timeout);
    }

    /// Connects to the next node that answers and restores this
    /// process's sessions, logins and unstarted operations there.
    auto fail_over() -> bool {
        const auto n = _config.endpoints.size();
        const std::size_t start = _client ? (_current + 1) % n : _current;
        _client.reset();
        for (std::size_t i = 0; i < n; ++i) {
            const auto at = (start + i) % n;
            auto conn = connect(_config.endpoints[at]);
            if (!conn) {
                continue;
            }
            auto c = std::make_unique<wire_client>(std::move(conn));
            auto hello = c->hello();
            if (!hello || hello->version != wire::protocol_version) {
                continue;
            }
            _client = std::move(c);
            _current = at;
            restore();
            return true;
        }
        return false;
    }

    void restore() {
        for (auto& [h, s] : _sessions) {
            if (s.dead) {
                continue;
            }
            if (s.made_session_objects) {
                // Its objects were on the node that is gone.
                s.dead = true;
                continue;
            }
            auto r = _client->open_session(s.slot, s.flags);
            if (!r) {
                s.dead = true;
                continue;
            }
            s.remote = *r;
            s.wrap.reset();
        }
        for (auto it = _logins.begin(); it != _logins.end();) {
            const session* on_slot = nullptr;
            for (const auto& [h, s] : _sessions) {
                if (!s.dead && s.slot == it->first) {
                    on_slot = &s;
                    break;
                }
            }
            if (on_slot == nullptr) {
                it = _logins.erase(it);
                continue;
            }
            (void)_client->login(on_slot->remote, it->second.user, it->second.pin);
            ++it;
        }
        for (auto& [h, s] : _sessions) {
            if (s.dead) {
                continue;
            }
            for (auto& [kind, op] : s.ops) {
                if (op.advanced || op.output) {
                    // Data reached the old node, or its output is already
                    // here: nothing to start again.
                    op.lost = op.lost || (op.advanced && !op.output);
                    continue;
                }
                ck_result<void> again = unexpected(CKR_DEVICE_ERROR);
                if (kind == op_kind::find) {
                    again = _client->find_objects_init(s.remote, op.find_template);
                } else {
                    kythira::hsm::byte_reader r(op.mechanism);
                    wire::mechanism_params m;
                    if (m.read(r) == CKR_OK) {
                        again = init_on(*_client, s.remote, kind, m.get(), op.key);
                    }
                }
                op.lost = !again;
            }
        }
    }

    void reset_state(bool close) {
        if (close && _client && !_client->transport_failed()) {
            for (const auto& [h, s] : _sessions) {
                if (!s.dead) {
                    (void)_client->close_session(s.remote);
                }
            }
        }
        _client.reset();
        _sessions.clear();
        _logins.clear();
        _current = 0;
    }

    std::mutex _life;
    call_lock _lock;
    bool _initialized = false;
    pid_t _pid = 0;
    hsm::pkcs11lib::library_config _config;
    std::unique_ptr<wire_client> _client;
    std::size_t _current = 0;
    CK_SESSION_HANDLE _next_session = 0;
    std::map<CK_SESSION_HANDLE, session> _sessions;
    std::map<CK_SLOT_ID, login> _logins;
};

auto lib() -> library& {
    static library instance;
    return instance;
}

#define KYTHIRA_GUARD()                \
    const library::guard guard(lib()); \
    if (guard.rv() != CKR_OK) {        \
        return guard.rv();             \
    }

}  // namespace

// --- Entry points --------------------------------------------------------------
// Every C_ function is defined with C linkage; the version script exports
// only C_GetFunctionList, C_GetInterfaceList and C_GetInterface, so a
// consumer always goes through a function list.

// The library builds with hidden visibility; these three are the exports
// kythira_pkcs11.map names.
#define KYTHIRA_PKCS11_EXPORT __attribute__((visibility("default")))

extern "C" {

CK_RV C_Initialize(CK_VOID_PTR args) {
    return lib().initialize(args);
}

CK_RV C_Finalize(CK_VOID_PTR reserved) {
    return lib().finalize(reserved);
}

CK_RV C_GetInfo(CK_INFO_PTR info) {
    KYTHIRA_GUARD();
    if (info == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    info->cryptokiVersion = kythira::hsm::cryptoki_version;
    pad(info->manufacturerID, sizeof info->manufacturerID, manufacturer);
    info->flags = 0;
    pad(info->libraryDescription, sizeof info->libraryDescription, "Kythira virtual HSM client");
    info->libraryVersion = library_version;
    return CKR_OK;
}

KYTHIRA_PKCS11_EXPORT CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list);
KYTHIRA_PKCS11_EXPORT CK_RV C_GetInterfaceList(CK_INTERFACE_PTR list, CK_ULONG_PTR count);
KYTHIRA_PKCS11_EXPORT CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version,
                                           CK_INTERFACE_PTR_PTR out, CK_FLAGS flags);

CK_RV C_GetSlotList(CK_BBOOL /*present*/, CK_SLOT_ID_PTR list, CK_ULONG_PTR count) {
    KYTHIRA_GUARD();
    return lib().get_slot_list(list, count);
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info) {
    KYTHIRA_GUARD();
    return lib().get_slot_info(slot, info);
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
    KYTHIRA_GUARD();
    return lib().get_token_info(slot, info);
}

CK_RV C_GetMechanismList(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    KYTHIRA_GUARD();
    return lib().get_mechanism_list(slot, list, count);
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slot, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info) {
    KYTHIRA_GUARD();
    return lib().get_mechanism_info(slot, type, info);
}

CK_RV C_InitToken(CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin, CK_ULONG len, CK_UTF8CHAR_PTR label) {
    KYTHIRA_GUARD();
    return lib().init_token(slot, pin, len, label);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR pin, CK_ULONG len) {
    KYTHIRA_GUARD();
    return lib().init_pin(h, pin, len);
}

CK_RV C_SetPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_len,
               CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len) {
    KYTHIRA_GUARD();
    return lib().set_pin(h, old_pin, old_len, new_pin, new_len);
}

CK_RV C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR /*app*/, CK_NOTIFY /*notify*/,
                    CK_SESSION_HANDLE_PTR out) {
    KYTHIRA_GUARD();
    return lib().open_session(slot, flags, out);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE h) {
    KYTHIRA_GUARD();
    return lib().close_session(h);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slot) {
    KYTHIRA_GUARD();
    return lib().close_all_sessions(slot);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE h, CK_SESSION_INFO_PTR info) {
    KYTHIRA_GUARD();
    return lib().get_session_info(h, info);
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE,
                          CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE h, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG len) {
    KYTHIRA_GUARD();
    return lib().do_login(h, user, pin, len);
}

CK_RV C_Logout(CK_SESSION_HANDLE h) {
    KYTHIRA_GUARD();
    return lib().do_logout(h);
}

CK_RV C_CreateObject(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR o) {
    KYTHIRA_GUARD();
    return lib().create_object(h, t, n, o);
}

CK_RV C_CopyObject(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                   CK_OBJECT_HANDLE_PTR out) {
    KYTHIRA_GUARD();
    return lib().copy_object(h, o, t, n, out);
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o) {
    KYTHIRA_GUARD();
    return lib().destroy_object(h, o);
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ULONG_PTR size) {
    KYTHIRA_GUARD();
    return lib().get_object_size(h, o, size);
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    KYTHIRA_GUARD();
    return lib().get_attribute_value(h, o, t, n);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    KYTHIRA_GUARD();
    return lib().set_attribute_value(h, o, t, n);
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    KYTHIRA_GUARD();
    return lib().find_objects_init(h, t, n);
}

CK_RV C_FindObjects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR out, CK_ULONG max,
                    CK_ULONG_PTR count) {
    KYTHIRA_GUARD();
    return lib().find_objects(h, out, max, count);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE h) {
    KYTHIRA_GUARD();
    return lib().find_objects_final(h);
}

// Encrypt.

CK_RV C_EncryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE key) {
    KYTHIRA_GUARD();
    return lib().op_init(h, op_kind::encrypt, m, key);
}

CK_RV C_Encrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR out,
                CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().output_call(h, op_kind::encrypt, true, out, out_len,
                             [d](wire_client& c, CK_SESSION_HANDLE r) { return c.encrypt(r, *d); });
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR /*out*/,
                      CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d || out_len == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    // The node buffers the input and produces everything at the final
    // call, which PKCS#11 allows.
    *out_len = 0;
    return lib().update_call(h, op_kind::encrypt, [d](wire_client& c, CK_SESSION_HANDLE r) {
        return c.encrypt_update(r, *d);
    });
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    return lib().output_call(
        h, op_kind::encrypt, false, out, out_len,
        [](wire_client& c, CK_SESSION_HANDLE r) { return c.encrypt_final(r); });
}

// Decrypt.

CK_RV C_DecryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE key) {
    KYTHIRA_GUARD();
    return lib().op_init(h, op_kind::decrypt, m, key);
}

CK_RV C_Decrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR out,
                CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().output_call(h, op_kind::decrypt, true, out, out_len,
                             [d](wire_client& c, CK_SESSION_HANDLE r) { return c.decrypt(r, *d); });
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR /*out*/,
                      CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d || out_len == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    *out_len = 0;
    return lib().update_call(h, op_kind::decrypt, [d](wire_client& c, CK_SESSION_HANDLE r) {
        return c.decrypt_update(r, *d);
    });
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    return lib().output_call(
        h, op_kind::decrypt, false, out, out_len,
        [](wire_client& c, CK_SESSION_HANDLE r) { return c.decrypt_final(r); });
}

// Digest.

CK_RV C_DigestInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m) {
    KYTHIRA_GUARD();
    return lib().op_init(h, op_kind::digest, m, CK_INVALID_HANDLE);
}

CK_RV C_Digest(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR out,
               CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().output_call(h, op_kind::digest, true, out, out_len,
                             [d](wire_client& c, CK_SESSION_HANDLE r) { return c.digest(r, *d); });
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().update_call(h, op_kind::digest, [d](wire_client& c, CK_SESSION_HANDLE r) {
        return c.digest_update(r, *d);
    });
}

CK_RV C_DigestKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    return lib().output_call(h, op_kind::digest, false, out, out_len,
                             [](wire_client& c, CK_SESSION_HANDLE r) { return c.digest_final(r); });
}

// Sign and verify.

CK_RV C_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE key) {
    KYTHIRA_GUARD();
    return lib().op_init(h, op_kind::sign, m, key);
}

CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR out,
             CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().output_call(h, op_kind::sign, true, out, out_len,
                             [d](wire_client& c, CK_SESSION_HANDLE r) { return c.sign(r, *d); });
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().update_call(h, op_kind::sign, [d](wire_client& c, CK_SESSION_HANDLE r) {
        return c.sign_update(r, *d);
    });
}

CK_RV C_SignFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {
    KYTHIRA_GUARD();
    return lib().output_call(h, op_kind::sign, false, out, out_len,
                             [](wire_client& c, CK_SESSION_HANDLE r) { return c.sign_final(r); });
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE key) {
    KYTHIRA_GUARD();
    return lib().op_init(h, op_kind::verify, m, key);
}

CK_RV C_Verify(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR sig,
               CK_ULONG sig_len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    const auto s = span_of(sig, sig_len);
    if (!d || !s) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().verify_call(
        h, [d, s](wire_client& c, CK_SESSION_HANDLE r) { return c.verify(r, *d, *s); });
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG len) {
    KYTHIRA_GUARD();
    const auto d = span_of(data, len);
    if (!d) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().update_call(h, op_kind::verify, [d](wire_client& c, CK_SESSION_HANDLE r) {
        return c.verify_update(r, *d);
    });
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR sig, CK_ULONG sig_len) {
    KYTHIRA_GUARD();
    const auto s = span_of(sig, sig_len);
    if (!s) {
        return CKR_ARGUMENTS_BAD;
    }
    return lib().verify_call(
        h, [s](wire_client& c, CK_SESSION_HANDLE r) { return c.verify_final(r, *s); });
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// Keys.

CK_RV C_GenerateKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                    CK_OBJECT_HANDLE_PTR out) {
    KYTHIRA_GUARD();
    return lib().generate_key(h, m, t, n, out);
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR pt, CK_ULONG pn,
                        CK_ATTRIBUTE_PTR vt, CK_ULONG vn, CK_OBJECT_HANDLE_PTR pub,
                        CK_OBJECT_HANDLE_PTR priv) {
    KYTHIRA_GUARD();
    return lib().generate_key_pair(h, m, pt, pn, vt, vn, pub, priv);
}

CK_RV C_WrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE wrapping,
                CK_OBJECT_HANDLE key, CK_BYTE_PTR out, CK_ULONG_PTR len) {
    KYTHIRA_GUARD();
    return lib().wrap_key(h, m, wrapping, key, out, len);
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE unwrapping,
                  CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                  CK_OBJECT_HANDLE_PTR out) {
    KYTHIRA_GUARD();
    return lib().unwrap_key(h, m, unwrapping, wrapped, wrapped_len, t, n, out);
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE base,
                  CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR out) {
    KYTHIRA_GUARD();
    return lib().derive_key(h, m, base, t, n, out);
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR seed, CK_ULONG len) {
    KYTHIRA_GUARD();
    return lib().seed_random(h, seed, len);
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR out, CK_ULONG len) {
    KYTHIRA_GUARD();
    return lib().generate_random(h, out, len);
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE) {
    KYTHIRA_GUARD();
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE) {
    KYTHIRA_GUARD();
    return CKR_FUNCTION_NOT_PARALLEL;
}

// Even an unsupported call reports a library not yet initialized first.
CK_RV C_WaitForSlotEvent(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) {
    KYTHIRA_GUARD();
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// PKCS#11 3.0 functions this library does not implement (requirement 6.5).

CK_RV C_LoginUser(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR,
                  CK_ULONG) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SessionCancel(CK_SESSION_HANDLE, CK_FLAGS) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_EncryptMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                       CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG,
                           CK_BYTE_PTR, CK_ULONG_PTR, CK_FLAGS) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                       CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG,
                           CK_BYTE_PTR, CK_ULONG_PTR, CK_FLAGS) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageSignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG,
                        CK_BYTE_PTR, CK_ULONG_PTR) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageSignFinal(CK_SESSION_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyMessage(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                      CK_ULONG) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG,
                          CK_BYTE_PTR, CK_ULONG) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

}  // extern "C"

// --- Function lists and interfaces ------------------------------------------------
// Built the way the OASIS headers intend: pkcs11f.h names every function
// in order, once for the 3.0 list and once, up to C_WaitForSlotEvent, for
// the 2.40 list.

namespace {

#define CK_PKCS11_FUNCTION_INFO(name) name,

CK_FUNCTION_LIST_3_0 function_list_3_0 = {
    kythira::hsm::cryptoki_version,
#include <pkcs11f.h>
};

#define CK_PKCS11_2_0_ONLY 1
CK_FUNCTION_LIST function_list_2_40 = {
    {2, 40},
#include <pkcs11f.h>
};
#undef CK_PKCS11_2_0_ONLY
#undef CK_PKCS11_FUNCTION_INFO

// PKCS#11 names the interface "PKCS 11"; CK_INTERFACE takes a mutable
// pointer, though no consumer writes through it.
std::array<CK_CHAR, 8> interface_name{'P', 'K', 'C', 'S', ' ', '1', '1', '\0'};

std::array<CK_INTERFACE, 2> interfaces{{
    {interface_name.data(), &function_list_3_0, 0},
    {interface_name.data(), &function_list_2_40, 0},
}};

}  // namespace

extern "C" {

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) {
    if (list == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    *list = &function_list_2_40;
    return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR list, CK_ULONG_PTR count) {
    if (count == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    if (list == nullptr) {
        *count = interfaces.size();
        return CKR_OK;
    }
    if (*count < interfaces.size()) {
        *count = interfaces.size();
        return CKR_BUFFER_TOO_SMALL;
    }
    std::copy(interfaces.begin(), interfaces.end(), list);
    *count = interfaces.size();
    return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out,
                     CK_FLAGS flags) {
    if (out == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }
    if (name != nullptr && std::strcmp(reinterpret_cast<const char*>(name), "PKCS 11") != 0) {
        return CKR_ARGUMENTS_BAD;
    }
    for (auto& i : interfaces) {
        const auto* v = static_cast<const CK_VERSION*>(i.pFunctionList);
        if (version != nullptr && (v->major != version->major || v->minor != version->minor)) {
            continue;
        }
        if ((i.flags & flags) != flags) {
            continue;
        }
        *out = &i;
        return CKR_OK;
    }
    return CKR_ARGUMENTS_BAD;
}

}  // extern "C"
