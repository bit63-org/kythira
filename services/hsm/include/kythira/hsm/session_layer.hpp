// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The node's PKCS#11 sessions (requirement 7.3, design "Sessions are
// node-local" and "Use on any replica, existence through read index"):
// applications, logins, sessions, session objects and multi-part operation
// state, all in this node's memory and none replicated. Everything a
// session changes on a token goes through the store as a Raft entry built
// by key_store.hpp; everything it reads comes from this node's replica.
//
// Applications. A PKCS#11 application is one client: a native_client in
// this process or one wire connection (wire_server.hpp). It carries the identity
// the catalog's bindings name, and logins are per application and token,
// as PKCS#11 has them: every session the application has on the token
// shares one login state, and closing its last session there logs it out.
// A token the identity is not bound to is not there for it
// (CKR_TOKEN_NOT_PRESENT), whether or not it exists.
//
// Using a key. An operation checks the key when it starts (it exists, is
// visible to the session, and allows the operation) and again when the
// cryptography runs: a read-index round on the token's group (the store's
// read_barrier), then the object as this replica has it after that round.
// A key destroyed or narrowed before the round is never used afterwards,
// on any node (requirement 3.4, 3.5); a failed round is CKR_DEVICE_ERROR,
// never a stale answer. Opened keys are cached by (token, handle, version)
// and the sealed bytes they came from, and dropped when the object changes
// or the node seals.
//
// PINs. The PIN is checked here, against the verifier in this replica's
// token record, and only the outcome is proposed: the state machine counts
// failures and locks in log order, so a guess on any node counts on all of
// them (requirement 7.2) and a locked PIN stays locked even when this
// replica has not yet applied the lock.
//
// Multi-part operations buffer their input (up to max_operation_bytes) and
// run the one-shot mechanism at the final call, so an update never returns
// output; PKCS#11 allows that, and it keeps every mechanism's state in one
// place. Input that may be secret (data to encrypt, sign or digest) is
// buffered in the secure arena.
//
// A sealed node answers every cryptographic call, key generation included,
// CKR_DEVICE_ERROR (design "Error handling"); sessions and logins still
// work, as they need no key.

#include <kythira/hsm/attribute_policy.hpp>
#include <kythira/hsm/audit.hpp>
#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/client_types.hpp>
#include <kythira/hsm/hsm_store.hpp>
#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/mechanisms.hpp>
#include <kythira/hsm/object_import.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/sealing.hpp>
#include <kythira/hsm/secret_bytes.hpp>
#include <kythira/hsm/secure_arena.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace kythira::hsm {

struct session_options {
    /// scrypt cost of new PIN verifiers (tests lower it).
    std::uint8_t pin_log2_n = default_pin_log2_n;
    std::uint32_t max_login_failures = default_max_login_failures;
    std::size_t max_sessions = 4096;
    /// Input a multi-part operation may buffer before its final call.
    std::size_t max_operation_bytes = std::size_t{16} << 20U;
    /// Opened keys kept for reuse; the cache is emptied when it is full.
    std::size_t max_cached_keys = 1024;
    /// Fresh random handles tried when a new token object's is taken.
    int handle_attempts = 8;
    /// Receives an event per audited call (audit.hpp); none when empty.
    audit_hook audit;
    /// A counted operation is logged on its first call and then once in
    /// this many.
    std::uint64_t audit_sample_every = 1000;
};

inline constexpr CK_ULONG min_pin_length = 4;
inline constexpr CK_ULONG max_pin_length = 255;
/// Session object handles start here, above every token object handle.
inline constexpr CK_OBJECT_HANDLE first_session_object_handle = max_token_object_handle + 1;

using app_id = std::uint64_t;

/// A CK_MECHANISM copied out of the caller's memory, parameters and the
/// buffers they point at included, so an operation can outlive the call
/// that started it.
class mechanism_copy {
public:
    static constexpr std::size_t max_parameter_bytes = 64U << 10U;

    [[nodiscard]] static auto from(const CK_MECHANISM& m) -> ck_result<mechanism_copy> {
        mechanism_copy out;
        out._type = m.mechanism;
        if (m.pParameter == nullptr || m.ulParameterLen == 0) {
            if (m.ulParameterLen != 0) {
                return unexpected(CKR_MECHANISM_PARAM_INVALID);
            }
            return out;
        }
        if (m.ulParameterLen > max_parameter_bytes) {
            return unexpected(CKR_MECHANISM_PARAM_INVALID);
        }
        const auto* p = static_cast<const std::uint8_t*>(m.pParameter);
        out._param.assign(p, p + m.ulParameterLen);
        auto copy = [](const void* src, CK_ULONG len, std::vector<std::uint8_t>& dst) -> bool {
            if (len > max_parameter_bytes || (src == nullptr && len != 0)) {
                return false;
            }
            const auto* b = static_cast<const std::uint8_t*>(src);
            dst.assign(b, b + len);
            return true;
        };
        switch (m.mechanism) {
            case CKM_AES_GCM: {
                if (m.ulParameterLen != sizeof(CK_GCM_PARAMS)) {
                    return unexpected(CKR_MECHANISM_PARAM_INVALID);
                }
                const auto& g = *static_cast<const CK_GCM_PARAMS*>(m.pParameter);
                if (!copy(g.pIv, g.ulIvLen, out._first) || !copy(g.pAAD, g.ulAADLen, out._second)) {
                    return unexpected(CKR_MECHANISM_PARAM_INVALID);
                }
                out._kind = kind::gcm;
                break;
            }
            case CKM_RSA_PKCS_OAEP: {
                if (m.ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
                    return unexpected(CKR_MECHANISM_PARAM_INVALID);
                }
                const auto& o = *static_cast<const CK_RSA_PKCS_OAEP_PARAMS*>(m.pParameter);
                if (!copy(o.pSourceData, o.ulSourceDataLen, out._first)) {
                    return unexpected(CKR_MECHANISM_PARAM_INVALID);
                }
                out._kind = kind::oaep;
                break;
            }
            case CKM_EDDSA: {
                if (m.ulParameterLen != sizeof(CK_EDDSA_PARAMS)) {
                    return unexpected(CKR_MECHANISM_PARAM_INVALID);
                }
                const auto& e = *static_cast<const CK_EDDSA_PARAMS*>(m.pParameter);
                if (!copy(e.pContextData, e.ulContextDataLen, out._first)) {
                    return unexpected(CKR_MECHANISM_PARAM_INVALID);
                }
                out._kind = kind::eddsa;
                break;
            }
            default:
                // Every other parameter this token takes is a flat structure
                // or a byte string (an IV, CK_RSA_PKCS_PSS_PARAMS).
                break;
        }
        return out;
    }

    [[nodiscard]] auto type() const noexcept -> CK_MECHANISM_TYPE { return _type; }

    /// The mechanism, pointing into this copy; valid while it lives and is
    /// not moved.
    [[nodiscard]] auto get() -> CK_MECHANISM {
        CK_MECHANISM m{_type, nullptr, 0};
        if (_param.empty()) {
            return m;
        }
        m.ulParameterLen = static_cast<CK_ULONG>(_param.size());
        auto data = [](std::vector<std::uint8_t>& v) -> CK_BYTE_PTR {
            return v.empty() ? nullptr : v.data();
        };
        switch (_kind) {
            case kind::gcm: {
                std::memcpy(&_gcm, _param.data(), sizeof _gcm);
                _gcm.pIv = data(_first);
                _gcm.pAAD = data(_second);
                m.pParameter = &_gcm;
                break;
            }
            case kind::oaep:
                std::memcpy(&_oaep, _param.data(), sizeof _oaep);
                _oaep.pSourceData = data(_first);
                m.pParameter = &_oaep;
                break;
            case kind::eddsa:
                std::memcpy(&_eddsa, _param.data(), sizeof _eddsa);
                _eddsa.pContextData = data(_first);
                m.pParameter = &_eddsa;
                break;
            case kind::flat:
                m.pParameter = _param.data();
                break;
        }
        return m;
    }

private:
    enum class kind : std::uint8_t {
        flat,
        gcm,
        oaep,
        eddsa
    };

    CK_MECHANISM_TYPE _type = 0;
    kind _kind = kind::flat;
    std::vector<std::uint8_t> _param;
    std::vector<std::uint8_t> _first;
    std::vector<std::uint8_t> _second;
    CK_GCM_PARAMS _gcm{};
    CK_RSA_PKCS_OAEP_PARAMS _oaep{};
    CK_EDDSA_PARAMS _eddsa{};
};

class session_layer {
public:
    session_layer(hsm_store& store, key_vault& vault, session_options options = {})
        : _store(&store), _vault(&vault), _opt(std::move(options)) {}

    session_layer(const session_layer&) = delete;
    auto operator=(const session_layer&) -> session_layer& = delete;
    session_layer(session_layer&&) = delete;
    auto operator=(session_layer&&) -> session_layer& = delete;
    ~session_layer() = default;

    // -- Applications --------------------------------------------------------

    /// A new application acting as `identity` (the name the catalog's
    /// bindings use).
    auto register_app(std::string identity) -> app_id {
        const std::lock_guard lock(_mutex);
        const app_id id = ++_next_app;
        _apps.emplace(id, std::move(identity));
        return id;
    }

    /// Closes every session of the application (C_Finalize).
    auto unregister_app(app_id app) -> void {
        const std::lock_guard lock(_mutex);
        std::vector<CK_SESSION_HANDLE> mine;
        for (const auto& [h, s] : _sessions) {
            if (s->app == app) {
                mine.push_back(h);
            }
        }
        for (auto h : mine) {
            close_locked(h);
        }
        _apps.erase(app);
    }

    /// Wipes every opened key this layer holds and seals the vault
    /// (requirement 4.7). Session objects are destroyed, as their material
    /// is a key like any other; sessions stay open, and their calls answer
    /// CKR_DEVICE_ERROR until the node is unsealed again.
    auto seal() -> void {
        {
            const std::lock_guard lock(_cache_mutex);
            _cache.clear();
        }
        {
            const std::lock_guard lock(_mutex);
            for (auto& [h, o] : _session_objects) {
                o.key.reset();
            }
            _session_objects.clear();
        }
        _vault->seal();
    }

    [[nodiscard]] auto session_count() const -> std::size_t {
        const std::lock_guard lock(_mutex);
        return _sessions.size();
    }

    // -- Slots and tokens ----------------------------------------------------

    /// The tokens `app` may see, in id order; slot ids are token ids.
    [[nodiscard]] auto slots(app_id app) const -> std::vector<CK_SLOT_ID> {
        const auto identity = identity_of(app);
        std::vector<CK_SLOT_ID> out;
        if (!identity) {
            return out;
        }
        for (const auto& t : _store->tokens()) {
            if (_store->may_open(*identity, t.token_id)) {
                out.push_back(static_cast<CK_SLOT_ID>(t.token_id));
            }
        }
        return out;
    }

    [[nodiscard]] auto get_token_info(app_id app, CK_SLOT_ID slot) const -> ck_result<token_info> {
        if (auto r = check_slot(app, slot); !r) {
            return unexpected(r.error());
        }
        auto entry = _store->token(slot);
        auto rec = _store->token_record_of(slot);
        token_info out;
        if (!rec) {
            out.label = entry ? entry->label : std::string();
            out.flags = CKF_RNG | CKF_LOGIN_REQUIRED;
        } else {
            out.label = rec->label;
            out.flags = rec->pin_flags();
        }
        const std::lock_guard lock(_mutex);
        for (const auto& [h, s] : _sessions) {
            if (s->token == slot) {
                ++out.session_count;
                out.rw_session_count += s->rw ? 1U : 0U;
            }
        }
        return out;
    }

    /// C_InitToken: the token's record replaced, its objects destroyed.
    /// Needs the current SO PIN once there is one; a token the admin API
    /// has just created has none, and its first C_InitToken sets it. No
    /// session may be open on the token on this node.
    auto init_token(app_id app, CK_SLOT_ID slot, std::string_view so_pin, std::string_view label)
        -> ck_result<void> {
        const auto t0 = audit_clock::now();
        auto r = init_token_unaudited(app, slot, so_pin, label);
        if (_opt.audit) {
            audit_event e;
            e.action = "init_token";
            e.identity = identity_of(app).value_or("");
            e.token = slot;
            e.label = std::string(label);
            emit(std::move(e), rv_of(r), t0);
        }
        return r;
    }

private:
    auto init_token_unaudited(app_id app, CK_SLOT_ID slot, std::string_view so_pin,
                              std::string_view label) -> ck_result<void> {
        if (auto r = check_slot(app, slot); !r) {
            return unexpected(r.error());
        }
        if (auto r = check_pin_length(so_pin); !r) {
            return r;
        }
        {
            const std::lock_guard lock(_mutex);
            for (const auto& [h, s] : _sessions) {
                if (s->token == slot) {
                    return unexpected(CKR_SESSION_EXISTS);
                }
            }
        }
        if (!_store->hosts(slot)) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        if (auto rec = _store->token_record_of(slot); rec && rec->so_pin) {
            if (auto r = verify_pin(slot, pin_user::so, so_pin); !r) {
                return r;
            }
        }
        auto verifier = new_verifier(so_pin);
        if (!verifier) {
            return unexpected(verifier.error());
        }
        auto reply = propose(
            slot, make_init_token_command(trim_label(label), *verifier, _opt.max_login_failures));
        if (!reply) {
            return unexpected(reply.error());
        }
        if (reply->rv != CKR_OK) {
            return unexpected(reply->rv);
        }
        drop_cached_token(slot);
        return {};
    }

public:
    // -- Sessions ------------------------------------------------------------

    auto open_session(app_id app, CK_SLOT_ID slot, CK_FLAGS flags) -> ck_result<CK_SESSION_HANDLE> {
        if (auto r = check_slot(app, slot); !r) {
            return unexpected(r.error());
        }
        if ((flags & CKF_SERIAL_SESSION) == 0) {
            return unexpected(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        }
        if (!_store->hosts(slot)) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        // A token initialized through another member may not have reached
        // this replica yet: only a caught-up replica says it is not.
        if (!_store->token_record_of(slot)) {
            if (auto b = _store->read_barrier(slot); !b) {
                return unexpected(b.error());
            }
            if (!_store->token_record_of(slot)) {
                return unexpected(CKR_TOKEN_NOT_RECOGNIZED);
            }
        }
        const bool rw = (flags & CKF_RW_SESSION) != 0;
        const std::lock_guard lock(_mutex);
        if (_sessions.size() >= _opt.max_sessions) {
            return unexpected(CKR_SESSION_COUNT);
        }
        if (!rw && login_locked(app, slot) == session_user::so) {
            return unexpected(CKR_SESSION_READ_WRITE_SO_EXISTS);
        }
        auto s = std::make_shared<session>();
        s->handle = ++_next_session;
        s->app = app;
        s->token = slot;
        s->rw = rw;
        _sessions.emplace(s->handle, s);
        return s->handle;
    }

    auto close_session(app_id app, CK_SESSION_HANDLE h) -> ck_result<void> {
        const std::lock_guard lock(_mutex);
        if (auto s = find_locked(app, h); !s) {
            return unexpected(s.error());
        }
        close_locked(h);
        return {};
    }

    auto close_all_sessions(app_id app, CK_SLOT_ID slot) -> ck_result<void> {
        if (auto r = check_slot(app, slot); !r) {
            return unexpected(r.error());
        }
        const std::lock_guard lock(_mutex);
        std::vector<CK_SESSION_HANDLE> mine;
        for (const auto& [h, s] : _sessions) {
            if (s->app == app && s->token == slot) {
                mine.push_back(h);
            }
        }
        for (auto h : mine) {
            close_locked(h);
        }
        return {};
    }

    [[nodiscard]] auto get_session_info(app_id app, CK_SESSION_HANDLE h) const
        -> ck_result<session_info> {
        const std::lock_guard lock(_mutex);
        auto s = find_locked(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        session_info out;
        out.slot = static_cast<CK_SLOT_ID>((*s)->token);
        out.flags = CKF_SERIAL_SESSION | ((*s)->rw ? CKF_RW_SESSION : 0);
        switch (login_locked(app, (*s)->token)) {
            case session_user::none:
                out.state = (*s)->rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
                break;
            case session_user::user:
                out.state = (*s)->rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
                break;
            case session_user::so:
                out.state = CKS_RW_SO_FUNCTIONS;
                break;
        }
        return out;
    }

    // -- Logins and PINs -----------------------------------------------------

    auto login(app_id app, CK_SESSION_HANDLE h, CK_USER_TYPE user, std::string_view pin)
        -> ck_result<void> {
        const auto t0 = audit_clock::now();
        auto r = login_unaudited(app, h, user, pin);
        if (_opt.audit) {
            emit(audit_base(user == CKU_SO ? "login_so" : "login", app, h), rv_of(r), t0);
        }
        return r;
    }

private:
    auto login_unaudited(app_id app, CK_SESSION_HANDLE h, CK_USER_TYPE user, std::string_view pin)
        -> ck_result<void> {
        if (user == CKU_CONTEXT_SPECIFIC) {
            return unexpected(CKR_OPERATION_NOT_INITIALIZED);
        }
        if (user != CKU_SO && user != CKU_USER) {
            return unexpected(CKR_USER_TYPE_INVALID);
        }
        const auto who = user == CKU_SO ? session_user::so : session_user::user;
        std::uint64_t token = 0;
        {
            const std::lock_guard lock(_mutex);
            auto s = find_locked(app, h);
            if (!s) {
                return unexpected(s.error());
            }
            token = (*s)->token;
            const auto current = login_locked(app, token);
            if (current == who) {
                return unexpected(CKR_USER_ALREADY_LOGGED_IN);
            }
            if (current != session_user::none) {
                return unexpected(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
            }
            if (who == session_user::so) {
                for (const auto& [sh, other] : _sessions) {
                    if (other->app == app && other->token == token && !other->rw) {
                        return unexpected(CKR_SESSION_READ_ONLY_EXISTS);
                    }
                }
            }
        }
        if (auto r =
                verify_pin(token, who == session_user::so ? pin_user::so : pin_user::user, pin);
            !r) {
            return r;
        }
        const std::lock_guard lock(_mutex);
        const auto current = login_locked(app, token);
        if (current != session_user::none) {
            // Another session of the application logged in meanwhile.
            return unexpected(current == who ? CKR_USER_ALREADY_LOGGED_IN
                                             : CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
        }
        _logins[{app, token}] = who;
        return {};
    }

public:
    auto logout(app_id app, CK_SESSION_HANDLE h) -> ck_result<void> {
        const std::lock_guard lock(_mutex);
        auto s = find_locked(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        if (_logins.erase({app, (*s)->token}) == 0) {
            return unexpected(CKR_USER_NOT_LOGGED_IN);
        }
        return {};
    }

    /// C_InitPIN: the SO sets the user PIN, which also unlocks it.
    auto init_pin(app_id app, CK_SESSION_HANDLE h, std::string_view pin) -> ck_result<void> {
        const auto t0 = audit_clock::now();
        auto r = init_pin_unaudited(app, h, pin);
        if (_opt.audit) {
            emit(audit_base("init_pin", app, h), rv_of(r), t0);
        }
        return r;
    }

private:
    auto init_pin_unaudited(app_id app, CK_SESSION_HANDLE h, std::string_view pin)
        -> ck_result<void> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (ctx->user != session_user::so || !ctx->rw) {
            return unexpected(CKR_USER_NOT_LOGGED_IN);
        }
        if (auto r = check_pin_length(pin); !r) {
            return r;
        }
        return store_pin(ctx->token, pin_user::user, pin);
    }

public:
    /// C_SetPIN: the logged-in user's PIN, or the user PIN in a public
    /// session. A wrong old PIN counts as a failed login.
    auto set_pin(app_id app, CK_SESSION_HANDLE h, std::string_view old_pin,
                 std::string_view new_pin) -> ck_result<void> {
        const auto t0 = audit_clock::now();
        auto r = set_pin_unaudited(app, h, old_pin, new_pin);
        if (_opt.audit) {
            emit(audit_base("set_pin", app, h), rv_of(r), t0);
        }
        return r;
    }

private:
    auto set_pin_unaudited(app_id app, CK_SESSION_HANDLE h, std::string_view old_pin,
                           std::string_view new_pin) -> ck_result<void> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (!ctx->rw) {
            return unexpected(CKR_SESSION_READ_ONLY);
        }
        if (auto r = check_pin_length(new_pin); !r) {
            return r;
        }
        const auto who = ctx->user == session_user::so ? pin_user::so : pin_user::user;
        if (auto r = verify_pin(ctx->token, who, old_pin); !r) {
            return r;
        }
        return store_pin(ctx->token, who, new_pin);
    }

public:
    // -- Objects -------------------------------------------------------------

    /// C_GenerateKey. A token object (CKA_TOKEN true) is generated, sealed
    /// and proposed here; a session object stays in this node's memory.
    auto generate_key(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                      const attribute_map& tmpl) -> ck_result<CK_OBJECT_HANDLE> {
        const auto t0 = audit_clock::now();
        auto r = generate_key_unaudited(app, h, mechanism, tmpl);
        audit_created("generate_key", app, h, r, tmpl, mechanism.mechanism, t0);
        return r;
    }

private:
    auto generate_key_unaudited(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                                const attribute_map& tmpl) -> ck_result<CK_OBJECT_HANDLE> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = require_unsealed(); !r) {
            return unexpected(r.error());
        }
        attribute_map t = tmpl;
        if (auto r = expect_class(t, CKO_SECRET_KEY); !r) {
            return unexpected(r.error());
        }
        auto checked = check_new_object(*ctx, t, CKO_SECRET_KEY);
        if (!checked) {
            return unexpected(checked.error());
        }
        if (auto r = check_trusted(t, ctx->user); !r) {
            return unexpected(r.error());
        }
        if (!*checked) {
            auto o = build_secret_key(next_session_object(), mechanism, t);
            if (!o) {
                return unexpected(o.error());
            }
            return add_session_object(*ctx, std::move(o->record), std::move(o->material));
        }
        const auto entry = _store->token(ctx->token);
        if (!entry) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        for (int attempt = 0; attempt < _opt.handle_attempts; ++attempt) {
            const auto handle = random_object_handle();
            auto cmd =
                flatten(_vault->with_token_key(*entry, [&](std::span<const std::uint8_t> tk) {
                    return prepare_generate_key(tk, ctx->token, handle, mechanism, t);
                }));
            if (!cmd) {
                return unexpected(cmd.error());
            }
            auto reply = propose(ctx->token, std::move(*cmd));
            if (!reply) {
                return unexpected(reply.error());
            }
            if (reply->rv == CKR_OK) {
                return handle;
            }
            if (reply->rv != CKR_FUNCTION_REJECTED) {
                return unexpected(reply->rv);
            }
        }
        return unexpected(CKR_DEVICE_ERROR);
    }

public:
    /// C_GenerateKeyPair: both objects in one entry when either is a token
    /// object (a token key pair whose public half is a session object is
    /// still generated once, here). The event names the private key.
    auto generate_key_pair(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                           const attribute_map& public_tmpl, const attribute_map& private_tmpl)
        -> ck_result<std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>> {
        const auto t0 = audit_clock::now();
        auto r = generate_key_pair_unaudited(app, h, mechanism, public_tmpl, private_tmpl);
        if (_opt.audit) {
            auto e = audit_base("generate_key_pair", app, h);
            e.mechanism = mechanism.mechanism;
            e.label = label_in(private_tmpl);
            if (r) {
                e.object = r->second;
            }
            emit(std::move(e), rv_of(r), t0);
        }
        return r;
    }

private:
    auto generate_key_pair_unaudited(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                                     const attribute_map& public_tmpl,
                                     const attribute_map& private_tmpl)
        -> ck_result<std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = require_unsealed(); !r) {
            return unexpected(r.error());
        }
        attribute_map pub = public_tmpl;
        attribute_map priv = private_tmpl;
        if (auto r = expect_class(pub, CKO_PUBLIC_KEY); !r) {
            return unexpected(r.error());
        }
        if (auto r = expect_class(priv, CKO_PRIVATE_KEY); !r) {
            return unexpected(r.error());
        }
        auto pub_token = check_new_object(*ctx, pub, CKO_PUBLIC_KEY);
        if (!pub_token) {
            return unexpected(pub_token.error());
        }
        auto priv_token = check_new_object(*ctx, priv, CKO_PRIVATE_KEY);
        if (!priv_token) {
            return unexpected(priv_token.error());
        }
        for (const auto* t : {&pub, &priv}) {
            if (auto r = check_trusted(*t, ctx->user); !r) {
                return unexpected(r.error());
            }
        }
        const auto entry = _store->token(ctx->token);
        if ((*pub_token || *priv_token) && !entry) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        for (int attempt = 0; attempt < _opt.handle_attempts; ++attempt) {
            const auto pub_handle = *pub_token ? random_object_handle() : next_session_object();
            auto priv_handle = *priv_token ? random_object_handle() : next_session_object();
            if (priv_handle == pub_handle) {
                continue;
            }
            auto pair = build_key_pair(pub_handle, priv_handle, mechanism, pub, priv);
            if (!pair) {
                return unexpected(pair.error());
            }
            std::vector<object_record> to_store;
            if (*priv_token) {
                auto sealed = _vault->with_token_key(*entry, [&](std::span<const std::uint8_t> tk) {
                    seal_object(tk, ctx->token, pair->private_key);
                    return true;
                });
                if (!sealed) {
                    return unexpected(sealed.error());
                }
                to_store.push_back(pair->private_key.record);
            }
            if (*pub_token) {
                to_store.push_back(pair->public_key);
            }
            if (!to_store.empty()) {
                auto reply = propose(ctx->token, make_create_objects_command(to_store));
                if (!reply) {
                    return unexpected(reply.error());
                }
                if (reply->rv == CKR_FUNCTION_REJECTED) {
                    continue;  // a handle was taken; generate again
                }
                if (reply->rv != CKR_OK) {
                    return unexpected(reply->rv);
                }
            }
            if (!*pub_token) {
                add_session_object(*ctx, std::move(pair->public_key), secret_bytes{});
            }
            if (!*priv_token) {
                add_session_object(*ctx, std::move(pair->private_key.record),
                                   std::move(pair->private_key.material));
            }
            return std::pair{pub_handle, priv_handle};
        }
        return unexpected(CKR_DEVICE_ERROR);
    }

public:
    /// C_DestroyObject. For a token object it returns once the destroy has
    /// committed, after which no node uses the key (requirement 3.5).
    auto destroy_object(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object)
        -> ck_result<void> {
        const auto t0 = audit_clock::now();
        auto label = _opt.audit ? label_of(app, h, object) : std::string();
        auto r = destroy_object_unaudited(app, h, object);
        audit_object("destroy_object", app, h, object, std::move(label), rv_of(r), t0);
        return r;
    }

private:
    auto destroy_object_unaudited(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object)
        -> ck_result<void> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        auto o = lookup(*ctx, object);
        if (!o) {
            return unexpected(o.error());
        }
        if (!o->attributes.get_bool(CKA_DESTROYABLE, true).value_or(true)) {
            return unexpected(CKR_ACTION_PROHIBITED);
        }
        if (is_session_object(object)) {
            const std::lock_guard lock(_mutex);
            _session_objects.erase(object);
            return {};
        }
        if (!ctx->rw) {
            return unexpected(CKR_SESSION_READ_ONLY);
        }
        auto reply = propose(ctx->token, make_destroy_object_command(object));
        if (!reply) {
            return unexpected(reply.error());
        }
        drop_cached(ctx->token, object);
        if (reply->rv != CKR_OK) {
            return unexpected(reply->rv);
        }
        return {};
    }

public:
    /// C_GetAttributeValue. A secret key's CKA_VALUE is read from its
    /// material when the key is extractable and not sensitive; private key
    /// components are never shown.
    auto get_attribute_value(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object,
                             std::span<const CK_ATTRIBUTE_TYPE> types)
        -> ck_result<std::vector<attribute_value>> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        auto o = lookup(*ctx, object);
        if (!o) {
            return unexpected(o.error());
        }
        const auto cls = o->attributes.get_ulong(CKA_CLASS).value_or(std::nullopt);
        std::vector<attribute_value> out;
        for (const auto type : types) {
            attribute_value v{.type = type, .value = std::nullopt, .rv = CKR_OK};
            if (auto r = check_readable(o->attributes, type); !r) {
                v.rv = r.error();
            } else if (auto b = o->attributes.bytes(type)) {
                v.value.emplace(b->begin(), b->end());
            } else if (type == CKA_VALUE && (cls == CKO_SECRET_KEY || cls == CKO_DATA)) {
                auto k = value_of(*ctx, *o);
                if (!k) {
                    return unexpected(k.error());
                }
                v.value.emplace(k->view().begin(), k->view().end());
            } else if (auto implied = implied_attribute(o->attributes, type)) {
                v.value = std::move(*implied);
            } else {
                v.rv = CKR_ATTRIBUTE_TYPE_INVALID;
            }
            out.push_back(std::move(v));
        }
        return out;
    }

    /// C_SetAttributeValue: the attribute rules, then for a token object an
    /// update entry naming the version it read, retried on a race.
    auto set_attribute_value(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object,
                             const attribute_map& changes) -> ck_result<void> {
        const auto t0 = audit_clock::now();
        auto label = _opt.audit ? label_of(app, h, object) : std::string();
        auto r = set_attribute_value_unaudited(app, h, object, changes);
        audit_object("set_attribute_value", app, h, object, std::move(label), rv_of(r), t0);
        return r;
    }

private:
    auto set_attribute_value_unaudited(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object,
                                       const attribute_map& changes) -> ck_result<void> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (changes.has(CKA_TOKEN) || changes.has(CKA_PRIVATE)) {
            return unexpected(CKR_ATTRIBUTE_READ_ONLY);
        }
        if (is_session_object(object)) {
            auto o = lookup(*ctx, object);
            if (!o) {
                return unexpected(o.error());
            }
            auto next = set_attributes(o->attributes, changes, ctx->user);
            if (!next) {
                return unexpected(next.error());
            }
            const std::lock_guard lock(_mutex);
            const auto it = _session_objects.find(object);
            if (it == _session_objects.end()) {
                return unexpected(CKR_OBJECT_HANDLE_INVALID);
            }
            it->second.record.attributes = std::move(*next);
            ++it->second.record.version;
            return {};
        }
        if (!ctx->rw) {
            return unexpected(CKR_SESSION_READ_ONLY);
        }
        if (auto r = require_unsealed(); !r) {
            return r;
        }
        const auto entry = _store->token(ctx->token);
        if (!entry) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        for (int attempt = 0; attempt < _opt.handle_attempts; ++attempt) {
            if (attempt > 0) {
                if (auto r = _store->read_barrier(ctx->token); !r) {
                    return unexpected(CKR_DEVICE_ERROR);
                }
            }
            auto o = lookup(*ctx, object);
            if (!o) {
                return unexpected(o.error());
            }
            auto cmd =
                flatten(_vault->with_token_key(*entry, [&](std::span<const std::uint8_t> tk) {
                    return prepare_set_attributes(tk, ctx->token, *o, changes, ctx->user);
                }));
            if (!cmd) {
                return unexpected(cmd.error());
            }
            auto reply = propose(ctx->token, std::move(*cmd));
            if (!reply) {
                return unexpected(reply.error());
            }
            if (reply->rv == CKR_OK) {
                drop_cached(ctx->token, object);
                return {};
            }
            if (reply->rv != CKR_FUNCTION_REJECTED) {
                return unexpected(reply->rv);
            }
        }
        return unexpected(CKR_DEVICE_ERROR);
    }

public:
    /// C_CreateObject: a key, data object or certificate from the caller's
    /// template (object_import.hpp). Secret parts are sealed for a token
    /// object and never kept in the record.
    auto create_object(app_id app, CK_SESSION_HANDLE h, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        const auto t0 = audit_clock::now();
        auto r = create_object_unaudited(app, h, tmpl);
        audit_created("create_object", app, h, r, tmpl, std::nullopt, t0);
        return r;
    }

private:
    auto create_object_unaudited(app_id app, CK_SESSION_HANDLE h, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = require_unsealed(); !r) {
            return unexpected(r.error());
        }
        attribute_map t = tmpl;
        auto cls = t.get_ulong(CKA_CLASS);
        if (!cls) {
            return unexpected(cls.error());
        }
        if (!*cls) {
            return unexpected(CKR_TEMPLATE_INCOMPLETE);
        }
        auto token = check_new_object(*ctx, t, **cls);
        if (!token) {
            return unexpected(token.error());
        }
        if (auto r = check_trusted(t, ctx->user); !r) {
            return unexpected(r.error());
        }
        auto o = build_created_object(t);
        if (!o) {
            return unexpected(o.error());
        }
        return store_new_object(*ctx, std::move(*o), *token);
    }

public:
    /// C_CopyObject: the object with the template's changes, which may only
    /// be CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE, CKA_DESTROYABLE,
    /// CKA_LABEL, CKA_ID, and the one-way CKA_SENSITIVE and
    /// CKA_EXTRACTABLE moves.
    auto copy_object(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object,
                     const attribute_map& tmpl) -> ck_result<CK_OBJECT_HANDLE> {
        const auto t0 = audit_clock::now();
        auto r = copy_object_unaudited(app, h, object, tmpl);
        audit_created("copy_object", app, h, r, tmpl, std::nullopt, t0);
        return r;
    }

private:
    auto copy_object_unaudited(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object,
                               const attribute_map& tmpl) -> ck_result<CK_OBJECT_HANDLE> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = require_unsealed(); !r) {
            return unexpected(r.error());
        }
        auto o = lookup(*ctx, object);
        if (!o) {
            return unexpected(o.error());
        }
        if (!o->attributes.get_bool(CKA_COPYABLE, true).value_or(true)) {
            return unexpected(CKR_ACTION_PROHIBITED);
        }
        const bool data_object =
            o->attributes.get_ulong(CKA_CLASS).value_or(std::nullopt) == CKO_DATA;
        for (const auto& [type, value] : tmpl) {
            switch (type) {
                // A data object's attributes may all be changed (PKCS#11
                // 2.40 table 24), its value on a copy included.
                case CKA_VALUE:
                case CKA_APPLICATION:
                case CKA_OBJECT_ID:
                    if (!data_object) {
                        return unexpected(CKR_ATTRIBUTE_READ_ONLY);
                    }
                    break;
                case CKA_TOKEN:
                case CKA_PRIVATE:
                case CKA_MODIFIABLE:
                case CKA_DESTROYABLE:
                case CKA_LABEL:
                case CKA_ID:
                case CKA_SENSITIVE:
                case CKA_EXTRACTABLE:
                    break;
                default:
                    return unexpected(CKR_ATTRIBUTE_READ_ONLY);
            }
        }
        if (auto r = check_sensitive_change(o->attributes, tmpl); !r) {
            return unexpected(r.error());
        }
        if (auto r = check_extractable_change(o->attributes, tmpl); !r) {
            return unexpected(r.error());
        }
        attribute_map t = o->attributes;
        t.merge(tmpl);
        const auto cls = t.get_ulong(CKA_CLASS).value_or(std::nullopt).value_or(CKO_DATA);
        auto token = check_new_object(*ctx, t, cls);
        if (!token) {
            return unexpected(token.error());
        }
        built_object copy;
        copy.record.public_der = o->public_der;
        if (data_object && t.has(CKA_VALUE)) {
            // The new value is sealed material, as C_CreateObject keeps it.
            const auto v = t.bytes(CKA_VALUE);
            copy.material = v ? secret_bytes(*v) : secret_bytes{};
            t.erase(CKA_VALUE);
            copy.record.attributes = std::move(t);
        } else if (copy.record.attributes = std::move(t); has_material(cls)) {
            auto v = value_of(*ctx, *o);
            if (!v) {
                return unexpected(v.error());
            }
            copy.material = std::move(*v);
        }
        return store_new_object(*ctx, std::move(copy), *token);
    }

public:
    /// C_WrapKey: the key's value or PKCS#8 encrypted under the wrapping
    /// key, after a read-index round and every wrap rule (CKA_WRAP,
    /// CKA_EXTRACTABLE, CKA_WRAP_WITH_TRUSTED, CKA_WRAP_TEMPLATE).
    /// The event names the key wrapped.
    auto wrap_key(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                  CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key) -> ck_result<bytes> {
        const auto t0 = audit_clock::now();
        auto r = wrap_key_unaudited(app, h, mechanism, wrapping_key, key);
        if (_opt.audit) {
            auto e = audit_base("wrap_key", app, h);
            e.object = key;
            e.label = label_of(app, h, key);
            e.mechanism = mechanism.mechanism;
            emit(std::move(e), rv_of(r), t0);
        }
        return r;
    }

private:
    auto wrap_key_unaudited(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                            CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key)
        -> ck_result<bytes> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = mechanism_allows(mechanism, CKF_WRAP); !r) {
            return unexpected(r.error());
        }
        auto w = key_for_use(*ctx, wrapping_key, key_operation::wrap);
        if (!w) {
            return unexpected(w.error() == CKR_KEY_HANDLE_INVALID ? CKR_WRAPPING_KEY_HANDLE_INVALID
                                                                  : w.error());
        }
        // The round above covered this token; a session key needs none.
        auto k = lookup(*ctx, key);
        if (!k) {
            return unexpected(CKR_KEY_HANDLE_INVALID);
        }
        const auto cls = k->attributes.get_ulong(CKA_CLASS).value_or(std::nullopt);
        if (cls != CKO_SECRET_KEY && cls != CKO_PRIVATE_KEY) {
            return unexpected(CKR_KEY_NOT_WRAPPABLE);
        }
        if (auto r = check_wrappable(w->record.attributes, k->attributes); !r) {
            return unexpected(r.error());
        }
        auto value = value_of(*ctx, *k);
        if (!value) {
            return unexpected(value.error());
        }
        return kythira::hsm::wrap(mechanism, *w->key, value->view());
    }

public:
    /// C_UnwrapKey: a new key from wrapped bytes, under the unwrapping
    /// key's CKA_UNWRAP_TEMPLATE.
    auto unwrap_key(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                    CK_OBJECT_HANDLE unwrapping_key, std::span<const std::uint8_t> wrapped,
                    const attribute_map& tmpl) -> ck_result<CK_OBJECT_HANDLE> {
        const auto t0 = audit_clock::now();
        auto r = unwrap_key_unaudited(app, h, mechanism, unwrapping_key, wrapped, tmpl);
        audit_created("unwrap_key", app, h, r, tmpl, mechanism.mechanism, t0);
        return r;
    }

private:
    auto unwrap_key_unaudited(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                              CK_OBJECT_HANDLE unwrapping_key,
                              std::span<const std::uint8_t> wrapped, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = mechanism_allows(mechanism, CKF_UNWRAP); !r) {
            return unexpected(r.error());
        }
        auto u = key_for_use(*ctx, unwrapping_key, key_operation::unwrap);
        if (!u) {
            return unexpected(u.error() == CKR_KEY_HANDLE_INVALID
                                  ? CKR_UNWRAPPING_KEY_HANDLE_INVALID
                                  : u.error());
        }
        auto t = apply_key_template(u->record.attributes, CKA_UNWRAP_TEMPLATE, tmpl);
        if (!t) {
            return unexpected(t.error());
        }
        auto cls = t->get_ulong(CKA_CLASS);
        if (!cls) {
            return unexpected(cls.error());
        }
        if (!*cls) {
            return unexpected(CKR_TEMPLATE_INCOMPLETE);
        }
        auto token = check_new_object(*ctx, *t, **cls);
        if (!token) {
            return unexpected(token.error());
        }
        if (auto r = check_trusted(*t, ctx->user); !r) {
            return unexpected(r.error());
        }
        auto key_bytes = kythira::hsm::unwrap(mechanism, *u->key, wrapped);
        if (!key_bytes) {
            return unexpected(key_bytes.error());
        }
        auto o = build_unwrapped_key(*t, std::move(*key_bytes));
        if (!o) {
            return unexpected(o.error());
        }
        return store_new_object(*ctx, std::move(*o), *token);
    }

public:
    /// C_DeriveKey: a secret key (or, for CKM_HKDF_DATA, a data object)
    /// from the base key, under its CKA_DERIVE_TEMPLATE.
    auto derive_key(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                    CK_OBJECT_HANDLE base_key, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        const auto t0 = audit_clock::now();
        auto r = derive_key_unaudited(app, h, mechanism, base_key, tmpl);
        audit_created("derive_key", app, h, r, tmpl, mechanism.mechanism, t0);
        return r;
    }

private:
    auto derive_key_unaudited(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism,
                              CK_OBJECT_HANDLE base_key, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = mechanism_allows(mechanism, CKF_DERIVE); !r) {
            return unexpected(r.error());
        }
        auto base = key_for_use(*ctx, base_key, key_operation::derive);
        if (!base) {
            return unexpected(base.error());
        }
        auto t = apply_key_template(base->record.attributes, CKA_DERIVE_TEMPLATE, tmpl);
        if (!t) {
            return unexpected(t.error());
        }
        const CK_OBJECT_CLASS want =
            mechanism.mechanism == CKM_HKDF_DATA ? CKO_DATA : CKO_SECRET_KEY;
        auto given = t->get_ulong(CKA_CLASS);
        if (!given) {
            return unexpected(given.error());
        }
        if (*given && **given != want) {
            return unexpected(CKR_TEMPLATE_INCONSISTENT);
        }
        t->set_ulong(CKA_CLASS, want);
        auto token = check_new_object(*ctx, *t, want);
        if (!token) {
            return unexpected(token.error());
        }
        if (auto r = check_trusted(*t, ctx->user); !r) {
            return unexpected(r.error());
        }
        auto len = t->get_ulong(CKA_VALUE_LEN);
        if (!len) {
            return unexpected(len.error());
        }
        auto value = kythira::hsm::derive(mechanism, *base->key, len->value_or(0));
        if (!value) {
            return unexpected(value.error());
        }
        auto o = build_derived_object(*t, std::move(*value), base->record.attributes);
        if (!o) {
            return unexpected(o.error());
        }
        return store_new_object(*ctx, std::move(*o), *token);
    }

public:
    auto find_objects_init(app_id app, CK_SESSION_HANDLE h, const attribute_map& tmpl)
        -> ck_result<void> {
        auto s = session_of(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        const std::lock_guard op((*s)->op_mutex);
        if ((*s)->find) {
            return unexpected(CKR_OPERATION_ACTIVE);
        }
        std::vector<CK_OBJECT_HANDLE> found;
        for (const auto& o : _store->objects(ctx->token)) {
            if (visible(*ctx, o.attributes) && o.attributes.satisfies(tmpl)) {
                found.push_back(static_cast<CK_OBJECT_HANDLE>(o.handle));
            }
        }
        {
            const std::lock_guard lock(_mutex);
            for (const auto& [handle, o] : _session_objects) {
                if (o.app == app && o.token == ctx->token && visible(*ctx, o.record.attributes) &&
                    o.record.attributes.satisfies(tmpl)) {
                    found.push_back(handle);
                }
            }
        }
        (*s)->find = find_state{std::move(found), 0};
        return {};
    }

    auto find_objects(app_id app, CK_SESSION_HANDLE h, std::size_t max)
        -> ck_result<std::vector<CK_OBJECT_HANDLE>> {
        auto s = session_of(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        const std::lock_guard op((*s)->op_mutex);
        if (!(*s)->find) {
            return unexpected(CKR_OPERATION_NOT_INITIALIZED);
        }
        auto& f = *(*s)->find;
        const std::size_t n = std::min(max, f.handles.size() - f.next);
        std::vector<CK_OBJECT_HANDLE> out(
            f.handles.begin() + static_cast<std::ptrdiff_t>(f.next),
            f.handles.begin() + static_cast<std::ptrdiff_t>(f.next + n));
        f.next += n;
        return out;
    }

    auto find_objects_final(app_id app, CK_SESSION_HANDLE h) -> ck_result<void> {
        auto s = session_of(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        const std::lock_guard op((*s)->op_mutex);
        if (!(*s)->find) {
            return unexpected(CKR_OPERATION_NOT_INITIALIZED);
        }
        (*s)->find.reset();
        return {};
    }

    /// C_SessionCancel: ends the session's active operations that `flags`
    /// names (CKF_SIGN, CKF_VERIFY, CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST,
    /// CKF_FIND_OBJECTS), wiping any input they buffered. Naming one that is
    /// not active is not an error.
    auto session_cancel(app_id app, CK_SESSION_HANDLE h, CK_FLAGS flags) -> ck_result<void> {
        auto s = session_of(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        const std::lock_guard op((*s)->op_mutex);
        for (const auto kind : {op_kind::sign, op_kind::verify, op_kind::encrypt, op_kind::decrypt,
                                op_kind::digest}) {
            if ((flags & flag_of(kind)) != 0) {
                (*s)->ops[static_cast<std::size_t>(kind)].reset();
            }
        }
        if ((flags & CKF_FIND_OBJECTS) != 0) {
            (*s)->find.reset();
        }
        return {};
    }

    // -- Cryptographic operations --------------------------------------------

    enum class op_kind : std::uint8_t {
        sign,
        verify,
        encrypt,
        decrypt,
        digest
    };

    /// C_SignInit, C_VerifyInit, C_EncryptInit, C_DecryptInit: the key must
    /// exist, be visible and allow the operation now; it is checked again
    /// when the operation runs. Counted per client, token, key and kind,
    /// and sampled into the audit log (audit.hpp).
    auto operation_init(app_id app, CK_SESSION_HANDLE h, op_kind kind,
                        const CK_MECHANISM& mechanism, CK_OBJECT_HANDLE key) -> ck_result<void> {
        const auto t0 = audit_clock::now();
        auto r = operation_init_unaudited(app, h, kind, mechanism, key);
        if (_opt.audit && kind != op_kind::digest) {
            audit_counted(app, h, kind, mechanism.mechanism, key, rv_of(r), t0);
        }
        return r;
    }

private:
    auto operation_init_unaudited(app_id app, CK_SESSION_HANDLE h, op_kind kind,
                                  const CK_MECHANISM& mechanism, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        auto s = session_of(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        if (auto r = require_unsealed(); !r) {
            return r;
        }
        auto m = mechanism_copy::from(mechanism);
        if (!m) {
            return unexpected(m.error());
        }
        const auto info = mechanism_info(mechanism.mechanism);
        if (!info) {
            return unexpected(info.error());
        }
        if ((info->flags & flag_of(kind)) == 0) {
            return unexpected(CKR_MECHANISM_INVALID);
        }
        if (kind != op_kind::digest) {
            auto o = lookup(*ctx, key);
            if (!o) {
                return unexpected(o.error() == CKR_OBJECT_HANDLE_INVALID ? CKR_KEY_HANDLE_INVALID
                                                                         : o.error());
            }
            if (auto r = check_usage(o->attributes, usage_of(kind)); !r) {
                return r;
            }
        }
        const std::lock_guard op((*s)->op_mutex);
        auto& slot = (*s)->ops[static_cast<std::size_t>(kind)];
        if (slot) {
            return unexpected(CKR_OPERATION_ACTIVE);
        }
        slot.emplace(operation{std::move(*m), key, {}, false});
        return {};
    }

public:
    auto digest_init(app_id app, CK_SESSION_HANDLE h, const CK_MECHANISM& mechanism)
        -> ck_result<void> {
        return operation_init(app, h, op_kind::digest, mechanism, CK_INVALID_HANDLE);
    }

    /// C_*Update: buffers `data` for the final call.
    auto operation_update(app_id app, CK_SESSION_HANDLE h, op_kind kind,
                          std::span<const std::uint8_t> data) -> ck_result<void> {
        auto s = session_of(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        const std::lock_guard op((*s)->op_mutex);
        auto& slot = (*s)->ops[static_cast<std::size_t>(kind)];
        if (!slot) {
            return unexpected(CKR_OPERATION_NOT_INITIALIZED);
        }
        if (slot->data.size() + data.size() > _opt.max_operation_bytes) {
            slot.reset();
            return unexpected(CKR_DATA_LEN_RANGE);
        }
        slot->multi_part = true;
        slot->data.insert(slot->data.end(), data.begin(), data.end());
        return {};
    }

    auto sign(app_id app, CK_SESSION_HANDLE h, std::span<const std::uint8_t> data)
        -> ck_result<bytes> {
        return run<bytes>(
            app, h, op_kind::sign, data, true,
            [](const CK_MECHANISM& m, const key_material* k, std::span<const std::uint8_t> in) {
                return kythira::hsm::sign(m, *k, in);
            });
    }

    auto sign_final(app_id app, CK_SESSION_HANDLE h) -> ck_result<bytes> {
        return run<bytes>(
            app, h, op_kind::sign, {}, false,
            [](const CK_MECHANISM& m, const key_material* k, std::span<const std::uint8_t> in) {
                return kythira::hsm::sign(m, *k, in);
            });
    }

    auto verify(app_id app, CK_SESSION_HANDLE h, std::span<const std::uint8_t> data,
                std::span<const std::uint8_t> signature) -> ck_result<void> {
        return run<void>(
            app, h, op_kind::verify, data, true,
            [&](const CK_MECHANISM& m, const key_material* k, std::span<const std::uint8_t> in) {
                return kythira::hsm::verify(m, *k, in, signature);
            });
    }

    auto verify_final(app_id app, CK_SESSION_HANDLE h, std::span<const std::uint8_t> signature)
        -> ck_result<void> {
        return run<void>(
            app, h, op_kind::verify, {}, false,
            [&](const CK_MECHANISM& m, const key_material* k, std::span<const std::uint8_t> in) {
                return kythira::hsm::verify(m, *k, in, signature);
            });
    }

    auto encrypt(app_id app, CK_SESSION_HANDLE h, std::span<const std::uint8_t> data)
        -> ck_result<bytes> {
        return run<bytes>(app, h, op_kind::encrypt, data, true, encrypt_fn);
    }

    auto encrypt_final(app_id app, CK_SESSION_HANDLE h) -> ck_result<bytes> {
        return run<bytes>(app, h, op_kind::encrypt, {}, false, encrypt_fn);
    }

    auto decrypt(app_id app, CK_SESSION_HANDLE h, std::span<const std::uint8_t> data)
        -> ck_result<secret_bytes> {
        return run<secret_bytes>(app, h, op_kind::decrypt, data, true, decrypt_fn);
    }

    auto decrypt_final(app_id app, CK_SESSION_HANDLE h) -> ck_result<secret_bytes> {
        return run<secret_bytes>(app, h, op_kind::decrypt, {}, false, decrypt_fn);
    }

    auto digest(app_id app, CK_SESSION_HANDLE h, std::span<const std::uint8_t> data)
        -> ck_result<bytes> {
        return run<bytes>(app, h, op_kind::digest, data, true, digest_fn);
    }

    auto digest_final(app_id app, CK_SESSION_HANDLE h) -> ck_result<bytes> {
        return run<bytes>(app, h, op_kind::digest, {}, false, digest_fn);
    }

    auto generate_random(app_id app, CK_SESSION_HANDLE h, std::size_t length) -> ck_result<bytes> {
        if (auto s = session_of(app, h); !s) {
            return unexpected(s.error());
        }
        if (auto r = require_unsealed(); !r) {
            return unexpected(r.error());
        }
        bytes out(length);
        if (auto r = kythira::hsm::generate_random(out); !r) {
            return unexpected(r.error());
        }
        return out;
    }

    // -- For tests and metrics -----------------------------------------------

    [[nodiscard]] auto cached_keys() const -> std::size_t {
        const std::lock_guard lock(_cache_mutex);
        return _cache.size();
    }

private:
    using secure_buffer = std::vector<std::uint8_t, secure_allocator<std::uint8_t>>;
    using audit_clock = std::chrono::steady_clock;

    template<typename T> [[nodiscard]] static auto rv_of(const ck_result<T>& r) -> CK_RV {
        return r ? CKR_OK : r.error();
    }

    [[nodiscard]] static auto label_in(const attribute_map& t) -> std::string {
        const auto v = t.bytes(CKA_LABEL);
        return v ? std::string(v->begin(), v->end()) : std::string();
    }

    /// An object's label as `app` sees it through `h`; empty when it has
    /// none or cannot be read.
    [[nodiscard]] auto label_of(app_id app, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE object) const
        -> std::string {
        const auto ctx = context(app, h);
        if (!ctx) {
            return {};
        }
        const auto o = lookup(*ctx, object);
        return o ? label_in(o->attributes) : std::string();
    }

    /// An event for a call through session `h`, naming its token when the
    /// session exists.
    [[nodiscard]] auto audit_base(std::string_view action, app_id app, CK_SESSION_HANDLE h) const
        -> audit_event {
        audit_event e;
        e.action = action;
        e.identity = identity_of(app).value_or("");
        const std::lock_guard lock(_mutex);
        if (const auto it = _sessions.find(h); it != _sessions.end() && it->second->app == app) {
            e.token = it->second->token;
        }
        return e;
    }

    void emit(audit_event e, CK_RV rv, audit_clock::time_point started) const {
        e.rv = rv;
        e.elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(audit_clock::now() - started);
        _opt.audit(e);
    }

    void audit_object(std::string_view action, app_id app, CK_SESSION_HANDLE h,
                      CK_OBJECT_HANDLE object, std::string label, CK_RV rv,
                      audit_clock::time_point started) const {
        if (!_opt.audit) {
            return;
        }
        auto e = audit_base(action, app, h);
        e.object = object;
        e.label = std::move(label);
        emit(std::move(e), rv, started);
    }

    void audit_created(std::string_view action, app_id app, CK_SESSION_HANDLE h,
                       const ck_result<CK_OBJECT_HANDLE>& r, const attribute_map& tmpl,
                       std::optional<CK_MECHANISM_TYPE> mechanism,
                       audit_clock::time_point started) const {
        if (!_opt.audit) {
            return;
        }
        auto e = audit_base(action, app, h);
        if (r) {
            e.object = *r;
        }
        e.label = label_in(tmpl);
        e.mechanism = mechanism;
        emit(std::move(e), rv_of(r), started);
    }

    /// Counts an operation's start; logs the first call, then one in
    /// audit_sample_every with the calls since the last, and every refusal.
    void audit_counted(app_id app, CK_SESSION_HANDLE h, op_kind kind, CK_MECHANISM_TYPE mechanism,
                       CK_OBJECT_HANDLE key, CK_RV rv, audit_clock::time_point started) {
        static constexpr std::array<std::string_view, 5> names{"sign", "verify", "encrypt",
                                                               "decrypt", "digest"};
        auto e = audit_base(names.at(static_cast<std::size_t>(kind)), app, h);
        e.object = key;
        e.mechanism = mechanism;
        if (rv == CKR_OK) {
            const std::lock_guard lock(_audit_mutex);
            if (_op_counts.size() >= max_op_counts) {
                _op_counts.clear();  // forget keys long destroyed; counts restart
            }
            auto& c = _op_counts[{e.identity, e.token.value_or(0), key, kind}];
            ++c.calls;
            const auto every = std::max<std::uint64_t>(_opt.audit_sample_every, 1);
            e.logged = c.calls == 1 || c.calls % every == 0;
            if (e.logged) {
                e.calls = c.calls - c.logged;
                c.logged = c.calls;
            } else {
                e.calls = 1;
            }
        }
        if (e.logged) {
            e.label = label_of(app, h, key);
        }
        emit(std::move(e), rv, started);
    }

    struct op_count {
        std::uint64_t calls = 0;
        std::uint64_t logged = 0;  // calls already reported
    };
    static constexpr std::size_t max_op_counts = 65536;

    struct operation {
        mechanism_copy mechanism;
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        secure_buffer data;
        bool multi_part = false;
    };

    struct find_state {
        std::vector<CK_OBJECT_HANDLE> handles;
        std::size_t next = 0;
    };

    struct session {
        CK_SESSION_HANDLE handle = 0;
        app_id app = 0;
        std::uint64_t token = 0;
        bool rw = false;
        std::mutex op_mutex;
        std::array<std::optional<operation>, 5> ops;
        std::optional<find_state> find;
    };

    struct session_object {
        app_id app = 0;
        std::uint64_t token = 0;
        CK_SESSION_HANDLE creator = 0;
        object_record record;
        std::shared_ptr<const key_material> key;
    };

    /// What a call knows about its session, read once under the lock.
    struct call_context {
        app_id app = 0;
        CK_SESSION_HANDLE session = 0;
        std::uint64_t token = 0;
        bool rw = false;
        session_user user = session_user::none;
    };

    struct cached_key {
        std::uint64_t version = 0;
        std::uint64_t epoch = 0;
        std::vector<std::uint8_t> source;
        std::shared_ptr<const key_material> key;
    };

    static constexpr auto encrypt_fn = [](const CK_MECHANISM& m, const key_material* k,
                                          std::span<const std::uint8_t> in) {
        return kythira::hsm::encrypt(m, *k, in);
    };
    static constexpr auto decrypt_fn = [](const CK_MECHANISM& m, const key_material* k,
                                          std::span<const std::uint8_t> in) {
        return kythira::hsm::decrypt(m, *k, in);
    };
    static constexpr auto digest_fn = [](const CK_MECHANISM& m, const key_material* /*k*/,
                                         std::span<const std::uint8_t> in) {
        return kythira::hsm::digest(m, in);
    };

    [[nodiscard]] static constexpr auto usage_of(op_kind kind) noexcept -> key_operation {
        switch (kind) {
            case op_kind::sign:
                return key_operation::sign;
            case op_kind::verify:
                return key_operation::verify;
            case op_kind::encrypt:
                return key_operation::encrypt;
            case op_kind::decrypt:
            case op_kind::digest:
                break;
        }
        return key_operation::decrypt;
    }

    [[nodiscard]] static constexpr auto flag_of(op_kind kind) noexcept -> CK_FLAGS {
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
                break;
        }
        return CKF_DIGEST;
    }

    [[nodiscard]] static auto is_session_object(CK_OBJECT_HANDLE h) noexcept -> bool {
        return h >= first_session_object_handle;
    }

    template<typename T>
    [[nodiscard]] static auto flatten(ck_result<ck_result<T>> r) -> ck_result<T> {
        if (!r) {
            return unexpected(r.error());
        }
        return std::move(*r);
    }

    [[nodiscard]] static auto trim_label(std::string_view label) -> std::string {
        while (!label.empty() && (label.back() == ' ' || label.back() == '\0')) {
            label.remove_suffix(1);
        }
        return std::string(label.substr(0, 32));
    }

    [[nodiscard]] static auto check_pin_length(std::string_view pin) -> ck_result<void> {
        if (pin.size() < min_pin_length || pin.size() > max_pin_length) {
            return unexpected(CKR_PIN_LEN_RANGE);
        }
        return {};
    }

    [[nodiscard]] auto identity_of(app_id app) const -> std::optional<std::string> {
        const std::lock_guard lock(_mutex);
        const auto it = _apps.find(app);
        return it == _apps.end() ? std::nullopt : std::optional<std::string>(it->second);
    }

    [[nodiscard]] auto check_slot(app_id app, CK_SLOT_ID slot) const -> ck_result<void> {
        const auto identity = identity_of(app);
        if (!identity) {
            return unexpected(CKR_CRYPTOKI_NOT_INITIALIZED);
        }
        if (!_store->token(slot) || !_store->may_open(*identity, slot)) {
            return unexpected(CKR_TOKEN_NOT_PRESENT);
        }
        return {};
    }

    /// The node is unsealed and the mechanism can do `flag`.
    [[nodiscard]] auto mechanism_allows(const CK_MECHANISM& m, CK_FLAGS flag) const
        -> ck_result<void> {
        if (auto r = require_unsealed(); !r) {
            return r;
        }
        const auto info = mechanism_info(m.mechanism);
        if (!info) {
            return unexpected(info.error());
        }
        if ((info->flags & flag) == 0) {
            return unexpected(CKR_MECHANISM_INVALID);
        }
        return {};
    }

    [[nodiscard]] auto require_unsealed() const -> ck_result<void> {
        if (_vault->sealed()) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        return {};
    }

    [[nodiscard]] auto login_locked(app_id app, std::uint64_t token) const -> session_user {
        const auto it = _logins.find({app, token});
        return it == _logins.end() ? session_user::none : it->second;
    }

    [[nodiscard]] auto find_locked(app_id app, CK_SESSION_HANDLE h) const
        -> ck_result<std::shared_ptr<session>> {
        const auto it = _sessions.find(h);
        if (it == _sessions.end() || it->second->app != app) {
            return unexpected(CKR_SESSION_HANDLE_INVALID);
        }
        return it->second;
    }

    [[nodiscard]] auto session_of(app_id app, CK_SESSION_HANDLE h) const
        -> ck_result<std::shared_ptr<session>> {
        const std::lock_guard lock(_mutex);
        return find_locked(app, h);
    }

    [[nodiscard]] auto context(app_id app, CK_SESSION_HANDLE h) const -> ck_result<call_context> {
        const std::lock_guard lock(_mutex);
        auto s = find_locked(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        return call_context{app, h, (*s)->token, (*s)->rw, login_locked(app, (*s)->token)};
    }

    /// Closes `h`: its session objects go, and the application is logged
    /// out of the token when this was its last session there.
    auto close_locked(CK_SESSION_HANDLE h) -> void {
        const auto it = _sessions.find(h);
        if (it == _sessions.end()) {
            return;
        }
        const auto app = it->second->app;
        const auto token = it->second->token;
        _sessions.erase(it);
        std::erase_if(_session_objects, [&](const auto& kv) { return kv.second.creator == h; });
        const bool last = std::ranges::none_of(_sessions, [&](const auto& kv) {
            return kv.second->app == app && kv.second->token == token;
        });
        if (last) {
            _logins.erase({app, token});
        }
    }

    /// A private object is visible only to a session logged in as the user.
    [[nodiscard]] static auto visible(const call_context& ctx, const attribute_map& attrs) -> bool {
        return !attrs.flag(CKA_PRIVATE) || ctx.user == session_user::user;
    }

    /// The object as this replica (or this node, for a session object) has
    /// it, if the session may see it.
    [[nodiscard]] auto lookup(const call_context& ctx, CK_OBJECT_HANDLE h) const
        -> ck_result<object_record> {
        if (is_session_object(h)) {
            const std::lock_guard lock(_mutex);
            const auto it = _session_objects.find(h);
            if (it == _session_objects.end() || it->second.app != ctx.app ||
                it->second.token != ctx.token || !visible(ctx, it->second.record.attributes)) {
                return unexpected(CKR_OBJECT_HANDLE_INVALID);
            }
            return it->second.record;
        }
        if (h == CK_INVALID_HANDLE || h > max_token_object_handle) {
            return unexpected(CKR_OBJECT_HANDLE_INVALID);
        }
        auto o = _store->object(ctx.token, h);
        if (!o || !visible(ctx, o->attributes)) {
            return unexpected(CKR_OBJECT_HANDLE_INVALID);
        }
        return *o;
    }

    /// CKA_CLASS, when the caller gives it, must be the one the call makes.
    [[nodiscard]] static auto expect_class(attribute_map& t, CK_OBJECT_CLASS cls)
        -> ck_result<void> {
        auto given = t.get_ulong(CKA_CLASS);
        if (!given) {
            return unexpected(given.error());
        }
        if (*given && **given != cls) {
            return unexpected(CKR_TEMPLATE_INCONSISTENT);
        }
        t.erase(CKA_CLASS);
        return {};
    }

    /// The defaults and session rules for a new object: CKA_PRIVATE is true
    /// for secret and private keys (false for anything else) unless the
    /// caller says otherwise, a
    /// private object needs the user logged in, and a token object needs a
    /// read-write session. Answers whether it is a token object.
    [[nodiscard]] static auto check_new_object(const call_context& ctx, attribute_map& t,
                                               CK_OBJECT_CLASS cls) -> ck_result<bool> {
        auto priv = t.get_bool(CKA_PRIVATE, cls == CKO_SECRET_KEY || cls == CKO_PRIVATE_KEY);
        auto token = t.get_bool(CKA_TOKEN, false);
        if (!priv || !token) {
            return unexpected(!priv ? priv.error() : token.error());
        }
        t.set_bool(CKA_PRIVATE, *priv);
        t.set_bool(CKA_TOKEN, *token);
        if (*priv && ctx.user != session_user::user) {
            return unexpected(CKR_USER_NOT_LOGGED_IN);
        }
        if (*token && !ctx.rw) {
            return unexpected(CKR_SESSION_READ_ONLY);
        }
        return *token;
    }

    auto next_session_object() -> CK_OBJECT_HANDLE {
        const std::lock_guard lock(_mutex);
        return first_session_object_handle + _next_session_object++;
    }

    auto add_session_object(const call_context& ctx, object_record record, secret_bytes material)
        -> CK_OBJECT_HANDLE {
        auto key = std::make_shared<key_material>();
        key->object_class =
            record.attributes.get_ulong(CKA_CLASS).value_or(std::nullopt).value_or(CKO_SECRET_KEY);
        key->key_type = record.attributes.get_ulong(CKA_KEY_TYPE)
                            .value_or(std::nullopt)
                            .value_or(CKK_GENERIC_SECRET);
        key->secret = std::move(material);
        key->public_der = record.public_der;
        record.version = 1;
        const auto handle = static_cast<CK_OBJECT_HANDLE>(record.handle);
        const std::lock_guard lock(_mutex);
        _session_objects.emplace(handle, session_object{ctx.app, ctx.token, ctx.session,
                                                        std::move(record), std::move(key)});
        return handle;
    }

    [[nodiscard]] auto new_verifier(std::string_view pin) const -> ck_result<pin_verifier> {
        try {
            return make_pin_verifier(pin, _opt.pin_log2_n);
        } catch (const std::exception&) {
            return unexpected(CKR_DEVICE_ERROR);
        }
    }

    auto propose(std::uint64_t token, std::vector<std::byte> command) -> ck_result<token_reply> {
        auto reply = _store->propose_token(token, std::move(command));
        if (!reply) {
            return unexpected(reply.error());
        }
        try {
            return token_reply::decode(*reply);
        } catch (const std::exception&) {
            return unexpected(CKR_DEVICE_ERROR);
        }
    }

    /// Checks `pin` against this replica's verifier and records the outcome
    /// in the token's group, which decides (in log order) whether the PIN
    /// is locked.
    auto verify_pin(std::uint64_t token, pin_user who, std::string_view pin) -> ck_result<void> {
        // The verifier and the lock as the group has them now: a PIN
        // changed or locked through another member must not be checked
        // against this replica's older copy.
        if (auto b = _store->read_barrier(token); !b) {
            return unexpected(b.error());
        }
        auto rec = _store->token_record_of(token);
        if (!rec) {
            return unexpected(CKR_TOKEN_NOT_RECOGNIZED);
        }
        const auto& verifier = who == pin_user::so ? rec->so_pin : rec->user_pin;
        if (!verifier) {
            return unexpected(who == pin_user::user ? CKR_USER_PIN_NOT_INITIALIZED
                                                    : CKR_PIN_INCORRECT);
        }
        if (rec->locked(who)) {
            return unexpected(CKR_PIN_LOCKED);
        }
        const bool ok = check_pin(*verifier, pin);
        auto reply = propose(token, make_login_result_command(who, ok));
        if (!reply) {
            return unexpected(reply.error());
        }
        if (reply->rv != CKR_OK) {
            return unexpected(reply->rv);
        }
        return {};
    }

    auto store_pin(std::uint64_t token, pin_user who, std::string_view pin) -> ck_result<void> {
        auto verifier = new_verifier(pin);
        if (!verifier) {
            return unexpected(verifier.error());
        }
        auto reply = propose(token, make_set_pin_command(who, *verifier));
        if (!reply) {
            return unexpected(reply.error());
        }
        if (reply->rv != CKR_OK) {
            return unexpected(reply->rv);
        }
        return {};
    }

    /// The key material of `o`, opened (and cached) if it is a token
    /// object. No barrier or usage check: callers do those.
    auto material(const call_context& ctx, const object_record& o)
        -> ck_result<std::shared_ptr<const key_material>> {
        if (is_session_object(o.handle)) {
            const std::lock_guard lock(_mutex);
            const auto it = _session_objects.find(o.handle);
            if (it == _session_objects.end() || !it->second.key) {
                return unexpected(CKR_OBJECT_HANDLE_INVALID);
            }
            return it->second.key;
        }
        const auto& source = o.sealed.empty() ? o.public_der : o.sealed;
        const auto epoch = _vault->epoch();
        {
            const std::lock_guard lock(_cache_mutex);
            const auto it = _cache.find({ctx.token, o.handle});
            if (it != _cache.end() && it->second.version == o.version &&
                it->second.epoch == epoch && it->second.source == source) {
                return it->second.key;
            }
        }
        const auto entry = _store->token(ctx.token);
        if (!entry) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        auto k = flatten(_vault->with_token_key(*entry, [&](std::span<const std::uint8_t> tk) {
            return key_material_of(tk, ctx.token, o);
        }));
        if (!k) {
            return unexpected(k.error());
        }
        auto shared = std::make_shared<const key_material>(std::move(*k));
        const std::lock_guard lock(_cache_mutex);
        if (_cache.size() >= _opt.max_cached_keys) {
            _cache.clear();
        }
        _cache.insert_or_assign(std::pair{ctx.token, o.handle},
                                cached_key{o.version, epoch, source, shared});
        return shared;
    }

    /// The key an operation is about to use, checked as of now: for a
    /// token object, after a read-index round (requirement 3.4, 3.5).
    struct key_in_use {
        object_record record;
        std::shared_ptr<const key_material> key;
    };

    auto key_for_use(const call_context& ctx, CK_OBJECT_HANDLE h, key_operation op)
        -> ck_result<key_in_use> {
        if (auto r = require_unsealed(); !r) {
            return unexpected(r.error());
        }
        if (!is_session_object(h)) {
            if (auto r = _store->read_barrier(ctx.token); !r) {
                return unexpected(CKR_DEVICE_ERROR);
            }
        }
        auto o = lookup(ctx, h);
        if (!o) {
            drop_cached(ctx.token, h);
            return unexpected(CKR_KEY_HANDLE_INVALID);
        }
        if (auto r = check_usage(o->attributes, op); !r) {
            return unexpected(r.error());
        }
        auto k = material(ctx, *o);
        if (!k) {
            return unexpected(k.error());
        }
        return key_in_use{std::move(*o), std::move(*k)};
    }

    /// The secret part of `o` (a secret key's value, a private key's
    /// PKCS#8, a data object's value), copied. No barrier or usage check.
    auto value_of(const call_context& ctx, const object_record& o) -> ck_result<secret_bytes> {
        if (is_session_object(o.handle)) {
            const std::lock_guard lock(_mutex);
            const auto it = _session_objects.find(o.handle);
            if (it == _session_objects.end() || !it->second.key) {
                return unexpected(CKR_OBJECT_HANDLE_INVALID);
            }
            return it->second.key->secret.clone();
        }
        if (o.sealed.empty()) {
            return secret_bytes{};
        }
        const auto entry = _store->token(ctx.token);
        if (!entry) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        auto v = _vault->with_token_key(*entry, [&](std::span<const std::uint8_t> tk) {
            return open_object(tk, ctx.token, o);
        });
        if (!v || !*v) {
            return unexpected(CKR_DEVICE_ERROR);  // sealed, or a bad tag
        }
        return std::move(**v);
    }

    /// Stores a new object: a session object in memory, or a token object
    /// sealed under a fresh random handle and proposed, with another
    /// handle tried if that one is taken.
    auto store_new_object(const call_context& ctx, built_object o, bool token)
        -> ck_result<CK_OBJECT_HANDLE> {
        o.record.attributes.set_bool(CKA_TOKEN, token);
        if (!token) {
            o.record.handle = next_session_object();
            return add_session_object(ctx, std::move(o.record), std::move(o.material));
        }
        const auto entry = _store->token(ctx.token);
        if (!entry) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        const auto cls = o.record.attributes.get_ulong(CKA_CLASS).value_or(std::nullopt);
        for (int attempt = 0; attempt < _opt.handle_attempts; ++attempt) {
            o.record.handle = random_object_handle();
            if (cls && has_material(*cls)) {
                auto sealed = _vault->with_token_key(*entry, [&](std::span<const std::uint8_t> tk) {
                    seal_object(tk, ctx.token, o);
                    return true;
                });
                if (!sealed) {
                    return unexpected(sealed.error());
                }
            }
            auto reply = propose(ctx.token, make_create_objects_command({o.record}));
            if (!reply) {
                return unexpected(reply.error());
            }
            if (reply->rv == CKR_OK) {
                return static_cast<CK_OBJECT_HANDLE>(o.record.handle);
            }
            if (reply->rv != CKR_FUNCTION_REJECTED) {
                return unexpected(reply->rv);
            }
        }
        return unexpected(CKR_DEVICE_ERROR);
    }

    auto drop_cached(std::uint64_t token, std::uint64_t handle) -> void {
        const std::lock_guard lock(_cache_mutex);
        _cache.erase({token, handle});
    }

    auto drop_cached_token(std::uint64_t token) -> void {
        const std::lock_guard lock(_cache_mutex);
        std::erase_if(_cache, [&](const auto& kv) { return kv.first.first == token; });
    }

    /// The single-part call (`single`, with `data`) or the final call of a
    /// multi-part operation: runs `fn` on the buffered input with the key
    /// as of now, and ends the operation whatever the outcome.
    template<typename R, typename Fn>
    auto run(app_id app, CK_SESSION_HANDLE h, op_kind kind, std::span<const std::uint8_t> data,
             bool single, Fn&& fn) -> ck_result<R> {
        auto s = session_of(app, h);
        if (!s) {
            return unexpected(s.error());
        }
        const std::lock_guard op((*s)->op_mutex);
        auto& slot = (*s)->ops[static_cast<std::size_t>(kind)];
        if (!slot) {
            return unexpected(CKR_OPERATION_NOT_INITIALIZED);
        }
        auto current = std::move(*slot);
        slot.reset();
        if (single && current.multi_part) {
            return unexpected(CKR_OPERATION_ACTIVE);
        }
        if (single) {
            current.data.assign(data.begin(), data.end());
        }
        auto ctx = context(app, h);
        if (!ctx) {
            return unexpected(ctx.error());
        }
        std::shared_ptr<const key_material> key;
        if (kind != op_kind::digest) {
            auto k = key_for_use(*ctx, current.key, usage_of(kind));
            if (!k) {
                return unexpected(k.error());
            }
            key = std::move(k->key);
        } else if (auto r = require_unsealed(); !r) {
            return unexpected(r.error());
        }
        const auto m = current.mechanism.get();
        return fn(m, key.get(), std::span<const std::uint8_t>(current.data));
    }

    hsm_store* _store;
    key_vault* _vault;
    session_options _opt;

    mutable std::mutex _mutex;
    app_id _next_app{0};
    CK_SESSION_HANDLE _next_session{0};
    CK_OBJECT_HANDLE _next_session_object{0};
    std::map<app_id, std::string> _apps;
    std::map<CK_SESSION_HANDLE, std::shared_ptr<session>> _sessions;
    std::map<std::pair<app_id, std::uint64_t>, session_user> _logins;
    std::map<CK_OBJECT_HANDLE, session_object> _session_objects;

    mutable std::mutex _cache_mutex;
    std::map<std::pair<std::uint64_t, std::uint64_t>, cached_key> _cache;

    std::mutex _audit_mutex;
    std::map<std::tuple<std::string, std::uint64_t, CK_OBJECT_HANDLE, op_kind>, op_count>
        _op_counts;
};

}  // namespace kythira::hsm
