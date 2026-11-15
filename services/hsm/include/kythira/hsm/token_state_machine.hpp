// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// One token's Raft group (requirement 3.1): its metadata, PIN verifiers,
// login counters and objects, on the persistent state machine.
//
// Nothing secret is ever in a command or a record: object material arrives
// already sealed under the token key by the leader (key_store.hpp), and PINs
// arrive as scrypt verifiers. Replicas store exactly the bytes in the entry,
// so they stay identical without generating anything (requirement 3.3).
//
// Layout under the group's namespace `ns`:
//   data  ns "t"                 token record
//   data  ns "o" be64(handle)    object record
//   meta  ns                     applied index
//
// The state machine enforces what must hold on every replica: a handle is
// created once, updates and destroys name the version they read (so a
// read-modify-write that raced another change is refused rather than
// silently overwriting it), and objects exist only on an initialized token.
// PKCS#11 attribute rules are checked by the leader before it proposes
// (attribute_policy.hpp); the PIN check happens on the serving node, and
// only its outcome is replicated, so failures count across the cluster
// (requirement 7.2).
//
// Replies are a CK_RV (u32) followed by the command's result fields.
// CKR_FUNCTION_REJECTED means "conflict, read again and retry": a taken
// handle or a stale version.

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/codec.hpp>
#include <kythira/hsm/persistent_group.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/sealing.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/persistent_state_machine.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::hsm {

enum class pin_user : std::uint8_t {
    so = 1,
    user = 2
};

inline constexpr std::uint32_t default_max_login_failures = 10;

/// Token object handles are in [1, 2^31): session objects (task 6) take the
/// upper half, and 32-bit PKCS#11 clients see every handle intact.
inline constexpr std::uint64_t max_token_object_handle = (std::uint64_t{1} << 31U) - 1;

struct token_record {
    std::string label;
    std::optional<pin_verifier> so_pin;
    std::optional<pin_verifier> user_pin;
    std::uint32_t so_failures = 0;
    std::uint32_t user_failures = 0;
    std::uint32_t max_failures = default_max_login_failures;

    [[nodiscard]] auto failures(pin_user who) const -> std::uint32_t {
        return who == pin_user::so ? so_failures : user_failures;
    }
    [[nodiscard]] auto locked(pin_user who) const -> bool { return failures(who) >= max_failures; }

    /// The CKF_*_PIN_* flags C_GetTokenInfo reports.
    [[nodiscard]] auto pin_flags() const -> CK_FLAGS {
        CK_FLAGS f = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_RNG;
        if (user_pin.has_value()) {
            f |= CKF_USER_PIN_INITIALIZED;
        }
        auto add = [&](std::uint32_t n, CK_FLAGS low, CK_FLAGS final_try, CK_FLAGS lock) {
            if (n >= max_failures) {
                f |= lock;
            } else if (n + 1 == max_failures) {
                f |= final_try | low;
            } else if (n > 0) {
                f |= low;
            }
        };
        add(user_failures, CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED);
        add(so_failures, CKF_SO_PIN_COUNT_LOW, CKF_SO_PIN_FINAL_TRY, CKF_SO_PIN_LOCKED);
        return f;
    }

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1).str(label);
        auto pin = [&](const std::optional<pin_verifier>& v) {
            w.bytes(v.has_value() ? v->encode() : std::vector<std::uint8_t>{});
        };
        pin(so_pin);
        pin(user_pin);
        w.u32(so_failures).u32(user_failures).u32(max_failures);
        return w.take_string();
    }

    [[nodiscard]] static auto decode(std::string_view in) -> token_record {
        byte_reader r(in);
        if (r.u8() != 1) {
            throw std::invalid_argument("token record: unknown version");
        }
        token_record t;
        t.label = r.str();
        auto pin = [&]() -> std::optional<pin_verifier> {
            auto b = r.bytes();
            if (b.empty()) {
                return std::nullopt;
            }
            auto v = pin_verifier::decode(b);
            if (!v) {
                throw std::invalid_argument("token record: bad PIN verifier");
            }
            return v;
        };
        t.so_pin = pin();
        t.user_pin = pin();
        t.so_failures = r.u32();
        t.user_failures = r.u32();
        t.max_failures = r.u32();
        r.finish();
        return t;
    }
};

struct object_record {
    std::uint64_t handle = 0;
    std::uint64_t version = 0;
    attribute_map attributes;
    /// SubjectPublicKeyInfo DER for public and private keys; empty otherwise.
    std::vector<std::uint8_t> public_der;
    /// Secret or private key material sealed under the TK with
    /// object_ad(token, handle, attributes); empty for public objects.
    sealed_bytes sealed;

    auto encode_to(byte_writer& w) const -> void {
        w.u64(handle).u64(version).bytes(attributes.encode()).bytes(public_der).bytes(sealed);
    }

    [[nodiscard]] static auto decode_from(byte_reader& r) -> object_record {
        object_record o;
        o.handle = r.u64();
        o.version = r.u64();
        auto attrs = attribute_map::decode(r.bytes());
        if (!attrs) {
            throw std::invalid_argument("object record: bad attributes");
        }
        o.attributes = std::move(*attrs);
        o.public_der = r.bytes();
        o.sealed = r.bytes();
        return o;
    }
};

/// The token commands' tags.
enum class token_command : std::uint8_t {
    init_token = 1,
    set_pin = 2,
    login_result = 3,
    create_objects = 4,
    update_object = 5,
    destroy_object = 6,
};

// --- Command builders -------------------------------------------------------

[[nodiscard]] inline auto make_init_token_command(
    std::string_view label, const pin_verifier& so_pin,
    std::uint32_t max_failures = default_max_login_failures) -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(token_command::init_token))
        .str(label)
        .bytes(so_pin.encode())
        .u32(max_failures);
    return w.take();
}

[[nodiscard]] inline auto make_set_pin_command(pin_user who, const pin_verifier& pin)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(token_command::set_pin))
        .u8(static_cast<std::uint8_t>(who))
        .bytes(pin.encode());
    return w.take();
}

[[nodiscard]] inline auto make_login_result_command(pin_user who, bool success)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(token_command::login_result))
        .u8(static_cast<std::uint8_t>(who))
        .u8(success ? 1 : 0);
    return w.take();
}

/// Creates every object or none (a key pair is one entry).
[[nodiscard]] inline auto make_create_objects_command(const std::vector<object_record>& objects)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(token_command::create_objects))
        .u32(static_cast<std::uint32_t>(objects.size()));
    for (const auto& o : objects) {
        o.encode_to(w);
    }
    return w.take();
}

/// Replaces an object's attributes and sealed material if its version is
/// still `expected_version`.
[[nodiscard]] inline auto make_update_object_command(std::uint64_t handle,
                                                     std::uint64_t expected_version,
                                                     const attribute_map& attributes,
                                                     const sealed_bytes& sealed)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(token_command::update_object))
        .u64(handle)
        .u64(expected_version)
        .bytes(attributes.encode())
        .bytes(sealed);
    return w.take();
}

/// Destroys an object if its version is `expected_version` (0: any).
[[nodiscard]] inline auto make_destroy_object_command(std::uint64_t handle,
                                                      std::uint64_t expected_version = 0)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(token_command::destroy_object))
        .u64(handle)
        .u64(expected_version);
    return w.take();
}

/// A decoded reply: the CK_RV and, for login results, the counter state;
/// for updates, the new version.
struct token_reply {
    CK_RV rv = CKR_OK;
    std::uint32_t failures = 0;
    bool locked = false;
    std::uint64_t version = 0;

    [[nodiscard]] static auto decode(const std::vector<std::byte>& in) -> token_reply {
        byte_reader r(in);
        token_reply t;
        t.rv = r.u32();
        t.failures = r.u32();
        t.locked = r.u8() != 0;
        t.version = r.u64();
        r.finish();
        return t;
    }
};

// --- The state machine ------------------------------------------------------

template<kythira::kv_engine Engine = kythira::memory_kv_engine, typename LogIndex = std::uint64_t>
class token_state_machine : public persistent_group<Engine, LogIndex> {
    using base = persistent_group<Engine, LogIndex>;

public:
    using engine_type = Engine;

    /// `ns` is the token group's engine namespace; `token_id` is the
    /// catalog's id for the token, which the sealed material's AD names.
    token_state_machine(std::string ns, std::uint64_t token_id)
        : base(std::move(ns)), _token_id(token_id) {}

    [[nodiscard]] auto token_id() const noexcept -> std::uint64_t { return _token_id; }

    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        if (this->already_applied(index)) {
            return {};
        }
        kythira::write_batch batch;
        token_reply reply;
        byte_reader r(command);
        switch (static_cast<token_command>(r.u8())) {
            case token_command::init_token:
                reply = apply_init(r, batch);
                break;
            case token_command::set_pin:
                reply = apply_set_pin(r, batch);
                break;
            case token_command::login_result:
                reply = apply_login(r, batch);
                break;
            case token_command::create_objects:
                reply = apply_create(r, batch);
                break;
            case token_command::update_object:
                reply = apply_update(r, batch);
                break;
            case token_command::destroy_object:
                reply = apply_destroy(r, batch);
                break;
            default:
                throw std::invalid_argument("token_state_machine: unknown command");
        }
        r.finish();
        this->commit(batch, index);
        byte_writer w;
        w.u32(static_cast<std::uint32_t>(reply.rv))
            .u32(reply.failures)
            .u8(reply.locked ? 1 : 0)
            .u64(reply.version);
        return w.take();
    }

    // -- Reads (on any replica that has applied the entries) ----------------

    [[nodiscard]] auto token() const -> std::optional<token_record> {
        auto v = this->get("t");
        if (!v) {
            return std::nullopt;
        }
        return token_record::decode(*v);
    }

    [[nodiscard]] auto object(std::uint64_t handle) const -> std::optional<object_record> {
        auto v = this->get(object_key(handle));
        if (!v) {
            return std::nullopt;
        }
        byte_reader r(*v);
        auto o = object_record::decode_from(r);
        r.finish();
        return o;
    }

    /// Every object, in handle order; `f` returns false to stop.
    template<typename F> auto for_each_object(F&& f) const -> void {
        this->scan_prefix("o", [&](std::string_view, std::string_view v) {
            byte_reader r(v);
            auto o = object_record::decode_from(r);
            return f(o);
        });
    }

    [[nodiscard]] auto object_count() const -> std::size_t {
        std::size_t n = 0;
        for_each_object([&](const object_record&) {
            ++n;
            return true;
        });
        return n;
    }

private:
    [[nodiscard]] static auto object_key(std::uint64_t handle) -> std::string {
        return "o" + be64_key(handle);
    }

    auto put_token(kythira::write_batch& batch, const token_record& t) -> void {
        batch.put(kythira::column_family::data, this->key("t"), t.encode());
    }

    auto put_object(kythira::write_batch& batch, const object_record& o) -> void {
        byte_writer w;
        o.encode_to(w);
        batch.put(kythira::column_family::data, this->key(object_key(o.handle)), w.take_string());
    }

    static auto read_pin(byte_reader& r) -> pin_verifier {
        auto v = pin_verifier::decode(r.bytes());
        if (!v) {
            throw std::invalid_argument("token_state_machine: bad PIN verifier");
        }
        return *v;
    }

    static auto read_user(byte_reader& r) -> pin_user {
        const auto u = r.u8();
        if (u != static_cast<std::uint8_t>(pin_user::so) &&
            u != static_cast<std::uint8_t>(pin_user::user)) {
            throw std::invalid_argument("token_state_machine: bad user type");
        }
        return static_cast<pin_user>(u);
    }

    /// C_InitToken: a fresh token record and no objects. The SO PIN check
    /// (on a token that already has one) happened before proposing.
    auto apply_init(byte_reader& r, kythira::write_batch& batch) -> token_reply {
        token_record t;
        t.label = r.str();
        t.so_pin = read_pin(r);
        t.max_failures = r.u32();
        if (t.max_failures == 0) {
            throw std::invalid_argument("token_state_machine: max_failures is zero");
        }
        const std::string objects = this->key("o");
        batch.erase_range(kythira::column_family::data,
                          kythira::key_range{objects, base::prefix_end(objects)});
        put_token(batch, t);
        return {};
    }

    /// C_InitPIN (SO sets the user PIN) and C_SetPIN: a new verifier, and
    /// that user's counter cleared, which is how the SO unlocks a user.
    auto apply_set_pin(byte_reader& r, kythira::write_batch& batch) -> token_reply {
        const auto who = read_user(r);
        const auto pin = read_pin(r);
        auto t = token();
        if (!t) {
            return {.rv = CKR_TOKEN_NOT_RECOGNIZED};
        }
        if (who == pin_user::so) {
            t->so_pin = pin;
            t->so_failures = 0;
        } else {
            t->user_pin = pin;
            t->user_failures = 0;
        }
        put_token(batch, *t);
        return {};
    }

    /// The outcome of a PIN check on the serving node.
    auto apply_login(byte_reader& r, kythira::write_batch& batch) -> token_reply {
        const auto who = read_user(r);
        const bool success = r.u8() != 0;
        auto t = token();
        if (!t) {
            return {.rv = CKR_TOKEN_NOT_RECOGNIZED};
        }
        auto& n = who == pin_user::so ? t->so_failures : t->user_failures;
        if (t->locked(who)) {
            return {.rv = CKR_PIN_LOCKED, .failures = n, .locked = true};
        }
        CK_RV rv = CKR_OK;
        if (success) {
            n = 0;
        } else {
            ++n;
            rv = t->locked(who) ? CKR_PIN_LOCKED : CKR_PIN_INCORRECT;
        }
        put_token(batch, *t);
        return {.rv = rv, .failures = n, .locked = t->locked(who)};
    }

    auto apply_create(byte_reader& r, kythira::write_batch& batch) -> token_reply {
        const auto count = r.u32();
        std::vector<object_record> objects;
        for (std::uint32_t i = 0; i < count; ++i) {
            objects.push_back(object_record::decode_from(r));
        }
        if (!token()) {
            return {.rv = CKR_TOKEN_NOT_RECOGNIZED};
        }
        for (std::size_t i = 0; i < objects.size(); ++i) {
            const auto h = objects[i].handle;
            if (h == 0 || h > max_token_object_handle) {
                throw std::invalid_argument("token_state_machine: handle out of range");
            }
            bool repeated = false;
            for (std::size_t j = 0; j < i; ++j) {
                repeated = repeated || objects[j].handle == h;
            }
            if (repeated || this->get(object_key(h)).has_value()) {
                return {.rv = CKR_FUNCTION_REJECTED};
            }
        }
        for (auto& o : objects) {
            o.version = 1;
            put_object(batch, o);
        }
        return {.version = 1};
    }

    auto apply_update(byte_reader& r, kythira::write_batch& batch) -> token_reply {
        const auto handle = r.u64();
        const auto expected = r.u64();
        auto attrs = attribute_map::decode(r.bytes());
        auto sealed = r.bytes();
        if (!attrs) {
            throw std::invalid_argument("token_state_machine: bad attributes");
        }
        auto o = object(handle);
        if (!o) {
            return {.rv = CKR_OBJECT_HANDLE_INVALID};
        }
        if (o->version != expected) {
            return {.rv = CKR_FUNCTION_REJECTED, .version = o->version};
        }
        o->attributes = std::move(*attrs);
        o->sealed = std::move(sealed);
        ++o->version;
        put_object(batch, *o);
        return {.version = o->version};
    }

    auto apply_destroy(byte_reader& r, kythira::write_batch& batch) -> token_reply {
        const auto handle = r.u64();
        const auto expected = r.u64();
        auto o = object(handle);
        if (!o) {
            return {.rv = CKR_OBJECT_HANDLE_INVALID};
        }
        if (expected != 0 && o->version != expected) {
            return {.rv = CKR_FUNCTION_REJECTED, .version = o->version};
        }
        batch.erase(kythira::column_family::data, this->key(object_key(handle)));
        return {};
    }

    std::uint64_t _token_id;
};

static_assert(kythira::persistent_state_machine<token_state_machine<>>);
static_assert(!kythira::state_machine<token_state_machine<>, std::uint64_t>);

}  // namespace kythira::hsm
