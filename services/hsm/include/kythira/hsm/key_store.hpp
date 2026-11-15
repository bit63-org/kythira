// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The leader's side of the key store (requirement 3.3, design "Generation on
// the leader, material in the log"): generate or re-seal key material with
// the unsealed keys only the leader's memory holds, and turn the result into
// the token or catalog command that carries it, already sealed. Every
// function here runs before a proposal; nothing here is called on apply.
//
// The callers (the session layer, task 6) check the caller's template with
// attribute_policy.hpp first; these functions add what the token sets
// (class, key type, CKA_LOCAL and friends, public attributes) and the safe
// defaults.

#include <kythira/hsm/attribute_policy.hpp>
#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/mechanisms.hpp>
#include <kythira/hsm/sealing.hpp>
#include <kythira/hsm/secret_bytes.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace kythira::hsm {

/// A fresh token key and its entry for the catalog, sealed under `mk`.
struct new_token {
    secret_bytes tk;
    token_entry entry;
};

[[nodiscard]] inline auto prepare_token(std::span<const std::uint8_t> mk, std::uint32_t generation,
                                        std::uint64_t token_id, std::string label) -> new_token {
    new_token out;
    out.tk = secret_bytes(sealing_key_size);
    if (!generate_random(out.tk.span())) {
        throw std::runtime_error("prepare_token: no randomness");
    }
    out.entry.token_id = token_id;
    out.entry.label = std::move(label);
    out.entry.generation = generation;
    out.entry.sealed_tk = seal(mk, token_key_ad(token_id, generation), out.tk.view());
    return out;
}

/// The token key of a catalog entry, or nothing if `mk` is not the MK it
/// was sealed under.
[[nodiscard]] inline auto open_token_key(std::span<const std::uint8_t> mk, const token_entry& entry)
    -> std::optional<secret_bytes> {
    return unseal(mk, token_key_ad(entry.token_id, entry.generation), entry.sealed_tk);
}

/// The rekey entry: every token key re-sealed from `old_mk` to `new_mk`
/// under the next generation. Fails (nothing) if any key does not open,
/// which means `old_mk` is wrong.
[[nodiscard]] inline auto prepare_rekey(std::span<const std::uint8_t> old_mk,
                                        std::span<const std::uint8_t> new_mk,
                                        std::span<const std::uint8_t, 8> new_mk_check,
                                        const catalog_record& catalog,
                                        const std::vector<token_entry>& tokens)
    -> std::optional<std::vector<std::byte>> {
    const std::uint32_t next = catalog.generation + 1;
    std::vector<std::pair<std::uint64_t, sealed_bytes>> resealed;
    for (const auto& t : tokens) {
        auto tk = open_token_key(old_mk, t);
        if (!tk) {
            return std::nullopt;
        }
        resealed.emplace_back(t.token_id, seal(new_mk, token_key_ad(t.token_id, next), tk->view()));
    }
    return make_rekey_command(next, new_mk_check, resealed);
}

/// An object's material, or nothing if the sealed bytes do not belong to
/// this token, handle and attributes (or were altered).
[[nodiscard]] inline auto open_object(std::span<const std::uint8_t> tk, std::uint64_t token_id,
                                      const object_record& o) -> std::optional<secret_bytes> {
    if (o.sealed.empty()) {
        return std::nullopt;
    }
    return unseal(tk, object_ad(token_id, o.handle, o.attributes), o.sealed);
}

/// The material as the mechanisms take it.
[[nodiscard]] inline auto key_material_of(std::span<const std::uint8_t> tk, std::uint64_t token_id,
                                          const object_record& o) -> ck_result<key_material> {
    key_material k;
    auto cls = o.attributes.get_ulong(CKA_CLASS);
    auto type = o.attributes.get_ulong(CKA_KEY_TYPE);
    if (!cls || !*cls || !type || !*type) {
        return unexpected(CKR_KEY_HANDLE_INVALID);
    }
    k.object_class = **cls;
    k.key_type = **type;
    k.public_der = o.public_der;
    if (k.object_class != CKO_PUBLIC_KEY) {
        auto secret = open_object(tk, token_id, o);
        if (!secret) {
            // Corruption or tampering; design "Error handling".
            return unexpected(CKR_DEVICE_ERROR);
        }
        k.secret = std::move(*secret);
    }
    return k;
}

namespace detail {

[[nodiscard]] inline auto secret_key_type_for(CK_MECHANISM_TYPE m) -> std::optional<CK_KEY_TYPE> {
    switch (m) {
        case CKM_AES_KEY_GEN:
            return CKK_AES;
        case CKM_GENERIC_SECRET_KEY_GEN:
            return CKK_GENERIC_SECRET;
        case CKM_HKDF_KEY_GEN:
            return CKK_HKDF;
        default:
            return std::nullopt;
    }
}

inline void apply_public_defaults(attribute_map& key) {
    for (CK_ATTRIBUTE_TYPE t : {CKA_VERIFY, CKA_ENCRYPT, CKA_WRAP, CKA_DERIVE, CKA_TRUSTED}) {
        if (!key.has(t)) {
            key.set_bool(t, false);
        }
    }
    if (!key.has(CKA_MODIFIABLE)) {
        key.set_bool(CKA_MODIFIABLE, true);
    }
}

}  // namespace detail

/// A new object before it is stored: its record (attributes final, `sealed`
/// still empty) and its material in the secure arena. Token objects are
/// sealed from this (prepare_generate_key); session objects keep the
/// material as it is (session_layer.hpp).
struct built_object {
    object_record record;
    secret_bytes material;
};

/// C_GenerateKey's object: the key and its attributes. CKA_TOKEN keeps the
/// caller's value (PKCS#11 default false). `tmpl` must carry
/// CKA_VALUE_LEN for AES and generic secrets.
[[nodiscard]] inline auto build_secret_key(std::uint64_t handle, const CK_MECHANISM& mechanism,
                                           const attribute_map& tmpl) -> ck_result<built_object> {
    const auto key_type = detail::secret_key_type_for(mechanism.mechanism);
    if (!key_type) {
        return unexpected(CKR_MECHANISM_INVALID);
    }
    if (auto r = check_caller_settable(tmpl); !r) {
        return unexpected(r.error());
    }
    auto len = tmpl.get_ulong(CKA_VALUE_LEN);
    if (!len) {
        return unexpected(len.error());
    }
    if (!*len) {
        return unexpected(CKR_TEMPLATE_INCOMPLETE);
    }
    auto token = tmpl.get_bool(CKA_TOKEN, false);
    if (!token) {
        return unexpected(token.error());
    }
    auto value = generate_secret_key(mechanism, **len);
    if (!value) {
        return unexpected(value.error());
    }
    built_object out;
    out.record.handle = handle;
    out.record.attributes = tmpl;
    out.record.attributes.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    out.record.attributes.set_ulong(CKA_KEY_TYPE, *key_type);
    out.record.attributes.set_ulong(CKA_KEY_GEN_MECHANISM, mechanism.mechanism);
    out.record.attributes.set_bool(CKA_TOKEN, *token);
    apply_key_defaults(out.record.attributes);
    set_origin_flags(out.record.attributes, key_origin::generated);
    out.material = std::move(*value);
    return out;
}

/// C_GenerateKeyPair's two objects. The public template supplies
/// CKA_MODULUS_BITS and CKA_PUBLIC_EXPONENT (RSA) or CKA_EC_PARAMS (EC,
/// Ed25519). The public key has no secret material.
struct built_pair {
    object_record public_key;
    built_object private_key;
};

[[nodiscard]] inline auto build_key_pair(std::uint64_t public_handle, std::uint64_t private_handle,
                                         const CK_MECHANISM& mechanism,
                                         const attribute_map& public_tmpl,
                                         const attribute_map& private_tmpl)
    -> ck_result<built_pair> {
    for (const auto* t : {&public_tmpl, &private_tmpl}) {
        if (auto r = check_caller_settable(*t); !r) {
            return unexpected(r.error());
        }
    }
    auto pub_token = public_tmpl.get_bool(CKA_TOKEN, false);
    auto priv_token = private_tmpl.get_bool(CKA_TOKEN, false);
    if (!pub_token || !priv_token) {
        return unexpected(!pub_token ? pub_token.error() : priv_token.error());
    }
    key_pair_request req;
    auto bits = public_tmpl.get_ulong(CKA_MODULUS_BITS);
    if (!bits) {
        return unexpected(bits.error());
    }
    req.modulus_bits = bits->value_or(0);
    if (auto e = public_tmpl.bytes(CKA_PUBLIC_EXPONENT)) {
        req.public_exponent.assign(e->begin(), e->end());
    }
    if (auto p = public_tmpl.bytes(CKA_EC_PARAMS)) {
        req.ec_params.assign(p->begin(), p->end());
    }
    auto pair = generate_key_pair(mechanism, req);
    if (!pair) {
        return unexpected(pair.error());
    }

    built_pair out;
    auto& pub = out.public_key;
    pub.handle = public_handle;
    pub.attributes = public_tmpl;
    pub.attributes.merge(pair->public_attributes);
    pub.attributes.set_ulong(CKA_CLASS, CKO_PUBLIC_KEY);
    pub.attributes.set_ulong(CKA_KEY_TYPE, pair->key_type);
    pub.attributes.set_ulong(CKA_KEY_GEN_MECHANISM, mechanism.mechanism);
    pub.attributes.set_bool(CKA_TOKEN, *pub_token);
    pub.attributes.set_bool(CKA_LOCAL, true);
    detail::apply_public_defaults(pub.attributes);
    pub.public_der = pair->public_spki;

    auto& priv = out.private_key.record;
    priv.handle = private_handle;
    priv.attributes = private_tmpl;
    // The private object shows the public parameters too (not the point).
    for (CK_ATTRIBUTE_TYPE t : {CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_EC_PARAMS}) {
        if (auto v = pair->public_attributes.bytes(t)) {
            priv.attributes.set_bytes(t, *v);
        }
    }
    priv.attributes.set_ulong(CKA_CLASS, CKO_PRIVATE_KEY);
    priv.attributes.set_ulong(CKA_KEY_TYPE, pair->key_type);
    priv.attributes.set_ulong(CKA_KEY_GEN_MECHANISM, mechanism.mechanism);
    priv.attributes.set_bool(CKA_TOKEN, *priv_token);
    apply_key_defaults(priv.attributes);
    set_origin_flags(priv.attributes, key_origin::generated);
    priv.public_der = pair->public_spki;
    out.private_key.material = std::move(pair->private_pkcs8);
    return out;
}

/// Seals a built token object under `tk`, binding its token, handle and
/// final attributes.
inline void seal_object(std::span<const std::uint8_t> tk, std::uint64_t token_id, built_object& o) {
    o.record.sealed =
        seal(tk, object_ad(token_id, o.record.handle, o.record.attributes), o.material.view());
}

/// C_GenerateKey on the leader: the key, sealed, as a create_objects entry.
/// The object is a token object whatever the template says.
[[nodiscard]] inline auto prepare_generate_key(std::span<const std::uint8_t> tk,
                                               std::uint64_t token_id, std::uint64_t handle,
                                               const CK_MECHANISM& mechanism,
                                               const attribute_map& tmpl)
    -> ck_result<std::vector<std::byte>> {
    attribute_map t = tmpl;
    t.set_bool(CKA_TOKEN, true);
    auto o = build_secret_key(handle, mechanism, t);
    if (!o) {
        return unexpected(o.error());
    }
    seal_object(tk, token_id, *o);
    return make_create_objects_command({o->record});
}

/// C_GenerateKeyPair on the leader: both objects, as token objects, in one
/// create_objects entry.
[[nodiscard]] inline auto prepare_generate_key_pair(
    std::span<const std::uint8_t> tk, std::uint64_t token_id, std::uint64_t public_handle,
    std::uint64_t private_handle, const CK_MECHANISM& mechanism, const attribute_map& public_tmpl,
    const attribute_map& private_tmpl) -> ck_result<std::vector<std::byte>> {
    attribute_map pt = public_tmpl;
    attribute_map vt = private_tmpl;
    pt.set_bool(CKA_TOKEN, true);
    vt.set_bool(CKA_TOKEN, true);
    auto pair = build_key_pair(public_handle, private_handle, mechanism, pt, vt);
    if (!pair) {
        return unexpected(pair.error());
    }
    seal_object(tk, token_id, pair->private_key);
    return make_create_objects_command({pair->public_key, pair->private_key.record});
}

/// C_SetAttributeValue on the leader: the policy-checked new attributes,
/// with the material re-sealed under them (the AD binds the attributes), as
/// an update entry that names the version it read.
[[nodiscard]] inline auto prepare_set_attributes(std::span<const std::uint8_t> tk,
                                                 std::uint64_t token_id,
                                                 const object_record& current,
                                                 const attribute_map& changes, session_user who)
    -> ck_result<std::vector<std::byte>> {
    auto next = set_attributes(current.attributes, changes, who);
    if (!next) {
        return unexpected(next.error());
    }
    sealed_bytes sealed;
    if (!current.sealed.empty()) {
        auto material = open_object(tk, token_id, current);
        if (!material) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        sealed = seal(tk, object_ad(token_id, current.handle, *next), material->view());
    }
    return make_update_object_command(current.handle, current.version, *next, sealed);
}

/// A random token object handle in [1, 2^31). A collision is refused on
/// apply (CKR_FUNCTION_REJECTED) and the caller picks again.
[[nodiscard]] inline auto random_object_handle() -> std::uint64_t {
    std::array<std::uint8_t, 4> b{};
    if (!generate_random(b)) {
        throw std::runtime_error("random_object_handle: no randomness");
    }
    std::uint64_t h = (std::uint64_t{b[0]} << 24U) | (std::uint64_t{b[1]} << 16U) |
                      (std::uint64_t{b[2]} << 8U) | b[3];
    h &= max_token_object_handle;
    return h == 0 ? 1 : h;
}

}  // namespace kythira::hsm
