// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// PKCS#11 attribute enforcement (requirement 6.3 and 6.4), one function
// per rule so each has its own test (13.3). The session layer calls these
// around every operation; mechanisms.hpp never looks at attributes.
//
//   rule                              function                     CK_RV
//   usage flags (CKA_SIGN, ...)       check_usage                  KEY_FUNCTION_NOT_PERMITTED
//   sensitive values unreadable       check_readable               ATTRIBUTE_SENSITIVE
//   CKA_SENSITIVE only false->true    check_sensitive_change       ATTRIBUTE_READ_ONLY
//   CKA_EXTRACTABLE only true->false  check_extractable_change     ATTRIBUTE_READ_ONLY
//   CKA_WRAP_WITH_TRUSTED one-way     check_wrap_with_trusted_change ATTRIBUTE_READ_ONLY
//   CKA_TRUSTED=true only by the SO   check_trusted                ATTRIBUTE_READ_ONLY
//   token-set attributes              check_caller_settable        ATTRIBUTE_READ_ONLY
//   fixed after creation              check_changeable             ATTRIBUTE_READ_ONLY
//   CKA_MODIFIABLE=false              check_modifiable             ACTION_PROHIBITED
//   non-extractable never wrapped     check_wrappable              KEY_UNEXTRACTABLE
//   wrap-with-trusted, wrap template  check_wrappable              KEY_NOT_WRAPPABLE
//   unwrap and derive templates       apply_key_template           TEMPLATE_INCONSISTENT
//   ALWAYS_SENSITIVE etc. at birth    set_origin_flags             -
//   secure defaults                   apply_key_defaults           -
//
// set_attributes() is C_SetAttributeValue: every change rule, in order.

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/pkcs11.hpp>

#include <algorithm>
#include <array>

namespace kythira::hsm {

enum class key_operation : std::uint8_t {
    sign,
    verify,
    encrypt,
    decrypt,
    wrap,
    unwrap,
    derive
};

/// Who is logged in on the session making the call.
enum class session_user : std::uint8_t {
    none,
    user,
    so
};

/// How a key came to exist, for the flags PKCS#11 derives at creation.
enum class key_origin : std::uint8_t {
    generated,
    created,
    unwrapped,
    derived
};

[[nodiscard]] constexpr auto usage_attribute(key_operation op) noexcept -> CK_ATTRIBUTE_TYPE {
    switch (op) {
        case key_operation::sign:
            return CKA_SIGN;
        case key_operation::verify:
            return CKA_VERIFY;
        case key_operation::encrypt:
            return CKA_ENCRYPT;
        case key_operation::decrypt:
            return CKA_DECRYPT;
        case key_operation::wrap:
            return CKA_WRAP;
        case key_operation::unwrap:
            return CKA_UNWRAP;
        case key_operation::derive:
            return CKA_DERIVE;
    }
    return CKA_VENDOR_DEFINED;
}

/// The key may be used for `op` only when its usage flag is true.
[[nodiscard]] inline auto check_usage(const attribute_map& key, key_operation op)
    -> ck_result<void> {
    if (!key.flag(usage_attribute(op))) {
        return unexpected(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    return {};
}

/// The attributes that hold secret or private key material.
[[nodiscard]] constexpr auto is_sensitive_attribute(CK_ATTRIBUTE_TYPE type) noexcept -> bool {
    switch (type) {
        case CKA_VALUE:
        case CKA_PRIVATE_EXPONENT:
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_COEFFICIENT:
            return true;
        default:
            return false;
    }
}

/// C_GetAttributeValue: a secret or private key's material is unreadable
/// when the key is sensitive or not extractable (6.4).
[[nodiscard]] inline auto check_readable(const attribute_map& key, CK_ATTRIBUTE_TYPE type)
    -> ck_result<void> {
    const auto cls = key.get_ulong(CKA_CLASS).value_or(std::nullopt).value_or(CKO_DATA);
    if (cls != CKO_SECRET_KEY && cls != CKO_PRIVATE_KEY) {
        return {};
    }
    if (is_sensitive_attribute(type) && (key.flag(CKA_SENSITIVE) || !key.flag(CKA_EXTRACTABLE))) {
        return unexpected(CKR_ATTRIBUTE_SENSITIVE);
    }
    return {};
}

namespace detail {

/// A one-way boolean: it may move from `from` to `!from` but never back.
[[nodiscard]] inline auto one_way(const attribute_map& current, const attribute_map& changes,
                                  CK_ATTRIBUTE_TYPE type, bool locked_value) -> ck_result<void> {
    if (!changes.has(type)) {
        return {};
    }
    auto next = changes.get_bool(type, false);
    if (!next) {
        return unexpected(next.error());
    }
    if (current.flag(type) == locked_value && *next != locked_value) {
        return unexpected(CKR_ATTRIBUTE_READ_ONLY);
    }
    return {};
}

}  // namespace detail

/// CKA_SENSITIVE may be set to true, never back to false.
[[nodiscard]] inline auto check_sensitive_change(const attribute_map& current,
                                                 const attribute_map& changes) -> ck_result<void> {
    return detail::one_way(current, changes, CKA_SENSITIVE, true);
}

/// CKA_EXTRACTABLE may be set to false, never back to true.
[[nodiscard]] inline auto check_extractable_change(const attribute_map& current,
                                                   const attribute_map& changes)
    -> ck_result<void> {
    return detail::one_way(current, changes, CKA_EXTRACTABLE, false);
}

/// CKA_WRAP_WITH_TRUSTED may be set to true, never back to false.
[[nodiscard]] inline auto check_wrap_with_trusted_change(const attribute_map& current,
                                                         const attribute_map& changes)
    -> ck_result<void> {
    return detail::one_way(current, changes, CKA_WRAP_WITH_TRUSTED, true);
}

/// Only the SO may set CKA_TRUSTED to true (on creation or later).
[[nodiscard]] inline auto check_trusted(const attribute_map& tmpl, session_user who)
    -> ck_result<void> {
    auto trusted = tmpl.get_bool(CKA_TRUSTED, false);
    if (!trusted) {
        return unexpected(trusted.error());
    }
    if (*trusted && who != session_user::so) {
        return unexpected(CKR_ATTRIBUTE_READ_ONLY);
    }
    return {};
}

/// Attributes only the token sets; a caller's template may not name them.
[[nodiscard]] inline auto check_caller_settable(const attribute_map& tmpl) -> ck_result<void> {
    static constexpr std::array<CK_ATTRIBUTE_TYPE, 4> token_set{
        CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM};
    if (std::ranges::any_of(token_set, [&](CK_ATTRIBUTE_TYPE t) { return tmpl.has(t); })) {
        return unexpected(CKR_ATTRIBUTE_READ_ONLY);
    }
    return {};
}

/// Attributes fixed once the object exists: identity, material, the
/// templates and the lifecycle flags. Everything else (labels, ids, usage
/// flags and the one-way flags under their own rules) may change.
[[nodiscard]] inline auto check_changeable(const attribute_map& changes) -> ck_result<void> {
    static constexpr std::array<CK_ATTRIBUTE_TYPE, 25> fixed{
        CKA_CLASS,
        CKA_KEY_TYPE,
        CKA_TOKEN,
        CKA_PRIVATE,
        CKA_VALUE,
        CKA_VALUE_LEN,
        CKA_MODULUS,
        CKA_MODULUS_BITS,
        CKA_PUBLIC_EXPONENT,
        CKA_PRIVATE_EXPONENT,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_COEFFICIENT,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
        CKA_WRAP_TEMPLATE,
        CKA_UNWRAP_TEMPLATE,
        CKA_DERIVE_TEMPLATE,
        CKA_MODIFIABLE,
        CKA_DESTROYABLE,
        CKA_LOCAL,
        CKA_ALWAYS_SENSITIVE,
        CKA_NEVER_EXTRACTABLE,
    };
    if (std::ranges::any_of(fixed, [&](CK_ATTRIBUTE_TYPE t) { return changes.has(t); })) {
        return unexpected(CKR_ATTRIBUTE_READ_ONLY);
    }
    // CKA_COPYABLE may only be turned off.
    if (changes.has(CKA_COPYABLE) && changes.get_bool(CKA_COPYABLE, false).value_or(true)) {
        return unexpected(CKR_ATTRIBUTE_READ_ONLY);
    }
    return {};
}

/// An object with CKA_MODIFIABLE false refuses every change.
[[nodiscard]] inline auto check_modifiable(const attribute_map& current) -> ck_result<void> {
    if (!current.get_bool(CKA_MODIFIABLE, true).value_or(true)) {
        return unexpected(CKR_ACTION_PROHIBITED);
    }
    return {};
}

/// C_WrapKey's checks beyond the wrapping key's CKA_WRAP (check_usage):
/// the key must be extractable; a CKA_WRAP_WITH_TRUSTED key needs a
/// CKA_TRUSTED wrapping key; and the key must satisfy the wrapping key's
/// CKA_WRAP_TEMPLATE.
[[nodiscard]] inline auto check_wrappable(const attribute_map& wrapping_key,
                                          const attribute_map& key) -> ck_result<void> {
    if (!key.flag(CKA_EXTRACTABLE)) {
        return unexpected(CKR_KEY_UNEXTRACTABLE);
    }
    if (key.flag(CKA_WRAP_WITH_TRUSTED) && !wrapping_key.flag(CKA_TRUSTED)) {
        return unexpected(CKR_KEY_NOT_WRAPPABLE);
    }
    auto required = wrapping_key.get_template(CKA_WRAP_TEMPLATE);
    if (!required) {
        return unexpected(required.error());
    }
    if (!key.satisfies(*required)) {
        return unexpected(CKR_KEY_NOT_WRAPPABLE);
    }
    return {};
}

/// C_UnwrapKey and C_DeriveKey: the caller's template, merged with the
/// unwrapping key's CKA_UNWRAP_TEMPLATE (or the base key's
/// CKA_DERIVE_TEMPLATE). A caller attribute that disagrees with the
/// template is CKR_TEMPLATE_INCONSISTENT.
[[nodiscard]] inline auto apply_key_template(const attribute_map& source_key,
                                             CK_ATTRIBUTE_TYPE template_type,
                                             const attribute_map& caller)
    -> ck_result<attribute_map> {
    auto required = source_key.get_template(template_type);
    if (!required) {
        return unexpected(required.error());
    }
    for (const auto& [type, value] : *required) {
        auto mine = caller.bytes(type);
        if (mine && !std::ranges::equal(*mine, value)) {
            return unexpected(CKR_TEMPLATE_INCONSISTENT);
        }
    }
    attribute_map out = caller;
    out.merge(*required);
    return out;
}

/// Secure defaults for a new secret or private key: sensitive, not
/// extractable, not trusted, modifiable, and no usage flag the caller did
/// not ask for. PKCS#11 leaves SENSITIVE and EXTRACTABLE token-specific;
/// this token chooses the safe value.
inline void apply_key_defaults(attribute_map& key) {
    if (!key.has(CKA_SENSITIVE)) {
        key.set_bool(CKA_SENSITIVE, true);
    }
    if (!key.has(CKA_EXTRACTABLE)) {
        key.set_bool(CKA_EXTRACTABLE, false);
    }
    for (CK_ATTRIBUTE_TYPE t : {CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP,
                                CKA_UNWRAP, CKA_DERIVE, CKA_TRUSTED, CKA_WRAP_WITH_TRUSTED}) {
        if (!key.has(t)) {
            key.set_bool(t, false);
        }
    }
    if (!key.has(CKA_MODIFIABLE)) {
        key.set_bool(CKA_MODIFIABLE, true);
    }
}

/// CKA_LOCAL, CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE at creation.
/// A generated key is local and inherits its own flags; a derived key keeps
/// them only if the base key had them; an imported or unwrapped key has
/// been outside the token and gets neither.
inline void set_origin_flags(attribute_map& key, key_origin origin,
                             const attribute_map* base = nullptr) {
    const bool sensitive = key.flag(CKA_SENSITIVE);
    const bool extractable = key.flag(CKA_EXTRACTABLE);
    switch (origin) {
        case key_origin::generated:
            key.set_bool(CKA_LOCAL, true);
            key.set_bool(CKA_ALWAYS_SENSITIVE, sensitive);
            key.set_bool(CKA_NEVER_EXTRACTABLE, !extractable);
            return;
        case key_origin::derived:
            key.set_bool(CKA_LOCAL, false);
            key.set_bool(CKA_ALWAYS_SENSITIVE,
                         base != nullptr && base->flag(CKA_ALWAYS_SENSITIVE) && sensitive);
            key.set_bool(CKA_NEVER_EXTRACTABLE,
                         base != nullptr && base->flag(CKA_NEVER_EXTRACTABLE) && !extractable);
            return;
        case key_origin::created:
        case key_origin::unwrapped:
            key.set_bool(CKA_LOCAL, false);
            key.set_bool(CKA_ALWAYS_SENSITIVE, false);
            key.set_bool(CKA_NEVER_EXTRACTABLE, false);
            return;
    }
}

/// C_SetAttributeValue: every change rule, then the merged attributes.
[[nodiscard]] inline auto set_attributes(const attribute_map& current, const attribute_map& changes,
                                         session_user who) -> ck_result<attribute_map> {
    for (auto rule : {
             +[](const attribute_map& c, const attribute_map&, session_user) {
                 return check_modifiable(c);
             },
             +[](const attribute_map&, const attribute_map& ch, session_user) {
                 return check_caller_settable(ch);
             },
             +[](const attribute_map&, const attribute_map& ch, session_user) {
                 return check_changeable(ch);
             },
             +[](const attribute_map& c, const attribute_map& ch, session_user) {
                 return check_sensitive_change(c, ch);
             },
             +[](const attribute_map& c, const attribute_map& ch, session_user) {
                 return check_extractable_change(c, ch);
             },
             +[](const attribute_map& c, const attribute_map& ch, session_user) {
                 return check_wrap_with_trusted_change(c, ch);
             },
             +[](const attribute_map&, const attribute_map& ch, session_user w) {
                 return check_trusted(ch, w);
             },
         }) {
        if (auto r = rule(current, changes, who); !r) {
            return unexpected(r.error());
        }
    }
    attribute_map out = current;
    out.merge(changes);
    return out;
}

}  // namespace kythira::hsm
