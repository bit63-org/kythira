// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 4, requirements 6.3, 6.4 and 13.3: one test per attribute rule in
// attribute_policy.hpp, plus the attribute_map they work on.

#define BOOST_TEST_MODULE hsm_attribute_policy_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/attribute_policy.hpp>

#include <array>
#include <cstdint>
#include <vector>

namespace hsm = kythira::hsm;

namespace {

auto key_with(std::initializer_list<std::pair<CK_ATTRIBUTE_TYPE, bool>> flags,
              CK_OBJECT_CLASS cls = CKO_SECRET_KEY) -> hsm::attribute_map {
    hsm::attribute_map m;
    m.set_ulong(CKA_CLASS, cls);
    m.set_ulong(CKA_KEY_TYPE, CKK_AES);
    for (const auto& [type, value] : flags) {
        m.set_bool(type, value);
    }
    return m;
}

auto change(CK_ATTRIBUTE_TYPE type, bool value) -> hsm::attribute_map {
    hsm::attribute_map m;
    m.set_bool(type, value);
    return m;
}

}  // namespace

// --- attribute_map ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(attribute_map_reads_templates_and_nested_templates) {
    CK_BBOOL yes = CK_TRUE;
    CK_ULONG cls = CKO_SECRET_KEY;
    std::array<CK_ATTRIBUTE, 1> inner{{{CKA_SENSITIVE, &yes, sizeof yes}}};
    std::array<CK_ATTRIBUTE, 3> outer{{{CKA_CLASS, &cls, sizeof cls},
                                       {CKA_EXTRACTABLE, &yes, sizeof yes},
                                       {CKA_WRAP_TEMPLATE, inner.data(), sizeof inner}}};
    auto m = hsm::attribute_map::from_template(outer);
    BOOST_REQUIRE(m.has_value());
    BOOST_TEST(m->get_ulong(CKA_CLASS).value().value() == CKO_SECRET_KEY);
    BOOST_TEST(m->flag(CKA_EXTRACTABLE));
    auto t = m->get_template(CKA_WRAP_TEMPLATE);
    BOOST_REQUIRE(t.has_value());
    BOOST_TEST(t->flag(CKA_SENSITIVE));
    BOOST_TEST(t->size() == 1U);
}

BOOST_AUTO_TEST_CASE(attribute_map_refuses_malformed_templates) {
    CK_BBOOL yes = CK_TRUE;
    std::array<CK_ATTRIBUTE, 2> dup{{{CKA_SIGN, &yes, 1}, {CKA_SIGN, &yes, 1}}};
    BOOST_TEST(hsm::attribute_map::from_template(dup).error() == CKR_TEMPLATE_INCONSISTENT);
    std::array<CK_ATTRIBUTE, 1> null_value{{{CKA_LABEL, nullptr, 4}}};
    BOOST_TEST(hsm::attribute_map::from_template(null_value).error() ==
               CKR_ATTRIBUTE_VALUE_INVALID);
    std::array<CK_ATTRIBUTE, 1> ragged{{{CKA_WRAP_TEMPLATE, &yes, 1}}};
    BOOST_TEST(hsm::attribute_map::from_template(ragged).error() == CKR_ATTRIBUTE_VALUE_INVALID);
    std::array<CK_ATTRIBUTE, 1> deepest{{{CKA_SIGN, &yes, 1}}};
    std::array<CK_ATTRIBUTE, 1> deeper{{{CKA_WRAP_TEMPLATE, deepest.data(), sizeof deepest}}};
    std::array<CK_ATTRIBUTE, 1> deep{{{CKA_UNWRAP_TEMPLATE, deeper.data(), sizeof deeper}}};
    BOOST_TEST(hsm::attribute_map::from_template(deep).error() == CKR_ATTRIBUTE_VALUE_INVALID);
    hsm::attribute_map m;
    m.set_bytes(CKA_SIGN, std::vector<std::uint8_t>{1, 1});
    BOOST_TEST(m.get_bool(CKA_SIGN, false).error() == CKR_ATTRIBUTE_VALUE_INVALID);
}

// --- One test per rule ------------------------------------------------------

BOOST_AUTO_TEST_CASE(rule_usage_flags_gate_every_operation) {
    using op = hsm::key_operation;
    for (auto o :
         {op::sign, op::verify, op::encrypt, op::decrypt, op::wrap, op::unwrap, op::derive}) {
        const auto attr = hsm::usage_attribute(o);
        BOOST_TEST(hsm::check_usage(key_with({{attr, true}}), o).has_value());
        BOOST_TEST(hsm::check_usage(key_with({{attr, false}}), o).error() ==
                   CKR_KEY_FUNCTION_NOT_PERMITTED);
        BOOST_TEST(hsm::check_usage(key_with({}), o).error() == CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
}

BOOST_AUTO_TEST_CASE(rule_sensitive_or_unextractable_values_are_unreadable) {
    const auto sensitive = key_with({{CKA_SENSITIVE, true}, {CKA_EXTRACTABLE, true}});
    const auto unextractable = key_with({{CKA_SENSITIVE, false}, {CKA_EXTRACTABLE, false}});
    const auto open = key_with({{CKA_SENSITIVE, false}, {CKA_EXTRACTABLE, true}});
    BOOST_TEST(hsm::check_readable(sensitive, CKA_VALUE).error() == CKR_ATTRIBUTE_SENSITIVE);
    BOOST_TEST(hsm::check_readable(unextractable, CKA_VALUE).error() == CKR_ATTRIBUTE_SENSITIVE);
    BOOST_TEST(hsm::check_readable(open, CKA_VALUE).has_value());
    BOOST_TEST(hsm::check_readable(sensitive, CKA_LABEL).has_value());
    const auto rsa_private = key_with({{CKA_SENSITIVE, true}}, CKO_PRIVATE_KEY);
    for (auto t : {CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2,
                   CKA_COEFFICIENT}) {
        BOOST_TEST(hsm::check_readable(rsa_private, t).error() == CKR_ATTRIBUTE_SENSITIVE);
    }
    BOOST_TEST(hsm::check_readable(rsa_private, CKA_MODULUS).has_value());
    // A public key's CKA_VALUE (if any) is public.
    BOOST_TEST(hsm::check_readable(key_with({{CKA_SENSITIVE, true}}, CKO_PUBLIC_KEY), CKA_VALUE)
                   .has_value());
}

BOOST_AUTO_TEST_CASE(rule_sensitive_is_one_way) {
    BOOST_TEST(
        hsm::check_sensitive_change(key_with({{CKA_SENSITIVE, false}}), change(CKA_SENSITIVE, true))
            .has_value());
    BOOST_TEST(
        hsm::check_sensitive_change(key_with({{CKA_SENSITIVE, true}}), change(CKA_SENSITIVE, false))
            .error() == CKR_ATTRIBUTE_READ_ONLY);
    BOOST_TEST(
        hsm::check_sensitive_change(key_with({{CKA_SENSITIVE, true}}), change(CKA_SENSITIVE, true))
            .has_value());
}

BOOST_AUTO_TEST_CASE(rule_extractable_is_one_way) {
    BOOST_TEST(hsm::check_extractable_change(key_with({{CKA_EXTRACTABLE, true}}),
                                             change(CKA_EXTRACTABLE, false))
                   .has_value());
    BOOST_TEST(hsm::check_extractable_change(key_with({{CKA_EXTRACTABLE, false}}),
                                             change(CKA_EXTRACTABLE, true))
                   .error() == CKR_ATTRIBUTE_READ_ONLY);
}

BOOST_AUTO_TEST_CASE(rule_wrap_with_trusted_is_one_way) {
    BOOST_TEST(hsm::check_wrap_with_trusted_change(key_with({{CKA_WRAP_WITH_TRUSTED, false}}),
                                                   change(CKA_WRAP_WITH_TRUSTED, true))
                   .has_value());
    BOOST_TEST(hsm::check_wrap_with_trusted_change(key_with({{CKA_WRAP_WITH_TRUSTED, true}}),
                                                   change(CKA_WRAP_WITH_TRUSTED, false))
                   .error() == CKR_ATTRIBUTE_READ_ONLY);
}

BOOST_AUTO_TEST_CASE(rule_only_the_so_sets_trusted) {
    const auto trusted = change(CKA_TRUSTED, true);
    BOOST_TEST(hsm::check_trusted(trusted, hsm::session_user::so).has_value());
    BOOST_TEST(hsm::check_trusted(trusted, hsm::session_user::user).error() ==
               CKR_ATTRIBUTE_READ_ONLY);
    BOOST_TEST(hsm::check_trusted(trusted, hsm::session_user::none).error() ==
               CKR_ATTRIBUTE_READ_ONLY);
    BOOST_TEST(hsm::check_trusted(change(CKA_TRUSTED, false), hsm::session_user::user).has_value());
}

BOOST_AUTO_TEST_CASE(rule_token_set_attributes_are_not_in_caller_templates) {
    for (auto t : {CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM}) {
        hsm::attribute_map m;
        m.set_bool(t, true);
        BOOST_TEST(hsm::check_caller_settable(m).error() == CKR_ATTRIBUTE_READ_ONLY);
    }
    BOOST_TEST(hsm::check_caller_settable(change(CKA_SIGN, true)).has_value());
}

BOOST_AUTO_TEST_CASE(rule_identity_material_and_templates_are_fixed) {
    for (auto t :
         {CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE, CKA_VALUE_LEN, CKA_MODULUS, CKA_EC_POINT,
          CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE}) {
        hsm::attribute_map m;
        m.set_ulong(t, 1);
        BOOST_TEST_INFO("attribute 0x" << std::hex << t);
        BOOST_TEST(hsm::check_changeable(m).error() == CKR_ATTRIBUTE_READ_ONLY);
    }
    BOOST_TEST(hsm::check_changeable(change(CKA_COPYABLE, true)).error() ==
               CKR_ATTRIBUTE_READ_ONLY);
    BOOST_TEST(hsm::check_changeable(change(CKA_COPYABLE, false)).has_value());
    BOOST_TEST(hsm::check_changeable(change(CKA_DECRYPT, true)).has_value());
}

BOOST_AUTO_TEST_CASE(rule_unmodifiable_objects_refuse_every_change) {
    BOOST_TEST(hsm::check_modifiable(key_with({{CKA_MODIFIABLE, false}})).error() ==
               CKR_ACTION_PROHIBITED);
    BOOST_TEST(hsm::check_modifiable(key_with({{CKA_MODIFIABLE, true}})).has_value());
    BOOST_TEST(hsm::check_modifiable(key_with({})).has_value());  // default true
}

BOOST_AUTO_TEST_CASE(rule_non_extractable_keys_are_never_wrapped) {
    const auto kek = key_with({{CKA_WRAP, true}});
    BOOST_TEST(hsm::check_wrappable(kek, key_with({{CKA_EXTRACTABLE, false}})).error() ==
               CKR_KEY_UNEXTRACTABLE);
    BOOST_TEST(hsm::check_wrappable(kek, key_with({})).error() == CKR_KEY_UNEXTRACTABLE);
    BOOST_TEST(hsm::check_wrappable(kek, key_with({{CKA_EXTRACTABLE, true}})).has_value());
}

BOOST_AUTO_TEST_CASE(rule_wrap_with_trusted_needs_a_trusted_wrapping_key) {
    const auto key = key_with({{CKA_EXTRACTABLE, true}, {CKA_WRAP_WITH_TRUSTED, true}});
    BOOST_TEST(hsm::check_wrappable(key_with({{CKA_WRAP, true}}), key).error() ==
               CKR_KEY_NOT_WRAPPABLE);
    BOOST_TEST(
        hsm::check_wrappable(key_with({{CKA_WRAP, true}, {CKA_TRUSTED, true}}), key).has_value());
}

BOOST_AUTO_TEST_CASE(rule_wrapped_keys_must_match_the_wrap_template) {
    auto kek = key_with({{CKA_WRAP, true}});
    hsm::attribute_map only_sensitive;
    only_sensitive.set_bool(CKA_SENSITIVE, true);
    kek.set_template(CKA_WRAP_TEMPLATE, only_sensitive);
    BOOST_TEST(
        hsm::check_wrappable(kek, key_with({{CKA_EXTRACTABLE, true}, {CKA_SENSITIVE, false}}))
            .error() == CKR_KEY_NOT_WRAPPABLE);
    BOOST_TEST(hsm::check_wrappable(kek, key_with({{CKA_EXTRACTABLE, true}})).error() ==
               CKR_KEY_NOT_WRAPPABLE);
    BOOST_TEST(hsm::check_wrappable(kek, key_with({{CKA_EXTRACTABLE, true}, {CKA_SENSITIVE, true}}))
                   .has_value());
}

BOOST_AUTO_TEST_CASE(rule_unwrap_and_derive_templates_are_applied) {
    auto unwrapper = key_with({{CKA_UNWRAP, true}});
    hsm::attribute_map forced;
    forced.set_bool(CKA_SENSITIVE, true);
    forced.set_bool(CKA_EXTRACTABLE, false);
    unwrapper.set_template(CKA_UNWRAP_TEMPLATE, forced);
    // The template's attributes are added...
    auto merged =
        hsm::apply_key_template(unwrapper, CKA_UNWRAP_TEMPLATE, change(CKA_DECRYPT, true));
    BOOST_REQUIRE(merged.has_value());
    BOOST_TEST(merged->flag(CKA_SENSITIVE));
    BOOST_TEST(!merged->flag(CKA_EXTRACTABLE));
    BOOST_TEST(merged->flag(CKA_DECRYPT));
    // ...agreeing ones are fine, and a contradiction is refused.
    BOOST_TEST(hsm::apply_key_template(unwrapper, CKA_UNWRAP_TEMPLATE, change(CKA_SENSITIVE, true))
                   .has_value());
    BOOST_TEST(
        hsm::apply_key_template(unwrapper, CKA_UNWRAP_TEMPLATE, change(CKA_EXTRACTABLE, true))
            .error() == CKR_TEMPLATE_INCONSISTENT);
    // CKA_DERIVE_TEMPLATE works the same way.
    auto base = key_with({{CKA_DERIVE, true}});
    base.set_template(CKA_DERIVE_TEMPLATE, forced);
    BOOST_TEST(
        hsm::apply_key_template(base, CKA_DERIVE_TEMPLATE, change(CKA_SENSITIVE, false)).error() ==
        CKR_TEMPLATE_INCONSISTENT);
    // No template: the caller's attributes pass unchanged.
    auto plain = hsm::apply_key_template(key_with({}), CKA_UNWRAP_TEMPLATE, change(CKA_SIGN, true));
    BOOST_TEST(*plain == change(CKA_SIGN, true));
}

BOOST_AUTO_TEST_CASE(rule_origin_sets_local_always_sensitive_and_never_extractable) {
    auto generated = key_with({{CKA_SENSITIVE, true}, {CKA_EXTRACTABLE, false}});
    hsm::set_origin_flags(generated, hsm::key_origin::generated);
    BOOST_TEST(generated.flag(CKA_LOCAL));
    BOOST_TEST(generated.flag(CKA_ALWAYS_SENSITIVE));
    BOOST_TEST(generated.flag(CKA_NEVER_EXTRACTABLE));

    auto unwrapped = key_with({{CKA_SENSITIVE, true}, {CKA_EXTRACTABLE, false}});
    hsm::set_origin_flags(unwrapped, hsm::key_origin::unwrapped);
    BOOST_TEST(!unwrapped.flag(CKA_LOCAL));
    BOOST_TEST(!unwrapped.flag(CKA_ALWAYS_SENSITIVE));
    BOOST_TEST(!unwrapped.flag(CKA_NEVER_EXTRACTABLE));

    auto derived = key_with({{CKA_SENSITIVE, true}, {CKA_EXTRACTABLE, false}});
    hsm::set_origin_flags(derived, hsm::key_origin::derived, &generated);
    BOOST_TEST(derived.flag(CKA_ALWAYS_SENSITIVE));
    BOOST_TEST(derived.flag(CKA_NEVER_EXTRACTABLE));
    auto from_unwrapped = key_with({{CKA_SENSITIVE, true}, {CKA_EXTRACTABLE, false}});
    hsm::set_origin_flags(from_unwrapped, hsm::key_origin::derived, &unwrapped);
    BOOST_TEST(!from_unwrapped.flag(CKA_ALWAYS_SENSITIVE));
    BOOST_TEST(!from_unwrapped.flag(CKA_NEVER_EXTRACTABLE));

    // Turning SENSITIVE on later does not make a key ALWAYS_SENSITIVE.
    auto later = key_with({{CKA_SENSITIVE, false}, {CKA_EXTRACTABLE, true}});
    hsm::set_origin_flags(later, hsm::key_origin::generated);
    auto now = hsm::set_attributes(later, change(CKA_SENSITIVE, true), hsm::session_user::user);
    BOOST_REQUIRE(now.has_value());
    BOOST_TEST(now->flag(CKA_SENSITIVE));
    BOOST_TEST(!now->flag(CKA_ALWAYS_SENSITIVE));
}

BOOST_AUTO_TEST_CASE(rule_defaults_are_the_safe_values) {
    auto k = key_with({{CKA_SIGN, true}});
    hsm::apply_key_defaults(k);
    BOOST_TEST(k.flag(CKA_SENSITIVE));
    BOOST_TEST(!k.flag(CKA_EXTRACTABLE));
    BOOST_TEST(!k.flag(CKA_TRUSTED));
    BOOST_TEST(!k.flag(CKA_DECRYPT));
    BOOST_TEST(k.flag(CKA_SIGN));  // what the caller asked for stays
    BOOST_TEST(k.flag(CKA_MODIFIABLE));
    auto open = key_with({{CKA_EXTRACTABLE, true}, {CKA_SENSITIVE, false}});
    hsm::apply_key_defaults(open);
    BOOST_TEST(open.flag(CKA_EXTRACTABLE));
    BOOST_TEST(!open.flag(CKA_SENSITIVE));
}

BOOST_AUTO_TEST_CASE(set_attributes_applies_every_rule) {
    auto k = key_with({{CKA_SENSITIVE, true}, {CKA_EXTRACTABLE, false}, {CKA_MODIFIABLE, true}});
    hsm::set_origin_flags(k, hsm::key_origin::generated);
    using who = hsm::session_user;
    BOOST_TEST(hsm::set_attributes(k, change(CKA_SENSITIVE, false), who::user).error() ==
               CKR_ATTRIBUTE_READ_ONLY);
    BOOST_TEST(hsm::set_attributes(k, change(CKA_EXTRACTABLE, true), who::user).error() ==
               CKR_ATTRIBUTE_READ_ONLY);
    BOOST_TEST(hsm::set_attributes(k, change(CKA_TRUSTED, true), who::user).error() ==
               CKR_ATTRIBUTE_READ_ONLY);
    BOOST_TEST(hsm::set_attributes(k, change(CKA_TRUSTED, true), who::so).has_value());
    BOOST_TEST(hsm::set_attributes(k, change(CKA_ALWAYS_SENSITIVE, false), who::so).error() ==
               CKR_ATTRIBUTE_READ_ONLY);
    auto ok = hsm::set_attributes(k, change(CKA_DECRYPT, true), who::user);
    BOOST_REQUIRE(ok.has_value());
    BOOST_TEST(ok->flag(CKA_DECRYPT));
    auto frozen = k;
    frozen.set_bool(CKA_MODIFIABLE, false);
    BOOST_TEST(hsm::set_attributes(frozen, change(CKA_DECRYPT, true), who::so).error() ==
               CKR_ACTION_PROHIBITED);
}
