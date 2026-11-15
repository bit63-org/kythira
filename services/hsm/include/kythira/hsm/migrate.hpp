// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// hsm_ctl migrate (.kiro/specs/virtual-hsm/ task 12b, Requirement 9.3):
// copy a token's keys from the virtual HSM to an external PKCS#11 module,
// so a cluster can move to hardware without re-issuing what it may move.
//
// Keys never leave either module in the clear. The target makes an RSA
// transport key pair (or uses one the operator names); its public half is
// imported into the source as a session object; the source makes a
// session AES-256 key, wraps it to the target with RSA-OAEP, and the
// target unwraps it. Every extractable key then travels wrapped under that
// AES key with AES key wrap with padding (RFC 5649) and is unwrapped by
// the target as a token object, sensitive and, unless asked otherwise, no
// longer extractable. A key pair's public half and every certificate are
// public and are created as they are. The transport keys are session
// objects on both sides and go when the sessions close.
//
// What cannot move is reported, not forced: a key that is not extractable
// needs re-issuing on the target (the virtual HSM makes keys
// non-extractable unless asked, so most do); data objects are left to the
// operator. An object the target already holds (same class, label and id)
// is left alone, so a run can be repeated after a failure.
//
// The target must unwrap with RSA-OAEP and with RFC 5649 key wrap, as
// CKM_AES_KEY_WRAP_KWP or, as SoftHSM2 and CloudHSM's older SDK name it,
// CKM_AES_KEY_WRAP_PAD (the same bytes there). A module without them (the
// YubiHSM 2, whose only key wrap is its own AES-CCM) is refused before
// anything is copied; such a module needs its vendor's import tool, fed
// with keys re-issued for it.
//
// RSA-OAEP is tried with SHA-256 first, then with SHA-1, which SoftHSM2
// 2.6 needs and which is still sound for OAEP.

#include <kythira/hsm/pkcs11.hpp>

#include <raft/pkcs11_module.hpp>
#include <raft/pkcs11_uri.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::hsm {

struct migrate_options {
    /// Report what would happen and change nothing on either side.
    bool dry_run = false;
    /// Keep CKA_EXTRACTABLE true on the target (default: false there).
    bool keep_extractable = false;
    /// The target's RSA private key to unwrap the transport key with
    /// (CKA_UNWRAP); by default a session key pair is made for the run.
    std::optional<pkcs11::uri> transport_key;
};

enum class migrate_outcome : std::uint8_t {
    copied,         ///< now on the target (or would be, in a dry run)
    exists,         ///< the target holds this class, label and id already
    needs_reissue,  ///< not extractable: make a new key on the target
    skipped,        ///< not a key or certificate (data objects)
    failed          ///< the copy was attempted and refused; see detail
};

[[nodiscard]] constexpr auto outcome_name(migrate_outcome o) -> std::string_view {
    switch (o) {
        case migrate_outcome::copied:
            return "copied";
        case migrate_outcome::exists:
            return "exists";
        case migrate_outcome::needs_reissue:
            return "needs_reissue";
        case migrate_outcome::skipped:
            return "skipped";
        case migrate_outcome::failed:
            return "failed";
    }
    return "failed";
}

struct migrate_entry {
    CK_OBJECT_CLASS object_class = CKO_DATA;
    std::optional<CK_KEY_TYPE> key_type;
    std::string label;
    std::vector<std::uint8_t> id;
    migrate_outcome outcome = migrate_outcome::failed;
    std::string detail;
};

struct migrate_report {
    bool dry_run = false;
    /// The target's RFC 5649 mechanism and the OAEP hash used.
    CK_MECHANISM_TYPE unwrap_mechanism = CKM_AES_KEY_WRAP_KWP;
    std::string oaep_hash;
    std::vector<migrate_entry> entries;

    [[nodiscard]] auto count(migrate_outcome o) const -> std::size_t {
        return static_cast<std::size_t>(
            std::ranges::count_if(entries, [o](const migrate_entry& e) { return e.outcome == o; }));
    }
    /// Nothing attempted was refused.
    [[nodiscard]] auto ok() const -> bool { return count(migrate_outcome::failed) == 0; }
};

namespace detail::migrate {

using pkcs11::attribute;
using pkcs11::bytes;

[[nodiscard]] inline auto flag(const std::optional<bytes>& v) -> std::optional<bool> {
    if (!v || v->size() != 1) {
        return std::nullopt;
    }
    return v->front() != CK_FALSE;
}

[[nodiscard]] inline auto text(const std::optional<bytes>& v) -> std::string {
    return v ? std::string(v->begin(), v->end()) : std::string();
}

/// The usage flags a key carries, copied to the target as they are.
inline constexpr std::array<CK_ATTRIBUTE_TYPE, 7> usage_flags{
    CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE};

/// The attributes a public key is made from, by key type.
[[nodiscard]] inline auto public_parts(CK_KEY_TYPE t) -> std::vector<CK_ATTRIBUTE_TYPE> {
    if (t == CKK_RSA) {
        return {CKA_MODULUS, CKA_PUBLIC_EXPONENT};
    }
    return {CKA_EC_PARAMS, CKA_EC_POINT};
}

/// Every object of `cls` on the token (session objects left out).
[[nodiscard]] inline auto token_objects(pkcs11::backend& b, CK_SESSION_HANDLE s,
                                        CK_OBJECT_CLASS cls) -> std::vector<CK_OBJECT_HANDLE> {
    const std::array<attribute, 2> tmpl{attribute::of_ulong(CKA_CLASS, cls),
                                        attribute::of_bool(CKA_TOKEN, true)};
    return b.find_objects(s, tmpl);
}

[[nodiscard]] inline auto oaep(pkcs11::hash_algorithm h, CK_RSA_PKCS_OAEP_PARAMS& p)
    -> CK_MECHANISM {
    p = {pkcs11::detail::hash_mechanism(h), pkcs11::detail::mgf(h), CKZ_DATA_SPECIFIED, nullptr, 0};
    return {CKM_RSA_PKCS_OAEP, &p, sizeof p};
}

}  // namespace detail::migrate

/// Copies `from`'s token objects to `to`'s token. Throws pkcs11::error
/// when the run cannot start (a module lacks a mechanism, the transport
/// key cannot be made or moved); a refusal for one object is reported in
/// its entry and the run goes on.
inline auto migrate(pkcs11::session& from, pkcs11::session& to, const migrate_options& opts = {})
    -> migrate_report {
    namespace m = detail::migrate;
    using pkcs11::attribute;
    using pkcs11::bytes;

    auto src = from.unrestricted();
    auto dst = to.unrestricted();
    migrate_report report;
    report.dry_run = opts.dry_run;

    // What each side can do.
    const auto has = [](const std::vector<CK_MECHANISM_TYPE>& list, CK_MECHANISM_TYPE t) {
        return std::ranges::find(list, t) != list.end();
    };
    const auto src_mechs = src.b.mechanisms(from.slot());
    const auto dst_mechs = dst.b.mechanisms(to.slot());
    if (!has(src_mechs, CKM_AES_KEY_WRAP_KWP) || !has(src_mechs, CKM_RSA_PKCS_OAEP)) {
        throw pkcs11::error("migrate: the source cannot wrap with AES-KWP and RSA-OAEP",
                            CKR_MECHANISM_INVALID);
    }
    if (!has(dst_mechs, CKM_RSA_PKCS_OAEP)) {
        throw pkcs11::error("migrate: the target cannot unwrap with RSA-OAEP",
                            CKR_MECHANISM_INVALID);
    }
    if (has(dst_mechs, CKM_AES_KEY_WRAP_KWP)) {
        report.unwrap_mechanism = CKM_AES_KEY_WRAP_KWP;
    } else if (has(dst_mechs, CKM_AES_KEY_WRAP_PAD)) {
        report.unwrap_mechanism = CKM_AES_KEY_WRAP_PAD;
    } else {
        throw pkcs11::error(
            "migrate: the target has no AES key wrap with padding (RFC 5649); it needs its "
            "vendor's import tool and keys re-issued for it",
            CKR_MECHANISM_INVALID);
    }

    // The inventory, with what would happen to each object.
    struct item {
        CK_OBJECT_HANDLE handle;
        migrate_entry entry;
        std::vector<std::optional<bytes>> usage;
        std::optional<CK_OBJECT_HANDLE> public_half;
    };
    std::vector<item> items;
    const auto exists_on_target = [&](CK_OBJECT_CLASS cls, const migrate_entry& e) {
        const std::array<attribute, 4> tmpl{
            attribute::of_ulong(CKA_CLASS, cls), attribute::of_bool(CKA_TOKEN, true),
            attribute::of_string(CKA_LABEL, e.label), attribute::of_bytes(CKA_ID, e.id)};
        return !dst.b.find_objects(dst.handle, tmpl).empty();
    };
    static constexpr std::array<CK_ATTRIBUTE_TYPE, 4> ident{CKA_LABEL, CKA_ID, CKA_KEY_TYPE,
                                                            CKA_EXTRACTABLE};
    for (const CK_OBJECT_CLASS cls : {CKO_SECRET_KEY, CKO_PRIVATE_KEY}) {
        for (const auto h : m::token_objects(src.b, src.handle, cls)) {
            auto v = src.b.get_attributes(src.handle, h, ident);
            item it{h, {}, src.b.get_attributes(src.handle, h, m::usage_flags), std::nullopt};
            it.entry.object_class = cls;
            it.entry.label = m::text(v[0]);
            it.entry.id = v[1].value_or(bytes{});
            it.entry.key_type = pkcs11::as_ulong(v[2]);
            if (exists_on_target(cls, it.entry)) {
                it.entry.outcome = migrate_outcome::exists;
            } else if (!m::flag(v[3]).value_or(false)) {
                it.entry.outcome = migrate_outcome::needs_reissue;
                it.entry.detail = "not extractable";
            } else {
                it.entry.outcome = migrate_outcome::copied;
            }
            if (cls == CKO_PRIVATE_KEY && it.entry.outcome == migrate_outcome::copied &&
                it.entry.key_type) {
                const std::array<attribute, 4> tmpl{
                    attribute::of_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
                    attribute::of_bool(CKA_TOKEN, true),
                    attribute::of_ulong(CKA_KEY_TYPE, *it.entry.key_type),
                    attribute::of_bytes(CKA_ID, it.entry.id)};
                const auto pub = src.b.find_objects(src.handle, tmpl);
                if (pub.size() == 1) {
                    it.public_half = pub.front();
                }
            }
            items.push_back(std::move(it));
        }
    }
    struct certificate {
        CK_OBJECT_HANDLE handle;
        migrate_entry entry;
    };
    std::vector<certificate> certs;
    for (const auto h : m::token_objects(src.b, src.handle, CKO_CERTIFICATE)) {
        static constexpr std::array<CK_ATTRIBUTE_TYPE, 2> types{CKA_LABEL, CKA_ID};
        auto v = src.b.get_attributes(src.handle, h, types);
        certificate c{h, {}};
        c.entry.object_class = CKO_CERTIFICATE;
        c.entry.label = m::text(v[0]);
        c.entry.id = v[1].value_or(bytes{});
        c.entry.outcome = exists_on_target(CKO_CERTIFICATE, c.entry) ? migrate_outcome::exists
                                                                     : migrate_outcome::copied;
        certs.push_back(std::move(c));
    }
    for (const auto h : m::token_objects(src.b, src.handle, CKO_DATA)) {
        static constexpr std::array<CK_ATTRIBUTE_TYPE, 1> types{CKA_LABEL};
        migrate_entry e;
        e.object_class = CKO_DATA;
        e.label = m::text(src.b.get_attributes(src.handle, h, types)[0]);
        e.outcome = migrate_outcome::skipped;
        e.detail = "data objects are not migrated";
        report.entries.push_back(std::move(e));
    }

    if (opts.dry_run) {
        for (auto& it : items) {
            report.entries.push_back(std::move(it.entry));
        }
        for (auto& c : certs) {
            report.entries.push_back(std::move(c.entry));
        }
        return report;
    }
    const bool any_key = std::ranges::any_of(
        items, [](const item& it) { return it.entry.outcome == migrate_outcome::copied; });

    // The transport keys, when there is a key to carry.
    std::optional<CK_OBJECT_HANDLE> src_aes;
    std::optional<CK_OBJECT_HANDLE> dst_aes;
    if (any_key) {
        CK_OBJECT_HANDLE dst_rsa = CK_INVALID_HANDLE;
        pkcs11::public_key_info rsa_pub;
        if (opts.transport_key) {
            dst_rsa = to.find(*opts.transport_key);
            rsa_pub = to.public_key(dst_rsa);
            if (rsa_pub.key_type != CKK_RSA) {
                throw pkcs11::error("migrate: the transport key is not RSA",
                                    CKR_KEY_TYPE_INCONSISTENT);
            }
        } else {
            CK_MECHANISM gen{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
            const std::array<attribute, 6> pub{
                attribute::of_bool(CKA_TOKEN, false),
                attribute::of_bool(CKA_WRAP, true),
                attribute::of_bool(CKA_ENCRYPT, false),
                attribute::of_bool(CKA_VERIFY, false),
                attribute::of_ulong(CKA_MODULUS_BITS, 3072),
                attribute::of_bytes(CKA_PUBLIC_EXPONENT, std::array<std::uint8_t, 3>{1, 0, 1})};
            const std::array<attribute, 7> priv{
                attribute::of_bool(CKA_TOKEN, false),    attribute::of_bool(CKA_PRIVATE, true),
                attribute::of_bool(CKA_SENSITIVE, true), attribute::of_bool(CKA_EXTRACTABLE, false),
                attribute::of_bool(CKA_UNWRAP, true),    attribute::of_bool(CKA_DECRYPT, false),
                attribute::of_bool(CKA_SIGN, false)};
            dst_rsa = dst.b.generate_key_pair(dst.handle, gen, pub, priv).second;
            rsa_pub = to.public_key(dst_rsa);
        }
        // The target's public key in the source, to wrap to.
        const std::array<attribute, 7> imported{
            attribute::of_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
            attribute::of_ulong(CKA_KEY_TYPE, CKK_RSA),
            attribute::of_bool(CKA_TOKEN, false),
            attribute::of_bool(CKA_WRAP, true),
            attribute::of_bool(CKA_ENCRYPT, false),
            attribute::of_bytes(CKA_MODULUS, rsa_pub.modulus),
            attribute::of_bytes(CKA_PUBLIC_EXPONENT, rsa_pub.public_exponent)};
        const auto src_rsa = src.b.create_object(src.handle, imported);

        CK_MECHANISM aes_gen{CKM_AES_KEY_GEN, nullptr, 0};
        const std::array<attribute, 9> aes{attribute::of_ulong(CKA_CLASS, CKO_SECRET_KEY),
                                           attribute::of_ulong(CKA_KEY_TYPE, CKK_AES),
                                           attribute::of_ulong(CKA_VALUE_LEN, 32),
                                           attribute::of_bool(CKA_TOKEN, false),
                                           attribute::of_bool(CKA_SENSITIVE, true),
                                           attribute::of_bool(CKA_EXTRACTABLE, true),
                                           attribute::of_bool(CKA_WRAP, true),
                                           attribute::of_bool(CKA_ENCRYPT, false),
                                           attribute::of_bool(CKA_DECRYPT, false)};
        src_aes = src.b.generate_key(src.handle, aes_gen, aes);

        const std::array<attribute, 8> landed{attribute::of_ulong(CKA_CLASS, CKO_SECRET_KEY),
                                              attribute::of_ulong(CKA_KEY_TYPE, CKK_AES),
                                              attribute::of_bool(CKA_TOKEN, false),
                                              attribute::of_bool(CKA_SENSITIVE, true),
                                              attribute::of_bool(CKA_EXTRACTABLE, false),
                                              attribute::of_bool(CKA_UNWRAP, true),
                                              attribute::of_bool(CKA_ENCRYPT, false),
                                              attribute::of_bool(CKA_DECRYPT, false)};
        std::optional<pkcs11::error> last;
        for (const auto h : {pkcs11::hash_algorithm::sha256, pkcs11::hash_algorithm::sha1}) {
            CK_RSA_PKCS_OAEP_PARAMS p{};
            const auto mech = m::oaep(h, p);
            try {
                const auto wrapped = src.b.wrap_key(src.handle, mech, src_rsa, *src_aes);
                dst_aes = dst.b.unwrap_key(dst.handle, mech, dst_rsa, wrapped, landed);
                report.oaep_hash = h == pkcs11::hash_algorithm::sha256 ? "SHA-256" : "SHA-1";
                break;
            } catch (const pkcs11::error& e) {
                last = e;
            }
        }
        if (!dst_aes) {
            throw pkcs11::error(std::string("migrate: moving the transport key failed (") +
                                    (last ? last->what() : "") + ")",
                                last ? last->rv() : CKR_FUNCTION_FAILED);
        }
    }

    // The keys.
    CK_MECHANISM kwp{CKM_AES_KEY_WRAP_KWP, nullptr, 0};
    CK_MECHANISM unkwp{report.unwrap_mechanism, nullptr, 0};
    for (auto& it : items) {
        if (it.entry.outcome != migrate_outcome::copied) {
            report.entries.push_back(std::move(it.entry));
            continue;
        }
        try {
            if (!it.entry.key_type) {
                throw pkcs11::error("no key type", CKR_KEY_TYPE_INCONSISTENT);
            }
            std::vector<attribute> tmpl{attribute::of_ulong(CKA_CLASS, it.entry.object_class),
                                        attribute::of_ulong(CKA_KEY_TYPE, *it.entry.key_type),
                                        attribute::of_bool(CKA_TOKEN, true),
                                        attribute::of_bool(CKA_PRIVATE, true),
                                        attribute::of_bool(CKA_SENSITIVE, true),
                                        attribute::of_bool(CKA_EXTRACTABLE, opts.keep_extractable),
                                        attribute::of_string(CKA_LABEL, it.entry.label),
                                        attribute::of_bytes(CKA_ID, it.entry.id)};
            for (std::size_t i = 0; i < m::usage_flags.size(); ++i) {
                const auto t = m::usage_flags.at(i);
                const bool private_key = it.entry.object_class == CKO_PRIVATE_KEY;
                // A private key cannot carry its public half's usages.
                if (private_key && (t == CKA_ENCRYPT || t == CKA_VERIFY || t == CKA_WRAP)) {
                    continue;
                }
                if (const auto f = m::flag(it.usage.at(i))) {
                    tmpl.push_back(attribute::of_bool(t, *f));
                }
            }
            const auto wrapped = src.b.wrap_key(src.handle, kwp, *src_aes, it.handle);
            (void)dst.b.unwrap_key(dst.handle, unkwp, *dst_aes, wrapped, tmpl);
            if (it.public_half) {
                migrate_entry pub_entry = it.entry;
                pub_entry.object_class = CKO_PUBLIC_KEY;
                if (exists_on_target(CKO_PUBLIC_KEY, pub_entry)) {
                    pub_entry.outcome = migrate_outcome::exists;
                } else {
                    const auto parts = m::public_parts(*it.entry.key_type);
                    auto values = src.b.get_attributes(src.handle, *it.public_half, parts);
                    static constexpr std::array<CK_ATTRIBUTE_TYPE, 3> pub_usage{
                        CKA_VERIFY, CKA_ENCRYPT, CKA_WRAP};
                    auto usage = src.b.get_attributes(src.handle, *it.public_half, pub_usage);
                    std::vector<attribute> pub{
                        attribute::of_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
                        attribute::of_ulong(CKA_KEY_TYPE, *it.entry.key_type),
                        attribute::of_bool(CKA_TOKEN, true),
                        attribute::of_string(CKA_LABEL, it.entry.label),
                        attribute::of_bytes(CKA_ID, it.entry.id)};
                    for (std::size_t i = 0; i < parts.size(); ++i) {
                        if (values[i]) {
                            pub.push_back({parts[i], std::move(*values[i])});
                        }
                    }
                    for (std::size_t i = 0; i < pub_usage.size(); ++i) {
                        if (const auto f = m::flag(usage[i])) {
                            pub.push_back(attribute::of_bool(pub_usage.at(i), *f));
                        }
                    }
                    (void)dst.b.create_object(dst.handle, pub);
                    pub_entry.outcome = migrate_outcome::copied;
                }
                report.entries.push_back(std::move(it.entry));
                report.entries.push_back(std::move(pub_entry));
                continue;
            }
        } catch (const pkcs11::error& e) {
            it.entry.outcome = migrate_outcome::failed;
            it.entry.detail = e.what();
        }
        report.entries.push_back(std::move(it.entry));
    }

    // Certificates are public: created as they are.
    static constexpr std::array<CK_ATTRIBUTE_TYPE, 6> cert_parts{
        CKA_CERTIFICATE_TYPE, CKA_SUBJECT, CKA_ISSUER,
        CKA_SERIAL_NUMBER,    CKA_VALUE,   CKA_CERTIFICATE_CATEGORY};
    for (auto& c : certs) {
        if (c.entry.outcome == migrate_outcome::copied) {
            try {
                auto values = src.b.get_attributes(src.handle, c.handle, cert_parts);
                std::vector<attribute> tmpl{attribute::of_ulong(CKA_CLASS, CKO_CERTIFICATE),
                                            attribute::of_bool(CKA_TOKEN, true),
                                            attribute::of_string(CKA_LABEL, c.entry.label),
                                            attribute::of_bytes(CKA_ID, c.entry.id)};
                for (std::size_t i = 0; i < cert_parts.size(); ++i) {
                    if (values[i]) {
                        tmpl.push_back({cert_parts.at(i), std::move(*values[i])});
                    }
                }
                (void)dst.b.create_object(dst.handle, tmpl);
            } catch (const pkcs11::error& e) {
                c.entry.outcome = migrate_outcome::failed;
                c.entry.detail = e.what();
            }
        }
        report.entries.push_back(std::move(c.entry));
    }
    return report;
}

}  // namespace kythira::hsm
