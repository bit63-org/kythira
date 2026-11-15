// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// PKCS#11 attribute values as the HSM stores them: a map from attribute type
// to the value's bytes, in the encoding PKCS#11 gives them (CK_BBOOL is one
// byte, CK_ULONG is native width). Template attributes (CKA_WRAP_TEMPLATE,
// CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE) are arrays of CK_ATTRIBUTE in the
// API; here they are flattened into a self-describing byte string so the map
// is a plain value type that can be replicated and compared.
//
// Key material never goes in an attribute_map: secret values and private
// keys are carried in secret_bytes next to it (key_material in
// mechanisms.hpp), and the attribute policy decides what may be read.

#include <kythira/hsm/pkcs11.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <kythira/hsm/expected.hpp>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace kythira::hsm {

/// A PKCS#11 result: the value, or the CK_RV to return.
template<class T> using ck_result = expected<T, CK_RV>;

/// True for the attributes whose value is an array of CK_ATTRIBUTE.
[[nodiscard]] constexpr auto is_template_attribute(CK_ATTRIBUTE_TYPE type) noexcept -> bool {
    return type == CKA_WRAP_TEMPLATE || type == CKA_UNWRAP_TEMPLATE || type == CKA_DERIVE_TEMPLATE;
}

class attribute_map {
public:
    using value_type = std::vector<std::uint8_t>;

    attribute_map() = default;

    /// Reads a caller's template. A null value with a non-zero length is
    /// CKR_ATTRIBUTE_VALUE_INVALID; the same type twice is
    /// CKR_TEMPLATE_INCONSISTENT. Template attributes are flattened, and may
    /// not themselves contain template attributes.
    [[nodiscard]] static auto from_template(std::span<const CK_ATTRIBUTE> attrs,
                                            bool nested = false) -> ck_result<attribute_map> {
        attribute_map out;
        for (const auto& a : attrs) {
            if (a.pValue == nullptr && a.ulValueLen != 0) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            if (out._values.contains(a.type)) {
                return unexpected(CKR_TEMPLATE_INCONSISTENT);
            }
            if (is_template_attribute(a.type)) {
                if (nested || a.ulValueLen % sizeof(CK_ATTRIBUTE) != 0) {
                    return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
                }
                const std::span inner(static_cast<const CK_ATTRIBUTE*>(a.pValue),
                                      a.ulValueLen / sizeof(CK_ATTRIBUTE));
                auto parsed = from_template(inner, true);
                if (!parsed) {
                    return unexpected(parsed.error());
                }
                out._values.emplace(a.type, parsed->flatten());
                continue;
            }
            const auto* p = static_cast<const std::uint8_t*>(a.pValue);
            out._values.emplace(a.type, value_type(p, p + a.ulValueLen));
        }
        return out;
    }

    [[nodiscard]] auto has(CK_ATTRIBUTE_TYPE type) const -> bool { return _values.contains(type); }
    [[nodiscard]] auto size() const noexcept -> std::size_t { return _values.size(); }
    [[nodiscard]] auto empty() const noexcept -> bool { return _values.empty(); }
    [[nodiscard]] auto begin() const { return _values.begin(); }
    [[nodiscard]] auto end() const { return _values.end(); }

    [[nodiscard]] auto bytes(CK_ATTRIBUTE_TYPE type) const
        -> std::optional<std::span<const std::uint8_t>> {
        auto it = _values.find(type);
        if (it == _values.end()) {
            return std::nullopt;
        }
        return std::span<const std::uint8_t>(it->second);
    }

    /// A CK_BBOOL attribute: absent gives `fallback`, a value that is not one
    /// byte is CKR_ATTRIBUTE_VALUE_INVALID.
    [[nodiscard]] auto get_bool(CK_ATTRIBUTE_TYPE type, bool fallback) const -> ck_result<bool> {
        auto it = _values.find(type);
        if (it == _values.end()) {
            return fallback;
        }
        if (it->second.size() != sizeof(CK_BBOOL)) {
            return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        return it->second[0] != CK_FALSE;
    }

    /// The flag's value, false when absent or malformed (for stored objects,
    /// whose attributes were validated when they were made).
    [[nodiscard]] auto flag(CK_ATTRIBUTE_TYPE type) const -> bool {
        return get_bool(type, false).value_or(false);
    }

    [[nodiscard]] auto get_ulong(CK_ATTRIBUTE_TYPE type) const
        -> ck_result<std::optional<CK_ULONG>> {
        auto it = _values.find(type);
        if (it == _values.end()) {
            return std::optional<CK_ULONG>{};
        }
        if (it->second.size() != sizeof(CK_ULONG)) {
            return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        CK_ULONG v = 0;
        std::memcpy(&v, it->second.data(), sizeof v);
        return std::optional<CK_ULONG>{v};
    }

    /// A template attribute's contents.
    [[nodiscard]] auto get_template(CK_ATTRIBUTE_TYPE type) const -> ck_result<attribute_map> {
        auto it = _values.find(type);
        if (it == _values.end()) {
            return attribute_map{};
        }
        return unflatten(it->second);
    }

    void set_bool(CK_ATTRIBUTE_TYPE type, bool v) {
        _values[type] = value_type{static_cast<std::uint8_t>(v ? CK_TRUE : CK_FALSE)};
    }

    void set_ulong(CK_ATTRIBUTE_TYPE type, CK_ULONG v) {
        value_type bytes(sizeof v);
        std::memcpy(bytes.data(), &v, sizeof v);
        _values[type] = std::move(bytes);
    }

    void set_bytes(CK_ATTRIBUTE_TYPE type, std::span<const std::uint8_t> v) {
        _values[type] = value_type(v.begin(), v.end());
    }

    void set_template(CK_ATTRIBUTE_TYPE type, const attribute_map& inner) {
        _values[type] = inner.flatten();
    }

    void erase(CK_ATTRIBUTE_TYPE type) { _values.erase(type); }

    /// Adds every attribute of `other`, replacing values already present.
    void merge(const attribute_map& other) {
        for (const auto& [type, value] : other._values) {
            _values[type] = value;
        }
    }

    /// True when every attribute in `required` is present here with an equal
    /// value: how PKCS#11 matches a key against a wrap or unwrap template.
    [[nodiscard]] auto satisfies(const attribute_map& required) const -> bool {
        for (const auto& [type, value] : required._values) {
            auto it = _values.find(type);
            if (it == _values.end() || it->second != value) {
                return false;
            }
        }
        return true;
    }

    auto operator==(const attribute_map&) const -> bool = default;

private:
    // type (8 bytes LE) | length (8 bytes LE) | value, repeated.
    [[nodiscard]] auto flatten() const -> value_type {
        value_type out;
        for (const auto& [type, value] : _values) {
            put_u64(out, type);
            put_u64(out, value.size());
            out.insert(out.end(), value.begin(), value.end());
        }
        return out;
    }

    [[nodiscard]] static auto unflatten(std::span<const std::uint8_t> in)
        -> ck_result<attribute_map> {
        attribute_map out;
        std::size_t at = 0;
        while (at < in.size()) {
            if (in.size() - at < 16) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            const auto type = get_u64(in.subspan(at, 8));
            const auto len = get_u64(in.subspan(at + 8, 8));
            at += 16;
            if (len > in.size() - at) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            const auto value = in.subspan(at, static_cast<std::size_t>(len));
            out._values.emplace(static_cast<CK_ATTRIBUTE_TYPE>(type),
                                value_type(value.begin(), value.end()));
            at += static_cast<std::size_t>(len);
        }
        return out;
    }

    static void put_u64(value_type& out, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
        }
    }

    [[nodiscard]] static auto get_u64(std::span<const std::uint8_t> in) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 7; i >= 0; --i) {
            v = (v << 8U) | in[static_cast<std::size_t>(i)];
        }
        return v;
    }

    std::map<CK_ATTRIBUTE_TYPE, value_type> _values;
};

}  // namespace kythira::hsm
