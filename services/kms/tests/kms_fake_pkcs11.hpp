// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An in-memory pkcs11::backend for the KMS's job tests: objects with
// attributes, generation with random "material" the test can look for,
// and a switch that makes every call fail as a sealed virtual HSM does
// (CKR_DEVICE_ERROR). It implements only what backing_store calls.

#include <raft/pkcs11_module.hpp>

#include <openssl/rand.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace kythira::kms::test {

namespace p11 = kythira::pkcs11;

class fake_backend final : public p11::backend {
public:
    struct object {
        std::map<CK_ATTRIBUTE_TYPE, p11::bytes> attrs;
        p11::bytes material;  // what a real token would keep secret
    };

    bool sealed = false;
    int generated = 0;

    [[nodiscard]] auto library() -> p11::library_info override { return {}; }
    [[nodiscard]] auto tokens() -> std::vector<p11::token_info> override { return {}; }
    [[nodiscard]] auto mechanisms(CK_SLOT_ID) -> std::vector<CK_MECHANISM_TYPE> override {
        return {};
    }
    [[nodiscard]] auto open_session(CK_SLOT_ID) -> CK_SESSION_HANDLE override {
        const std::lock_guard l(_mu);
        return ++_sessions;
    }
    void close_session(CK_SESSION_HANDLE) override {}
    void login(CK_SESSION_HANDLE, std::string_view pin) override {
        if (pin != "1234") {
            throw p11::error("login", CKR_PIN_INCORRECT);
        }
    }

    [[nodiscard]] auto find_objects(CK_SESSION_HANDLE, std::span<const p11::attribute> tmpl)
        -> std::vector<CK_OBJECT_HANDLE> override {
        const std::lock_guard l(_mu);
        std::vector<CK_OBJECT_HANDLE> out;
        for (const auto& [h, o] : _objects) {
            bool match = true;
            for (const auto& a : tmpl) {
                const auto it = o.attrs.find(a.type);
                match = match && it != o.attrs.end() && it->second == a.value;
            }
            if (match) {
                out.push_back(h);
            }
        }
        return out;
    }

    [[nodiscard]] auto get_attributes(CK_SESSION_HANDLE, CK_OBJECT_HANDLE o,
                                      std::span<const CK_ATTRIBUTE_TYPE> types)
        -> std::vector<std::optional<p11::bytes>> override {
        const std::lock_guard l(_mu);
        std::vector<std::optional<p11::bytes>> out;
        const auto& obj = _objects.at(o);
        for (const auto t : types) {
            const auto it = obj.attrs.find(t);
            out.push_back(it == obj.attrs.end() ? std::nullopt
                                                : std::optional<p11::bytes>(it->second));
        }
        return out;
    }

    [[nodiscard]] auto generate_key(CK_SESSION_HANDLE, const CK_MECHANISM& m,
                                    std::span<const p11::attribute> tmpl)
        -> CK_OBJECT_HANDLE override {
        check_unsealed();
        if (m.mechanism != CKM_AES_KEY_GEN && m.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            throw p11::error("generate_key", CKR_MECHANISM_INVALID);
        }
        return add(tmpl, 32);
    }

    [[nodiscard]] auto generate_key_pair(CK_SESSION_HANDLE, const CK_MECHANISM& m,
                                         std::span<const p11::attribute> pub,
                                         std::span<const p11::attribute> priv)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> override {
        check_unsealed();
        if (m.mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN && m.mechanism != CKM_EC_KEY_PAIR_GEN) {
            throw p11::error("generate_key_pair", CKR_MECHANISM_INVALID);
        }
        std::vector<p11::attribute> p(pub.begin(), pub.end());
        p.push_back(p11::attribute::of_ulong(CKA_CLASS, CKO_PUBLIC_KEY));
        std::vector<p11::attribute> s(priv.begin(), priv.end());
        s.push_back(p11::attribute::of_ulong(CKA_CLASS, CKO_PRIVATE_KEY));
        const auto ph = add(p, 0);
        return {ph, add(s, 64)};
    }

    [[nodiscard]] auto create_object(CK_SESSION_HANDLE, std::span<const p11::attribute>)
        -> CK_OBJECT_HANDLE override {
        throw p11::error("create_object", CKR_FUNCTION_NOT_SUPPORTED);
    }
    void destroy_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE o) override {
        check_unsealed();
        const std::lock_guard l(_mu);
        if (_objects.erase(o) == 0) {
            throw p11::error("destroy_object", CKR_OBJECT_HANDLE_INVALID);
        }
    }
    [[nodiscard]] auto sign(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                            std::span<const std::uint8_t>) -> p11::bytes override {
        throw p11::error("sign", CKR_FUNCTION_NOT_SUPPORTED);
    }
    [[nodiscard]] auto verify(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                              std::span<const std::uint8_t>, std::span<const std::uint8_t>)
        -> bool override {
        throw p11::error("verify", CKR_FUNCTION_NOT_SUPPORTED);
    }
    [[nodiscard]] auto encrypt(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                               std::span<const std::uint8_t>) -> p11::bytes override {
        throw p11::error("encrypt", CKR_FUNCTION_NOT_SUPPORTED);
    }
    [[nodiscard]] auto decrypt(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                               std::span<const std::uint8_t>) -> p11::bytes override {
        throw p11::error("decrypt", CKR_FUNCTION_NOT_SUPPORTED);
    }
    [[nodiscard]] auto wrap_key(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                                CK_OBJECT_HANDLE) -> p11::bytes override {
        throw p11::error("wrap_key", CKR_FUNCTION_NOT_SUPPORTED);
    }
    [[nodiscard]] auto unwrap_key(CK_SESSION_HANDLE, const CK_MECHANISM&, CK_OBJECT_HANDLE,
                                  std::span<const std::uint8_t>, std::span<const p11::attribute>)
        -> CK_OBJECT_HANDLE override {
        throw p11::error("unwrap_key", CKR_FUNCTION_NOT_SUPPORTED);
    }

    /// Adds an object with `label` (a stray, or another application's).
    auto plant(const std::string& label, CK_OBJECT_CLASS cls = CKO_SECRET_KEY) -> CK_OBJECT_HANDLE {
        const std::vector<p11::attribute> t{p11::attribute::of_ulong(CKA_CLASS, cls),
                                            p11::attribute::of_string(CKA_LABEL, label)};
        return add(t, 32);
    }

    [[nodiscard]] auto objects() const -> std::map<CK_OBJECT_HANDLE, object> {
        const std::lock_guard l(_mu);
        return _objects;
    }

private:
    void check_unsealed() const {
        if (sealed) {
            throw p11::error("sealed", CKR_DEVICE_ERROR);
        }
    }

    auto add(std::span<const p11::attribute> tmpl, std::size_t material) -> CK_OBJECT_HANDLE {
        const std::lock_guard l(_mu);
        object o;
        for (const auto& a : tmpl) {
            o.attrs[a.type] = a.value;
        }
        o.material.resize(material);
        if (material > 0 &&
            RAND_bytes(o.material.data(), static_cast<int>(o.material.size())) != 1) {
            throw std::runtime_error("RAND_bytes");
        }
        ++generated;
        const auto h = _next++;
        _objects.emplace(h, std::move(o));
        return h;
    }

    mutable std::mutex _mu;
    CK_SESSION_HANDLE _sessions = 0;
    CK_OBJECT_HANDLE _next = 0x1000;
    std::map<CK_OBJECT_HANDLE, object> _objects;
};

}  // namespace kythira::kms::test
