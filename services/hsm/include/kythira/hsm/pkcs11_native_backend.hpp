// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// core's kythira::pkcs11::backend over this node's session layer (task 12;
// design "PKCS#11 is the only boundary consumers see"): what a module
// co-located with the virtual HSM hands to kythira::pkcs11::module, so it
// uses the HSM in process through the same calls it would make on a
// dlopen'd libkythira_pkcs11.so or on real hardware.
//
// It is one native_client, so one application with the identity given
// here: it sees only the tokens the catalog binds to that identity, and
// needs their PINs, like any other client. CK_INFO, CK_SLOT_INFO and
// CK_TOKEN_INFO read as they do through libkythira_pkcs11.so
// (client_types.hpp), so a URI written for one matches the other.

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/client_types.hpp>
#include <kythira/hsm/mechanisms.hpp>
#include <kythira/hsm/native_client.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/session_layer.hpp>

#include <raft/pkcs11_module.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::hsm {

class pkcs11_native_backend final : public pkcs11::backend {
public:
    pkcs11_native_backend(session_layer& layer, std::string identity)
        : _client(layer, std::move(identity)) {}

    [[nodiscard]] auto library() -> pkcs11::library_info override {
        return {std::string(client_manufacturer), std::string(client_library_description),
                client_library_version};
    }

    [[nodiscard]] auto tokens() -> std::vector<pkcs11::token_info> override {
        std::vector<pkcs11::token_info> out;
        for (const auto slot : _client.get_slot_list()) {
            auto t = _client.get_token_info(slot);
            if (!t) {
                continue;  // unbound or deleted meanwhile
            }
            out.push_back({slot, client_slot_description(slot), std::string(client_manufacturer),
                           t->label, std::string(client_manufacturer),
                           std::string(client_token_model), client_token_serial(slot),
                           t->flags | CKF_RNG | CKF_LOGIN_REQUIRED});
        }
        return out;
    }

    [[nodiscard]] auto mechanisms(CK_SLOT_ID /*slot*/) -> std::vector<CK_MECHANISM_TYPE> override {
        std::vector<CK_MECHANISM_TYPE> out;
        for (const auto& e : supported_mechanisms()) {
            out.push_back(e.type);
        }
        return out;
    }

    [[nodiscard]] auto open_session(CK_SLOT_ID slot) -> CK_SESSION_HANDLE override {
        return value(_client.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION),
                     "C_OpenSession");
    }

    void close_session(CK_SESSION_HANDLE s) override {
        done(_client.close_session(s), "C_CloseSession");
    }

    void login(CK_SESSION_HANDLE s, std::string_view pin) override {
        auto r = _client.login(s, CKU_USER, pin);
        if (!r && r.error() == CKR_USER_ALREADY_LOGGED_IN) {
            return;
        }
        done(std::move(r), "C_Login");
    }

    [[nodiscard]] auto find_objects(CK_SESSION_HANDLE s, std::span<const pkcs11::attribute> tmpl)
        -> std::vector<CK_OBJECT_HANDLE> override {
        done(_client.find_objects_init(s, to_map(tmpl)), "C_FindObjectsInit");
        std::vector<CK_OBJECT_HANDLE> out;
        while (true) {
            auto batch = _client.find_objects(s, 64);
            if (!batch) {
                (void)_client.find_objects_final(s);
                throw pkcs11::error("C_FindObjects", batch.error());
            }
            if (batch->empty()) {
                break;
            }
            out.insert(out.end(), batch->begin(), batch->end());
        }
        done(_client.find_objects_final(s), "C_FindObjectsFinal");
        return out;
    }

    [[nodiscard]] auto get_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                                      std::span<const CK_ATTRIBUTE_TYPE> types)
        -> std::vector<std::optional<pkcs11::bytes>> override {
        auto values = value(_client.get_attribute_value(s, o, types), "C_GetAttributeValue");
        std::vector<std::optional<pkcs11::bytes>> out;
        out.reserve(values.size());
        for (auto& v : values) {
            out.push_back(std::move(v.value));
        }
        return out;
    }

    [[nodiscard]] auto generate_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                    std::span<const pkcs11::attribute> tmpl)
        -> CK_OBJECT_HANDLE override {
        return value(_client.generate_key(s, m, to_map(tmpl)), "C_GenerateKey");
    }

    [[nodiscard]] auto generate_key_pair(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                         std::span<const pkcs11::attribute> public_tmpl,
                                         std::span<const pkcs11::attribute> private_tmpl)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> override {
        return value(_client.generate_key_pair(s, m, to_map(public_tmpl), to_map(private_tmpl)),
                     "C_GenerateKeyPair");
    }

    [[nodiscard]] auto create_object(CK_SESSION_HANDLE s, std::span<const pkcs11::attribute> tmpl)
        -> CK_OBJECT_HANDLE override {
        return value(_client.create_object(s, to_map(tmpl)), "C_CreateObject");
    }

    void destroy_object(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o) override {
        done(_client.destroy_object(s, o), "C_DestroyObject");
    }

    [[nodiscard]] auto sign(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                            std::span<const std::uint8_t> data) -> pkcs11::bytes override {
        done(_client.sign_init(s, m, key), "C_SignInit");
        return value(_client.sign(s, data), "C_Sign");
    }

    [[nodiscard]] auto verify(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                              std::span<const std::uint8_t> data,
                              std::span<const std::uint8_t> signature) -> bool override {
        done(_client.verify_init(s, m, key), "C_VerifyInit");
        auto r = _client.verify(s, data, signature);
        if (!r && (r.error() == CKR_SIGNATURE_INVALID || r.error() == CKR_SIGNATURE_LEN_RANGE)) {
            return false;
        }
        done(std::move(r), "C_Verify");
        return true;
    }

    [[nodiscard]] auto encrypt(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                               std::span<const std::uint8_t> data) -> pkcs11::bytes override {
        done(_client.encrypt_init(s, m, key), "C_EncryptInit");
        return value(_client.encrypt(s, data), "C_Encrypt");
    }

    [[nodiscard]] auto decrypt(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key,
                               std::span<const std::uint8_t> data) -> pkcs11::bytes override {
        done(_client.decrypt_init(s, m, key), "C_DecryptInit");
        auto plain = value(_client.decrypt(s, data), "C_Decrypt");
        // The caller asked for the plaintext; it leaves the secure arena here.
        return {plain.data(), plain.data() + plain.size()};
    }

    [[nodiscard]] auto wrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key)
        -> pkcs11::bytes override {
        return value(_client.wrap_key(s, m, wrapping_key, key), "C_WrapKey");
    }

    [[nodiscard]] auto unwrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                                  CK_OBJECT_HANDLE unwrapping_key,
                                  std::span<const std::uint8_t> wrapped,
                                  std::span<const pkcs11::attribute> tmpl)
        -> CK_OBJECT_HANDLE override {
        return value(_client.unwrap_key(s, m, unwrapping_key, wrapped, to_map(tmpl)),
                     "C_UnwrapKey");
    }

private:
    template<class T> static auto value(ck_result<T> r, std::string_view what) -> T {
        if (!r) {
            throw pkcs11::error(what, r.error());
        }
        return std::move(*r);
    }

    static void done(ck_result<void> r, std::string_view what) {
        if (!r) {
            throw pkcs11::error(what, r.error());
        }
    }

    static auto to_map(std::span<const pkcs11::attribute> tmpl) -> attribute_map {
        auto t = pkcs11::detail::ck_template(tmpl);
        return value(attribute_map::from_template(t), "template");
    }

    native_client _client;
};

}  // namespace kythira::hsm
