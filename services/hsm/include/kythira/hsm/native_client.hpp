// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The in-process client co-located modules use (requirement 2.3, design
// "PKCS#11 is the only boundary consumers see"): one PKCS#11 application
// on this node's session layer, with no network hop. It is authenticated
// by construction (the identity is the module's, set by the code that
// builds it) and authorized like any other client: it sees only the
// tokens the catalog binds to that identity, and needs their PINs.
//
// The calls are PKCS#11's, in C++ form: buffers are vectors rather than
// caller-sized arrays, so there is no length query, and results carry a
// CK_RV through ck_result. The consumer wrapper of task 12
// (kythira::pkcs11::module) presents this and a dlopen'd module through
// one interface.
//
// Destroying the client closes its sessions (C_Finalize).

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/session_layer.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::hsm {

class native_client {
public:
    native_client(session_layer& layer, std::string identity)
        : _layer(&layer), _app(layer.register_app(std::move(identity))) {}

    native_client(const native_client&) = delete;
    auto operator=(const native_client&) -> native_client& = delete;
    native_client(native_client&&) = delete;
    auto operator=(native_client&&) -> native_client& = delete;
    ~native_client() { _layer->unregister_app(_app); }

    [[nodiscard]] auto get_slot_list() const -> std::vector<CK_SLOT_ID> {
        return _layer->slots(_app);
    }
    [[nodiscard]] auto get_token_info(CK_SLOT_ID slot) const -> ck_result<token_info> {
        return _layer->get_token_info(_app, slot);
    }
    auto init_token(CK_SLOT_ID slot, std::string_view so_pin, std::string_view label)
        -> ck_result<void> {
        return _layer->init_token(_app, slot, so_pin, label);
    }

    auto open_session(CK_SLOT_ID slot, CK_FLAGS flags) -> ck_result<CK_SESSION_HANDLE> {
        return _layer->open_session(_app, slot, flags);
    }
    auto close_session(CK_SESSION_HANDLE s) -> ck_result<void> {
        return _layer->close_session(_app, s);
    }
    auto close_all_sessions(CK_SLOT_ID slot) -> ck_result<void> {
        return _layer->close_all_sessions(_app, slot);
    }
    [[nodiscard]] auto get_session_info(CK_SESSION_HANDLE s) const -> ck_result<session_info> {
        return _layer->get_session_info(_app, s);
    }

    auto login(CK_SESSION_HANDLE s, CK_USER_TYPE user, std::string_view pin) -> ck_result<void> {
        return _layer->login(_app, s, user, pin);
    }
    auto logout(CK_SESSION_HANDLE s) -> ck_result<void> { return _layer->logout(_app, s); }
    auto init_pin(CK_SESSION_HANDLE s, std::string_view pin) -> ck_result<void> {
        return _layer->init_pin(_app, s, pin);
    }
    auto set_pin(CK_SESSION_HANDLE s, std::string_view old_pin, std::string_view new_pin)
        -> ck_result<void> {
        return _layer->set_pin(_app, s, old_pin, new_pin);
    }

    auto generate_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        return _layer->generate_key(_app, s, m, tmpl);
    }
    auto generate_key_pair(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                           const attribute_map& public_tmpl, const attribute_map& private_tmpl)
        -> ck_result<std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>> {
        return _layer->generate_key_pair(_app, s, m, public_tmpl, private_tmpl);
    }
    auto destroy_object(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o) -> ck_result<void> {
        return _layer->destroy_object(_app, s, o);
    }
    auto get_attribute_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                             std::span<const CK_ATTRIBUTE_TYPE> types)
        -> ck_result<std::vector<attribute_value>> {
        return _layer->get_attribute_value(_app, s, o, types);
    }
    auto set_attribute_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, const attribute_map& changes)
        -> ck_result<void> {
        return _layer->set_attribute_value(_app, s, o, changes);
    }
    auto find_objects_init(CK_SESSION_HANDLE s, const attribute_map& tmpl) -> ck_result<void> {
        return _layer->find_objects_init(_app, s, tmpl);
    }
    auto find_objects(CK_SESSION_HANDLE s, std::size_t max)
        -> ck_result<std::vector<CK_OBJECT_HANDLE>> {
        return _layer->find_objects(_app, s, max);
    }
    auto find_objects_final(CK_SESSION_HANDLE s) -> ck_result<void> {
        return _layer->find_objects_final(_app, s);
    }

    auto sign_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return _layer->operation_init(_app, s, session_layer::op_kind::sign, m, key);
    }
    auto sign(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<bytes> {
        return _layer->sign(_app, s, data);
    }
    auto sign_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<void> {
        return _layer->operation_update(_app, s, session_layer::op_kind::sign, data);
    }
    auto sign_final(CK_SESSION_HANDLE s) -> ck_result<bytes> { return _layer->sign_final(_app, s); }

    auto verify_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return _layer->operation_init(_app, s, session_layer::op_kind::verify, m, key);
    }
    auto verify(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data,
                std::span<const std::uint8_t> signature) -> ck_result<void> {
        return _layer->verify(_app, s, data, signature);
    }
    auto verify_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<void> {
        return _layer->operation_update(_app, s, session_layer::op_kind::verify, data);
    }
    auto verify_final(CK_SESSION_HANDLE s, std::span<const std::uint8_t> signature)
        -> ck_result<void> {
        return _layer->verify_final(_app, s, signature);
    }

    auto encrypt_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return _layer->operation_init(_app, s, session_layer::op_kind::encrypt, m, key);
    }
    auto encrypt(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<bytes> {
        return _layer->encrypt(_app, s, data);
    }
    auto encrypt_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data)
        -> ck_result<void> {
        return _layer->operation_update(_app, s, session_layer::op_kind::encrypt, data);
    }
    auto encrypt_final(CK_SESSION_HANDLE s) -> ck_result<bytes> {
        return _layer->encrypt_final(_app, s);
    }

    auto decrypt_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return _layer->operation_init(_app, s, session_layer::op_kind::decrypt, m, key);
    }
    auto decrypt(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data)
        -> ck_result<secret_bytes> {
        return _layer->decrypt(_app, s, data);
    }
    auto decrypt_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data)
        -> ck_result<void> {
        return _layer->operation_update(_app, s, session_layer::op_kind::decrypt, data);
    }
    auto decrypt_final(CK_SESSION_HANDLE s) -> ck_result<secret_bytes> {
        return _layer->decrypt_final(_app, s);
    }

    auto digest_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m) -> ck_result<void> {
        return _layer->digest_init(_app, s, m);
    }
    auto digest(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<bytes> {
        return _layer->digest(_app, s, data);
    }
    auto digest_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<void> {
        return _layer->operation_update(_app, s, session_layer::op_kind::digest, data);
    }
    auto digest_final(CK_SESSION_HANDLE s) -> ck_result<bytes> {
        return _layer->digest_final(_app, s);
    }

    auto generate_random(CK_SESSION_HANDLE s, std::size_t length) -> ck_result<bytes> {
        return _layer->generate_random(_app, s, length);
    }

    [[nodiscard]] auto app() const noexcept -> app_id { return _app; }

private:
    session_layer* _layer;
    app_id _app;
};

}  // namespace kythira::hsm
