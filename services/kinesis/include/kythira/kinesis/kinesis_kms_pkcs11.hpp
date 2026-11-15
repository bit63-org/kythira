// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_kms_pkcs11.hpp
/// @brief `KINESIS_KMS=pkcs11` (`.kiro/specs/virtual-hsm/` task 13,
///        Requirement 10.2): stream data keys protected by a key on a
///        PKCS#11 token, through core's consumer wrapper.
///
/// The token is the virtual HSM, in process when it is co-located or
/// through `libkythira_pkcs11.so`, or any other module the URI's
/// `module-path` names: a YubiHSM 2, CloudHSM, SoftHSM2. To stay within
/// what all of them offer (raft/pkcs11_module.hpp's common subset), the key
/// is an RSA pair made for decryption, and data keys are sealed with
/// envelope encryption (raft/pkcs11_envelope.hpp): RSA-OAEP in software on
/// the public half, decryption on the token. Requirement 10.2's first
/// wording, an AES key on the token, would need AES key wrap, which the
/// YubiHSM 2 does not offer.
///
/// A stream's KMS key id names the key: a PKCS#11 URI with `object=` or
/// `id=` (its token attributes, when given, must match the configured
/// token), or plainly the key's label. The id and the encryption context
/// are bound to the sealed data key, so it opens under no other.
///
/// The module is opened on first use, so a co-located HSM bound when the
/// node starts serves keys from then on. A call that finds the session
/// gone (the module restarted, a node failover) opens a new one and tries
/// once more.

#include <kythira/kinesis/kinesis_kms.hpp>

#include <raft/pkcs11_envelope.hpp>
#include <raft/pkcs11_module.hpp>
#include <raft/pkcs11_uri.hpp>

#include <openssl/crypto.h>

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace kythira::kinesis {

struct pkcs11_kms_config {
    /// The token: `pkcs11:token=...`, with `pin-source` (or `pin-value`)
    /// and, when the HSM is not co-located, `module-path`.
    pkcs11::uri token;
    /// RSA-OAEP's hash for new seals: SHA-256, or SHA-1 for a module that
    /// takes only that (SoftHSM2 2.6). Sealed keys record theirs.
    pkcs11::hash_algorithm oaep = pkcs11::hash_algorithm::sha256;
};

class pkcs11_kms_provider {
public:
    /// Called once, on first use, for the module to open.
    using module_source = std::function<pkcs11::module()>;

    static constexpr std::size_t k_max_key_id = 2048;

    pkcs11_kms_provider(pkcs11_kms_config config, module_source source)
        : _state(std::make_shared<state>(std::move(config), std::move(source))) {}

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context) const
        -> generated_data_key {
        return with_key(key_id, [&](const pkcs11::envelope_key& key) {
            generated_data_key out;
            kms_detail::random_fill(out._plaintext);
            const auto binding = kms_detail::binding(k_label, key_id, context);
            const auto sealed = key.seal(out._plaintext, as_bytes(binding));
            out._wrapped.assign(sealed.begin(), sealed.end());
            out._key_id = key_id;
            return out;
        });
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context) const -> data_key_bytes {
        return with_key(key_id, [&](const pkcs11::envelope_key& key) {
            const auto binding = kms_detail::binding(k_label, key_id, context);
            auto plain = key.open(as_bytes(wrapped), as_bytes(binding));
            if (plain.size() != 32) {
                OPENSSL_cleanse(plain.data(), plain.size());
                throw kms_error(kms_failure::invalid_state, "The wrapped data key is malformed.");
            }
            data_key_bytes out{};
            std::copy(plain.begin(), plain.end(), out.begin());
            OPENSSL_cleanse(plain.data(), plain.size());
            return out;
        });
    }

private:
    static constexpr std::string_view k_label = "kythira-kinesis-pkcs11-kms-v1";

    struct state {
        state(pkcs11_kms_config c, module_source s)
            : _config(std::move(c)), _source(std::move(s)) {}
        pkcs11_kms_config _config;
        module_source _source;
        std::mutex _mutex;
        std::optional<pkcs11::module> _module;
        std::optional<pkcs11::session> _session;
        std::map<std::string, std::unique_ptr<pkcs11::envelope_key>, std::less<>> _keys;
    };

    [[nodiscard]] static auto as_bytes(std::string_view s) -> std::span<const std::uint8_t> {
        return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
    }

    [[nodiscard]] static auto failure_of(CK_RV rv) -> kms_failure {
        switch (rv) {
            case CKR_OBJECT_HANDLE_INVALID:
            case CKR_KEY_HANDLE_INVALID:
            case CKR_TOKEN_NOT_PRESENT:
            case CKR_SLOT_ID_INVALID:
                return kms_failure::not_found;
            case CKR_PIN_INCORRECT:
            case CKR_PIN_LOCKED:
            case CKR_USER_NOT_LOGGED_IN:
            case CKR_KEY_FUNCTION_NOT_PERMITTED:
                return kms_failure::access_denied;
            case CKR_DEVICE_ERROR:
            case CKR_DEVICE_REMOVED:
            case CKR_SESSION_HANDLE_INVALID:
            case CKR_SESSION_CLOSED:
            case CKR_GENERAL_ERROR:
                return kms_failure::unavailable;
            default:
                return kms_failure::invalid_state;
        }
    }

    /// The URI naming `key_id` on the configured token.
    [[nodiscard]] auto key_uri(const std::string& key_id) const -> pkcs11::uri {
        if (key_id.empty() || key_id.size() > k_max_key_id) {
            throw kms_error(kms_failure::not_found, "Invalid KeyId.");
        }
        pkcs11::uri u;
        if (key_id.starts_with("pkcs11:")) {
            try {
                u = pkcs11::uri::parse(key_id);
            } catch (const pkcs11::uri_error& e) {
                throw kms_error(kms_failure::not_found, std::string("Invalid KeyId: ") + e.what());
            }
            const auto& t = _state->_config.token;
            if ((u.token && u.token != t.token) || (u.serial && u.serial != t.serial) ||
                u.module_path || u.module_name || u.pin_value || u.pin_source) {
                throw kms_error(kms_failure::not_found,
                                "Invalid KeyId: a key URI names only a key on the configured "
                                "token.");
            }
            if (u.type && u.type != pkcs11::object_type::private_key) {
                throw kms_error(kms_failure::not_found, "Invalid KeyId: not a private key.");
            }
        } else {
            u.object = key_id;
        }
        u.type = pkcs11::object_type::private_key;
        return u;
    }

    /// Runs `use` with the key's envelope_key, opening the module, the
    /// session and the key as needed, and once more on a new session when
    /// the first fails as if the session were gone.
    template<class Use>
    [[nodiscard]] auto with_key(const std::string& key_id, Use use) const
        -> std::invoke_result_t<Use, const pkcs11::envelope_key&> {
        const auto u = key_uri(key_id);
        const std::scoped_lock lock(_state->_mutex);
        for (int attempt = 0;; ++attempt) {
            try {
                return use(key_of(key_id, u));
            } catch (const pkcs11::error& e) {
                if (attempt == 0 && pkcs11::session_lost(e.rv())) {
                    _state->_keys.clear();
                    _state->_session.reset();
                    continue;
                }
                if (e.rv() == CKR_ENCRYPTED_DATA_INVALID) {
                    throw kms_error(kms_failure::invalid_state,
                                    "The data key does not unwrap under key " + key_id + ".");
                }
                throw kms_error(failure_of(e.rv()),
                                std::string("PKCS#11 key ") + key_id + ": " + e.what());
            } catch (const pkcs11::uri_error& e) {
                throw kms_error(kms_failure::access_denied,
                                std::string("PKCS#11 token PIN: ") + e.what());
            }
        }
    }

    [[nodiscard]] auto key_of(const std::string& key_id, const pkcs11::uri& u) const
        -> const pkcs11::envelope_key& {
        auto& st = *_state;
        if (!st._module) {
            st._module.emplace(st._source());
        }
        if (!st._session) {
            st._session.emplace(st._module->open(st._config.token));
        }
        auto it = st._keys.find(key_id);
        if (it == st._keys.end()) {
            const auto handle = st._session->find(u);
            it = st._keys
                     .emplace(key_id, std::make_unique<pkcs11::envelope_key>(*st._session, handle,
                                                                             st._config.oaep))
                     .first;
        }
        return *it->second;
    }

    std::shared_ptr<state> _state;
};

static_assert(kms_key_provider<pkcs11_kms_provider>);

}  // namespace kythira::kinesis
