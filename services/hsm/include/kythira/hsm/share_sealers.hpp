// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Share sealers beyond the key file (.kiro/specs/virtual-hsm/ task 8b,
// requirement 4.4): a node-unseal share sealed under a key the node's disk
// does not hold, so that a copied data directory alone opens nothing.
//
//   kms_share_sealer  envelope encryption through any of core's KMS key
//                     providers (raft/kms_key_provider*.hpp, the ones
//                     Kinesis and DynamoDB use): AWS KMS, a PKCS#11 token
//                     such as a YubiHSM 2 or CloudHSM, Azure Key Vault or
//                     GCP Cloud KMS. A fresh 256-bit data key seals the
//                     share; the provider wraps the data key under the
//                     operator's key, bound to the share's check value by
//                     the encryption context.
//
// A sealed share is
//
//   "KHS1" | u8 sealer-name length | sealer name | u16 key-id length |
//   key id | u32 wrapped length | wrapped data key | sealed share
//
// The key id stored is the one the provider resolved (AWS KMS: the key's
// ARN), so moving an alias later does not strand a share. The sealed share
// is sealing.hpp's AES-256-GCM under the data key with the same additional
// data as the key-file sealer: a file renamed to stand for another master
// key does not open.
//
// A share that does not open (another sealer's file, a refused or
// unreachable KMS) reads as absent, and the member collects that share from
// its peers instead; `last_error()` says why, for the log.

#include <kythira/hsm/node_unseal.hpp>
#include <kythira/hsm/sealing.hpp>
#include <kythira/hsm/secret_bytes.hpp>

#include <raft/kms_key_provider.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::hsm {

namespace share_sealer_detail {

inline constexpr std::string_view k_magic = "KHS1";

inline void put_u16(std::vector<std::uint8_t>& out, std::size_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8U));
    out.push_back(static_cast<std::uint8_t>(v));
}

inline void put_u32(std::vector<std::uint8_t>& out, std::size_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
    }
}

/// A cursor over a sealed share; every read fails once past the end.
struct reader {
    std::span<const std::uint8_t> in;
    std::size_t at = 0;
    bool ok = true;

    auto take(std::size_t n) -> std::span<const std::uint8_t> {
        if (!ok || in.size() - at < n) {
            ok = false;
            return {};
        }
        auto s = in.subspan(at, n);
        at += n;
        return s;
    }
    auto u8() -> std::size_t {
        const auto s = take(1);
        return ok ? s[0] : 0;
    }
    auto u16() -> std::size_t {
        const auto s = take(2);
        return ok ? (std::size_t{s[0]} << 8U) | s[1] : 0;
    }
    auto u32() -> std::size_t {
        const auto s = take(4);
        if (!ok) {
            return 0;
        }
        return (std::size_t{s[0]} << 24U) | (std::size_t{s[1]} << 16U) | (std::size_t{s[2]} << 8U) |
               s[3];
    }
    auto text(std::size_t n) -> std::string {
        const auto s = take(n);
        return ok ? std::string(s.begin(), s.end()) : std::string();
    }
};

}  // namespace share_sealer_detail

/// A share sealed under a data key from a KMS key provider.
class kms_share_sealer final : public share_sealer {
public:
    /// The context key the share's check value is bound under.
    static constexpr const char* k_context_key = "kythira:hsm:share";

    /// @param name What `KYTHIRA_HSM_SHARE_SEALER` called it (aws-kms,
    ///        pkcs11, azure-key-vault, gcp-kms); stored in each share, so
    ///        a share sealed by one sealer is not handed to another.
    /// @param provider Thread-safe, as every core provider is.
    /// @param key_id The operator's key, in the provider's terms.
    kms_share_sealer(std::string name, kms_provider::key_provider provider, std::string key_id)
        : _name(std::move(name)), _provider(std::move(provider)), _key_id(std::move(key_id)) {
        if (_name.empty() || _name.size() > 255 || !_provider || _key_id.empty() ||
            _key_id.size() > 0xFFFF) {
            throw std::invalid_argument(
                "kms_share_sealer needs a name, a key provider and a key id");
        }
    }

    [[nodiscard]] auto name() const -> std::string_view override { return _name; }

    /// Throws kms_provider::kms_error when the KMS refuses or is away: a
    /// share that cannot be sealed must not be acknowledged.
    [[nodiscard]] auto seal(std::span<const std::uint8_t> share,
                            std::span<const std::uint8_t> context) -> sealed_bytes override {
        namespace d = share_sealer_detail;
        auto made = _provider.generate_data_key(_key_id, context_of(context));
        const secret_bytes key{std::span<const std::uint8_t>(made._plaintext)};
        OPENSSL_cleanse(made._plaintext.data(), made._plaintext.size());
        const auto& resolved = made._key_id.empty() ? _key_id : made._key_id;
        if (resolved.size() > 0xFFFF) {
            throw std::runtime_error("kms_share_sealer: the provider's key id is too long");
        }
        sealed_bytes out(d::k_magic.begin(), d::k_magic.end());
        out.push_back(static_cast<std::uint8_t>(_name.size()));
        out.insert(out.end(), _name.begin(), _name.end());
        d::put_u16(out, resolved.size());
        out.insert(out.end(), resolved.begin(), resolved.end());
        d::put_u32(out, made._wrapped.size());
        out.insert(out.end(), made._wrapped.begin(), made._wrapped.end());
        const auto sealed = hsm::seal(key.view(), node_unseal_detail::share_ad(context), share);
        out.insert(out.end(), sealed.begin(), sealed.end());
        return out;
    }

    [[nodiscard]] auto unseal(std::span<const std::uint8_t> sealed,
                              std::span<const std::uint8_t> context)
        -> std::optional<secret_bytes> override {
        namespace d = share_sealer_detail;
        d::reader r{sealed};
        const auto magic = r.take(d::k_magic.size());
        if (!r.ok || !std::equal(magic.begin(), magic.end(), d::k_magic.begin())) {
            return fail("not a share sealed under a KMS key");
        }
        const auto name = r.text(r.u8());
        const auto key_id = r.text(r.u16());
        const auto wrapped = r.text(r.u32());
        if (!r.ok || r.at >= sealed.size()) {
            return fail("a truncated sealed share");
        }
        if (name != _name) {
            return fail("the share was sealed by the " + name + " sealer, not " + _name);
        }
        try {
            auto plain = _provider.decrypt_data_key(key_id, wrapped, context_of(context));
            const secret_bytes key{std::span<const std::uint8_t>(plain)};
            OPENSSL_cleanse(plain.data(), plain.size());
            auto share = hsm::unseal(key.view(), node_unseal_detail::share_ad(context),
                                     sealed.subspan(r.at));
            if (!share) {
                return fail("the sealed share does not open under its data key");
            }
            const std::scoped_lock lock(_mutex);
            _last_error.clear();
            return share;
        } catch (const kms_provider::kms_error& e) {
            return fail(std::string("the KMS did not open the share's data key: ") + e.what());
        }
    }

    /// Why the last unseal found nothing; empty after one that opened.
    [[nodiscard]] auto last_error() const -> std::string {
        const std::scoped_lock lock(_mutex);
        return _last_error;
    }

private:
    [[nodiscard]] static auto context_of(std::span<const std::uint8_t> context)
        -> kms_provider::encryption_context {
        return {{k_context_key, node_unseal_detail::hex(context)}};
    }

    auto fail(std::string why) -> std::optional<secret_bytes> {
        const std::scoped_lock lock(_mutex);
        _last_error = std::move(why);
        return std::nullopt;
    }

    std::string _name;
    kms_provider::key_provider _provider;
    std::string _key_id;
    mutable std::mutex _mutex;
    std::string _last_error;
};

}  // namespace kythira::hsm
