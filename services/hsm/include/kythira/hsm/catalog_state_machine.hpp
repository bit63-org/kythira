// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The HSM catalog group: the token list, each token's key sealed under the
// master key, which client identities may open which tokens, the MK's check
// value and generation, and the unseal mode (requirements 3.1, 4.5, 7.4 and
// 8.2). One per HSM.
//
// The MK itself is never here: initialization records only its 8-byte
// check value (the same one every Shamir share carries), so a node can tell
// a correct unseal from a wrong one. Token keys are sealed with
// token_key_ad(token, generation); rekey replaces every one of them and
// bumps the generation in one entry, so the old MK opens nothing.
//
// Layout under `ns`:
//   data  ns "c"                         catalog record
//   data  ns "k" be64(token)             token entry
//   data  ns "b" identity 0x00 be64(t)   binding (identity may open t)
//   data  ns "r" be64(t) identity        the same binding, by token
//   data  ns "x" be64(t)                 token t was deleted (ids are
//                                        never reused: its group id is
//                                        tombstoned on every member)
//   meta  ns                             applied index
//
// Replies are a CK_RV (u32); CKR_FUNCTION_REJECTED is a conflict (already
// initialized, a token id taken, a stale generation).

#include <kythira/hsm/codec.hpp>
#include <kythira/hsm/persistent_group.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/sealing.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/persistent_state_machine.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace kythira::hsm {

enum class unseal_mode : std::uint8_t {
    /// k operators each enter a share after every restart (requirement 4.3).
    operator_shares = 1,
    /// Each node holds one share sealed to itself and collects k - 1 more
    /// from peers (requirement 4.4).
    node_shares = 2,
};

struct catalog_record {
    unseal_mode mode = unseal_mode::operator_shares;
    std::uint8_t k = 0;
    std::uint8_t n = 0;
    std::uint32_t generation = 1;
    std::array<std::uint8_t, 8> mk_check{};

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1).u8(static_cast<std::uint8_t>(mode)).u8(k).u8(n).u32(generation).bytes(mk_check);
        return w.take_string();
    }

    [[nodiscard]] static auto decode(std::string_view in) -> catalog_record {
        byte_reader r(in);
        if (r.u8() != 1) {
            throw std::invalid_argument("catalog record: unknown version");
        }
        catalog_record c;
        c.mode = static_cast<unseal_mode>(r.u8());
        c.k = r.u8();
        c.n = r.u8();
        c.generation = r.u32();
        auto check = r.bytes();
        r.finish();
        if (check.size() != c.mk_check.size()) {
            throw std::invalid_argument("catalog record: bad check value");
        }
        std::ranges::copy(check, c.mk_check.begin());
        return c;
    }
};

struct token_entry {
    std::uint64_t token_id = 0;
    std::string label;
    /// The MK generation `sealed_tk` is sealed under.
    std::uint32_t generation = 0;
    sealed_bytes sealed_tk;

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1).u64(token_id).str(label).u32(generation).bytes(sealed_tk);
        return w.take_string();
    }

    [[nodiscard]] static auto decode(std::string_view in) -> token_entry {
        byte_reader r(in);
        if (r.u8() != 1) {
            throw std::invalid_argument("token entry: unknown version");
        }
        token_entry t;
        t.token_id = r.u64();
        t.label = r.str();
        t.generation = r.u32();
        t.sealed_tk = r.bytes();
        r.finish();
        return t;
    }
};

enum class catalog_command : std::uint8_t {
    initialize = 1,
    create_token = 2,
    delete_token = 3,
    bind = 4,
    unbind = 5,
    rekey = 6,
    set_mode = 7,
};

[[nodiscard]] inline auto valid_unseal_parameters(unseal_mode mode, std::uint8_t k, std::uint8_t n)
    -> bool {
    return (mode == unseal_mode::operator_shares || mode == unseal_mode::node_shares) && k >= 1 &&
           k <= n && n <= 16;
}

[[nodiscard]] inline auto make_initialize_command(unseal_mode mode, std::uint8_t k, std::uint8_t n,
                                                  std::span<const std::uint8_t, 8> mk_check)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(catalog_command::initialize))
        .u8(static_cast<std::uint8_t>(mode))
        .u8(k)
        .u8(n)
        .bytes(mk_check);
    return w.take();
}

[[nodiscard]] inline auto make_create_token_command(const token_entry& t)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(catalog_command::create_token))
        .u64(t.token_id)
        .str(t.label)
        .u32(t.generation)
        .bytes(t.sealed_tk);
    return w.take();
}

/// Destroys the token's sealed key and its bindings (requirement 7.4).
[[nodiscard]] inline auto make_delete_token_command(std::uint64_t token_id)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(catalog_command::delete_token)).u64(token_id);
    return w.take();
}

[[nodiscard]] inline auto make_bind_command(std::string_view identity, std::uint64_t token_id)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(catalog_command::bind)).str(identity).u64(token_id);
    return w.take();
}

[[nodiscard]] inline auto make_unbind_command(std::string_view identity, std::uint64_t token_id)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(catalog_command::unbind)).str(identity).u64(token_id);
    return w.take();
}

/// Every token's key re-sealed under a new MK, as one entry: `generation`
/// must be the current one plus one and `tokens` must name every token.
[[nodiscard]] inline auto make_rekey_command(
    std::uint32_t generation, std::span<const std::uint8_t, 8> mk_check,
    const std::vector<std::pair<std::uint64_t, sealed_bytes>>& tokens) -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(catalog_command::rekey))
        .u32(generation)
        .bytes(mk_check)
        .u32(static_cast<std::uint32_t>(tokens.size()));
    for (const auto& [id, sealed] : tokens) {
        w.u64(id).bytes(sealed);
    }
    return w.take();
}

/// Records a new unseal mode (requirement 4.5: the switch itself, with its
/// re-split, happens on an unsealed cluster before this is proposed).
[[nodiscard]] inline auto make_set_mode_command(unseal_mode mode, std::uint8_t k, std::uint8_t n)
    -> std::vector<std::byte> {
    byte_writer w;
    w.u8(static_cast<std::uint8_t>(catalog_command::set_mode))
        .u8(static_cast<std::uint8_t>(mode))
        .u8(k)
        .u8(n);
    return w.take();
}

[[nodiscard]] inline auto catalog_reply_rv(const std::vector<std::byte>& reply) -> CK_RV {
    byte_reader r(reply);
    const CK_RV rv = r.u32();
    r.finish();
    return rv;
}

template<kythira::kv_engine Engine = kythira::memory_kv_engine, typename LogIndex = std::uint64_t>
class hsm_catalog_state_machine : public persistent_group<Engine, LogIndex> {
    using base = persistent_group<Engine, LogIndex>;

public:
    using engine_type = Engine;

    explicit hsm_catalog_state_machine(std::string ns) : base(std::move(ns)) {}

    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        if (this->already_applied(index)) {
            return {};
        }
        kythira::write_batch batch;
        byte_reader r(command);
        CK_RV rv = CKR_OK;
        const auto tag = static_cast<catalog_command>(r.u8());
        switch (tag) {
            case catalog_command::initialize:
                rv = apply_initialize(r, batch);
                break;
            case catalog_command::create_token:
                rv = apply_create_token(r, batch);
                break;
            case catalog_command::delete_token:
                rv = apply_delete_token(r, batch);
                break;
            case catalog_command::bind:
            case catalog_command::unbind:
                rv = apply_binding(r, batch, tag == catalog_command::bind);
                break;
            case catalog_command::rekey:
                rv = apply_rekey(r, batch);
                break;
            case catalog_command::set_mode:
                rv = apply_set_mode(r, batch);
                break;
            default:
                throw std::invalid_argument("hsm_catalog_state_machine: unknown command");
        }
        r.finish();
        this->commit(batch, index);
        byte_writer w;
        w.u32(static_cast<std::uint32_t>(rv));
        return w.take();
    }

    // -- Reads ---------------------------------------------------------------

    [[nodiscard]] auto catalog() const -> std::optional<catalog_record> {
        auto v = this->get("c");
        if (!v) {
            return std::nullopt;
        }
        return catalog_record::decode(*v);
    }

    [[nodiscard]] auto token(std::uint64_t token_id) const -> std::optional<token_entry> {
        auto v = this->get("k" + be64_key(token_id));
        if (!v) {
            return std::nullopt;
        }
        return token_entry::decode(*v);
    }

    [[nodiscard]] auto tokens() const -> std::vector<token_entry> {
        std::vector<token_entry> out;
        this->scan_prefix("k", [&](std::string_view, std::string_view v) {
            out.push_back(token_entry::decode(v));
            return true;
        });
        return out;
    }

    /// The tokens `identity` may open, in id order (requirement 8.2).
    [[nodiscard]] auto bound_tokens(std::string_view identity) const -> std::vector<std::uint64_t> {
        std::vector<std::uint64_t> out;
        const std::string prefix = "b" + std::string(identity) + std::string(1, '\0');
        this->scan_prefix(prefix, [&](std::string_view k, std::string_view) {
            out.push_back(from_be64_key(k.substr(prefix.size())));
            return true;
        });
        return out;
    }

    [[nodiscard]] auto may_open(std::string_view identity, std::uint64_t token_id) const -> bool {
        return this->get(binding_key(identity, token_id)).has_value();
    }

    /// Whether token `token_id` existed and was deleted.
    [[nodiscard]] auto deleted(std::uint64_t token_id) const -> bool {
        return this->get("x" + be64_key(token_id)).has_value();
    }

    /// Every deleted token's id, in order, so each member destroys its group.
    [[nodiscard]] auto deleted_tokens() const -> std::vector<std::uint64_t> {
        std::vector<std::uint64_t> out;
        this->scan_prefix("x", [&](std::string_view k, std::string_view) {
            out.push_back(from_be64_key(k.substr(1)));
            return true;
        });
        return out;
    }

private:
    [[nodiscard]] static auto binding_key(std::string_view identity, std::uint64_t token_id)
        -> std::string {
        return "b" + std::string(identity) + std::string(1, '\0') + be64_key(token_id);
    }
    [[nodiscard]] static auto reverse_key(std::uint64_t token_id, std::string_view identity)
        -> std::string {
        return "r" + be64_key(token_id) + std::string(identity);
    }

    auto put(kythira::write_batch& batch, const std::string& suffix, std::string value) -> void {
        batch.put(kythira::column_family::data, this->key(suffix), std::move(value));
    }

    auto apply_initialize(byte_reader& r, kythira::write_batch& batch) -> CK_RV {
        catalog_record c;
        c.mode = static_cast<unseal_mode>(r.u8());
        c.k = r.u8();
        c.n = r.u8();
        auto check = r.bytes();
        if (check.size() != c.mk_check.size() || !valid_unseal_parameters(c.mode, c.k, c.n)) {
            throw std::invalid_argument("hsm_catalog_state_machine: bad initialize");
        }
        std::ranges::copy(check, c.mk_check.begin());
        if (catalog()) {
            return CKR_FUNCTION_REJECTED;
        }
        put(batch, "c", c.encode());
        return CKR_OK;
    }

    auto apply_create_token(byte_reader& r, kythira::write_batch& batch) -> CK_RV {
        token_entry t;
        t.token_id = r.u64();
        t.label = r.str();
        t.generation = r.u32();
        t.sealed_tk = r.bytes();
        auto c = catalog();
        if (!c) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if (t.token_id == 0 || t.generation != c->generation || token(t.token_id) ||
            deleted(t.token_id)) {
            return CKR_FUNCTION_REJECTED;
        }
        put(batch, "k" + be64_key(t.token_id), t.encode());
        return CKR_OK;
    }

    auto apply_delete_token(byte_reader& r, kythira::write_batch& batch) -> CK_RV {
        const auto id = r.u64();
        if (!token(id)) {
            return CKR_TOKEN_NOT_PRESENT;
        }
        batch.erase(kythira::column_family::data, this->key("k" + be64_key(id)));
        put(batch, "x" + be64_key(id), std::string());
        const std::string prefix = "r" + be64_key(id);
        this->scan_prefix(prefix, [&](std::string_view k, std::string_view) {
            const std::string identity(k.substr(prefix.size()));
            batch.erase(kythira::column_family::data, this->key(binding_key(identity, id)));
            batch.erase(kythira::column_family::data, this->key(std::string(k)));
            return true;
        });
        return CKR_OK;
    }

    auto apply_binding(byte_reader& r, kythira::write_batch& batch, bool add) -> CK_RV {
        const auto identity = r.str();
        const auto id = r.u64();
        if (identity.empty() || identity.find('\0') != std::string::npos) {
            throw std::invalid_argument("hsm_catalog_state_machine: bad identity");
        }
        if (!token(id)) {
            return CKR_TOKEN_NOT_PRESENT;
        }
        if (add) {
            put(batch, binding_key(identity, id), {});
            put(batch, reverse_key(id, identity), {});
        } else {
            batch.erase(kythira::column_family::data, this->key(binding_key(identity, id)));
            batch.erase(kythira::column_family::data, this->key(reverse_key(id, identity)));
        }
        return CKR_OK;
    }

    auto apply_rekey(byte_reader& r, kythira::write_batch& batch) -> CK_RV {
        const auto generation = r.u32();
        auto check = r.bytes();
        const auto count = r.u32();
        std::vector<std::pair<std::uint64_t, sealed_bytes>> resealed;
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto id = r.u64();
            resealed.emplace_back(id, r.bytes());
        }
        if (check.size() != 8) {
            throw std::invalid_argument("hsm_catalog_state_machine: bad rekey");
        }
        auto c = catalog();
        if (!c) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if (generation != c->generation + 1) {
            return CKR_FUNCTION_REJECTED;
        }
        // Exactly the current tokens, each once: a token left out would keep
        // a key sealed under the retired MK, which nothing could open.
        auto current = tokens();
        std::set<std::uint64_t> want;
        for (const auto& t : current) {
            want.insert(t.token_id);
        }
        std::set<std::uint64_t> got;
        for (const auto& [id, sealed] : resealed) {
            if (!got.insert(id).second) {
                return CKR_FUNCTION_REJECTED;
            }
        }
        if (got != want) {
            return CKR_FUNCTION_REJECTED;
        }
        for (auto& t : current) {
            for (auto& [id, sealed] : resealed) {
                if (id == t.token_id) {
                    t.sealed_tk = sealed;
                }
            }
            t.generation = generation;
            put(batch, "k" + be64_key(t.token_id), t.encode());
        }
        c->generation = generation;
        std::ranges::copy(check, c->mk_check.begin());
        put(batch, "c", c->encode());
        return CKR_OK;
    }

    auto apply_set_mode(byte_reader& r, kythira::write_batch& batch) -> CK_RV {
        const auto mode = static_cast<unseal_mode>(r.u8());
        const auto k = r.u8();
        const auto n = r.u8();
        if (!valid_unseal_parameters(mode, k, n)) {
            throw std::invalid_argument("hsm_catalog_state_machine: bad mode");
        }
        auto c = catalog();
        if (!c) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        c->mode = mode;
        c->k = k;
        c->n = n;
        put(batch, "c", c->encode());
        return CKR_OK;
    }
};

static_assert(kythira::persistent_state_machine<hsm_catalog_state_machine<>>);

}  // namespace kythira::hsm
