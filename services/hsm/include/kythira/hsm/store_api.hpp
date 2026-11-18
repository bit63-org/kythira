// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The store API a crypto node outside the HSM's groups reads through
// (.kiro/specs/hsm-independent-layers/ task 3, Requirements 3 and 4).
//
// A co-located node reads its own replica after a read barrier. A
// crypto-only node has no replica, so it sends the read with the barrier:
//
//   POST /v1/peer/store-read/<local group>   body: a store_read_request
//
// Any store member serves it, the way it serves its own session layer: a
// read-index round on the catalog group (so the answer carries the seal
// state the group had committed, Requirement 4.2), then, for a token
// group, a read-index round on that group (Requirement 4.1), and then
// reads of its replica, which has applied at least that far. A member
// that does not lead a group gets the round from the leader with the
// ordinary read-index forwarding; that is a read, nothing is proposed, so
// the "proposals are never forwarded twice" rule of Requirement 3.2 is
// untouched. A round that cannot be had answers `unavailable`, never a
// stale view (Requirement 4.3).
//
// A catalog read answers the whole catalog: its record, the live tokens
// with their sealed token keys, and every binding. It is small (a token
// entry is a label and a sealed key) and the crypto node polls it to
// follow seals while idle (Requirement 4.4).
//
// A token read names the objects the caller already holds, as (handle,
// version) pairs, and is answered with the token record, every live
// handle with its version, and the full records of only those handles
// that are new or changed. So the crypto node keeps wrapped objects by
// (handle, version) and fetches each version once (Requirement 3.4).
//
// Every field here is a record the store already holds: catalog and token
// records, sealed token keys, objects with sealed material, PIN
// verifiers. Nothing unwrapped is ever read or accepted (Requirement 3.3);
// proposals keep their own route (/v1/peer/propose/), whose commands are
// built from wrapped bytes by the crypto node.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/codec.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::hsm {

inline constexpr std::string_view peer_store_read_path = "/v1/peer/store-read/";

/// A handle and the version of it the caller holds.
struct object_version {
    std::uint64_t handle = 0;
    std::uint64_t version = 0;

    friend auto operator==(const object_version&, const object_version&) -> bool = default;
};

/// What a crypto node sends with a store read: the object versions it
/// already holds of the token (empty for the catalog).
struct store_read_request {
    std::vector<object_version> have;

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1).u32(static_cast<std::uint32_t>(have.size()));
        for (const auto& h : have) {
            w.u64(h.handle).u64(h.version);
        }
        return w.take_string();
    }

    /// Nothing when `body` is malformed.
    [[nodiscard]] static auto decode(std::string_view body) -> std::optional<store_read_request> {
        try {
            byte_reader r(body);
            if (r.u8() != 1) {
                return std::nullopt;
            }
            const auto n = r.u32();
            // Each pair is 16 bytes: refuse a count the body cannot hold
            // before reserving for it.
            if (n > (body.size() - 5) / 16) {
                return std::nullopt;
            }
            store_read_request out;
            out.have.reserve(n);
            for (std::uint32_t i = 0; i < n; ++i) {
                const auto handle = r.u64();
                out.have.push_back({handle, r.u64()});
            }
            r.finish();
            return out;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
};

enum class store_read_status : std::uint8_t {
    ok = 0,
    /// The token does not exist (never created, or deleted).
    absent = 1,
    /// A read-index round could not be had: answer CKR_DEVICE_ERROR.
    unavailable = 2,
};

/// The catalog as a store member had it after a catalog barrier.
struct catalog_view {
    std::optional<catalog_record> record;
    std::vector<token_entry> tokens;
    std::vector<std::pair<std::string, std::uint64_t>> bindings;
};

/// A token group as a store member had it after a barrier on it.
struct token_view {
    std::optional<token_record> record;
    /// Every live object's handle and version, in handle order.
    std::vector<object_version> live;
    /// The full records of the live objects the caller did not hold at
    /// that version.
    std::vector<object_record> changed;
};

struct store_read_answer {
    store_read_status status = store_read_status::unavailable;
    /// The catalog record after the catalog barrier: the seal state every
    /// answer carries (Requirement 4.2). Nothing before initialization.
    std::optional<catalog_record> seal_state;
    /// Filled for a catalog read.
    catalog_view catalog;
    /// Filled for a token read.
    token_view token;
};

namespace detail {

inline auto put_optional(byte_writer& w, const std::optional<std::string>& v) -> void {
    w.u8(v ? 1 : 0);
    w.str(v.value_or(std::string()));
}

inline auto get_optional(byte_reader& r) -> std::optional<std::string> {
    const bool has = r.u8() != 0;
    auto s = r.str();
    if (!has) {
        return std::nullopt;
    }
    return s;
}

}  // namespace detail

/// `a` on the wire.
[[nodiscard]] inline auto encode_store_read_answer(const store_read_answer& a) -> std::string {
    byte_writer w;
    w.u8(1).u8(static_cast<std::uint8_t>(a.status));
    detail::put_optional(w, a.seal_state ? std::optional(a.seal_state->encode()) : std::nullopt);
    // Catalog view.
    detail::put_optional(
        w, a.catalog.record ? std::optional(a.catalog.record->encode()) : std::nullopt);
    w.u32(static_cast<std::uint32_t>(a.catalog.tokens.size()));
    for (const auto& t : a.catalog.tokens) {
        w.str(t.encode());
    }
    w.u32(static_cast<std::uint32_t>(a.catalog.bindings.size()));
    for (const auto& [identity, token] : a.catalog.bindings) {
        w.str(identity).u64(token);
    }
    // Token view.
    detail::put_optional(w,
                         a.token.record ? std::optional(a.token.record->encode()) : std::nullopt);
    w.u32(static_cast<std::uint32_t>(a.token.live.size()));
    for (const auto& l : a.token.live) {
        w.u64(l.handle).u64(l.version);
    }
    w.u32(static_cast<std::uint32_t>(a.token.changed.size()));
    for (const auto& o : a.token.changed) {
        byte_writer one;
        o.encode_to(one);
        w.str(one.take_string());
    }
    return w.take_string();
}

/// The answer in `body`; `unavailable` when it does not decode.
[[nodiscard]] inline auto decode_store_read_answer(std::string_view body) -> store_read_answer {
    store_read_answer out;
    try {
        byte_reader r(body);
        if (r.u8() != 1) {
            return {};
        }
        const auto status = r.u8();
        if (status > static_cast<std::uint8_t>(store_read_status::unavailable)) {
            return {};
        }
        out.status = static_cast<store_read_status>(status);
        if (auto s = detail::get_optional(r)) {
            out.seal_state = catalog_record::decode(*s);
        }
        if (auto c = detail::get_optional(r)) {
            out.catalog.record = catalog_record::decode(*c);
        }
        for (auto n = r.u32(); n > 0; --n) {
            out.catalog.tokens.push_back(token_entry::decode(r.str()));
        }
        for (auto n = r.u32(); n > 0; --n) {
            auto identity = r.str();
            out.catalog.bindings.emplace_back(std::move(identity), r.u64());
        }
        if (auto t = detail::get_optional(r)) {
            out.token.record = token_record::decode(*t);
        }
        for (auto n = r.u32(); n > 0; --n) {
            const auto handle = r.u64();
            out.token.live.push_back({handle, r.u64()});
        }
        for (auto n = r.u32(); n > 0; --n) {
            const auto one = r.str();
            byte_reader o(one);
            out.token.changed.push_back(object_record::decode_from(o));
            o.finish();
        }
        r.finish();
    } catch (const std::exception&) {
        return {};
    }
    return out;
}

/// Answers a store read of local group `group` (0 the catalog, else a
/// token id) from `host`'s replica, after the barriers described above.
/// `host` is a basic_hsm_host or anything with its catalog_barrier(),
/// read_barrier(), reads and bindings().
template<typename HsmHost>
[[nodiscard]] auto serve_store_read(HsmHost& host, std::uint64_t group,
                                    const store_read_request& request) -> store_read_answer {
    store_read_answer out;
    if (!host.catalog_barrier()) {
        return out;  // unavailable
    }
    out.seal_state = host.catalog();
    if (group == 0) {
        out.status = store_read_status::ok;
        out.catalog.record = out.seal_state;
        out.catalog.tokens = host.tokens();
        out.catalog.bindings = host.bindings();
        return out;
    }
    if (!host.token(group)) {
        out.status = store_read_status::absent;
        return out;
    }
    if (!host.read_barrier(group)) {
        // A delete committed meanwhile destroys the group under the
        // barrier; that is an absent token, not an outage.
        if (host.catalog_barrier() && !host.token(group)) {
            out.status = store_read_status::absent;
        }
        return out;
    }
    std::map<std::uint64_t, std::uint64_t> held;
    for (const auto& h : request.have) {
        held[h.handle] = h.version;
    }
    out.token.record = host.token_record_of(group);
    for (auto& o : host.objects(group)) {
        out.token.live.push_back({o.handle, o.version});
        const auto it = held.find(o.handle);
        if (it == held.end() || it->second != o.version) {
            out.token.changed.push_back(std::move(o));
        }
    }
    out.status = store_read_status::ok;
    return out;
}

}  // namespace kythira::hsm
