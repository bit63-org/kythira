// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS catalog group (.kiro/specs/kms-compatible-api/ task 4,
// Requirements 3.3-3.5, 6.1, 6.2, 8.1, 9.4, 13.4): every account's keys,
// their backing-key versions, aliases, key policies, grants, tags and the
// state the leader's jobs work from (creations to finish, rotations and
// deletions that are due). One per KMS.
//
// It holds no key material. A version names its backing key by the HSM
// object id the HSM gave it; the material stays a non-extractable object
// on the HSM's `kms` token. The command format has no field for bytes at
// all, only integers and UTF-8 text (kms_codec.hpp), so raw material
// cannot ride in the log or a snapshot even by mistake.
//
// Every command starts with a format byte (k_command_format) and a tag,
// and carries the leader's clock as `now_ms` where it needs time, so every
// replica applies it alike.
//
// Key states follow AWS: Creating (between the catalog entry and the
// HSM's backing key, design "Metadata in the KMS"), Enabled, Disabled and
// PendingDeletion. Destroying a key keeps a tombstone, so DescribeKey
// answers NotFoundException and the id is never reused (9.4).
//
// Layout under `ns`:
//   data  ns "k" key-id                     key record
//   data  ns "K" account 0x00 key-id        the account's keys, for ListKeys
//   data  ns "v" key-id 0x00 be32(version)  backing-key version
//   data  ns "a" account 0x00 alias         alias record
//   data  ns "A" key-id 0x00 alias          the key's aliases
//   data  ns "g" key-id 0x00 grant-id       grant record
//   data  ns "t" key-id 0x00 tag-key        tag value
//   data  ns "x" key-id                     tombstone (the account)
//   data  ns "n" account                    the account's counts
//   data  ns "l" account                    the account's limit overrides
//   data  ns "J"                            the job lease
//   meta  ns                                applied index
//
// A reply is one catalog_status byte.
//
// The job lease (.kiro/specs/kms-independent-layers/ task 2,
// Requirements 5.1-5.3): rotation, deletion and the orphan sweep call the
// HSM, so they run on one front end, the lease holder, not on the
// catalog leader (a data node holds no HSM credentials). The lease is a
// record with a holder, an expiry on the proposer's clock and a fencing
// token. acquire_lease grants it when it is free, expired at the
// command's now_ms, or already the proposer's (a renewal, same token); a
// new holder gets the next token. A job command is sent fenced
// (make_fenced_command): the token, then the command itself, and apply
// refuses it with stale_lease unless the token is the current one and
// the lease is held (not released). Commands carry no clock check: a
// holder past its expiry with nobody taking over may still act, which is
// safe because nobody else does. So a
// holder that stalled past its expiry while another took over cannot
// commit a stale step.

#include <kythira/kms/kms_codec.hpp>
#include <kythira/kms/kms_group.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/persistent_state_machine.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

/// The command format this catalog writes and applies.
inline constexpr std::uint8_t k_command_format = 1;

// AWS's quotas and limits (Key Management Service Developer Guide,
// "Quotas"). The per-account counts are operator-overridable
// (set_account_limits); the others are fixed, as on AWS.
inline constexpr std::uint32_t k_default_max_keys = 100000;
inline constexpr std::uint32_t k_default_max_aliases = 50000;
inline constexpr std::size_t k_max_grants_per_key = 50000;
inline constexpr std::size_t k_max_aliases_per_key = 50;
inline constexpr std::size_t k_max_tags_per_key = 50;
inline constexpr std::size_t k_max_policy_bytes = 32768;
inline constexpr std::size_t k_max_description_bytes = 8192;
inline constexpr std::uint64_t k_ms_per_day = 86400000;
/// How often AWS managed keys rotate.
inline constexpr std::uint32_t k_managed_rotation_days = 365;

enum class key_spec : std::uint8_t {
    symmetric_default = 1,
    rsa_2048,
    rsa_3072,
    rsa_4096,
    ecc_nist_p256,
    ecc_nist_p384,
    ecc_nist_p521,
    ecc_secg_p256k1,
    hmac_224,
    hmac_256,
    hmac_384,
    hmac_512,
};

enum class key_usage : std::uint8_t {
    encrypt_decrypt = 1,
    sign_verify = 2,
    generate_verify_mac = 3,
};

enum class key_state : std::uint8_t {
    creating = 1,
    enabled = 2,
    disabled = 3,
    pending_deletion = 4,
};

enum class key_manager : std::uint8_t {
    customer = 1,
    aws = 2,
    /// A consuming service's owned key (Requirement 10.3): listed in no
    /// account and used only by that service (kms_managed.hpp).
    owned = 3,
};

/// Whether a service manages `m`, not the customer: AWS managed and owned
/// keys refuse every change a customer could ask for.
[[nodiscard]] constexpr auto service_managed(key_manager m) noexcept -> bool {
    return m != key_manager::customer;
}

enum class rotation_type : std::uint8_t {
    initial = 0,
    automatic = 1,
    on_demand = 2,
};

enum class grant_constraint : std::uint8_t {
    none = 0,
    context_equals = 1,
    context_subset = 2,
};

enum class catalog_status : std::uint8_t {
    ok = 0,
    not_found = 1,       // NotFoundException
    already_exists = 2,  // AlreadyExistsException
    invalid_state = 3,   // KMSInvalidStateException
    limit_exceeded = 4,  // LimitExceededException
    /// The request names something this catalog cannot do: a tombstoned
    /// id, a version out of order, an alias of another account's key.
    rejected = 5,
    /// A fenced job command whose lease token is not the current one, or
    /// a lease request while another holder's lease is live: the proposer
    /// does not hold the job lease (independent-layers Requirement 5.2).
    stale_lease = 6,
};

struct key_spec_info {
    key_spec spec;
    std::string_view name;
    std::array<key_usage, 2> usages;  // unused slot repeats the first
};

/// Each spec Requirement 3.2 names, its AWS name and the usages AWS allows
/// for it. KEY_AGREEMENT on ECC keys is not here: DeriveSharedSecret is
/// in no task of the spec.
inline constexpr std::array<key_spec_info, 12> k_key_specs{{
    {key_spec::symmetric_default,
     "SYMMETRIC_DEFAULT",
     {key_usage::encrypt_decrypt, key_usage::encrypt_decrypt}},
    {key_spec::rsa_2048, "RSA_2048", {key_usage::encrypt_decrypt, key_usage::sign_verify}},
    {key_spec::rsa_3072, "RSA_3072", {key_usage::encrypt_decrypt, key_usage::sign_verify}},
    {key_spec::rsa_4096, "RSA_4096", {key_usage::encrypt_decrypt, key_usage::sign_verify}},
    {key_spec::ecc_nist_p256, "ECC_NIST_P256", {key_usage::sign_verify, key_usage::sign_verify}},
    {key_spec::ecc_nist_p384, "ECC_NIST_P384", {key_usage::sign_verify, key_usage::sign_verify}},
    {key_spec::ecc_nist_p521, "ECC_NIST_P521", {key_usage::sign_verify, key_usage::sign_verify}},
    {key_spec::ecc_secg_p256k1,
     "ECC_SECG_P256K1",
     {key_usage::sign_verify, key_usage::sign_verify}},
    {key_spec::hmac_224,
     "HMAC_224",
     {key_usage::generate_verify_mac, key_usage::generate_verify_mac}},
    {key_spec::hmac_256,
     "HMAC_256",
     {key_usage::generate_verify_mac, key_usage::generate_verify_mac}},
    {key_spec::hmac_384,
     "HMAC_384",
     {key_usage::generate_verify_mac, key_usage::generate_verify_mac}},
    {key_spec::hmac_512,
     "HMAC_512",
     {key_usage::generate_verify_mac, key_usage::generate_verify_mac}},
}};

[[nodiscard]] constexpr auto find_key_spec(key_spec s) -> const key_spec_info* {
    for (const auto& i : k_key_specs) {
        if (i.spec == s) {
            return &i;
        }
    }
    return nullptr;
}

[[nodiscard]] constexpr auto usage_allowed(key_spec s, key_usage u) -> bool {
    const auto* i = find_key_spec(s);
    return i != nullptr && (i->usages[0] == u || i->usages[1] == u);
}

[[nodiscard]] constexpr auto is_symmetric(key_spec s) -> bool {
    return s == key_spec::symmetric_default;
}

/// AWS's alias name rule: `alias/` then 1 to 250 of [A-Za-z0-9/_-].
/// `alias/aws/` names are AWS managed keys' and no customer may make one.
[[nodiscard]] inline auto valid_alias_name(std::string_view name) -> bool {
    static constexpr std::string_view prefix = "alias/";
    if (!name.starts_with(prefix) || name.size() == prefix.size() || name.size() > 256) {
        return false;
    }
    return std::ranges::all_of(name.substr(prefix.size()), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '/' || c == '_' || c == '-';
    });
}

[[nodiscard]] inline auto is_aws_alias(std::string_view name) -> bool {
    return name.starts_with("alias/aws/");
}

using tag_map = std::map<std::string, std::string, std::less<>>;

namespace detail {

inline auto put_map(byte_writer& w, const tag_map& m) -> void {
    w.u32(static_cast<std::uint32_t>(m.size()));
    for (const auto& [k, v] : m) {
        w.str(k).str(v);
    }
}

inline auto get_map(byte_reader& r) -> tag_map {
    tag_map m;
    const auto n = r.u32();
    for (std::uint32_t i = 0; i < n; ++i) {
        auto k = r.str();
        m[std::move(k)] = r.str();
    }
    return m;
}

inline auto put_list(byte_writer& w, const std::vector<std::string>& v) -> void {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const auto& s : v) {
        w.str(s);
    }
}

inline auto get_list(byte_reader& r) -> std::vector<std::string> {
    std::vector<std::string> v;
    const auto n = r.u32();
    for (std::uint32_t i = 0; i < n; ++i) {
        v.push_back(r.str());
    }
    return v;
}

[[nodiscard]] inline auto be32_key(std::uint32_t v) -> std::string {
    std::string out(4, '\0');
    for (int i = 3; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = static_cast<char>(v & 0xFFU);
        v >>= 8U;
    }
    return out;
}

template<typename E> [[nodiscard]] auto enum_in(std::uint8_t v, E lo, E hi) -> E {
    if (v < static_cast<std::uint8_t>(lo) || v > static_cast<std::uint8_t>(hi)) {
        throw std::invalid_argument("kms catalog: enum out of range");
    }
    return static_cast<E>(v);
}

}  // namespace detail

/// A key's metadata (Requirement 3.5).
struct key_record {
    std::string key_id;
    std::string account;
    std::string description;
    key_spec spec = key_spec::symmetric_default;
    key_usage usage = key_usage::encrypt_decrypt;
    key_state state = key_state::creating;
    key_manager manager = key_manager::customer;
    std::uint64_t creation_ms = 0;
    /// When a PendingDeletion key is destroyed.
    std::uint64_t deletion_ms = 0;
    std::uint32_t pending_window_days = 0;
    bool rotation_enabled = false;
    std::uint32_t rotation_period_days = 0;
    std::uint64_t next_rotation_ms = 0;
    /// The version new ciphertexts use; 0 while Creating.
    std::uint32_t current_version = 0;
    std::string policy;

    auto operator==(const key_record&) const -> bool = default;

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1).str(key_id).str(account).str(description);
        w.u8(static_cast<std::uint8_t>(spec))
            .u8(static_cast<std::uint8_t>(usage))
            .u8(static_cast<std::uint8_t>(state))
            .u8(static_cast<std::uint8_t>(manager));
        w.u64(creation_ms).u64(deletion_ms).u32(pending_window_days);
        w.boolean(rotation_enabled).u32(rotation_period_days).u64(next_rotation_ms);
        w.u32(current_version).str(policy);
        return w.take_string();
    }

    [[nodiscard]] static auto decode(std::string_view in) -> key_record {
        byte_reader r(in);
        if (r.u8() != 1) {
            throw std::invalid_argument("kms key record: unknown version");
        }
        key_record k;
        k.key_id = r.str();
        k.account = r.str();
        k.description = r.str();
        k.spec = detail::enum_in(r.u8(), key_spec::symmetric_default, key_spec::hmac_512);
        k.usage =
            detail::enum_in(r.u8(), key_usage::encrypt_decrypt, key_usage::generate_verify_mac);
        k.state = detail::enum_in(r.u8(), key_state::creating, key_state::pending_deletion);
        k.manager = detail::enum_in(r.u8(), key_manager::customer, key_manager::owned);
        k.creation_ms = r.u64();
        k.deletion_ms = r.u64();
        k.pending_window_days = r.u32();
        k.rotation_enabled = r.boolean();
        k.rotation_period_days = r.u32();
        k.next_rotation_ms = r.u64();
        k.current_version = r.u32();
        k.policy = r.str();
        r.finish();
        return k;
    }
};

/// One backing key of a KMS key: the HSM object that holds its material.
struct key_version {
    std::uint32_t version = 0;
    std::uint64_t hsm_object = 0;
    std::uint64_t created_ms = 0;
    rotation_type type = rotation_type::initial;

    auto operator==(const key_version&) const -> bool = default;

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1).u32(version).u64(hsm_object).u64(created_ms).u8(static_cast<std::uint8_t>(type));
        return w.take_string();
    }

    [[nodiscard]] static auto decode(std::string_view in) -> key_version {
        byte_reader r(in);
        if (r.u8() != 1) {
            throw std::invalid_argument("kms key version: unknown version");
        }
        key_version v;
        v.version = r.u32();
        v.hsm_object = r.u64();
        v.created_ms = r.u64();
        v.type = detail::enum_in(r.u8(), rotation_type::initial, rotation_type::on_demand);
        r.finish();
        return v;
    }
};

struct alias_record {
    std::string account;
    std::string name;
    std::string key_id;
    std::uint64_t created_ms = 0;
    std::uint64_t updated_ms = 0;

    auto operator==(const alias_record&) const -> bool = default;

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1).str(account).str(name).str(key_id).u64(created_ms).u64(updated_ms);
        return w.take_string();
    }

    [[nodiscard]] static auto decode(std::string_view in) -> alias_record {
        byte_reader r(in);
        if (r.u8() != 1) {
            throw std::invalid_argument("kms alias record: unknown version");
        }
        alias_record a;
        a.account = r.str();
        a.name = r.str();
        a.key_id = r.str();
        a.created_ms = r.u64();
        a.updated_ms = r.u64();
        r.finish();
        return a;
    }
};

struct grant_record {
    std::string grant_id;
    std::string key_id;
    std::string name;
    std::string grantee_principal;
    std::string retiring_principal;
    std::string issuing_account;
    std::vector<std::string> operations;
    grant_constraint constraint = grant_constraint::none;
    tag_map constraint_context;
    std::uint64_t created_ms = 0;
    /// Made by an AWS managed key's service (Requirement 8.4).
    bool for_aws_resource = false;

    auto operator==(const grant_record&) const -> bool = default;

    auto write(byte_writer& w) const -> void {
        w.str(grant_id).str(key_id).str(name).str(grantee_principal).str(retiring_principal);
        w.str(issuing_account);
        detail::put_list(w, operations);
        w.u8(static_cast<std::uint8_t>(constraint));
        detail::put_map(w, constraint_context);
        w.u64(created_ms).boolean(for_aws_resource);
    }

    static auto read(byte_reader& r) -> grant_record {
        grant_record g;
        g.grant_id = r.str();
        g.key_id = r.str();
        g.name = r.str();
        g.grantee_principal = r.str();
        g.retiring_principal = r.str();
        g.issuing_account = r.str();
        g.operations = detail::get_list(r);
        g.constraint =
            detail::enum_in(r.u8(), grant_constraint::none, grant_constraint::context_subset);
        g.constraint_context = detail::get_map(r);
        g.created_ms = r.u64();
        g.for_aws_resource = r.boolean();
        return g;
    }

    [[nodiscard]] auto encode() const -> std::string {
        byte_writer w;
        w.u8(1);
        write(w);
        return w.take_string();
    }

    [[nodiscard]] static auto decode(std::string_view in) -> grant_record {
        byte_reader r(in);
        if (r.u8() != 1) {
            throw std::invalid_argument("kms grant record: unknown version");
        }
        auto g = read(r);
        r.finish();
        return g;
    }
};

/// An account's live keys and aliases; AWS managed keys do not count
/// toward the key quota, as on AWS.
struct account_counts {
    std::uint32_t keys = 0;
    std::uint32_t aliases = 0;

    auto operator==(const account_counts&) const -> bool = default;
};

/// Operator overrides of the account quotas; 0 keeps AWS's default.
struct account_limits {
    std::uint32_t max_keys = 0;
    std::uint32_t max_aliases = 0;

    auto operator==(const account_limits&) const -> bool = default;
};

enum class catalog_command : std::uint8_t {
    create_key = 1,
    complete_key = 2,
    set_enabled = 3,
    update_description = 4,
    put_policy = 5,
    schedule_deletion = 6,
    cancel_deletion = 7,
    destroy_key = 8,
    add_version = 9,
    set_rotation = 10,
    create_alias = 11,
    update_alias = 12,
    delete_alias = 13,
    tag_key = 14,
    untag_key = 15,
    create_grant = 16,
    remove_grant = 17,
    set_account_limits = 18,
    acquire_lease = 19,
    release_lease = 20,
    /// A token, then a whole command after its format byte.
    fenced = 21,
};

/// The job lease (independent-layers task 2). Token 0 means no holder ever.
struct job_lease {
    std::string holder;  ///< empty when released or never held
    std::uint64_t token = 0;
    std::uint64_t expiry_ms = 0;

    auto operator==(const job_lease&) const -> bool = default;

    /// Whether `who` holds it at `now_ms` by the record (the holder's own
    /// view should keep a margin before expiry_ms).
    [[nodiscard]] auto held_by(std::string_view who, std::uint64_t now_ms) const -> bool {
        return !holder.empty() && holder == who && now_ms < expiry_ms;
    }
};

namespace detail {

inline auto start(catalog_command c) -> byte_writer {
    byte_writer w;
    w.u8(k_command_format).u8(static_cast<std::uint8_t>(c));
    return w;
}

}  // namespace detail

// -- Commands ------------------------------------------------------------------
//
// The leader validates a request against AWS's rules before it proposes a
// command, so a structurally bad command is a bug and apply throws; a
// command that is well formed but conflicts with the state (a name taken,
// a key in the wrong state, a quota reached) gets a catalog_status.

/// A new key in Creating, with its policy, tags and description; the
/// backing key comes next (complete_key).
[[nodiscard]] inline auto make_create_key_command(const key_record& k, const tag_map& tags)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::create_key);
    w.str(k.key_id).str(k.account).str(k.description);
    w.u8(static_cast<std::uint8_t>(k.spec))
        .u8(static_cast<std::uint8_t>(k.usage))
        .u8(static_cast<std::uint8_t>(k.manager));
    w.u64(k.creation_ms).str(k.policy);
    detail::put_map(w, tags);
    return w.take();
}

/// The backing key the HSM made for a Creating key: version 1, Enabled.
[[nodiscard]] inline auto make_complete_key_command(std::string_view key_id,
                                                    std::uint64_t hsm_object, std::uint64_t now_ms)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::complete_key);
    w.str(key_id).u64(hsm_object).u64(now_ms);
    return w.take();
}

/// EnableKey or DisableKey.
[[nodiscard]] inline auto make_set_enabled_command(std::string_view key_id, bool enabled)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::set_enabled);
    w.str(key_id).boolean(enabled);
    return w.take();
}

[[nodiscard]] inline auto make_update_description_command(std::string_view key_id,
                                                          std::string_view description)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::update_description);
    w.str(key_id).str(description);
    return w.take();
}

[[nodiscard]] inline auto make_put_policy_command(std::string_view key_id, std::string_view policy)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::put_policy);
    w.str(key_id).str(policy);
    return w.take();
}

/// ScheduleKeyDeletion with a 7 to 30 day window.
[[nodiscard]] inline auto make_schedule_deletion_command(std::string_view key_id,
                                                         std::uint32_t window_days,
                                                         std::uint64_t now_ms)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::schedule_deletion);
    w.str(key_id).u32(window_days).u64(now_ms);
    return w.take();
}

[[nodiscard]] inline auto make_cancel_deletion_command(std::string_view key_id)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::cancel_deletion);
    w.str(key_id);
    return w.take();
}

/// The end of a key: a PendingDeletion key whose window has passed (after
/// the leader destroyed its backing keys on the HSM), or a Creating key
/// the orphan sweep gives up on. Leaves a tombstone.
[[nodiscard]] inline auto make_destroy_key_command(std::string_view key_id, std::uint64_t now_ms)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::destroy_key);
    w.str(key_id).u64(now_ms);
    return w.take();
}

/// A rotation: `version` must be the key's current one plus one.
[[nodiscard]] inline auto make_add_version_command(std::string_view key_id, std::uint32_t version,
                                                   std::uint64_t hsm_object, rotation_type type,
                                                   std::uint64_t now_ms) -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::add_version);
    w.str(key_id).u32(version).u64(hsm_object).u8(static_cast<std::uint8_t>(type)).u64(now_ms);
    return w.take();
}

/// EnableKeyRotation (period 90 to 2560 days) or DisableKeyRotation.
[[nodiscard]] inline auto make_set_rotation_command(std::string_view key_id, bool enabled,
                                                    std::uint32_t period_days, std::uint64_t now_ms)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::set_rotation);
    w.str(key_id).boolean(enabled).u32(period_days).u64(now_ms);
    return w.take();
}

/// CreateAlias. `managed` lets an AWS managed key's `alias/aws/...` in.
[[nodiscard]] inline auto make_create_alias_command(std::string_view account, std::string_view name,
                                                    std::string_view key_id, bool managed,
                                                    std::uint64_t now_ms)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::create_alias);
    w.str(account).str(name).str(key_id).boolean(managed).u64(now_ms);
    return w.take();
}

[[nodiscard]] inline auto make_update_alias_command(std::string_view account, std::string_view name,
                                                    std::string_view key_id, std::uint64_t now_ms)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::update_alias);
    w.str(account).str(name).str(key_id).u64(now_ms);
    return w.take();
}

[[nodiscard]] inline auto make_delete_alias_command(std::string_view account, std::string_view name)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::delete_alias);
    w.str(account).str(name);
    return w.take();
}

/// TagResource: adds or replaces each tag.
[[nodiscard]] inline auto make_tag_key_command(std::string_view key_id, const tag_map& tags)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::tag_key);
    w.str(key_id);
    detail::put_map(w, tags);
    return w.take();
}

[[nodiscard]] inline auto make_untag_key_command(std::string_view key_id,
                                                 const std::vector<std::string>& keys)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::untag_key);
    w.str(key_id);
    detail::put_list(w, keys);
    return w.take();
}

[[nodiscard]] inline auto make_create_grant_command(const grant_record& g)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::create_grant);
    g.write(w);
    return w.take();
}

/// RetireGrant or RevokeGrant: both remove the grant.
[[nodiscard]] inline auto make_remove_grant_command(std::string_view key_id,
                                                    std::string_view grant_id)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::remove_grant);
    w.str(key_id).str(grant_id);
    return w.take();
}

/// The operator's override of an account's key and alias quotas
/// (Requirement 13.4); 0 restores AWS's default.
[[nodiscard]] inline auto make_set_account_limits_command(std::string_view account,
                                                          const account_limits& l)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::set_account_limits);
    w.str(account).u32(l.max_keys).u32(l.max_aliases);
    return w.take();
}

/// Takes the job lease for `holder` until now_ms + duration_ms, or renews
/// it; stale_lease while another holder's lease is live.
[[nodiscard]] inline auto make_acquire_lease_command(std::string_view holder, std::uint64_t now_ms,
                                                     std::uint64_t duration_ms)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::acquire_lease);
    w.str(holder).u64(now_ms).u64(duration_ms);
    return w.take();
}

/// Gives the lease up (a draining holder, Requirement 10.2), so another
/// takes it at once rather than at expiry; stale_lease when `holder` with
/// `token` no longer holds it.
[[nodiscard]] inline auto make_release_lease_command(std::string_view holder, std::uint64_t token)
    -> std::vector<std::byte> {
    auto w = detail::start(catalog_command::release_lease);
    w.str(holder).u64(token);
    return w.take();
}

/// `command` applied only while `token` is the job lease's current token.
/// The command follows the token as it is, without a length, so the
/// format still has no byte field. A lease command cannot be fenced.
[[nodiscard]] inline auto make_fenced_command(std::uint64_t token,
                                              const std::vector<std::byte>& command)
    -> std::vector<std::byte> {
    if (command.size() < 2 || std::to_integer<std::uint8_t>(command[0]) != k_command_format) {
        throw std::invalid_argument("make_fenced_command: not a catalog command");
    }
    const auto tag = static_cast<catalog_command>(std::to_integer<std::uint8_t>(command[1]));
    if (tag == catalog_command::fenced || tag == catalog_command::acquire_lease ||
        tag == catalog_command::release_lease) {
        throw std::invalid_argument("make_fenced_command: a lease command is not fenced");
    }
    auto w = detail::start(catalog_command::fenced);
    w.u64(token);
    auto out = w.take();
    out.insert(out.end(), command.begin() + 1, command.end());
    return out;
}

[[nodiscard]] inline auto catalog_reply_status(const std::vector<std::byte>& reply)
    -> catalog_status {
    byte_reader r(reply);
    const auto v = r.u8();
    r.finish();
    return detail::enum_in(v, catalog_status::ok, catalog_status::stale_lease);
}

template<kythira::kv_engine Engine = kythira::memory_kv_engine, typename LogIndex = std::uint64_t>
class kms_catalog_state_machine : public kms_group<Engine, LogIndex> {
    using base = kms_group<Engine, LogIndex>;

public:
    using engine_type = Engine;

    explicit kms_catalog_state_machine(std::string ns) : base(std::move(ns)) {}

    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        if (this->already_applied(index)) {
            return {};
        }
        kythira::write_batch batch;
        byte_reader r(command);
        if (r.u8() != k_command_format) {
            throw std::invalid_argument("kms_catalog_state_machine: unknown command format");
        }
        auto tag = static_cast<catalog_command>(r.u8());
        if (tag == catalog_command::fenced) {
            const auto token = r.u64();
            tag = static_cast<catalog_command>(r.u8());
            if (tag == catalog_command::fenced || tag == catalog_command::acquire_lease ||
                tag == catalog_command::release_lease) {
                throw std::invalid_argument("kms_catalog_state_machine: a fenced lease command");
            }
            if (const auto l = lease(); token == 0 || token != l.token || l.holder.empty()) {
                // The rest is not read: a stale holder's step changes
                // nothing, whatever it was.
                this->commit(batch, index);
                return status_reply(catalog_status::stale_lease);
            }
        }
        catalog_status s = catalog_status::ok;
        switch (tag) {
            case catalog_command::create_key:
                s = apply_create_key(r, batch);
                break;
            case catalog_command::complete_key:
                s = apply_complete_key(r, batch);
                break;
            case catalog_command::set_enabled:
                s = apply_set_enabled(r, batch);
                break;
            case catalog_command::update_description:
                s = apply_update_description(r, batch);
                break;
            case catalog_command::put_policy:
                s = apply_put_policy(r, batch);
                break;
            case catalog_command::schedule_deletion:
                s = apply_schedule_deletion(r, batch);
                break;
            case catalog_command::cancel_deletion:
                s = apply_cancel_deletion(r, batch);
                break;
            case catalog_command::destroy_key:
                s = apply_destroy_key(r, batch);
                break;
            case catalog_command::add_version:
                s = apply_add_version(r, batch);
                break;
            case catalog_command::set_rotation:
                s = apply_set_rotation(r, batch);
                break;
            case catalog_command::create_alias:
                s = apply_create_alias(r, batch);
                break;
            case catalog_command::update_alias:
                s = apply_update_alias(r, batch);
                break;
            case catalog_command::delete_alias:
                s = apply_delete_alias(r, batch);
                break;
            case catalog_command::tag_key:
                s = apply_tag_key(r, batch);
                break;
            case catalog_command::untag_key:
                s = apply_untag_key(r, batch);
                break;
            case catalog_command::create_grant:
                s = apply_create_grant(r, batch);
                break;
            case catalog_command::remove_grant:
                s = apply_remove_grant(r, batch);
                break;
            case catalog_command::set_account_limits:
                s = apply_set_account_limits(r, batch);
                break;
            case catalog_command::acquire_lease:
                s = apply_acquire_lease(r, batch);
                break;
            case catalog_command::release_lease:
                s = apply_release_lease(r, batch);
                break;
            default:
                throw std::invalid_argument("kms_catalog_state_machine: unknown command");
        }
        r.finish();
        this->commit(batch, index);
        return status_reply(s);
    }

    // -- Reads ---------------------------------------------------------------

    [[nodiscard]] auto key(std::string_view key_id) const -> std::optional<key_record> {
        auto v = this->get("k" + std::string(key_id));
        if (!v) {
            return std::nullopt;
        }
        return key_record::decode(*v);
    }

    /// Whether `key_id` was a key and was destroyed.
    [[nodiscard]] auto tombstoned(std::string_view key_id) const -> bool {
        return this->get("x" + std::string(key_id)).has_value();
    }

    /// Up to `limit` of the account's keys after `after` (exclusive), in id
    /// order, for ListKeys' Marker.
    [[nodiscard]] auto keys(std::string_view account, std::string_view after = {},
                            std::size_t limit = SIZE_MAX) const -> std::vector<std::string> {
        std::vector<std::string> out;
        const std::string prefix = "K" + std::string(account) + std::string(1, '\0');
        this->scan_prefix(prefix, [&](std::string_view k, std::string_view) {
            const auto id = k.substr(prefix.size());
            if (!after.empty() && id <= after) {
                return true;
            }
            out.emplace_back(id);
            return out.size() < limit;
        });
        return out;
    }

    [[nodiscard]] auto versions(std::string_view key_id) const -> std::vector<key_version> {
        std::vector<key_version> out;
        this->scan_prefix(key_child_prefix('v', key_id), [&](std::string_view, std::string_view v) {
            out.push_back(key_version::decode(v));
            return true;
        });
        return out;
    }

    [[nodiscard]] auto version(std::string_view key_id, std::uint32_t v) const
        -> std::optional<key_version> {
        auto s = this->get(key_child_prefix('v', key_id) + detail::be32_key(v));
        if (!s) {
            return std::nullopt;
        }
        return key_version::decode(*s);
    }

    [[nodiscard]] auto alias(std::string_view account, std::string_view name) const
        -> std::optional<alias_record> {
        auto v = this->get(alias_key(account, name));
        if (!v) {
            return std::nullopt;
        }
        return alias_record::decode(*v);
    }

    /// The account's aliases in name order, or only `key_id`'s.
    [[nodiscard]] auto aliases(std::string_view account, std::string_view key_id = {}) const
        -> std::vector<alias_record> {
        std::vector<alias_record> out;
        if (!key_id.empty()) {
            const std::string prefix = key_alias_prefix(key_id);
            this->scan_prefix(prefix, [&](std::string_view k, std::string_view) {
                if (auto a = alias(account, k.substr(prefix.size()))) {
                    out.push_back(std::move(*a));
                }
                return true;
            });
            return out;
        }
        this->scan_prefix("a" + std::string(account) + std::string(1, '\0'),
                          [&](std::string_view, std::string_view v) {
                              out.push_back(alias_record::decode(v));
                              return true;
                          });
        return out;
    }

    [[nodiscard]] auto grant(std::string_view key_id, std::string_view grant_id) const
        -> std::optional<grant_record> {
        auto v = this->get(grant_key(key_id, grant_id));
        if (!v) {
            return std::nullopt;
        }
        return grant_record::decode(*v);
    }

    [[nodiscard]] auto grants(std::string_view key_id) const -> std::vector<grant_record> {
        std::vector<grant_record> out;
        this->scan_prefix(key_child_prefix('g', key_id), [&](std::string_view, std::string_view v) {
            out.push_back(grant_record::decode(v));
            return true;
        });
        return out;
    }

    [[nodiscard]] auto tags(std::string_view key_id) const -> tag_map {
        tag_map out;
        const auto prefix = key_child_prefix('t', key_id);
        this->scan_prefix(prefix, [&](std::string_view k, std::string_view v) {
            out.emplace(std::string(k.substr(prefix.size())), std::string(v));
            return true;
        });
        return out;
    }

    [[nodiscard]] auto counts(std::string_view account) const -> account_counts {
        auto v = this->get("n" + std::string(account));
        if (!v) {
            return {};
        }
        byte_reader r(*v);
        account_counts c;
        c.keys = r.u32();
        c.aliases = r.u32();
        r.finish();
        return c;
    }

    [[nodiscard]] auto limits(std::string_view account) const -> account_limits {
        auto v = this->get("l" + std::string(account));
        if (!v) {
            return {};
        }
        byte_reader r(*v);
        account_limits l;
        l.max_keys = r.u32();
        l.max_aliases = r.u32();
        r.finish();
        return l;
    }

    /// The job lease as last written (independent-layers task 2).
    [[nodiscard]] auto lease() const -> job_lease {
        auto v = this->get("J");
        if (!v) {
            return {};
        }
        byte_reader r(*v);
        job_lease l;
        l.holder = r.str();
        l.token = r.u64();
        l.expiry_ms = r.u64();
        r.finish();
        return l;
    }

    // -- What the jobs work from (Requirement 3.4, 9.3, 9.4) ---------------------

    /// Keys still Creating: the orphan sweep finishes or destroys them.
    [[nodiscard]] auto creating_keys() const -> std::vector<key_record> {
        return keys_where([](const key_record& k) { return k.state == key_state::creating; });
    }

    /// PendingDeletion keys whose window ended at or before `now_ms`.
    [[nodiscard]] auto due_deletions(std::uint64_t now_ms) const -> std::vector<key_record> {
        return keys_where([now_ms](const key_record& k) {
            return k.state == key_state::pending_deletion && k.deletion_ms <= now_ms;
        });
    }

    /// Enabled symmetric keys with rotation on whose next rotation is due.
    [[nodiscard]] auto due_rotations(std::uint64_t now_ms) const -> std::vector<key_record> {
        return keys_where([now_ms](const key_record& k) {
            return k.state == key_state::enabled && k.rotation_enabled &&
                   k.next_rotation_ms <= now_ms;
        });
    }

private:
    template<typename P> [[nodiscard]] auto keys_where(P pred) const -> std::vector<key_record> {
        std::vector<key_record> out;
        this->scan_prefix("k", [&](std::string_view, std::string_view v) {
            auto k = key_record::decode(v);
            if (pred(k)) {
                out.push_back(std::move(k));
            }
            return true;
        });
        return out;
    }

    [[nodiscard]] static auto alias_key(std::string_view account, std::string_view name)
        -> std::string {
        return "a" + std::string(account) + std::string(1, '\0') + std::string(name);
    }
    [[nodiscard]] static auto key_alias_prefix(std::string_view key_id) -> std::string {
        return key_child_prefix('A', key_id);
    }
    [[nodiscard]] static auto key_child_prefix(char kind, std::string_view key_id) -> std::string {
        return std::string(1, kind) + std::string(key_id) + std::string(1, '\0');
    }
    [[nodiscard]] static auto grant_key(std::string_view key_id, std::string_view grant_id)
        -> std::string {
        return key_child_prefix('g', key_id) + std::string(grant_id);
    }
    [[nodiscard]] static auto account_key_index(std::string_view account, std::string_view key_id)
        -> std::string {
        return "K" + std::string(account) + std::string(1, '\0') + std::string(key_id);
    }

    auto put(kythira::write_batch& batch, const std::string& suffix, std::string value) -> void {
        batch.put(kythira::column_family::data, base::key(suffix), std::move(value));
    }
    auto erase(kythira::write_batch& batch, const std::string& suffix) -> void {
        batch.erase(kythira::column_family::data, base::key(suffix));
    }

    auto put_key(kythira::write_batch& batch, const key_record& k) -> void {
        put(batch, "k" + k.key_id, k.encode());
    }

    auto put_counts(kythira::write_batch& batch, std::string_view account, const account_counts& c)
        -> void {
        byte_writer w;
        w.u32(c.keys).u32(c.aliases);
        put(batch, "n" + std::string(account), w.take_string());
    }

    [[nodiscard]] auto max_keys(std::string_view account) const -> std::uint32_t {
        const auto l = limits(account).max_keys;
        return l == 0 ? k_default_max_keys : l;
    }
    [[nodiscard]] auto max_aliases(std::string_view account) const -> std::uint32_t {
        const auto l = limits(account).max_aliases;
        return l == 0 ? k_default_max_aliases : l;
    }

    // Structural checks a leader's validation makes impossible to fail.
    static auto require(bool ok, const char* what) -> void {
        if (!ok) {
            throw std::invalid_argument(std::string("kms_catalog_state_machine: ") + what);
        }
    }
    static auto require_key_id(std::string_view id) -> void {
        require(!id.empty() && id.size() <= 64 && id.find('\0') == std::string_view::npos,
                "bad key id");
    }
    static auto require_account(std::string_view a) -> void {
        require(
            a.size() == 12 && std::ranges::all_of(a, [](char c) { return c >= '0' && c <= '9'; }),
            "bad account");
    }
    static auto require_tags(const tag_map& tags) -> void {
        for (const auto& [k, v] : tags) {
            require(!k.empty() && k.size() <= 128 && v.size() <= 256 &&
                        k.find('\0') == std::string::npos,
                    "bad tag");
        }
    }

    // A key that exists (not tombstoned) and the command may act on.
    [[nodiscard]] auto live_key(std::string_view key_id) const -> std::optional<key_record> {
        return key(key_id);
    }

    auto apply_create_key(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        key_record k;
        k.key_id = r.str();
        k.account = r.str();
        k.description = r.str();
        k.spec = detail::enum_in(r.u8(), key_spec::symmetric_default, key_spec::hmac_512);
        k.usage =
            detail::enum_in(r.u8(), key_usage::encrypt_decrypt, key_usage::generate_verify_mac);
        k.manager = detail::enum_in(r.u8(), key_manager::customer, key_manager::owned);
        k.creation_ms = r.u64();
        k.policy = r.str();
        const auto tags = detail::get_map(r);
        require_key_id(k.key_id);
        require_account(k.account);
        require(usage_allowed(k.spec, k.usage), "usage not allowed for the key spec");
        require(k.description.size() <= k_max_description_bytes, "description too long");
        require(!k.policy.empty() && k.policy.size() <= k_max_policy_bytes, "bad policy");
        require(tags.size() <= k_max_tags_per_key, "too many tags");
        require_tags(tags);
        if (key(k.key_id) || tombstoned(k.key_id)) {
            return catalog_status::rejected;
        }
        auto c = counts(k.account);
        if (k.manager == key_manager::customer) {
            if (c.keys >= max_keys(k.account)) {
                return catalog_status::limit_exceeded;
            }
            ++c.keys;
            put_counts(batch, k.account, c);
        }
        k.state = key_state::creating;
        put_key(batch, k);
        if (k.manager != key_manager::owned) {
            // An owned key is listed in no account (Requirement 10.3).
            put(batch, account_key_index(k.account, k.key_id), {});
        }
        for (const auto& [tk, tv] : tags) {
            put(batch, key_child_prefix('t', k.key_id) + tk, tv);
        }
        return catalog_status::ok;
    }

    auto apply_complete_key(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const auto object = r.u64();
        const auto now = r.u64();
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (k->state != key_state::creating) {
            return catalog_status::invalid_state;
        }
        k->state = key_state::enabled;
        k->current_version = 1;
        if (service_managed(k->manager)) {
            // AWS managed and owned keys rotate every year, set here so no command
            // a customer could send turns it on or off (Requirement 10.2).
            k->rotation_enabled = true;
            k->rotation_period_days = k_managed_rotation_days;
            k->next_rotation_ms = now + std::uint64_t{k_managed_rotation_days} * k_ms_per_day;
        }
        put_key(batch, *k);
        put(batch, key_child_prefix('v', id) + detail::be32_key(1),
            key_version{1, object, now, rotation_type::initial}.encode());
        return catalog_status::ok;
    }

    auto apply_set_enabled(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const bool enabled = r.boolean();
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        // AWS: EnableKey and DisableKey act on Enabled and Disabled keys
        // (each idempotent); a key Creating or PendingDeletion is
        // KMSInvalidStateException.
        if (k->state != key_state::enabled && k->state != key_state::disabled) {
            return catalog_status::invalid_state;
        }
        if (service_managed(k->manager)) {
            return catalog_status::rejected;  // AWS managed keys stay enabled
        }
        k->state = enabled ? key_state::enabled : key_state::disabled;
        put_key(batch, *k);
        return catalog_status::ok;
    }

    auto apply_update_description(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        auto description = r.str();
        require(description.size() <= k_max_description_bytes, "description too long");
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (k->state == key_state::creating || k->state == key_state::pending_deletion) {
            return catalog_status::invalid_state;
        }
        if (service_managed(k->manager)) {
            return catalog_status::rejected;  // AWS's description, not the customer's
        }
        k->description = std::move(description);
        put_key(batch, *k);
        return catalog_status::ok;
    }

    auto apply_put_policy(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        auto policy = r.str();
        require(!policy.empty() && policy.size() <= k_max_policy_bytes, "bad policy");
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        // AWS lets a PendingDeletion key's policy change (so it can be
        // recovered) but not a Creating one's.
        if (k->state == key_state::creating) {
            return catalog_status::invalid_state;
        }
        k->policy = std::move(policy);
        put_key(batch, *k);
        return catalog_status::ok;
    }

    auto apply_schedule_deletion(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const auto days = r.u32();
        const auto now = r.u64();
        require(days >= 7 && days <= 30, "pending window outside 7 to 30 days");
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (service_managed(k->manager)) {
            return catalog_status::rejected;  // AWS managed keys are never deleted
        }
        if (k->state != key_state::enabled && k->state != key_state::disabled) {
            return catalog_status::invalid_state;
        }
        k->state = key_state::pending_deletion;
        k->pending_window_days = days;
        k->deletion_ms = now + (days * k_ms_per_day);
        put_key(batch, *k);
        return catalog_status::ok;
    }

    auto apply_cancel_deletion(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (k->state != key_state::pending_deletion) {
            return catalog_status::invalid_state;
        }
        // AWS: a key whose deletion is cancelled is Disabled.
        k->state = key_state::disabled;
        k->pending_window_days = 0;
        k->deletion_ms = 0;
        put_key(batch, *k);
        return catalog_status::ok;
    }

    auto apply_destroy_key(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const auto now = r.u64();
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        const bool due = k->state == key_state::pending_deletion && k->deletion_ms <= now;
        if (!due && k->state != key_state::creating) {
            return catalog_status::invalid_state;
        }
        auto c = counts(k->account);
        if (k->manager == key_manager::customer && c.keys > 0) {
            --c.keys;
        }
        // Its aliases, grants, tags and versions go with it (AWS deletes a
        // key's aliases and grants when it deletes the key).
        const auto alias_prefix = key_alias_prefix(id);
        this->scan_prefix(alias_prefix, [&](std::string_view key, std::string_view) {
            erase(batch, alias_key(k->account, key.substr(alias_prefix.size())));
            erase(batch, std::string(key));
            if (c.aliases > 0) {
                --c.aliases;
            }
            return true;
        });
        for (const char kind : {'g', 't', 'v'}) {
            this->scan_prefix(key_child_prefix(kind, id),
                              [&](std::string_view key, std::string_view) {
                                  erase(batch, std::string(key));
                                  return true;
                              });
        }
        erase(batch, "k" + id);
        erase(batch, account_key_index(k->account, id));
        put(batch, "x" + id, k->account);
        put_counts(batch, k->account, c);
        return catalog_status::ok;
    }

    auto apply_add_version(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const auto v = r.u32();
        const auto object = r.u64();
        const auto type =
            detail::enum_in(r.u8(), rotation_type::automatic, rotation_type::on_demand);
        const auto now = r.u64();
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (!is_symmetric(k->spec)) {
            return catalog_status::rejected;  // AWS rotates symmetric keys only
        }
        if (k->state != key_state::enabled) {
            return catalog_status::invalid_state;
        }
        // Exactly the next version, so a rotation the leader retries after
        // a leader change cannot add two (Requirement 9.3).
        if (v != k->current_version + 1) {
            return catalog_status::rejected;
        }
        k->current_version = v;
        if (type == rotation_type::automatic && k->rotation_enabled) {
            k->next_rotation_ms = now + (k->rotation_period_days * k_ms_per_day);
        }
        put_key(batch, *k);
        put(batch, key_child_prefix('v', id) + detail::be32_key(v),
            key_version{v, object, now, type}.encode());
        return catalog_status::ok;
    }

    auto apply_set_rotation(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const bool enabled = r.boolean();
        const auto period = r.u32();
        const auto now = r.u64();
        require(!enabled || (period >= 90 && period <= 2560), "rotation period outside 90 to 2560");
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (!is_symmetric(k->spec) || service_managed(k->manager)) {
            return catalog_status::rejected;
        }
        if (k->state != key_state::enabled && k->state != key_state::disabled) {
            return catalog_status::invalid_state;
        }
        k->rotation_enabled = enabled;
        k->rotation_period_days = enabled ? period : 0;
        k->next_rotation_ms = enabled ? now + (period * k_ms_per_day) : 0;
        put_key(batch, *k);
        return catalog_status::ok;
    }

    auto apply_create_alias(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        alias_record a;
        a.account = r.str();
        a.name = r.str();
        a.key_id = r.str();
        const bool managed = r.boolean();
        a.created_ms = r.u64();
        a.updated_ms = a.created_ms;
        require_account(a.account);
        require(valid_alias_name(a.name) && is_aws_alias(a.name) == managed, "bad alias name");
        auto k = live_key(a.key_id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (k->account != a.account) {
            return catalog_status::rejected;
        }
        if (k->state == key_state::pending_deletion || k->state == key_state::creating) {
            return catalog_status::invalid_state;
        }
        if (alias(a.account, a.name)) {
            return catalog_status::already_exists;
        }
        auto c = counts(a.account);
        if (c.aliases >= max_aliases(a.account) ||
            aliases(a.account, a.key_id).size() >= k_max_aliases_per_key) {
            return catalog_status::limit_exceeded;
        }
        ++c.aliases;
        put_counts(batch, a.account, c);
        put(batch, alias_key(a.account, a.name), a.encode());
        put(batch, key_alias_prefix(a.key_id) + a.name, {});
        return catalog_status::ok;
    }

    auto apply_update_alias(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto account = r.str();
        const auto name = r.str();
        const auto key_id = r.str();
        const auto now = r.u64();
        require_account(account);
        require(valid_alias_name(name), "bad alias name");
        auto a = alias(account, name);
        if (!a) {
            return catalog_status::not_found;
        }
        if (is_aws_alias(name)) {
            return catalog_status::rejected;
        }
        auto from = live_key(a->key_id);
        auto to = live_key(key_id);
        if (!to) {
            return catalog_status::not_found;
        }
        // AWS: the new key must be in the same account, of the same type
        // and usage, and not pending deletion.
        if (to->account != account ||
            (from && (from->spec != to->spec || from->usage != to->usage))) {
            return catalog_status::rejected;
        }
        if (to->state == key_state::pending_deletion || to->state == key_state::creating) {
            return catalog_status::invalid_state;
        }
        if (a->key_id != key_id && aliases(account, key_id).size() >= k_max_aliases_per_key) {
            return catalog_status::limit_exceeded;
        }
        erase(batch, key_alias_prefix(a->key_id) + name);
        a->key_id = key_id;
        a->updated_ms = now;
        put(batch, alias_key(account, name), a->encode());
        put(batch, key_alias_prefix(key_id) + name, {});
        return catalog_status::ok;
    }

    auto apply_delete_alias(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto account = r.str();
        const auto name = r.str();
        require_account(account);
        auto a = alias(account, name);
        if (!a) {
            return catalog_status::not_found;
        }
        if (is_aws_alias(name)) {
            return catalog_status::rejected;
        }
        auto c = counts(account);
        if (c.aliases > 0) {
            --c.aliases;
        }
        put_counts(batch, account, c);
        erase(batch, alias_key(account, name));
        erase(batch, key_alias_prefix(a->key_id) + name);
        return catalog_status::ok;
    }

    auto apply_tag_key(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const auto add = detail::get_map(r);
        require_tags(add);
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (k->state == key_state::creating || k->state == key_state::pending_deletion ||
            service_managed(k->manager)) {
            return catalog_status::invalid_state;
        }
        auto merged = tags(id);
        for (const auto& [tk, tv] : add) {
            merged[tk] = tv;
        }
        if (merged.size() > k_max_tags_per_key) {
            return catalog_status::limit_exceeded;
        }
        for (const auto& [tk, tv] : add) {
            put(batch, key_child_prefix('t', id) + tk, tv);
        }
        return catalog_status::ok;
    }

    auto apply_untag_key(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const auto names = detail::get_list(r);
        auto k = live_key(id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (k->state == key_state::creating || k->state == key_state::pending_deletion ||
            service_managed(k->manager)) {
            return catalog_status::invalid_state;
        }
        for (const auto& n : names) {
            require(n.find('\0') == std::string::npos, "bad tag key");
            erase(batch, key_child_prefix('t', id) + n);
        }
        return catalog_status::ok;
    }

    auto apply_create_grant(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto g = grant_record::read(r);
        require(!g.grant_id.empty() && g.grant_id.find('\0') == std::string::npos, "bad grant id");
        require(!g.grantee_principal.empty() && !g.operations.empty(), "bad grant");
        require(g.constraint != grant_constraint::none || g.constraint_context.empty(),
                "constraint context without a constraint");
        auto k = live_key(g.key_id);
        if (!k) {
            return catalog_status::not_found;
        }
        if (k->state == key_state::creating || k->state == key_state::pending_deletion) {
            return catalog_status::invalid_state;
        }
        if (grant(g.key_id, g.grant_id)) {
            return catalog_status::already_exists;
        }
        if (grants(g.key_id).size() >= k_max_grants_per_key) {
            return catalog_status::limit_exceeded;
        }
        put(batch, grant_key(g.key_id, g.grant_id), g.encode());
        return catalog_status::ok;
    }

    auto apply_remove_grant(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto id = r.str();
        const auto grant_id = r.str();
        if (!live_key(id)) {
            return catalog_status::not_found;
        }
        if (!grant(id, grant_id)) {
            return catalog_status::not_found;
        }
        erase(batch, grant_key(id, grant_id));
        return catalog_status::ok;
    }

    [[nodiscard]] static auto status_reply(catalog_status s) -> std::vector<std::byte> {
        byte_writer w;
        w.u8(static_cast<std::uint8_t>(s));
        return w.take();
    }

    auto put_lease(kythira::write_batch& batch, const job_lease& l) -> void {
        byte_writer w;
        w.str(l.holder).u64(l.token).u64(l.expiry_ms);
        put(batch, "J", w.take_string());
    }

    auto apply_acquire_lease(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto holder = r.str();
        const auto now_ms = r.u64();
        const auto duration_ms = r.u64();
        require(!holder.empty() && holder.size() <= 256, "lease holder");
        require(duration_ms > 0 && now_ms <= UINT64_MAX - duration_ms, "lease duration");
        auto l = lease();
        if (l.holder != holder) {
            if (!l.holder.empty() && now_ms < l.expiry_ms) {
                return catalog_status::stale_lease;  // another holder's live lease
            }
            l.holder = holder;
            ++l.token;
        }
        l.expiry_ms = now_ms + duration_ms;
        put_lease(batch, l);
        return catalog_status::ok;
    }

    auto apply_release_lease(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto holder = r.str();
        const auto token = r.u64();
        auto l = lease();
        if (l.holder.empty() || l.holder != holder || l.token != token) {
            return catalog_status::stale_lease;
        }
        // The token stays, so the next holder's is new.
        l.holder.clear();
        l.expiry_ms = 0;
        put_lease(batch, l);
        return catalog_status::ok;
    }

    auto apply_set_account_limits(byte_reader& r, kythira::write_batch& batch) -> catalog_status {
        const auto account = r.str();
        account_limits l;
        l.max_keys = r.u32();
        l.max_aliases = r.u32();
        require_account(account);
        if (l == account_limits{}) {
            erase(batch, "l" + account);
        } else {
            byte_writer w;
            w.u32(l.max_keys).u32(l.max_aliases);
            put(batch, "l" + account, w.take_string());
        }
        return catalog_status::ok;
    }
};

static_assert(kythira::persistent_state_machine<kms_catalog_state_machine<>>);

}  // namespace kythira::kms
