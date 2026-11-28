// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_acl.hpp
/// @brief Users, secrets, roles and key scopes for the Redis-compatible
///        gateway (.kiro/specs/redis-compatible-kv/ design Component 6).
///
/// The threat model is a build farm: every sccache client shares one
/// password and it lives in `SCCACHE_REDIS_ENDPOINT` on hundreds of
/// machines. So the ACL assumes the secret will leak eventually and limits
/// what it buys: a role (a read-only build farm cannot poison the cache),
/// a key prefix (one farm cannot see another's artefacts) and a KDF slow
/// enough that a copy of the ACL file is not a copy of the password.
///
/// ACL file format, one user per line, `#` comments and blank lines ignored:
///
///     user <name> <secret-record|nopass|disabled> <role> [prefix ...]
///          [cert=<subject>] [auth=password|iam|both]
///
/// where `<secret-record>` is `pbkdf2-sha256$<iterations>$<b64 salt>$<b64 dk>`
/// as produced by `redis_acl::hash_secret` (and the daemon's `--hash-secret`
/// subcommand). A user with no prefix can reach no keys: scope is granted,
/// never assumed. A `cert=` subject lets an mTLS client authenticate without
/// an AUTH command.
///
/// `auth=` (IAM task 21, Requirement 13.1) says how `AUTH` authenticates the
/// user: `password` (the default) against the secret record, `iam` only
/// through the gateway's credential verifier (an IAM auth token), and `both`
/// through the verifier first and then the password. It is a reserved
/// attribute like `cert=`, never a key prefix; a repeated or unknown value is
/// a parse error. For a user that is not `password`, `nopass` needs no
/// `cert=` and `disabled` means "no password" rather than "no login": an
/// older gateway, which reads `auth=iam` as a key prefix, refuses a
/// `disabled` user outright, so that is how an IAM-only user stays IAM-only
/// during a rolling upgrade.
///
/// Command rules and key scopes (.kiro/specs/redis-general-data-types/
/// task 5, Requirements 5 and 15) are further words on the same line, read
/// left to right after the role, later rules winning as in Redis:
///
/// | word                         | meaning                                         |
/// |------------------------------|-------------------------------------------------|
/// | `+@cat` / `-@cat`            | allow / deny every command in a category        |
/// | `+cmd` / `-cmd`              | allow / deny one command                        |
/// | `allcommands` / `nocommands` | `+@all` / `-@all`                               |
/// | `~prefix`                    | read and write keys under `prefix`              |
/// | `%R~prefix` / `%W~prefix`    | read only / write only (`%RW~` is `~`)          |
/// | `mutable~prefix`             | keys the immutable-value rule lets change       |
/// | `allkeys`                    | `~*`                                            |
///
/// A trailing `*` on a prefix is optional (`~app:*` is `~app:`); any other
/// glob character is refused, since scopes are prefixes. A bare word is a
/// read and write prefix as before, and `*` is every key. The role is the
/// starting set of commands the rules edit:
///
/// - `read_only`: `+@all -@write -@admin -@dangerous`;
/// - `read_write`: `+@all -@admin -@dangerous`;
/// - `admin`: `+@all`.
///
/// (`KYTHIRA.TXN`, the transaction coordinator's internal hop, is in the
/// `read_write` set whatever its categories say.) A rule never reaches a
/// command this build does not ship.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kythira/redis/redis_command_ids.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace kythira {

enum class redis_role : std::uint8_t {
    read_only,
    read_write,
    admin
};

[[nodiscard]] inline auto redis_role_name(redis_role r) -> std::string_view {
    switch (r) {
        case redis_role::read_only:
            return "read_only";
        case redis_role::read_write:
            return "read_write";
        case redis_role::admin:
            return "admin";
    }
    return "unknown";
}

[[nodiscard]] inline auto parse_redis_role(std::string_view s) -> std::optional<redis_role> {
    if (s == "read_only" || s == "read-only" || s == "ro") {
        return redis_role::read_only;
    }
    if (s == "read_write" || s == "read-write" || s == "rw") {
        return redis_role::read_write;
    }
    if (s == "admin") {
        return redis_role::admin;
    }
    return std::nullopt;
}

/// How `AUTH` authenticates a user (the ACL's `auth=` attribute).
enum class redis_auth_mode : std::uint8_t {
    password,
    iam,
    both
};

[[nodiscard]] inline auto parse_redis_auth_mode(std::string_view s)
    -> std::optional<redis_auth_mode> {
    if (s == "password") {
        return redis_auth_mode::password;
    }
    if (s == "iam") {
        return redis_auth_mode::iam;
    }
    if (s == "both") {
        return redis_auth_mode::both;
    }
    return std::nullopt;
}

/// One `+@cat`, `-@cat`, `+cmd` or `-cmd` word of an ACL line.
struct redis_command_rule {
    bool _allow = true;
    /// `redis_acl_category` bits; every bit for `@all`; 0 with `_command`.
    std::uint32_t _categories = 0;
    /// The upper-case command name of a single-command rule.
    std::string _command;
    auto operator==(const redis_command_rule&) const -> bool = default;
};

struct redis_acl_user {
    std::string _name;
    /// `pbkdf2-sha256$<iters>$<b64 salt>$<b64 dk>`, or empty for `nopass`.
    /// An empty secret means the user has no password at all: it can only
    /// authenticate through a mapped client certificate, never via AUTH.
    std::string _secret;
    bool _enabled = true;
    redis_role _role = redis_role::read_only;
    /// Key prefixes this user may read and write. With no scope of any
    /// kind the user reaches NO keys.
    std::vector<std::string> _key_prefixes;
    std::vector<std::string> _read_prefixes;
    std::vector<std::string> _write_prefixes;
    std::vector<std::string> _mutable_prefixes;
    std::vector<redis_command_rule> _command_rules;
    /// TLS client-certificate subjects that authenticate as this user.
    std::vector<std::string> _cert_subjects;
    /// How `AUTH` authenticates this user.
    redis_auth_mode _auth = redis_auth_mode::password;
};

/// What a connection carries after authentication succeeds.
struct redis_identity {
    std::string _user;
    redis_role _role = redis_role::read_only;
    /// Read and write scopes (`~prefix` and the original bare prefixes).
    std::vector<std::string> _key_prefixes;
    /// `%R~prefix`: read only.
    std::vector<std::string> _read_prefixes;
    /// `%W~prefix`: write only.
    std::vector<std::string> _write_prefixes;
    /// `mutable~prefix`: keys the immutable-value rule lets change.
    std::vector<std::string> _mutable_prefixes;
    /// Applied in order on top of the role's command set.
    std::vector<redis_command_rule> _command_rules;
};

/// The identity a user's line grants.
[[nodiscard]] inline auto redis_identity_of(const redis_acl_user& u) -> redis_identity {
    return redis_identity{u._name,          u._role,           u._key_prefixes,
                          u._read_prefixes, u._write_prefixes, u._mutable_prefixes,
                          u._command_rules};
}

/// What a command does to its keys, for the read and write scopes.
namespace redis_key_access {
inline constexpr unsigned none = 0;  ///< metadata only: any scope will do
inline constexpr unsigned read = 1;
inline constexpr unsigned write = 2;
}  // namespace redis_key_access

enum class acl_decision : std::uint8_t {
    allow,
    deny_command,
    deny_key
};

/// Which role a command needs: from the command's ACL categories in the
/// registry (`@admin` or `@dangerous`: admin; `@write`: read_write; else
/// read_only), so a command shipped later needs no entry here. Commands
/// this build does not ship need a role nobody has, and so do commands
/// that never go through authorization: `KYTHIRA.ADVISE`, a peer-only hop,
/// and `KYTHIRA.INSTALL`, an `exec` record id a transaction's commit
/// applies, never a client command.
[[nodiscard]] inline auto redis_command_min_role(std::string_view upper_name)
    -> std::optional<redis_role> {
    // The transaction coordinator's internal hop; the gateway also refuses
    // it from any non-internal session.
    if (upper_name == "KYTHIRA.TXN") {
        return redis_role::read_write;
    }
    if (upper_name == "KYTHIRA.ADVISE" || upper_name == "KYTHIRA.INSTALL") {
        return std::nullopt;
    }
    const auto* info = find_redis_command(upper_name);
    if (info == nullptr || info->status != redis_command_status::shipped) {
        return std::nullopt;
    }
    if ((info->acl_categories & (redis_acl_category::admin | redis_acl_category::dangerous)) != 0) {
        return redis_role::admin;
    }
    if ((info->acl_categories & redis_acl_category::write) != 0) {
        return redis_role::read_write;
    }
    return redis_role::read_only;
}

/// What a command needs of each of its keys (Redis's key-spec `ACCESS`
/// and `INSERT|DELETE|UPDATE` flags): a read needs a read scope unless it
/// only looks at metadata; a write needs a write scope, and a read scope
/// too when it also returns or uses the old value.
[[nodiscard]] inline auto redis_command_key_access(std::string_view upper_name) -> unsigned {
    using namespace redis_key_access;
    if (upper_name == "EXISTS" || upper_name == "TYPE" || upper_name == "TTL" ||
        upper_name == "PTTL" || upper_name == "EXPIRETIME" || upper_name == "PEXPIRETIME" ||
        upper_name == "TOUCH" || upper_name == "OBJECT" || upper_name == "STRLEN" ||
        upper_name == "WATCH" || upper_name == "HLEN" || upper_name == "HEXISTS" ||
        upper_name == "HSTRLEN" || upper_name == "SCARD" || upper_name == "LLEN") {
        return none;
    }
    if (upper_name == "GETSET" || upper_name == "GETDEL" || upper_name == "GETEX" ||
        upper_name == "INCR" || upper_name == "DECR" || upper_name == "INCRBY" ||
        upper_name == "DECRBY" || upper_name == "INCRBYFLOAT" || upper_name == "RENAME" ||
        upper_name == "RENAMENX" || upper_name == "COPY" || upper_name == "HINCRBY" ||
        upper_name == "HINCRBYFLOAT" || upper_name == "SPOP" || upper_name == "LPOP" ||
        upper_name == "RPOP" || upper_name == "LMOVE" || upper_name == "RPOPLPUSH" ||
        upper_name == "LMPOP") {
        return read | write;
    }
    const auto* info = find_redis_command(upper_name);
    if (info == nullptr) {
        return none;
    }
    if ((info->flags & redis_command_flag::write) != 0) {
        return write;
    }
    if ((info->flags & redis_command_flag::readonly) != 0) {
        return read;
    }
    return none;
}

/// The `redis_acl_category` bit of a category name (without the `@`).
/// Redis categories with no command in this build yet (`sortedset`,
/// `pubsub`, ...) are accepted and match nothing; `all` is every bit.
[[nodiscard]] inline auto parse_redis_acl_category(std::string_view name)
    -> std::optional<std::uint32_t> {
    namespace c = redis_acl_category;
    struct entry {
        std::string_view name;
        std::uint32_t bits;
    };
    static constexpr std::array<entry, 22> k_names{{
        {"keyspace", c::keyspace},
        {"read", c::read},
        {"write", c::write},
        {"set", c::set},
        {"list", c::list},
        {"hash", c::hash},
        {"string", c::string},
        {"admin", c::admin},
        {"fast", c::fast},
        {"slow", c::slow},
        {"blocking", c::blocking},
        {"dangerous", c::dangerous},
        {"connection", c::connection},
        {"transaction", c::transaction},
        {"all", 0xFFFFFFFFU},
        {"sortedset", 0},
        {"bitmap", 0},
        {"hyperloglog", 0},
        {"geo", 0},
        {"stream", 0},
        {"pubsub", 0},
        {"scripting", 0},
    }};
    for (const auto& e : k_names) {
        if (e.name == name) {
            return e.bits;
        }
    }
    return std::nullopt;
}

class redis_acl_parse_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace redis_acl_detail {

inline constexpr std::string_view b64_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

[[nodiscard]] inline auto b64_encode(const std::vector<unsigned char>& in) -> std::string {
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 2 < in.size()) {
        std::uint32_t v = (static_cast<std::uint32_t>(in[i]) << 16) |
                          (static_cast<std::uint32_t>(in[i + 1]) << 8) |
                          static_cast<std::uint32_t>(in[i + 2]);
        out += b64_alphabet[(v >> 18) & 63];
        out += b64_alphabet[(v >> 12) & 63];
        out += b64_alphabet[(v >> 6) & 63];
        out += b64_alphabet[v & 63];
        i += 3;
    }
    if (i + 1 == in.size()) {
        std::uint32_t v = static_cast<std::uint32_t>(in[i]) << 16;
        out += b64_alphabet[(v >> 18) & 63];
        out += b64_alphabet[(v >> 12) & 63];
        out += "==";
    } else if (i + 2 == in.size()) {
        std::uint32_t v = (static_cast<std::uint32_t>(in[i]) << 16) |
                          (static_cast<std::uint32_t>(in[i + 1]) << 8);
        out += b64_alphabet[(v >> 18) & 63];
        out += b64_alphabet[(v >> 12) & 63];
        out += b64_alphabet[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

[[nodiscard]] inline auto b64_decode(std::string_view in)
    -> std::optional<std::vector<unsigned char>> {
    if (in.size() % 4 != 0) {
        return std::nullopt;
    }
    std::vector<unsigned char> out;
    out.reserve(in.size() / 4 * 3);
    std::uint32_t acc = 0;
    int bits = 0;
    std::size_t pad = 0;
    for (char c : in) {
        if (c == '=') {
            ++pad;
            continue;
        }
        if (pad != 0) {
            return std::nullopt;
        }
        auto pos = b64_alphabet.find(c);
        if (pos == std::string_view::npos) {
            return std::nullopt;
        }
        acc = (acc << 6) | static_cast<std::uint32_t>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((acc >> bits) & 0xFF));
        }
    }
    if (pad > 2) {
        return std::nullopt;
    }
    return out;
}

inline auto split_ws(std::string_view line) -> std::vector<std::string> {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) {
            ++i;
        }
        std::size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t') {
            ++i;
        }
        if (i > start) {
            out.emplace_back(line.substr(start, i - start));
        }
    }
    return out;
}

struct secret_record {
    std::uint32_t _iterations = 0;
    std::vector<unsigned char> _salt;
    std::vector<unsigned char> _dk;
};

[[nodiscard]] inline auto parse_secret_record(std::string_view s) -> std::optional<secret_record> {
    constexpr std::string_view prefix = "pbkdf2-sha256$";
    if (s.substr(0, prefix.size()) != prefix) {
        return std::nullopt;
    }
    s.remove_prefix(prefix.size());
    auto d1 = s.find('$');
    if (d1 == std::string_view::npos) {
        return std::nullopt;
    }
    auto d2 = s.find('$', d1 + 1);
    if (d2 == std::string_view::npos) {
        return std::nullopt;
    }
    secret_record r;
    auto iters = s.substr(0, d1);
    if (iters.empty() || iters.size() > 9) {
        return std::nullopt;
    }
    std::uint32_t v = 0;
    for (char c : iters) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        v = v * 10 + static_cast<std::uint32_t>(c - '0');
    }
    if (v == 0) {
        return std::nullopt;
    }
    r._iterations = v;
    auto salt = b64_decode(s.substr(d1 + 1, d2 - d1 - 1));
    auto dk = b64_decode(s.substr(d2 + 1));
    if (!salt || !dk || salt->empty() || dk->empty()) {
        return std::nullopt;
    }
    r._salt = std::move(*salt);
    r._dk = std::move(*dk);
    return r;
}

[[nodiscard]] inline auto derive(std::string_view secret, const std::vector<unsigned char>& salt,
                                 std::uint32_t iterations, std::size_t dk_len)
    -> std::vector<unsigned char> {
    std::vector<unsigned char> dk(dk_len);
    if (PKCS5_PBKDF2_HMAC(secret.data(), static_cast<int>(secret.size()), salt.data(),
                          static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(),
                          static_cast<int>(dk.size()), dk.data()) != 1) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
    return dk;
}

}  // namespace redis_acl_detail

/// Default PBKDF2 iteration count for newly hashed secrets: OWASP's 2023
/// recommendation for PBKDF2-HMAC-SHA256. An AUTH costs this many HMACs,
/// which is why auth failures are rate-limited per source address.
inline constexpr std::uint32_t redis_acl_default_iterations = 600000;

/// Immutable snapshot of the users table. `redis_acl` swaps the whole thing
/// on reload so a connection mid-authentication sees one consistent table.
class redis_acl_table {
public:
    redis_acl_table() : redis_acl_table(std::vector<redis_acl_user>{}) {}
    explicit redis_acl_table(std::vector<redis_acl_user> users) : _users(std::move(users)) {
        // The decoy record an unknown user is verified against uses the
        // largest iteration count in the table, so a probe for a username
        // costs at least as much as a probe against a real one. Built here,
        // once per reload, rather than per failed AUTH.
        std::uint32_t iterations = 1000;
        for (const auto& u : _users) {
            if (auto rec = redis_acl_detail::parse_secret_record(u._secret)) {
                iterations = std::max(iterations, rec->_iterations);
            }
        }
        std::vector<unsigned char> salt(16, 0x5a);
        auto dk = redis_acl_detail::derive("kythira-decoy", salt, iterations, 32);
        _decoy_record = "pbkdf2-sha256$" + std::to_string(iterations) + "$" +
                        redis_acl_detail::b64_encode(salt) + "$" + redis_acl_detail::b64_encode(dk);
    }

    [[nodiscard]] auto decoy_record() const -> const std::string& { return _decoy_record; }

    [[nodiscard]] auto find(std::string_view name) const -> const redis_acl_user* {
        for (const auto& u : _users) {
            if (u._name == name) {
                return &u;
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto find_by_cert_subject(std::string_view subject) const
        -> const redis_acl_user* {
        for (const auto& u : _users) {
            for (const auto& s : u._cert_subjects) {
                if (s == subject) {
                    return &u;
                }
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto users() const -> const std::vector<redis_acl_user>& { return _users; }
    [[nodiscard]] auto empty() const noexcept -> bool { return _users.empty(); }

private:
    std::vector<redis_acl_user> _users;
    std::string _decoy_record;
};

class redis_acl {
public:
    redis_acl() : _table(std::make_shared<const redis_acl_table>()) {}
    explicit redis_acl(std::vector<redis_acl_user> users)
        : _table(std::make_shared<const redis_acl_table>(std::move(users))) {}

    // ---- secrets -----------------------------------------------------------

    /// Produce a `pbkdf2-sha256$...` record for `secret` with a fresh 16-byte
    /// salt. This is the only place secrets are hashed, so the daemon's
    /// `--hash-secret` and the tests agree on the format by construction.
    [[nodiscard]] static auto hash_secret(std::string_view secret,
                                          std::uint32_t iterations = redis_acl_default_iterations)
        -> std::string {
        std::vector<unsigned char> salt(16);
        if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        auto dk = redis_acl_detail::derive(secret, salt, iterations, 32);
        return "pbkdf2-sha256$" + std::to_string(iterations) + "$" +
               redis_acl_detail::b64_encode(salt) + "$" + redis_acl_detail::b64_encode(dk);
    }

    /// Constant-time verification of `secret` against a record. Public so a
    /// unit test can check the record format without an ACL table.
    [[nodiscard]] static auto verify_secret(std::string_view record, std::string_view secret)
        -> bool {
        auto parsed = redis_acl_detail::parse_secret_record(record);
        if (!parsed) {
            return false;
        }
        auto dk = redis_acl_detail::derive(secret, parsed->_salt, parsed->_iterations,
                                           parsed->_dk.size());
        return CRYPTO_memcmp(dk.data(), parsed->_dk.data(), dk.size()) == 0;
    }

    // ---- authentication ----------------------------------------------------

    /// Returns an identity or nullopt. Unknown user, disabled user, `nopass`
    /// user and wrong secret are indistinguishable to the caller — same
    /// result, and the same KDF work, so timing does not reveal which
    /// usernames exist.
    ///
    /// A `nopass` user never authenticates here: it is certificate-only, and
    /// accepting any password for it would hand its role to anyone who can
    /// reach the plaintext listener and knows the name.
    [[nodiscard]] auto authenticate(std::string_view user, std::string_view secret) const
        -> std::optional<redis_identity> {
        auto table = snapshot();
        const auto* u = table->find(user);
        bool ok = false;
        // An `auth=iam` user has no password, whatever its record says.
        if (u != nullptr && u->_enabled && !u->_secret.empty() &&
            u->_auth != redis_auth_mode::iam) {
            ok = verify_secret(u->_secret, secret);
        } else {
            // Burn the same KDF work as a real verification would.
            (void)verify_secret(table->decoy_record(), secret);
        }
        if (!ok) {
            return std::nullopt;
        }
        return redis_identity_of(*u);
    }

    /// The identity of an enabled user, without checking any secret. Only for
    /// a caller that has authenticated the user some other way: the gateway
    /// after a credential verifier accepted the user's credential
    /// (.kiro/specs/redis-gateway-module/ Requirement 6.5).
    [[nodiscard]] auto identity_of(std::string_view user) const -> std::optional<redis_identity> {
        auto table = snapshot();
        const auto* u = table->find(user);
        if (u == nullptr || !u->_enabled) {
            return std::nullopt;
        }
        return redis_identity_of(*u);
    }

    /// The `auth=` mode of an enabled user, or nothing for an unknown or
    /// disabled one. The composition root selects the users the credential
    /// verifier handles from this (`iam` and `both`).
    [[nodiscard]] auto auth_mode_of(std::string_view user) const -> std::optional<redis_auth_mode> {
        auto table = snapshot();
        const auto* u = table->find(user);
        if (u == nullptr || !u->_enabled) {
            return std::nullopt;
        }
        return u->_auth;
    }

    /// mTLS: map a verified client-certificate subject to a user.
    [[nodiscard]] auto authenticate_certificate(std::string_view subject) const
        -> std::optional<redis_identity> {
        auto table = snapshot();
        const auto* u = table->find_by_cert_subject(subject);
        if (u == nullptr || !u->_enabled) {
            return std::nullopt;
        }
        return redis_identity_of(*u);
    }

    // ---- authorization -----------------------------------------------------

    /// `command` is the upper-cased command name; `keys` are every key the
    /// command touches (empty for key-less commands). A command the closure
    /// does not know is a command denial, which the gateway never reaches
    /// because it rejects unknown commands first. `access` overrides what
    /// the command needs of its keys (`SET ... GET` also reads).
    [[nodiscard]] static auto authorize(const redis_identity& id, std::string_view command,
                                        const std::vector<std::string_view>& keys,
                                        std::optional<unsigned> access = std::nullopt)
        -> acl_decision {
        if (!command_allowed(id, command)) {
            return acl_decision::deny_command;
        }
        const auto needed = access.value_or(redis_command_key_access(command));
        for (auto key : keys) {
            if (!key_permits(id, key, needed)) {
                return acl_decision::deny_key;
            }
        }
        return acl_decision::allow;
    }

    /// The role's command set, edited by the user's rules in order.
    [[nodiscard]] static auto command_allowed(const redis_identity& id, std::string_view command)
        -> bool {
        auto needed = redis_command_min_role(command);
        if (!needed.has_value()) {
            return false;
        }
        bool allowed = static_cast<int>(id._role) >= static_cast<int>(*needed);
        if (id._command_rules.empty()) {
            return allowed;
        }
        const auto* info = find_redis_command(command);
        const std::uint32_t categories = info == nullptr ? 0 : info->acl_categories;
        for (const auto& rule : id._command_rules) {
            const bool matches = rule._command.empty() ? (rule._categories & categories) != 0 ||
                                                             rule._categories == 0xFFFFFFFFU
                                                       : rule._command == command;
            if (matches) {
                allowed = rule._allow;
            }
        }
        return allowed;
    }

    /// Whether `key` is in a read and write scope (`~prefix`).
    [[nodiscard]] static auto key_in_scope(const redis_identity& id, std::string_view key) -> bool {
        return under_any(id._key_prefixes, key);
    }

    /// Whether `id` may do `needed` (`redis_key_access` bits) to `key`.
    [[nodiscard]] static auto key_permits(const redis_identity& id, std::string_view key,
                                          unsigned needed) -> bool {
        const bool both = under_any(id._key_prefixes, key);
        const bool read = both || under_any(id._read_prefixes, key);
        const bool write = both || under_any(id._write_prefixes, key);
        if (needed == redis_key_access::none) {
            return read || write;
        }
        return ((needed & redis_key_access::read) == 0 || read) &&
               ((needed & redis_key_access::write) == 0 || write);
    }

    /// Whether the immutable-value rule lets `id` change `key`
    /// (Requirement 5.2): the key is under one of its mutable prefixes.
    [[nodiscard]] static auto key_is_mutable(const redis_identity& id, std::string_view key)
        -> bool {
        return under_any(id._mutable_prefixes, key);
    }

    [[nodiscard]] static auto under_any(const std::vector<std::string>& prefixes,
                                        std::string_view key) -> bool {
        return std::ranges::any_of(
            prefixes, [&](const std::string& prefix) { return key.starts_with(prefix); });
    }

    // ---- table management --------------------------------------------------

    /// Parse the ACL file format. Throws `redis_acl_parse_error` with the
    /// line number on any malformed line; nothing is installed on failure.
    [[nodiscard]] static auto parse(std::string_view text) -> std::vector<redis_acl_user> {
        std::vector<redis_acl_user> users;
        std::size_t line_no = 0;
        std::size_t pos = 0;
        while (pos <= text.size()) {
            auto nl = text.find('\n', pos);
            auto line =
                text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
            pos = nl == std::string_view::npos ? text.size() + 1 : nl + 1;
            ++line_no;
            if (!line.empty() && line.back() == '\r') {
                line.remove_suffix(1);
            }
            auto words = redis_acl_detail::split_ws(line);
            if (words.empty() || words[0][0] == '#') {
                continue;
            }
            auto fail = [&](const std::string& why) {
                throw redis_acl_parse_error("acl line " + std::to_string(line_no) + ": " + why);
            };
            if (words[0] != "user") {
                fail("expected 'user'");
            }
            if (words.size() < 4) {
                fail(
                    "expected: user <name> <secret|nopass|disabled> <role> [prefix ...] "
                    "[cert=<subject>] [auth=password|iam|both]");
            }
            redis_acl_user u;
            u._name = words[1];
            if (u._name.empty() || u._name == "nopass") {
                fail("invalid user name");
            }
            for (const auto& existing : users) {
                if (existing._name == u._name) {
                    fail("duplicate user '" + u._name + "'");
                }
            }
            // `auth=` first: it changes what `nopass` and `disabled` mean.
            bool auth_seen = false;
            for (std::size_t i = 4; i < words.size(); ++i) {
                if (words[i].rfind("auth=", 0) != 0) {
                    continue;
                }
                if (auth_seen) {
                    fail("repeated auth= attribute");
                }
                auth_seen = true;
                auto mode = parse_redis_auth_mode(std::string_view(words[i]).substr(5));
                if (!mode) {
                    fail("unknown auth= value '" + words[i].substr(5) + "' (password|iam|both)");
                }
                u._auth = *mode;
            }
            if (words[2] == "nopass") {
                u._secret.clear();
            } else if (words[2] == "disabled") {
                // No password. For a password user that means no login at
                // all; an iam or both user still logs in through the
                // verifier.
                u._enabled = u._auth != redis_auth_mode::password;
            } else if (redis_acl_detail::parse_secret_record(words[2]).has_value()) {
                u._secret = words[2];
            } else {
                fail("secret must be 'nopass', 'disabled' or a pbkdf2-sha256$... record");
            }
            auto role = parse_redis_role(words[3]);
            if (!role.has_value()) {
                fail("unknown role '" + words[3] + "' (read_only|read_write|admin)");
            }
            u._role = *role;
            for (std::size_t i = 4; i < words.size(); ++i) {
                const auto& w = words[i];
                if (w.rfind("auth=", 0) == 0) {
                    continue;  // read above
                }
                if (w.rfind("cert=", 0) == 0) {
                    auto subject = w.substr(5);
                    if (subject.empty()) {
                        fail("empty cert= subject");
                    }
                    u._cert_subjects.push_back(subject);
                } else if (auto why = parse_rule_word(w, u); !why.empty()) {
                    fail(why);
                }
            }
            if (u._enabled && u._secret.empty() && u._cert_subjects.empty() &&
                u._auth == redis_auth_mode::password) {
                fail("'nopass' user '" + u._name +
                     "' needs a cert=<subject>; it cannot authenticate by password");
            }
            users.push_back(std::move(u));
        }
        return users;
    }

    /// Applies one word after the role to `u`; returns why it is refused,
    /// or empty.
    static auto parse_rule_word(const std::string& w, redis_acl_user& u) -> std::string {
        // A scope: `~p`, `%R~p`, `%W~p`, `%RW~p`, `mutable~p`.
        const auto prefix_of = [](std::string_view pattern, std::string& out) -> bool {
            if (pattern.ends_with('*')) {
                pattern.remove_suffix(1);
            }
            if (pattern.find_first_of("*?[]\\") != std::string_view::npos) {
                return false;
            }
            out = std::string(pattern);
            return true;
        };
        const auto scope = [&](std::string_view pattern, std::vector<std::string>& into) {
            std::string prefix;
            if (!prefix_of(pattern, prefix)) {
                return "key pattern '" + std::string(pattern) +
                       "' is not a prefix (only a trailing * is supported)";
            }
            into.push_back(std::move(prefix));
            return std::string();
        };
        if (w == "*" || w == "allkeys") {
            u._key_prefixes.emplace_back("");
            return {};
        }
        if (w.starts_with('~')) {
            return scope(std::string_view(w).substr(1), u._key_prefixes);
        }
        if (w.starts_with("%")) {
            const auto tilde = w.find('~');
            const auto perms = std::string_view(w).substr(
                1, tilde == std::string::npos ? std::string_view::npos : tilde - 1);
            if (tilde == std::string::npos) {
                return "expected %R~, %W~ or %RW~ in '" + w + "'";
            }
            const auto pattern = std::string_view(w).substr(tilde + 1);
            if (perms == "R") {
                return scope(pattern, u._read_prefixes);
            }
            if (perms == "W") {
                return scope(pattern, u._write_prefixes);
            }
            if (perms == "RW" || perms == "WR") {
                return scope(pattern, u._key_prefixes);
            }
            return "unknown key permission '%" + std::string(perms) + "' (R, W or RW)";
        }
        if (w.starts_with("mutable~")) {
            return scope(std::string_view(w).substr(8), u._mutable_prefixes);
        }
        // A command rule.
        if (w == "allcommands" || w == "nocommands") {
            u._command_rules.push_back({w == "allcommands", 0xFFFFFFFFU, {}});
            return {};
        }
        if (w.starts_with('+') || w.starts_with('-')) {
            const bool allow = w[0] == '+';
            const auto rest = std::string_view(w).substr(1);
            if (rest.starts_with('@')) {
                const auto bits = parse_redis_acl_category(rest.substr(1));
                if (!bits) {
                    return "unknown command category '" + std::string(rest) + "'";
                }
                u._command_rules.push_back({allow, *bits, {}});
                return {};
            }
            std::string upper(rest);
            for (auto& c : upper) {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            if (upper.find('|') != std::string::npos) {
                return "subcommand rules ('" + w + "') are not supported";
            }
            if (find_redis_command(upper) == nullptr) {
                return "unknown command '" + std::string(rest) + "'";
            }
            u._command_rules.push_back({allow, 0, std::move(upper)});
            return {};
        }
        // The original format: a bare word is a read and write prefix.
        u._key_prefixes.push_back(w);
        return {};
    }

    /// Replace the table atomically. A parse failure throws and keeps the
    /// prior table in force, so a bad edit cannot lock everyone out.
    auto reload(std::string_view text) -> std::size_t {
        auto users = parse(text);
        auto fresh = std::make_shared<const redis_acl_table>(std::move(users));
        std::lock_guard<std::mutex> lock(_mutex);
        _table = std::move(fresh);
        return _table->users().size();
    }

    auto reload_file(const std::string& path) -> std::size_t {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw redis_acl_parse_error("cannot open acl file '" + path + "'");
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        return reload(ss.str());
    }

    [[nodiscard]] auto snapshot() const -> std::shared_ptr<const redis_acl_table> {
        std::lock_guard<std::mutex> lock(_mutex);
        return _table;
    }

    [[nodiscard]] auto empty() const -> bool { return snapshot()->empty(); }

private:
    mutable std::mutex _mutex;
    std::shared_ptr<const redis_acl_table> _table;
};

}  // namespace kythira
