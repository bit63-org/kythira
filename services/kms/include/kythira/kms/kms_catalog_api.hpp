// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS data layer's catalog API and the remote catalog access over it
// (.kiro/specs/kms-independent-layers/ task 3, Requirements 3.1, 3.3 and
// 4.1-4.3). A front end without a catalog replica reads and writes the
// catalog through a data node with these three requests on the data
// node's KMS listener:
//
//   POST /v1/kms/catalog/read-index   -> the index a read must reach
//   POST /v1/kms/catalog/query        min index, query, arguments -> answer
//   POST /v1/kms/catalog/propose      catalog command -> status, index
//
// Consistency (Requirement 4.1). read-index is the read barrier: the data
// node runs one (through the catalog leader when it does not lead) and
// answers the index it has applied after it. Every query carries the
// index of the caller's last barrier, and a data node answers only once
// it has applied that far, so the leader's read-index round is paid once
// per operation and any data node, follower or leader, may answer the
// queries that follow. A proposal answers the data node's applied index
// after the command applied, which the caller's next queries then reach
// (read your writes).
//
// Failures. A data node that cannot reach a read-index point, or cannot
// apply far enough in time, answers 503; the remote access tries the next
// data node, and when none answers, barrier() is false (the handler's
// DependencyTimeoutException) and a query throws kms_catalog_unreachable
// (KMSInternalException, Requirement 4.3). Nothing is ever answered from
// a cache: there is none.
//
// Who may call is the listener's business (serve_catalog takes the
// verdict): the data-layer API admits front ends and other data nodes
// only (Requirement 9.2).
//
// Wire format: kms_codec.hpp's integers and text, records in their own
// catalog encodings as length-prefixed fields. Every body starts with a
// version byte.

#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_catalog_access.hpp>
#include <kythira/kms/kms_codec.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::kms {

inline constexpr std::string_view catalog_read_index_path = "/v1/kms/catalog/read-index";
inline constexpr std::string_view catalog_query_path = "/v1/kms/catalog/query";
inline constexpr std::string_view catalog_propose_path = "/v1/kms/catalog/propose";
inline constexpr std::uint8_t k_catalog_api_version = 1;

/// Whether `target` (path, optionally with a query) is a catalog API path.
[[nodiscard]] inline auto is_catalog_path(std::string_view target) -> bool {
    return target.starts_with("/v1/kms/catalog/");
}

/// The catalog queries the API carries: kms_catalog_reader's, one each.
enum class catalog_query : std::uint8_t {
    key = 1,
    tombstoned = 2,
    keys = 3,
    versions = 4,
    version = 5,
    tags = 6,
    alias = 7,
    aliases = 8,
    grant = 9,
    grants = 10,
    counts = 11,
    limits = 12,
    lease = 13,
    creating_keys = 14,
    due_deletions = 15,
    due_rotations = 16,
};

namespace catalog_api_detail {

/// A length-prefixed field of raw bytes: a record in its own encoding.
inline auto put_blob(byte_writer& w, std::string_view v) -> void {
    if (v.size() > UINT32_MAX) {
        throw std::length_error("kms catalog api: field too long");
    }
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const char c : v) {
        w.u8(static_cast<std::uint8_t>(c));
    }
}

inline auto get_blob(byte_reader& r) -> std::string {
    const auto n = r.u32();
    std::string out;
    out.reserve(std::min<std::size_t>(n, 1U << 20U));
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(static_cast<char>(r.u8()));
    }
    return out;
}

inline auto bytes_of(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<std::byte>(s[i]);
    }
    return out;
}

inline auto text_of(const std::vector<std::byte>& b) -> std::string {
    std::string out(b.size(), '\0');
    for (std::size_t i = 0; i < b.size(); ++i) {
        out[i] = static_cast<char>(b[i]);
    }
    return out;
}

template<typename Record>
inline auto put_optional(byte_writer& w, const std::optional<Record>& r) -> void {
    w.boolean(r.has_value());
    if (r) {
        put_blob(w, r->encode());
    }
}

template<typename Record> inline auto get_optional(byte_reader& r) -> std::optional<Record> {
    if (!r.boolean()) {
        return std::nullopt;
    }
    return Record::decode(get_blob(r));
}

template<typename Record>
inline auto put_records(byte_writer& w, const std::vector<Record>& records) -> void {
    w.u32(static_cast<std::uint32_t>(records.size()));
    for (const auto& rec : records) {
        put_blob(w, rec.encode());
    }
}

template<typename Record> inline auto get_records(byte_reader& r) -> std::vector<Record> {
    const auto n = r.u32();
    std::vector<Record> out;
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(Record::decode(get_blob(r)));
    }
    return out;
}

inline auto put_strings(byte_writer& w, const std::vector<std::string>& v) -> void {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const auto& s : v) {
        w.str(s);
    }
}

inline auto get_strings(byte_reader& r) -> std::vector<std::string> {
    const auto n = r.u32();
    std::vector<std::string> out;
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(r.str());
    }
    return out;
}

}  // namespace catalog_api_detail

// -- The data node's side --------------------------------------------------------

/// What a data node serves the API from: its own replica and host.
struct catalog_server_deps {
    /// A read barrier, then the index this replica has applied; nullopt
    /// when no read-index point was reached in time.
    std::function<std::optional<std::uint64_t>()> read_index;
    /// Waits (bounded) until this replica has applied `index`.
    std::function<bool(std::uint64_t)> wait_applied;
    /// The index this replica has applied.
    std::function<std::uint64_t()> applied_index;
    /// This replica's queries, or null before the catalog opens.
    std::function<std::shared_ptr<const kms_catalog_reader>()> reader;
    /// A proposal through this node's host; throws when the outcome is
    /// unknown.
    std::function<catalog_status(const std::vector<std::byte>&)> propose;
};

/// An answer to a catalog API request: the HTTP status and body.
struct catalog_answer {
    unsigned status = 0;
    std::string body;
};

namespace catalog_api_detail {

inline auto answer_query(const kms_catalog_reader& c, byte_reader& in, byte_writer& out) -> void {
    const auto q = static_cast<catalog_query>(in.u8());
    switch (q) {
        case catalog_query::key:
            put_optional(out, c.key(in.str()));
            break;
        case catalog_query::tombstoned:
            out.boolean(c.tombstoned(in.str()));
            break;
        case catalog_query::keys: {
            const auto account = in.str();
            const auto after = in.str();
            const auto limit = in.u64();
            put_strings(out, c.keys(account, after,
                                    limit > SIZE_MAX ? SIZE_MAX : static_cast<std::size_t>(limit)));
            break;
        }
        case catalog_query::versions:
            put_records(out, c.versions(in.str()));
            break;
        case catalog_query::version: {
            const auto id = in.str();
            put_optional(out, c.version(id, in.u32()));
            break;
        }
        case catalog_query::tags: {
            const auto tags = c.tags(in.str());
            out.u32(static_cast<std::uint32_t>(tags.size()));
            for (const auto& [k, v] : tags) {
                out.str(k).str(v);
            }
            break;
        }
        case catalog_query::alias: {
            const auto account = in.str();
            put_optional(out, c.alias(account, in.str()));
            break;
        }
        case catalog_query::aliases: {
            const auto account = in.str();
            put_records(out, c.aliases(account, in.str()));
            break;
        }
        case catalog_query::grant: {
            const auto id = in.str();
            put_optional(out, c.grant(id, in.str()));
            break;
        }
        case catalog_query::grants:
            put_records(out, c.grants(in.str()));
            break;
        case catalog_query::counts: {
            const auto n = c.counts(in.str());
            out.u32(n.keys).u32(n.aliases);
            break;
        }
        case catalog_query::limits: {
            const auto l = c.limits(in.str());
            out.u32(l.max_keys).u32(l.max_aliases);
            break;
        }
        case catalog_query::lease: {
            const auto l = c.lease();
            out.str(l.holder).u64(l.token).u64(l.expiry_ms);
            break;
        }
        case catalog_query::creating_keys:
            put_records(out, c.creating_keys());
            break;
        case catalog_query::due_deletions:
            put_records(out, c.due_deletions(in.u64()));
            break;
        case catalog_query::due_rotations:
            put_records(out, c.due_rotations(in.u64()));
            break;
        default:
            throw std::invalid_argument("kms catalog api: unknown query");
    }
    in.finish();
}

}  // namespace catalog_api_detail

/// Answers a catalog API request, or nothing when `target` is not one.
/// `allowed` is the listener's verdict on the caller (a front end or a
/// data node, Requirement 9.2).
[[nodiscard]] inline auto serve_catalog(const catalog_server_deps& deps, bool allowed,
                                        std::string_view method, std::string_view target,
                                        std::string_view body) -> std::optional<catalog_answer> {
    using namespace catalog_api_detail;  // NOLINT(google-build-using-namespace)
    if (!is_catalog_path(target)) {
        return std::nullopt;
    }
    if (!allowed) {
        return catalog_answer{403, "not a KMS front end or data node"};
    }
    if (method != "POST") {
        return catalog_answer{400, "malformed catalog request"};
    }
    try {
        byte_writer out;
        out.u8(k_catalog_api_version);
        if (target == catalog_read_index_path) {
            const auto index = deps.read_index();
            if (!index) {
                return catalog_answer{503, "no read-index point"};
            }
            out.u64(*index);
            return catalog_answer{200, out.take_string()};
        }
        if (target == catalog_propose_path) {
            byte_reader in(body);
            if (in.u8() != k_catalog_api_version) {
                return catalog_answer{400, "unknown catalog api version"};
            }
            const auto command = bytes_of(get_blob(in));
            in.finish();
            catalog_status s{};
            try {
                s = deps.propose(command);
            } catch (const std::invalid_argument&) {
                throw;  // a malformed command: the caller's bug
            } catch (const std::exception&) {
                return catalog_answer{503, "proposal outcome unknown"};
            }
            out.u8(static_cast<std::uint8_t>(s)).u64(deps.applied_index());
            return catalog_answer{200, out.take_string()};
        }
        if (target == catalog_query_path) {
            byte_reader in(body);
            if (in.u8() != k_catalog_api_version) {
                return catalog_answer{400, "unknown catalog api version"};
            }
            const auto min_index = in.u64();
            if (!deps.wait_applied(min_index)) {
                return catalog_answer{503, "not applied far enough"};
            }
            const auto c = deps.reader();
            if (!c) {
                return catalog_answer{503, "the catalog has not opened"};
            }
            answer_query(*c, in, out);
            return catalog_answer{200, out.take_string()};
        }
    } catch (const std::invalid_argument&) {
        return catalog_answer{400, "malformed catalog request"};
    } catch (const std::out_of_range&) {
        return catalog_answer{400, "malformed catalog request"};
    } catch (const std::exception&) {
        return catalog_answer{503, "catalog request failed"};
    }
    return catalog_answer{400, "malformed catalog request"};
}

/// catalog_server_deps over a basic_kms_host (kms_host.hpp) and its
/// replica's access; both must outlive the deps.
template<typename KmsHost>
[[nodiscard]] auto catalog_server_over(KmsHost& host, kms_catalog_access& local)
    -> catalog_server_deps {
    return catalog_server_deps{
        .read_index = [&host]() -> std::optional<std::uint64_t> {
            if (!host.barrier()) {
                return std::nullopt;
            }
            return host.applied_index();
        },
        .wait_applied = [&host](std::uint64_t index) { return host.await_applied(index); },
        .applied_index = [&host] { return host.applied_index(); },
        .reader = [&local] { return local.reader(); },
        .propose = [&host](const std::vector<std::byte>& c) { return host.propose(c); },
    };
}

// -- The front end's side --------------------------------------------------------

/// One POST to a data node: the HTTP status and body, or nothing when the
/// node could not be reached. `base_url` is "https://host:port".
using catalog_transport = std::function<std::optional<std::pair<unsigned, std::string>>(
    std::string_view base_url, std::string_view target, std::string body)>;

/// kms_catalog_access over the data layer's catalog API: a front end
/// without the `data` role (Requirement 2.2). Data nodes are tried in
/// turn, starting from the last one that answered.
class remote_catalog_access final : public kms_catalog_access {
public:
    remote_catalog_access(std::vector<std::string> data_nodes, catalog_transport transport)
        : _shared(std::make_shared<shared>(std::move(data_nodes), std::move(transport))) {
        if (_shared->nodes.empty() || !_shared->transport) {
            throw std::invalid_argument("remote_catalog_access: no data nodes or no transport");
        }
    }

    /// One read-index round through a data node: later readers' queries
    /// are answered only once a data node has applied that far.
    [[nodiscard]] auto barrier() -> bool override {
        byte_writer w;
        w.u8(k_catalog_api_version);
        const auto body = _shared->call(catalog_read_index_path, w.take_string());
        if (!body) {
            return false;
        }
        try {
            byte_reader r(*body);
            if (r.u8() != k_catalog_api_version) {
                return false;
            }
            const auto index = r.u64();
            r.finish();
            _shared->raise(index);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    /// A reader whose every query is one request, answered at or past the
    /// index of this access's latest barrier or proposal when it is asked
    /// (so a reader kept across passes, as the jobs keep theirs, never
    /// reads behind a later barrier).
    [[nodiscard]] auto reader() const -> std::shared_ptr<const kms_catalog_reader> override {
        return std::make_shared<const remote_reader>(_shared);
    }

    auto propose(const std::vector<std::byte>& command) -> catalog_status override {
        byte_writer w;
        w.u8(k_catalog_api_version);
        catalog_api_detail::put_blob(w, catalog_api_detail::text_of(command));
        const auto body = _shared->call(catalog_propose_path, w.take_string());
        if (!body) {
            throw kms_catalog_unreachable("kms: no data node took the proposal");
        }
        byte_reader r(*body);
        if (r.u8() != k_catalog_api_version) {
            throw kms_catalog_unreachable("kms: unknown catalog api version");
        }
        const auto s = detail::enum_in(r.u8(), catalog_status::ok, catalog_status::stale_lease);
        const auto index = r.u64();
        r.finish();
        _shared->raise(index);
        return s;
    }

    /// The index the next reader's queries must reach (for tests).
    [[nodiscard]] auto min_index() const -> std::uint64_t { return _shared->min_index.load(); }

private:
    struct shared {
        shared(std::vector<std::string> n, catalog_transport t)
            : nodes(std::move(n)), transport(std::move(t)) {}

        std::vector<std::string> nodes;
        catalog_transport transport;
        std::atomic<std::size_t> next{0};
        std::atomic<std::uint64_t> min_index{0};

        void raise(std::uint64_t index) {
            auto cur = min_index.load();
            while (cur < index && !min_index.compare_exchange_weak(cur, index)) {
            }
        }

        /// The body of the first 200 from a data node, trying each once.
        [[nodiscard]] auto call(std::string_view target, const std::string& body)
            -> std::optional<std::string> {
            const auto start = next.load();
            for (std::size_t i = 0; i < nodes.size(); ++i) {
                const auto at = (start + i) % nodes.size();
                std::optional<std::pair<unsigned, std::string>> res;
                try {
                    res = transport(nodes[at], target, body);
                } catch (const std::exception&) {
                    res.reset();
                }
                if (res && res->first == 200) {
                    next.store(at);
                    return std::move(res->second);
                }
                if (res && res->first == 400) {
                    // The request itself is wrong; another node says the same.
                    throw std::invalid_argument("kms catalog api: " + res->second);
                }
            }
            return std::nullopt;
        }
    };

    class remote_reader final : public kms_catalog_reader {
    public:
        explicit remote_reader(std::shared_ptr<shared> s) : _s(std::move(s)) {}

        [[nodiscard]] auto key(std::string_view id) const -> std::optional<key_record> override {
            return ask(
                catalog_query::key, [&](byte_writer& w) { w.str(id); },
                [](byte_reader& r) { return catalog_api_detail::get_optional<key_record>(r); });
        }
        [[nodiscard]] auto tombstoned(std::string_view id) const -> bool override {
            return ask(
                catalog_query::tombstoned, [&](byte_writer& w) { w.str(id); },
                [](byte_reader& r) { return r.boolean(); });
        }
        [[nodiscard]] auto keys(std::string_view account, std::string_view after,
                                std::size_t limit) const -> std::vector<std::string> override {
            return ask(
                catalog_query::keys, [&](byte_writer& w) { w.str(account).str(after).u64(limit); },
                [](byte_reader& r) { return catalog_api_detail::get_strings(r); });
        }
        [[nodiscard]] auto versions(std::string_view id) const
            -> std::vector<key_version> override {
            return ask(
                catalog_query::versions, [&](byte_writer& w) { w.str(id); },
                [](byte_reader& r) { return catalog_api_detail::get_records<key_version>(r); });
        }
        [[nodiscard]] auto version(std::string_view id, std::uint32_t v) const
            -> std::optional<key_version> override {
            return ask(
                catalog_query::version, [&](byte_writer& w) { w.str(id).u32(v); },
                [](byte_reader& r) { return catalog_api_detail::get_optional<key_version>(r); });
        }
        [[nodiscard]] auto tags(std::string_view id) const -> tag_map override {
            return ask(
                catalog_query::tags, [&](byte_writer& w) { w.str(id); },
                [](byte_reader& r) {
                    tag_map out;
                    const auto n = r.u32();
                    for (std::uint32_t i = 0; i < n; ++i) {
                        auto k = r.str();
                        out.emplace(std::move(k), r.str());
                    }
                    return out;
                });
        }
        [[nodiscard]] auto alias(std::string_view account, std::string_view name) const
            -> std::optional<alias_record> override {
            return ask(
                catalog_query::alias, [&](byte_writer& w) { w.str(account).str(name); },
                [](byte_reader& r) { return catalog_api_detail::get_optional<alias_record>(r); });
        }
        [[nodiscard]] auto aliases(std::string_view account, std::string_view id) const
            -> std::vector<alias_record> override {
            return ask(
                catalog_query::aliases, [&](byte_writer& w) { w.str(account).str(id); },
                [](byte_reader& r) { return catalog_api_detail::get_records<alias_record>(r); });
        }
        [[nodiscard]] auto grant(std::string_view id, std::string_view grant_id) const
            -> std::optional<grant_record> override {
            return ask(
                catalog_query::grant, [&](byte_writer& w) { w.str(id).str(grant_id); },
                [](byte_reader& r) { return catalog_api_detail::get_optional<grant_record>(r); });
        }
        [[nodiscard]] auto grants(std::string_view id) const -> std::vector<grant_record> override {
            return ask(
                catalog_query::grants, [&](byte_writer& w) { w.str(id); },
                [](byte_reader& r) { return catalog_api_detail::get_records<grant_record>(r); });
        }
        [[nodiscard]] auto counts(std::string_view account) const -> account_counts override {
            return ask(
                catalog_query::counts, [&](byte_writer& w) { w.str(account); },
                [](byte_reader& r) {
                    account_counts c;
                    c.keys = r.u32();
                    c.aliases = r.u32();
                    return c;
                });
        }
        [[nodiscard]] auto limits(std::string_view account) const -> account_limits override {
            return ask(
                catalog_query::limits, [&](byte_writer& w) { w.str(account); },
                [](byte_reader& r) {
                    account_limits l;
                    l.max_keys = r.u32();
                    l.max_aliases = r.u32();
                    return l;
                });
        }
        [[nodiscard]] auto lease() const -> job_lease override {
            return ask(
                catalog_query::lease, [](byte_writer&) {},
                [](byte_reader& r) {
                    job_lease l;
                    l.holder = r.str();
                    l.token = r.u64();
                    l.expiry_ms = r.u64();
                    return l;
                });
        }
        [[nodiscard]] auto creating_keys() const -> std::vector<key_record> override {
            return ask(
                catalog_query::creating_keys, [](byte_writer&) {},
                [](byte_reader& r) { return catalog_api_detail::get_records<key_record>(r); });
        }
        [[nodiscard]] auto due_deletions(std::uint64_t now_ms) const
            -> std::vector<key_record> override {
            return ask(
                catalog_query::due_deletions, [&](byte_writer& w) { w.u64(now_ms); },
                [](byte_reader& r) { return catalog_api_detail::get_records<key_record>(r); });
        }
        [[nodiscard]] auto due_rotations(std::uint64_t now_ms) const
            -> std::vector<key_record> override {
            return ask(
                catalog_query::due_rotations, [&](byte_writer& w) { w.u64(now_ms); },
                [](byte_reader& r) { return catalog_api_detail::get_records<key_record>(r); });
        }

    private:
        /// One query: the request is the version, the access's minimum
        /// index, the query and what `args` writes; the answer is what
        /// `read` makes of the body after its version byte.
        template<typename Args, typename Read>
        auto ask(catalog_query q, Args&& args, Read&& read) const
            -> std::invoke_result_t<Read&, byte_reader&> {
            byte_writer w;
            w.u8(k_catalog_api_version).u64(_s->min_index.load()).u8(static_cast<std::uint8_t>(q));
            std::forward<Args>(args)(w);
            const auto body = _s->call(catalog_query_path, w.take_string());
            if (!body) {
                throw kms_catalog_unreachable("kms: no data node answered a catalog query");
            }
            byte_reader r(*body);
            if (r.u8() != k_catalog_api_version) {
                throw kms_catalog_unreachable("kms: unknown catalog api version");
            }
            auto out = std::forward<Read>(read)(r);
            r.finish();
            return out;
        }

        std::shared_ptr<shared> _s;
    };

    std::shared_ptr<shared> _shared;
};

}  // namespace kythira::kms
