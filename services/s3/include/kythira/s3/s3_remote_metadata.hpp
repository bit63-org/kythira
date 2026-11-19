// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_remote_metadata.hpp
/// @brief The metadata layer reached over the internal transport, and the
///        per-call choice between it and the local one
///        (.kiro/specs/s3-compatible-storage/ task 16; Requirements 14.2,
///        14.7; Kinesis independent-layers Requirement 3).
///
/// The handlers and workers reach the object index only through
/// `metadata_access` (`s3_metadata.hpp`), which returns values. There are
/// three implementations of it:
///
///  - **local**: `local_metadata`, the group in this process. A co-located
///    node uses it alone, so a local operation costs no hop (14.7).
///  - **remote**: `remote_metadata`, which sends each call to a metadata
///    node's `metadata_server` and decodes the answer. A front end without
///    the metadata role uses it.
///  - **hybrid**: `hybrid_metadata`, which asks a `metadata_choice` about
///    each call and sends it to the local or the remote one. A node with
///    both the front end and the metadata role that is also given other
///    metadata nodes runs it: calls for groups it holds and leads stay in
///    process, the rest go to the node that does.
///
/// **Wire.** One route per call on the internal listener, binary bodies in
/// the index's own record encoding (`s3_index_records.hpp`), so a manifest
/// or a version crosses the wire exactly as it is stored:
///
/// | Request | Answer |
/// |---|---|
/// | `POST /_kythira/s3/metadata/v1/<call>`, body = arguments | 200 with the result |
///
/// where `<call>` is one of `propose`, `bucket`, `list_buckets`, `version`,
/// `list_objects`, `list_versions`, `upload`, `list_uploads`, and for the
/// workers `refcount`, `pending_deletions`, `pending_restores`,
/// `tier_garbage_list`, `change_cursor`, `read_changes`. Every body starts
/// with a format byte. Errors: 400 a body that does not decode, 404 an
/// unknown call, 405 another method, 503 the node cannot serve now (not the
/// group's leader, still starting), 500 the call threw. Who may call is the
/// listener's route guard (`internal_route_rules()` in `s3_roles.hpp`).
///
/// **Failures.** A call that gets no good answer from any endpoint throws
/// `metadata_unavailable`. The pipeline answers it with `503
/// ServiceUnavailable`, which every S3 client retries; a worker's pass
/// stops and the next one starts over. A `propose` that fails this way may
/// or may not have been applied, which is what a client retrying a 503 on
/// S3 already allows for: every entry is either idempotent or makes a new
/// version.
///
/// Reads are answered by the node the transport reaches, at or after every
/// write it acknowledged; until the index groups run on Raft (one group per
/// metadata node today) that node is the only copy, so a read sees every
/// write before it (Requirement 7.2).

#include <kythira/s3/s3_change_log.hpp>
#include <kythira/s3/s3_index_records.hpp>
#include <kythira/s3/s3_index_state_machine.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_roles.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

namespace metadata_wire {

/// The first byte of every request and answer body.
inline constexpr std::uint8_t format = 1;

[[nodiscard]] inline auto begin() -> detail::writer {
    detail::writer w;
    w.u8(format);
    return w;
}

[[nodiscard]] inline auto open(std::string_view body, std::string_view what) -> detail::reader {
    detail::reader r(body);
    r.expect_format(format, what);
    return r;
}

[[nodiscard]] inline auto bytes_of(const std::vector<std::byte>& b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

[[nodiscard]] inline auto vector_of(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<std::byte>(s[i]);
    }
    return out;
}

inline void write_listing(detail::writer& w, const object_listing& l) {
    w.u32(static_cast<std::uint32_t>(l.contents.size()));
    for (const auto& v : l.contents) {
        w.str(codec::encode(v));
    }
    w.u32(static_cast<std::uint32_t>(l.common_prefixes.size()));
    for (const auto& p : l.common_prefixes) {
        w.str(p);
    }
    w.boolean(l.truncated).str(l.next_marker);
}

[[nodiscard]] inline auto read_listing(detail::reader& r) -> object_listing {
    object_listing l;
    l.contents.resize(r.u32());
    for (auto& v : l.contents) {
        v = codec::decode_version(r.str());
    }
    l.common_prefixes.resize(r.u32());
    for (auto& p : l.common_prefixes) {
        p = r.str();
    }
    l.truncated = r.boolean();
    l.next_marker = r.str();
    return l;
}

inline void write_versions(detail::writer& w, const version_listing& l) {
    w.u32(static_cast<std::uint32_t>(l.versions.size()));
    for (const auto& e : l.versions) {
        w.str(codec::encode(e.version)).boolean(e.is_latest);
    }
    w.u32(static_cast<std::uint32_t>(l.common_prefixes.size()));
    for (const auto& p : l.common_prefixes) {
        w.str(p);
    }
    w.boolean(l.truncated).str(l.next_key_marker).str(l.next_version_id_marker);
}

[[nodiscard]] inline auto read_versions(detail::reader& r) -> version_listing {
    version_listing l;
    l.versions.resize(r.u32());
    for (auto& e : l.versions) {
        e.version = codec::decode_version(r.str());
        e.is_latest = r.boolean();
    }
    l.common_prefixes.resize(r.u32());
    for (auto& p : l.common_prefixes) {
        p = r.str();
    }
    l.truncated = r.boolean();
    l.next_key_marker = r.str();
    l.next_version_id_marker = r.str();
    return l;
}

}  // namespace metadata_wire

/// Answers the metadata routes from a `metadata_access` (the node's local
/// group). The extra calls the workers make are answered when `M` has
/// them, and are unknown calls (404) otherwise.
template<metadata_access M> class metadata_server {
public:
    /// `ready`: whether this node may answer now (it leads the group);
    /// empty means always. A node that may not answers 503, so the caller
    /// tries the next endpoint.
    explicit metadata_server(M& meta, std::function<bool()> ready = {})
        : _meta(meta), _ready(std::move(ready)) {}

    /// Whether `target` (path, any query) is a metadata route.
    [[nodiscard]] static auto owns(std::string_view target) -> bool {
        return target.starts_with(metadata_route_prefix);
    }

    /// The status and body for one request on a metadata route.
    [[nodiscard]] auto handle(std::string_view method, std::string_view target,
                              std::string_view body) -> std::pair<unsigned, std::string> {
        if (!owns(target)) {
            return {404, "not a metadata route"};
        }
        auto call = target.substr(metadata_route_prefix.size());
        call = call.substr(0, call.find('?'));
        if (method != "POST") {
            return {405, "metadata calls are POST"};
        }
        if (_ready && !_ready()) {
            return {503, "this node cannot answer metadata calls now"};
        }
        try {
            auto out = answer(call, body);
            if (!out) {
                return {404, "unknown metadata call " + std::string(call)};
            }
            ++_served;
            return {200, std::move(*out)};
        } catch (const index_format_error& e) {
            return {400, e.what()};
        } catch (const std::exception& e) {
            return {500, e.what()};
        }
    }

    [[nodiscard]] auto served() const noexcept -> std::uint64_t { return _served.load(); }

private:
    [[nodiscard]] auto answer(std::string_view call, std::string_view body)
        -> std::optional<std::string> {
        namespace mw = metadata_wire;
        auto r = mw::open(body, "metadata request");
        auto w = mw::begin();
        if (call == "propose") {
            const auto bytes = r.str();
            r.done("propose");
            const auto res = _meta.propose(codec::decode_command(mw::vector_of(bytes)));
            w.str(mw::bytes_of(codec::encode(res)));
        } else if (call == "bucket") {
            const auto name = r.str();
            r.done("bucket");
            const auto b = static_cast<const M&>(_meta).bucket(name);
            w.boolean(b.has_value());
            if (b) {
                w.str(codec::encode(*b));
            }
        } else if (call == "list_buckets") {
            const auto owner = r.str();
            r.done("list_buckets");
            const auto list = static_cast<const M&>(_meta).list_buckets(owner);
            w.u32(static_cast<std::uint32_t>(list.size()));
            for (const auto& b : list) {
                w.str(codec::encode(b));
            }
        } else if (call == "version") {
            const auto id = r.u64();
            const auto key = r.str();
            const auto vid = r.opt_str();
            r.done("version");
            const auto v = static_cast<const M&>(_meta).version(id, key, vid);
            w.boolean(v.has_value());
            if (v) {
                w.str(codec::encode(*v));
            }
        } else if (call == "list_objects") {
            const auto id = r.u64();
            const auto prefix = r.str();
            const auto delimiter = r.str();
            const auto marker = r.str();
            const auto max = static_cast<std::size_t>(r.u64());
            r.done("list_objects");
            mw::write_listing(
                w, static_cast<const M&>(_meta).list_objects(id, prefix, delimiter, marker, max));
        } else if (call == "list_versions") {
            const auto id = r.u64();
            const auto prefix = r.str();
            const auto delimiter = r.str();
            const auto key_marker = r.str();
            const auto vid_marker = r.str();
            const auto max = static_cast<std::size_t>(r.u64());
            r.done("list_versions");
            mw::write_versions(w, static_cast<const M&>(_meta).list_versions(
                                      id, prefix, delimiter, key_marker, vid_marker, max));
        } else if (call == "upload") {
            const auto id = r.u64();
            const auto key = r.str();
            const auto upload_id = r.str();
            r.done("upload");
            const auto u = static_cast<const M&>(_meta).upload(id, key, upload_id);
            w.boolean(u.has_value());
            if (u) {
                w.str(codec::encode(*u));
            }
        } else if (call == "list_uploads") {
            const auto id = r.u64();
            const auto prefix = r.str();
            const auto key_marker = r.str();
            const auto upload_marker = r.str();
            const auto max = static_cast<std::size_t>(r.u64());
            r.done("list_uploads");
            const auto [list, more] = static_cast<const M&>(_meta).list_uploads(
                id, prefix, key_marker, upload_marker, max);
            w.u32(static_cast<std::uint32_t>(list.size()));
            for (const auto& u : list) {
                w.str(codec::encode(u));
            }
            w.boolean(more);
        } else {
            return worker_call(call, r, w);
        }
        return w.take();
    }

    [[nodiscard]] auto worker_call(std::string_view call, detail::reader& r, detail::writer& w)
        -> std::optional<std::string> {
        const auto& cm = static_cast<const M&>(_meta);
        if (call == "refcount") {
            if constexpr (requires(const chunk_sha& s) { cm.refcount(s); }) {
                const auto sha = r.sha();
                r.done("refcount");
                const auto c = cm.refcount(sha);
                w.boolean(c.has_value());
                if (c) {
                    w.str(codec::encode(*c));
                }
                return w.take();
            }
        } else if (call == "pending_deletions") {
            if constexpr (requires(std::size_t n) { cm.pending_deletions(n); }) {
                const auto max = static_cast<std::size_t>(r.u64());
                r.done("pending_deletions");
                const auto list = cm.pending_deletions(max);
                w.u32(static_cast<std::uint32_t>(list.size()));
                for (const auto& s : list) {
                    w.sha(s);
                }
                return w.take();
            }
        } else if (call == "pending_restores") {
            if constexpr (requires(std::size_t n) { cm.pending_restores(n); }) {
                const auto max = static_cast<std::size_t>(r.u64());
                r.done("pending_restores");
                const auto list = cm.pending_restores(max);
                w.u32(static_cast<std::uint32_t>(list.size()));
                for (const auto& p : list) {
                    w.u64(p.bucket_id).str(p.key).u64(p.stamp).u32(p.days);
                }
                return w.take();
            }
        } else if (call == "tier_garbage_list") {
            if constexpr (requires(std::size_t n) { cm.tier_garbage_list(n); }) {
                const auto max = static_cast<std::size_t>(r.u64());
                r.done("tier_garbage_list");
                const auto list = cm.tier_garbage_list(max);
                w.u32(static_cast<std::uint32_t>(list.size()));
                for (const auto& g : list) {
                    w.str(g.index_key).str(g.tier).u64(g.bucket_id).u64(g.stamp);
                    w.u32(static_cast<std::uint32_t>(g.chunks.size()));
                    for (const auto& s : g.chunks) {
                        w.sha(s);
                    }
                }
                return w.take();
            }
        } else if (call == "change_cursor") {
            if constexpr (change_log_access<M>) {
                const auto consumer = r.str();
                r.done("change_cursor");
                w.u64(cm.change_cursor(consumer));
                return w.take();
            }
        } else if (call == "read_changes") {
            if constexpr (change_log_access<M>) {
                const auto after = r.u64();
                const auto max = static_cast<std::size_t>(r.u64());
                r.done("read_changes");
                const auto list = cm.read_changes(after, max);
                w.u32(static_cast<std::uint32_t>(list.size()));
                for (const auto& c : list) {
                    w.u64(c.seq).str(codec::encode_change(c.record));
                }
                return w.take();
            }
        }
        return std::nullopt;
    }

    M& _meta;
    std::function<bool()> _ready;
    std::atomic<std::uint64_t> _served{0};
};

/// Sends one metadata call (`call`, its encoded arguments) and returns the
/// status and body, or nothing when no answer came back.
using metadata_transport = std::function<std::optional<std::pair<unsigned, std::string>>(
    std::string_view call, const std::string& body)>;

/// Sends one request to one endpoint: (base URL, target, body) to the status
/// and body, or nothing when the exchange failed.
using endpoint_send = std::function<std::optional<std::pair<unsigned, std::string>>(
    const std::string& url, const std::string& target, const std::string& body)>;

/// A transport over several metadata nodes: each call goes to the endpoint
/// that last answered, then to the others in order when that one does not
/// answer or answers 503 (it is not the leader, or is starting). Any other
/// answer, success or error, is the call's.
class endpoint_transport {
public:
    endpoint_transport(std::vector<std::string> urls, endpoint_send send)
        : _urls(std::move(urls)), _send(std::move(send)) {
        if (_urls.empty() || !_send) {
            throw std::invalid_argument("s3 metadata transport: needs endpoints and a sender");
        }
    }

    auto operator()(std::string_view call, const std::string& body) const
        -> std::optional<std::pair<unsigned, std::string>> {
        const auto target = std::string(metadata_route_prefix) + std::string(call);
        const auto first = _preferred->load();
        for (std::size_t i = 0; i < _urls.size(); ++i) {
            const auto at = (first + i) % _urls.size();
            auto res = _send(_urls[at], target, body);
            if (res && res->first != 503) {
                _preferred->store(at);
                return res;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto urls() const noexcept -> const std::vector<std::string>& { return _urls; }

private:
    std::vector<std::string> _urls;
    endpoint_send _send;
    std::shared_ptr<std::atomic<std::size_t>> _preferred =
        std::make_shared<std::atomic<std::size_t>>(0);
};

/// `metadata_access` over the internal transport.
class remote_metadata {
public:
    explicit remote_metadata(metadata_transport transport) : _transport(std::move(transport)) {
        if (!_transport) {
            throw std::invalid_argument("s3 remote metadata: needs a transport");
        }
    }

    auto propose(const index_command& c) -> index_result {
        auto w = metadata_wire::begin();
        w.str(metadata_wire::bytes_of(codec::encode(c)));
        const auto answer = call("propose", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        auto out = codec::decode_result(metadata_wire::vector_of(r.str()));
        r.done("propose answer");
        return out;
    }

    [[nodiscard]] auto bucket(std::string_view name) const -> std::optional<bucket_descriptor> {
        auto w = metadata_wire::begin();
        w.str(name);
        const auto answer = call("bucket", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::optional<bucket_descriptor> out;
        if (r.boolean()) {
            out = codec::decode_bucket(r.str());
        }
        r.done("bucket answer");
        return out;
    }

    [[nodiscard]] auto list_buckets(std::string_view owner) const
        -> std::vector<bucket_descriptor> {
        auto w = metadata_wire::begin();
        w.str(owner);
        const auto answer = call("list_buckets", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::vector<bucket_descriptor> out(r.u32());
        for (auto& b : out) {
            b = codec::decode_bucket(r.str());
        }
        r.done("list_buckets answer");
        return out;
    }

    [[nodiscard]] auto version(std::uint64_t bucket_id, std::string_view key,
                               const std::optional<std::string>& version_id) const
        -> std::optional<object_version> {
        auto w = metadata_wire::begin();
        w.u64(bucket_id).str(key).opt_str(version_id);
        const auto answer = call("version", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::optional<object_version> out;
        if (r.boolean()) {
            out = codec::decode_version(r.str());
        }
        r.done("version answer");
        return out;
    }

    [[nodiscard]] auto list_objects(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view delimiter, std::string_view marker,
                                    std::size_t max_keys) const -> object_listing {
        auto w = metadata_wire::begin();
        w.u64(bucket_id).str(prefix).str(delimiter).str(marker).u64(max_keys);
        const auto answer = call("list_objects", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        auto out = metadata_wire::read_listing(r);
        r.done("list_objects answer");
        return out;
    }

    [[nodiscard]] auto list_versions(std::uint64_t bucket_id, std::string_view prefix,
                                     std::string_view delimiter, std::string_view key_marker,
                                     std::string_view version_id_marker, std::size_t max_keys) const
        -> version_listing {
        auto w = metadata_wire::begin();
        w.u64(bucket_id).str(prefix).str(delimiter).str(key_marker).str(version_id_marker);
        w.u64(max_keys);
        const auto answer = call("list_versions", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        auto out = metadata_wire::read_versions(r);
        r.done("list_versions answer");
        return out;
    }

    [[nodiscard]] auto upload(std::uint64_t bucket_id, std::string_view key,
                              std::string_view upload_id) const -> std::optional<upload_record> {
        auto w = metadata_wire::begin();
        w.u64(bucket_id).str(key).str(upload_id);
        const auto answer = call("upload", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::optional<upload_record> out;
        if (r.boolean()) {
            out = codec::decode_upload(r.str());
        }
        r.done("upload answer");
        return out;
    }

    [[nodiscard]] auto list_uploads(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view key_marker, std::string_view upload_id_marker,
                                    std::size_t max) const
        -> std::pair<std::vector<upload_record>, bool> {
        auto w = metadata_wire::begin();
        w.u64(bucket_id).str(prefix).str(key_marker).str(upload_id_marker).u64(max);
        const auto answer = call("list_uploads", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::pair<std::vector<upload_record>, bool> out;
        out.first.resize(r.u32());
        for (auto& u : out.first) {
            u = codec::decode_upload(r.str());
        }
        out.second = r.boolean();
        r.done("list_uploads answer");
        return out;
    }

    [[nodiscard]] auto refcount(const chunk_sha& sha) const -> std::optional<refcount_record> {
        auto w = metadata_wire::begin();
        w.sha(sha);
        const auto answer = call("refcount", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::optional<refcount_record> out;
        if (r.boolean()) {
            out = codec::decode_refcount(r.str());
        }
        r.done("refcount answer");
        return out;
    }

    [[nodiscard]] auto pending_deletions(std::size_t max) const -> std::vector<chunk_sha> {
        auto w = metadata_wire::begin();
        w.u64(max);
        const auto answer = call("pending_deletions", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::vector<chunk_sha> out(r.u32());
        for (auto& s : out) {
            s = r.sha();
        }
        r.done("pending_deletions answer");
        return out;
    }

    [[nodiscard]] auto pending_restores(std::size_t max) const -> std::vector<pending_restore> {
        auto w = metadata_wire::begin();
        w.u64(max);
        const auto answer = call("pending_restores", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::vector<pending_restore> out(r.u32());
        for (auto& p : out) {
            p.bucket_id = r.u64();
            p.key = r.str();
            p.stamp = r.u64();
            p.days = r.u32();
        }
        r.done("pending_restores answer");
        return out;
    }

    [[nodiscard]] auto tier_garbage_list(std::size_t max) const -> std::vector<tier_garbage_entry> {
        auto w = metadata_wire::begin();
        w.u64(max);
        const auto answer = call("tier_garbage_list", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::vector<tier_garbage_entry> out(r.u32());
        for (auto& g : out) {
            g.index_key = r.str();
            g.tier = r.str();
            g.bucket_id = r.u64();
            g.stamp = r.u64();
            g.chunks.resize(r.u32());
            for (auto& s : g.chunks) {
                s = r.sha();
            }
        }
        r.done("tier_garbage_list answer");
        return out;
    }

    [[nodiscard]] auto change_cursor(std::string_view consumer) const -> std::uint64_t {
        auto w = metadata_wire::begin();
        w.str(consumer);
        const auto answer = call("change_cursor", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        const auto out = r.u64();
        r.done("change_cursor answer");
        return out;
    }

    [[nodiscard]] auto read_changes(std::uint64_t after, std::size_t max) const
        -> std::vector<sequenced_change> {
        auto w = metadata_wire::begin();
        w.u64(after).u64(max);
        const auto answer = call("read_changes", w.take());
        auto r = metadata_wire::open(answer, "metadata answer");
        std::vector<sequenced_change> out(r.u32());
        for (auto& c : out) {
            c.seq = r.u64();
            c.record = codec::decode_change(r.str());
        }
        r.done("read_changes answer");
        return out;
    }

private:
    /// Sends `name` and returns the body of its 200 answer.
    [[nodiscard]] auto call(std::string_view name, const std::string& body) const -> std::string {
        auto res = _transport(name, body);
        if (!res) {
            throw metadata_unavailable("no metadata node answered " + std::string(name));
        }
        if (res->first != 200) {
            throw metadata_unavailable("metadata call " + std::string(name) + " answered " +
                                       std::to_string(res->first) + ": " +
                                       res->second.substr(0, 200));
        }
        return std::move(res->second);
    }

    metadata_transport _transport;
};

static_assert(metadata_access<remote_metadata>);
static_assert(change_log_access<remote_metadata>);

/// What `hybrid_metadata` asks about each call.
struct metadata_call {
    enum class kind : std::uint8_t {
        /// `propose`: needs the group's leader.
        write,
        /// A read of the catalog or of one bucket's objects.
        read,
        /// The workers' reads (counts, collection, restores, the change
        /// log).
        worker,
    };
    kind what = kind::read;
    /// The bucket the call is about: the catalog name for catalog calls
    /// (`bucket`, a bucket-level `propose`), the id for object calls; empty
    /// and 0 for calls about no one bucket (`list_buckets`, the workers').
    std::string_view bucket;
    std::uint64_t bucket_id = 0;
};

/// True: serve the call from the local group. False: send it to the remote
/// one.
using metadata_choice = std::function<bool(const metadata_call&)>;

/// `metadata_access` that chooses local or remote per call (Kinesis
/// Requirement 3.2: per call, not per cluster). Does not own either side.
template<metadata_access L, metadata_access R> class hybrid_metadata {
public:
    /// An empty `choice` keeps every call local.
    hybrid_metadata(L& local, R& remote, metadata_choice choice)
        : _local(local), _remote(remote), _choice(std::move(choice)) {}

    auto propose(const index_command& c) -> index_result {
        const auto bucket_id = c.target.id;
        return local({metadata_call::kind::write, c.bucket, bucket_id}) ? _local.propose(c)
                                                                        : _remote.propose(c);
    }
    [[nodiscard]] auto bucket(std::string_view name) const -> std::optional<bucket_descriptor> {
        return pick({metadata_call::kind::read, name, 0},
                    [&](const auto& m) { return m.bucket(name); });
    }
    [[nodiscard]] auto list_buckets(std::string_view owner) const
        -> std::vector<bucket_descriptor> {
        return pick({metadata_call::kind::read, {}, 0},
                    [&](const auto& m) { return m.list_buckets(owner); });
    }
    [[nodiscard]] auto version(std::uint64_t id, std::string_view key,
                               const std::optional<std::string>& vid) const
        -> std::optional<object_version> {
        return pick({metadata_call::kind::read, {}, id},
                    [&](const auto& m) { return m.version(id, key, vid); });
    }
    [[nodiscard]] auto list_objects(std::uint64_t id, std::string_view prefix,
                                    std::string_view delimiter, std::string_view marker,
                                    std::size_t max) const -> object_listing {
        return pick({metadata_call::kind::read, {}, id}, [&](const auto& m) {
            return m.list_objects(id, prefix, delimiter, marker, max);
        });
    }
    [[nodiscard]] auto list_versions(std::uint64_t id, std::string_view prefix,
                                     std::string_view delimiter, std::string_view key_marker,
                                     std::string_view vid_marker, std::size_t max) const
        -> version_listing {
        return pick({metadata_call::kind::read, {}, id}, [&](const auto& m) {
            return m.list_versions(id, prefix, delimiter, key_marker, vid_marker, max);
        });
    }
    [[nodiscard]] auto upload(std::uint64_t id, std::string_view key,
                              std::string_view upload_id) const -> std::optional<upload_record> {
        return pick({metadata_call::kind::read, {}, id},
                    [&](const auto& m) { return m.upload(id, key, upload_id); });
    }
    [[nodiscard]] auto list_uploads(std::uint64_t id, std::string_view prefix,
                                    std::string_view key_marker, std::string_view upload_marker,
                                    std::size_t max) const
        -> std::pair<std::vector<upload_record>, bool> {
        return pick({metadata_call::kind::read, {}, id}, [&](const auto& m) {
            return m.list_uploads(id, prefix, key_marker, upload_marker, max);
        });
    }

    /// The change log, when both sides have it.
    [[nodiscard]] auto change_cursor(std::string_view consumer) const -> std::uint64_t
    requires change_log_access<L> && change_log_access<R>
    {
        return pick({metadata_call::kind::worker, {}, 0},
                    [&](const auto& m) { return m.change_cursor(consumer); });
    }
    [[nodiscard]] auto read_changes(std::uint64_t after, std::size_t max) const
        -> std::vector<sequenced_change>
    requires change_log_access<L> && change_log_access<R>
    {
        return pick({metadata_call::kind::worker, {}, 0},
                    [&](const auto& m) { return m.read_changes(after, max); });
    }

    /// Calls served by each side.
    [[nodiscard]] auto local_calls() const noexcept -> std::uint64_t { return _local_calls.load(); }
    [[nodiscard]] auto remote_calls() const noexcept -> std::uint64_t {
        return _remote_calls.load();
    }

private:
    [[nodiscard]] auto local(const metadata_call& c) const -> bool {
        const bool here = !_choice || _choice(c);
        ++(here ? _local_calls : _remote_calls);
        return here;
    }
    template<typename F> [[nodiscard]] auto pick(const metadata_call& c, F&& f) const {
        return local(c) ? f(static_cast<const L&>(_local)) : f(static_cast<const R&>(_remote));
    }

    L& _local;
    R& _remote;
    metadata_choice _choice;
    mutable std::atomic<std::uint64_t> _local_calls{0};
    mutable std::atomic<std::uint64_t> _remote_calls{0};
};

}  // namespace kythira::s3
