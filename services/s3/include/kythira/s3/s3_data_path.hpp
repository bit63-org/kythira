// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_data_path.hpp
/// @brief The S3 front end's write and read path for object bytes
///        (.kiro/specs/s3-compatible-storage/ task 5, design "Object bytes
///        never go through Raft"; Requirements 7.1, 10.1, 10.2, 10.5, 15.1).
///
/// **Write.** A body is cut into chunks of `data_path_options::chunk_bytes`
/// (8 MiB by default; the multipart part size where a part is the body).
/// Each chunk is hashed with SHA-256 and written to every node its placement
/// names (`s3_placement.hpp`), through `chunk_access` (`chunk_service.hpp`):
/// a function call for this node's own store, one HTTPS request for another
/// node's. A chunk counts once a write quorum of copies answer durable
/// (fsynced, directory entry included). Only when every chunk of the body
/// has its quorum does `put_object` call the commit, which proposes the
/// manifest through Raft; that order is Requirement 10.2's invariant, no
/// committed manifest names a chunk that is nowhere. A chunk that misses
/// its quorum fails the request with `503 SlowDown`, retryable, and nothing
/// is committed. Chunks it did write are durable but unreferenced, which is
/// what the orphan sweep (task 12) and the reference-count grace period are
/// for (10.3, 10.4).
///
/// The body's MD5 is computed alongside, for the single-part ETag S3 gives
/// an unencrypted object (7.4).
///
/// The copies of one chunk are written in parallel and the write waits for
/// all of them, not just the quorum: the bytes are the caller's, so no
/// write may outlive the call. Acknowledging at quorum while stragglers
/// finish needs the chunk owned by the writes; that is an optimisation for
/// the measurement task.
///
/// **Read.** A read takes the manifest of the version the metadata layer
/// returned (the strongly consistent part) and fetches the chunks it
/// overlaps, which are immutable and need no consistency of their own. Each
/// chunk is read from its placement's nodes in order until one answers with
/// bytes that hash to the chunk's name (both `chunk_access` implementations
/// check). Copies on the way that were missing or corrupt are rewritten from
/// the good bytes and reported through `chunk_event_fn` (10.5); a node that
/// does not answer is skipped and not "repaired", since it may be fine. If
/// no copy is good the read fails with `500 InternalError` and every bad
/// copy is reported: a bad chunk is never served.
///
/// **Placement.** The path asks a `placement_fn` where each chunk goes and
/// a `copy_resolver` for each node's access, so it is the same code
/// co-located (the owning group's replicas, this node's in-process) and
/// with a blob pool.

#include <kythira/s3/s3_index_records.hpp>
#include <kythira/s3/s3_placement.hpp>

#include <raft/aws_rest_xml_protocol.hpp>
#include <raft/chunk_service.hpp>
#include <raft/chunk_store.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// One node's chunks, whatever `chunk_access` implementation reaches them.
/// Does not own the access.
class chunk_copy {
public:
    template<chunk_access A>
    chunk_copy(std::string node, A& access)
        : _node(std::move(node)),
          _write([&access](const chunk_sha& sha, std::span<const std::byte> b) {
              return access.write(sha, b);
          }),
          _read([&access](const chunk_sha& sha) { return access.read(sha); }) {}

    [[nodiscard]] auto write(const chunk_sha& sha, std::span<const std::byte> bytes) const
        -> chunk_write_result {
        return _write(sha, bytes);
    }
    [[nodiscard]] auto read(const chunk_sha& sha) const -> chunk_read_result { return _read(sha); }
    [[nodiscard]] auto node() const noexcept -> const std::string& { return _node; }

private:
    std::string _node;
    std::function<chunk_write_result(const chunk_sha&, std::span<const std::byte>)> _write;
    std::function<chunk_read_result(const chunk_sha&)> _read;
};

static_assert(chunk_access<const chunk_copy>);

/// Where a chunk goes (usually `place` over the current map).
using placement_fn = std::function<chunk_placement(const chunk_sha&)>;
/// A node's access by id; `nullptr` for a node this one cannot reach, which
/// counts as unavailable.
using copy_resolver = std::function<const chunk_copy*(std::string_view node)>;

/// A copy a read found missing or corrupt, and whether it was rewritten.
struct chunk_event {
    chunk_sha sha{};
    std::string node;
    chunk_read_status found = chunk_read_status::corrupt;
    bool repaired = false;
};
using chunk_event_fn = std::function<void(const chunk_event&)>;

struct data_path_options {
    /// At most the blob stores' `chunk_store_options::_max_chunk_bytes`.
    std::size_t chunk_bytes = std::size_t{8} * 1024 * 1024;
    /// Write a chunk's copies on threads of their own; off, one after
    /// another (tests, single-copy placements).
    bool parallel_writes = true;
};

/// Counters for the metrics endpoint and tests.
struct data_path_stats {
    std::uint64_t chunks_written = 0;
    std::uint64_t copies_written = 0;
    std::uint64_t quorum_failures = 0;
    std::uint64_t chunks_read = 0;
    std::uint64_t bad_copies = 0;
    std::uint64_t repairs = 0;
    std::uint64_t unreadable_chunks = 0;
};

/// A written body: its manifest, size and MD5.
struct written_body {
    std::vector<chunk_ref> manifest;
    std::uint64_t size = 0;
    /// Lower-case hex, S3's single-part ETag (without the quotes).
    std::string md5_hex;
};

namespace detail {

class md5_stream {
public:
    md5_stream() : _ctx(::EVP_MD_CTX_new()) {
        if (!_ctx || ::EVP_DigestInit_ex(_ctx.get(), ::EVP_md5(), nullptr) != 1) {
            throw std::runtime_error("s3 data path: MD5 init failed");
        }
    }
    void update(std::span<const std::byte> b) {
        if (!b.empty() && ::EVP_DigestUpdate(_ctx.get(), b.data(), b.size()) != 1) {
            throw std::runtime_error("s3 data path: MD5 update failed");
        }
    }
    [[nodiscard]] auto hex() -> std::string {
        std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
        unsigned int len = 0;
        if (::EVP_DigestFinal_ex(_ctx.get(), md.data(), &len) != 1) {
            throw std::runtime_error("s3 data path: MD5 final failed");
        }
        static constexpr std::string_view digits = "0123456789abcdef";
        std::string out;
        for (unsigned int i = 0; i < len; ++i) {
            out.push_back(digits[md.at(i) >> 4U]);
            out.push_back(digits[md.at(i) & 0xFU]);
        }
        return out;
    }

private:
    struct free_ctx {
        void operator()(EVP_MD_CTX* c) const noexcept { ::EVP_MD_CTX_free(c); }
    };
    std::unique_ptr<EVP_MD_CTX, free_ctx> _ctx;
};

}  // namespace detail

[[nodiscard]] inline auto slow_down() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(503, "SlowDown", "Please reduce your request rate.");
}
[[nodiscard]] inline auto internal_error(std::string detail) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(500, "InternalError",
                                        "We encountered an internal error. Please try again.");
    if (!detail.empty()) {
        e.extra.emplace_back("Detail", std::move(detail));
    }
    return e;
}
[[nodiscard]] inline auto invalid_range() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(416, "InvalidRange",
                                      "The requested range is not satisfiable");
}

class data_path {
public:
    data_path(placement_fn placement, copy_resolver resolve, data_path_options options = {},
              chunk_event_fn on_event = {})
        : _placement(std::move(placement)),
          _resolve(std::move(resolve)),
          _options(options),
          _on_event(std::move(on_event)) {
        if (!_placement || !_resolve || _options.chunk_bytes == 0) {
            throw std::invalid_argument("s3 data path: needs placement, resolver and chunk size");
        }
    }

    /// Store one chunk on a write quorum of its placement.
    auto write_chunk(std::span<const std::byte> bytes) -> aws_rest_xml::result<chunk_ref> {
        const chunk_ref ref{sha256_of(bytes), bytes.size()};
        const auto p = _placement(ref.sha);
        if (p.write_quorum == 0 || p.write_quorum > p.nodes.size()) {
            return internal_error("placement asks for an impossible write quorum");
        }
        std::vector<chunk_write_result> results(p.nodes.size(), chunk_write_result::unavailable);
        auto write_one = [&](std::size_t i) {
            if (const auto* copy = _resolve(p.nodes[i])) {
                results[i] = copy->write(ref.sha, bytes);
            }
        };
        if (_options.parallel_writes && p.nodes.size() > 1) {
            std::vector<std::future<void>> pending;
            pending.reserve(p.nodes.size() - 1);
            for (std::size_t i = 1; i < p.nodes.size(); ++i) {
                pending.push_back(std::async(std::launch::async, write_one, i));
            }
            write_one(0);
            for (auto& f : pending) {
                f.get();
            }
        } else {
            for (std::size_t i = 0; i < p.nodes.size(); ++i) {
                write_one(i);
            }
        }
        const auto durable = static_cast<std::size_t>(std::ranges::count_if(results, is_durable));
        _stats.copies_written += durable;
        if (std::ranges::find(results, chunk_write_result::refused) != results.end()) {
            // We hashed the bytes ourselves, so only a chunk larger than a
            // store takes is refused: configuration, not load.
            ++_stats.quorum_failures;
            return internal_error("a blob store refused a chunk of " +
                                  std::to_string(bytes.size()) + " bytes");
        }
        if (durable < p.write_quorum) {
            ++_stats.quorum_failures;
            return slow_down();
        }
        ++_stats.chunks_written;
        return ref;
    }

    /// Cuts a streamed body into chunks and writes each as it fills.
    class body_writer {
    public:
        explicit body_writer(data_path& path) : _path(&path) {
            _buffer.reserve(std::min<std::size_t>(path._options.chunk_bytes, 1024 * 1024));
        }

        /// Add bytes. An error is final: the body is abandoned.
        auto append(std::span<const std::byte> bytes) -> std::optional<aws_rest_xml::error> {
            if (_failed) {
                return _failed;
            }
            _md5.update(bytes);
            _size += bytes.size();
            const auto chunk = _path->_options.chunk_bytes;
            while (!bytes.empty()) {
                if (_buffer.empty() && bytes.size() >= chunk) {
                    // A whole chunk straight from the caller's buffer.
                    if (auto e = flush(bytes.first(chunk))) {
                        return e;
                    }
                    bytes = bytes.subspan(chunk);
                    continue;
                }
                const auto take = std::min(chunk - _buffer.size(), bytes.size());
                _buffer.insert(_buffer.end(), bytes.begin(),
                               bytes.begin() + static_cast<std::ptrdiff_t>(take));
                bytes = bytes.subspan(take);
                if (_buffer.size() == chunk) {
                    if (auto e = flush(_buffer)) {
                        return e;
                    }
                    _buffer.clear();
                }
            }
            return std::nullopt;
        }

        /// Write what remains and give the manifest. An empty body has no
        /// chunks.
        auto finish() -> aws_rest_xml::result<written_body> {
            if (_failed) {
                return *_failed;
            }
            if (!_buffer.empty()) {
                if (auto e = flush(_buffer)) {
                    return *e;
                }
                _buffer.clear();
            }
            return written_body{std::move(_manifest), _size, _md5.hex()};
        }

    private:
        auto flush(std::span<const std::byte> chunk) -> std::optional<aws_rest_xml::error> {
            auto r = _path->write_chunk(chunk);
            if (!r) {
                _failed = r.error();
                return _failed;
            }
            _manifest.push_back(*r);
            return std::nullopt;
        }

        data_path* _path;
        std::vector<std::byte> _buffer;
        std::vector<chunk_ref> _manifest;
        std::uint64_t _size = 0;
        detail::md5_stream _md5;
        std::optional<aws_rest_xml::error> _failed;
    };

    [[nodiscard]] auto writer() -> body_writer { return body_writer(*this); }

    auto write_body(std::span<const std::byte> body) -> aws_rest_xml::result<written_body> {
        auto w = writer();
        if (auto e = w.append(body)) {
            return *e;
        }
        return w.finish();
    }

    /// Write `body`, fill `content`'s manifest and ETag, and only then call
    /// `commit(content)`, which proposes the manifest through Raft and
    /// returns what applying it produced. Nothing is committed if a chunk
    /// misses its quorum.
    template<typename Commit>
    requires std::invocable<Commit&, const object_content&>
    auto put_object(object_content content, std::span<const std::byte> body, Commit&& commit)
        -> aws_rest_xml::result<std::invoke_result_t<Commit&, const object_content&>> {
        auto w = write_body(body);
        if (!w) {
            return w.error();
        }
        content.manifest = std::move(w->manifest);
        content.etag = std::move(w->md5_hex);
        return std::invoke(commit, std::as_const(content));
    }

    /// One chunk's bytes from the first good copy, repairing the bad copies
    /// read before it.
    auto read_chunk(const chunk_ref& ref) -> aws_rest_xml::result<std::vector<std::byte>> {
        ++_stats.chunks_read;
        const auto p = _placement(ref.sha);
        std::vector<std::pair<const chunk_copy*, chunk_read_status>> bad;
        for (const auto& node : p.nodes) {
            const auto* copy = _resolve(node);
            if (copy == nullptr) {
                continue;
            }
            auto r = copy->read(ref.sha);
            if (r._status == chunk_read_status::found) {
                for (const auto& [b, status] : bad) {
                    const bool repaired = is_durable(b->write(ref.sha, r._bytes));
                    _stats.repairs += repaired ? 1 : 0;
                    report({ref.sha, b->node(), status, repaired});
                }
                return std::move(r._bytes);
            }
            if (r._status == chunk_read_status::missing ||
                r._status == chunk_read_status::corrupt) {
                ++_stats.bad_copies;
                bad.emplace_back(copy, r._status);
            }
        }
        ++_stats.unreadable_chunks;
        for (const auto& [b, status] : bad) {
            report({ref.sha, b->node(), status, false});
        }
        return internal_error("no good copy of chunk " + to_hex(ref.sha));
    }

    /// Deliver `length` bytes of the object from `offset` to
    /// `sink(std::span<const std::byte>)`, chunk by chunk. The caller has
    /// read `content` from the metadata layer and resolved the range; a
    /// range past the end is `416 InvalidRange`. On an error part of the
    /// range may have been delivered already.
    template<typename Sink>
    requires std::invocable<Sink&, std::span<const std::byte>>
    auto read_range(const object_content& content, std::uint64_t offset, std::uint64_t length,
                    Sink&& sink) -> aws_rest_xml::result<std::uint64_t> {
        const auto size = content.size();
        if (offset > size || length > size - offset) {
            return invalid_range();
        }
        std::uint64_t pos = 0;
        std::uint64_t delivered = 0;
        const std::uint64_t end = offset + length;
        for (const auto& ref : content.manifest) {
            const std::uint64_t chunk_end = pos + ref.size;
            if (chunk_end > offset && pos < end && ref.size > 0) {
                auto bytes = read_chunk(ref);
                if (!bytes) {
                    return bytes.error();
                }
                if (bytes->size() != ref.size) {
                    return internal_error("chunk " + to_hex(ref.sha) +
                                          " is not the size its manifest says");
                }
                const auto from = std::max(offset, pos) - pos;
                const auto to = std::min(end, chunk_end) - pos;
                std::invoke(sink, std::span<const std::byte>(*bytes).subspan(from, to - from));
                delivered += to - from;
            }
            pos = chunk_end;
            if (pos >= end) {
                break;
            }
        }
        return delivered;
    }

    [[nodiscard]] auto stats() const noexcept -> const data_path_stats& { return _stats; }
    [[nodiscard]] auto options() const noexcept -> const data_path_options& { return _options; }

private:
    void report(const chunk_event& e) const {
        if (_on_event) {
            _on_event(e);
        }
    }

    placement_fn _placement;
    copy_resolver _resolve;
    data_path_options _options;
    chunk_event_fn _on_event;
    data_path_stats _stats;
};

/// The usual resolver: copies by node id, this node's included.
[[nodiscard]] inline auto resolver_for(const std::vector<chunk_copy>& copies) -> copy_resolver {
    return [&copies](std::string_view node) -> const chunk_copy* {
        for (const auto& c : copies) {
            if (c.node() == node) {
                return &c;
            }
        }
        return nullptr;
    };
}

}  // namespace kythira::s3
