// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_sweeps.hpp
/// @brief Chunk collection, the orphan sweep and placement repair
///        (.kiro/specs/s3-compatible-storage/ task 12, Requirements 10.3,
///        10.4, 10.6).
///
/// `chunk_sweeper` is the background worker over the blob stores. One
/// `sweep()` does three things:
///
/// 1. **Collection.** It proposes `collect_chunks`, which marks the chunks
///    whose reference count has been zero for the grace period as
///    collecting, and deletes them from every node.
/// 2. **Orphans.** It walks every node's store (the paged listing of
///    `chunk_service.hpp`, merged across nodes in hash order, so the walk
///    holds one page per node) and looks each chunk up in the index. A
///    chunk with no record at all was written by a PUT that never
///    committed (10.4). It becomes a candidate, and a candidate still
///    record-less a grace period after this sweeper first saw it is
///    claimed (`claim_chunks`, which marks it collecting only if it still
///    has no record) and deleted like a collected one.
/// 3. **Repair.** A live chunk missing from a reachable node of its
///    placement is copied there from a node that has it, through the
///    verified read (10.6). A node that does not answer the listing is not
///    written to and does not count as missing anything.
///
/// **Why deleting is safe.** A write stores its chunks first and commits
/// the manifest after, so between the two the index has never heard of
/// them, and a chunk it found already stored is skipped. Three rules keep a
/// commit from naming bytes the sweeper deletes:
///
/// - The index refuses a reference to a chunk marked collecting (503
///   SlowDown; the SDKs retry, and the retry stores the bytes again).
/// - Once deleted, the chunk keeps a tombstone for a grace period, and a
///   reference from a write that began storing before the deletion plus
///   `chunk_clock_skew_ms` is refused the same way (`written_ms`).
/// - A write that takes longer than `service_options::max_write_ms` from
///   its first chunk to its commit is refused by the front end, and the
///   grace period must exceed that plus the clock allowance, which the
///   constructor checks. So no write outlives the tombstones it needs, and
///   none can be in flight on a chunk that has had no record for a whole
///   grace period.
///
/// A chunk stays in the index's pending list (`s3/p/`) from being marked
/// collecting until every node has answered its delete (removed or not
/// held), so a sweeper that stops half way, or meets a node that is down,
/// finishes the job on a later pass. Until then that chunk's bytes are
/// refused to writers, so a node that is gone for good must leave the node
/// list the sweeper is given.
///
/// A chunk whose record says deleted but which some node still holds is
/// left alone: it may be a new write of the same bytes that has yet to
/// commit. When the tombstone is purged it has no record, and the orphan
/// rule takes over.
///
/// One sweeper runs at a time per index (task 16 runs it on the metadata
/// group's leader); `sweep()` is not reentrant. The candidate list lives in
/// memory, so a restarted sweeper waits one more grace period before it
/// claims anything, which only delays it.

#include <kythira/s3/s3_data_path.hpp>
#include <kythira/s3/s3_index_state_machine.hpp>
#include <kythira/s3/s3_placement.hpp>

#include <raft/chunk_service.hpp>

#include <algorithm>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// What the sweeper needs from the metadata layer.
template<typename M>
concept chunk_metadata_access =
    requires(M& m, const M& cm, const index_command& c, const chunk_sha& sha, std::size_t n) {
        { m.propose(c) } -> std::same_as<index_result>;
        { cm.refcount(sha) } -> std::same_as<std::optional<refcount_record>>;
        { cm.pending_deletions(n) } -> std::same_as<std::vector<chunk_sha>>;
    };

/// A node's chunk access that can also list and delete: `local_chunk_access`
/// or `remote_chunk_access`.
template<typename A>
concept chunk_inventory_access =
    chunk_access<A> &&
    requires(A& a, const std::optional<chunk_sha>& after, std::size_t n, const chunk_sha& sha) {
        { a.list(after, n) } -> std::same_as<std::optional<chunk_listing>>;
        { a.remove(sha) } -> std::same_as<chunk_remove_result>;
    };

/// One node's whole store. Does not own the access.
class chunk_inventory {
public:
    template<chunk_inventory_access A>
    chunk_inventory(std::string node, A& access)
        : _copy(node, access),
          _list([&access](const std::optional<chunk_sha>& after, std::size_t n) {
              return access.list(after, n);
          }),
          _remove([&access](const chunk_sha& sha) { return access.remove(sha); }) {}

    [[nodiscard]] auto list(const std::optional<chunk_sha>& after, std::size_t limit) const
        -> std::optional<chunk_listing> {
        return _list(after, limit);
    }
    [[nodiscard]] auto remove(const chunk_sha& sha) const -> chunk_remove_result {
        return _remove(sha);
    }
    /// Reads and writes, for repair.
    [[nodiscard]] auto copy() const noexcept -> const chunk_copy& { return _copy; }
    [[nodiscard]] auto node() const noexcept -> const std::string& { return _copy.node(); }

private:
    chunk_copy _copy;
    std::function<std::optional<chunk_listing>(const std::optional<chunk_sha>&, std::size_t)> _list;
    std::function<chunk_remove_result(const chunk_sha&)> _remove;
};

/// The nodes that hold chunks now.
using inventory_list_fn = std::function<std::vector<const chunk_inventory*>()>;

struct sweep_options {
    /// How long a chunk's count stays at zero, and an orphan stays a
    /// candidate, before deletion; also how long tombstones last.
    std::uint64_t grace_ms = std::uint64_t{60} * 60 * 1000;
    /// The front end's `service_options::max_write_ms`; the grace period
    /// must exceed it plus `chunk_clock_skew_ms`.
    std::uint64_t max_write_ms = std::uint64_t{15} * 60 * 1000;
    /// Chunks per index entry (collect, claim, deleted) and per listing
    /// page.
    std::size_t batch = 1000;
    /// Collection entries per sweep, so one sweep's work is bounded.
    std::size_t max_batches = 100;
    /// The clock, for tests; the system clock when empty.
    std::function<std::uint64_t()> clock;
};

/// What one sweep did.
struct sweep_report {
    /// Chunks whose count reached zero a grace period ago.
    std::uint64_t collected = 0;
    /// Record-less chunks seen, and those claimed (seen a grace period ago).
    std::uint64_t orphans_seen = 0;
    std::uint64_t orphans_claimed = 0;
    /// Chunks deleted from every node and reported to the index.
    std::uint64_t deleted = 0;
    /// Collecting chunks some node could not delete yet.
    std::uint64_t deletes_pending = 0;
    std::uint64_t copies_removed = 0;
    /// Copies written to restore placements, and copies that could not be.
    std::uint64_t repaired = 0;
    std::uint64_t repair_failures = 0;
    std::uint64_t chunks_listed = 0;
    /// Nodes whose listing failed part way (or at once).
    std::uint64_t unreachable_nodes = 0;
};

template<chunk_metadata_access M> class chunk_sweeper {
public:
    chunk_sweeper(M& meta, inventory_list_fn nodes, placement_fn placement,
                  sweep_options options = {})
        : _meta(meta),
          _nodes(std::move(nodes)),
          _placement(std::move(placement)),
          _options(std::move(options)) {
        if (!_nodes || !_placement || _options.batch == 0) {
            throw std::invalid_argument("s3 sweeper: needs nodes, placement and a batch size");
        }
        if (_options.grace_ms <= _options.max_write_ms + chunk_clock_skew_ms) {
            throw std::invalid_argument(
                "s3 sweeper: the grace period must exceed the longest write plus the clock "
                "allowance");
        }
    }

    auto sweep() -> sweep_report {
        sweep_report r;
        const auto nodes = _nodes();
        collect(r);
        walk(nodes, r);
        finish_pending(nodes, r);
        return r;
    }

    /// Orphan candidates being watched, for tests and metrics.
    [[nodiscard]] auto candidates() const noexcept -> std::size_t { return _candidates.size(); }
    [[nodiscard]] auto options() const noexcept -> const sweep_options& { return _options; }

private:
    [[nodiscard]] auto now_ms() const -> std::uint64_t {
        if (_options.clock) {
            return _options.clock();
        }
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

    void collect(sweep_report& r) {
        for (std::size_t i = 0; i < _options.max_batches; ++i) {
            index_command c;
            c.op = index_command::kind::collect_chunks;
            c.now_ms = now_ms();
            c.grace_ms = _options.grace_ms;
            c.max = static_cast<std::uint32_t>(_options.batch);
            const auto res = _meta.propose(c);
            r.collected += res.collected.size();
            if (res.collected.size() < _options.batch) {
                break;
            }
        }
    }

    /// One node's listing, a page at a time.
    struct cursor {
        const chunk_inventory* inv = nullptr;
        chunk_listing page;
        std::size_t at = 0;
        std::optional<chunk_sha> after;
        bool more = true;
        bool failed = false;

        [[nodiscard]] auto done() const -> bool { return failed || at >= page.chunks.size(); }
        [[nodiscard]] auto head() const -> const chunk_sha& { return page.chunks[at].first; }
    };

    /// The next page once the current one is used up.
    void fill(cursor& c, sweep_report& r) const {
        while (!c.failed && c.more && c.at >= c.page.chunks.size()) {
            auto next = c.inv->list(c.after, _options.batch);
            if (!next) {
                c.failed = true;
                ++r.unreachable_nodes;
                return;
            }
            c.page = std::move(*next);
            c.at = 0;
            c.more = c.page.truncated && !c.page.chunks.empty();
            if (!c.page.chunks.empty()) {
                c.after = c.page.chunks.back().first;
            }
            r.chunks_listed += c.page.chunks.size();
        }
    }

    /// Merge every node's listing in hash order and judge each chunk once.
    void walk(const std::vector<const chunk_inventory*>& nodes, sweep_report& r) {
        std::vector<cursor> cursors;
        cursors.reserve(nodes.size());
        for (const auto* n : nodes) {
            if (n != nullptr) {
                cursors.emplace_back().inv = n;
                fill(cursors.back(), r);
            }
        }
        const auto now = now_ms();
        std::map<chunk_sha, std::uint64_t> seen;
        std::vector<chunk_sha> due;
        for (;;) {
            const chunk_sha* low = nullptr;
            for (const auto& c : cursors) {
                if (!c.done() && (low == nullptr || c.head() < *low)) {
                    low = &c.head();
                }
            }
            if (low == nullptr) {
                break;
            }
            const chunk_sha sha = *low;
            std::vector<const chunk_inventory*> holders;
            for (auto& c : cursors) {
                if (!c.done() && c.head() == sha) {
                    holders.push_back(c.inv);
                    ++c.at;
                    fill(c, r);
                }
            }
            judge(sha, holders, cursors, now, seen, due, r);
            if (due.size() >= _options.batch) {
                claim(due, r);
            }
        }
        claim(due, r);
        // Candidates not seen this time were claimed, deleted or committed.
        _candidates = std::move(seen);
    }

    void judge(const chunk_sha& sha, const std::vector<const chunk_inventory*>& holders,
               const std::vector<cursor>& cursors, std::uint64_t now,
               std::map<chunk_sha, std::uint64_t>& seen, std::vector<chunk_sha>& due,
               sweep_report& r) {
        const auto rec = _meta.refcount(sha);
        if (!rec) {
            ++r.orphans_seen;
            const auto it = _candidates.find(sha);
            const auto first = it != _candidates.end() ? it->second : now;
            if (first + _options.grace_ms <= now) {
                due.push_back(sha);
            } else {
                seen.emplace(sha, first);
            }
            return;
        }
        if (rec->state != chunk_state::live) {
            return;  // collecting: finish_pending; deleted: see the file comment
        }
        repair(sha, holders, cursors, r);
    }

    void repair(const chunk_sha& sha, const std::vector<const chunk_inventory*>& holders,
                const std::vector<cursor>& cursors, sweep_report& r) {
        const auto p = _placement(sha);
        std::vector<const chunk_inventory*> lacking;
        for (const auto& node : p.nodes) {
            const auto c = std::ranges::find_if(
                cursors, [&](const cursor& k) { return k.inv->node() == node; });
            if (c == cursors.end() || c->failed) {
                continue;  // not reachable: neither written nor counted
            }
            if (std::ranges::none_of(holders,
                                     [&](const chunk_inventory* h) { return h->node() == node; })) {
                lacking.push_back(c->inv);
            }
        }
        if (lacking.empty()) {
            return;
        }
        std::optional<std::vector<std::byte>> bytes;
        for (const auto* h : holders) {
            auto got = h->copy().read(sha);  // verified against the hash
            if (got._status == chunk_read_status::found) {
                bytes = std::move(got._bytes);
                break;
            }
        }
        for (const auto* to : lacking) {
            if (bytes && is_durable(to->copy().write(sha, *bytes))) {
                ++r.repaired;
            } else {
                ++r.repair_failures;
            }
        }
    }

    void claim(std::vector<chunk_sha>& due, sweep_report& r) {
        if (due.empty()) {
            return;
        }
        index_command c;
        c.op = index_command::kind::claim_chunks;
        c.now_ms = now_ms();
        c.chunks = std::move(due);
        due.clear();
        r.orphans_claimed += _meta.propose(c).collected.size();
    }

    /// Delete every collecting chunk from every node, and report the ones
    /// all nodes answered for.
    void finish_pending(const std::vector<const chunk_inventory*>& nodes, sweep_report& r) {
        for (std::size_t i = 0; i < _options.max_batches; ++i) {
            const auto pending = _meta.pending_deletions(_options.batch);
            if (pending.empty()) {
                return;
            }
            std::vector<chunk_sha> gone;
            for (const auto& sha : pending) {
                bool all = true;
                for (const auto* n : nodes) {
                    if (n == nullptr) {
                        continue;
                    }
                    switch (n->remove(sha)) {
                        case chunk_remove_result::removed:
                            ++r.copies_removed;
                            break;
                        case chunk_remove_result::missing:
                            break;
                        case chunk_remove_result::unavailable:
                            all = false;
                            break;
                    }
                }
                if (all) {
                    gone.push_back(sha);
                }
            }
            r.deletes_pending += pending.size() - gone.size();
            if (!gone.empty()) {
                index_command c;
                c.op = index_command::kind::chunks_deleted;
                c.now_ms = now_ms();  // after the deletes: the tombstone's time
                c.chunks = gone;
                _meta.propose(c);
                r.deleted += gone.size();
            }
            if (gone.size() < pending.size() || pending.size() < _options.batch) {
                return;  // the rest wait for a node to come back
            }
        }
    }

    M& _meta;
    inventory_list_fn _nodes;
    placement_fn _placement;
    sweep_options _options;
    /// Record-less chunks and when this sweeper first saw each.
    std::map<chunk_sha, std::uint64_t> _candidates;
};

}  // namespace kythira::s3
