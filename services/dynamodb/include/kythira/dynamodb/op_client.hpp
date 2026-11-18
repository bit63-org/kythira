// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file op_client.hpp
/// @brief The calling half of the op protocol `raft_backend.hpp` defines:
///        every `dynamo_backend` call encoded as an op and sent through the
///        derived class's routing (.kiro/specs/dynamodb-independent-layers/
///        task 3).
///
/// `raft_backend` (a data node: runs an op here first, then wherever its
/// answers point, finding groups in its host's shard map) and
/// `remote_backend` (a front end without the data role: sends every op to
/// a data node, finding groups in a route cache) encode the same ops and
/// read the same answers, so that part lives here once. A derived class
/// provides, as members this class may call (it is a friend):
///
/// | Member | What |
/// |---|---|
/// | `run(op, desc)` | runs `op`, aimed at group `desc` when set, until served; returns the answer
/// payload, throws `txn_stale_route` or on error | | `edge_group(range, forward)` | the group at
/// the start (or end) of `range` | | `groups_in(range)` | every group overlapping `range`, in key
/// order | | `group_of(key)` | the group owning `key` | | `now_ms()` | the clock change records are
/// stamped with | | `txn_now_ms()` | the clock transaction deadlines are read on | | `options()` |
/// the `raft_backend_options` (deadline, backoff, txn) | | `txn()` | the `txn_client`, declared
/// last so its threads stop first |

#include <kythira/dynamodb/backend.hpp>
#include <kythira/dynamodb/catalog.hpp>
#include <kythira/dynamodb/gsi_propagator.hpp>
#include <kythira/dynamodb/item_codec.hpp>
#include <kythira/dynamodb/item_state_machine.hpp>
#include <kythira/dynamodb/op_wire.hpp>

#include <raft/future_default.hpp>
#include <raft/txn_coordinator.hpp>
#include <raft/txn_envelope.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::dynamodb {

template<typename Derived, typename Descriptor> class op_client {
public:
    auto catalog(const catalog_command& c) -> catalog_result {
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::catalog));
        op += encode_catalog_command(c);
        const auto out = self().run(op, std::nullopt, catalog_route());
        auto r = decode_catalog_result(out);
        if (!r) {
            throw std::runtime_error("raft_backend: unreadable catalog result");
        }
        return *r;
    }

    auto write(const item_command& c) -> item_result {
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::write));
        op += encode_item_command(stamp_written(c, self().now_ms()));
        return item_answer(self().run(op, std::nullopt, op_route{command_key(c).value_or("")}));
    }

    auto read(std::uint64_t table_id, const key_schema& schema, const item& key, bool consistent)
        -> std::optional<item> {
        auto base = base_item_key(table_id, schema, key);
        if (!base) {
            return std::nullopt;
        }
        item_command c;
        c.table_id = table_id;
        c.schema = schema;
        c.payload = key;
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::read));
        op.push_back(consistent ? '\1' : '\0');
        op += encode_item_command(c);
        const auto out = self().run(op, std::nullopt, op_route{std::move(*base), consistent});
        if (out.empty()) {
            return std::nullopt;
        }
        auto it = decode_item(out);
        if (!it) {
            throw std::runtime_error("raft_backend: unreadable item");
        }
        return it;
    }

    /// Carries the item's pending GSI change from this node before
    /// returning, for tables with synchronous GSIs (`gsi-consistency=sync`):
    /// a read of an index after the write sees it. The item group's
    /// propagator may carry the same change at the same time, which the
    /// entry versions make harmless.
    auto settle_item(const table_descriptor& table, const item& key) -> void {
        item_command c;
        c.table_id = table.table_id;
        c.schema = table.schema;
        c.payload = key;
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::pending));
        op += encode_item_command(c);
        const auto out =
            self().run(op, std::nullopt,
                       op_route{base_item_key(table.table_id, table.schema, key).value_or("")});
        if (out.empty()) {
            return;
        }
        detail::reader in(out);
        auto pkey = in.bytes();
        auto record = in.bytes();
        const auto has_item = in.byte();
        auto pending = record ? decode_gsi_pending(*record) : std::nullopt;
        if (!pkey || !pending || !has_item) {
            throw std::runtime_error("raft_backend: unreadable pending change");
        }
        gsi_work w;
        w.pending_key = std::move(*pkey);
        w.pending = std::move(*pending);
        if (*has_item == 1) {
            const auto bytes = in.bytes();
            w.current = bytes ? decode_item(*bytes) : std::nullopt;
            if (!w.current) {
                throw std::runtime_error("raft_backend: unreadable pending change");
            }
        }
        const auto plan = plan_propagation(table, w);
        for (const auto& write_cmd : plan.index_writes) {
            (void)write(write_cmd);
        }
        (void)write(plan.ack);
    }

    auto read_range(const kythira::key_range& range, kythira::scan_direction direction,
                    bool consistent, const range_visitor& visit) -> void {
        read_pages(range, direction, consistent, false,
                   [&](std::string_view key, const item& it, const std::optional<replica_stamp>&) {
                       return visit(key, it);
                   });
    }

    /// `read_range` (consistent, forward) with each item's stamp (task 22).
    auto read_stamped_range(const kythira::key_range& range, const stamped_visitor& visit) -> void {
        read_pages(range, kythira::scan_direction::forward, true, true, visit);
    }

protected:
    void read_pages(const kythira::key_range& range, kythira::scan_direction direction,
                    bool consistent, bool stamped, const stamped_visitor& visit) {
        using raft_backend_detail::op_tag;
        const bool forward = direction == kythira::scan_direction::forward;
        auto remaining = range;
        const auto deadline = std::chrono::steady_clock::now() + self().options().deadline;
        while (!remaining.empty()) {
            const auto desc = self().edge_group(remaining, forward);
            if (!desc) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    throw std::runtime_error("raft_backend: no group owns part of the range");
                }
                std::this_thread::sleep_for(self().options().retry_backoff);
                continue;
            }
            std::string op(1, static_cast<char>(op_tag::page));
            detail::put_varint(op, static_cast<std::uint64_t>(desc->_group_id));
            raft_backend_detail::put_range(op, remaining);
            op.push_back(forward ? '\1' : '\0');
            op.push_back(consistent ? '\1' : '\0');
            if (stamped) {
                op.push_back('\1');
            }
            std::string answer;
            try {
                answer = self().run(op, desc, op_route{std::string(), consistent});
            } catch (const txn_stale_route&) {
                // A split or merge moved the range off the group resolved
                // above: resolve it again from the current map. Resending
                // the same op would only hear the same answer until the
                // deadline.
                if (std::chrono::steady_clock::now() >= deadline) {
                    throw std::runtime_error("raft_backend: the range kept moving");
                }
                std::this_thread::sleep_for(self().options().retry_backoff);
                continue;
            }
            const auto p = raft_backend_detail::decode_page(answer);
            if (!p) {
                throw std::runtime_error("raft_backend: unreadable page");
            }
            for (std::size_t i = 0; i < p->items.size(); ++i) {
                const auto& [key, it] = p->items[i];
                const std::optional<replica_stamp> none;
                const auto& s = i < p->stamps.size() ? p->stamps[i] : none;
                if (!visit(key, it, s)) {
                    return;
                }
            }
            if (p->more && !p->items.empty()) {
                const auto& last = p->items.back().first;
                if (forward) {
                    remaining.start = last + '\0';
                } else {
                    remaining.end = last;
                }
                continue;
            }
            // This group's part is done; go past it.
            if (forward) {
                if (!p->covered.end) {
                    return;
                }
                remaining.start = *p->covered.end;
            } else {
                if (p->covered.start <= remaining.start) {
                    return;
                }
                remaining.end = p->covered.start;
            }
        }
    }

public:
    auto describe(std::string_view name) -> std::optional<table_descriptor> {
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::describe));
        detail::put_bytes(op, name);
        const auto out = self().run(op, std::nullopt, catalog_route());
        if (out.empty()) {
            return std::nullopt;
        }
        auto d = decode_table_descriptor(out);
        if (!d) {
            throw std::runtime_error("raft_backend: unreadable table descriptor");
        }
        return d;
    }

    auto list_tables(std::string_view exclusive_start, std::size_t limit)
        -> std::vector<std::string> {
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::list));
        detail::put_bytes(op, exclusive_start);
        detail::put_varint(op, limit);
        const auto out = self().run(op, std::nullopt, catalog_route());
        detail::reader in(out);
        const auto n = in.count();
        if (!n) {
            throw std::runtime_error("raft_backend: unreadable table list");
        }
        std::vector<std::string> names;
        for (std::size_t i = 0; i < *n; ++i) {
            auto s = in.bytes();
            if (!s) {
                throw std::runtime_error("raft_backend: unreadable table list");
            }
            names.push_back(std::move(*s));
        }
        return names;
    }

    /// The change log streams of every item group overlapping `range`, as
    /// DynamoDB Streams shards (task 16), each once: the closed streams a
    /// split left are named by every child.
    auto change_shards(const kythira::key_range& range) -> std::vector<change_shard> {
        std::map<std::string, change_shard> by_key;
        for (const auto& desc : self().groups_in(range)) {
            std::string op(1, static_cast<char>(raft_backend_detail::op_tag::shards));
            detail::put_varint(op, static_cast<std::uint64_t>(desc._group_id));
            auto got = decode_change_shards(self().run(op, desc, op_route{}));
            if (!got) {
                throw std::runtime_error("raft_backend: unreadable change shards");
            }
            for (auto& s : *got) {
                auto [it, fresh] = by_key.try_emplace(s.stream.key, s);
                // Two children may have trimmed a shared parent unevenly:
                // keep the copy that still names the most.
                if (!fresh && !it->second.open && !s.open &&
                    s.stream.first_seq < it->second.stream.first_seq) {
                    it->second = std::move(s);
                }
            }
        }
        std::vector<change_shard> out;
        out.reserve(by_key.size());
        for (auto& [key, s] : by_key) {
            out.push_back(std::move(s));
        }
        return out;
    }

    /// Up to `max_records` records of change log stream `key` from
    /// `from_seq`, from the group that continues it (the one holding its
    /// range start), at that group's leader.
    auto read_changes(const std::string& key, std::uint64_t from_seq, std::size_t max_records)
        -> change_page {
        const auto parsed = parse_change_stream_key(key);
        if (!parsed) {
            return {};
        }
        const auto desc = self().group_of(parsed->first);
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::changes));
        detail::put_bytes(op, key);
        detail::put_varint(op, from_seq);
        detail::put_varint(op, max_records);
        auto p = decode_change_page(self().run(op, desc, op_route{parsed->first}));
        if (!p) {
            throw std::runtime_error("raft_backend: unreadable change page");
        }
        return std::move(*p);
    }

    auto transact(const std::vector<item_command>& actions) -> txn_report {
        kythira::transaction_coordinator<txn_client, std::string> coordinator(self().txn(),
                                                                              self().options().txn);
        std::vector<std::string> keys;
        keys.reserve(actions.size());
        coordinator.begin();
        for (const auto& a : actions) {
            auto key = base_item_key(a.table_id, a.schema, a.payload);
            if (!key) {
                throw std::invalid_argument("raft_backend: a transaction action without a key");
            }
            coordinator.put(*key, raft_backend_detail::to_bytes(
                                      encode_item_command(stamp_written(a, self().now_ms()))));
            keys.push_back(std::move(*key));
        }
        const auto out = coordinator.commit();
        txn_report r;
        r.results.resize(actions.size());
        r.conflicts.assign(actions.size(), false);
        const auto index_of = [&](const std::string& key) -> std::optional<std::size_t> {
            const auto it = std::find(keys.begin(), keys.end(), key);
            if (it == keys.end()) {
                return std::nullopt;
            }
            return static_cast<std::size_t>(it - keys.begin());
        };
        for (const auto& v : out._validations) {
            const auto i = index_of(v._key);
            if (!i || v._detail.empty()) {
                continue;
            }
            auto decoded = decode_item_result(raft_backend_detail::view(v._detail));
            if (!decoded) {
                throw std::runtime_error("raft_backend: unreadable validation detail");
            }
            r.results[*i] = std::move(*decoded);
        }
        switch (out._kind) {
            case kythira::txn_outcome_kind::committed:
                for (std::size_t i = 0; i < actions.size(); ++i) {
                    // A one-phase commit retried after a timeout is answered
                    // from memory, without the reads: never pass that off as
                    // items that are not there.
                    if (actions[i].op == item_command::kind::read_lock && !r.results[i]) {
                        throw std::runtime_error(
                            "raft_backend: a transaction read lost its result");
                    }
                }
                // commit() returns once the primary's group has committed;
                // the other groups' commits are still in flight. DynamoDB
                // promises every item is visible once TransactWriteItems
                // returns, and a consistent read serves the leader's applied
                // state without looking at intents, so wait for them here.
                // Without this a GetItem straight after the call could still
                // see the old value of an item in another group.
                coordinator.drain();
                return r;
            case kythira::txn_outcome_kind::unknown:
                throw std::runtime_error("raft_backend: transaction outcome unknown: " +
                                         out._detail);
            case kythira::txn_outcome_kind::aborted:
                break;
        }
        switch (out._reason) {
            case kythira::txn_abort_reason::validation_failed:
                r.outcome = txn_report::status::cancelled;
                return r;
            case kythira::txn_abort_reason::write_conflict:
                r.outcome = txn_report::status::cancelled;
                if (out._conflict_key) {
                    if (const auto i = index_of(*out._conflict_key)) {
                        r.conflicts[*i] = true;
                    }
                }
                return r;
            default:
                throw std::runtime_error("raft_backend: transaction aborted (" +
                                         std::to_string(static_cast<int>(out._reason)) + ") " +
                                         out._detail);
        }
    }

protected:
    op_client() = default;

    [[nodiscard]] auto self() -> Derived& { return static_cast<Derived&>(*this); }

    /// The catalog ops' route: the catalog group's leader.
    [[nodiscard]] static auto catalog_route() -> op_route {
        return op_route{std::string(k_catalog_prefix)};
    }

    /// The coordinator's way to the groups: every envelope is a txn op.
    class txn_client {
    public:
        using group_id_type = std::remove_cvref_t<decltype(std::declval<Descriptor>()._group_id)>;
        using send_future = kythira::future_default<std::vector<std::byte>>;

        explicit txn_client(op_client& backend) : _backend(backend) {}
        txn_client(const txn_client&) = delete;
        auto operator=(const txn_client&) -> txn_client& = delete;
        txn_client(txn_client&&) = delete;
        auto operator=(txn_client&&) -> txn_client& = delete;

        ~txn_client() {
            const std::lock_guard lock(_mu);
            for (auto& s : _senders) {
                s.thread.join();
            }
        }

        [[nodiscard]] auto resolve(const std::string& key) -> std::optional<group_id_type> {
            const auto desc = _backend.self().group_of(key);
            if (!desc) {
                return std::nullopt;
            }
            return desc->_group_id;
        }

        /// Each send runs on a thread of its own, so the coordinator's
        /// prepares to several groups are in flight together.
        [[nodiscard]] auto send(const std::vector<std::string>& keys,
                                const std::vector<std::byte>& envelope, std::chrono::milliseconds)
            -> send_future {
            kythira::promise_default<std::vector<std::byte>> promise;
            auto result = promise.getFuture();
            const std::lock_guard lock(_mu);
            reap();
            auto& s = _senders.emplace_back();
            s.done = std::make_shared<std::atomic<bool>>(false);
            s.thread = std::thread(
                [this, keys, envelope, promise = std::move(promise), done = s.done]() mutable {
                    try {
                        promise.setValue(_backend.send_txn(keys, envelope));
                    } catch (...) {
                        promise.setException(std::current_exception());
                    }
                    done->store(true);
                });
            return result;
        }

        [[nodiscard]] auto refresh(std::exception_ptr error) -> bool {
            try {
                std::rethrow_exception(std::move(error));
            } catch (const txn_stale_route&) {
                // This node's routing map catches up as its replicas apply
                // the split or merge.
                std::this_thread::sleep_for(_backend.self().options().retry_backoff);
                return true;
            } catch (...) {
                return false;
            }
        }

        /// Transactions here read through `validate` (a `read_lock`), never
        /// through the coordinator's `get`.
        [[nodiscard]] auto read(const std::string&, std::chrono::milliseconds)
            -> kythira::txn_read_result<std::string> {
            throw std::logic_error("raft_backend: transaction reads go through read_lock");
        }

        [[nodiscard]] auto now_ms() const -> std::uint64_t { return _backend.self().txn_now_ms(); }

    private:
        struct sender {
            std::thread thread;
            std::shared_ptr<std::atomic<bool>> done;
        };

        auto reap() -> void {
            for (auto it = _senders.begin(); it != _senders.end();) {
                if (it->done->load()) {
                    it->thread.join();
                    it = _senders.erase(it);
                } else {
                    ++it;
                }
            }
        }

        op_client& _backend;
        std::mutex _mu;
        std::list<sender> _senders;
    };
    static_assert(kythira::txn_participant_client<txn_client, std::string>);

    /// Runs one envelope on the group owning `keys` and returns the encoded
    /// `txn_result`. Throws `txn_stale_route` when the keys span groups now.
    auto send_txn(const std::vector<std::string>& keys, const std::vector<std::byte>& envelope)
        -> std::vector<std::byte> {
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::txn));
        detail::put_varint(op, keys.size());
        for (const auto& k : keys) {
            detail::put_bytes(op, k);
        }
        detail::put_bytes(op, raft_backend_detail::view(envelope));
        return raft_backend_detail::to_bytes(
            self().run(op, std::nullopt, op_route{keys.empty() ? std::string() : keys.front()}));
    }

    [[nodiscard]] static auto item_answer(const std::string& out) -> item_result {
        auto r = decode_item_result(out);
        if (!r) {
            throw std::runtime_error("raft_backend: unreadable item result");
        }
        return *r;
    }
};

}  // namespace kythira::dynamodb
