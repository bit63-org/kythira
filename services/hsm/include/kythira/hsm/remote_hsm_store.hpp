// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// hsm_store for a crypto node that is not a member of the HSM's groups
// (.kiro/specs/hsm-independent-layers/ task 3, Requirements 3 and 4).
//
// A co-located node reads its own replica, which lags the leader by at
// most what the next read barrier catches up. A crypto-only node has no
// replica, so it keeps a mirror instead and fills it from the store API
// (store_api.hpp) on store members:
//
//  - Reads. Each read answers from the mirror, as a co-located read answers
//    from a replica that may lag. A part of the mirror never fetched,
//    marked stale by a proposal of this node (so a caller reads its own
//    writes), or older than `mirror_ttl` is fetched first, so the mirror
//    lags the store by about what a follower's replica lags its leader,
//    not without bound. A fetch that fails leaves the old mirror in place,
//    exactly like a replica that has not caught up.
//  - Read barriers. read_barrier(token) is a store read of the token: the
//    store member runs a read-index round on the catalog and on the token
//    group and answers what it then holds. The mirror sends the (handle,
//    version) pairs it already has and gets back only the objects that
//    are new or changed, so each wrapped object crosses the network once
//    per version (Requirement 3.4). A barrier that cannot be had answers
//    CKR_DEVICE_ERROR (Requirement 4.3); a token that was deleted answers
//    it too, as a co-located barrier on a destroyed group does once its
//    timeout passes.
//  - Seal state. Every store answer carries the catalog record the member
//    had after its catalog barrier. Before the answer is used, the vault
//    is checked against it (key_vault::enforce): a seal or a rekey
//    committed since this node unsealed seals it, the on_seal callback
//    drops what was opened with it, and the call answers CKR_DEVICE_ERROR
//    (Requirement 4.2, design "Seal state rides on every barrier"). The
//    watch thread (start()) also fetches the catalog every maintenance
//    interval, so an idle crypto node drops its keys after a `seal`
//    without waiting for a call (Requirement 4.4).
//  - Proposals. Sent to the group's leader: the store member answers
//    not_leader with a hint and never forwards further, and the mirror
//    tries the hinted member (url_of) or the next one until the timeout
//    (Requirement 3.2). Any other failure may have committed, so it answers
//    CKR_DEVICE_ERROR rather than risk applying a login failure twice, as a
//    co-located member does. A proposal that succeeds marks the group's
//    mirror stale, so the next read fetches it.
//
// The transport is a store_link: two calls, in production a peer_client
// over mutual TLS (make_store_link), in the tests direct calls into store
// members' serve_peer.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/hsm_peer.hpp>
#include <kythira/hsm/hsm_store.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/store_api.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace kythira::hsm {

/// How a crypto node reaches store members. Each call blocks; a transport
/// failure answers `unavailable` (propose) or nothing (read).
struct store_link {
    std::function<forward_reply<std::string>(std::string_view url, std::uint64_t group,
                                             const std::vector<std::byte>& command)>
        propose;
    std::function<std::optional<std::string>(std::string_view url, std::uint64_t group,
                                             std::string request)>
        read;
};

/// A store_link over `client` (mutual TLS to the members' listeners).
/// `client` must outlive the link.
[[nodiscard]] inline auto make_store_link(const peer_client& client) -> store_link {
    store_link link;
    link.propose = [&client](std::string_view url, std::uint64_t group,
                             const std::vector<std::byte>& command) {
        return client.propose(url, group, command);
    };
    link.read = [&client](std::string_view url, std::uint64_t group, std::string request) {
        return client.store_read(url, group, std::move(request));
    };
    return link;
}

struct remote_store_options {
    /// The store members' listeners ("https://host:port"), tried in turn.
    std::vector<std::string> store_urls;
    /// The listener of a leader named in a not_leader hint (its node id as
    /// text), or nothing when it is not known.
    std::function<std::optional<std::string>(std::string_view leader)> url_of;
    /// The whole budget of one read, barrier or proposal.
    std::chrono::milliseconds timeout{5000};
    /// Pause between watch passes (the seal state's bound while idle).
    std::chrono::milliseconds maintenance_interval{200};
    /// Pause between attempts.
    std::chrono::milliseconds retry_interval{20};
    /// How long a fetched part of the mirror is read without fetching it
    /// again (a follower's replica lags its leader by about a heartbeat).
    std::chrono::milliseconds mirror_ttl{100};
};

/// Counters for the module's metrics and the tests.
struct remote_store_stats {
    std::uint64_t reads = 0;
    std::uint64_t read_failures = 0;
    std::uint64_t proposals = 0;
    std::uint64_t proposals_redirected = 0;
    /// Wrapped objects fetched, and held ones a token read did not resend.
    std::uint64_t objects_fetched = 0;
    std::uint64_t objects_reused = 0;
    /// Times a store answer's seal state sealed this node.
    std::uint64_t seals_enforced = 0;
};

class remote_hsm_store final : public hsm_store {
public:
    /// `vault`, when given, is checked against the seal state of every
    /// answer; it must outlive the store.
    remote_hsm_store(store_link link, remote_store_options options, key_vault* vault = nullptr)
        : _link(std::move(link)), _opts(std::move(options)), _vault(vault) {
        if (_opts.store_urls.empty()) {
            throw std::invalid_argument("remote_hsm_store: no store members");
        }
    }

    remote_hsm_store(const remote_hsm_store&) = delete;
    auto operator=(const remote_hsm_store&) -> remote_hsm_store& = delete;
    remote_hsm_store(remote_hsm_store&&) = delete;
    auto operator=(remote_hsm_store&&) -> remote_hsm_store& = delete;

    ~remote_hsm_store() override { stop(); }

    /// Called whenever a store answer sealed the vault, after it sealed:
    /// the module passes session_layer::seal, which also drops the key
    /// cache and every session's login.
    auto set_on_seal(std::function<void()> on_seal) -> void {
        const std::lock_guard lock(_mutex);
        _on_seal = std::move(on_seal);
    }

    /// Start the watch thread (Requirement 4.4).
    auto start() -> void {
        const std::lock_guard lock(_run_mutex);
        if (_worker.joinable()) {
            return;
        }
        _stopping = false;
        _worker = std::thread([this] { watch_loop(); });
    }

    auto stop() -> void {
        {
            const std::lock_guard lock(_run_mutex);
            _stopping = true;
        }
        _run_cv.notify_all();
        if (_worker.joinable()) {
            _worker.join();
        }
    }

    /// Fetch the catalog now (the watch does this every pass).
    auto refresh_catalog() const -> ck_result<void> {
        auto answer = read(0, store_read_request{});
        if (!answer) {
            return unexpected(answer.error());
        }
        const std::lock_guard lock(_mutex);
        _catalog = std::move(answer->catalog);
        _catalog_stale = false;
        _catalog_fetched = clock::now();
        return {};
    }

    [[nodiscard]] auto stats() const -> remote_store_stats {
        const std::lock_guard lock(_mutex);
        return _stats;
    }

    // -- hsm_store: reads of the mirror --------------------------------------

    [[nodiscard]] auto catalog() const -> std::optional<catalog_record> override {
        ensure_catalog();
        const std::lock_guard lock(_mutex);
        return _catalog ? _catalog->record : std::nullopt;
    }

    [[nodiscard]] auto tokens() const -> std::vector<token_entry> override {
        ensure_catalog();
        const std::lock_guard lock(_mutex);
        return _catalog ? _catalog->tokens : std::vector<token_entry>{};
    }

    [[nodiscard]] auto token(std::uint64_t token_id) const -> std::optional<token_entry> override {
        ensure_catalog();
        const std::lock_guard lock(_mutex);
        return token_locked(token_id);
    }

    [[nodiscard]] auto may_open(std::string_view identity, std::uint64_t token_id) const
        -> bool override {
        ensure_catalog();
        const std::lock_guard lock(_mutex);
        if (!_catalog) {
            return false;
        }
        for (const auto& [who, t] : _catalog->bindings) {
            if (t == token_id && who == identity) {
                return true;
            }
        }
        return false;
    }

    /// A crypto-only node hosts no group; it serves every token the
    /// catalog names.
    [[nodiscard]] auto hosts(std::uint64_t token_id) const -> bool override {
        return token(token_id).has_value();
    }

    [[nodiscard]] auto token_record_of(std::uint64_t token_id) const
        -> std::optional<token_record> override {
        ensure_token(token_id);
        const std::lock_guard lock(_mutex);
        const auto it = _tokens.find(token_id);
        return it == _tokens.end() ? std::nullopt : it->second.record;
    }

    [[nodiscard]] auto object(std::uint64_t token_id, std::uint64_t handle) const
        -> std::optional<object_record> override {
        ensure_token(token_id);
        const std::lock_guard lock(_mutex);
        const auto it = _tokens.find(token_id);
        if (it == _tokens.end()) {
            return std::nullopt;
        }
        const auto o = it->second.objects.find(handle);
        return o == it->second.objects.end() ? std::nullopt : std::optional(o->second);
    }

    [[nodiscard]] auto objects(std::uint64_t token_id) const
        -> std::vector<object_record> override {
        ensure_token(token_id);
        const std::lock_guard lock(_mutex);
        std::vector<object_record> out;
        if (const auto it = _tokens.find(token_id); it != _tokens.end()) {
            for (const auto& [h, o] : it->second.objects) {
                out.push_back(o);
            }
        }
        return out;
    }

    // -- hsm_store: writes and barriers --------------------------------------

    auto propose_catalog(std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> override {
        return propose(0, command);
    }

    auto propose_token(std::uint64_t token_id, std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> override {
        if (token_id == 0) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        return propose(token_id, command);
    }

    auto read_barrier(std::uint64_t token_id) -> ck_result<void> override {
        if (token_id == 0) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        return fetch_token(token_id);
    }

private:
    using clock = std::chrono::steady_clock;

    struct token_mirror {
        bool stale = false;
        clock::time_point fetched{};
        std::optional<token_record> record;
        std::map<std::uint64_t, object_record> objects;
    };

    [[nodiscard]] auto token_locked(std::uint64_t token_id) const -> std::optional<token_entry> {
        if (!_catalog) {
            return std::nullopt;
        }
        for (const auto& t : _catalog->tokens) {
            if (t.token_id == token_id) {
                return t;
            }
        }
        return std::nullopt;
    }

    /// Fetch the catalog if it was never fetched or is stale; a failure
    /// keeps the mirror as it is (a replica that has not caught up).
    auto ensure_catalog() const -> void {
        {
            const std::lock_guard lock(_mutex);
            if (_catalog && !_catalog_stale && clock::now() - _catalog_fetched < _opts.mirror_ttl) {
                return;
            }
        }
        std::ignore = refresh_catalog();
    }

    auto ensure_token(std::uint64_t token_id) const -> void {
        {
            const std::lock_guard lock(_mutex);
            const auto it = _tokens.find(token_id);
            if (it != _tokens.end() && !it->second.stale &&
                clock::now() - it->second.fetched < _opts.mirror_ttl) {
                return;
            }
        }
        std::ignore = fetch_token(token_id);
    }

    /// A store read of `token_id`: the barrier, then the mirror updated.
    auto fetch_token(std::uint64_t token_id) const -> ck_result<void> {
        // Twice at most: a concurrent fetch can replace a held object
        // between building the request and merging the answer, and the
        // second round then asks for everything.
        for (int attempt = 0; attempt < 2; ++attempt) {
            store_read_request request;
            if (attempt == 0) {
                const std::lock_guard lock(_mutex);
                if (const auto it = _tokens.find(token_id); it != _tokens.end()) {
                    for (const auto& [h, o] : it->second.objects) {
                        request.have.push_back({h, o.version});
                    }
                }
            }
            auto answer = read(token_id, request);
            if (!answer) {
                return unexpected(answer.error());
            }
            const std::lock_guard lock(_mutex);
            if (answer->status == store_read_status::absent) {
                _tokens.erase(token_id);
                _catalog_stale = true;  // the catalog no longer names it
                return unexpected(CKR_DEVICE_ERROR);
            }
            auto& mirror = _tokens[token_id];
            std::map<std::uint64_t, object_record> next;
            std::map<std::uint64_t, object_record> changed;
            for (auto& o : answer->token.changed) {
                const auto h = o.handle;
                changed.emplace(h, std::move(o));
            }
            bool complete = true;
            std::uint64_t reused = 0;
            for (const auto& l : answer->token.live) {
                if (auto c = changed.find(l.handle); c != changed.end()) {
                    next.emplace(l.handle, std::move(c->second));
                    continue;
                }
                const auto held = mirror.objects.find(l.handle);
                if (held == mirror.objects.end() || held->second.version != l.version) {
                    complete = false;
                    break;
                }
                next.emplace(l.handle, held->second);
                ++reused;
            }
            if (!complete) {
                continue;
            }
            _stats.objects_fetched += changed.size();
            _stats.objects_reused += reused;
            mirror.record = std::move(answer->token.record);
            mirror.objects = std::move(next);
            mirror.stale = false;
            mirror.fetched = clock::now();
            return {};
        }
        return unexpected(CKR_DEVICE_ERROR);
    }

    /// One store read of local group `group`, from any store member, with
    /// the seal state checked before the answer is used.
    auto read(std::uint64_t group, const store_read_request& request) const
        -> ck_result<store_read_answer> {
        const auto body = request.encode();
        const auto deadline = clock::now() + _opts.timeout;
        for (;;) {
            const auto url = current_url();
            std::optional<std::string> raw;
            try {
                raw = _link.read(url, group, body);
            } catch (const std::exception&) {
                raw.reset();
            }
            if (raw) {
                auto answer = decode_store_read_answer(*raw);
                if (answer.status != store_read_status::unavailable) {
                    count(&remote_store_stats::reads);
                    if (seal_state_sealed(answer.seal_state)) {
                        return unexpected(CKR_DEVICE_ERROR);
                    }
                    return answer;
                }
            }
            count(&remote_store_stats::read_failures);
            next_url(url);
            if (clock::now() + _opts.retry_interval >= deadline) {
                return unexpected(CKR_DEVICE_ERROR);
            }
            std::this_thread::sleep_for(_opts.retry_interval);
        }
    }

    /// Checks the vault against `seal_state`; true when it sealed the
    /// node. Also marks the catalog stale when its record moved on (a
    /// rekey replaces every sealed token key).
    auto seal_state_sealed(const std::optional<catalog_record>& seal_state) const -> bool {
        std::function<void()> on_seal;
        {
            const std::lock_guard lock(_mutex);
            const auto held = _catalog ? _catalog->record : std::nullopt;
            if (held.has_value() != seal_state.has_value() ||
                (held && (held->generation != seal_state->generation ||
                          held->seal_epoch != seal_state->seal_epoch ||
                          held->mk_check != seal_state->mk_check))) {
                _catalog_stale = true;
            }
            on_seal = _on_seal;
        }
        if (_vault == nullptr || !_vault->enforce(seal_state)) {
            return false;
        }
        count(&remote_store_stats::seals_enforced);
        if (on_seal) {
            on_seal();
        }
        return true;
    }

    /// Propose `command` to local group `group` through its leader.
    auto propose(std::uint64_t group, const std::vector<std::byte>& command)
        -> ck_result<std::vector<std::byte>> {
        using status = forward_reply<std::string>::status;
        count(&remote_store_stats::proposals);
        const auto deadline = clock::now() + _opts.timeout;
        std::string url = leader_url(group);
        for (;;) {
            forward_reply<std::string> r;
            try {
                r = _link.propose(url, group, command);
            } catch (const std::exception&) {
                r = {};  // unavailable
            }
            if (r.result == status::ok) {
                mark_stale(group);
                return std::move(r.reply);
            }
            if (r.result == status::unavailable) {
                // It may have committed: never retried. The next call
                // starts from another member.
                forget_leader(group);
                next_url(url);
                mark_stale(group);
                return unexpected(CKR_DEVICE_ERROR);
            }
            // not_leader: nothing was submitted, so try the hinted member
            // or the next one.
            count(&remote_store_stats::proposals_redirected);
            std::optional<std::string> hinted;
            if (r.leader && _opts.url_of) {
                hinted = _opts.url_of(*r.leader);
            }
            if (hinted && *hinted != url) {
                url = *hinted;
                remember_leader(group, url);
            } else {
                forget_leader(group);
                url = following(url);
            }
            if (clock::now() + _opts.retry_interval >= deadline) {
                return unexpected(CKR_DEVICE_ERROR);
            }
            std::this_thread::sleep_for(_opts.retry_interval);
        }
    }

    auto mark_stale(std::uint64_t group) const -> void {
        const std::lock_guard lock(_mutex);
        if (group == 0) {
            _catalog_stale = true;
        } else if (const auto it = _tokens.find(group); it != _tokens.end()) {
            it->second.stale = true;
        }
    }

    [[nodiscard]] auto current_url() const -> std::string {
        const std::lock_guard lock(_mutex);
        return _opts.store_urls.at(_preferred % _opts.store_urls.size());
    }

    /// The member after `url` in the list.
    [[nodiscard]] auto following(const std::string& url) const -> std::string {
        const auto& urls = _opts.store_urls;
        for (std::size_t i = 0; i < urls.size(); ++i) {
            if (urls[i] == url) {
                return urls[(i + 1) % urls.size()];
            }
        }
        return urls.front();
    }

    /// Move the preferred member past `url`, unless another call did.
    auto next_url(const std::string& url) const -> void {
        const std::lock_guard lock(_mutex);
        if (_opts.store_urls.at(_preferred % _opts.store_urls.size()) == url) {
            _preferred = (_preferred + 1) % _opts.store_urls.size();
        }
    }

    [[nodiscard]] auto leader_url(std::uint64_t group) const -> std::string {
        {
            const std::lock_guard lock(_mutex);
            if (const auto it = _leaders.find(group); it != _leaders.end()) {
                return it->second;
            }
        }
        return current_url();
    }

    auto remember_leader(std::uint64_t group, const std::string& url) const -> void {
        const std::lock_guard lock(_mutex);
        _leaders[group] = url;
    }

    auto forget_leader(std::uint64_t group) const -> void {
        const std::lock_guard lock(_mutex);
        _leaders.erase(group);
    }

    auto count(std::uint64_t remote_store_stats::* field) const -> void {
        const std::lock_guard lock(_mutex);
        ++(_stats.*field);
    }

    auto watch_loop() -> void {
        std::unique_lock lock(_run_mutex);
        while (!_stopping) {
            lock.unlock();
            try {
                std::ignore = refresh_catalog();
            } catch (const std::exception&) {
                // A malformed answer or a callback that threw: next pass.
            }
            lock.lock();
            _run_cv.wait_for(lock, _opts.maintenance_interval, [this] { return _stopping; });
        }
    }

    store_link _link;
    remote_store_options _opts;
    key_vault* _vault;

    // The mirror is what a co-located node's replica is: reads fill it.
    mutable std::mutex _mutex;
    mutable std::optional<catalog_view> _catalog;
    mutable bool _catalog_stale = true;
    mutable clock::time_point _catalog_fetched{};
    mutable std::map<std::uint64_t, token_mirror> _tokens;
    mutable std::map<std::uint64_t, std::string> _leaders;
    mutable std::size_t _preferred = 0;
    std::function<void()> _on_seal;
    mutable remote_store_stats _stats;

    std::mutex _run_mutex;
    std::condition_variable _run_cv;
    bool _stopping = false;
    std::thread _worker;
};

}  // namespace kythira::hsm
