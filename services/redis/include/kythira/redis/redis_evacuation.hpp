// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_evacuation.hpp
/// @brief `KYTHIRA.EVACUATE`: moving every replica a data node holds onto
///        other data nodes before it loses the `data` role
///        (.kiro/specs/redis-general-data-types/ task 19, Requirement 21.3).
///
/// The moves are the shared `replica_evacuator`'s (raft/replica_evacuation.hpp):
/// add a target as a learner, let it catch up, promote it, hand leadership
/// away if the evacuee leads, remove the evacuee. Each data node runs the
/// same job and acts on the groups it leads, so the command fans out to
/// every data node the one that took it knows (`KYTHIRA_REDIS_PEER_GATEWAYS`
/// plus any it learned from the command), over the forward link as the
/// internal identity.
///
/// Sub-commands (the gateway lets admins and internal callers in):
///
/// - `START <node> [TO <id>...] [REPLICAS <n>] [ADDRESS <id> <raft-url> <gateway>]... [LOCAL]`
///   evacuates `<node>`. Without `TO`, every other data node this node knows
///   is a target; `ADDRESS` makes a target reachable (its Raft URL and the
///   `host:port` of its gateway) for a node that was not in the settings.
///   `LOCAL` is the fanned-out form: start here only.
/// - `STATUS [LOCAL]`: every data node's view merged (`done` once every
///   group any node holds is led by a node that reports it done), or this
///   node's own, as one bulk string for the merge.
/// - `CANCEL [LOCAL]`: stops the job everywhere (or here).
/// - `RELEASE`: on the evacuee, once the merged status is done and every
///   data node runs a job evacuating it, marks it released, so a restart
///   without `data` may discard its stale replicas.
/// - `DESCRIPTOR <group>` (internal): this node's live descriptor of a
///   group it holds, for a joining node's lazy replica creation.
///
/// A target learns a group it is being added to from a peer's `DESCRIPTOR`
/// answer (`lookup_descriptor`), which lists it as a learner as soon as the
/// leader has started the change.

#include <kythira/redis/redis_admin_answer.hpp>
#include <kythira/redis/redis_data_wire.hpp>

#include <raft/composite_node_id.hpp>
#include <raft/replica_evacuation.hpp>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::redis_evacuation {

/// Where a target is reached, for a node that did not have it in its
/// settings.
struct target_address {
    std::string _id;
    std::string _raft;
    std::string _gateway;

    [[nodiscard]] auto operator==(const target_address&) const -> bool = default;
};

/// A parsed `START`.
struct start_request {
    std::string _node;
    std::vector<std::string> _targets;
    std::size_t _replicas = 0;
    std::vector<target_address> _addresses;
    bool _local = false;

    [[nodiscard]] auto operator==(const start_request&) const -> bool = default;
};

namespace detail {

[[nodiscard]] inline auto upper(std::string_view s) -> std::string {
    std::string out(s);
    for (auto& c : out) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
    }
    return out;
}

/// One line of a status: no newline may split it.
[[nodiscard]] inline auto one_line(std::string s) -> std::string {
    std::replace(s.begin(), s.end(), '\n', ' ');
    std::replace(s.begin(), s.end(), '\r', ' ');
    return s;
}

[[nodiscard]] inline auto split_words(std::string_view line) -> std::vector<std::string> {
    std::vector<std::string> out;
    std::istringstream in{std::string(line)};
    std::string w;
    while (in >> w) {
        out.push_back(w);
    }
    return out;
}

/// The payload of one RESP bulk string reply, or nullopt for anything else.
[[nodiscard]] inline auto bulk_payload(std::string_view reply) -> std::optional<std::string_view> {
    if (reply.size() < 4 || reply.front() != '$') {
        return std::nullopt;
    }
    const auto eol = reply.find("\r\n");
    if (eol == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t n = 0;
    const auto* first = reply.data() + 1;
    const auto* last = reply.data() + eol;
    const auto [end, ec] = std::from_chars(first, last, n);
    if (ec != std::errc{} || end != last || reply.size() != eol + 2 + n + 2 ||
        reply.substr(eol + 2 + n) != "\r\n") {
        return std::nullopt;
    }
    return reply.substr(eol + 2, n);
}

}  // namespace detail

/// `START`'s arguments (the words after `START`), or nullopt with `why`.
[[nodiscard]] inline auto parse_start(const std::vector<std::string>& args, std::string& why)
    -> std::optional<start_request> {
    if (args.empty() || args.front().empty()) {
        why = "START needs the node to evacuate";
        return std::nullopt;
    }
    start_request r;
    r._node = args.front();
    std::size_t i = 1;
    while (i < args.size()) {
        const auto word = detail::upper(args[i]);
        if (word == "LOCAL") {
            r._local = true;
            ++i;
        } else if (word == "REPLICAS") {
            if (i + 1 >= args.size()) {
                why = "REPLICAS needs a number";
                return std::nullopt;
            }
            const auto& n = args[i + 1];
            std::size_t v = 0;
            const auto [end, ec] = std::from_chars(n.data(), n.data() + n.size(), v);
            if (ec != std::errc{} || end != n.data() + n.size() || v == 0 || v > 64) {
                why = "REPLICAS must be a number from 1 to 64";
                return std::nullopt;
            }
            r._replicas = v;
            i += 2;
        } else if (word == "ADDRESS") {
            if (i + 3 >= args.size()) {
                why = "ADDRESS needs <id> <raft-url> <gateway host:port>";
                return std::nullopt;
            }
            r._addresses.push_back(target_address{args[i + 1], args[i + 2], args[i + 3]});
            i += 4;
        } else if (word == "TO") {
            ++i;
            const auto before = r._targets.size();
            while (i < args.size()) {
                const auto next = detail::upper(args[i]);
                if (next == "LOCAL" || next == "REPLICAS" || next == "ADDRESS" || next == "TO") {
                    break;
                }
                if (args[i] == r._node) {
                    why = "the evacuee cannot be its own target";
                    return std::nullopt;
                }
                if (std::find(r._targets.begin(), r._targets.end(), args[i]) == r._targets.end()) {
                    r._targets.push_back(args[i]);
                }
                ++i;
            }
            if (r._targets.size() == before) {
                why = "TO needs at least one target";
                return std::nullopt;
            }
        } else {
            why = "unknown START option '" + args[i] + "'";
            return std::nullopt;
        }
    }
    return r;
}

/// The command a node fans `r` out with: the same job, started there only.
[[nodiscard]] inline auto to_argv(const start_request& r) -> std::vector<std::string> {
    std::vector<std::string> out{"KYTHIRA.EVACUATE", "START", r._node};
    if (!r._targets.empty()) {
        out.emplace_back("TO");
        out.insert(out.end(), r._targets.begin(), r._targets.end());
    }
    if (r._replicas != 0) {
        out.emplace_back("REPLICAS");
        out.push_back(std::to_string(r._replicas));
    }
    for (const auto& a : r._addresses) {
        out.insert(out.end(), {"ADDRESS", a._id, a._raft, a._gateway});
    }
    out.emplace_back("LOCAL");
    return out;
}

/// One group a node leads, with the step it took or waits on.
struct led_group {
    std::string _group;
    std::string _action;
    std::string _node;
    std::string _error;

    [[nodiscard]] auto operator==(const led_group&) const -> bool = default;
};

/// One data node's view of the job (`STATUS LOCAL`).
struct node_view {
    std::string _node;
    bool _running = false;
    std::string _evacuee;
    std::vector<std::string> _held;
    std::vector<led_group> _led;
    /// The voters and learners of the groups this node leads: the nodes
    /// the job still depends on. A node in none of them may be down (a
    /// failed evacuee once removed, a data node never added) without
    /// holding the merge back.
    std::vector<std::string> _members;
    /// Set by the merge for a peer that did not answer: its id and
    /// gateway, as `id@host:port`.
    std::string _unreachable;

    [[nodiscard]] auto done() const -> bool {
        return std::all_of(_led.begin(), _led.end(),
                           [](const auto& g) { return g._action == "done"; });
    }
    [[nodiscard]] auto operator==(const node_view&) const -> bool = default;
};

/// `STATUS LOCAL`'s bulk string: a header line, the held groups, the
/// members of the led groups, then one line per led group. Ids, group numbers and action names have
/// no spaces; an error, last on its line, may.
[[nodiscard]] inline auto encode_node_view(const node_view& v) -> std::string {
    std::string out = "node " + v._node + " running " + (v._running ? "1" : "0") + " evacuee " +
                      (v._evacuee.empty() ? "-" : v._evacuee) + "\nheld";
    for (const auto& g : v._held) {
        out += " " + g;
    }
    out += "\nmembers";
    for (const auto& m : v._members) {
        out += " " + m;
    }
    for (const auto& g : v._led) {
        out += "\nled " + g._group + " " + g._action + " " + (g._node.empty() ? "-" : g._node);
        if (!g._error.empty()) {
            out += " " + detail::one_line(g._error);
        }
    }
    return out;
}

[[nodiscard]] inline auto decode_node_view(std::string_view text) -> std::optional<node_view> {
    std::vector<std::string_view> lines;
    for (;;) {
        const auto nl = text.find('\n');
        lines.push_back(text.substr(0, nl));
        if (nl == std::string_view::npos) {
            break;
        }
        text.remove_prefix(nl + 1);
    }
    if (lines.size() < 2) {
        return std::nullopt;
    }
    node_view v;
    for (std::size_t line_no = 0; line_no < lines.size(); ++line_no) {
        const auto line = lines[line_no];
        const auto w = detail::split_words(line);
        if (line_no == 0) {
            if (w.size() != 6 || w[0] != "node" || w[2] != "running" || w[4] != "evacuee" ||
                (w[3] != "0" && w[3] != "1")) {
                return std::nullopt;
            }
            v._node = w[1];
            v._running = w[3] == "1";
            v._evacuee = w[5] == "-" ? std::string{} : w[5];
        } else if (line_no == 1) {
            if (w.empty() || w[0] != "held") {
                return std::nullopt;
            }
            v._held.assign(w.begin() + 1, w.end());
        } else if (!w.empty() && w[0] == "members") {
            v._members.assign(w.begin() + 1, w.end());
        } else {
            if (w.size() < 4 || w[0] != "led") {
                return std::nullopt;
            }
            led_group g{w[1], w[2], w[3] == "-" ? std::string{} : w[3], {}};
            // The error is the rest of the line, spaces kept.
            std::size_t pos = 0;
            for (int i = 0; i < 4; ++i) {
                pos = line.find_first_not_of(' ', pos);
                pos = line.find(' ', pos);
            }
            if (pos != std::string_view::npos) {
                g._error = std::string(line.substr(pos + 1));
            }
            v._led.push_back(std::move(g));
        }
    }
    return v;
}

/// Every data node's view, merged.
struct cluster_view {
    bool _done = false;
    std::vector<node_view> _nodes;
};

/// The id half of an unreachable peer's `id@host:port`.
[[nodiscard]] inline auto unreachable_id(const node_view& v) -> std::string {
    return v._unreachable.substr(0, v._unreachable.find('@'));
}

/// Done once some node holds a group, every group any node holds is led by
/// a node that reports it done, and every node that did not answer is a
/// member of no led group. That last part lets a failed node be evacuated:
/// it never answers, and once the groups have removed it nothing waits on
/// it. A node that did not answer and is still a member may still lead
/// or hold something nobody else reports, so the merge is not done.
[[nodiscard]] inline auto merge(std::vector<node_view> views) -> cluster_view {
    cluster_view out;
    std::set<std::string> held;
    std::set<std::string> members;
    std::map<std::string, bool> led_done;
    for (const auto& v : views) {
        if (!v._unreachable.empty()) {
            continue;
        }
        held.insert(v._held.begin(), v._held.end());
        members.insert(v._members.begin(), v._members.end());
        for (const auto& g : v._led) {
            led_done[g._group] = g._action == "done";
        }
    }
    const bool reachable = std::none_of(views.begin(), views.end(), [&](const node_view& v) {
        return !v._unreachable.empty() && members.contains(unreachable_id(v));
    });
    out._done = reachable && !held.empty();
    for (const auto& g : held) {
        const auto it = led_done.find(g);
        out._done = out._done && it != led_done.end() && it->second;
    }
    out._nodes = std::move(views);
    return out;
}

/// Whether `self` may call itself released: the merge is done and every
/// node that answered runs a job evacuating it.
[[nodiscard]] inline auto released(const cluster_view& c, const std::string& self) -> bool {
    if (!c._done) {
        return false;
    }
    // A node the merge let be down (a member of no group) has no say.
    return std::all_of(c._nodes.begin(), c._nodes.end(), [&](const node_view& v) {
        return !v._unreachable.empty() || (v._running && v._evacuee == self);
    });
}

/// The operator's `STATUS`: one line per node and per led group.
[[nodiscard]] inline auto status_lines(const cluster_view& c) -> std::vector<std::string> {
    std::vector<std::string> out{std::string("done ") + (c._done ? "1" : "0")};
    for (const auto& v : c._nodes) {
        if (!v._unreachable.empty()) {
            out.push_back("node " + v._unreachable + " unreachable");
            continue;
        }
        std::string line = "node " + v._node + " running " + (v._running ? "1" : "0") +
                           " evacuee " + (v._evacuee.empty() ? "-" : v._evacuee) + " held " +
                           std::to_string(v._held.size()) + " led " +
                           std::to_string(v._led.size()) + " done " + (v.done() ? "1" : "0");
        out.push_back(std::move(line));
        for (const auto& g : v._led) {
            std::string gl = "  group " + g._group + " " + g._action;
            if (!g._node.empty()) {
                gl += " " + g._node;
            }
            if (!g._error.empty()) {
                gl += " error: " + g._error;
            }
            out.push_back(std::move(gl));
        }
    }
    return out;
}

using answer = kythira::redis_admin_answer;

/// The job on one data node: the evacuator, the thread that drives it, and
/// the command's sub-commands.
template<typename Host> class controller {
public:
    using node_id_type = typename Host::node_id_type;
    using group_id_type = decltype(std::declval<Host&>().group_ids())::value_type;
    using descriptor_type = typename Host::descriptor_type;
    using evacuator_type = kythira::replica_evacuator<Host>;

    struct hooks {
        /// Sends a command to the gateway at `host:port` as the internal
        /// identity; the whole RESP reply, or nullopt when unreachable.
        std::function<std::optional<std::string>(const std::string&,
                                                 const std::vector<std::string>&)>
            _call;
        /// Every other data node: its id and its gateway's `host:port`.
        std::function<std::vector<std::pair<node_id_type, std::string>>()> _peers;
        /// Makes a target reachable (its Raft URL and gateway).
        std::function<void(const node_id_type&, const target_address&)> _learn;
        /// Marks this node released; false when it has nothing on disk to
        /// mark (an in-memory store).
        std::function<bool()> _release;
        /// This node is a target again: a restart without `data` must refuse.
        std::function<void()> _unrelease;
        std::function<void(const std::string&)> _log;
    };

    /// @param replicas The voters a group keeps when `START` names none.
    controller(Host& host, std::size_t replicas, hooks h)
        : _host(host), _replicas(replicas), _hooks(std::move(h)), _evacuator(host) {}

    controller(const controller&) = delete;
    auto operator=(const controller&) -> controller& = delete;
    controller(controller&&) = delete;
    auto operator=(controller&&) -> controller& = delete;
    ~controller() { stop(); }

    void stop() {
        _running.store(false, std::memory_order_release);
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    /// `args` are the words after `KYTHIRA.EVACUATE`.
    auto handle(const std::vector<std::string>& args, bool internal) -> answer {
        const auto sub = args.empty() ? std::string{} : detail::upper(args.front());
        const std::vector<std::string> rest(args.empty() ? args.end() : args.begin() + 1,
                                            args.end());
        const bool local = !rest.empty() && detail::upper(rest.back()) == "LOCAL";
        if (sub == "START") {
            return start(rest);
        }
        if (sub == "STATUS" && rest.size() <= 1 && (rest.empty() || local)) {
            if (local) {
                return answer::bulk(encode_node_view(local_view()));
            }
            return {answer::kind::lines, status_lines(cluster_status())};
        }
        if (sub == "CANCEL" && rest.size() <= 1 && (rest.empty() || local)) {
            _evacuator.cancel();
            log("redis evacuation: cancelled");
            if (!local) {
                for (const auto& [id, gw] : _hooks._peers()) {
                    (void)_hooks._call(gw, {"KYTHIRA.EVACUATE", "CANCEL", "LOCAL"});
                }
            }
            return answer::ok();
        }
        if (sub == "RELEASE" && rest.empty()) {
            return release();
        }
        if (sub == "DESCRIPTOR" && rest.size() == 1) {
            if (!internal) {
                return answer::error(
                    "NOPERM KYTHIRA.EVACUATE DESCRIPTOR is internal to the layers");
            }
            return descriptor(rest.front());
        }
        return answer::error(
            "ERR syntax: KYTHIRA.EVACUATE START <node> [TO <id>...] [REPLICAS <n>] "
            "[ADDRESS <id> <raft-url> <gateway>]... | STATUS | CANCEL | RELEASE");
    }

    /// A group's descriptor from the peers, for `lookup_descriptor`: the
    /// first that leads it, else the first that holds it.
    [[nodiscard]] auto lookup_descriptor(const group_id_type& group)
        -> std::optional<descriptor_type> {
        std::optional<descriptor_type> held;
        for (const auto& [id, gw] : _hooks._peers()) {
            const auto reply =
                _hooks._call(gw, {"KYTHIRA.EVACUATE", "DESCRIPTOR", std::to_string(group)});
            if (!reply) {
                continue;
            }
            const auto payload = detail::bulk_payload(*reply);
            if (!payload) {
                continue;
            }
            auto routes = redis_data_wire::decode_routes<group_id_type, node_id_type>(*payload);
            if (!routes || routes->routes.size() != 1) {
                continue;
            }
            auto d = std::move(routes->routes.front());
            const bool leads = d._leader_hint && *d._leader_hint == id;
            d._leader_hint.reset();
            if (leads) {
                return d;
            }
            if (!held) {
                held = std::move(d);
            }
        }
        return held;
    }

    /// This node's view of the job.
    [[nodiscard]] auto local_view() -> node_view {
        node_view v;
        v._node = text(_host.node_id());
        const auto job = _evacuator.current();
        v._running = job.has_value();
        if (job) {
            v._evacuee = text(job->_evacuee);
        }
        std::set<std::string> members;
        for (const auto& g : _host.group_ids()) {
            v._held.push_back(std::to_string(g));
            auto* n = _host.group_node(g);
            if (n == nullptr || !n->is_leader()) {
                continue;
            }
            const auto m = n->current_membership();
            for (const auto* ids : {&m.voters, &m.learners}) {
                for (const auto& id : *ids) {
                    members.insert(text(id));
                }
            }
        }
        v._members.assign(members.begin(), members.end());
        const std::scoped_lock lock(_mu);
        for (const auto& g : _last._led) {
            v._led.push_back(led_group{std::to_string(g._group), kythira::to_string(g._action),
                                       g._node ? text(*g._node) : std::string{}, g._error});
        }
        return v;
    }

    /// Every data node's view, merged.
    [[nodiscard]] auto cluster_status() -> cluster_view {
        std::vector<node_view> views{local_view()};
        const auto no_data = "-" + std::string{k_evacuate_no_data};
        for (const auto& [id, gw] : _hooks._peers()) {
            const auto reply = _hooks._call(gw, {"KYTHIRA.EVACUATE", "STATUS", "LOCAL"});
            if (reply && reply->rfind(no_data, 0) == 0) {
                continue;  // no data there, so no part in the job
            }
            const auto payload = reply ? detail::bulk_payload(*reply) : std::nullopt;
            auto v = payload ? decode_node_view(*payload) : std::nullopt;
            // A view from another node than the one asked: the address now
            // belongs to someone else (a container's address handed on
            // after it died, over plaintext, where no certificate names
            // the peer). Its view is counted where it answers for itself.
            if (v && v->_node != text(id)) {
                log("redis evacuation: " + gw + " answered as node " + v->_node + ", not " +
                    text(id) + "; counting it unreachable");
                v.reset();
            }
            if (!v) {
                node_view miss;
                miss._unreachable = text(id) + "@" + gw;
                views.push_back(std::move(miss));
                continue;
            }
            views.push_back(std::move(*v));
        }
        return merge(std::move(views));
    }

    /// Runs one pass now (the thread does this every 200 ms); for tests.
    void pass_now() {
        auto p = _evacuator.pass();
        const std::scoped_lock lock(_mu);
        _last = std::move(p);
    }

private:
    static auto text(const node_id_type& n) -> std::string {
        return node_id_traits<node_id_type>::to_text(n);
    }
    static auto parse_id(const std::string& s) -> std::optional<node_id_type> {
        return node_id_traits<node_id_type>::from_text(s);
    }

    /// The most voters any group this node holds a replica of has now.
    auto held_voter_count() -> std::size_t {
        std::size_t most = 0;
        for (const auto& g : _host.group_ids()) {
            if (auto* n = _host.group_node(g)) {
                most = std::max(most, n->current_membership().voters.size());
            }
        }
        return most;
    }

    void log(const std::string& line) {
        if (_hooks._log) {
            _hooks._log(line);
        }
    }

    auto start(const std::vector<std::string>& rest) -> answer {
        std::string why;
        auto r = parse_start(rest, why);
        if (!r) {
            return answer::error("ERR " + why);
        }
        const auto evacuee = parse_id(r->_node);
        if (!evacuee) {
            return answer::error("ERR '" + r->_node + "' is not a node id");
        }
        // The voters each group keeps: REPLICAS, else this node's setting,
        // else (a node that joined, which founded nothing and so knows no
        // founding count) the most voters a group it holds has now. Settled
        // before anything changes, and fanned out, so every node uses one
        // number.
        if (r->_replicas == 0) {
            r->_replicas = _replicas != 0 ? _replicas : held_voter_count();
        }
        if (r->_replicas == 0) {
            return answer::error(
                "ERR this node holds no group, so it knows no voter count; pass REPLICAS <n>, "
                "or run START on a node that holds groups");
        }
        for (const auto& a : r->_addresses) {
            const auto id = parse_id(a._id);
            if (!id) {
                return answer::error("ERR '" + a._id + "' is not a node id");
            }
            if (*id != _host.node_id() && _hooks._learn) {
                _hooks._learn(*id, a);
            }
        }
        // The targets every node uses: the named ones, or every data node
        // this one knows but the evacuee, resolved here so the fan-out
        // carries the same list.
        if (r->_targets.empty()) {
            if (_host.node_id() != *evacuee) {
                r->_targets.push_back(text(_host.node_id()));
            }
            for (const auto& [id, gw] : _hooks._peers()) {
                if (id != *evacuee) {
                    r->_targets.push_back(text(id));
                }
            }
        }
        typename evacuator_type::job job;
        job._evacuee = *evacuee;
        for (const auto& t : r->_targets) {
            const auto id = parse_id(t);
            if (!id) {
                return answer::error("ERR '" + t + "' is not a node id");
            }
            if (*id == _host.node_id() && _hooks._unrelease) {
                _hooks._unrelease();
            }
            job._targets.push_back(*id);
        }
        if (job._targets.empty()) {
            return answer::error("ERR no data node can take the replicas");
        }
        job._replicas = r->_replicas;
        _evacuator.start(job);
        {
            const std::scoped_lock lock(_mu);
            _last = {};
        }
        log("redis evacuation: evacuating node " + r->_node + " to " +
            std::to_string(job._targets.size()) + " target(s), " + std::to_string(job._replicas) +
            " voters per group");
        ensure_thread();
        if (!r->_local) {
            const auto argv = to_argv(*r);
            // A peer that refused holds the start back. One that did not
            // answer does not: it may be the evacuee, down for good, or a
            // node that is not running, and if it still leads a group,
            // STATUS stays short of done (that group has no live leader's
            // view) until START runs again. A node without data has no
            // part in the job.
            std::vector<std::string> missed;
            std::vector<std::string> silent;
            const auto no_data = "-" + std::string{k_evacuate_no_data};
            for (const auto& [id, gw] : _hooks._peers()) {
                const auto reply = _hooks._call(gw, argv);
                if (!reply) {
                    silent.push_back(text(id) + "@" + gw);
                } else if (reply->rfind("+OK", 0) != 0 && reply->rfind(no_data, 0) != 0) {
                    missed.push_back(text(id) + "@" + gw);
                }
            }
            if (!silent.empty()) {
                std::string list;
                for (const auto& m : silent) {
                    list += (list.empty() ? "" : ", ") + m;
                }
                log("redis evacuation: no answer from " + list +
                    "; STATUS waits for any group they still lead");
            }
            if (!missed.empty()) {
                std::string list;
                for (const auto& m : missed) {
                    list += (list.empty() ? "" : ", ") + m;
                }
                log("redis evacuation: not started on " + list +
                    "; the groups they lead wait for them");
                return answer::error("TRYAGAIN started here, not on " + list +
                                     "; run START again once they answer");
            }
        }
        return answer::ok();
    }

    auto release() -> answer {
        const auto self = _host.node_id();
        for (const auto& g : _host.group_ids()) {
            auto* n = _host.group_node(g);
            if (n != nullptr && n->is_leader()) {
                const auto m = n->current_membership();
                if (std::find(m.voters.begin(), m.voters.end(), self) != m.voters.end()) {
                    return answer::error("ERR this node still leads group " + std::to_string(g));
                }
            }
        }
        if (!released(cluster_status(), text(self))) {
            return answer::error(
                "ERR no finished evacuation of this node on every data node "
                "(KYTHIRA.EVACUATE STATUS)");
        }
        const bool marked = _hooks._release && _hooks._release();
        log(std::string("redis evacuation: released") +
            (marked ? "; this node may restart without the data role"
                    : " (an in-memory store: nothing on disk to mark)"));
        return answer::ok();
    }

    auto descriptor(const std::string& group_text) -> answer {
        group_id_type group{};
        const auto [end, ec] =
            std::from_chars(group_text.data(), group_text.data() + group_text.size(), group);
        if (ec != std::errc{} || end != group_text.data() + group_text.size()) {
            return answer::error("ERR group must be a number");
        }
        auto d = kythira::live_descriptor(_host, group);
        if (!d) {
            return answer::error("ERR no replica of that group here");
        }
        auto* n = _host.group_node(group);
        d->_leader_hint.reset();
        if (n != nullptr && n->is_leader()) {
            d->_leader_hint = _host.node_id();
        }
        redis_data_wire::routes_payload<group_id_type, node_id_type> p;
        p.routes.push_back(std::move(*d));
        return answer::bulk(redis_data_wire::encode_routes(p));
    }

    void ensure_thread() {
        if (_running.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        _thread = std::thread([this] {
            while (_running.load(std::memory_order_acquire)) {
                try {
                    pass_now();
                } catch (const std::exception& e) {
                    log(std::string("redis evacuation: pass failed: ") + e.what());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{200});
            }
        });
    }

    Host& _host;
    std::size_t _replicas;
    hooks _hooks;
    evacuator_type _evacuator;
    std::mutex _mu;
    typename evacuator_type::pass_type _last;
    std::atomic<bool> _running{false};
    std::thread _thread;
};

}  // namespace kythira::redis_evacuation
