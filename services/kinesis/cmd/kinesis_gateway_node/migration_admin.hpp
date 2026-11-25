// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file migration_admin.hpp
/// @brief A data node's live migration admin calls
///        (.kiro/specs/kinesis-independent-layers/ task 13): the `evacuate`
///        job over `replica_evacuator`, its status across the cluster, the
///        evacuee's release, and the descriptor lookup a joining node's
///        lazy replica creation asks its peers. The store move is the
///        module's (it reopens the module's store); this class routes it.
///
/// The wire forms are in kinesis_migration.hpp. Every call arrives signed
/// with the forwarding secret through the gateway's admin route.

#include <kythira/kinesis/kinesis_gateway.hpp>
#include <kythira/kinesis/kinesis_migration.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>

#include <raft/host_node_id.hpp>
#include <raft/replica_evacuation.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::kinesis_node {

namespace migration_detail {

[[nodiscard]] inline auto query_value(std::string_view query, std::string_view key)
    -> std::optional<std::string> {
    while (!query.empty()) {
        const auto amp = query.find('&');
        const auto item = query.substr(0, amp);
        const auto eq = item.find('=');
        if (item.substr(0, eq) == key) {
            return std::string(eq == std::string_view::npos ? std::string_view()
                                                            : item.substr(eq + 1));
        }
        if (amp == std::string_view::npos) {
            break;
        }
        query.remove_prefix(amp + 1);
    }
    return std::nullopt;
}

}  // namespace migration_detail

/// The group descriptor a peer at one of `gateways` answers for `group`
/// (`GET admin/descriptor`): the first that leads it, else the first that
/// holds it. For `multi_raft_config::lookup_descriptor` on a joining node.
template<typename Descriptor>
[[nodiscard]] auto lookup_descriptor_from_peers(const kinesis::peer_client& client,
                                                std::string_view secret,
                                                const std::vector<std::string>& gateways,
                                                std::uint64_t group) -> std::optional<Descriptor> {
    std::optional<Descriptor> held;
    for (const auto& gw : gateways) {
        const auto res = kinesis::admin_request(client, secret, gw, boost::beast::http::verb::get,
                                                "descriptor?group=" + std::to_string(group));
        if (!res || res->_status != 200) {
            continue;
        }
        std::string why;
        auto d = kinesis::parse_descriptor_json<Descriptor>(res->_body, why);
        if (!d) {
            continue;
        }
        if (res->_body.find("\"leader\":true") != std::string::npos) {
            return d;
        }
        if (!held) {
            held = std::move(d);
        }
    }
    return held;
}

template<typename RaftHost> class migration_admin {
public:
    using evacuator_type = kythira::replica_evacuator<RaftHost>;
    using descriptor_type = typename RaftHost::descriptor_type;

    struct hooks {
        /// Makes a target reachable: its Raft URL and gateway address.
        std::function<void(const kinesis::migration_target&)> _learn_target;
        /// Every other data node's gateway `host:port`.
        std::function<std::vector<std::string>()> _peer_gateways;
        /// The node was released: write the marker.
        std::function<void()> _release;
        /// The node is an evacuation's target again: remove the marker, so
        /// a restart without the data role refuses rather than deleting
        /// replicas it now holds.
        std::function<void()> _unrelease;
        /// `POST`/`GET store-move`.
        std::function<https::response(const https::request&)> _store_move;
        std::function<void(const std::string&)> _log;
    };

    migration_admin(RaftHost& raft, kythira::host_node_id self, std::size_t replicas,
                    const kinesis::peer_client& client, std::string secret, hooks h)
        : _raft(raft),
          _self(std::move(self)),
          _replicas(replicas),
          _client(client),
          _secret(std::move(secret)),
          _hooks(std::move(h)),
          _evacuator(raft) {}

    migration_admin(const migration_admin&) = delete;
    auto operator=(const migration_admin&) -> migration_admin& = delete;
    migration_admin(migration_admin&&) = delete;
    auto operator=(migration_admin&&) -> migration_admin& = delete;
    ~migration_admin() { stop(); }

    void stop() {
        _running.store(false, std::memory_order_release);
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    auto handle(const https::request& req, std::string_view op, std::string_view query)
        -> https::response {
        namespace http = boost::beast::http;
        const bool post = req.method() == http::verb::post;
        const bool get = req.method() == http::verb::get;
        if (op == "evacuate" && post) {
            return start_evacuation(req);
        }
        if (op == "evacuate" && get) {
            const auto scope = migration_detail::query_value(query, "scope");
            return json(req, 200, scope && *scope == "node" ? node_status() : cluster_status());
        }
        if (op == "evacuate/cancel" && post) {
            _evacuator.cancel();
            {
                const std::scoped_lock lock(_mu);
                _request.reset();
            }
            if (migration_detail::query_value(query, "fan_out") !=
                std::optional<std::string>{"false"}) {
                for (const auto& gw : _hooks._peer_gateways()) {
                    (void)kinesis::admin_request(_client, _secret, gw, http::verb::post,
                                                 "evacuate/cancel?fan_out=false");
                }
            }
            return json(req, 200, R"({"cancelled":true})");
        }
        if (op == "release" && post) {
            if (_raft.group_count() > 0 && leads_any()) {
                return json(req, 409, R"({"message":"this node still leads a group"})");
            }
            if (!released_by_cluster()) {
                return json(
                    req, 409,
                    R"({"message":"no finished evacuation of this node on every data node"})");
            }
            _hooks._release();
            return json(req, 200, R"({"released":true})");
        }
        if (op == "descriptor" && get) {
            return descriptor(req, query);
        }
        if (op == "store-move" && (post || get)) {
            return _hooks._store_move(req);
        }
        return gateway_detail_reply(req, 404, "not found\n");
    }

    /// This node's view of the job: the groups it leads and their steps.
    [[nodiscard]] auto node_status() -> std::string {
        boost::json::object o;
        o["node"] = kythira::host_node_id_text(_self);
        const auto job = _evacuator.current();
        o["running"] = job.has_value();
        if (job) {
            o["evacuee"] = kythira::host_node_id_text(job->_evacuee);
        }
        boost::json::array held;
        for (const auto& g : _raft.group_ids()) {
            held.emplace_back(g);
        }
        o["groups"] = std::move(held);
        boost::json::array led;
        bool done = true;
        {
            const std::scoped_lock lock(_mu);
            for (const auto& g : _last._led) {
                boost::json::object e;
                e["group"] = g._group;
                e["action"] = kythira::to_string(g._action);
                if (g._node) {
                    e["node"] = kythira::host_node_id_text(*g._node);
                }
                if (!g._error.empty()) {
                    e["error"] = g._error;
                }
                done = done && g._action == kythira::evacuation_action::done;
                led.push_back(std::move(e));
            }
        }
        o["led"] = std::move(led);
        o["done"] = done;
        return boost::json::serialize(o);
    }

    /// Every data node's view merged: done once every group any node holds
    /// is led by a node that reports it done.
    [[nodiscard]] auto cluster_status() -> std::string {
        std::vector<boost::json::value> views;
        views.push_back(boost::json::parse(node_status()));
        for (const auto& gw : _hooks._peer_gateways()) {
            const auto res = kinesis::admin_request(
                _client, _secret, gw, boost::beast::http::verb::get, "evacuate?scope=node");
            if (!res || res->_status != 200) {
                boost::json::object miss;
                miss["gateway"] = gw;
                miss["unreachable"] = true;
                views.emplace_back(std::move(miss));
                continue;
            }
            std::error_code ec;
            auto v = boost::json::parse(res->_body, ec);
            if (!ec && v.is_object()) {
                views.push_back(std::move(v));
            }
        }
        std::set<std::uint64_t> groups;
        std::map<std::uint64_t, bool> led_done;
        bool reachable = true;
        for (const auto& v : views) {
            const auto& o = v.as_object();
            if (o.contains("unreachable")) {
                reachable = false;
                continue;
            }
            if (const auto* gs = o.if_contains("groups"); gs != nullptr && gs->is_array()) {
                for (const auto& g : gs->as_array()) {
                    std::error_code ec;
                    const auto id = g.to_number<std::uint64_t>(ec);
                    if (!ec) {
                        groups.insert(id);
                    }
                }
            }
            if (const auto* led = o.if_contains("led"); led != nullptr && led->is_array()) {
                for (const auto& e : led->as_array()) {
                    const auto& eo = e.as_object();
                    std::error_code ec;
                    const auto id = eo.at("group").to_number<std::uint64_t>(ec);
                    if (!ec) {
                        led_done[id] = eo.at("action").as_string() == "done";
                    }
                }
            }
        }
        bool done = reachable && !groups.empty();
        for (const auto g : groups) {
            const auto it = led_done.find(g);
            done = done && it != led_done.end() && it->second;
        }
        boost::json::object out;
        out["done"] = done;
        boost::json::array nodes;
        for (auto& v : views) {
            nodes.push_back(std::move(v));
        }
        out["nodes"] = std::move(nodes);
        return boost::json::serialize(out);
    }

private:
    static auto gateway_detail_reply(const https::request& req, unsigned status, std::string body)
        -> https::response {
        return kinesis::gateway_detail::reply(req, status, std::move(body), "text/plain");
    }

    static auto json(const https::request& req, unsigned status, std::string body)
        -> https::response {
        return kinesis::gateway_detail::reply(req, status, std::move(body), "application/json");
    }

    [[nodiscard]] auto leads_any() -> bool {
        for (const auto& g : _raft.group_ids()) {
            auto* n = _raft.group_node(g);
            if (n != nullptr && n->is_leader()) {
                const auto m = n->current_membership();
                if (std::find(m.voters.begin(), m.voters.end(), _self) != m.voters.end()) {
                    return true;
                }
            }
        }
        return false;
    }

    /// True when the cluster's merged status is done and every data node
    /// that answered runs a job evacuating this node: no group still
    /// counts on it as a voter, as far as any leader knows.
    [[nodiscard]] auto released_by_cluster() -> bool {
        std::error_code ec;
        const auto v = boost::json::parse(cluster_status(), ec);
        if (ec || !v.is_object()) {
            return false;
        }
        const auto& o = v.as_object();
        const auto* done = o.if_contains("done");
        if (done == nullptr || !done->is_bool() || !done->as_bool()) {
            return false;
        }
        const auto self = kythira::host_node_id_text(_self);
        for (const auto& n : o.at("nodes").as_array()) {
            const auto* evacuee = n.as_object().if_contains("evacuee");
            if (evacuee == nullptr || !evacuee->is_string() || evacuee->as_string() != self) {
                return false;
            }
        }
        return true;
    }

    auto start_evacuation(const https::request& req) -> https::response {
        std::string why;
        auto r = kinesis::parse_evacuation_request(req.body(), why);
        if (!r) {
            return json(req, 400, boost::json::serialize(boost::json::object{{"message", why}}));
        }
        for (const auto& t : r->_targets) {
            if (!t._raft.empty() || !t._gateway.empty()) {
                _hooks._learn_target(t);
            }
            if (t._id == _self && _hooks._unrelease) {
                _hooks._unrelease();
            }
        }
        typename evacuator_type::job job;
        job._evacuee = r->_node;
        for (const auto& t : r->_targets) {
            job._targets.push_back(t._id);
        }
        job._replicas = r->_replicas != 0 ? r->_replicas : _replicas;
        _evacuator.start(job);
        {
            const std::scoped_lock lock(_mu);
            _request = *r;
            _last = {};
        }
        _hooks._log("kinesis migration: evacuating node " + kythira::host_node_id_text(r->_node) +
                    " to " + std::to_string(r->_targets.size()) + " target(s), " +
                    std::to_string(job._replicas) + " voters per group");
        ensure_thread();
        if (r->_fan_out) {
            auto relay = *r;
            relay._fan_out = false;
            const auto body = kinesis::serialize(relay);
            for (const auto& gw : _hooks._peer_gateways()) {
                const auto res = kinesis::admin_request(
                    _client, _secret, gw, boost::beast::http::verb::post, "evacuate", body);
                if (!res || res->_status != 202) {
                    _hooks._log("kinesis migration: peer " + gw +
                                " did not take the evacuation; its groups wait for it");
                }
            }
        }
        return json(req, 202, R"({"started":true})");
    }

    void ensure_thread() {
        if (_running.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        _thread = std::thread([this] {
            while (_running.load(std::memory_order_acquire)) {
                try {
                    auto p = _evacuator.pass();
                    const std::scoped_lock lock(_mu);
                    _last = std::move(p);
                } catch (const std::exception& e) {
                    _hooks._log(std::string("kinesis migration: pass failed: ") + e.what());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{200});
            }
        });
    }

    auto descriptor(const https::request& req, std::string_view query) -> https::response {
        const auto g = migration_detail::query_value(query, "group");
        std::uint64_t group = 0;
        if (!g || g->empty() || g->size() > 20 ||
            g->find_first_not_of("0123456789") != std::string::npos) {
            return json(req, 400, R"({"message":"group must be a number"})");
        }
        group = std::stoull(*g);
        auto d = kythira::live_descriptor(_raft, group);
        if (!d) {
            return json(req, 404, R"({"message":"no replica of that group here"})");
        }
        auto* n = _raft.group_node(group);
        auto body = kinesis::descriptor_json(*d);
        // A leader's answer is the freshest; say so for the asker.
        body.pop_back();
        body +=
            std::string(",\"leader\":") + (n != nullptr && n->is_leader() ? "true" : "false") + "}";
        return json(req, 200, std::move(body));
    }

    RaftHost& _raft;
    kythira::host_node_id _self;
    std::size_t _replicas;
    const kinesis::peer_client& _client;
    std::string _secret;
    hooks _hooks;
    evacuator_type _evacuator;
    std::mutex _mu;
    std::optional<kinesis::evacuation_request> _request;
    typename evacuator_type::pass_type _last;
    std::atomic<bool> _running{false};
    std::thread _thread;
};

}  // namespace kythira::kinesis_node
