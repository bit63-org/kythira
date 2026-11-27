// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_acl_probes.hpp
/// @brief ElastiCache access strings against the gateway's ACL
///        (.kiro/specs/redis-general-data-types/ Requirement 25.3).
///
/// An access string valid on ElastiCache must grant the same permissions on
/// Kythira (written after the ACL's `none` role). ElastiCache evaluates
/// access strings with Redis's own ACL code, so Redis 7.2 and Valkey 8 are
/// the ground truth: for every access string in access_strings() and every
/// probe in acl_probes(), the container run (redis_differential_test.cpp)
/// asks each reference server `ACL DRYRUN` and records whether the user may
/// run it, and recs/acl/access-strings.json keeps the answers. The replay
/// test (redis_differential_replay_test.cpp) logs in to an in-process
/// gateway as each user and sends every probe for real, so the comparison
/// covers the gateway's own key extraction and per-key access, not a model
/// of it.
///
/// A decision is one character: `a` allowed, `c` refused for the command,
/// `k` refused for a key, `e` the server refused the probe itself (it is
/// then not compared).

#include "redis_differential.hpp"

#include <kythira/redis/redis_known_commands.hpp>

#include <boost/json.hpp>

#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace kythira::redis_diff {

/// The access strings compared. The first two are ElastiCache's own
/// examples (the default user, and Requirement 25.3's); the rest exercise
/// each kind of word on the keys the probes name (`a:` .. `h:`).
inline auto access_strings() -> const std::vector<std::string>& {
    static const std::vector<std::string> table{
        "on ~* &* +@all",
        "on ~app:* +@string -@dangerous",
        "on ~a:* +@string -@dangerous",
        "on ~* -@all +@read",
        "on ~* +@all -@write",
        "on ~a:* ~b:* +@all -@dangerous -@admin",
        "on %R~a:* %W~b:* ~c:* +@all",
        "on ~e:* -@all +@hash +@read -hgetall",
        // ElastiCache's documented read-mostly example, on every key (one
        // literal over two lines).
        // NOLINTNEXTLINE(bugprone-suspicious-missing-comma)
        "on ~* -@all +@read +@hash +@bitmap +@geo -setbit -bitfield -hset -hsetnx -hmset "
        "-incrby -decrby -bitop -hincrby -geoadd",
        "on ~* +@all -flushall -flushdb -keys",
        "on resetchannels ~* +@all -@dangerous +info",
        "on allkeys allchannels allcommands -@admin",
        "on ~* nocommands +get +set +ping",
        "on ~* +@all -@list +lrange",
        "on ~* -@all +@transaction +@string",
        "on ~* -@all +@connection",
        "on ~* -@all +@keyspace -del +unlink",
        "on ~* -@all +@set +@fast",
        "on ~d:* ~e:* resetkeys ~f:* +@all",
        "on ~* +@all -@slow",
        "on %R~* %W~a:* +@all -@dangerous",
        "on ~* -@all +@write -@read",
    };
    return table;
}

/// One or two argument vectors per command: the first ones the seeded
/// generator emits for each command (so every shipped command with a shape
/// is probed, with valid arguments), then the commands it leaves out that
/// a client can send. `AUTH` and `HELLO` are left out: both servers and
/// Kythira authenticate before any ACL applies. Kythira-only commands, and
/// the generator's unknown-command shape, are left out: the reference
/// servers do not know them.
inline auto acl_probes() -> const std::vector<std::vector<std::string>>& {
    static const std::vector<std::vector<std::string>> table = [] {
        std::vector<std::vector<std::string>> out;
        generator_options opt;
        opt.length = 20000;
        opt.tag = "acl";
        std::map<std::string, int> seen;
        std::set<std::vector<std::string>> unique;
        for (auto& c : generate(1, opt)) {
            const auto name = detail::upper(c.argv.front());
            if (!is_known_redis_command(name) || seen[name] >= 2 || !unique.insert(c.argv).second) {
                continue;
            }
            ++seen[name];
            out.push_back(std::move(c.argv));
        }
        for (auto argv : std::vector<std::vector<std::string>>{
                 {"CLIENT", "ID"},
                 {"CLIENT", "GETNAME"},
                 {"COMMAND", "COUNT"},
                 {"INFO", "server"},
                 {"DBSIZE"},
                 {"MEMORY", "USAGE", "a:acl"},
                 {"SLOWLOG", "LEN"},
                 {"RANDOMKEY"},
                 {"FLUSHDB"},
                 {"FLUSHALL"},
                 {"RESET"},
                 {"QUIT"},
             }) {
            out.push_back(std::move(argv));
        }
        return out;
    }();
    return table;
}

/// What `ACL DRYRUN` answered: `+OK`, or a bulk string saying why not; an
/// error means the server refused the probe itself (an arity error, say).
inline auto dryrun_decision(const reply& r) -> char {
    if (r.kind != reply_kind::simple && r.kind != reply_kind::bulk) {
        return 'e';
    }
    if (r.text == "OK") {
        return 'a';
    }
    if (r.text.find("permissions to run") != std::string::npos) {
        return 'c';
    }
    if (r.text.find("permissions to access") != std::string::npos) {
        return 'k';
    }
    return 'e';
}

/// What a probe sent to the gateway as the user answered.
inline auto gateway_decision(const reply& r) -> char {
    if (r.kind != reply_kind::error || !r.text.starts_with("NOPERM")) {
        return 'a';
    }
    return r.text.find("access a key") != std::string::npos ? 'k' : 'c';
}

struct acl_recording {
    std::map<std::string, std::string> versions;  // server -> version
    std::string date;
    std::vector<std::vector<std::string>> probes;
    /// access string -> server -> one decision per probe.
    std::vector<std::pair<std::string, std::map<std::string, std::string>>> decisions;
};

/// One probe or access string per line, so a regeneration diffs line by
/// line in review.
inline auto serialize(const acl_recording& r) -> std::string {
    std::string out = "{\n  \"format\": 1,\n  \"versions\": ";
    boost::json::object versions;
    for (const auto& [server, version] : r.versions) {
        versions[server] = version;
    }
    out += boost::json::serialize(versions) + ",\n";
    out += "  \"date\": " + boost::json::serialize(boost::json::value(r.date)) + ",\n";
    out += "  \"probes\": [\n";
    for (std::size_t i = 0; i < r.probes.size(); ++i) {
        boost::json::array argv;
        for (const auto& a : r.probes[i]) {
            argv.emplace_back(a);
        }
        out += "    " + boost::json::serialize(argv) + (i + 1 < r.probes.size() ? ",\n" : "\n");
    }
    out += "  ],\n  \"decisions\": [\n";
    for (std::size_t i = 0; i < r.decisions.size(); ++i) {
        boost::json::object by_server;
        for (const auto& [server, d] : r.decisions[i].second) {
            by_server[server] = d;
        }
        boost::json::object row{{"access", r.decisions[i].first}, {"servers", by_server}};
        out += "    " + boost::json::serialize(row) + (i + 1 < r.decisions.size() ? ",\n" : "\n");
    }
    out += "  ]\n}\n";
    return out;
}

inline auto acl_recording_from_json(const boost::json::value& v) -> acl_recording {
    const auto& o = v.as_object();
    if (o.at("format").to_number<int>() != 1) {
        throw std::runtime_error("acl recording: unknown format");
    }
    acl_recording r;
    for (const auto& [server, version] : o.at("versions").as_object()) {
        r.versions[std::string(server)] = std::string(version.as_string());
    }
    r.date = std::string(o.at("date").as_string());
    for (const auto& p : o.at("probes").as_array()) {
        std::vector<std::string> argv;
        for (const auto& a : p.as_array()) {
            argv.emplace_back(a.as_string());
        }
        r.probes.push_back(std::move(argv));
    }
    for (const auto& d : o.at("decisions").as_array()) {
        const auto& row = d.as_object();
        std::map<std::string, std::string> by_server;
        for (const auto& [server, s] : row.at("servers").as_object()) {
            by_server[std::string(server)] = std::string(s.as_string());
        }
        r.decisions.emplace_back(std::string(row.at("access").as_string()), std::move(by_server));
    }
    return r;
}

/// Records one reference server's decisions. `call` sends one command to
/// it as an admin and returns the parsed reply.
template<typename Call>
auto record_acl_decisions(Call&& call) -> std::vector<std::pair<std::string, std::string>> {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& access : access_strings()) {
        std::vector<std::string> setuser{"ACL", "SETUSER", "kythira-acl-probe", "reset"};
        for (std::size_t pos = 0; pos < access.size();) {
            const auto end = access.find(' ', pos);
            setuser.push_back(access.substr(pos, end == std::string::npos ? end : end - pos));
            pos = end == std::string::npos ? access.size() : end + 1;
        }
        const auto set = call(setuser);
        if (set.kind == reply_kind::error) {
            throw std::runtime_error("ACL SETUSER " + access + ": " + set.text);
        }
        std::string decisions;
        for (const auto& probe : acl_probes()) {
            std::vector<std::string> dry{"ACL", "DRYRUN", "kythira-acl-probe"};
            dry.insert(dry.end(), probe.begin(), probe.end());
            decisions += dryrun_decision(call(dry));
        }
        out.emplace_back(access, std::move(decisions));
    }
    (void)call(std::vector<std::string>{"ACL", "DELUSER", "kythira-acl-probe"});
    return out;
}

}  // namespace kythira::redis_diff
