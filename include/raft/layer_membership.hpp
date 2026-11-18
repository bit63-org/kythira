// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file layer_membership.hpp
/// @brief The member list of a service's stateless layers, kept in one small
///        Raft group of their own or read from configuration
///        (.kiro/specs/kinesis-independent-layers/ task 11, design "Layer
///        membership group", Requirements 10.1-10.3).
///
/// Gateways and front ends hold no data, but they need a shared list of who
/// is up (for affinity, task 8), which roles each runs, where it listens,
/// whether it is draining, how loaded it is (for scaling, task 12), and the
/// version of the settings every front end must agree on (iterator key ids,
/// compatibility defaults).
///
/// Two sources give that list through one interface, `member_directory`:
///
///  - **The layer membership group** (optional): a single Raft group whose
///    state machine is `layer_membership_state_machine`. It has a small
///    fixed voter set (three or five) and every other stateless node joins
///    as a learner (`.kiro/specs/non-voting-nodes/`), so the layer can grow
///    without growing its quorum. It holds no service data: losing it
///    entirely loses only the member list, which members re-announce on
///    restart. `replicated_layer_membership` is a member's view of it,
///    through two hooks so this header names no node or host type.
///  - **Configuration** (`static_member_directory`): the member list from
///    settings such as `KINESIS_FRONT_ENDS`, or from DNS peer discovery,
///    when the group is off (Requirement 10.2).
///
/// ## Determinism
///
/// `apply()` reads no clock: every time it stores (announce, load report)
/// comes in the command, stamped by the member that proposed it. Whether a
/// member is *live* is decided at query time from the caller's clock
/// (`live_members`), so replicas never diverge on wall-clock reads.

#include <raft/layer_roles.hpp>
#include <raft/types.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::layers {

/// Where a member is in leaving: a draining member finishes in-flight
/// calls and takes no new ones; a drained one may be stopped.
enum class drain_state : std::uint8_t {
    serving = 0,
    draining = 1,
    drained = 2,
};

[[nodiscard]] constexpr auto to_string(drain_state s) noexcept -> std::string_view {
    switch (s) {
        case drain_state::serving:
            return "serving";
        case drain_state::draining:
            return "draining";
        case drain_state::drained:
            return "drained";
    }
    return "serving";
}

/// What a member reports about its load: the signals the layer's capacity
/// policy scales on (Requirement 10.4).
struct layer_load {
    double requests_per_second = 0.0;
    std::uint64_t open_streams = 0;
    /// 0..1 of the node's CPUs.
    double cpu = 0.0;
    std::uint64_t bytes_served_per_second = 0;

    friend auto operator==(const layer_load&, const layer_load&) -> bool = default;
};

/// One gateway or front end.
struct layer_member {
    std::string id;
    role_set roles;
    /// Where it serves the internal API ("host:port", a name or a literal).
    std::string address;
    std::string placement_group;
    drain_state drain = drain_state::serving;
    layer_load load;
    /// When it last announced itself and last reported load (ms since the
    /// epoch, its own clock).
    std::int64_t announced_at_ms = 0;
    std::int64_t reported_at_ms = 0;

    friend auto operator==(const layer_member&, const layer_member&) -> bool = default;
};

/// The members a layer routes over, from the group or from configuration.
class member_directory {
public:
    member_directory() = default;
    member_directory(const member_directory&) = delete;
    auto operator=(const member_directory&) -> member_directory& = delete;
    member_directory(member_directory&&) = delete;
    auto operator=(member_directory&&) -> member_directory& = delete;
    virtual ~member_directory() = default;

    /// Every known member, by id.
    [[nodiscard]] virtual auto members() const -> std::vector<layer_member> = 0;

    /// Members that run any of `roles`, are serving, and reported within
    /// `stale_after_ms` of `now_ms`. A directory without load reports
    /// (configuration) treats every member as fresh.
    [[nodiscard]] virtual auto live_members(role_set roles, std::int64_t now_ms,
                                            std::int64_t stale_after_ms) const
        -> std::vector<layer_member> {
        std::vector<layer_member> out;
        for (auto& m : members()) {
            if (m.roles.intersects(roles) && m.drain == drain_state::serving &&
                (!reports_load() || now_ms - m.reported_at_ms <= stale_after_ms)) {
                out.push_back(std::move(m));
            }
        }
        return out;
    }

    /// Whether members' `reported_at_ms` means anything here.
    [[nodiscard]] virtual auto reports_load() const -> bool = 0;
};

/// Members from configuration or DNS discovery. Every listed member is
/// serving with the roles it was listed under; the list is replaced whole
/// when discovery finds a new one.
class static_member_directory final : public member_directory {
public:
    explicit static_member_directory(std::vector<layer_member> members = {}) {
        replace(std::move(members));
    }

    /// Parses a comma-separated list of "id=host:port" or "host:port"
    /// entries (the address is the id when no id is given), all with
    /// `roles`. Throws `std::invalid_argument` naming `setting` on an empty
    /// entry or a duplicate id.
    [[nodiscard]] static auto parse(std::string_view setting, std::string_view text, role_set roles)
        -> std::vector<layer_member> {
        std::vector<layer_member> out;
        if (text.empty()) {
            return out;
        }
        std::size_t start = 0;
        for (;;) {
            const auto comma = text.find(',', start);
            const auto entry = text.substr(
                start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
            if (entry.empty()) {
                throw std::invalid_argument(std::string(setting) + ": empty entry in \"" +
                                            std::string(text) + "\"");
            }
            layer_member m;
            const auto eq = entry.find('=');
            if (eq == std::string_view::npos) {
                m.id = std::string(entry);
                m.address = std::string(entry);
            } else {
                m.id = std::string(entry.substr(0, eq));
                m.address = std::string(entry.substr(eq + 1));
            }
            if (m.id.empty() || m.address.empty()) {
                throw std::invalid_argument(std::string(setting) + ": bad entry \"" +
                                            std::string(entry) + "\"");
            }
            if (std::ranges::any_of(out, [&](const layer_member& o) { return o.id == m.id; })) {
                throw std::invalid_argument(std::string(setting) + ": \"" + m.id +
                                            "\" is listed twice");
            }
            m.roles = roles;
            out.push_back(std::move(m));
            if (comma == std::string_view::npos) {
                return out;
            }
            start = comma + 1;
        }
    }

    void replace(std::vector<layer_member> members) {
        std::ranges::sort(members, {}, &layer_member::id);
        const std::lock_guard lock(_mu);
        _members = std::move(members);
    }

    [[nodiscard]] auto members() const -> std::vector<layer_member> override {
        const std::lock_guard lock(_mu);
        return _members;
    }
    [[nodiscard]] auto reports_load() const -> bool override { return false; }

private:
    mutable std::mutex _mu;
    std::vector<layer_member> _members;
};

/// The group's state, without locking or Raft: what `apply` changes and a
/// snapshot holds.
class layer_membership_core {
public:
    /// Applies one command (see the encoders). Returns whether it changed
    /// anything; a refused command (unknown member, an older settings
    /// version, a malformed command) changes nothing.
    auto apply_command(const std::vector<std::byte>& command) -> bool {
        boost::json::value v;
        try {
            v = boost::json::parse(
                std::string_view(reinterpret_cast<const char*>(command.data()), command.size()));
        } catch (const std::exception&) {
            return false;
        }
        if (!v.is_object()) {
            return false;
        }
        const auto& o = v.as_object();
        try {
            const auto op = std::string_view(o.at("op").as_string());
            if (op == "announce") {
                auto m = member_from_json(o.at("member").as_object());
                if (m.id.empty() || m.roles.empty()) {
                    return false;
                }
                // A re-announcing member keeps its drain state: a restart
                // must not undo an operator's drain.
                if (auto it = _members.find(m.id); it != _members.end()) {
                    m.drain = it->second.drain;
                }
                _members[m.id] = std::move(m);
                return true;
            }
            if (op == "leave") {
                return _members.erase(std::string(o.at("id").as_string())) != 0;
            }
            if (op == "drain") {
                auto it = _members.find(std::string(o.at("id").as_string()));
                const auto state = o.at("state").to_number<std::uint64_t>();
                if (it == _members.end() || state > 2) {
                    return false;
                }
                it->second.drain = static_cast<drain_state>(state);
                return true;
            }
            if (op == "load") {
                auto it = _members.find(std::string(o.at("id").as_string()));
                if (it == _members.end()) {
                    return false;
                }
                const auto at = o.at("at_ms").to_number<std::int64_t>();
                if (at < it->second.reported_at_ms) {
                    return false;  // an older report arriving late
                }
                it->second.load = load_from_json(o.at("load").as_object());
                it->second.reported_at_ms = at;
                return true;
            }
            if (op == "settings") {
                const auto version = o.at("version").to_number<std::uint64_t>();
                if (version <= _settings_version) {
                    return false;
                }
                _settings_version = version;
                return true;
            }
        } catch (const std::exception&) {
            return false;
        }
        return false;
    }

    [[nodiscard]] auto members() const -> std::vector<layer_member> {
        std::vector<layer_member> out;
        out.reserve(_members.size());
        for (const auto& [id, m] : _members) {
            out.push_back(m);
        }
        return out;
    }
    [[nodiscard]] auto find(const std::string& id) const -> std::optional<layer_member> {
        const auto it = _members.find(id);
        if (it == _members.end()) {
            return std::nullopt;
        }
        return it->second;
    }
    [[nodiscard]] auto settings_version() const noexcept -> std::uint64_t {
        return _settings_version;
    }

    // ---- commands ---------------------------------------------------------

    [[nodiscard]] static auto encode_announce(const layer_member& m) -> std::vector<std::byte> {
        return to_bytes(boost::json::object{{"op", "announce"}, {"member", member_to_json(m)}});
    }
    [[nodiscard]] static auto encode_leave(const std::string& id) -> std::vector<std::byte> {
        return to_bytes(boost::json::object{{"op", "leave"}, {"id", id}});
    }
    [[nodiscard]] static auto encode_drain(const std::string& id, drain_state s)
        -> std::vector<std::byte> {
        return to_bytes(boost::json::object{
            {"op", "drain"}, {"id", id}, {"state", static_cast<std::uint64_t>(s)}});
    }
    [[nodiscard]] static auto encode_load(const std::string& id, const layer_load& load,
                                          std::int64_t at_ms) -> std::vector<std::byte> {
        return to_bytes(boost::json::object{
            {"op", "load"}, {"id", id}, {"load", load_to_json(load)}, {"at_ms", at_ms}});
    }
    [[nodiscard]] static auto encode_settings(std::uint64_t version) -> std::vector<std::byte> {
        return to_bytes(boost::json::object{{"op", "settings"}, {"version", version}});
    }

    // ---- snapshot ---------------------------------------------------------

    [[nodiscard]] auto to_json() const -> boost::json::value {
        boost::json::array members;
        for (const auto& [id, m] : _members) {
            members.push_back(member_to_json(m));
        }
        return boost::json::object{{"version", 1},
                                   {"settings_version", _settings_version},
                                   {"members", std::move(members)}};
    }

    void from_json(const boost::json::value& v) {
        const auto& o = v.as_object();
        if (o.at("version").to_number<int>() != 1) {
            throw std::invalid_argument("layer membership snapshot: unknown version");
        }
        std::map<std::string, layer_member> members;
        for (const auto& m : o.at("members").as_array()) {
            auto member = member_from_json(m.as_object());
            auto id = member.id;
            members.emplace(std::move(id), std::move(member));
        }
        _settings_version = o.at("settings_version").to_number<std::uint64_t>();
        _members = std::move(members);
    }

    [[nodiscard]] static auto to_bytes(const boost::json::value& v) -> std::vector<std::byte> {
        const auto s = boost::json::serialize(v);
        std::vector<std::byte> out(s.size());
        std::ranges::transform(s, out.begin(), [](char c) { return static_cast<std::byte>(c); });
        return out;
    }

private:
    [[nodiscard]] static auto load_to_json(const layer_load& l) -> boost::json::object {
        return {{"rps", l.requests_per_second},
                {"streams", l.open_streams},
                {"cpu", l.cpu},
                {"bps", l.bytes_served_per_second}};
    }
    [[nodiscard]] static auto load_from_json(const boost::json::object& o) -> layer_load {
        layer_load l;
        l.requests_per_second = o.at("rps").to_number<double>();
        l.open_streams = o.at("streams").to_number<std::uint64_t>();
        l.cpu = o.at("cpu").to_number<double>();
        l.bytes_served_per_second = o.at("bps").to_number<std::uint64_t>();
        return l;
    }
    [[nodiscard]] static auto member_to_json(const layer_member& m) -> boost::json::object {
        return {{"id", m.id},
                {"roles", m.roles.to_string()},
                {"address", m.address},
                {"placement_group", m.placement_group},
                {"drain", static_cast<std::uint64_t>(m.drain)},
                {"load", load_to_json(m.load)},
                {"announced_at_ms", m.announced_at_ms},
                {"reported_at_ms", m.reported_at_ms}};
    }
    [[nodiscard]] static auto member_from_json(const boost::json::object& o) -> layer_member {
        layer_member m;
        m.id = std::string(o.at("id").as_string());
        m.roles = role_set::parse(std::string_view(o.at("roles").as_string()));
        m.address = std::string(o.at("address").as_string());
        m.placement_group = std::string(o.at("placement_group").as_string());
        const auto drain = o.at("drain").to_number<std::uint64_t>();
        if (drain > 2) {
            throw std::invalid_argument("layer membership: bad drain state");
        }
        m.drain = static_cast<drain_state>(drain);
        m.load = load_from_json(o.at("load").as_object());
        m.announced_at_ms = o.at("announced_at_ms").to_number<std::int64_t>();
        m.reported_at_ms = o.at("reported_at_ms").to_number<std::int64_t>();
        return m;
    }

    std::map<std::string, layer_member> _members;
    std::uint64_t _settings_version = 0;
};

/// The group's state machine. Answers one byte: 1 when the command changed
/// the state, 0 when it was refused.
template<typename LogIndex = std::uint64_t> class layer_membership_state_machine {
public:
    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        const std::lock_guard lock(*_mutex);
        _last_applied = index;
        return {_core.apply_command(command) ? std::byte{1} : std::byte{0}};
    }

    [[nodiscard]] auto get_state() const -> std::vector<std::byte> {
        const std::lock_guard lock(*_mutex);
        return layer_membership_core::to_bytes(_core.to_json());
    }

    void restore_from_snapshot(const std::vector<std::byte>& data, LogIndex index) {
        const std::lock_guard lock(*_mutex);
        _last_applied = index;
        if (data.empty()) {
            _core = layer_membership_core{};
            return;
        }
        _core.from_json(boost::json::parse(
            std::string_view(reinterpret_cast<const char*>(data.data()), data.size())));
    }

    [[nodiscard]] auto members() const -> std::vector<layer_member> {
        const std::lock_guard lock(*_mutex);
        return _core.members();
    }
    [[nodiscard]] auto find(const std::string& id) const -> std::optional<layer_member> {
        const std::lock_guard lock(*_mutex);
        return _core.find(id);
    }
    [[nodiscard]] auto settings_version() const -> std::uint64_t {
        const std::lock_guard lock(*_mutex);
        return _core.settings_version();
    }
    [[nodiscard]] auto last_applied() const -> LogIndex {
        const std::lock_guard lock(*_mutex);
        return _last_applied;
    }

private:
    // Behind a pointer so the state machine stays movable, which
    // `node_config` requires of whatever it is handed.
    std::unique_ptr<std::mutex> _mutex{std::make_unique<std::mutex>()};
    layer_membership_core _core;
    LogIndex _last_applied{0};
};

static_assert(state_machine<layer_membership_state_machine<std::uint64_t>, std::uint64_t>);

/// A member's view of the layer membership group, through two hooks so
/// this header never names a node or host type:
///
/// - `propose(bytes)` submits a command to the group (forwarding to its
///   leader as the host does) and returns the state machine's one-byte
///   answer once the entry has applied, or `nullopt` when it could not be
///   committed (no leader, timeout). A `nullopt` write may still commit.
/// - `read()` returns the committed member list from this node's replica
///   (a learner's replica lags by at most the replication delay).
class replicated_layer_membership final : public member_directory {
public:
    using proposer = std::function<std::optional<std::vector<std::byte>>(std::vector<std::byte>)>;
    using reader = std::function<std::vector<layer_member>()>;

    replicated_layer_membership(proposer propose, reader read)
        : _propose(std::move(propose)), _read(std::move(read)) {}

    /// Announces (or re-announces) `self`. Returns whether it committed.
    auto announce(const layer_member& self) -> bool {
        return submit(layer_membership_core::encode_announce(self));
    }
    auto leave(const std::string& id) -> bool {
        return submit(layer_membership_core::encode_leave(id));
    }
    auto set_drain(const std::string& id, drain_state s) -> bool {
        return submit(layer_membership_core::encode_drain(id, s));
    }
    auto report_load(const std::string& id, const layer_load& load, std::int64_t at_ms) -> bool {
        return submit(layer_membership_core::encode_load(id, load, at_ms));
    }
    /// Publishes a new shared-settings version; refused unless it is higher.
    auto publish_settings_version(std::uint64_t version) -> bool {
        return submit(layer_membership_core::encode_settings(version));
    }

    [[nodiscard]] auto members() const -> std::vector<layer_member> override { return _read(); }
    [[nodiscard]] auto reports_load() const -> bool override { return true; }

private:
    auto submit(std::vector<std::byte> command) -> bool {
        const auto answer = _propose(std::move(command));
        return answer && answer->size() == 1 && (*answer)[0] == std::byte{1};
    }

    proposer _propose;
    reader _read;
};

}  // namespace kythira::layers
