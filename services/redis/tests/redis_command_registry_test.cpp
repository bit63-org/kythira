// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_command_registry_test.cpp
/// @brief The generated command registry (.kiro/specs/redis-general-data-types/
///        task 1): its table is well formed, it agrees with the commands the
///        gateway accepts today, and no command id ever changes.
///
/// A command id is what a format-0x03 `exec` log record carries, so a
/// renumbered id would make a new binary apply an old log entry as a
/// different command. golden/redis/command_ids.txt records every id ever
/// issued; this test refuses any change to an existing line, and
/// KYTHIRA_UPDATE_GOLDENS=1 may only append lines for new commands.

#define BOOST_TEST_MODULE redis_command_registry_test
#include <boost/test/unit_test.hpp>

#include "redis_golden_bytes.hpp"

#include <kythira/redis/redis_acl.hpp>
#include <kythira/redis/redis_command_ids.hpp>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>

namespace {

using kythira::find_redis_command;
using kythira::k_redis_commands;
using kythira::redis_command_id;
using kythira::redis_command_info;
using kythira::redis_command_status;
namespace flag = kythira::redis_command_flag;
namespace cat = kythira::redis_acl_category;

/// Every command the gateway accepted before this spec, as its ACL knows
/// them, plus the internal KYTHIRA.ADVISE the ACL leaves to the gateway and
/// KYTHIRA.INSTALL, which only a transaction's commit record names.
auto accepted_today() -> std::set<std::string> {
    std::set<std::string> out{"KYTHIRA.ADVISE", "KYTHIRA.INSTALL"};
    for (const auto& c : k_redis_commands) {
        if (kythira::redis_command_min_role(c.name)) {
            out.emplace(c.name);
        }
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_table_is_sorted_with_unique_names_and_ids) {
    BOOST_REQUIRE(!k_redis_commands.empty());
    std::set<std::uint16_t> ids;
    for (std::size_t i = 0; i < k_redis_commands.size(); ++i) {
        const auto& c = k_redis_commands[i];
        if (i > 0) {
            BOOST_CHECK_LT(k_redis_commands[i - 1].name, c.name);
        }
        BOOST_CHECK_MESSAGE(ids.insert(c.id).second, c.name << " reuses id " << c.id);
        BOOST_CHECK_NE(c.id, 0U);
        BOOST_CHECK(std::ranges::all_of(c.name, [](char ch) {
            return (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.';
        }));
    }
}

BOOST_AUTO_TEST_CASE(lookups_by_name_and_id_agree) {
    for (const auto& c : k_redis_commands) {
        const auto* by_name = find_redis_command(c.name);
        BOOST_REQUIRE(by_name != nullptr);
        BOOST_CHECK_EQUAL(by_name, &c);
        const auto* by_id = find_redis_command(static_cast<redis_command_id>(c.id));
        BOOST_REQUIRE(by_id != nullptr);
        BOOST_CHECK_EQUAL(by_id, &c);
    }
    BOOST_CHECK(find_redis_command("get") == nullptr);  // names are matched upper case
    BOOST_CHECK(find_redis_command("NOSUCH") == nullptr);
    BOOST_CHECK(find_redis_command(static_cast<redis_command_id>(0)) == nullptr);
    BOOST_CHECK(find_redis_command(static_cast<redis_command_id>(65535)) == nullptr);
    static_assert(find_redis_command("SET") != nullptr);
    static_assert(find_redis_command("SET")->id ==
                  static_cast<std::uint16_t>(redis_command_id::set));
}

// The registry's `shipped` set is exactly what the gateway accepts today;
// a planned command is one the gateway still refuses as unknown
// (Requirement 1.1). A task that ships a command flips its status and
// adds it to the gateway's ACL table.
BOOST_AUTO_TEST_CASE(shipped_means_accepted_by_the_gateway) {
    const auto accepted = accepted_today();
    for (const auto& c : k_redis_commands) {
        const bool shipped = c.status == redis_command_status::shipped;
        BOOST_CHECK_MESSAGE(shipped == accepted.contains(std::string(c.name)),
                            c.name << (shipped ? " is shipped but not accepted"
                                               : " is accepted but still planned"));
        // Task 0 is the earlier specs' commands, all shipped; a planned
        // command names the task that ships it, and keeps naming it after.
        BOOST_CHECK_MESSAGE(shipped || c.task != 0,
                            c.name << ": a planned command names the task that ships it");
    }
}

// Redis's own invariants on COMMAND INFO values, so `COMMAND` can be
// answered from the table.
BOOST_AUTO_TEST_CASE(metadata_is_consistent) {
    for (const auto& c : k_redis_commands) {
        BOOST_TEST_CONTEXT(c.name) {
            const auto has_flag = [&](std::uint32_t f) { return (c.flags & f) != 0U; };
            const auto in_category = [&](std::uint32_t k) { return (c.acl_categories & k) != 0U; };
            BOOST_CHECK(!(has_flag(flag::write) && has_flag(flag::readonly)));
            if (has_flag(flag::write)) {
                BOOST_CHECK(in_category(cat::write));
            }
            if (has_flag(flag::readonly)) {
                BOOST_CHECK(in_category(cat::read));
            }
            BOOST_CHECK_EQUAL(has_flag(flag::fast), in_category(cat::fast));
            BOOST_CHECK(!(in_category(cat::fast) && in_category(cat::slow)));
            BOOST_CHECK(c.arity != 0);
            if (c.first_key > 0) {
                // The first key is an argument the arity guarantees.
                BOOST_CHECK_LT(c.first_key, c.arity > 0 ? c.arity : -c.arity);
                BOOST_CHECK(c.last_key == -1 || c.last_key >= c.first_key);
                BOOST_CHECK_GE(c.step, 1);
            } else {
                BOOST_CHECK_EQUAL(c.last_key, 0);
                BOOST_CHECK_EQUAL(c.step, 0);
            }
        }
    }
}

// Every id ever issued keeps its command. The golden file is append-only:
// an existing line that changed or vanished fails even when regenerating.
BOOST_AUTO_TEST_CASE(command_ids_never_change) {
    std::ostringstream body;
    body << "# Every Redis command id ever issued (services/redis/tools/redis_commands.yaml).\n"
            "# Append-only: an id is never renumbered or reused, because format-0x03\n"
            "# log records carry it. Regenerate with KYTHIRA_UPDATE_GOLDENS=1 to add lines.\n";
    std::map<std::uint16_t, std::string> by_id;
    for (const auto& c : k_redis_commands) {
        by_id.emplace(c.id, std::string(c.name));
    }
    for (const auto& r : kythira::k_redis_retired_commands) {
        BOOST_CHECK_MESSAGE(by_id.emplace(r.id, std::string(r.name)).second,
                            "retired id " << r.id << " is still in use");
    }
    for (const auto& [id, name] : by_id) {
        body << id << ' ' << name << '\n';
    }

    const auto path = kythira::testing::golden::golden_dir() / "command_ids.txt";
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream fields(line);
        unsigned id = 0;
        std::string name;
        fields >> id >> name;
        const auto it = by_id.find(static_cast<std::uint16_t>(id));
        BOOST_CHECK_MESSAGE(it != by_id.end() && it->second == name,
                            "command id " << id << " was issued to " << name
                                          << "; it may never change (retire it instead)");
    }
    kythira::testing::golden::check_golden("command_ids.txt", body.str());
}
