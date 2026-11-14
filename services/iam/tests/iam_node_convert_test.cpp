// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// `iam_node --convert-data-dir` (.kiro/specs/service-colocation/ task 8b,
// convert_data_dir.hpp): a member's state in the plain Raft group's layout
// moves into the IAM group's on the multi-raft host whole: the snapshot,
// every entry after it, the term and the vote. The IAM state rebuilt from
// the converted files is the state the old ones held; the old files are
// kept aside; a directory is converted once; a log with a hole is refused
// before anything moves.

#define BOOST_TEST_MODULE iam_node_convert_test
#include <boost/test/unit_test.hpp>

#include "convert_data_dir.hpp"

#include <kythira/iam/iam_raft.hpp>
#include <kythira/iam/iam_state_machine.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/file_persistence.hpp>
#include <raft/host_node_id.hpp>
#include <raft/private_file.hpp>

#include <boost/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace iam = kythira::iam;
namespace leader = kythira::iam::iam_leader;
using node_id = kythira::host_node_id;
using old_engine = kythira::file_persistence_engine<node_id>;
using new_engine = kythira::binary_file_persistence_engine<node_id>;
using entry = old_engine::log_entry_t;

auto id(int n) -> node_id {
    return kythira::parse_host_node_id(std::to_string(n)).value();
}

// The first account carries the cluster's KEK salt, as the admin route
// sends it.
auto create_account(const std::string& account, bool first = false) -> std::vector<std::byte> {
    boost::json::object body{{"account", account}};
    if (first) {
        body["kek_salt"] = "c2FsdHNhbHRzYWx0c2FsdA";
    }
    return leader::command(iam::iam_command::create_account, std::move(body), 1700000000);
}

auto has_account(const iam::iam_state_machine& sm, const std::string& account) -> bool {
    return sm.account(account) != nullptr;
}

struct temp_dir {
    temp_dir() : path(raft::make_private_temp_directory(fs::temp_directory_path(), "iam-conv-")) {}
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    fs::path path;
};

// A member of a three-voter group in the old layout: a snapshot at index
// 2 holding one account, then entries 3 and 4 creating two more.
void write_old_member(const fs::path& dir) {
    iam::iam_state_machine sm(iam::iam_config{});
    (void)sm.apply(create_account("111122223333", true), 1);
    (void)sm.apply(create_account("222233334444"), 2);
    old_engine old(dir);
    old_engine::snapshot_t snap{};
    snap._last_included_index = 2;
    snap._last_included_term = 1;
    snap._configuration =
        kythira::cluster_configuration<node_id>{{id(1), id(2), id(3)}, false, std::nullopt, {}};
    snap._state_machine_state = sm.get_state();
    old.save_snapshot(snap);
    old.append_log_entry(entry{2, 3, create_account("333344445555")});
    old.append_log_entry(entry{3, 4, create_account("444455556666")});
    old.save_hard_state(3, id(2));
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_whole_raft_state_moves_and_rebuilds_the_same_iam_state) {
    temp_dir d;
    write_old_member(d.path);
    BOOST_TEST(iam_node::has_unconverted_state(d.path));

    const auto done = iam_node::convert_data_dir(d.path);
    BOOST_TEST(done.snapshot_index == 2U);
    BOOST_TEST(done.first_entry == 3U);
    BOOST_TEST(done.last_entry == 4U);
    BOOST_TEST(done.term == 3U);
    BOOST_TEST(!iam_node::has_unconverted_state(d.path));

    // The new layout, where the IAM group's host opens it.
    new_engine fresh(iam::iam_raft_dir(d.path) / std::to_string(iam::k_iam_group_id));
    BOOST_TEST(fresh.load_current_term() == 3U);
    BOOST_TEST((fresh.load_voted_for() == std::optional<node_id>(id(2))));
    const auto snap = fresh.load_snapshot();
    BOOST_REQUIRE(snap.has_value());
    BOOST_TEST(snap->_last_included_index == 2U);
    BOOST_TEST(snap->_last_included_term == 1U);
    BOOST_TEST(snap->_configuration.nodes().size() == 3U);
    BOOST_TEST(fresh.get_last_log_index() == 4U);

    // Restoring the snapshot and applying the entries gives every account.
    iam::iam_state_machine sm(iam::iam_config{});
    sm.restore_from_snapshot(snap->_state_machine_state, snap->_last_included_index);
    for (const auto& e : fresh.get_log_entries(3, 4)) {
        (void)sm.apply(e.command(), e.index());
    }
    for (const auto* account : {"111122223333", "222233334444", "333344445555", "444455556666"}) {
        BOOST_TEST(has_account(sm, account), account);
    }

    // The old files are kept aside, and a second run refuses.
    for (const auto* name : iam_node::k_old_layout_files) {
        BOOST_TEST(!fs::exists(d.path / name), name);
    }
    BOOST_TEST(fs::exists(d.path / "pre-host" / "snapshot"));
    BOOST_TEST(fs::exists(d.path / "pre-host" / "log"));
    BOOST_CHECK_THROW((void)iam_node::convert_data_dir(d.path), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(a_log_with_a_hole_is_refused_before_anything_moves) {
    temp_dir d;
    {
        old_engine old(d.path);
        old.append_log_entry(entry{1, 1, create_account("111122223333", true)});
        old.append_log_entry(entry{1, 3, create_account("333344445555")});
        old.save_current_term(1);
    }
    BOOST_CHECK_THROW((void)iam_node::convert_data_dir(d.path), std::runtime_error);
    BOOST_TEST(!fs::exists(iam::iam_raft_dir(d.path)));
    BOOST_TEST(fs::exists(d.path / "log"));
    BOOST_TEST(iam_node::has_unconverted_state(d.path));
}

BOOST_AUTO_TEST_CASE(nothing_to_convert_is_an_error) {
    temp_dir d;
    BOOST_TEST(!iam_node::has_unconverted_state(d.path));
    BOOST_CHECK_THROW((void)iam_node::convert_data_dir(d.path), std::runtime_error);
}
