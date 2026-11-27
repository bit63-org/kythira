// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file witness_configuration_unit_test.cpp
/// @brief Witnesses and lagging members in stored configurations
///        (.kiro/specs/khold-block-service/ tasks 4 and 5): configuration log
///        entries and snapshots carry `witnesses()` and `lagging()`, and a
///        configuration with neither is stored byte for byte as it was before
///        they existed, so stores written by either version open in the
///        other.

#define BOOST_TEST_MODULE witness_configuration_unit_test
#include <boost/test/unit_test.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/config_entry.hpp>
#include <raft/file_persistence.hpp>
#include <raft/types.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace {

using config_t = kythira::cluster_configuration<std::uint64_t>;
using snapshot_t = kythira::snapshot<std::uint64_t, std::uint64_t, std::uint64_t>;

struct temp_dir {
    std::filesystem::path path;
    temp_dir() {
        std::random_device rd;
        path = std::filesystem::temp_directory_path() /
               ("witness_cfg_" + std::to_string(rd()) + "_" + std::to_string(rd()));
        std::filesystem::create_directories(path);
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
};

auto with_witness() -> config_t {
    config_t c{{1, 2, 3}, false, std::nullopt, {7}};
    c._witnesses = {3};
    return c;
}

auto text(const std::vector<std::byte>& b) -> std::string {
    std::string s;
    for (auto x : b) {
        s.push_back(static_cast<char>(x));
    }
    return s;
}

auto snapshot_of(const config_t& c) -> snapshot_t {
    return snapshot_t{._last_included_index = 10,
                      ._last_included_term = 2,
                      ._configuration = c,
                      ._state_machine_state = {std::byte{0xCA}, std::byte{0xFE}}};
}

template<typename Engine> auto snapshot_round_trip(const config_t& c) -> config_t {
    temp_dir d;
    {
        Engine e(d.path);
        e.save_snapshot(snapshot_of(c));
    }
    Engine reopened(d.path);
    auto s = reopened.load_snapshot();
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST((s->state_machine_state() == snapshot_of(c).state_machine_state()));
    return s->configuration();
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_configuration_entry_carries_its_witnesses) {
    const auto c = with_witness();
    const auto back =
        kythira::deserialize_configuration<std::uint64_t>(kythira::serialize_configuration(c));
    BOOST_TEST(back.nodes() == c.nodes());
    BOOST_TEST(back.learners() == c.learners());
    BOOST_TEST(back.witnesses() == c.witnesses());

    // Joint: a witness leaving is still marked while it is an old voter.
    config_t joint{{1, 2, 4}, true, std::vector<std::uint64_t>{1, 2, 3}, {}};
    joint._witnesses = {3, 4};
    const auto jb =
        kythira::deserialize_configuration<std::uint64_t>(kythira::serialize_configuration(joint));
    BOOST_TEST(jb.witnesses() == joint.witnesses());
    BOOST_TEST(jb.is_joint_consensus());
}

BOOST_AUTO_TEST_CASE(a_configuration_without_witnesses_encodes_as_before) {
    const config_t c{{1, 2, 3}, false, std::nullopt, {}};
    const auto s = text(kythira::serialize_configuration(c));
    BOOST_TEST(s.find("witnesses") == std::string::npos);
    // An entry written before witnesses existed decodes with none.
    const std::string old = R"({"nodes":[1,2,3],"is_joint_consensus":false,"learners":[]})";
    std::vector<std::byte> bytes;
    for (char ch : old) {
        bytes.push_back(static_cast<std::byte>(ch));
    }
    BOOST_TEST(kythira::deserialize_configuration<std::uint64_t>(bytes).witnesses().empty());
}

BOOST_AUTO_TEST_CASE(snapshots_carry_witnesses) {
    const auto c = with_witness();
    const auto file = snapshot_round_trip<kythira::file_persistence_engine<>>(c);
    BOOST_TEST(file.witnesses() == c.witnesses());
    BOOST_TEST(file.learners() == c.learners());
    const auto binary = snapshot_round_trip<kythira::binary_file_persistence_engine<>>(c);
    BOOST_TEST(binary.witnesses() == c.witnesses());
    BOOST_TEST(binary.learners() == c.learners());
}

BOOST_AUTO_TEST_CASE(snapshots_without_witnesses_are_unchanged) {
    const config_t c{{1, 2, 3}, false, std::nullopt, {9}};
    BOOST_TEST(snapshot_round_trip<kythira::file_persistence_engine<>>(c).witnesses().empty());
    BOOST_TEST(
        snapshot_round_trip<kythira::binary_file_persistence_engine<>>(c).witnesses().empty());

    // The binary snapshot of a configuration without witnesses ends with
    // the state, exactly as the format had it before: adding a witness is
    // the only thing that adds bytes.
    temp_dir a;
    temp_dir b;
    {
        kythira::binary_file_persistence_engine<> e(a.path);
        e.save_snapshot(snapshot_of(c));
    }
    {
        auto w = c;
        w._witnesses = {3};
        kythira::binary_file_persistence_engine<> e(b.path);
        e.save_snapshot(snapshot_of(w));
    }
    const auto size_of = [](const std::filesystem::path& dir) {
        std::uintmax_t total = 0;
        for (const auto& f : std::filesystem::directory_iterator(dir)) {
            if (f.path().filename().string().starts_with("snapshot")) {
                total += f.file_size();
            }
        }
        return total;
    };
    BOOST_TEST(size_of(b.path) > size_of(a.path));
}

BOOST_AUTO_TEST_CASE(lagging_members_are_stored_with_or_without_witnesses) {
    // With a witness: the general shape with its other data replica lagging.
    auto general = with_witness();
    general._lagging = {2};
    const auto back = kythira::deserialize_configuration<std::uint64_t>(
        kythira::serialize_configuration(general));
    BOOST_TEST(back.lagging() == general.lagging());
    BOOST_TEST(back.witnesses() == general.witnesses());
    for (const auto& c : {general, [] {
                              // Without one: the binary snapshot writes an empty
                              // witness list so the lagging list can follow it.
                              config_t p{{1, 2, 3}, false, std::nullopt, {}};
                              p._lagging = {3};
                              return p;
                          }()}) {
        const auto file = snapshot_round_trip<kythira::file_persistence_engine<>>(c);
        BOOST_TEST(file.lagging() == c.lagging());
        BOOST_TEST(file.witnesses() == c.witnesses());
        const auto binary = snapshot_round_trip<kythira::binary_file_persistence_engine<>>(c);
        BOOST_TEST(binary.lagging() == c.lagging());
        BOOST_TEST(binary.witnesses() == c.witnesses());
    }
    // Neither key appears without lagging members.
    BOOST_TEST(text(kythira::serialize_configuration(with_witness())).find("lagging") ==
               std::string::npos);
}
