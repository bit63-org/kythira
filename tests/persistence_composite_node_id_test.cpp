// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE persistence_composite_node_id_test
#include <boost/test/unit_test.hpp>

#include "mock_object_store.hpp"

#include <raft/composite_node_id.hpp>
#include <raft/file_persistence.hpp>
#include <raft/object_persistence_options.hpp>
#include <raft/object_store_persistence.hpp>
#include <raft/persistence.hpp>
#include <raft/persistence_node_id.hpp>
#include <raft/types.hpp>

#include <boost/json.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include <unistd.h>

// Composite cloud node ids in the file and object-store persistence engines
// (`.kiro/specs/cloud-composite-node-ids/` task 5.4's open item). Both engines
// stored a node id as a number unless it was `std::string`, so neither
// compiled with a composite `NodeId`. They now store a composite id as its
// canonical text through `persistence_node_id`, and read it back through the
// type's strict `parse`. The numeric and `std::string` cases below pin that
// the formats already on disk did not change.

namespace {

namespace fs = std::filesystem;
namespace pni = kythira::persistence_node_id;

using aws_id = kythira::aws_ec2_node_id;
using gcp_id = kythira::gcp_instance_node_id;

auto aws(std::string_view text) -> aws_id {
    auto id = aws_id::parse(text);
    BOOST_REQUIRE_MESSAGE(id.has_value(), "test id does not parse: " << text);
    return *id;
}

const std::string k_a = "aws-ec2:us-east-1:i-0123456789abcdef0";
const std::string k_b = "aws-ec2:us-east-1:i-1234abcd";
const std::string k_c = "aws-ec2:eu-west-2:i-0fedcba9876543210";

struct temp_dir {
    fs::path path;
    explicit temp_dir(const char* tag) {
        path = fs::temp_directory_path() / (std::string("kythira_pcni_") + tag + "_" +
                                            std::to_string(static_cast<unsigned>(::getpid())));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

auto read_all(const fs::path& p) -> std::string {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

auto write_all(const fs::path& p, const std::string& body) -> void {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << body;
}

template<typename NodeId>
auto make_snapshot(std::vector<NodeId> nodes, std::optional<std::vector<NodeId>> old_nodes,
                   std::vector<NodeId> learners = {}) -> kythira::snapshot<NodeId> {
    kythira::snapshot<NodeId> snap;
    snap._last_included_index = 42;
    snap._last_included_term = 7;
    snap._state_machine_state = {std::byte{0x01}, std::byte{0xFF}};
    snap._configuration._nodes = std::move(nodes);
    snap._configuration._is_joint_consensus = old_nodes.has_value();
    snap._configuration._old_nodes = std::move(old_nodes);
    snap._configuration._learners = std::move(learners);
    return snap;
}

template<typename NodeId>
auto check_same_snapshot(const kythira::snapshot<NodeId>& got,
                         const kythira::snapshot<NodeId>& want) -> void {
    BOOST_TEST(got.last_included_index() == want.last_included_index());
    BOOST_TEST(got.last_included_term() == want.last_included_term());
    BOOST_CHECK(got.state_machine_state() == want.state_machine_state());
    BOOST_CHECK(got.configuration().nodes() == want.configuration().nodes());
    BOOST_TEST(got.configuration().is_joint_consensus() ==
               want.configuration().is_joint_consensus());
    BOOST_CHECK(got.configuration().old_nodes() == want.configuration().old_nodes());
    BOOST_CHECK(got.configuration().learners() == want.configuration().learners());
}

}  // namespace

// ── The codec ─────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(codec)

BOOST_AUTO_TEST_CASE(numeric_ids_stay_json_integers) {
    const auto v = pni::to_json<std::uint64_t>(18446744073709551615ULL);
    BOOST_TEST(boost::json::serialize(v) == "18446744073709551615");
    BOOST_CHECK(pni::from_json<std::uint64_t>(v) == 18446744073709551615ULL);
    BOOST_CHECK(pni::from_json<std::uint64_t>(boost::json::value(7)) == 7U);
    // Out of range for the type, negative, and a string are refused.
    BOOST_CHECK(!pni::from_json<std::uint32_t>(v).has_value());
    BOOST_CHECK(!pni::from_json<std::uint64_t>(boost::json::value(-1)).has_value());
    BOOST_CHECK(!pni::from_json<std::uint64_t>(boost::json::value("7")).has_value());
}

BOOST_AUTO_TEST_CASE(string_ids_stay_json_strings_including_empty) {
    BOOST_TEST(boost::json::serialize(pni::to_json(std::string("n1"))) == "\"n1\"");
    BOOST_CHECK(pni::from_json<std::string>(boost::json::value("n1")) == std::string("n1"));
    BOOST_CHECK(pni::from_json<std::string>(boost::json::value("")) == std::string());
    BOOST_CHECK(!pni::from_json<std::string>(boost::json::value(1)).has_value());
}

BOOST_AUTO_TEST_CASE(composite_ids_are_canonical_text) {
    const auto id = aws(k_a);
    BOOST_TEST(pni::to_text(id) == k_a);
    BOOST_TEST(boost::json::serialize(pni::to_json(id)) == "\"" + k_a + "\"");
    BOOST_CHECK(pni::from_json<aws_id>(pni::to_json(id)) == id);
    BOOST_CHECK(pni::from_text<aws_id>(k_a) == id);
}

BOOST_AUTO_TEST_CASE(composite_ids_refuse_what_parse_refuses) {
    // Another provider's id, a malformed one, an empty one, and a number.
    BOOST_CHECK(!pni::from_text<aws_id>("gcp:proj/us-central1-a:n1").has_value());
    BOOST_CHECK(!pni::from_text<aws_id>("aws-ec2:us-east-1:").has_value());
    BOOST_CHECK(!pni::from_text<aws_id>("").has_value());
    BOOST_CHECK(!pni::from_json<aws_id>(boost::json::value(3)).has_value());
    BOOST_CHECK(!pni::from_json<gcp_id>(boost::json::value(k_a)).has_value());
}

BOOST_AUTO_TEST_SUITE_END()

// ── file_persistence_engine ───────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(file_engine)

using file_engine_t = kythira::file_persistence_engine<aws_id>;

BOOST_AUTO_TEST_CASE(engine_satisfies_the_persistence_concept) {
    static_assert(kythira::persistence_engine<file_engine_t, aws_id, std::uint64_t, std::uint64_t,
                                              kythira::log_entry<std::uint64_t, std::uint64_t>,
                                              kythira::snapshot<aws_id>>);
    static_assert(kythira::hard_state_persistence_engine<file_engine_t>);
}

BOOST_AUTO_TEST_CASE(vote_is_stored_as_canonical_text_and_survives_reload,
                     *boost::unit_test::timeout(10)) {
    temp_dir d("file_vote");
    {
        file_engine_t eng(d.path);
        eng.save_voted_for(aws(k_a));
        BOOST_CHECK(eng.load_voted_for() == aws(k_a));
    }
    BOOST_TEST(read_all(d.path / "voted_for") == k_a);
    file_engine_t eng(d.path);
    BOOST_CHECK(eng.load_voted_for() == aws(k_a));
}

BOOST_AUTO_TEST_CASE(hard_state_round_trips_a_vote_and_no_vote, *boost::unit_test::timeout(10)) {
    temp_dir d("file_hard");
    {
        file_engine_t eng(d.path);
        eng.save_hard_state(5, aws(k_b));
    }
    {
        file_engine_t eng(d.path);
        BOOST_TEST(eng.load_current_term() == 5U);
        BOOST_CHECK(eng.load_voted_for() == aws(k_b));
        eng.save_hard_state(6, std::nullopt);
    }
    file_engine_t eng(d.path);
    BOOST_TEST(eng.load_current_term() == 6U);
    BOOST_CHECK(!eng.load_voted_for().has_value());
}

BOOST_AUTO_TEST_CASE(joint_snapshot_survives_reload, *boost::unit_test::timeout(10)) {
    temp_dir d("file_snap");
    const auto snap = make_snapshot<aws_id>({aws(k_a), aws(k_b), aws(k_c)},
                                            std::vector<aws_id>{aws(k_a), aws(k_b)});
    {
        file_engine_t eng(d.path);
        eng.save_snapshot(snap);
    }
    const auto body = boost::json::parse(read_all(d.path / "snapshot")).as_object();
    BOOST_TEST(boost::json::serialize(body.at("nodes")) ==
               "[\"" + k_a + "\",\"" + k_b + "\",\"" + k_c + "\"]");
    file_engine_t eng(d.path);
    const auto loaded = eng.load_snapshot();
    BOOST_REQUIRE(loaded.has_value());
    check_same_snapshot(*loaded, snap);
}

BOOST_AUTO_TEST_CASE(snapshot_naming_another_provider_is_refused, *boost::unit_test::timeout(10)) {
    temp_dir d("file_bad");
    {
        file_engine_t eng(d.path);
        eng.save_snapshot(make_snapshot<aws_id>({aws(k_a)}, std::nullopt));
    }
    auto body = boost::json::parse(read_all(d.path / "snapshot")).as_object();
    body["nodes"] = boost::json::array{boost::json::string("gcp:proj/us-central1-a:n1")};
    write_all(d.path / "snapshot", boost::json::serialize(body));
    // This engine treats every unreadable file at load as absent, as it does
    // for a truncated one; the point is that the member is refused, not read
    // as some other node.
    file_engine_t eng(d.path);
    BOOST_CHECK(!eng.load_snapshot().has_value());
}

BOOST_AUTO_TEST_CASE(numeric_and_string_formats_are_unchanged, *boost::unit_test::timeout(10)) {
    temp_dir dn("file_num");
    {
        kythira::file_persistence_engine<> eng(dn.path);
        eng.save_voted_for(3);
        eng.save_snapshot(make_snapshot<std::uint64_t>({1, 2, 3}, std::vector<std::uint64_t>{1}));
    }
    BOOST_TEST(read_all(dn.path / "voted_for") == "3");
    const auto num = boost::json::parse(read_all(dn.path / "snapshot")).as_object();
    BOOST_TEST(boost::json::serialize(num.at("nodes")) == "[1,2,3]");
    BOOST_TEST(boost::json::serialize(num.at("old_nodes")) == "[1]");

    temp_dir ds("file_str");
    {
        kythira::file_persistence_engine<std::string> eng(ds.path);
        eng.save_voted_for("n2");
        eng.save_snapshot(make_snapshot<std::string>({"n1", "n2"}, std::nullopt));
    }
    BOOST_TEST(read_all(ds.path / "voted_for") == "n2");
    const auto str = boost::json::parse(read_all(ds.path / "snapshot")).as_object();
    BOOST_TEST(boost::json::serialize(str.at("nodes")) == "[\"n1\",\"n2\"]");
    kythira::file_persistence_engine<std::string> eng(ds.path);
    BOOST_CHECK(eng.load_voted_for() == std::string("n2"));
}

// Learners used to be dropped from this engine's snapshots, so a node restarted
// from one forgot every learner whose config entry had been compacted.
BOOST_AUTO_TEST_CASE(snapshot_learners_survive_reload, *boost::unit_test::timeout(10)) {
    temp_dir d("file_learn");
    const auto snap = make_snapshot<aws_id>({aws(k_a), aws(k_b)}, std::nullopt, {aws(k_c)});
    {
        file_engine_t eng(d.path);
        eng.save_snapshot(snap);
    }
    file_engine_t eng(d.path);
    const auto loaded = eng.load_snapshot();
    BOOST_REQUIRE(loaded.has_value());
    check_same_snapshot(*loaded, snap);

    // Without learners the record carries no member for them, as before.
    temp_dir dn("file_nolearn");
    {
        kythira::file_persistence_engine<> num(dn.path);
        num.save_snapshot(make_snapshot<std::uint64_t>({1, 2}, std::nullopt));
    }
    BOOST_TEST(
        !boost::json::parse(read_all(dn.path / "snapshot")).as_object().contains("learners"));
}

BOOST_AUTO_TEST_SUITE_END()

// ── object_store_persistence_engine ───────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(object_store_engine)

using store_t = kythira::mock_object_store;
using os_engine_t = kythira::object_store_persistence_engine<store_t, aws_id>;

auto options(kythira::hard_state_layout layout) -> kythira::object_persistence_options {
    kythira::object_persistence_options opts;
    opts.hard_state = layout;
    return opts;
}

BOOST_AUTO_TEST_CASE(engine_satisfies_the_persistence_concept) {
    static_assert(kythira::persistence_engine<os_engine_t, aws_id, std::uint64_t, std::uint64_t,
                                              kythira::log_entry<std::uint64_t, std::uint64_t>,
                                              kythira::snapshot<aws_id>>);
}

BOOST_AUTO_TEST_CASE(separate_layout_vote_is_canonical_text, *boost::unit_test::timeout(10)) {
    store_t store;
    {
        os_engine_t eng{store, "kythira", "raft"};
        eng.save_hard_state(4, aws(k_a));
    }
    BOOST_TEST(store.body("raft/voted_for") == k_a);
    BOOST_TEST(store.body("raft/term") == "4");
    os_engine_t eng{store, "kythira", "raft"};
    BOOST_TEST(eng.load_current_term() == 4U);
    BOOST_CHECK(eng.load_voted_for() == aws(k_a));
}

BOOST_AUTO_TEST_CASE(combined_layout_vote_is_a_json_string, *boost::unit_test::timeout(10)) {
    store_t store;
    const auto opts = options(kythira::hard_state_layout::combined);
    {
        os_engine_t eng{store, "kythira", "raft", opts};
        eng.save_hard_state(9, aws(k_b));
    }
    BOOST_TEST(store.body("raft/term") == "{\"term\":9,\"voted_for\":\"" + k_b + "\"}");
    os_engine_t eng{store, "kythira", "raft", opts};
    BOOST_TEST(eng.load_current_term() == 9U);
    BOOST_CHECK(eng.load_voted_for() == aws(k_b));
}

BOOST_AUTO_TEST_CASE(a_vote_this_type_cannot_read_is_corruption, *boost::unit_test::timeout(10)) {
    // Legacy layout: another provider's id in the vote object. Read as "no
    // vote", it would let this node vote twice in the term.
    {
        store_t store;
        store.seed("raft/term", "4");
        store.seed("raft/voted_for", "gcp:proj/us-central1-a:n1");
        BOOST_CHECK_THROW((os_engine_t{store, "kythira", "raft"}), std::exception);
    }
    // Combined layout: the same in the record.
    {
        store_t store;
        store.seed("raft/term", "{\"term\":4,\"voted_for\":\"aws-ec2:us-east-1:\"}");
        BOOST_CHECK_THROW(
            (os_engine_t{store, "kythira", "raft", options(kythira::hard_state_layout::combined)}),
            std::exception);
    }
}

BOOST_AUTO_TEST_CASE(joint_snapshot_survives_reload, *boost::unit_test::timeout(10)) {
    store_t store;
    const auto snap =
        make_snapshot<aws_id>({aws(k_a), aws(k_b), aws(k_c)}, std::vector<aws_id>{aws(k_c)});
    {
        os_engine_t eng{store, "kythira", "raft"};
        eng.save_snapshot(snap);
    }
    const auto body = boost::json::parse(store.body("raft/snapshot")).as_object();
    BOOST_TEST(boost::json::serialize(body.at("old_nodes")) == "[\"" + k_c + "\"]");
    os_engine_t eng{store, "kythira", "raft"};
    const auto loaded = eng.load_snapshot();
    BOOST_REQUIRE(loaded.has_value());
    check_same_snapshot(*loaded, snap);
}

BOOST_AUTO_TEST_CASE(snapshot_learners_survive_reload, *boost::unit_test::timeout(10)) {
    store_t store;
    const auto snap = make_snapshot<aws_id>({aws(k_a)}, std::nullopt, {aws(k_b), aws(k_c)});
    {
        os_engine_t eng{store, "kythira", "raft"};
        eng.save_snapshot(snap);
    }
    const auto body = boost::json::parse(store.body("raft/snapshot")).as_object();
    BOOST_TEST(boost::json::serialize(body.at("learners")) == "[\"" + k_b + "\",\"" + k_c + "\"]");
    os_engine_t eng{store, "kythira", "raft"};
    const auto loaded = eng.load_snapshot();
    BOOST_REQUIRE(loaded.has_value());
    check_same_snapshot(*loaded, snap);
}

BOOST_AUTO_TEST_CASE(numeric_records_are_unchanged, *boost::unit_test::timeout(10)) {
    store_t store;
    const auto opts = options(kythira::hard_state_layout::combined);
    {
        kythira::object_store_persistence_engine<store_t> eng{store, "kythira", "raft", opts};
        eng.save_hard_state(2, std::uint64_t{17});
        eng.save_snapshot(make_snapshot<std::uint64_t>({17, 18}, std::nullopt));
    }
    BOOST_TEST(store.body("raft/term") == "{\"term\":2,\"voted_for\":17}");
    const auto body = boost::json::parse(store.body("raft/snapshot")).as_object();
    BOOST_TEST(boost::json::serialize(body.at("nodes")) == "[17,18]");
    BOOST_TEST(!body.contains("learners"));
}

BOOST_AUTO_TEST_SUITE_END()
