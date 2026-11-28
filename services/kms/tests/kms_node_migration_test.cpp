// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Moving a running KMS between layouts (.kiro/specs/kms-independent-layers/
// task 6, Requirements 10.1-10.3, 11.2), as kms_node processes over
// SoftHSM2 with mutual TLS (kms_process_cluster.hpp). One test per path,
// each in both directions, under a workload of key administration and
// encryption; after every step each test checks Requirement 10.3:
//
//   * every key made so far is described with its last committed
//     description (no committed key, version or policy change lost);
//   * every ciphertext made before any step decrypts;
//   * a key disabled before the move is refused for encryption at every
//     step after its disable committed.
//
// Paths:
//   * the gateway role: a gateway alone takes the clients, the co-located
//     members drop the gateway one restart at a time, and back;
//   * the front-end role with the job lease: two gateway and front-end
//     nodes take over, the members restart as data nodes (the lease moves
//     with the drain of its holder), and back;
//   * the data role: three co-located members hand the catalog to three
//     data-only nodes (learner, promote, leadership transfer, remove, one
//     member at a time through POST /v1/kms/membership/evacuate), restart
//     as gateways and front ends, and then take it back;
//   * the whole co-located to split path, stopped part-way and reversed.

#define BOOST_TEST_MODULE kms_node_migration_test

#include "kms_process_cluster.hpp"

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace kms_process_testing;  // NOLINT(google-build-using-namespace)

namespace {

/// What the workload has made, and checks that it is all still there.
class workload {
public:
    explicit workload(process_cluster& c) : _c(c) {}

    /// A key with a description and a ciphertext under it, through member
    /// `via`; the first call also makes the key that is disabled.
    void add(std::size_t via, const std::string& label) {
        const auto k = _c.call(via, "CreateKey", R"({"Description":")" + label + R"("})");
        BOOST_REQUIRE_MESSAGE(k.status == 200, label << ": CreateKey " << k.status << " " << k.raw);
        entry e;
        e.id = std::string(k.body.at("KeyMetadata").as_object().at("KeyId").as_string());
        e.description = label;
        const auto enc =
            _c.call(via, "Encrypt", R"({"KeyId":")" + e.id + R"(","Plaintext":"bWlncmF0aW9u"})");
        BOOST_REQUIRE_MESSAGE(enc.status == 200, label << ": Encrypt " << enc.raw);
        e.ciphertext = enc.str("CiphertextBlob");
        // A committed change to the key, which must survive too.
        const auto upd =
            _c.call(via, "UpdateKeyDescription",
                    R"({"KeyId":")" + e.id + R"(","Description":")" + label + R"x( (updated)"})x");
        BOOST_REQUIRE_MESSAGE(upd.status == 200, label << ": UpdateKeyDescription " << upd.raw);
        e.description = label + " (updated)";
        _keys.push_back(std::move(e));
        if (!_disabled) {
            const auto d = _c.call(via, "CreateKey", R"({"Description":"disabled"})");
            BOOST_REQUIRE_MESSAGE(d.status == 200, "CreateKey " << d.raw);
            _disabled = std::string(d.body.at("KeyMetadata").as_object().at("KeyId").as_string());
            const auto off = _c.call(via, "DisableKey", R"({"KeyId":")" + *_disabled + R"("})");
            BOOST_REQUIRE_MESSAGE(off.status == 200, "DisableKey " << off.raw);
        }
    }

    /// Requirement 10.3 through member `via`.
    void check(std::size_t via, std::string_view step) {
        BOOST_TEST_CONTEXT("after " << step << ", through member " << via + 1) {
            for (const auto& e : _keys) {
                const auto d = _c.call(via, "DescribeKey", R"({"KeyId":")" + e.id + R"("})");
                BOOST_REQUIRE_MESSAGE(d.status == 200, "DescribeKey " << d.status << " " << d.raw);
                BOOST_TEST(d.body.at("KeyMetadata").as_object().at("Description").as_string() ==
                           e.description);
                const auto p =
                    _c.call(via, "Decrypt", R"({"CiphertextBlob":")" + e.ciphertext + R"("})");
                BOOST_REQUIRE_MESSAGE(p.status == 200, "Decrypt " << p.status << " " << p.raw);
                BOOST_TEST(p.str("Plaintext") == "bWlncmF0aW9u");
            }
            if (_disabled) {
                const auto r = _c.call(via, "Encrypt",
                                       R"({"KeyId":")" + *_disabled + R"(","Plaintext":"eA=="})");
                BOOST_TEST(r.str("__type") == "DisabledException", r.status << " " << r.raw);
            }
        }
    }

private:
    struct entry {
        std::string id;
        std::string description;
        std::string ciphertext;
    };

    process_cluster& _c;
    std::vector<entry> _keys;
    std::optional<std::string> _disabled;
};

/// Waits until a running data node reports, as the catalog's leader, that
/// the job evacuating `evacuee` (1-based id) is done; false after 60 s.
auto await_evacuated(process_cluster& c, const std::vector<std::size_t>& data_nodes,
                     std::size_t evacuee) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + 60s;
    while (std::chrono::steady_clock::now() < deadline) {
        for (const auto i : data_nodes) {
            if (!c.running(i)) {
                continue;
            }
            const auto s = c.as_member(i, "GET", "/v1/kms/membership/evacuate");
            if (s.status != 200) {
                continue;
            }
            const auto* job = s.body.if_contains("job");
            const bool ours = job != nullptr && job->is_object() &&
                              job->as_object().at("node").as_string() == std::to_string(evacuee);
            if (ours && s.body.at("leader").as_bool() && s.body.at("done").as_bool()) {
                return true;
            }
        }
        std::this_thread::sleep_for(200ms);
    }
    return false;
}

/// Moves member `evacuee`'s (0-based) catalog replica onto `targets`
/// (0-based), asking data node `via`, and waits for it.
void evacuate(process_cluster& c, std::size_t via, std::size_t evacuee,
              const std::vector<std::size_t>& targets, const std::vector<std::size_t>& data_nodes) {
    std::string list;
    for (const auto t : targets) {
        list += (list.empty() ? "\"" : ",\"") + std::to_string(t + 1) + "\"";
    }
    const auto r = c.as_member(via, "POST", "/v1/kms/membership/evacuate",
                               R"({"node":")" + std::to_string(evacuee + 1) + R"(","targets":[)" +
                                   list + R"(],"replicas":3})");
    BOOST_REQUIRE_MESSAGE(r.status == 200, "evacuate " << evacuee + 1 << ": " << r.raw);
    BOOST_REQUIRE_MESSAGE(await_evacuated(c, data_nodes, evacuee + 1),
                          "member " << evacuee + 1 << " still holds a catalog seat");
}

/// The catalog's voter count as member i's replica holds it.
auto voters_on(const process_cluster& c, std::size_t i) -> double {
    return c.metric(i, "catalog_voters").value_or(-1);
}

auto voters_spec() -> std::string {
    return "KYTHIRA_KMS_VOTERS=1,2,3";
}

/// Waits up to 30 s for member i's metric `name` to read `want`.
auto await_metric(const process_cluster& c, std::size_t i, std::string_view name, double want)
    -> bool {
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (c.metric(i, name) == want) {
            return true;
        }
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

/// Three co-located members (1-3), the founding voters, and the members
/// `later` describes (4 on), which start when the test says.
struct layout_cluster : process_cluster {
    explicit layout_cluster(const std::vector<std::string>& later)
        : process_cluster(specs(later), options_of()) {
        for (std::size_t i = 0; i < 3; ++i) {
            start(i);
        }
        for (std::size_t i = 0; i < 3; ++i) {
            wait_serving(i);
        }
    }

    static auto specs(const std::vector<std::string>& later) -> std::vector<member_spec> {
        std::vector<member_spec> out;
        std::vector<std::string> roles{"", "", ""};
        roles.insert(roles.end(), later.begin(), later.end());
        for (const auto& r : roles) {
            member_spec m;
            m.roles = r;
            m.env = {voters_spec()};
            out.push_back(std::move(m));
        }
        return out;
    }

    static auto options_of() -> options {
        options o;
        o.start = false;
        return o;
    }

    /// Restarts member i with `roles` (drain, stop, start).
    void restart_as(std::size_t i, const std::string& roles) {
        stop(i);
        spec(i).roles = roles;
        start(i);
        wait_serving(i);
    }

    void start_and_wait(std::size_t i) {
        start(i);
        wait_serving(i);
    }
};

/// Members 4-6 are data-only nodes.
struct data_move_cluster : layout_cluster {
    data_move_cluster() : layout_cluster({"data", "data", "data"}) {}
};

/// Member 4 is a gateway alone.
struct gateway_move_cluster : layout_cluster {
    gateway_move_cluster() : layout_cluster({"gateway"}) {}
};

/// Members 4 and 5 are gateways and front ends.
struct front_end_move_cluster : layout_cluster {
    front_end_move_cluster() : layout_cluster({"gateway,front_end", "gateway,front_end"}) {}
};

/// Member 4 a data node, 5 a gateway alone, 6 a front end alone.
struct full_path_cluster : layout_cluster {
    full_path_cluster() : layout_cluster({"data", "gateway", "front_end"}) {}
};

}  // namespace

// Requirement 10.1: the data role moves with learner, promote, leadership
// transfer and remove, from co-located members to data-only nodes and back,
// one member at a time, under the workload.
BOOST_FIXTURE_TEST_CASE(the_data_role_moves_to_data_nodes_and_back, data_move_cluster,
                        *boost::unit_test::timeout(900)) {
    workload w(*this);
    w.add(0, "before any step");
    w.check(1, "the start");

    // Joiners: outside the founding voters, they create no group.
    for (std::size_t i = 3; i < 6; ++i) {
        start(i);
    }
    for (std::size_t i = 3; i < 6; ++i) {
        wait_serving(i);
    }
    BOOST_TEST(voters_on(*this, 3) == 0.0);
    BOOST_TEST(voters_on(*this, 0) == 3.0);

    // Forward: each co-located member hands its seat to a data node, is
    // released and restarts as a gateway and front end over the data
    // nodes. An evacuated replica is never told it left, so the member
    // goes on to its restart at once rather than serving from it.
    const std::vector<std::size_t> all_data{0, 1, 2, 3, 4, 5};
    for (std::size_t m = 0; m < 3; ++m) {
        const auto other = (m + 1) % 3;
        evacuate(*this, 3, m, {3, 4, 5}, all_data);
        const auto r = as_member(m, "POST", "/v1/kms/membership/release");
        BOOST_REQUIRE_MESSAGE(r.status == 200, "release " << m + 1 << ": " << r.raw);
        restart_as(m, "gateway,front_end");
        w.add(other, "after moving member " + std::to_string(m + 1));
        w.check(m, "moving member " + std::to_string(m + 1));
    }
    BOOST_TEST(voters_on(*this, 3) == 3.0);
    // Only data nodes serve the catalog now.
    BOOST_TEST(peer(0, &tls(1), "/v1/kms/catalog/read-index") == 404);
    w.add(1, "split");
    w.check(2, "the split");

    // Back: one member at a time runs every layer again and takes a data
    // node's seat; the data node then leaves. A member that has left
    // joins, even as a founding voter, so it has no catalog of its own
    // until the move adds it.
    for (std::size_t m = 0; m < 3; ++m) {
        const auto d = m + 3;
        restart_as(m, "");
        BOOST_TEST(voters_on(*this, m) == 0.0);
        evacuate(*this, d, d, {m}, all_data);
        const auto r = as_member(d, "POST", "/v1/kms/membership/release");
        BOOST_REQUIRE_MESSAGE(r.status == 200, "release " << d + 1 << ": " << r.raw);
        stop(d);
        w.add(m, "after moving member " + std::to_string(d + 1));
        w.check(m, "moving member " + std::to_string(d + 1));
    }
    for (std::size_t m = 0; m < 3; ++m) {
        BOOST_TEST(voters_on(*this, m) == 3.0);
    }
    w.add(2, "co-located again");
    for (std::size_t m = 0; m < 3; ++m) {
        w.check(m, "the data nodes left");
    }
}

// A node still in the catalog group refuses to start without the data
// role (its old configuration could come back and vote); released, it
// starts.
BOOST_FIXTURE_TEST_CASE(a_member_still_in_the_group_keeps_the_data_role, data_move_cluster,
                        *boost::unit_test::timeout(300)) {
    BOOST_REQUIRE_EQUAL(call(0, "ListKeys", "{}").status, 200);
    stop(2);
    spec(2).roles = "gateway,front_end";
    start(2);
    const auto status = await_exit(2, 60s);
    BOOST_REQUIRE_MESSAGE(status.has_value(), "member 3 kept running:\n" << log_of(2));
    BOOST_TEST(log_of(2).find("still holds a catalog replica") != std::string::npos, log_of(2));
}

// Requirement 10.1: a stateless role moves with a drain and a restart. A
// gateway alone takes the clients; the co-located members drop their
// gateways one at a time; then they take them back and the gateway goes.
BOOST_FIXTURE_TEST_CASE(the_gateway_role_moves_out_and_back, gateway_move_cluster,
                        *boost::unit_test::timeout(900)) {
    workload w(*this);
    w.add(0, "before any step");
    start_and_wait(3);
    w.add(3, "through the gateway");
    w.check(3, "the gateway started");
    for (std::size_t m = 0; m < 3; ++m) {
        restart_as(m, "front_end,data");
        w.add(3, "after member " + std::to_string(m + 1) + " dropped its gateway");
        w.check(3, "member " + std::to_string(m + 1) + " dropped its gateway");
    }
    BOOST_TEST(await_metric(*this, 3, "front_ends_live", 3.0));
    // Back.
    for (std::size_t m = 0; m < 3; ++m) {
        restart_as(m, "");
        w.check(m, "member " + std::to_string(m + 1) + " took its gateway back");
    }
    stop(3);
    w.add(1, "co-located again");
    for (std::size_t m = 0; m < 3; ++m) {
        w.check(m, "the gateway left");
    }
}

// Requirements 10.1 and 10.2: the front-end role moves to two gateway and
// front-end nodes, and back; the job lease moves with each drain: a
// member restarting as a data node releases it and a front end takes it.
BOOST_FIXTURE_TEST_CASE(the_front_end_role_and_job_lease_move_out_and_back, front_end_move_cluster,
                        *boost::unit_test::timeout(900)) {
    workload w(*this);
    w.add(0, "before any step");
    start_and_wait(3);
    start_and_wait(4);
    for (std::size_t m = 0; m < 3; ++m) {
        restart_as(m, "data");
        w.add(3 + m % 2, "after member " + std::to_string(m + 1) + " became a data node");
        w.check(4 - m % 2, "member " + std::to_string(m + 1) + " became a data node");
    }
    // Only the new front ends may hold the lease now.
    const auto holder = await_one_lease_holder();
    BOOST_REQUIRE(holder.has_value());
    BOOST_TEST((*holder == 3 || *holder == 4), "lease on member " << *holder + 1);
    // Back: the members run every layer again; the front ends leave.
    for (std::size_t m = 0; m < 3; ++m) {
        restart_as(m, "");
    }
    stop(3);
    stop(4);
    const auto back = await_one_lease_holder();
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(*back < 3U, "lease on member " << *back + 1);
    w.add(2, "co-located again");
    for (std::size_t m = 0; m < 3; ++m) {
        w.check(m, "the front ends left");
    }
}

// Requirement 11.2: the whole co-located to split path, stopped part-way
// and reversed. A data node, a gateway and a front end join; member 1
// hands its catalog seat to the data node and restarts as a gateway and
// front end; then the move stops and everything goes back.
BOOST_FIXTURE_TEST_CASE(the_full_path_stops_midway_and_reverses, full_path_cluster,
                        *boost::unit_test::timeout(900)) {
    const std::vector<std::size_t> all_data{0, 1, 2, 3};
    workload w(*this);
    w.add(0, "before any step");
    for (std::size_t i = 3; i < 6; ++i) {
        start_and_wait(i);
    }
    w.add(4, "through the lone gateway");
    w.check(1, "the new layers joined");

    evacuate(*this, 3, 0, {3}, all_data);
    BOOST_REQUIRE_EQUAL(as_member(0, "POST", "/v1/kms/membership/release").status, 200);
    restart_as(0, "gateway,front_end");
    w.add(0, "midway");
    w.check(4, "midway");

    // Reverse from here.
    restart_as(0, "");
    evacuate(*this, 3, 3, {0}, all_data);
    BOOST_REQUIRE_EQUAL(as_member(3, "POST", "/v1/kms/membership/release").status, 200);
    stop(3);
    w.check(0, "member 1 took its seat back");
    stop(4);
    stop(5);
    w.add(1, "co-located again");
    for (std::size_t m = 0; m < 3; ++m) {
        w.check(m, "the reversal");
        BOOST_TEST(voters_on(*this, m) == 3.0);
    }
}
