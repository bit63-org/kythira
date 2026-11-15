// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 14 (Requirements 11.1 and 11.2): the audit line's shape, the shared
// audit queue's batches and drop count, the module's file sink, and the
// ledger sink's statements, table creation, retries and recorded gaps.

#define BOOST_TEST_MODULE hsm_audit_test

#include <boost/test/unit_test.hpp>

#include "hsm_audit.hpp"

#include <kythira/hsm/audit_json.hpp>
#include <kythira/hsm/audit_ledger.hpp>

#include <raft/audit_log.hpp>

#include <boost/json.hpp>

#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace hsm = kythira::hsm;

BOOST_AUTO_TEST_CASE(an_audit_line_names_who_what_and_the_result) {
    hsm::audit_event e;
    e.action = "sign";
    e.identity = "spiffe://apps/ca";
    e.token = 7;
    e.object = 0x1234;
    e.label = "root";
    e.mechanism = CKM_ECDSA_SHA256;
    e.rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
    e.elapsed = std::chrono::microseconds{42};
    e.calls = 1000;
    const auto o = boost::json::parse(hsm::audit_line(e, 1700000000)).as_object();
    BOOST_TEST(o.at("hsm_audit") == "sign");
    BOOST_TEST(o.at("time").to_number<std::int64_t>() == 1700000000);
    BOOST_TEST(o.at("identity") == "spiffe://apps/ca");
    BOOST_TEST(o.at("token").to_number<int>() == 7);
    BOOST_TEST(o.at("object").to_number<int>() == 0x1234);
    BOOST_TEST(o.at("label") == "root");
    BOOST_TEST(o.at("mechanism") == "0x00001044");
    BOOST_TEST(o.at("result") == "error");
    BOOST_TEST(o.at("rv") == "0x00000068");
    BOOST_TEST(o.at("elapsed_us").to_number<int>() == 42);
    BOOST_TEST(o.at("calls").to_number<int>() == 1000);
    BOOST_TEST(!o.contains("status"));

    hsm::audit_event bare;
    bare.action = "seal";
    bare.identity = "ops";
    const auto b = boost::json::parse(hsm::audit_line(bare, 1)).as_object();
    BOOST_TEST(b.at("result") == "ok");
    for (const auto* absent : {"token", "object", "label", "mechanism", "calls"}) {
        BOOST_TEST(!b.contains(absent), absent);
    }
}

BOOST_AUTO_TEST_CASE(the_audit_queue_hands_batches_and_counts_drops) {
    std::mutex mu;
    std::vector<std::string> seen;
    std::size_t batches = 0;
    {
        kythira::audit_log log(kythira::audit_log::batch_sink([&](std::span<const std::string> l) {
                                   const std::scoped_lock lock(mu);
                                   ++batches;
                                   seen.insert(seen.end(), l.begin(), l.end());
                               }),
                               4);
        for (int i = 0; i < 50; ++i) {
            log.post("line " + std::to_string(i));
        }
        log.flush();
        log.post("after");
        log.flush();
    }
    const std::scoped_lock lock(mu);
    BOOST_TEST(batches >= 1U);
    BOOST_TEST(seen.back() == "after");
    // What did not fit is reported, not lost silently.
    std::uint64_t reported = 0;
    std::size_t lines = 0;
    for (const auto& l : seen) {
        if (l.starts_with(R"({"audit":"dropped")")) {
            reported += boost::json::parse(l).at("lines").to_number<std::uint64_t>();
        } else {
            ++lines;
        }
    }
    BOOST_TEST(lines + reported == 51U);
}

namespace {

/// A ledger stand-in: records each request, answers what it is told.
struct fake_ledger {
    std::vector<std::pair<std::string, boost::json::object>> requests;
    bool up = true;
    bool table_exists = false;

    auto poster() -> hsm::ledger_audit_sink::poster {
        return [this](const std::string& target,
                      std::string body) -> std::optional<std::pair<unsigned, std::string>> {
            if (!up) {
                return std::nullopt;
            }
            auto o = boost::json::parse(body).as_object();
            requests.emplace_back(target, o);
            const auto& st = o.at("statements").as_array();
            if (st.size() == 1 && st[0].as_object().at("op") == "create_table") {
                if (table_exists) {
                    return std::pair{409U, std::string(R"({"code":"table_exists"})")};
                }
                table_exists = true;
            }
            return std::pair{200U, std::string("{}")};
        };
    }

    /// The audit lines committed, in order.
    [[nodiscard]] auto documents() const -> std::vector<boost::json::object> {
        std::vector<boost::json::object> out;
        for (const auto& [target, body] : requests) {
            for (const auto& st : body.at("statements").as_array()) {
                if (st.as_object().at("op") == "insert") {
                    out.push_back(st.as_object().at("value").as_object());
                }
            }
        }
        return out;
    }
};

auto line(int i) -> std::string {
    return boost::json::serialize(boost::json::object{{"hsm_audit", "sign"}, {"n", i}});
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_ledger_sink_inserts_each_line_in_order) {
    fake_ledger ledger;
    hsm::ledger_audit_config cfg;
    cfg.ledger = "trail";
    cfg.table = "hsm";
    cfg.batch = 3;
    hsm::ledger_audit_sink sink(cfg, ledger.poster());
    std::vector<std::string> lines;
    for (int i = 0; i < 7; ++i) {
        lines.push_back(line(i));
    }
    sink.send(lines);
    BOOST_REQUIRE(ledger.requests.size() == 4U);  // the table, then 3 + 3 + 1
    BOOST_TEST(ledger.requests[0].first == "/v1/ledgers/trail/execute");
    BOOST_TEST(ledger.requests[0].second.at("statements").as_array()[0].at("table") == "hsm");
    const auto docs = ledger.documents();
    BOOST_REQUIRE(docs.size() == 7U);
    std::set<std::string> ids;
    for (int i = 0; i < 7; ++i) {
        BOOST_TEST(docs[static_cast<std::size_t>(i)].at("n").to_number<int>() == i);
    }
    for (const auto& [target, body] : ledger.requests) {
        for (const auto& st : body.at("statements").as_array()) {
            if (st.as_object().at("op") == "insert") {
                const auto id = std::string(st.as_object().at("id").as_string());
                BOOST_TEST(id.size() == 22U);
                ids.insert(id);
            }
        }
    }
    BOOST_TEST(ids.size() == 7U);
    BOOST_TEST(sink.committed() == 3U);

    // A second sink on the same ledger finds the table there already.
    hsm::ledger_audit_sink again(cfg, ledger.poster());
    again.send(std::vector<std::string>{line(7)});
    BOOST_TEST(again.committed() == 1U);
    BOOST_TEST(ledger.documents().size() == 8U);
}

BOOST_AUTO_TEST_CASE(the_ledger_sink_keeps_lines_while_down_and_records_gaps) {
    fake_ledger ledger;
    hsm::ledger_audit_config cfg;
    cfg.max_pending = 4;
    hsm::ledger_audit_sink sink(cfg, ledger.poster());
    ledger.up = false;
    sink.send(std::vector<std::string>{line(0), line(1)});
    BOOST_TEST(sink.pending() == 2U);
    sink.send(std::vector<std::string>{line(2), line(3), line(4), line(5)});
    BOOST_TEST(sink.pending() == 4U);  // the two oldest dropped
    ledger.up = true;
    sink.send(std::vector<std::string>{line(6)});
    BOOST_TEST(sink.pending() == 0U);
    const auto docs = ledger.documents();
    BOOST_REQUIRE(docs.size() == 5U);
    // The gap is itself a document, ahead of what survived.
    BOOST_TEST(docs[0].at("audit") == "ledger_dropped");
    BOOST_TEST(docs[0].at("lines").to_number<int>() == 3);  // 0, 1 and then 2
    BOOST_TEST(docs[1].at("n").to_number<int>() == 3);
    BOOST_TEST(docs[4].at("n").to_number<int>() == 6);
}

BOOST_AUTO_TEST_CASE(the_module_appends_logged_events_to_a_file) {
    const auto path = std::filesystem::temp_directory_path() /
                      ("hsm_audit_test_" + std::to_string(::getpid()) + ".log");
    std::filesystem::remove(path);
    {
        kythira::hsm_node::hsm_options o;
        o.audit = "file:" + path.string();
        kythira::hsm_node::audit_pipeline audit(o);
        hsm::audit_event e;
        e.action = "login";
        e.identity = "app-a";
        audit.record(e);
        e.action = "sign";
        e.logged = false;  // counted, not sampled
        audit.record(e);
        audit.flush();
    }
    std::ifstream in(path);
    std::vector<std::string> lines;
    for (std::string l; std::getline(in, l);) {
        lines.push_back(l);
    }
    BOOST_REQUIRE(lines.size() == 1U);
    BOOST_TEST(boost::json::parse(lines[0]).at("hsm_audit") == "login");
    std::filesystem::remove(path);
}

// Requirement 11.3: every event, logged or only counted, reaches the
// metrics by action, mechanism and result, with latency, failed logins and
// refusals for a locked PIN.
BOOST_AUTO_TEST_CASE(events_become_metrics) {
    kythira::hsm_node::hsm_options o;
    o.audit = "off";
    kythira::hsm_node::audit_pipeline audit(o);
    hsm::audit_event sign;
    sign.action = "sign";
    sign.identity = "app-a";
    sign.mechanism = CKM_ECDSA_SHA256;
    sign.elapsed = std::chrono::microseconds{250};
    for (int i = 0; i < 3; ++i) {
        sign.logged = i == 0;
        audit.record(sign);
    }
    hsm::audit_event login;
    login.action = "login";
    login.rv = CKR_PIN_INCORRECT;
    audit.record(login);
    login.rv = CKR_PIN_LOCKED;
    audit.record(login);
    const auto metrics = audit.metrics();
    const auto value = [&](const std::string& name,
                           const std::vector<std::pair<std::string, std::string>>& labels) {
        for (const auto& m : metrics) {
            if (m.name == name && m.labels == labels) {
                return m.value;
            }
        }
        return -1.0;
    };
    BOOST_TEST(value("operations",
                     {{"action", "sign"}, {"mechanism", "0x00001044"}, {"result", "ok"}}) == 3.0);
    BOOST_TEST(value("operations", {{"action", "login"}, {"mechanism", ""}, {"result", "error"}}) ==
               2.0);
    BOOST_TEST(value("operation_latency_seconds_count", {{"action", "sign"}}) == 3.0);
    BOOST_TEST(value("operation_latency_seconds_sum", {{"action", "sign"}}) == 0.00075,
               boost::test_tools::tolerance(1e-9));
    BOOST_TEST(value("login_failures", {}) == 1.0);
    BOOST_TEST(value("pin_locked_refusals", {}) == 1.0);
    BOOST_TEST(value("audit_dropped", {}) == 0.0);
}
