// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Forwarding entries to a group's leader (`.kiro/specs/
// sqs-compatible-queues/` task 4): the node-to-node wire and its HMAC,
// stamping an entry with the proposing node's clock, and
// `raft_queue_cluster` over a stand-in multi-raft host.

#define BOOST_TEST_MODULE sqs_forward_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_queue_commands.hpp>
#include <kythira/sqs/sqs_raft_cluster.hpp>

#include <raft/memory_kv_engine.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace sqs = kythira::sqs;
namespace fwd = kythira::sqs::forward;

namespace {

auto bytes(const std::string& s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (const char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

auto text(const std::vector<std::byte>& b) -> std::string {
    std::string out;
    for (const auto c : b) {
        out.push_back(static_cast<char>(c));
    }
    return out;
}

const auto t0 = std::chrono::system_clock::time_point{std::chrono::seconds{1'800'000'000}};

auto create(const std::string& name, std::uint64_t now = 1) -> std::vector<std::byte> {
    sqs::catalog_command c;
    c._op = sqs::catalog_command::kind::create;
    c._account = "111122223333";
    c._name = name;
    c._now_ms = now;
    return bytes(sqs::encode_catalog_command(c));
}

/// What `submit_command` hands back: the cluster only calls `get()`.
struct settled {
    std::vector<std::byte> _value;
    std::exception_ptr _error;

    auto get() -> std::vector<std::byte> {
        if (_error) {
            std::rethrow_exception(_error);
        }
        return std::move(_value);
    }
};

/// A stand-in for `multi_raft`: one group, a leader that may be elsewhere.
struct fake_host {
    using node_id_type = std::string;
    using group_id_type = std::uint64_t;
    using state_machine_type = sqs::sqs_queue_state_machine<kythira::memory_kv_engine>;

    struct descriptor {
        group_id_type _group_id;
    };

    std::string _self = "n1";
    std::optional<std::string> _leader = "n1";
    bool _routed = true;
    bool _throw_other = false;
    kythira::memory_kv_engine _engine;
    state_machine_type _sm;
    std::uint64_t _index = 0;
    std::vector<std::vector<std::byte>> _submitted;

    fake_host() { _sm.open(_engine, kythira::key_range{"", std::nullopt}); }

    [[nodiscard]] auto node_id() const -> const std::string& { return _self; }

    [[nodiscard]] auto resolve(const std::string& /*key*/) const -> std::optional<descriptor> {
        if (!_routed) {
            return std::nullopt;
        }
        return descriptor{._group_id = 7};
    }

    template<typename F>
    auto with_group_state_machine(group_id_type group, F&& f)
        -> std::optional<decltype(f(_sm, descriptor{}))> {
        return std::forward<F>(f)(_sm, descriptor{._group_id = group});
    }

    auto submit_command(const std::string& /*key*/, const std::vector<std::byte>& entry,
                        std::chrono::milliseconds /*timeout*/) -> settled {
        _submitted.push_back(entry);
        if (_throw_other) {
            return {._value = {},
                    ._error = std::make_exception_ptr(std::runtime_error("timed out"))};
        }
        if (_leader != _self) {
            return {
                ._value = {},
                ._error = std::make_exception_ptr(
                    kythira::shard_not_leader_exception<group_id_type, node_id_type>(7, _leader))};
        }
        return {._value = _sm.apply(entry, ++_index), ._error = nullptr};
    }
};

using cluster_t = sqs::raft_queue_cluster<fake_host>;
static_assert(sqs::queue_cluster<cluster_t>);

struct forward_log {
    std::vector<std::string> _leaders;
    std::vector<std::vector<std::byte>> _entries;
    std::optional<std::vector<std::byte>> _answer = bytes("answer");
};

auto make_forwarder(forward_log& log) -> cluster_t::forwarder {
    return [&log](const std::string& leader, const std::string& /*key*/,
                  const std::vector<std::byte>& entry) {
        log._leaders.push_back(leader);
        log._entries.push_back(entry);
        return log._answer;
    };
}

auto clock_at(std::uint64_t ms) -> cluster_t::clock_fn {
    return [ms] { return ms; };
}

}  // namespace

BOOST_AUTO_TEST_SUITE(wire)

BOOST_AUTO_TEST_CASE(a_body_round_trips_with_nul_and_high_bytes) {
    const std::string key("\0meta/sqs/queues/1/q", 20);
    const fwd::proposal p{._key = key, ._entry = bytes(std::string("\x00\xff\x80z", 4))};
    const auto body = fwd::encode_body(p);
    BOOST_TEST(body.size() == 4 + 20 + 4U);
    const auto back = fwd::decode_body(body);
    BOOST_TEST_REQUIRE(back.has_value());
    BOOST_TEST((back->_key == key));
    BOOST_TEST((back->_entry == p._entry));
}

BOOST_AUTO_TEST_CASE(a_short_or_entryless_body_is_refused) {
    BOOST_TEST(!fwd::decode_body("").has_value());
    BOOST_TEST(!fwd::decode_body(std::string("\0\0\0", 3)).has_value());
    // A key and no entry.
    BOOST_TEST(!fwd::decode_body(std::string("\0\0\0\1k", 5)).has_value());
    // A length past the end.
    BOOST_TEST(!fwd::decode_body(std::string("\0\0\1\0kx", 6)).has_value());
}

BOOST_AUTO_TEST_CASE(a_signature_verifies_only_for_its_body_secret_and_time) {
    const auto h = fwd::sign("secret", "body", t0);
    BOOST_TEST(fwd::verify("secret", h, "body", t0));
    BOOST_TEST(fwd::verify("secret", h, "body", t0 + std::chrono::seconds{60}));
    BOOST_TEST(!fwd::verify("secret", h, "body", t0 + std::chrono::seconds{61}));
    BOOST_TEST(!fwd::verify("secret", h, "body", t0 - std::chrono::seconds{61}));
    BOOST_TEST(!fwd::verify("secret", h, "bodY", t0));
    BOOST_TEST(!fwd::verify("other", h, "body", t0));
    BOOST_TEST(!fwd::verify("", h, "body", t0));
    BOOST_TEST(!fwd::verify("secret", "", "body", t0));
    BOOST_TEST(!fwd::verify("secret", "x:" + h.substr(h.find(':') + 1), "body", t0));
    BOOST_TEST(!fwd::verify("secret", h.substr(0, h.size() - 1), "body", t0));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(stamping)

BOOST_AUTO_TEST_CASE(catalog_and_partition_entries_take_the_new_clock) {
    auto c = create("orders", 5);
    BOOST_TEST(sqs::stamp_now(c, 123'456));
    const auto cd = sqs::decode_catalog_command(text(c));
    BOOST_TEST_REQUIRE(cd.has_value());
    BOOST_TEST(cd->_now_ms == 123'456U);
    BOOST_TEST(cd->_name == "orders");

    sqs::queue_command q;
    q.op = sqs::queue_command::kind::receive;
    q.target = sqs::queue_target{9, 3, true, 60};
    q.now_ms = 5;
    q.max_messages = 7;
    auto qe = bytes(sqs::encode_queue_command(q));
    BOOST_TEST(sqs::stamp_now(qe, 0x0102030405060708ULL));
    const auto qd = sqs::decode_queue_command(text(qe));
    BOOST_TEST_REQUIRE(qd.has_value());
    q.now_ms = 0x0102030405060708ULL;
    BOOST_TEST((*qd == q));
}

BOOST_AUTO_TEST_CASE(other_or_short_entries_are_left_alone) {
    std::vector<std::byte> empty;
    BOOST_TEST(!sqs::stamp_now(empty, 1));
    auto junk = bytes("\x07junk");
    BOOST_TEST(!sqs::stamp_now(junk, 1));
    BOOST_TEST(text(junk) == "\x07junk");
    auto c = create("orders");
    c.resize(10);
    const auto before = c;
    BOOST_TEST(!sqs::stamp_now(c, 1));
    BOOST_TEST((c == before));
    auto q = bytes(sqs::encode_queue_command(sqs::queue_command{}));
    q.resize(20);
    BOOST_TEST(!sqs::stamp_now(q, 1));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(raft_cluster)

BOOST_AUTO_TEST_CASE(the_leader_proposes_locally_with_its_clock) {
    fake_host host;
    forward_log log;
    cluster_t cluster(host, make_forwarder(log), std::chrono::seconds{1}, clock_at(42'000));
    const auto out = cluster.propose("k", create("orders", 1));
    BOOST_TEST_REQUIRE(out.has_value());
    const auto r = sqs::decode_catalog_result(text(*out));
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->_record->_created_ms == 42'000U);
    BOOST_TEST(log._leaders.empty());
    BOOST_TEST(cluster.now_ms() == 42'000U);

    bool seen = false;
    BOOST_TEST(cluster.read("k", [&](const fake_host::state_machine_type& sm) {
        seen = sm.find_queue("111122223333", "orders").has_value();
    }));
    BOOST_TEST(seen);
}

BOOST_AUTO_TEST_CASE(a_follower_forwards_to_the_hinted_leader) {
    fake_host host;
    host._leader = "n2";
    forward_log log;
    cluster_t cluster(host, make_forwarder(log), std::chrono::seconds{1}, clock_at(7));
    const auto out = cluster.propose("k", create("orders"));
    BOOST_TEST_REQUIRE(out.has_value());
    BOOST_TEST(text(*out) == "answer");
    BOOST_TEST_REQUIRE(log._leaders.size() == 1U);
    BOOST_TEST(log._leaders.front() == "n2");
    BOOST_TEST(cluster.forwarded_count() == 1U);
    BOOST_TEST(sqs::decode_catalog_command(text(log._entries.front()))->_now_ms == 7U);
}

BOOST_AUTO_TEST_CASE(a_forwarded_entry_is_never_forwarded_again) {
    fake_host host;
    host._leader = "n2";
    forward_log log;
    cluster_t cluster(host, make_forwarder(log));
    BOOST_TEST(!cluster.propose_local("k", create("orders")).has_value());
    BOOST_TEST(log._leaders.empty());
}

BOOST_AUTO_TEST_CASE(no_hint_a_self_hint_or_no_forwarder_fails_as_unavailable) {
    forward_log log;
    {
        fake_host host;
        host._leader = std::nullopt;
        cluster_t cluster(host, make_forwarder(log));
        BOOST_TEST(!cluster.propose("k", create("a")).has_value());
    }
    {
        fake_host host;
        host._leader = "n2";
        host._self = "n2";
        host._leader = "n2";
        // Leading: proposes. Now pretend a stale self-hint.
        cluster_t cluster(host, make_forwarder(log));
        BOOST_TEST(cluster.propose("k", create("a")).has_value());
    }
    {
        fake_host host;
        host._leader = "n2";
        cluster_t cluster(host, nullptr);
        BOOST_TEST(!cluster.propose("k", create("a")).has_value());
    }
    BOOST_TEST(log._leaders.empty());
}

BOOST_AUTO_TEST_CASE(other_failures_unrouted_keys_and_junk_are_not_now) {
    fake_host host;
    forward_log log;
    cluster_t cluster(host, make_forwarder(log));
    host._throw_other = true;
    BOOST_TEST(!cluster.propose("k", create("a")).has_value());
    host._throw_other = false;
    // An entry that is neither kind is refused before it is submitted.
    const auto before = host._submitted.size();
    BOOST_TEST(!cluster.propose("k", bytes("\x07junk")).has_value());
    BOOST_TEST(host._submitted.size() == before);
    host._routed = false;
    BOOST_TEST(!cluster.read("k", [](const fake_host::state_machine_type&) {}));
    BOOST_TEST(log._leaders.empty());
}

BOOST_AUTO_TEST_SUITE_END()
