// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 12: the peer protocol members forward to the catalog's leader with
// (kms_peer.hpp): the reply's wire form, who counts as a member, and the
// answers serve_peer gives on a host standing in for kms_host.

#define BOOST_TEST_MODULE kms_peer_test

#include <boost/test/unit_test.hpp>

#include <kythira/kms/kms_peer.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kms = kythira::kms;

namespace {

using reply = kms::forward_reply<std::uint64_t>;

/// A kms_host's two leader-side calls, recording what they were given.
struct fake_host {
    std::vector<std::byte> proposed;
    int read_indexes = 0;
    reply answer;

    auto serve_propose(const std::vector<std::byte>& cmd) -> reply {
        proposed = cmd;
        return answer;
    }
    auto serve_read_index() -> reply {
        ++read_indexes;
        return answer;
    }
};

auto to_text(std::uint64_t id) -> std::string {
    return std::to_string(id);
}

auto member(std::vector<std::string> uris, std::vector<std::string> dns = {}) -> kms::peer_caller {
    return {.tls = true, .verified = true, .uri_sans = std::move(uris), .dns_sans = std::move(dns)};
}

}  // namespace

BOOST_AUTO_TEST_CASE(replies_round_trip) {
    kms::forward_reply<std::string> r;
    r.result = kms::forward_reply<std::string>::status::not_leader;
    r.index = 42;
    r.leader = "node-3";
    r.reply = {std::byte{0}, std::byte{0xff}, std::byte{7}};
    const auto back = kms::decode_forward_reply(kms::encode_forward_reply(r));
    BOOST_TEST(static_cast<int>(back.result) == static_cast<int>(r.result));
    BOOST_TEST(back.index == 42U);
    BOOST_TEST(back.leader.value_or("") == "node-3");
    BOOST_TEST(back.reply == r.reply);

    kms::forward_reply<std::string> none;
    none.result = kms::forward_reply<std::string>::status::ok;
    const auto back2 = kms::decode_forward_reply(kms::encode_forward_reply(none));
    BOOST_TEST(static_cast<int>(back2.result) == 0);
    BOOST_TEST(!back2.leader.has_value());
    BOOST_TEST(back2.reply.empty());
}

BOOST_AUTO_TEST_CASE(garbage_decodes_as_unavailable) {
    using st = kms::forward_reply<std::string>::status;
    kms::forward_reply<std::string> r;
    r.result = st::ok;
    r.reply = {std::byte{1}, std::byte{2}};
    const auto good = kms::encode_forward_reply(r);
    for (const std::string& bad :
         {std::string(), std::string("\x02", 1), good.substr(0, good.size() - 1), good + "x",
          std::string("\x01\x09", 2) + good.substr(2)}) {
        BOOST_TEST(static_cast<int>(kms::decode_forward_reply(bad).result) ==
                   static_cast<int>(st::unavailable));
    }
}

BOOST_AUTO_TEST_CASE(leader_ids_cross_as_text) {
    reply r;
    r.result = reply::status::not_leader;
    r.leader = 7;
    const auto wire = kms::to_wire(r, to_text);
    BOOST_TEST(wire.leader.value_or("") == "7");
    const auto back = kms::from_wire<std::uint64_t>(
        wire, [](const std::string& s) -> std::optional<std::uint64_t> {
            return s == "7" ? std::optional<std::uint64_t>(7) : std::nullopt;
        });
    BOOST_TEST(back.leader.value_or(0) == 7U);
}

BOOST_AUTO_TEST_CASE(only_members_may_forward) {
    const kms::peer_policy policy{.identities = {"spiffe://k/kms/1", "kms-2.example"}};
    BOOST_TEST(kms::is_member(policy, member({"spiffe://k/kms/1"})));
    BOOST_TEST(kms::is_member(policy, member({}, {"other", "kms-2.example"})));
    BOOST_TEST(!kms::is_member(policy, member({"spiffe://k/kms/9"})));
    auto unverified = member({"spiffe://k/kms/1"});
    unverified.verified = false;
    BOOST_TEST(!kms::is_member(policy, unverified));
    BOOST_TEST(!kms::is_member(policy, kms::peer_caller{}));  // plaintext
    const kms::peer_policy tests{.identities = {}, .allow_plaintext = true};
    BOOST_TEST(kms::is_member(tests, kms::peer_caller{}));
}

BOOST_AUTO_TEST_CASE(serve_peer_answers) {
    fake_host host;
    host.answer.result = reply::status::ok;
    host.answer.index = 9;
    host.answer.reply = {std::byte{5}};
    const kms::peer_policy policy{.identities = {"kms-1"}};
    const auto caller = member({}, {"kms-1"});

    // Not a peer path: the KMS API's.
    BOOST_TEST(!kms::serve_peer(host, policy, caller, "POST", "/", "", to_text).has_value());

    const auto p = kms::serve_peer(host, policy, caller, "POST", kms::peer_propose_path,
                                   std::string("\x01\x00\x02", 3), to_text);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->status == 200U);
    BOOST_TEST(host.proposed.size() == 3U);
    BOOST_TEST(static_cast<int>(host.proposed[1]) == 0);
    const auto decoded = kms::decode_forward_reply(p->body);
    BOOST_TEST(decoded.index == 9U);
    BOOST_TEST(decoded.reply == host.answer.reply);

    const auto ri =
        kms::serve_peer(host, policy, caller, "POST", kms::peer_read_index_path, "", to_text);
    BOOST_REQUIRE(ri.has_value());
    BOOST_TEST(ri->status == 200U);
    BOOST_TEST(host.read_indexes == 1);

    // Strangers are refused before anything reaches the host; members'
    // malformed requests are 400.
    BOOST_TEST(kms::serve_peer(host, policy, member({}, {"intruder"}), "POST",
                               kms::peer_propose_path, "x", to_text)
                   ->status == 403U);
    BOOST_TEST(kms::serve_peer(host, policy, caller, "GET", kms::peer_read_index_path, "", to_text)
                   ->status == 400U);
    BOOST_TEST(
        kms::serve_peer(host, policy, caller, "POST", "/v1/kms/peer/other", "", to_text)->status ==
        400U);
    BOOST_TEST(host.proposed.size() == 3U);
    BOOST_TEST(host.read_indexes == 1);
}
