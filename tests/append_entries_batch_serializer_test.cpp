// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file append_entries_batch_serializer_test.cpp
/// @brief JSON and CBOR encodings of the batched AppendEntries RPC
///        (`.kiro/specs/multi-raft-message-batching/` task 6, Requirement 5.1
///        and 7.3).
///
/// Two properties per serializer. A batch round-trips to an equal batch, and
/// each member's bytes appear inside the batch exactly as that member encodes
/// on its own: the batch is the members' standalone encodings spliced into an
/// array, never a second encoding of the same message.

#define BOOST_TEST_MODULE append_entries_batch_serializer_test
#include <boost/test/unit_test.hpp>

#include <raft/cbor_serializer.hpp>
#include <raft/exceptions.hpp>
#include <raft/json_serializer.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace {

using bytes = std::vector<std::byte>;
using ae_request = kythira::append_entries_request<>;
using ae_response = kythira::append_entries_response<>;
using batch_request = kythira::append_entries_batch_request<ae_request>;
using batch_response = kythira::append_entries_batch_response<ae_response>;
using kythira::batch_member_error;

auto member(std::uint64_t group, std::uint64_t term, std::size_t entries, std::mt19937_64& rng)
    -> ae_request {
    ae_request req{._term = term,
                   ._leader_id = 1 + (rng() % 5),
                   ._prev_log_index = rng() % 1000,
                   ._prev_log_term = term - 1,
                   ._entries = {},
                   ._leader_commit = rng() % 1000,
                   ._group_id = group};
    for (std::size_t i = 0; i < entries; ++i) {
        bytes cmd(rng() % 64);
        for (auto& b : cmd) {
            b = static_cast<std::byte>(rng());
        }
        req._entries.push_back({._term = term,
                                ._index = req._prev_log_index + 1 + i,
                                ._command = std::move(cmd),
                                ._type = i % 3 == 0 ? kythira::entry_type::configuration
                                                    : kythira::entry_type::normal});
    }
    return req;
}

auto sample_request() -> batch_request {
    std::mt19937_64 rng{20261120};
    batch_request batch;
    batch._members.push_back(member(1, 5, 0, rng));  // a heartbeat
    batch._members.push_back(member(2, 7, 3, rng));
    batch._members.push_back(member(1, 5, 1, rng));  // the same group again
    batch._members.push_back(member(9000000000ULL, 1, 2, rng));
    return batch;
}

auto sample_response() -> batch_response {
    batch_response batch;
    batch._members.emplace_back(ae_response{._term = 5,
                                            ._success = true,
                                            ._conflict_index = std::nullopt,
                                            ._conflict_term = std::nullopt,
                                            ._group_id = 1});
    batch._members.emplace_back(ae_response{
        ._term = 7, ._success = false, ._conflict_index = 41, ._conflict_term = 6, ._group_id = 2});
    batch._members.emplace_back(
        batch_member_error{._kind = batch_member_error::kind_type::unknown_group, ._message = ""});
    batch._members.emplace_back(batch_member_error{
        ._kind = batch_member_error::kind_type::handler_failed, ._message = "disk full \"x\""});
    return batch;
}

auto same(const ae_request& a, const ae_request& b) -> bool {
    if (a._term != b._term || a._leader_id != b._leader_id ||
        a._prev_log_index != b._prev_log_index || a._prev_log_term != b._prev_log_term ||
        a._leader_commit != b._leader_commit || a._group_id != b._group_id ||
        a._entries.size() != b._entries.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a._entries.size(); ++i) {
        const auto& x = a._entries[i];
        const auto& y = b._entries[i];
        if (x._term != y._term || x._index != y._index || x._command != y._command ||
            x._type != y._type) {
            return false;
        }
    }
    return true;
}

auto same(const ae_response& a, const ae_response& b) -> bool {
    return a._term == b._term && a._success == b._success &&
           a._conflict_index == b._conflict_index && a._conflict_term == b._conflict_term &&
           a._group_id == b._group_id;
}

auto contains(const bytes& haystack, const bytes& needle) -> bool {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
           haystack.end();
}

template<typename Serializer> auto check_request_round_trip() -> void {
    Serializer s;
    const auto batch = sample_request();
    const auto encoded = s.serialize(batch);
    const auto decoded = s.template deserialize<batch_request>(encoded);
    BOOST_REQUIRE_EQUAL(decoded._members.size(), batch._members.size());
    for (std::size_t i = 0; i < batch._members.size(); ++i) {
        BOOST_TEST(same(decoded._members[i], batch._members[i]), "member " << i);
        // Requirement 5.1: a member's bytes inside the batch are its bytes alone.
        BOOST_TEST(contains(encoded, s.serialize(batch._members[i])), "member " << i);
    }
    // Re-encoding the decoded batch gives back the same bytes.
    BOOST_TEST((s.serialize(decoded) == encoded));
}

template<typename Serializer> auto check_response_round_trip() -> void {
    Serializer s;
    const auto batch = sample_response();
    const auto encoded = s.serialize(batch);
    const auto decoded = s.template deserialize<batch_response>(encoded);
    BOOST_REQUIRE_EQUAL(decoded._members.size(), batch._members.size());
    for (std::size_t i = 0; i < batch._members.size(); ++i) {
        BOOST_REQUIRE_EQUAL(decoded._members[i].index(), batch._members[i].index());
        if (batch._members[i].index() == 0) {
            const auto& want = std::get<0>(batch._members[i]);
            BOOST_TEST(same(std::get<0>(decoded._members[i]), want), "member " << i);
            BOOST_TEST(contains(encoded, s.serialize(want)), "member " << i);
        } else {
            BOOST_TEST((std::get<1>(decoded._members[i]) == std::get<1>(batch._members[i])));
        }
    }
    BOOST_TEST((s.serialize(decoded) == encoded));
}

template<typename Serializer> auto check_empty_batches() -> void {
    Serializer s;
    BOOST_TEST(
        s.template deserialize<batch_request>(s.serialize(batch_request{}))._members.empty());
    BOOST_TEST(
        s.template deserialize<batch_response>(s.serialize(batch_response{}))._members.empty());
}

template<typename Serializer> auto check_rejects_a_lone_message_as_a_batch() -> void {
    Serializer s;
    std::mt19937_64 rng{1};
    const auto lone = s.serialize(member(1, 2, 1, rng));
    BOOST_CHECK_THROW(std::ignore = s.template deserialize<batch_request>(lone),
                      kythira::serialization_exception);
    // And a batch is not mistaken for a lone message.
    BOOST_CHECK_THROW(
        std::ignore = s.template deserialize<ae_request>(s.serialize(sample_request())),
        kythira::serialization_exception);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(json)
BOOST_AUTO_TEST_CASE(request_round_trips_with_member_bytes_intact) {
    check_request_round_trip<kythira::json_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(response_round_trips_with_member_bytes_intact) {
    check_response_round_trip<kythira::json_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(empty_batches_round_trip) {
    check_empty_batches<kythira::json_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(a_lone_message_is_not_a_batch) {
    check_rejects_a_lone_message_as_a_batch<kythira::json_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(a_member_of_the_wrong_type_is_refused) {
    kythira::json_rpc_serializer<bytes> s;
    const std::string text =
        R"({"type":"append_entries_batch_request","members":[{"type":"request_vote_request",)"
        R"("term":1,"candidate_id":1,"last_log_index":0,"last_log_term":0}]})";
    bytes data;
    for (char c : text) {
        data.push_back(static_cast<std::byte>(c));
    }
    BOOST_CHECK_THROW(std::ignore = s.deserialize<batch_request>(data),
                      kythira::serialization_exception);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(cbor)
BOOST_AUTO_TEST_CASE(request_round_trips_with_member_bytes_intact) {
    check_request_round_trip<kythira::cbor_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(response_round_trips_with_member_bytes_intact) {
    check_response_round_trip<kythira::cbor_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(empty_batches_round_trip) {
    check_empty_batches<kythira::cbor_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(a_lone_message_is_not_a_batch) {
    check_rejects_a_lone_message_as_a_batch<kythira::cbor_rpc_serializer<bytes>>();
}
BOOST_AUTO_TEST_CASE(a_truncated_batch_is_refused) {
    kythira::cbor_rpc_serializer<bytes> s;
    auto data = s.serialize(sample_request());
    data.resize(data.size() / 2);
    BOOST_CHECK_THROW(std::ignore = s.deserialize<batch_request>(data),
                      kythira::serialization_exception);
}
BOOST_AUTO_TEST_SUITE_END()
