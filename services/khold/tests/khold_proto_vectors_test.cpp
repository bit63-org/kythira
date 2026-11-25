// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 1 (.kiro/specs/khold-block-service/ Requirements 1.4 and 11.5):
// kythira consumes antikythera's src/proto/ through the antikythera-proto
// overlay port, and reproduces antikythera's test vectors byte for byte
// from kythira's own build. For each vector this encodes the listed fields
// with the overlay's headers, signs signed frames with the listed RFC 8032
// key through OpenSSL (not antikythera's hull verifier, which kythira does
// not link), compares the bytes, decodes them back, and checks the
// signature verifies under the public key and fails over altered bytes.
//
// A failure here means the pinned antikythera commit and kythira disagree
// on a wire format: fix the format in antikythera, then move the pin.

#define BOOST_TEST_MODULE khold_proto_vectors_test

#include <boost/test/unit_test.hpp>

#include <kythira/khold/khold_proto.hpp>

#include "proto/replica_config.hpp"
#include "proto/test_vectors.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

namespace proto = ak::proto;
namespace vec = ak::proto::vectors;
namespace kh = kythira::khold;

constexpr std::uint8_t ula = 0xFD;
constexpr std::size_t last = 15;
constexpr std::uint16_t rcfg4_port = 7300;
constexpr std::uint16_t layout6_port = 7400;
constexpr std::size_t ed25519_key_size = 32;

auto from_hex(std::string_view hex) -> std::vector<std::byte> {
    const auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') {
            return static_cast<unsigned>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<unsigned>(c - 'a' + 10);
        }
        throw std::invalid_argument("bad hex digit");
    };
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("odd hex length");
    }
    std::vector<std::byte> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = std::byte{
            static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4U) | nibble(hex[(2 * i) + 1]))};
    }
    return out;
}

struct PkeyFree {
    auto operator()(EVP_PKEY* k) const noexcept -> void { EVP_PKEY_free(k); }
};
struct MdCtxFree {
    auto operator()(EVP_MD_CTX* c) const noexcept -> void { EVP_MD_CTX_free(c); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxFree>;

auto raw_key(std::string_view hex, bool secret) -> Pkey {
    const auto bytes = from_hex(hex);
    BOOST_REQUIRE(bytes.size() == ed25519_key_size);
    const auto* p = reinterpret_cast<const unsigned char*>(bytes.data());
    Pkey k{secret ? EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, p, bytes.size())
                  : EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, p, bytes.size())};
    BOOST_REQUIRE(k != nullptr);
    return k;
}

auto sign(std::string_view secret_hex, std::span<const std::byte> msg) -> proto::Ed25519Signature {
    const auto key = raw_key(secret_hex, true);
    MdCtx ctx{EVP_MD_CTX_new()};
    BOOST_REQUIRE(ctx != nullptr);
    BOOST_REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1);
    proto::Ed25519Signature sig{};
    std::size_t len = sig.size();
    BOOST_REQUIRE(EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(sig.data()), &len,
                                 reinterpret_cast<const unsigned char*>(msg.data()),
                                 msg.size()) == 1);
    BOOST_REQUIRE(len == sig.size());
    return sig;
}

auto verifies(std::string_view public_hex, std::span<const std::byte> msg,
              std::span<const std::byte> sig) -> bool {
    const auto key = raw_key(public_hex, false);
    MdCtx ctx{EVP_MD_CTX_new()};
    BOOST_REQUIRE(ctx != nullptr);
    BOOST_REQUIRE(EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1);
    return EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(sig.data()),
                            sig.size(), reinterpret_cast<const unsigned char*>(msg.data()),
                            msg.size()) == 1;
}

auto endpoint(std::uint64_t server) -> proto::StorageEndpoint {
    proto::StorageEndpoint e{};
    e[0] = std::byte{ula};
    e[last] = std::byte{static_cast<std::uint8_t>(server)};
    return e;
}

// Encodes `fields`, signs the signed bytes with key 1, and checks the
// result against the vector; then decodes the vector back to the fields
// and checks the signature under key 1's public half.
template<typename Frame, typename Encode, typename Decode, typename Signed, typename SetSig>
auto check_signed_vector(std::string_view frame_hex, std::string_view sig_hex, const Frame& fields,
                         Encode encode, Decode decode, Signed signed_bytes, SetSig set_signature)
    -> void {
    const auto want = from_hex(frame_hex);
    auto frame = encode(fields);
    BOOST_REQUIRE(frame.has_value());
    set_signature(*frame, sign(vec::key1_secret, signed_bytes(*frame)));
    BOOST_TEST((*frame == want));
    BOOST_TEST(
        std::ranges::equal(std::span{want}.last(proto::ed25519_signature_size), from_hex(sig_hex)));

    auto got = decode(want);
    BOOST_REQUIRE(got.has_value());
    auto expect = fields;
    std::ranges::copy(from_hex(sig_hex), expect.signature.begin());
    BOOST_TEST((*got == expect));

    BOOST_TEST(verifies(vec::key1_public, signed_bytes(want), got->signature));
    BOOST_TEST(!verifies(vec::key2_public, signed_bytes(want), got->signature));
    auto altered = want;
    altered[proto::ed25519_signature_size] ^= std::byte{1};
    BOOST_TEST(!verifies(vec::key1_public, signed_bytes(altered), got->signature));
}

auto encoded(const proto::HoldV2Frame& f) -> std::vector<std::byte> {
    auto b = proto::encode_hold_v2_frame(f);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto encoded(const proto::Report& r) -> std::vector<std::byte> {
    auto b = proto::encode_report(r);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto hv2_header(proto::HoldV2Opcode op) -> proto::HoldV2Header {
    return {.opcode = op,
            .flags = 0,
            .payload_len = 0,
            .status = proto::HoldV2Status::ok,
            .request_id = 77,
            .volume_id = 0x200,
            .epoch = 3,
            .attachment_id = 0xA1,
            .generation = 2,
            .blocks = 0,
            .lba = 0,
            .group_id = 0x5001,
            .term = 4};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(khold_proto_vectors)

// Vector 4: hold's replica config, which khold reads when it takes a
// volume over from hold (Requirement 11.3).
BOOST_AUTO_TEST_CASE(replica_config_vector_4_reproduces) {
    const auto member = [](std::uint64_t server, proto::ReplicaRole role) {
        return proto::ReplicaMember{.server_id = server,
                                    .endpoint = endpoint(server),
                                    .port = rcfg4_port,
                                    .role = role,
                                    .replica_gen = 1};
    };
    const proto::ReplicaConfig fields{
        .key_id = vec::rcfg4_key_id,
        .server_id = vec::rcfg4_server_id,
        .volume_id = vec::rcfg4_volume_id,
        .epoch = vec::rcfg4_epoch,
        .lineage_id = 0x1EE,
        .capacity_blocks = 1U << 18U,
        .block_size = proto::block_size_4096,
        .flags = proto::replica_flags::multi_attach,
        .qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 16000, .burst_mib = 1000},
        .lease_ms = 4000,
        .resync_window_s = 900,
        .source = {},
        .members = {member(0x21, proto::ReplicaRole::primary),
                    member(0x22, proto::ReplicaRole::secondary)},
        .attachments = {{.attachment_id = 0xA1,
                         .server_id = 7,
                         .generation = 2,
                         .mode = proto::AttachMode::rw},
                        {.attachment_id = 0xA2,
                         .server_id = 8,
                         .generation = 1,
                         .mode = proto::AttachMode::rw}},
        .signature = {}};
    check_signed_vector(
        vec::rcfg4, vec::rcfg4_signature, fields,
        [](const proto::ReplicaConfig& c) { return proto::encode_replica_config(c); },
        [](std::span<const std::byte> b) { return proto::decode_replica_config(b); },
        [](std::span<const std::byte> b) { return proto::replica_config_signed_bytes(b); },
        [](std::span<std::byte> b, const auto& sig) {
            proto::set_replica_config_signature(b, sig);
        });
}

// Vector 6: a signed VolumeLayout of two general-class groups.
BOOST_AUTO_TEST_CASE(volume_layout_vector_6_reproduces) {
    using K = proto::MemberKind;
    const auto member = [](std::uint64_t server, K kind, std::uint8_t drive) {
        return proto::LayoutMember{.server_id = server,
                                   .endpoint = endpoint(server),
                                   .port = layout6_port,
                                   .kind = kind,
                                   .drive = drive};
    };
    const proto::VolumeLayout fields{
        .key_id = vec::layout6_key_id,
        .server_id = vec::layout6_server_id,
        .volume_id = vec::layout6_volume_id,
        .epoch = vec::layout6_epoch,
        .lineage_id = 0x2EE,
        .capacity_blocks = 1U << 20U,
        .block_size = proto::block_size_4096,
        .stripe_unit = 1U << 20U,
        .flags = 0,
        .commit_rule = proto::CommitRule::all_in_sync,
        .group_skew_pct = 10,
        .qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 16000, .burst_mib = 1000},
        .timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900},
        .mirror = {},
        .groups = {{.group_id = 0x5001,
                    .members = {member(0x21, K::data, 0), member(0x22, K::data, 1),
                                member(0x23, K::witness, 0)}},
                   {.group_id = 0x5002,
                    .members = {member(0x22, K::data, 0), member(0x23, K::data, 1),
                                member(0x24, K::witness, 0)}}},
        .gateways = {},
        .attachments = {{.attachment_id = 0xA1,
                         .server_id = 7,
                         .generation = 2,
                         .mode = proto::AttachMode::rw}},
        .signature = {}};
    check_signed_vector(
        vec::layout6, vec::layout6_signature, fields,
        [](const proto::VolumeLayout& l) { return proto::encode_volume_layout(l); },
        [](std::span<const std::byte> b) { return proto::decode_volume_layout(b); },
        [](std::span<const std::byte> b) { return proto::volume_layout_signed_bytes(b); },
        [](std::span<std::byte> b, const auto& sig) {
            proto::set_volume_layout_signature(b, sig);
        });

    // Both groups have the general class's shape, and the module helpers
    // agree with the layout's own lookups.
    for (const auto& g : fields.groups) {
        BOOST_TEST((kh::group_shape(g) == kh::general_group_shape));
        BOOST_TEST(kh::group_voters(kh::group_shape(g)) == 3U);
    }
}

// Vectors 7 to 9: hold wire v2 frames.
BOOST_AUTO_TEST_CASE(hold_wire_v2_vectors_7_to_9_reproduce) {
    constexpr std::uint32_t block = proto::block_size_512;
    std::vector<std::byte> data(block);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = std::byte{static_cast<std::uint8_t>((i * 13U) + 1U)};
    }
    const auto crcs = proto::block_crcs(data, block);
    auto w = hv2_header(proto::HoldV2Opcode::write);
    w.blocks = 1;
    w.lba = 0x1000;
    BOOST_TEST(
        (encoded({.header = w,
                  .payload = proto::BlockData{.block_size = block, .crcs = crcs, .data = data}}) ==
         from_hex(vec::hold_v2_write7)));

    auto r = hv2_header(proto::HoldV2Opcode::redirect);
    r.flags = proto::hold_flags::response;
    r.status = proto::HoldV2Status::not_leader;
    r.request_id = 78;
    r.term = 5;
    BOOST_TEST((encoded({.header = r,
                         .payload = proto::HoldV2Redirect{.leader_server = 0x22,
                                                          .endpoint = endpoint(0x22),
                                                          .port = layout6_port,
                                                          .leader_term = 5}}) ==
                from_hex(vec::hold_v2_redirect8)));

    auto ok = hv2_header(proto::HoldV2Opcode::hello_ok);
    ok.flags = proto::hold_flags::response;
    ok.request_id = 1;
    ok.group_id = 0;
    ok.term = 0;
    BOOST_TEST((encoded({.header = ok,
                         .payload = proto::HoldV2HelloOk{.block_size = proto::block_size_4096,
                                                         .capacity_blocks = 1U << 20U,
                                                         .stripe_unit = 1U << 20U,
                                                         .stripe_width = 2}}) ==
                from_hex(vec::hold_v2_hello_ok9)));

    for (auto hex : {vec::hold_v2_write7, vec::hold_v2_redirect8, vec::hold_v2_hello_ok9}) {
        const auto bytes = from_hex(hex);
        const auto version = kh::hold_wire_version(bytes);
        BOOST_REQUIRE(version.has_value());
        BOOST_TEST((*version == kh::HoldWireVersion::v2));
        auto f = proto::decode_hold_v2_frame(bytes);
        BOOST_REQUIRE(f.has_value());
        BOOST_TEST((encoded(*f) == bytes));
        // A v2 frame is refused by the v1 decoder, so a listener that peeks
        // the wrong version cannot misread it.
        BOOST_TEST(!proto::decode_hold_frame(bytes).has_value());
    }
}

// Vectors 10 and 11: the khold reports a host sends its controller.
BOOST_AUTO_TEST_CASE(report_vectors_10_and_11_reproduce) {
    const proto::Report status{
        .server_id = 0x21,
        .report_seq = 5,
        .body = proto::GroupStatus{.slot = 3,
                                   .entries = {{.volume_id = 0x200,
                                                .group_id = 0x5001,
                                                .epoch = 3,
                                                .term = 4,
                                                .commit_index = 90,
                                                .applied_index = 88,
                                                .kind = 1,
                                                .state = proto::GroupMemberState::leader,
                                                .lagging = 1,
                                                .drive = 0,
                                                .allocated_bytes = 1U << 30U}}}};
    BOOST_TEST((encoded(status) == from_hex(vec::report_group_status10)));

    const proto::Report fault{.server_id = 0x21,
                              .report_seq = 6,
                              .body = proto::GroupFault{.volume_id = 0x200,
                                                        .group_id = 0x5001,
                                                        .epoch = 3,
                                                        .term = 4,
                                                        .suspect = 0x22,
                                                        .kind = proto::GroupFaultKind::lagging,
                                                        .slot = 3,
                                                        .drive = 0}};
    BOOST_TEST((encoded(fault) == from_hex(vec::report_group_fault11)));

    for (auto hex : {vec::report_group_status10, vec::report_group_fault11}) {
        const auto bytes = from_hex(hex);
        auto back = proto::decode_report(bytes);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((encoded(*back) == bytes));
    }
}

// The version peek refuses what is not a hold frame, and a version this
// build does not speak.
BOOST_AUTO_TEST_CASE(hold_wire_version_refuses_garbage) {
    BOOST_TEST(!kh::hold_wire_version({}).has_value());
    auto bytes = from_hex(vec::hold_v2_hello_ok9);
    auto wrong_magic = bytes;
    wrong_magic[0] ^= std::byte{1};
    BOOST_TEST((kh::hold_wire_version(wrong_magic).error() == proto::DecodeError::bad_magic));
    auto v3 = bytes;
    v3[4] = std::byte{3};
    BOOST_TEST((kh::hold_wire_version(v3).error() == proto::DecodeError::bad_version));
}

BOOST_AUTO_TEST_SUITE_END()
