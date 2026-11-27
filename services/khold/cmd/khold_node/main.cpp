// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// khold_node: the Kythira block server (.kiro/specs/khold-block-service/).
//
// A placeholder until the stripe group state machine (task 7) and the
// co-located cluster (task 13) arrive. Today it links the module and the
// antikythera wire formats, so the target, its build flags and the module
// boundary are exercised from task 1 on, and it reports what it is when
// asked. The container smoke job in khold-module.yml runs --self-test.

#include <kythira/khold/khold_proto.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: khold_node [--help | --self-test]\n"
    "\n"
    "The Kythira block server. Not implemented yet: the server arrives with\n"
    ".kiro/specs/khold-block-service/ tasks 7 and 13.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  round-trip a hold wire v2 frame and a volume layout, then exit\n";

constexpr std::uint64_t self_test_volume = 0x200;
constexpr std::uint64_t self_test_group = 0x5001;
constexpr std::uint64_t self_test_term = 4;
constexpr std::uint64_t self_test_capacity = std::uint64_t{1} << 20U;
constexpr std::uint16_t self_test_port = 7400;

auto fail(const char* what) -> int {
    std::fprintf(stderr, "self-test: %s\n", what);
    return 1;
}

auto self_test() -> int {
    namespace kh = kythira::khold;
    namespace p = ak::proto;

    // A v2 ping: encodes, is seen as v2, decodes to the same header.
    p::HoldV2Header h{};
    h.opcode = p::HoldV2Opcode::ping;
    h.request_id = 1;
    h.volume_id = self_test_volume;
    h.epoch = 1;
    h.group_id = self_test_group;
    h.term = self_test_term;
    const auto frame = p::encode_hold_v2_frame({.header = h, .payload = {}});
    if (!frame) {
        return fail("cannot encode a hold v2 ping");
    }
    const auto version = kh::hold_wire_version(*frame);
    if (!version || *version != kh::HoldWireVersion::v2) {
        return fail("a hold v2 frame is not seen as version 2");
    }
    const auto back = p::decode_hold_v2_frame(*frame);
    if (!back || back->header != h) {
        return fail("a hold v2 ping does not round-trip");
    }

    // A general-class layout (2 data + 1 witness): encodes, decodes, and
    // classifies as the general shape.
    p::VolumeLayout l{};
    l.key_id = 1;
    l.server_id = 1;
    l.volume_id = self_test_volume;
    l.epoch = 1;
    l.lineage_id = 1;
    l.capacity_blocks = self_test_capacity;
    l.qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 3000, .burst_mib = 125};
    l.timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900};
    p::StripeGroup g{.group_id = self_test_group, .members = {}};
    for (std::uint64_t s = 1; s <= 3; ++s) {
        p::LayoutMember m{};
        m.server_id = s;
        m.endpoint[0] = std::byte{0xFD};
        m.endpoint[p::ipv6_address_size - 1] = static_cast<std::byte>(s);
        m.port = self_test_port;
        m.kind = s == 3 ? p::MemberKind::witness : p::MemberKind::data;
        g.members.push_back(m);
    }
    l.groups.push_back(g);
    const auto bytes = p::encode_volume_layout(l);
    if (!bytes) {
        return fail("cannot encode a general-class volume layout");
    }
    const auto decoded = p::decode_volume_layout(*bytes);
    if (!decoded || *decoded != l) {
        return fail("a volume layout does not round-trip");
    }
    if (kh::group_shape(decoded->groups.front()) != kh::general_group_shape) {
        return fail("a 2 data + 1 witness group is not the general shape");
    }

    std::puts("khold_node self-test passed");
    return 0;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view{argv[1]} : std::string_view{};
    if (argc == 2 && arg == "--self-test") {
        return self_test();
    }
    if (argc == 2 && (arg == "--help" || arg == "-h")) {
        std::fputs(usage.data(), stdout);
        return 0;
    }
    std::fputs(usage.data(), stderr);
    return 2;
}
