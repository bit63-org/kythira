// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The khold module's view of antikythera's wire formats
// (.kiro/specs/khold-block-service/ Requirements 1.4, 11.1, 11.2 and 11.5).
//
// The formats themselves live in antikythera's src/proto/, consumed through
// the antikythera-proto overlay port, so hold, khold and every antikythera
// host decode the same bytes with the same code. This header pulls in the
// ones khold speaks (hold wire versions 1 and 2, the signed VolumeLayout,
// the host reports) and adds the few module-level helpers the later tasks
// build on: telling a hold frame's version before decoding it, and
// classifying a stripe group's shape against the volume classes.

#include "proto/codec.hpp"
#include "proto/hold_wire.hpp"
#include "proto/hold_wire_v2.hpp"
#include "proto/report.hpp"
#include "proto/volume_layout.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace kythira::khold {

namespace proto = ak::proto;

// The hold wire versions a khold gateway or server can meet on one port.
enum class HoldWireVersion : std::uint8_t {
    v1 = 1,  // hold (the server khold retires at parity)
    v2 = 2,  // khold: group IDs, terms, REDIRECT
};

// The version of a hold wire frame, from its magic and version byte, so a
// listener hands the frame to the matching decoder. A frame that is too
// short, has the wrong magic, or names a version this build does not know
// is refused with the decoder's own error.
[[nodiscard]] inline auto hold_wire_version(std::span<const std::byte> frame) noexcept
    -> std::expected<HoldWireVersion, proto::DecodeError> {
    const auto v = proto::hold_frame_version(frame);
    if (!v) {
        return std::unexpected(v.error());
    }
    switch (*v) {
        case static_cast<std::uint8_t>(HoldWireVersion::v1):
            return HoldWireVersion::v1;
        case static_cast<std::uint8_t>(HoldWireVersion::v2):
            return HoldWireVersion::v2;
        default:
            return std::unexpected(proto::DecodeError::bad_version);
    }
}

// How many members of each kind a stripe group has.
struct GroupShape {
    std::size_t _data{0};
    std::size_t _witness{0};
    std::size_t _learner{0};
    friend auto operator==(const GroupShape&, const GroupShape&) -> bool = default;
};

[[nodiscard]] inline auto group_shape(const proto::StripeGroup& group) noexcept -> GroupShape {
    GroupShape s;
    for (const auto& m : group.members) {
        switch (m.kind) {
            case proto::MemberKind::data:
                ++s._data;
                break;
            case proto::MemberKind::witness:
                ++s._witness;
                break;
            case proto::MemberKind::learner:
                ++s._learner;
                break;
        }
    }
    return s;
}

// The `general` volume class's steady shape (design.md "Volume classes"):
// two data replicas and one log-only witness, nobody being rebuilt.
inline constexpr GroupShape general_group_shape{._data = 2, ._witness = 1, ._learner = 0};

// The voters of a group: data members and the witness. Learners receive
// entries but do not vote until the controller promotes them.
[[nodiscard]] inline auto group_voters(const GroupShape& s) noexcept -> std::size_t {
    return s._data + s._witness;
}

}  // namespace kythira::khold
