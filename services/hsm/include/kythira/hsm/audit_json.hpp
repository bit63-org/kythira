// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An audit event (audit.hpp) as the JSON line the module writes and sends
// to a ledger (.kiro/specs/virtual-hsm/ task 14). Kept apart from audit.hpp
// so the session layer does not need Boost.JSON.

#include <kythira/hsm/audit.hpp>

#include <boost/json.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

namespace kythira::hsm {

/// One JSON line for `e`, at `now` (Unix seconds).
[[nodiscard]] inline auto audit_line(const audit_event& e, std::int64_t now) -> std::string {
    const auto hex = [](unsigned long v) {
        std::array<char, 24> buf{};
        std::snprintf(buf.data(), buf.size(), "0x%08lx", v);
        return std::string(buf.data());
    };
    boost::json::object o{{"hsm_audit", e.action},  {"time", now},
                          {"identity", e.identity}, {"result", e.rv == CKR_OK ? "ok" : "error"},
                          {"rv", hex(e.rv)},        {"elapsed_us", e.elapsed.count()}};
    if (e.token) {
        o["token"] = *e.token;
    }
    if (e.object) {
        o["object"] = static_cast<std::uint64_t>(*e.object);
    }
    if (!e.label.empty()) {
        o["label"] = e.label;
    }
    if (e.mechanism) {
        o["mechanism"] = hex(*e.mechanism);
    }
    if (e.http_status != 0) {
        o["status"] = e.http_status;
    }
    if (e.calls != 1) {
        o["calls"] = e.calls;
    }
    return boost::json::serialize(o);
}

}  // namespace kythira::hsm
