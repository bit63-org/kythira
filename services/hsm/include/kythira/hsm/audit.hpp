// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The virtual HSM's audit events (.kiro/specs/virtual-hsm/ task 14,
// Requirement 11.1): what the session layer and the operator API report,
// and the JSON line each becomes.
//
// Every login, PIN change, token initialization, object creation (generate,
// create, copy, derive, unwrap), attribute change, destruction and wrap is
// one event, as are unseal, seal, init and rekey. Signing, verification,
// encryption and decryption are counted per client, token, key and
// operation; an event reports the first call and then one in every
// `sample_every`, carrying how many calls it stands for, and every refused
// call is reported. An event names who, which token, which object (handle
// and label) and the result, and never a key, PIN, share or data.
// audit_json.hpp turns one into a JSON line.

#include <kythira/hsm/pkcs11.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace kythira::hsm {

struct audit_event {
    /// "login", "generate_key_pair", "destroy_object", "sign", "unseal", ...
    std::string_view action;
    /// The client identity (a certificate's, a socket allow list's or a
    /// co-located module's name), or the operator for admin actions.
    std::string identity;
    std::optional<std::uint64_t> token;
    std::optional<CK_OBJECT_HANDLE> object;
    /// The object's CKA_LABEL, when it has one.
    std::string label;
    std::optional<CK_MECHANISM_TYPE> mechanism;
    CK_RV rv = CKR_OK;
    std::chrono::microseconds elapsed{0};
    /// For the operator API, the HTTP status answered.
    unsigned http_status = 0;
    /// For a counted operation, the calls this event stands for.
    std::uint64_t calls = 1;
    /// False for a counted call not sampled into the log (metrics still
    /// see it).
    bool logged = true;
};

/// Receives every event (the module logs the ones marked `logged` and
/// counts them all). Called on the caller's thread: it must not block.
using audit_hook = std::function<void(const audit_event&)>;

}  // namespace kythira::hsm
