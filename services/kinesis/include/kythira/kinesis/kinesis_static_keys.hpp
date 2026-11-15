// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_static_keys.hpp
/// @brief Kinesis's names for core's static access-key file parser
///        (`raft/static_keys_file.hpp`), which began here
///        (`.kiro/specs/kinesis-compatible-streams/` task 6,
///        `KINESIS_STATIC_KEYS_FILE`).

#include <raft/static_keys_file.hpp>

namespace kythira::kinesis {

using aws_auth::parse_static_keys;
using aws_auth::parse_static_role;

}  // namespace kythira::kinesis
