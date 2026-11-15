// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_kms_pkcs11.hpp
/// @brief `KINESIS_KMS=pkcs11` (`.kiro/specs/virtual-hsm/` task 13,
///        Requirement 10.2): core's PKCS#11 provider
///        (raft/kms_key_provider_pkcs11.hpp).

#include <kythira/kinesis/kinesis_kms.hpp>

#include <raft/kms_key_provider_pkcs11.hpp>

namespace kythira::kinesis {

using kms_provider::pkcs11_kms_config;
using kms_provider::pkcs11_kms_provider;

}  // namespace kythira::kinesis
