// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_kms_aws.hpp
/// @brief `KINESIS_KMS=aws`: core's AWS KMS provider
///        (raft/kms_key_provider_aws.hpp), where it moved when DynamoDB
///        needed it. Its `kms_failure`s map onto Kinesis's `KMS*`
///        exceptions as every provider's do.

#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>

#include <raft/kms_key_provider_aws.hpp>

namespace kythira::kinesis {

using kms_provider::aws_kms_config;
using kms_provider::aws_kms_credentials;
using kms_provider::aws_kms_provider;
using kms_provider::aws_kms_transport;

namespace kms_aws_detail {
using namespace kms_provider::aws_detail;  // NOLINT(google-build-using-namespace)
}  // namespace kms_aws_detail

}  // namespace kythira::kinesis
