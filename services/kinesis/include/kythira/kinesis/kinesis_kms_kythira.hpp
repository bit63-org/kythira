// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_kms_kythira.hpp
/// @brief `KINESIS_KMS=kythira`: core's provider over Kythira's KMS
///        (raft/kms_key_provider_kythira.hpp), made for the "kinesis"
///        service, so the KMS sees `kms:ViaService`
///        `kinesis.<region>.amazonaws.com`.

#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_kms_aws.hpp>

#include <raft/kms_key_provider_kythira.hpp>

#include <utility>

namespace kythira::kinesis {

/// Kythira's KMS, called for the Kinesis caller through the "kinesis"
/// service.
class kythira_kms_provider : public kms_provider::kythira_kms_provider {
public:
    explicit kythira_kms_provider(endpoint_fn endpoint)
        : kms_provider::kythira_kms_provider(std::move(endpoint), "kinesis") {}
};

static_assert(per_caller_kms_key_provider<kythira_kms_provider>);

}  // namespace kythira::kinesis
