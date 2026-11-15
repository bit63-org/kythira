// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The KMS module's registration in kythira_node (.kiro/specs/
// kms-compatible-api/ task 5). kythira_node links this library
// whole-archive (KYTHIRA_NODE_MODULES), so the registrar below runs and
// KYTHIRA_SERVICES=kms finds the module; nothing names it.

#include "kms_module.hpp"

#include <raft/kythira_node_host.hpp>
#include <raft/module_registry.hpp>

#include <memory>

namespace {

namespace sn = kythira::service_node;

const sn::module_registrar<sn::kythira_node_host> k_kms_registrar("kms", [] {
    return std::make_unique<kythira::kms_node::kms_module<sn::kythira_node_host>>();
});

}  // namespace
