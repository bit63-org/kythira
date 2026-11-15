// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The HSM module's registration in kythira_node (.kiro/specs/virtual-hsm/
// task 6e). kythira_node links this library whole-archive
// (KYTHIRA_NODE_MODULES), so the registrar below runs and
// KYTHIRA_SERVICES=hsm finds the module; nothing names it.

#include "hsm_module.hpp"

#include <raft/kythira_node_host.hpp>
#include <raft/module_registry.hpp>

#include <memory>

namespace {

namespace sn = kythira::service_node;

const sn::module_registrar<sn::kythira_node_host> k_hsm_registrar("hsm", [] {
    return std::make_unique<kythira::hsm_node::hsm_module<sn::kythira_node_host>>();
});

}  // namespace
