// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The SQS module's registration in kythira_node
// (.kiro/specs/sqs-compatible-queues/ task 4, Requirement 1.2).
// kythira_node links this library whole-archive (KYTHIRA_NODE_MODULES), so
// the registrar below runs and KYTHIRA_SERVICES=sqs finds the module;
// nothing names it. The queues live in the node's RocksDB engine.

#include "sqs_module.hpp"

#include <raft/kythira_node_host.hpp>
#include <raft/module_registry.hpp>
#include <raft/rocksdb_kv_engine.hpp>

#include <memory>

namespace {

namespace sn = kythira::service_node;

const sn::module_registrar<sn::kythira_node_host> k_sqs_registrar("sqs", [] {
    return std::make_unique<
        kythira::sqs_node::sqs_module<sn::kythira_node_host, kythira::rocksdb_kv_engine>>();
});

}  // namespace
