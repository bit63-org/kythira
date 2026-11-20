// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// s3_gateway_node as a member of a Raft index group (run_raft.cpp), built
// where RocksDB is (KYTHIRA_S3_RAFT_DAEMON).

#include <kythira/s3/s3_node_config.hpp>

#include <functional>

namespace kythira::s3_node {

/// Runs the node until `wait` returns; the exit status.
auto run_raft(const s3::env_lookup& env, const s3::node_config& cfg,
              const std::function<void()>& wait) -> int;

}  // namespace kythira::s3_node
