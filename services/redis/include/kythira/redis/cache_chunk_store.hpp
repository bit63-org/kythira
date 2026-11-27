// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file cache_chunk_store.hpp
/// @brief The build cache's name for the core chunk store.
///
/// The store moved to `<raft/chunk_store.hpp>` so that the S3-compatible
/// storage service can share it (.kiro/specs/s3-compatible-storage/ task 2).
/// The build cache still spells it `cache_chunk_store`; these aliases keep
/// that spelling and change nothing else.

#include <raft/chunk_store.hpp>

namespace kythira {

using cache_chunk_store = chunk_store;
using cache_chunk_store_error = chunk_store_error;
using cache_chunk_store_options = chunk_store_options;
using cache_chunk_store_stats = chunk_store_stats;

}  // namespace kythira
