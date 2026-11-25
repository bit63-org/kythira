// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The role layout an in-process Kinesis test runs its front end in
// (`.kiro/specs/kinesis-independent-layers/` task 7, Requirement 15.1).
//
// A test that builds its service over `layered_access::get()`
// instead of over its cluster runs unchanged in each layout; CTest runs the
// same binary once per layout with `KINESIS_TEST_LAYOUT` set
// (`kythira_kinesis_layout_tests` in CMakeLists.txt), so no layout costs a
// second compile:
//
//   co_located         (also when unset) the service over
//                      `local_data_access` on the test's cluster: exactly
//                      what `kinesis_service<Cluster>` builds for itself.
//   front_end_apart    a front end with no replica: `remote_data_access`
//                      over the real internal transport (the peer client,
//                      signed with the forward secret, over loopback) to a
//                      data node whose gateway serves the data-layer API
//                      from the test's cluster.
//   mixed              a front end on a data node that holds a replica of
//                      the catalog group only: `hybrid_data_access` answers
//                      catalog calls locally and sends every shard call to
//                      the data node that holds the stream groups.
//
// Every layout keeps the test's state in the test's one cluster, so a test
// that inspects or drives the cluster directly (a clock, a seal, a crash)
// sees what the front end did whatever the layout. The data node shares
// the cluster's clock, as NTP keeps real layers in step.
//
// The layouts are built in kinesis_layouts.cpp, compiled once into
// kythira_kinesis_layouts: the HTTPS listener, peer client and remote
// access they instantiate tripled each suite's compile memory when this
// header carried them.

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace kythira::kinesis {
class data_access;
class local_stream_cluster;
}  // namespace kythira::kinesis

namespace kythira::kinesis::test {

struct cluster_handle;

enum class layout_kind : std::uint8_t {
    co_located,
    front_end_apart,
    mixed
};

[[nodiscard]] constexpr auto layout_name(layout_kind k) -> std::string_view {
    switch (k) {
        case layout_kind::co_located:
            return "co_located";
        case layout_kind::front_end_apart:
            return "front_end_apart";
        case layout_kind::mixed:
            return "mixed";
    }
    return "unknown";
}

/// The layout `KINESIS_TEST_LAYOUT` names; co-located when unset. Any other
/// value fails the test run rather than quietly testing co-located again.
[[nodiscard]] inline auto configured_layout() -> layout_kind {
    // Read before any test starts a thread.
    const char* v = std::getenv("KINESIS_TEST_LAYOUT");  // NOLINT(concurrency-mt-unsafe)
    if (v == nullptr || *v == '\0') {
        return layout_kind::co_located;
    }
    for (const auto k :
         {layout_kind::co_located, layout_kind::front_end_apart, layout_kind::mixed}) {
        if (layout_name(k) == v) {
            return k;
        }
    }
    throw std::invalid_argument(std::string("KINESIS_TEST_LAYOUT: unknown layout ") + v);
}

namespace layout_detail {

/// Signs and checks the data-layer calls between the front end and the
/// data node, as `KINESIS_FORWARD_SECRET` does between real nodes.
inline constexpr std::string_view k_secret = "layout-test-forward-secret-0123456789";

}  // namespace layout_detail

/// The `data_access` a test's service runs over in the layout `kind`
/// (default: `KINESIS_TEST_LAYOUT`'s). `cluster` must outlive it.
class layered_access {
public:
    explicit layered_access(local_stream_cluster& cluster, layout_kind kind = configured_layout());
    /// Over any data layer (kinesis_cluster_handle.hpp): the migration path
    /// tests' replicated one, whose replicas move between nodes.
    layered_access(const cluster_handle& handle, layout_kind kind);

    layered_access(const layered_access&) = delete;
    auto operator=(const layered_access&) -> layered_access& = delete;
    layered_access(layered_access&&) = delete;
    auto operator=(layered_access&&) -> layered_access& = delete;
    ~layered_access();

    [[nodiscard]] auto get() const noexcept -> data_access&;
    [[nodiscard]] auto kind() const noexcept -> layout_kind { return _kind; }

    /// Data-layer API calls the data node answered (0 co-located).
    [[nodiscard]] auto remote_calls() const -> std::uint64_t;

private:
    struct impl;
    layout_kind _kind;
    std::unique_ptr<impl> _impl;
};

/// A front end's `data_access` over the real internal transport to one
/// data node, signed with `layout_detail::k_secret`.
struct remote_access {
    std::shared_ptr<data_access> _access;
    /// Calls that found no data node answering.
    std::function<std::uint64_t()> _unreachable;
};

/// The remote access to the data node at `address` ("host:port") alone.
[[nodiscard]] auto remote_access_to(const std::string& address) -> remote_access;

/// Fills `slot` with the layered access over `cluster` and returns it, for
/// fixtures that build their service in a constructor body.
inline auto layer_over(std::unique_ptr<layered_access>& slot, local_stream_cluster& cluster)
    -> data_access& {
    slot = std::make_unique<layered_access>(cluster);
    return slot->get();
}

}  // namespace kythira::kinesis::test
