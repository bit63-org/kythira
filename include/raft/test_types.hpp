// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <raft/json_serializer.hpp>
#include <raft/serializer_registry.hpp>
#include <raft/metrics.hpp>
#include <raft/logger.hpp>
#include <raft/future_default.hpp>
#include <string>
#include <cstdint>

namespace kythira {

// Test transport types template for use in CoAP transport tests
template<typename Serializer> struct test_transport_types {
    // The project's chosen backend, not Folly by name, so the CoAP suites built
    // on this bundle also run in a Folly-free build. promise_template pairs with
    // future_template: coap_transport_impl.hpp's send_rpc() uses
    // promise_template<Response> to build the promise/future pair for both its
    // LIBCOAP_AVAILABLE and stub code paths.
    template<typename T> using future_template = kythira::future_default<T>;
    template<typename T> using promise_template = kythira::promise_default<T>;

    using serializer_type = Serializer;
    using serializer_registry_type = kythira::single_serializer_registry<Serializer>;
    using rpc_serializer_type = Serializer;
    using metrics_type = kythira::noop_metrics;
    using executor_type = int;  // named by the Types bundle, never invoked
    using logger_type = kythira::console_logger;
    using address_type = std::string;
    using port_type = std::uint16_t;
};

}  // namespace kythira
