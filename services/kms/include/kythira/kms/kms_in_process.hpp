// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// What the KMS module publishes as `kms.client`
// (.kiro/specs/kms-compatible-api/ task 12, Requirement 2.3): the calls a
// co-located consumer (Kinesis, DynamoDB) makes for its own caller,
// without a network hop.
//
// The call reaches the same front end the listener feeds, authorized as
// the consumer's caller with kms:ViaService set to the consumer, so a key
// policy reads the same whether the consumer is co-located or forwards
// over HTTPS from another cluster (raft/kms_https_client.hpp). Only the
// service operations are taken (kms_forwarding::service_operations); key
// administration goes through the listener.

#include <raft/module_interfaces.hpp>

#include <boost/json.hpp>

#include <shared_mutex>
#include <string>

namespace kythira::kms {

/// @tparam FrontEnd Anything with `handle_service_call`: front_end<A> in
///         the module, a fake in tests.
template<typename FrontEnd> class in_process_client final : public service_node::kms_endpoint {
public:
    /// @param front_end Outlives this object, or `close()` is called
    ///        before it goes.
    explicit in_process_client(FrontEnd& front_end) : _front_end(&front_end) {}

    [[nodiscard]] auto call(const service_node::caller& /*who*/,
                            const service_node::kms_request& request)
        -> service_node::aws_json_response override {
        const std::shared_lock lock(_mutex);
        if (_front_end == nullptr) {
            return {503, boost::json::serialize(
                             boost::json::object{{"__type", "KMSInternalException"},
                                                 {"message", "The KMS module has stopped."}})};
        }
        const auto answer = _front_end->handle_service_call(
            request.operation, request.body, request.principal, request.via_service,
            request.source_ip.empty() ? std::string("127.0.0.1") : request.source_ip);
        return {static_cast<int>(answer.status), answer.body};
    }

    /// Waits out calls in flight; every later call answers 503.
    void close() {
        const std::unique_lock lock(_mutex);
        _front_end = nullptr;
    }

private:
    std::shared_mutex _mutex;
    FrontEnd* _front_end;
};

}  // namespace kythira::kms
