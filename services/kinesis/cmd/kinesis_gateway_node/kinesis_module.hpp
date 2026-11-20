// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// Kinesis as a service module (.kiro/specs/service-colocation/ task 5): what
// kinesis_gateway_node's run() did between its Raft transport and its signal
// wait, behind service_module<Host>, so that kinesis_gateway_node (one
// module, its own CBOR Beast transport, ids and data directory exactly as
// before) and kythira_node (beside other modules, on the node's shared
// listener, in Kinesis's group space) run the same code.
//
// `Host` is a service_node::node_host: the module's multi_raft host takes
// the node's client and `server_for(space)`. Kinesis's groups are the
// initial tiling only (its shards split inside the stream state machine,
// never as Raft groups), so the groups are `space.to_host(1..n)`.
//
// It publishes `kinesis.put_records` (kinesis_in_process.hpp): the producer
// calls, for a co-located module such as DynamoDB's streaming destination.
//
// Data directory (KINESIS_DATA_DIR stand-alone, the node's data directory's
// kinesis/ in kythira_node):
//   raft/<group>/   each group's Raft log
//   segments/       the node's record segment store
//
// A node without the `data` role (kinesis-independent-layers task 7,
// KINESIS_ROLES=gateway,front_end) opens neither: it is in no Raft group,
// and serves the whole API, the Lease API and SubscribeToShard over
// remote_data_access, the data-layer API of the data nodes
// KINESIS_DATA_NODES names (kinesis_data_api.hpp).
//
// A node without the `front_end` role (task 8, KINESIS_ROLES=gateway)
// keeps only the public half: it frames, decodes and verifies each request
// and hands the authenticated call to a front end in KINESIS_FRONT_ENDS,
// chosen by affinity (kinesis_authenticated_call.hpp). Every node with the
// `front_end` role serves that front-end API on its listener, co-located
// nodes included, so gateways can be started in front of an existing
// cluster and removed again. A node without the `gateway` role refuses
// client calls with LayerNotServed and serves only the internal routes.

#include "config.hpp"
#ifdef KYTHIRA_KINESIS_GATEWAY_IAM
#include "iam_auth.hpp"
#endif
#include "tier.hpp"

#include <kythira/kinesis/kinesis_actions.hpp>
#include <kythira/kinesis/kinesis_authenticated_call.hpp>
#include <kythira/kinesis/kinesis_compat_profile.hpp>
#include <kythira/kinesis/kinesis_data_access.hpp>
#include <kythira/kinesis/kinesis_data_api.hpp>
#include <kythira/kinesis/kinesis_disk_guard.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_gateway.hpp>
#include <kythira/kinesis/kinesis_in_process.hpp>
#include <kythira/kinesis/kinesis_iterators.hpp>
#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_kms_aws.hpp>
#include <kythira/kinesis/kinesis_kms_kythira.hpp>
#include <kythira/kinesis/kinesis_kms_pkcs11.hpp>
#include <kythira/kinesis/kinesis_lease_api.hpp>
#include <kythira/kinesis/kinesis_channel_delivery.hpp>
#include <kythira/kinesis/kinesis_maintenance.hpp>
#include <kythira/kinesis/kinesis_on_demand.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>
#include <kythira/kinesis/kinesis_raft_cluster.hpp>
#include <kythira/kinesis/kinesis_service.hpp>
#include <kythira/kinesis/kinesis_static_keys.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>
#include <kythira/kinesis/kinesis_tiering.hpp>
#include <kythira/kinesis/kinesis_volume_keeper.hpp>

#include <raft/raft_log_kms.hpp>
#include <raft/beast_https_server.hpp>
#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/json_serializer.hpp>
#include <raft/kms_https_client.hpp>
#include <raft/metrics.hpp>
#include <raft/module_interfaces.hpp>
#include <raft/module_registry.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/node_core.hpp>
#include <raft/multi_raft_transport_handles.hpp>
#include <raft/persistence.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/remote_segment_store.hpp>
#include <raft/segment_volume_placement.hpp>
#include <raft/segment_volume_service.hpp>
#include <raft/service_module.hpp>
#include <raft/static_key_authorizer.hpp>
#include <raft/static_or_iam_authorizer.hpp>
#include <raft/txn_state_machine.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::kinesis_node {

/// The routing key a command names, so the host's cross-shard admission
/// check runs on every proposal and the transaction layer knows which keys
/// an entry touches.
struct stream_partitioner {
    [[nodiscard]] auto key_of(const std::vector<std::byte>& command) const -> std::string {
        return kinesis::command_key(kinesis::decode_command(command));
    }
};

/// Kinesis's multi_raft types on a node whose transport is `Host`'s.
template<typename Host> struct module_host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = kythira::host_node_id;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    /// Not used by the host: the wire is the node's transport's.
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using network_client_type =
        kythira::transport_client_handle<typename Host::client_type, node_id_type>;
    using network_server_type = typename Host::view_type;

    using persistence_engine_type =
        kythira::binary_file_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    /// Wrapped for tier-1 transactions, which resharding commits through
    /// (task 11): the wrapper locks keys a transaction holds and passes
    /// every other entry to the stream state machine.
    using state_machine_type =
        kythira::transactional_state_machine<kinesis::stream_state_machine<log_index_type>,
                                             std::string, stream_partitioner>;

    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type, group_id_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type, group_id_type>;
    using append_entries_request_type =
        kythira::append_entries_request<node_id_type, term_id_type, log_index_type, log_entry_type,
                                        group_id_type>;
    using append_entries_response_type =
        kythira::append_entries_response<term_id_type, log_index_type, group_id_type>;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type,
                                          group_id_type>;
    using install_snapshot_response_type =
        kythira::install_snapshot_response<term_id_type, group_id_type>;
};

inline auto read_file(const std::string& path, std::string_view what) -> std::string {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("kinesis_gateway_node: cannot read " + std::string(what) + " " +
                                 path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

template<typename Host> class kinesis_module final : public service_node::service_module<Host> {
public:
    using types = module_host_types<Host>;
    using raft_host = kythira::multi_raft<types, std::string, std::uint64_t>;
    using raft_config = kythira::multi_raft_config<types, std::string, std::uint64_t>;
    using descriptor_type =
        kythira::shard_descriptor<std::uint64_t, std::string, kythira::host_node_id>;
    using cluster_type = kinesis::raft_stream_cluster<raft_host>;
    using authorizer_type = aws_auth::static_or_iam_authorizer;
    using front_end_type = kinesis::front_end<authorizer_type>;
    using gateway_type = kinesis::gateway<front_end_type>;
    using producer_type = kinesis::in_process_producer<front_end_type>;

    /// @param standalone kinesis_gateway_node's module: its own variables
    ///        for the node-wide settings and the data directory itself.
    ///        Otherwise kythira_node's: the node's settings fill in what the
    ///        module's variables leave unset (composite_env), and the data
    ///        directory is the node's kinesis/.
    explicit kinesis_module(bool standalone) : _standalone(standalone) {}

    kinesis_module(const kinesis_module&) = delete;
    auto operator=(const kinesis_module&) -> kinesis_module& = delete;
    kinesis_module(kinesis_module&&) = delete;
    auto operator=(kinesis_module&&) -> kinesis_module& = delete;
    ~kinesis_module() override { stop(); }

    [[nodiscard]] auto name() const -> std::string_view override { return "kinesis"; }
    [[nodiscard]] auto number() const -> std::uint8_t override {
        return service_node::module_numbers::kinesis;
    }
    [[nodiscard]] auto env_prefix() const -> std::string_view override { return "KINESIS_"; }
    /// IAM's evaluator, and the virtual HSM for `KINESIS_KMS=pkcs11`, when
    /// co-located, answer before this module serves.
    [[nodiscard]] auto starts_after() const -> std::vector<std::string> override {
        return {"iam", "hsm", "kms"};
    }
    [[nodiscard]] auto data_subdir() const -> std::string override {
        return _standalone ? std::string() : std::string("kinesis");
    }

    /// Everything that can be wrong with the configuration fails here,
    /// before a port is bound: the variables, the key file, a key IAM also
    /// has, the compatibility profile.
    [[nodiscard]] auto configure(const service_node::env_lookup& env)
        -> std::optional<std::string> override {
        try {
            _opt = from_env(
                _standalone ? env : composite_env(service_node::module_tuning(env, "KINESIS_")));
            // Kythira's KMS is the default key provider wherever it runs in
            // the same node (kms-compatible-api Requirement 11.1).
            const bool kms_here = !_standalone && service_node::co_located(env, "kms");
            if (!_opt._kms_set && kms_here) {
                _opt._kms = "kythira";
            }
            if (uses_kms("kythira") && _opt._kms_endpoint.empty() && !kms_here) {
                return std::string(
                    "KINESIS_KMS=kythira needs the KMS module in this node or "
                    "KINESIS_KMS_ENDPOINT naming one on another cluster");
            }
            _logger.emplace(_opt._log_level);
            // IAM (KINESIS_AUTH=iam or both): the co-located IAM module's
            // evaluator when kythira_node runs one, taken at start;
            // otherwise the embedded replica, which outlives the gateway.
            std::optional<aws_auth::iam_hooks> hooks;
            _iam_in_process = !_standalone && _opt._auth != aws_auth::auth_mode::static_keys &&
                              service_node::co_located(env, "iam");
            if (_opt._auth != aws_auth::auth_mode::static_keys && !_iam_in_process) {
#ifdef KYTHIRA_KINESIS_GATEWAY_IAM
                _iam = start_iam_auth_from_env();
                hooks = _iam->hooks();
#else
                return std::string(
                    "KINESIS_AUTH=iam or both needs a build with CONFIG_KINESIS_GATEWAY_IAM");
#endif
            }
            _authorizer = std::make_unique<authorizer_type>(
                _opt._static_keys_file.empty()
                    ? std::vector<aws_auth::static_key>{}
                    : kinesis::parse_static_keys(
                          read_file(_opt._static_keys_file, "KINESIS_STATIC_KEYS_FILE")),
                _opt._partition);
            _authorizer->register_service(kinesis::kinesis_static_roles());
            // The Lease API authorizes on the DynamoDB actions KCL needs on
            // AWS.
            _authorizer->register_service(kinesis::lease_static_roles());
            // CreateChannel's iam:PassRole on the service execution role
            // (task 19): admin keys only.
            _authorizer->register_service(kinesis::channel_role_static_roles());
            if (!_iam_in_process) {
                _authorizer->set_mode(_opt._auth, std::move(hooks));
                if (auto clash = key_clash()) {
                    return clash;
                }
            }
            auto profile = kinesis::cluster_profile(_opt._compat);
            if (!profile) {
                return std::string("KINESIS_COMPAT refused");
            }
            _profile = *profile;
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
        return std::nullopt;
    }

    void register_groups(Host& host, const service_node::group_space& space) override {
        _peers = std::make_unique<kinesis::peer_client>(kinesis::peer_client_config{
            ._tls = !_opt._allow_plaintext,
            ._ca_path = _opt._peer_ca_path,
            ._timeout = _opt._command_timeout,
            ._user_agent = std::string(kinesis::k_peer_user_agent),
        });
        // The segment layer (kinesis-independent-layers task 10): a node
        // listed in KINESIS_SEGMENT_NODES holds the volumes placed on it,
        // and a segment node holds nothing else.
        open_volumes();
        if (is_segment_node(_opt._roles)) {
            return;
        }
        if (is_gateway_node(_opt._roles)) {
            build_gateway_node();
            return;
        }
        if (is_front_end_node(_opt._roles)) {
            build_front_end_node();
            return;
        }
        std::filesystem::create_directories(_opt._data_dir / "raft");
        open_store();
        for (const auto& [id, gw] : _opt._peer_gateways) {
            if (id != _opt._node_id) {
                _other_gateways.push_back(gw);
            }
        }
        _transport = kinesis::make_segment_transport(*_peers, _opt._forward_secret);
        // Tiering (task 10): sealed segments past KINESIS_TIER_AFTER_HOURS go
        // to the object store, and a read that needs one fetches it back.
        if (!_opt._tier_bucket.empty()) {
            _tier_owner = make_object_tier(_opt);
        }
        _tier = _tier_owner ? _tier_owner->store() : kinesis::tier_store{};
        // Restore cannot finish without the active segment a snapshot names:
        // try every peer, then the tier, and fail the restore (Raft retries
        // it) when none has it.
        _fetch = [this](const kythira::record_segment_descriptor& d) {
            if (_store->fetch_segment(d, _other_gateways, _transport)) {
                return;
            }
            if (d._sealed && kinesis::fetch_from_tier(*_store, _tier, d)) {
                _fetched.note(d._stream, d._first_seq, wall_ms());
                return;
            }
            throw kythira::record_segment_error("kinesis: no peer or tier served segment " +
                                                d._stream + " at " + std::to_string(d._first_seq));
        };

        for (const auto& [id, url] : _opt._peers) {
            _voters.push_back(id);
        }
        _raft = std::make_unique<raft_host>(make_raft_config(host, space));

        // Initial tiling: cuts sorted and deduplicated, one group per range.
        auto cuts = _opt._shard_cuts;
        std::sort(cuts.begin(), cuts.end());
        cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
        std::optional<std::string> start;
        std::uint64_t group = 1;
        for (std::size_t i = 0; i <= cuts.size(); ++i) {
            std::optional<std::string> end =
                i < cuts.size() ? std::optional<std::string>{cuts[i]} : std::nullopt;
            _raft->create_group(descriptor_type{
                ._group_id = space.to_host(group++),
                ._range = kythira::shard_range<std::string>{._start = start, ._end = end},
                ._epoch = kythira::shard_epoch{},
                ._voters = _voters});
            start = end;
        }
        _groups = cuts.size() + 1;

        build_service();
    }

    void publish(service_node::module_registry& registry) override {
        if (_producer) {
            registry.publish<service_node::aws_json_endpoint>(
                std::string(service_node::interface_names::kinesis_put_records), _producer);
        }
    }

    void start(service_node::module_registry& registry) override {
        if (is_segment_node(_opt._roles)) {
            start_segment_node();
            return;
        }
        if (_iam_in_process) {
            // IAM starts first (starts_after), so its evaluator answers
            // before this module serves a request.
            auto iam = registry.lookup<service_node::iam_evaluator>(
                std::string(service_node::interface_names::iam_evaluator));
            if (!iam) {
                throw std::invalid_argument(
                    "KINESIS_AUTH=iam or both: the IAM module publishes no evaluator");
            }
            iam->add_actions(kinesis::kinesis_actions());
            // The Lease API's DynamoDB actions, as on AWS's lease table.
            iam->add_actions(kinesis::lease_actions());
            _authorizer->set_mode(_opt._auth, iam->hooks());
            if (auto clash = key_clash()) {
                throw std::invalid_argument(*clash);
            }
            _iam_evaluator = std::move(iam);
        }
        if (uses_kms("kythira") && _opt._kms_endpoint.empty()) {
            // The KMS starts first (starts_after) and publishes its client.
            _kms_client = registry.lookup<service_node::kms_endpoint>(
                std::string(service_node::interface_names::kms_client));
            if (!_kms_client) {
                throw std::invalid_argument(
                    "KINESIS_KMS=kythira: the KMS module publishes no client");
            }
        }
        if (uses_kms("pkcs11") && !_kms_token.module_path) {
            // The HSM starts first (starts_after); a stand-alone node, or
            // one without the HSM module, names a module-path instead.
            _hsm_pkcs11 = registry.lookup<service_node::pkcs11_provider>(
                std::string(service_node::interface_names::hsm_pkcs11));
            if (!_hsm_pkcs11) {
                throw std::invalid_argument(
                    "KINESIS_KMS=pkcs11: KINESIS_KMS_PKCS11_URI names no module-path and no "
                    "virtual HSM is co-located");
            }
        }
        if (_raft) {
            _raft->start();
        }

        https::server_config hc;
        hc.bind_address = _opt._listen_host;
        hc.port = _opt._listen_port;
        hc.tls_cert_path = _opt._tls_cert_path;
        hc.tls_key_path = _opt._tls_key_path;
        hc.insecure_plaintext = _opt._allow_plaintext;
        hc.max_body_bytes = _opt._max_body_bytes;
        hc.max_connections = _opt._max_connections;
        // AWS SDKs subscribe to shards over HTTP/2 (task 13).
        hc.http2 = true;
        _server = std::make_unique<https::server>(
            hc,
            [this](const https::request& req, const https::request_context& ctx) {
                return _gateway->handle(req, ctx);
            },
            [this](bool warning, std::string_view message) {
                _logger->log(warning ? kythira::log_level::warning : kythira::log_level::info,
                             "kinesis gateway: " + std::string(message), {});
            });
        // SubscribeToShard answers with an event stream (task 13).
        _server->set_stream_handler(
            [this](const https::request& req, const https::request_context& ctx) {
                return _gateway->stream(req, ctx);
            });
        _server->start();
        if (!_raft) {
            // A front end or a gateway without data: no data-layer routes to
            // serve (it holds no replica and no segments), no Raft to drive,
            // no shard it leads to maintain. A front end serves the
            // front-end API on this listener.
            _started = true;
            std::cout << "kinesis_gateway_node " << kythira::host_node_id_text(_opt._node_id)
                      << " ready: "
                      << (is_gateway_node(_opt._roles)
                              ? "gateway without front end, front_ends=" +
                                    std::to_string(_opt._front_ends.size())
                              : "front end without data, data_nodes=" +
                                    std::to_string(_opt._data_nodes.size()))
                      << " roles=" << _opt._roles.to_string() << " kinesis=" << _server->port()
                      << (_opt._allow_plaintext ? " (http)" : " (https)") << std::endl;
            return;
        }
        if (_opt._internal_port != 0) {
            // KINESIS_INTERNAL_LISTEN: the routes between nodes on a listener
            // of their own (independent layers task 6).
            https::server_config ic = hc;
            ic.bind_address = _opt._internal_host;
            ic.port = _opt._internal_port;
            ic.http2 = false;
            _internal_server = std::make_unique<https::server>(
                ic,
                [this](const https::request& req, const https::request_context& ctx) {
                    return _gateway->handle_internal(req, ctx);
                },
                [this](bool warning, std::string_view message) {
                    _logger->log(warning ? kythira::log_level::warning : kythira::log_level::info,
                                 "kinesis internal listener: " + std::string(message), {});
                });
            _internal_server->start();
        }

        _driving = true;
        _driver = std::thread([this] {
            while (_driving.load(std::memory_order_acquire)) {
                (void)_raft->tick();
                std::this_thread::sleep_for(_opt._tick_interval);
            }
        });

        // Retention and tiering: each node runs the pass; only a shard's
        // leader seals, trims and tiers it.
        // Segment volume assignments (task 10): the catalog leader seeds
        // and replaces them; every node watches its own.
        if (!_opt._segment_nodes.empty()) {
            _keeper = std::make_unique<kinesis::volume_keeper<cluster_type>>(
                *_cluster, kinesis::volume_keeper_config{
                               ._service = "kinesis",
                               ._self = kythira::host_node_id_text(_opt._node_id),
                               ._replicas = volume_replicas(),
                               ._nodes = _opt._segment_nodes,
                               ._replace_after_ms = k_volume_replace_after_ms,
                               ._probe = [this](const kythira::segment_node_info& n) {
                                   return kythira::remote_segment_store::probe_space(
                                       kinesis::make_volume_transport(*_peers, _opt._forward_secret,
                                                                      n._endpoint));
                               }});
        }
        _maintenance = std::make_unique<kinesis::stream_maintenance<cluster_type>>(
            *_cluster, *_store, _tier, _fetched,
            kinesis::maintenance_config{._tier_after_ms = _opt._tier_after_ms,
                                        ._keep_fetched_ms = std::int64_t{10} * 60 * 1000});
        // On-demand streams (task 12): each node splits the hot shards it
        // leads.
        _on_demand =
            std::make_unique<kinesis::on_demand_controller<cluster_type>>(*_cluster, *_service);
        // Channels (task 19): each node delivers the shards it leads.
        if (_opt._channel_delivery) {
            _channel_destinations = make_channel_destinations(_opt);
            if (!_channel_destinations) {
                log_info(
                    "kinesis channels: this build has no S3 client (the AWS SDK's s3 "
                    "component); channels are not delivered from this node");
            }
        }
        kinesis::channel_delivery_config channels;
        channels._max_delay_ms = _opt._channel_max_delay_ms;
        // Encrypted channels (Requirement 18.4): the provider streams are
        // encrypted at rest with, or SSE-KMS in the bucket.
        channels._encryption = _opt._channel_sse_kms ? kinesis::channel_encryption::sse_kms
                                                     : kinesis::channel_encryption::envelope;
        channels._kms = _channel_kms;
        if (_channel_destinations) {
            channels._destination = [d = _channel_destinations.get()](
                                        const std::string& b, const kinesis::channel_access& a) {
                return d->bucket(b, a);
            };
            channels._tables = [d = _channel_destinations.get()](const std::string& arn,
                                                                 const kinesis::channel_access& a) {
                return d->tables(arn, a);
            };
        }
        _channels = std::make_unique<
            kinesis::channel_delivery<cluster_type, kinesis::kinesis_service<cluster_type>>>(
            *_cluster, *_service, std::move(channels));
        _maintaining = true;
        _maintainer = std::thread([this] { maintain(); });
        _started = true;

        std::cout << "kinesis_gateway_node " << kythira::host_node_id_text(_opt._node_id)
                  << " ready: raft=" << _opt._raft_port << " kinesis=" << _server->port()
                  << (_opt._allow_plaintext ? " (http)" : " (https)") << " groups=" << _groups
                  << " voters=" << _voters.size() << std::endl;
    }

    /// No request in flight, in-process or over the listener, once the host
    /// stops.
    void drain() override {
        // A gateway drains before it stops (Requirement 4.7): it stops
        // accepting connections, lets calls in flight finish up to
        // KINESIS_DRAIN_TIMEOUT_MS, and ends event streams with the
        // retryable error; a front end refuses new calls as not executed
        // so gateways take them elsewhere.
        if (_gateway && _server && !_drained.exchange(true)) {
            _gateway->begin_drain();
            if (_fe_server) {
                _fe_server->drain();
            }
            if (!_gateway->await_idle(_opt._drain_timeout)) {
                log_info("kinesis gateway: drain bound passed with " +
                         std::to_string(_gateway->in_flight()) + " call(s) in flight");
            }
        }
        if (_producer) {
            _producer->close();
        }
        _maintaining.store(false, std::memory_order_release);
        if (_maintainer.joinable()) {
            _maintainer.join();
        }
        if (_server) {
            _server->stop();
        }
        if (_internal_server) {
            _internal_server->stop();
        }
    }

    /// No tick once the host is gone.
    void stop() override {
        drain();
        _driving.store(false, std::memory_order_release);
        if (_driver.joinable()) {
            _driver.join();
        }
        if (_raft) {
            _raft->stop();
        }
        _started = false;
        // Everything that refers to the host goes before it.
        _channels.reset();
        _channel_destinations.reset();
        _on_demand.reset();
        _maintenance.reset();
        _keeper.reset();
        _server.reset();
        _internal_server.reset();
        _volumes.reset();
        _leases.reset();
        _remote_leases.reset();
        _gateway.reset();
        _fe_server.reset();
        _remote_fe.reset();
        _fe_peers.reset();
        _local_data.reset();
        _service.reset();
        _remote_service.reset();
        _remote_data.reset();
        _front_end.reset();
        _cluster.reset();
        _raft.reset();
    }

    [[nodiscard]] auto health() const -> service_node::module_health override {
        if (!_started) {
            return {false, "not started"};
        }
        // A replica whose volume does not answer has stopped applying
        // (Requirement 9.5): say so, so the data layer replaces it.
        if (_remote != nullptr && !_volume_reachable.load(std::memory_order_acquire)) {
            return {false, "segment volume " + _remote->volume() +
                               " is unreachable on segment node " + _volume_node};
        }
        // Placement moved this node's volume: it restarts into the new one.
        {
            const std::scoped_lock lock(_moved_mu);
            if (!_volume_moved.empty()) {
                return {false, _volume_moved};
            }
        }
        return {true, {}};
    }

    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> override {
        if (!_started) {
            return {};
        }
        std::vector<service_node::module_metric> out;
        if (_raft) {
            out.push_back({"groups", static_cast<double>(_groups), {}});
            out.push_back({"voters", static_cast<double>(_voters.size()), {}});
            out.push_back({"raft_term_sum", service_node::raft_term_sum(*_raft), {}});
        }
        if (_volumes) {
            out.push_back({"segment_volumes", static_cast<double>(_volumes->volumes().size()), {}});
        }
        // A front end without data: how its data-layer calls fare.
        if (_remote_data) {
            const auto st = _remote_data->stats();
            out.push_back({"data_api_calls", static_cast<double>(st._calls), {}});
            out.push_back({"data_api_not_leader", static_cast<double>(st._not_leader), {}});
            out.push_back({"data_api_stale_route", static_cast<double>(st._stale_route), {}});
            out.push_back({"data_api_unreachable", static_cast<double>(st._unreachable), {}});
        }
        // Task 8: how the handoff between gateways and front ends fares.
        if (_remote_fe) {
            auto& st = _remote_fe->stats();
            out.push_back({"front_end_calls", static_cast<double>(st._calls.load()), {}});
            out.push_back({"front_end_failovers", static_cast<double>(st._failovers.load()), {}});
            out.push_back({"front_end_unplaced", static_cast<double>(st._unplaced.load()), {}});
            out.push_back({"front_end_unanswered", static_cast<double>(st._unanswered.load()), {}});
        }
        if (_fe_server) {
            const auto& st = _fe_server->stats();
            out.push_back({"authenticated_calls", static_cast<double>(st._calls.load()), {}});
            out.push_back({"authenticated_refused", static_cast<double>(st._refused.load()), {}});
            out.push_back({"event_sessions", static_cast<double>(_fe_server->sessions()), {}});
        }
        // One series per role this node runs (kinesis-independent-layers
        // Requirement 2.6), so a dashboard can count each layer.
        for (const auto r : kythira::layers::every_role) {
            if (_opt._roles.has(r)) {
                out.push_back(
                    {"role", 1.0, {{"role", std::string(kythira::layers::role_name(r))}}});
            }
        }
        return out;
    }

    /// The API's port once started (tests pass port 0).
    [[nodiscard]] auto api_port() const -> std::uint16_t { return _server ? _server->port() : 0; }

private:
    /// The record segment store: the node's own directory, or with
    /// `KINESIS_ROLES` lacking `segments`, its volume on the segment node
    /// KINESIS_SEGMENT_NODES places it on. A segment node that is not up
    /// yet, or has not assigned the volume yet, is waited for; one that
    /// stays away fails the start.
    void open_store() {
        if (_opt._roles.has(kythira::layers::role::segments)) {
            std::filesystem::create_directories(_opt._data_dir / "segments");
            kythira::record_segment_store_options so;
            so._data_dir = _opt._data_dir / "segments";
            _store = std::make_unique<kythira::record_segment_store>(so);
            return;
        }
        const auto self = kythira::host_node_id_text(_opt._node_id);
        // The catalog's word, as this node last saw it, wins over the
        // settings' first placement: after a replacement the volume is
        // somewhere the settings do not say.
        auto assignment = saved_assignment(self);
        if (!assignment) {
            assignment = kythira::assignment_of(volume_assignments(_opt), self);
        }
        const auto node =
            assignment ? kythira::segment_node_of(_opt._segment_nodes, assignment->_segment_node)
                       : std::nullopt;
        if (!assignment || !node) {
            throw std::invalid_argument("kinesis: no segment volume is placed for node " + self);
        }
        _volume_node = node->_id;
        auto inner = kinesis::make_volume_transport(*_peers, _opt._forward_secret, node->_endpoint);
        kythira::segment_volume_transport transport =
            [this, inner = std::move(inner)](std::vector<std::byte> request) {
                auto r = inner(std::move(request));
                _volume_reachable.store(r.has_value(), std::memory_order_release);
                return r;
            };
        const auto deadline = std::chrono::steady_clock::now() + k_volume_wait;
        for (;;) {
            try {
                // A segment node that never held this volume (a replacement
                // moved it there) creates it at the catalog's epoch.
                kythira::remote_segment_store::assign(transport, assignment->_volume,
                                                      assignment->_epoch);
                auto remote = std::make_unique<kythira::remote_segment_store>(
                    transport, assignment->_volume, assignment->_epoch);
                _remote = remote.get();
                _store = std::move(remote);
                break;
            } catch (const kythira::record_segment_error& e) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    throw kythira::record_segment_error(
                        "kinesis: segment node " + node->_id + " (" + node->_endpoint +
                        ") did not open volume " + assignment->_volume + ": " + e.what());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
        _opened = *assignment;
        log_info("kinesis: record segments on volume " + assignment->_volume + " epoch " +
                 std::to_string(assignment->_epoch) + " at segment node " + node->_id + " (" +
                 node->_endpoint + ")");
    }

    /// The volumes KINESIS_SEGMENT_NODES places on this node, when it is
    /// one of them and runs `segments`. Re-assigning at the same epoch on
    /// restart keeps each volume's files.
    void open_volumes() {
        const auto self = kythira::host_node_id_text(_opt._node_id);
        if (!_opt._roles.has(kythira::layers::role::segments) ||
            !kythira::segment_node_of(_opt._segment_nodes, self)) {
            return;
        }
        // The local store's defaults: a replica's files must match what a
        // co-located replica would write (Requirement 9.7).
        _volumes = std::make_unique<kythira::segment_volume_service>(
            kythira::segment_volume_service_options{.data_dir = _opt._data_dir, .store = {}});
        // A volume already here at a newer epoch was moved here by a
        // replacement (or moved away and back): the catalog's epoch stands.
        std::map<std::string, std::uint64_t> held;
        for (const auto& [id, epoch] : _volumes->volumes()) {
            held[id] = epoch;
        }
        for (const auto& a : volume_assignments(_opt)) {
            const auto it = held.find(a._volume);
            if (a._segment_node == self && (it == held.end() || it->second < a._epoch)) {
                _volumes->assign(a._volume, a._epoch);
            }
        }
    }

    /// A segment node's listener: health and the volume API, nothing else.
    void start_segment_node() {
        https::server_config hc;
        hc.bind_address = _opt._listen_host;
        hc.port = _opt._listen_port;
        hc.tls_cert_path = _opt._tls_cert_path;
        hc.tls_key_path = _opt._tls_key_path;
        hc.insecure_plaintext = _opt._allow_plaintext;
        hc.max_body_bytes = _opt._max_body_bytes;
        hc.max_connections = _opt._max_connections;
        _server = std::make_unique<https::server>(
            hc,
            [this](const https::request& req, const https::request_context&) {
                const std::string_view target = req.target();
                const auto path = target.substr(0, target.find('?'));
                if (path == kinesis::k_health_path &&
                    req.method() == boost::beast::http::verb::get) {
                    auto res = kinesis::gateway_detail::reply(req, 200, "ok\n", "text/plain");
                    res.set(kinesis::k_roles_header, _opt._roles.to_string());
                    return res;
                }
                if (path == kinesis::k_volume_path) {
                    return kinesis::serve_volume(req, _opt._forward_secret, *_volumes,
                                                 std::chrono::system_clock::now());
                }
                return kinesis::gateway_detail::reply(req, 404, "not found\n", "text/plain");
            },
            [this](bool warning, std::string_view message) {
                _logger->log(warning ? kythira::log_level::warning : kythira::log_level::info,
                             "kinesis segment node: " + std::string(message), {});
            });
        _server->start();
        _started = true;
        std::cout << "kinesis_gateway_node " << kythira::host_node_id_text(_opt._node_id)
                  << " ready: segment node, volumes=" << _volumes->volumes().size()
                  << " kinesis=" << _server->port()
                  << (_opt._allow_plaintext ? " (http)" : " (https)") << std::endl;
    }

    /// The segment node's `{capacity, available}`, asked at most every few
    /// seconds; the last answer while it does not reply, nullopt before
    /// the first.
    [[nodiscard]] auto segment_space() -> std::optional<std::pair<std::uint64_t, std::uint64_t>> {
        const std::scoped_lock lock(_space_mu);
        const auto now = std::chrono::steady_clock::now();
        if (_remote != nullptr && (!_space || now - _space_at >= std::chrono::seconds{5})) {
            _space_at = now;
            try {
                _space = _remote->space();
            } catch (const std::exception&) {
                // Keep the last answer: a missed reply is not an empty disk.
            }
        }
        return _space;
    }

    /// KINESIS_AUTH=both: an access key id may be in the key file or in
    /// IAM, not both.
    [[nodiscard]] auto key_clash() const -> std::optional<std::string> {
        if (const auto clash = _authorizer->conflicting_keys(); !clash.empty()) {
            return "KINESIS_AUTH=both: IAM also has the static key " + clash.front() +
                   "; an access key id may be in one or the other";
        }
        return std::nullopt;
    }

    [[nodiscard]] static auto wall_ms() -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    auto make_raft_config(Host& host, const service_node::group_space& space) -> raft_config {
        const auto raft_dir = _opt._data_dir / "raft";
        // Sealed at rest when KYTHIRA_RAFT_LOG_KMS says so
        // (.kiro/specs/raft-log-encryption/); one key ring per data dir.
        const auto log_options = kythira::raft_log_options_for(
            _opt._data_dir, kythira::raft_log_encryption_settings::from_environment());
        raft_config cfg{
            .node_id = _opt._node_id,
            .network_client = typename types::network_client_type{host.client()},
            .network_server = host.server_for(space),
            .store_factory =
                [raft_dir, log_options](const std::uint64_t& group) {
                    return typename types::persistence_engine_type{raft_dir / std::to_string(group),
                                                                   log_options};
                },
        };
        cfg.state_machine_factory = [this](const std::uint64_t&) {
            return typename types::state_machine_type(
                kinesis::stream_state_machine<std::uint64_t>(_store.get(), _fetch));
        };
        cfg.logger = kythira::console_logger{_opt._log_level};
        cfg.logger_factory = [level = _opt._log_level](const std::uint64_t&) {
            return kythira::console_logger{level};
        };
        cfg.config._election_timeout_min = _opt._election_timeout_min;
        cfg.config._election_timeout_max = _opt._election_timeout_max;
        cfg.config._heartbeat_interval = _opt._heartbeat_interval;
        cfg.config._rpc_timeout = _opt._rpc_timeout;
        cfg.config._max_append_bytes = _opt._max_body_bytes;
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.executor_stripes = _opt._executor_stripes;
        cfg.policy_interval = _opt._policy_interval;
        cfg.partitioner = kythira::make_partitioner<std::string>(stream_partitioner{});
        // A data node on a volume reports its segment node's storage, so
        // the data layer's capacity policy counts the segment layer's room
        // (Requirement 10.6).
        if (_remote != nullptr) {
            cfg.capacity_probe = [this] {
                return segment_space().value_or(std::pair<std::uint64_t, std::uint64_t>{0, 0});
            };
        }
        return cfg;
    }

    /// Whether `name` is this node's key provider or its previous one.
    [[nodiscard]] auto uses_kms(std::string_view name) const -> bool {
        return _opt._kms == name || _opt._kms_previous == name;
    }

    /// The key provider `name` (`KINESIS_KMS` or `KINESIS_KMS_PREVIOUS`)
    /// from its settings; empty for `off`.
    auto make_kms_provider(const std::string& name) -> kinesis::key_provider {
        if (name == "local") {
            return kinesis::key_provider(kinesis::local_kms_provider(_opt._kms_passphrase));
        }
        if (name == "aws") {
            kinesis::aws_kms_config kc;
            kc._region = _opt._kms_region;
            kc._endpoint = _opt._kms_endpoint;
            // Read once at startup: nothing in the process changes its
            // environment.
            const auto env = [](const char* var) {
                const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe)
                return v != nullptr ? std::string(v) : std::string();
            };
            kc._credentials = [creds = kinesis::aws_kms_credentials{
                                   env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"),
                                   env("AWS_SESSION_TOKEN")}] { return creds; };
            return kinesis::key_provider(kinesis::aws_kms_provider(std::move(kc)));
        }
        if (name == "kythira") {
            if (!_opt._kms_endpoint.empty()) {
                // A KMS on another cluster: signed as this gateway, which
                // the KMS trusts to forward the caller it serves.
                const auto env = [](const char* var) {
                    const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe)
                    return v != nullptr ? std::string(v) : std::string();
                };
                service_node::kms_https_config kc;
                kc.endpoint = "https://" + _opt._kms_endpoint;
                kc.region = _opt._kms_region;
                kc.access_key_id = env("AWS_ACCESS_KEY_ID");
                kc.secret_access_key = env("AWS_SECRET_ACCESS_KEY");
                kc.session_token = env("AWS_SESSION_TOKEN");
                kc.tls.ca_path = _opt._kms_ca;
                kc.tls.client_certificate = false;
                _kms_client = std::make_shared<service_node::kms_https_endpoint>(std::move(kc));
            }
            // Set before the listener opens (here, or in start() for the
            // co-located client) and never after: a plain read.
            return kinesis::key_provider(
                kinesis::kythira_kms_provider([this] { return _kms_client; }));
        }
        if (name == "pkcs11") {
            _kms_token = pkcs11::uri::parse(_opt._kms_pkcs11_uri);
            kinesis::pkcs11_kms_config kc;
            kc.token = _kms_token;
            kc.oaep = _opt._kms_pkcs11_oaep == "sha1" ? pkcs11::hash_algorithm::sha1
                                                      : pkcs11::hash_algorithm::sha256;
            // The module opens on first use, after start() has found the
            // co-located HSM when the URI names no library.
            return kinesis::key_provider(
                kinesis::pkcs11_kms_provider(std::move(kc), [this]() -> pkcs11::module {
                    if (_kms_token.module_path) {
                        return pkcs11::module::load(_kms_token);
                    }
                    if (!_hsm_pkcs11) {
                        throw kinesis::kms_error(kinesis::kms_failure::unavailable,
                                                 "The co-located virtual HSM is not running.");
                    }
                    return pkcs11::module(_hsm_pkcs11->backend_for(_opt._kms_pkcs11_identity));
                }));
        }
        return {};
    }

    /// The cluster adapter, the front end, the service, the gateway and
    /// the Lease API: everything a request reaches, built before any
    /// listener opens.
    void build_service() {
        const auto gateways = _opt._peer_gateways;
        const auto address_of =
            [gateways](const kythira::host_node_id& id) -> std::optional<std::string> {
            const auto it = gateways.find(id);
            return it == gateways.end() ? std::nullopt : std::optional{it->second};
        };
        // On a volume, the guarded disk is the segment node's.
        _guard = _remote == nullptr ? std::make_unique<kinesis::disk_guard>(
                                          _opt._data_dir / "segments", _opt._disk_floor_bytes)
                                    : std::make_unique<kinesis::disk_guard>(
                                          _opt._disk_floor_bytes,
                                          [this]() -> std::optional<std::uint64_t> {
                                              if (auto s = segment_space()) {
                                                  return s->second;
                                              }
                                              return std::nullopt;
                                          },
                                          [] { return wall_ms(); }, std::chrono::seconds{5});
        _cluster =
            std::make_unique<cluster_type>(*_raft,
                                           kinesis::make_http_forwarder<kythira::host_node_id>(
                                               *_peers, _opt._forward_secret, address_of),
                                           _opt._command_timeout, &_write_limits, _guard.get());
        // Transaction ops (resharding, task 11) go to the leading gateway,
        // and the host's lock resolver asks other groups' leaders the same
        // way.
        _cluster->set_txn_forwarder(kinesis::make_http_txn_forwarder<kythira::host_node_id>(
            *_peers, _opt._forward_secret, address_of));
        _raft->set_txn_forwarder([this](const std::vector<std::string>& keys,
                                        const std::vector<std::byte>& envelope,
                                        std::chrono::milliseconds timeout) {
            return _cluster->txn_send(keys, envelope, timeout);
        });

        const auto fc = make_front_end_config();
        _front_end = std::make_unique<front_end_type>(fc, *_authorizer);
        _service = std::make_unique<kinesis::kinesis_service<cluster_type>>(*_cluster,
                                                                            make_service_config());
        _service->register_with(*_front_end);
        // Authorization sees a stream's tags and resource policy (task 15).
        _front_end->set_resource_lookup(
            [this](std::string_view arn) { return _service->resource_facts_of(arn); });
        _gateway = std::make_unique<gateway_type>(
            *_front_end,
            [this](const std::string& key, const std::vector<std::byte>& command,
                   kinesis::admission mode) { return _cluster->propose_local(key, command, mode); },
            _store.get(), _opt._forward_secret);
        _gateway->set_roles(_opt._roles);
        _gateway->set_volume_service(_volumes.get());
        _leases = std::make_unique<kinesis::lease_api<cluster_type, authorizer_type>>(
            *_cluster, *_authorizer, fc);
        _gateway->set_lease_handler(
            [this](const kinesis::front_end_request& r) { return _leases->handle(r); });
        if (_opt._metrics) {
            _gateway->set_metrics_handler([this] { return _service->metrics_text(); });
        }
        // The data-layer API (independent layers task 6): front ends without
        // a replica read and propose through this node's replicas.
        _local_data = std::make_unique<kinesis::local_data_access<cluster_type>>(*_cluster);
        _gateway->set_data_api(kinesis::data_api_deps_over(*_raft, *_cluster, *_local_data,
                                                           std::function(address_of)));
        _gateway->set_txn_handler(
            [this](const std::vector<std::string>& keys, const std::vector<std::byte>& envelope) {
                return _cluster->txn_submit_local(keys, envelope);
            });
        wire_layers([this](const kinesis::authenticated_call& c) { return _leases->execute(c); },
                    [this] { return _service->metrics_text(); });
    }

    /// The task 8 half of every node's wiring, once its front end and
    /// gateway exist: with `front_end`, serve the front-end API to gateways
    /// on other nodes; with `gateway` and no `front_end`, hand calls to
    /// KINESIS_FRONT_ENDS. The in-process producer is published only by a
    /// node that runs both, since it is the gateway and the front end in
    /// one call (Requirement 12.3); elsewhere DynamoDB's streaming
    /// destination misses the registry and uses its network client.
    void wire_layers(
        std::function<aws_json::http_response(const kinesis::authenticated_call&)> lease,
        std::function<std::string()> metrics) {
        using kythira::layers::role;
        if (_opt._roles.has(role::front_end)) {
            kinesis::front_end_routes routes;
            routes._execute = [this](kinesis::authenticated_call& c) {
                auto r = _front_end->execute(c);
                return kinesis::front_end_routes::execution{std::move(r._response),
                                                            std::move(r._events)};
            };
            routes._lease = std::move(lease);
            if (_opt._metrics) {
                routes._metrics = std::move(metrics);
            }
            _fe_server = std::make_unique<kinesis::front_end_server>(std::move(routes));
            _gateway->set_front_end_server(_fe_server.get());
        } else if (_opt._roles.has(role::gateway)) {
            wire_remote_front_ends();
        }
        _gateway->set_drain_hook([this] {
            if (_server) {
                _server->stop_accepting();
            }
        });
        if (_opt._roles.has(role::gateway) && _opt._roles.has(role::front_end)) {
            _producer = std::make_shared<producer_type>(*_front_end);
        }
    }

    /// A gateway without a local front end: calls go to KINESIS_FRONT_ENDS
    /// over a client whose timeout covers a front end's longest call (a
    /// write's commit timeout, then its own data-layer retries).
    void wire_remote_front_ends() {
        _fe_peers = std::make_unique<kinesis::peer_client>(kinesis::peer_client_config{
            ._tls = !_opt._allow_plaintext,
            ._ca_path = _opt._peer_ca_path,
            ._timeout = _opt._command_timeout * 2 + std::chrono::seconds{5},
            ._user_agent = std::string(kinesis::k_peer_user_agent),
        });
        _remote_fe = std::make_shared<kinesis::remote_front_ends>(
            _opt._front_ends,
            kinesis::make_http_front_end_transport(*_fe_peers, _opt._forward_secret));
        _front_end->set_operations_served_elsewhere(
            kinesis::kinesis_service<kinesis::data_access>::k_operations);
        _gateway->set_remote_front_ends(_remote_fe);
        _gateway->set_lease_authenticator(
            [this, fc = make_front_end_config()](const kinesis::front_end_request& r) {
                return kinesis::authenticate_lease_request(*_authorizer, fc, r);
            });
    }

    /// A gateway alone (task 8): no store, no Raft, no data access and no
    /// handlers. Its front end object only frames, decodes and verifies;
    /// every call goes to a front end in KINESIS_FRONT_ENDS. `/metrics` is
    /// a front end's, executed there, with this gateway's own counters
    /// after it.
    void build_gateway_node() {
        _front_end = std::make_unique<front_end_type>(make_front_end_config(), *_authorizer);
        _gateway = std::make_unique<gateway_type>(
            *_front_end,
            [](const std::string&, const std::vector<std::byte>&, kinesis::admission) {
                return std::optional<kinesis::apply_result>{};
            },
            nullptr, _opt._forward_secret);
        _gateway->set_roles(_opt._roles);
        wire_layers({}, {});
        if (_opt._metrics) {
            _gateway->set_metrics_handler(
                [this] { return _remote_fe->metrics().value_or("") + gateway_metrics_text(); });
        }
    }

    /// A gateway's own counters, in the Prometheus text format.
    [[nodiscard]] auto gateway_metrics_text() const -> std::string {
        std::ostringstream out;
        const auto line = [&out](std::string_view name, double v) {
            out << "# TYPE kythira_kinesis_gateway_" << name << " gauge\n"
                << "kythira_kinesis_gateway_" << name << ' ' << v << '\n';
        };
        if (_remote_fe) {
            auto& st = _remote_fe->stats();
            line("front_end_calls", static_cast<double>(st._calls.load()));
            line("front_end_failovers", static_cast<double>(st._failovers.load()));
            line("front_end_unplaced", static_cast<double>(st._unplaced.load()));
            line("front_end_unanswered", static_cast<double>(st._unanswered.load()));
            line("streams_relayed", static_cast<double>(st._streams_relayed.load()));
            line("streams_broken", static_cast<double>(st._streams_broken.load()));
            line("front_ends", static_cast<double>(_remote_fe->front_ends().addresses().size()));
            line("front_ends_suspect", static_cast<double>(_remote_fe->front_ends().suspects()));
        }
        if (_gateway) {
            line("in_flight", static_cast<double>(_gateway->in_flight()));
            line("draining", _gateway->draining() ? 1.0 : 0.0);
        }
        return out.str();
    }

    /// A front end without the `data` role (task 7): the same front end,
    /// service, Lease API and gateway as a data node's, over the data-layer
    /// API of the data nodes KINESIS_DATA_NODES names instead of a cluster.
    /// No Raft group, no store, no internal routes: a write is proposed on
    /// the data node that leads its group, a read answered by a replica.
    void build_front_end_node() {
        _remote_data = std::make_unique<kinesis::remote_data_access>(
            _opt._data_nodes, kinesis::make_http_data_transport(*_peers, _opt._forward_secret));
        const auto fc = make_front_end_config();
        _front_end = std::make_unique<front_end_type>(fc, *_authorizer);
        _remote_service = std::make_unique<kinesis::kinesis_service<kinesis::data_access>>(
            *_remote_data, make_service_config());
        _remote_service->register_with(*_front_end);
        _front_end->set_resource_lookup(
            [this](std::string_view arn) { return _remote_service->resource_facts_of(arn); });
        // A forwarded write or segment fetch never comes here (no peer
        // names this node), and would find nothing to propose to.
        _gateway = std::make_unique<gateway_type>(
            *_front_end,
            [](const std::string&, const std::vector<std::byte>&, kinesis::admission) {
                return std::optional<kinesis::apply_result>{};
            },
            nullptr, _opt._forward_secret);
        _gateway->set_roles(_opt._roles);
        _remote_leases =
            std::make_unique<kinesis::lease_api<kinesis::data_access, authorizer_type>>(
                *_remote_data, *_authorizer, fc);
        _gateway->set_lease_handler(
            [this](const kinesis::front_end_request& r) { return _remote_leases->handle(r); });
        if (_opt._metrics) {
            _gateway->set_metrics_handler([this] { return _remote_service->metrics_text(); });
        }
        wire_layers(
            [this](const kinesis::authenticated_call& c) { return _remote_leases->execute(c); },
            [this] { return _remote_service->metrics_text(); });
    }

    [[nodiscard]] auto make_front_end_config() const -> kinesis::front_end_config {
        kinesis::front_end_config fc;
        fc._region = _opt._region;
        fc._partition = _opt._partition;
        return fc;
    }

    /// The service's settings, the same on every front end: a data node's
    /// and one without data must sign iterators alike and open the same
    /// data keys, or a client moved between them fails.
    auto make_service_config() -> kinesis::kinesis_service_config {
        kinesis::kinesis_service_config sc;
        sc._cluster_profile = _profile;
        sc._limits = kinesis::kinesis_limits::for_region(_opt._region);
        // Every gateway must sign iterators with the same key, or a client's
        // next GetRecords on another node fails; a lone node without a
        // forwarding secret gets the service's random key.
        if (!_opt._iterator_keys_file.empty()) {
            sc._iterator_keys = kinesis::parse_iterator_keys(
                read_file(_opt._iterator_keys_file, "KINESIS_ITERATOR_KEYS_FILE"));
        } else if (!_opt._forward_secret.empty()) {
            sc._iterator_keys = kinesis::derived_iterator_key(_opt._forward_secret);
        }
        // Encryption at rest (task 14), and the provider older data keys
        // name (KMS task 15).
        sc._kms = make_kms_provider(_opt._kms);
        sc._kms_name = _opt._kms;
        // Channels seal delivered objects with the same provider (task 19).
        _channel_kms = sc._kms;
        sc._kms_caller_ttl = _opt._kms_caller_ttl;
        if (_opt._kms_previous != "off") {
            sc._kms_previous.emplace(_opt._kms_previous, make_kms_provider(_opt._kms_previous));
            sc._kms_untagged = _opt._kms_previous;
        }
        return sc;
    }

    /// Every voter, as volume records name replicas.
    [[nodiscard]] auto volume_replicas() const -> std::vector<std::string> {
        std::vector<std::string> out;
        for (const auto& id : _voters) {
            out.push_back(kythira::host_node_id_text(id));
        }
        return out;
    }

    [[nodiscard]] auto saved_assignment_path() const -> std::filesystem::path {
        return _opt._data_dir / "volume-assignment.json";
    }

    /// The assignment this node last read from the catalog, if it saved
    /// one for itself.
    [[nodiscard]] auto saved_assignment(const std::string& self) const
        -> std::optional<kythira::volume_assignment> {
        std::ifstream in(saved_assignment_path());
        if (!in) {
            return std::nullopt;
        }
        const std::string text((std::istreambuf_iterator<char>(in)), {});
        auto a = kythira::decode_volume_assignment(text);
        if (!a || a->_replica != self) {
            return std::nullopt;
        }
        return a;
    }

    /// Writes `a` through a temporary file and a rename, so a crash leaves
    /// the old assignment or the new one.
    void save_assignment(const kythira::volume_assignment& a) const {
        const auto path = saved_assignment_path();
        auto tmp = path;
        tmp += ".tmp";
        {
            std::ofstream out(tmp, std::ios::trunc);
            out << kythira::encode_volume_assignment(a) << "\n";
            out.flush();
            if (!out) {
                throw std::runtime_error("kinesis: cannot write " + tmp.string());
            }
        }
        std::filesystem::rename(tmp, path);
    }

    /// One volume keeper pass (task 10). When the catalog says this node's
    /// volume is somewhere other than where it opened it, the node saves
    /// the new assignment and reports itself unhealthy: a restart opens
    /// the new volume and restores into it from its snapshot and peers.
    void keep_volumes() {
        if (!_keeper) {
            return;
        }
        try {
            const auto p = _keeper->pass(_cluster->now_ms());
            if (p._seeded + p._replaced + p._unplaceable > 0) {
                log_info("kinesis volumes: seeded=" + std::to_string(p._seeded) +
                         " replaced=" + std::to_string(p._replaced) +
                         " unplaceable=" + std::to_string(p._unplaceable) +
                         " failures=" + std::to_string(p._failures));
            }
            if (_remote == nullptr || !_opened || !p._self || *p._self == *_opened) {
                return;
            }
            const std::scoped_lock lock(_moved_mu);
            if (!_volume_moved.empty()) {
                return;
            }
            save_assignment(*p._self);
            _volume_moved = "segment volume " + p._self->_volume + " moved to segment node " +
                            p._self->_segment_node + " at epoch " +
                            std::to_string(p._self->_epoch) +
                            "; restart this node to restore into it";
            log_info("kinesis: " + _volume_moved);
        } catch (const std::exception& e) {
            log_info(std::string("kinesis volumes: pass failed: ") + e.what());
        }
    }

    void maintain() {
        auto next = std::chrono::steady_clock::now() + _opt._maintenance_interval;
        while (_maintaining.load(std::memory_order_acquire)) {
            if (std::chrono::steady_clock::now() < next) {
                std::this_thread::sleep_for(std::chrono::milliseconds{100});
                continue;
            }
            next = std::chrono::steady_clock::now() + _opt._maintenance_interval;
            keep_volumes();
            const auto st = _maintenance->run_once();
            const auto od = _on_demand->run_once(_cluster->now_ms());
            const auto ch = _channels->run_once();
            if (ch._objects + ch._dead_letters + ch._failures + ch._failed_channels > 0) {
                log_info("kinesis channels: objects=" + std::to_string(ch._objects) +
                         " records=" + std::to_string(ch._records) +
                         " dead_letters=" + std::to_string(ch._dead_letters) +
                         " failures=" + std::to_string(ch._failures) +
                         " failed_channels=" + std::to_string(ch._failed_channels) +
                         (ch._last_failure.empty() ? std::string()
                                                   : " last_failure=" + ch._last_failure));
            }
            if (od._splits + od._failures > 0) {
                log_info("kinesis on-demand: hot=" + std::to_string(od._hot) + " splits=" +
                         std::to_string(od._splits) + " failures=" + std::to_string(od._failures));
            }
            // A create whose caller lost it between the catalog commit and
            // ACTIVE (a leader change mid-create) is finished here after
            // half a minute in CREATING.
            const auto created = _service->repair_creates(_cluster->now_ms(), 30000);
            if (created > 0) {
                log_info("kinesis maintenance: finished " + std::to_string(created) +
                         " interrupted create(s)");
            }
            // A reshard whose caller died after its transaction committed is
            // finished here once it has sat UPDATING for a minute.
            const auto repaired = _service->repair_reshards(_cluster->now_ms(), 60000);
            if (repaired > 0) {
                log_info("kinesis maintenance: completed " + std::to_string(repaired) +
                         " abandoned reshard(s)");
            }
            if (st._seals + st._trims + st._tiered + st._objects_deleted + st._evicted +
                    st._failures >
                0) {
                log_info("kinesis maintenance: seals=" + std::to_string(st._seals) + " trims=" +
                         std::to_string(st._trims) + " tiered=" + std::to_string(st._tiered) +
                         " objects_deleted=" + std::to_string(st._objects_deleted) + " evicted=" +
                         std::to_string(st._evicted) + " failures=" + std::to_string(st._failures));
            }
        }
    }

    void log_info(const std::string& message) {
        _logger->log(kythira::log_level::info, message, {});
    }

    bool _standalone;
    node_options _opt;
    std::optional<kythira::console_logger> _logger;
#ifdef KYTHIRA_KINESIS_GATEWAY_IAM
    std::unique_ptr<iam_auth> _iam;
#endif
    /// KINESIS_AUTH=iam|both in kythira_node beside the IAM module.
    bool _iam_in_process{false};
    std::shared_ptr<service_node::iam_evaluator> _iam_evaluator;
    pkcs11::uri _kms_token;
    std::shared_ptr<service_node::pkcs11_provider> _hsm_pkcs11;
    /// `KINESIS_KMS=kythira`: the co-located KMS's client, or one over
    /// HTTPS to a KMS on another cluster.
    std::shared_ptr<service_node::kms_endpoint> _kms_client;
    std::unique_ptr<authorizer_type> _authorizer;
    kinesis::kinesis_compat_profile _profile{};

    /// How long a data node waits for its segment node at start.
    static constexpr auto k_volume_wait = std::chrono::seconds{60};
    /// How long a segment node may stay silent before the catalog leader
    /// moves its volumes elsewhere.
    static constexpr std::int64_t k_volume_replace_after_ms = 60'000;

    std::unique_ptr<kythira::segment_store> _store;
    /// `_store` when it is a volume on a segment node.
    kythira::remote_segment_store* _remote = nullptr;
    std::string _volume_node;
    std::atomic<bool> _volume_reachable{true};
    /// The assignment `_store` was opened from (a volume only).
    std::optional<kythira::volume_assignment> _opened;
    std::unique_ptr<kinesis::volume_keeper<cluster_type>> _keeper;
    mutable std::mutex _moved_mu;
    /// Set once the catalog moved this node's volume.
    std::string _volume_moved;
    std::mutex _space_mu;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> _space;
    std::chrono::steady_clock::time_point _space_at{};
    /// The volumes this node holds for data nodes without `segments`.
    std::unique_ptr<kythira::segment_volume_service> _volumes;
    std::unique_ptr<kinesis::peer_client> _peers;
    std::vector<std::string> _other_gateways;
    kythira::segment_store::fetch_transport _transport;
    std::unique_ptr<object_tier> _tier_owner;
    kinesis::tier_store _tier;
    kinesis::fetched_segments _fetched;
    kinesis::segment_fetcher _fetch;
    std::vector<kythira::host_node_id> _voters;
    std::size_t _groups = 0;

    std::unique_ptr<raft_host> _raft;
    /// The leader's write buckets (task 8): what a stream with the
    /// throttling switch on meets when this node proposes for it.
    kinesis::write_throttle _write_limits;
    /// The disk guard (Requirement 11.4) on the segment disk.
    std::unique_ptr<kinesis::disk_guard> _guard;
    std::unique_ptr<cluster_type> _cluster;
    std::unique_ptr<front_end_type> _front_end;
    std::unique_ptr<kinesis::kinesis_service<cluster_type>> _service;
    std::unique_ptr<gateway_type> _gateway;
    std::unique_ptr<kinesis::lease_api<cluster_type, authorizer_type>> _leases;
    std::unique_ptr<kinesis::local_data_access<cluster_type>> _local_data;
    /// A front end without data (task 7): the data layer over the API, and
    /// the service and Lease API over it.
    std::unique_ptr<kinesis::remote_data_access> _remote_data;
    std::unique_ptr<kinesis::kinesis_service<kinesis::data_access>> _remote_service;
    std::unique_ptr<kinesis::lease_api<kinesis::data_access, authorizer_type>> _remote_leases;
    std::shared_ptr<producer_type> _producer;
    /// Task 8: the front-end API this node serves gateways (with
    /// `front_end`), or the front ends it hands calls to (a gateway
    /// without), over their own client.
    std::unique_ptr<kinesis::front_end_server> _fe_server;
    std::unique_ptr<kinesis::peer_client> _fe_peers;
    std::shared_ptr<kinesis::remote_front_ends> _remote_fe;
    std::atomic<bool> _drained{false};
    std::unique_ptr<https::server> _server;
    std::unique_ptr<https::server> _internal_server;

    std::atomic<bool> _driving{false};
    std::thread _driver;
    std::unique_ptr<kinesis::stream_maintenance<cluster_type>> _maintenance;
    std::unique_ptr<channel_destinations> _channel_destinations;
    /// The key provider envelope-encrypted channels seal with (the one
    /// streams are encrypted at rest with).
    kinesis::key_provider _channel_kms;
    std::unique_ptr<kinesis::channel_delivery<cluster_type, kinesis::kinesis_service<cluster_type>>>
        _channels;
    std::unique_ptr<kinesis::on_demand_controller<cluster_type>> _on_demand;
    std::atomic<bool> _maintaining{false};
    std::thread _maintainer;
    std::atomic<bool> _started{false};
};

}  // namespace kythira::kinesis_node
