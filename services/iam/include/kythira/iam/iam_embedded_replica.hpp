// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file iam_embedded_replica.hpp
/// @brief A front end's whole IAM side in one object: a read replica of the
///        IAM Raft group over mutual TLS, the unsealing key, the action
///        registry and the authorizer (`.kiro/specs/iam-compatible-auth/`
///        Requirement 7.3, task 21; on a multi-raft host since
///        `.kiro/specs/service-colocation/` task 8).
///
///   iam::embedded_replica_config cfg;   // from the front end's own flags
///   iam::embedded_replica replica(std::move(cfg));
///   replica.start();          // then `kythira-iam replica-add` admits it
///   iam::iam_redis_verifier v(replica.authorizer(), {...});
///
/// The replica is a learner of the IAM group (`iam_raft.hpp`) on its own
/// multi-raft host and Raft listener, so it joins iam_node and the IAM
/// module of kythira_node alike: the group id is the same in both. The
/// voters' leader dials it at the address `replica-add` registered.
///
/// The replica's certificate must carry its node id's reserved peer SAN
/// (`peer_identity_name`), as a member's does: the voters bind each
/// registered replica's certificate to its id, and the replica accepts
/// AppendEntries only from a certificate naming a voter. A kythira_node
/// voter dials it as any peer, so there the certificate must also name the
/// registered RPC host. Plaintext is not offered: a front end's replica
/// holds the unsealing passphrase.
///
/// The translation unit that builds one includes
/// raft/beast_http_transport_impl.hpp and raft/multi_raft_impl.hpp (a
/// composition root, boundary-allow.txt).

#include <kythira/iam/iam_admin.hpp>
#include <kythira/iam/iam_authorizer.hpp>
#include <kythira/iam/iam_raft.hpp>
#include <kythira/iam/iam_replica.hpp>
#include <kythira/iam/iam_service_registry.hpp>
#include <kythira/iam/iam_state_machine.hpp>

#include <raft/ca_http_helpers.hpp>
#include <raft/console_logger.hpp>
#include <raft/host_node_id.hpp>
#include <raft/multi_raft.hpp>
#include <raft/node_core.hpp>
#include <raft/node_host.hpp>
#include <raft/pkcs11_sealed_secret.hpp>
#include <raft/service_module.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kythira::iam {

/// One voter of the IAM group, as the replica reaches it.
struct replica_voter {
    host_node_id id;
    std::string rpc_host;
    std::uint16_t rpc_port = 0;
};

struct embedded_replica_config {
    /// This replica's id in the IAM group, registered with `replica-add`.
    host_node_id node_id;
    std::string rpc_address = "0.0.0.0";
    std::uint16_t rpc_port = 0;
    std::vector<replica_voter> voters;
    std::filesystem::path data_dir;
    /// The cluster's unsealing passphrase, which opens the access-key and
    /// STS-key secrets the authorizer verifies signatures with.
    std::string unseal_key_file;
    std::string rpc_tls_cert;
    std::string rpc_tls_key;
    std::string rpc_tls_ca;
    std::chrono::milliseconds max_staleness = replica_freshness::k_default_max_staleness;
    std::string partition = "aws";
    log_level log = log_level::warning;
};

/// `<id>:<host>:<port>[,...]`, the voters' Raft RPC addresses. An `@...`
/// suffix (an `iam_node --peers` entry's HTTPS URL) is ignored, so the same
/// list can be given to both.
[[nodiscard]] inline auto parse_replica_voters(std::string_view text)
    -> std::vector<replica_voter> {
    std::vector<replica_voter> out;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto comma = text.find(',', pos);
        auto item = text.substr(
            pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos);
        pos = comma == std::string_view::npos ? text.size() + 1 : comma + 1;
        if (item.empty()) {
            continue;
        }
        item = item.substr(0, item.find('@'));
        const auto port_colon = item.rfind(':');
        const auto host_colon = port_colon == std::string_view::npos
                                    ? std::string_view::npos
                                    : item.rfind(':', port_colon - 1);
        if (host_colon == std::string_view::npos || host_colon == 0 ||
            port_colon == host_colon + 1 || port_colon + 1 == item.size()) {
            throw std::invalid_argument("IAM voter '" + std::string(item) +
                                        "' is not <id>:<host>:<port>");
        }
        auto id = parse_host_peer_node_id(item.substr(0, host_colon));
        if (!id) {
            throw std::invalid_argument("IAM voter id: " + id.error());
        }
        const auto port_text = item.substr(port_colon + 1);
        unsigned long port = 0;
        for (const char c : port_text) {
            if (c < '0' || c > '9' || port > 65535) {
                port = 65536;
                break;
            }
            port = port * 10 + static_cast<unsigned long>(c - '0');
        }
        if (port == 0 || port > 65535) {
            throw std::invalid_argument("IAM voter port '" + std::string(port_text) +
                                        "' is not 1-65535");
        }
        out.push_back({*id, std::string(item.substr(host_colon + 1, port_colon - host_colon - 1)),
                       static_cast<std::uint16_t>(port)});
    }
    return out;
}

/// The unseal passphrase: the key file's first line, which must not be
/// empty, or the secret a file sealed under a PKCS#11 token key opens on
/// the token (virtual-hsm task 13c).
[[nodiscard]] inline auto read_unseal_passphrase_file(const std::string& path) -> std::string {
    return pkcs11::read_secret_file(path, "the IAM unseal key file");
}

class embedded_replica {
public:
    using stack_type = iam_raft_stack;
    using host_type =
        service_node::node_host<stack_type::client_type, stack_type::server_type, host_node_id>;
    using types = iam_host_types<stack_type::client_type, typename host_type::view_type>;
    using raft_host = multi_raft<types, std::string, std::uint64_t>;

    /// Throws std::invalid_argument or std::runtime_error on a bad
    /// configuration; nothing is listening until `start()`.
    explicit embedded_replica(embedded_replica_config cfg,
                              std::function<void(iam_service_registry&)> register_actions = {})
        : _cfg(std::move(cfg)), _keks(read_unseal_passphrase_file(_cfg.unseal_key_file)) {
        if (_cfg.voters.empty()) {
            throw std::invalid_argument("the IAM replica needs the IAM voters");
        }
        if (_cfg.rpc_port == 0) {
            throw std::invalid_argument("the IAM replica needs an RPC port");
        }
        if (_cfg.rpc_tls_cert.empty() || _cfg.rpc_tls_key.empty() || _cfg.rpc_tls_ca.empty()) {
            throw std::invalid_argument(
                "the IAM replica needs an RPC TLS certificate, key and CA: it holds the "
                "unsealing passphrase, so its RPC is never plaintext");
        }
        if (_cfg.data_dir.empty()) {
            throw std::invalid_argument("the IAM replica needs a data directory");
        }
        if (register_actions) {
            register_actions(_registry);
        }
        std::filesystem::create_directories(_cfg.data_dir);

        std::vector<host_node_id> trusted = voter_ids();
        trusted.push_back(_cfg.node_id);
        _trust = std::make_shared<iam_raft_trust>(iam_read_file(_cfg.rpc_tls_ca), trusted);
        std::unordered_map<host_node_id, std::string> urls;
        for (const auto& v : _cfg.voters) {
            urls.emplace(v.id, iam_raft_url(true, v.rpc_host, v.rpc_port));
        }
        _stack = std::make_unique<stack_type>(
            _cfg.rpc_address, _cfg.rpc_port, std::move(urls),
            iam_raft_tls{_cfg.rpc_tls_cert, _cfg.rpc_tls_key, _cfg.rpc_tls_ca}, _trust);
        service_node::node_config node;
        node.node_id = host_node_id_text(_cfg.node_id);
        node.data_dir = _cfg.data_dir;
        node.raft_bind = _cfg.rpc_address;
        node.raft_port = _cfg.rpc_port;
        _host = std::make_unique<host_type>(node, _cfg.node_id, _stack->client(), _stack->server());
        const auto space = service_node::group_space::standalone(k_iam_module_number);
        _raft = std::make_unique<raft_host>(iam_raft_config<types>(
            _cfg.node_id, typename types::network_client_type{_host->client()},
            _host->server_for(space), _cfg.data_dir, _cfg.partition, {}, _cfg.log));
        if (!_raft->has_group(k_iam_group_id)) {
            _raft->create_group(iam_group_descriptor(voter_ids(), {_cfg.node_id}));
        }
        _node = _raft->group_node(k_iam_group_id);
        if (_node == nullptr) {
            throw std::runtime_error("the IAM replica's group did not open");
        }
        _freshness = std::make_unique<replica_freshness>(
            [n = _node] { return n->last_caught_up(); }, _cfg.max_staleness);
        _authz = std::make_unique<iam_authorizer>(
            reader(), [this](std::string_view salt) -> const seal_key& { return _keks.get(salt); },
            _registry);
        _authz->set_freshness([f = _freshness.get()] { return f->fresh(); });
    }

    embedded_replica(const embedded_replica&) = delete;
    auto operator=(const embedded_replica&) -> embedded_replica& = delete;
    embedded_replica(embedded_replica&&) = delete;
    auto operator=(embedded_replica&&) -> embedded_replica& = delete;
    ~embedded_replica() { stop(); }

    /// Joins as a learner: it never campaigns, and applies what the
    /// leader sends once `replica-add` has registered it.
    void start() {
        if (_running) {
            return;
        }
        _raft->start();
        _driver.start(*_raft, "iam replica");
        _running = true;
    }

    void stop() {
        if (!_running) {
            if (_stack) {
                _stack->shutdown();
            }
            return;
        }
        _running = false;
        _driver.stop();
        _raft->stop();
        _stack->shutdown();
    }

    [[nodiscard]] auto authorizer() -> iam_authorizer& { return *_authz; }
    [[nodiscard]] auto freshness() const -> const replica_freshness& { return *_freshness; }

    /// Runs `f` on the applied IAM state, under the group's lock.
    [[nodiscard]] auto reader() -> state_reader {
        return [n = _node](const std::function<void(const iam_state_machine&)>& f) {
            n->with_state_machine([&](iam_state_machine& sm) { f(sm); });
        };
    }

private:
    [[nodiscard]] auto voter_ids() const -> std::vector<host_node_id> {
        std::vector<host_node_id> ids;
        ids.reserve(_cfg.voters.size());
        for (const auto& v : _cfg.voters) {
            ids.push_back(v.id);
        }
        return ids;
    }

    embedded_replica_config _cfg;
    admin::kek_cache _keks;
    iam_service_registry _registry;
    std::shared_ptr<iam_raft_trust> _trust;
    std::unique_ptr<stack_type> _stack;
    std::unique_ptr<host_type> _host;
    std::unique_ptr<raft_host> _raft;
    typename raft_host::group_node_type* _node = nullptr;
    std::unique_ptr<replica_freshness> _freshness;
    std::unique_ptr<iam_authorizer> _authz;
    iam_raft_driver _driver;
    bool _running = false;
};

}  // namespace kythira::iam
