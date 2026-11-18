// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// iam_node: hosts the IAM Raft group and serves IAM, STS and the Kythira
// admin routes on one HTTPS listener (.kiro/specs/iam-compatible-auth/
// Requirement 8, design Component 7).
//
// The IAM group is one group on a multi-raft host (iam_raft.hpp), run by
// the same IAM module kythira_node runs (iam_module.hpp), here alone on a
// node of its own (.kiro/specs/service-colocation/ task 8):
//
//  - Raft over Boost.Beast with the CBOR wire on --rpc-address/--rpc-port,
//    mutual TLS when --rpc-tls-* is given. Each member presents its
//    Kythira CA node certificate, and a peer is accepted only with the
//    reserved peer SAN of a configured member or registered replica,
//    bound to that member's node id (iam_raft_trust).
//  - The unseal passphrase comes from --unseal-key-file. The KEK is derived
//    from it and the salt the first create_account records, and checked
//    against a stored sealed secret: a member started with the wrong
//    passphrase exits instead of sealing secrets no other member can open.
//  - A follower answers an admin request with a 307 to the leader's address,
//    and 503 while no leader is known. /healthz answers on every member.
//  - The group's files are in --data-dir/raft/<group id>/, as the module
//    keeps them under kythira_node's iam/. A data directory from before
//    the move (a plain Raft group's files directly in --data-dir) is
//    refused until `iam_node --convert-data-dir` converts it
//    (convert_data_dir.hpp).
//
// The public listener is the core Beast HTTPS server
// (raft/beast_https_server.hpp). It asks for, but does not require, a client
// certificate: /v1/admin/* needs one whose URI SAN is on --admin-uri-san,
// while SigV4 clients present none. IAM and STS requests are routed by their
// credential scope and served by iam_service.hpp.
//
// Read replicas: `kythira-iam replica-add` registers a replica (a node
// started with --replica, or a front end's embedded replica) in the IAM
// state, and the leader adds it as a Raft learner. Every leader, including
// one elected later, reads the registered replicas from the state and makes
// each reachable, so the address list lives in the replicated log rather
// than in each member's flags. A replica reports its lag (seconds since it
// last held every committed change) in /healthz and as
// `kythira_iam_replica_lag_seconds` on /metrics, and past
// --iam-max-staleness-secs answers IAM and STS requests ServiceUnavailable.

#include "config.hpp"
#include "convert_data_dir.hpp"
#include "iam_module.hpp"

#include <kythira/iam/iam_raft.hpp>

#include <raft/beast_http_transport_impl.hpp>
#include <raft/ca_http_helpers.hpp>
#include <raft/console_logger.hpp>
#include <raft/module_registry.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/node_core.hpp>
#include <raft/node_host.hpp>
#include <raft/service_module.hpp>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <raft/process_init.hpp>

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
namespace {

using iam_node::node_id_type;
namespace iam = kythira::iam;
namespace sn = kythira::service_node;

using host_type =
    sn::node_host<iam::iam_raft_stack::client_type, iam::iam_raft_stack::server_type, node_id_type>;

std::atomic<bool> g_stop{false};
std::mutex g_stop_mu;
std::condition_variable g_stop_cv;
void on_signal(int) {
    g_stop = true;
    g_stop_cv.notify_all();
}

// Whether the certificate at `path` carries `name` as a DNS or URI SAN: a
// node certificate without its own reserved peer SAN would be refused by
// every peer, so iam_node says so at startup rather than failing to elect.
auto cert_names(const std::string& path, const std::string& name) -> bool {
    const auto pem = iam::iam_read_file(path);
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) {
        return false;
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (cert == nullptr) {
        return false;
    }
    auto* names =
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    bool found = false;
    for (int i = 0; names != nullptr && i < sk_GENERAL_NAME_num(names) && !found; ++i) {
        const GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
        const ASN1_STRING* s = nullptr;
        if (gn->type == GEN_DNS) {
            s = gn->d.dNSName;
        } else if (gn->type == GEN_URI) {
            s = gn->d.uniformResourceIdentifier;
        }
        if (s != nullptr) {
            found = std::string_view(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)),
                                     static_cast<std::size_t>(ASN1_STRING_length(s))) == name;
        }
    }
    GENERAL_NAMES_free(names);
    X509_free(cert);
    return found;
}

// The member: its transport, a node with the IAM module alone, and the
// signal wait. 0 on a stop, 1 when it cannot start.
auto run(const iam_node::config& cfg, std::string passphrase) -> int {
    std::optional<iam::iam_raft_tls> tls;
    std::shared_ptr<iam::iam_raft_trust> trust;
    if (cfg.rpc_tls()) {
        tls = iam::iam_raft_tls{cfg.rpc_tls_cert_path, cfg.rpc_tls_key_path, cfg.rpc_tls_ca_path};
        std::vector<node_id_type> members{cfg.node_id};
        for (const auto& p : cfg.peers) {
            members.push_back(p.node_id);
        }
        trust =
            std::make_shared<iam::iam_raft_trust>(iam::iam_read_file(cfg.rpc_tls_ca_path), members);
    }
    std::unordered_map<node_id_type, std::string> urls;
    for (const auto& p : cfg.peers) {
        urls.emplace(p.node_id, iam::iam_raft_url(cfg.rpc_tls(), p.rpc_host, p.rpc_port));
    }
    iam::iam_raft_stack stack(cfg.rpc_address, cfg.rpc_port, std::move(urls), tls, trust);

    sn::node_config node;
    node.node_id = kythira::host_node_id_text(cfg.node_id);
    node.data_dir = cfg.data_dir;
    node.raft_bind = cfg.rpc_address;
    node.raft_port = cfg.rpc_port;
    node.insecure_plaintext = !cfg.rpc_tls();
    host_type host(node, cfg.node_id, stack.client(), stack.server());

    sn::module_plan<host_type> plan;
    plan.modules.push_back(std::make_unique<iam_node::iam_module<host_type>>(
        cfg, std::move(passphrase), [trust](const node_id_type& id, const iam::replica_record&) {
            if (trust) {
                trust->add(id);
            }
        }));
    plan.spaces.push_back(sn::group_space::standalone(sn::module_numbers::iam));
    kythira::console_logger logger{kythira::log_level::info};
    sn::node_runner<host_type> runner(
        std::move(plan), node, [&logger](bool error, std::string_view line) {
            logger.log(error ? kythira::log_level::error : kythira::log_level::info,
                       "iam_node: " + std::string(line), {});
        });
    int status = 0;
    try {
        // The module was given its settings; it reads no variables.
        runner.start(host,
                     [](std::string_view) -> std::optional<std::string> { return std::nullopt; });
        std::unique_lock lock(g_stop_mu);
        g_stop_cv.wait(lock, [] { return g_stop.load(); });
        std::cerr << "[info] iam_node: stopping\n";
    } catch (const std::exception& e) {
        std::cerr << "iam_node: failed to start: " << e.what() << "\n";
        status = 1;
    }
    // The module stops its listener, then its group, before the transport.
    runner.stop([&stack] { stack.shutdown(); });
    return status;
}

}  // namespace

int main(int argc, char** argv) {
    // As in ca_cluster_node: folly::Init (where Folly is linked) with only
    // the program name, so its flag parser never sees this binary's flags.
    // It registers the Timekeeper the RPC client's retries use.
    const kythira::process_init process_init(argv[0]);

    iam_node::config cfg;
    try {
        cfg = iam_node::parse_args(argc, argv);
    } catch (const std::invalid_argument& e) {
        if (*e.what() != '\0') {
            std::cerr << "iam_node: " << e.what() << "\n\n";
        }
        std::cerr << iam_node::k_usage;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "iam_node: " << e.what() << "\n";
        return 1;
    }

    std::string passphrase;
    try {
        passphrase = iam_node::read_unseal_passphrase(cfg.unseal_key_file);
    } catch (const std::exception& e) {
        std::cerr << "iam_node: " << e.what() << "\n";
        return 1;
    }

    if (cfg.convert_data_dir) {
        try {
            const auto done = iam_node::convert_data_dir(cfg.data_dir);
            std::cerr << "iam_node: converted " << cfg.data_dir << " (snapshot at "
                      << done.snapshot_index << ", entries " << done.first_entry << "-"
                      << done.last_entry << ", term " << done.term
                      << "); the old files are in pre-host/\n";
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "iam_node: --convert-data-dir: " << e.what() << "\n";
            return 1;
        }
    }
    if (iam_node::has_unconverted_state(cfg.data_dir)) {
        std::cerr << "iam_node: " << cfg.data_dir
                  << " holds a Raft log from before IAM moved onto the multi-raft host; stop "
                     "every member and run iam_node --convert-data-dir with the same flags on "
                     "each first\n";
        return 1;
    }

    (void)std::signal(SIGTERM, on_signal);
    (void)std::signal(SIGINT, on_signal);
    (void)std::signal(SIGPIPE, SIG_IGN);

    try {
        if (cfg.rpc_tls()) {
            const auto own = raft::testing::peer_identity_name(cfg.node_id);
            if (!cert_names(cfg.rpc_tls_cert_path, own)) {
                std::cerr << "iam_node: --rpc-tls-cert does not carry this node's reserved peer "
                             "SAN "
                          << own << "; peers would refuse it\n";
                return 1;
            }
        } else {
            std::cerr << "[warn] iam_node: Raft RPC is PLAINTEXT and UNAUTHENTICATED on "
                      << cfg.rpc_address << ":" << cfg.rpc_port
                      << (cfg.allow_plaintext_rpc ? " (--allow-plaintext-rpc)" : " (loopback only)")
                      << "\n";
        }
        return run(cfg, std::move(passphrase));
    } catch (const std::exception& e) {
        std::cerr << "iam_node: failed to start: " << e.what() << "\n";
        return 1;
    }
}
