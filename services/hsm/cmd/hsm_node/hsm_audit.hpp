// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Where the HSM module's audit events go (.kiro/specs/virtual-hsm/ task 14,
// Requirements 11.1-11.3): one JSON line per logged event to stderr or a
// file, and, when KYTHIRA_HSM_AUDIT_LEDGER_URL is set, to a verifiable
// ledger too; and every event, logged or only counted, into the module's
// metrics (operations by action, mechanism and result, latency, failed
// logins, refusals for a locked PIN). Neither carries a key, PIN or share:
// an event has none to give. The session layer and the operator API call it on their own
// threads; it only formats the line and queues it (raft/audit_log.hpp), so
// a slow file or ledger never holds up a PKCS#11 call. The session layer
// may outlive the module (a co-located consumer keeps it), so the hooks
// hold this object by shared_ptr.

#include "hsm_config.hpp"

#include <kythira/hsm/audit_json.hpp>
#include <kythira/hsm/audit_ledger.hpp>
#include <kythira/hsm/mtls_client.hpp>

#include <raft/audit_log.hpp>
#include <raft/service_module.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace kythira::hsm_node {

class audit_pipeline {
public:
    explicit audit_pipeline(const hsm_options& o) {
        if (o.audit.starts_with("file:")) {
            const auto path = o.audit.substr(5);
            _file.open(path, std::ios::app);
            if (!_file) {
                throw std::runtime_error("KYTHIRA_HSM_AUDIT: cannot append to " + path);
            }
        }
        _to_stderr = o.audit == "stderr";
        if (!o.audit_ledger_url.empty()) {
            kythira::hsm::peer_client_config lc;
            lc.cert_path = o.audit_ledger_cert;
            lc.key_path = o.audit_ledger_key;
            lc.ca_path = o.audit_ledger_ca;
            lc.plaintext = o.audit_ledger_url.starts_with("http://");
            lc.timeout = std::chrono::seconds{10};
            auto client = std::make_shared<const kythira::hsm::mtls_client>(lc);
            kythira::hsm::ledger_audit_config cfg;
            cfg.ledger = o.audit_ledger;
            cfg.table = o.audit_ledger_table;
            _ledger = std::make_unique<kythira::hsm::ledger_audit_sink>(
                cfg,
                [client, url = o.audit_ledger_url](const std::string& target, std::string body) {
                    return client->request("POST", url, target, std::move(body), "application/json",
                                           "kythira-hsm-audit");
                });
        }
        if (_to_stderr || _file.is_open() || _ledger) {
            _log = std::make_unique<kythira::audit_log>(
                kythira::audit_log::batch_sink(
                    [this](std::span<const std::string> lines) { write(lines); }),
                8192);
        }
    }

    audit_pipeline(const audit_pipeline&) = delete;
    auto operator=(const audit_pipeline&) -> audit_pipeline& = delete;
    audit_pipeline(audit_pipeline&&) = delete;
    auto operator=(audit_pipeline&&) -> audit_pipeline& = delete;
    ~audit_pipeline() { _log.reset(); }  // drains the queue while the sinks exist

    void record(const kythira::hsm::audit_event& e) {
        count(e);
        if (_log && e.logged) {
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            _log->post(kythira::hsm::audit_line(e, now));
        }
    }

    /// Blocks until every queued line was written (tests, shutdown).
    void flush() {
        if (_log) {
            _log->flush();
        }
    }

    [[nodiscard]] auto dropped() const -> std::uint64_t { return _log ? _log->dropped() : 0; }
    [[nodiscard]] auto ledger_pending() const -> std::size_t {
        const std::scoped_lock lock(_mu);
        return _ledger ? _ledger->pending() : 0;
    }

    /// The counters as module metrics (the node prefixes them hsm_).
    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> {
        std::vector<service_node::module_metric> out;
        const std::scoped_lock lock(_metrics_mu);
        for (const auto& [k, n] : _ops) {
            const auto& [action, mechanism, result] = k;
            out.push_back({"operations",
                           static_cast<double>(n),
                           {{"action", action}, {"mechanism", mechanism}, {"result", result}}});
        }
        for (const auto& [action, l] : _latency) {
            out.push_back({"operation_latency_seconds_count",
                           static_cast<double>(l.first),
                           {{"action", action}}});
            out.push_back({"operation_latency_seconds_sum",
                           static_cast<double>(l.second) / 1e6,
                           {{"action", action}}});
        }
        out.push_back({"login_failures", static_cast<double>(_login_failures), {}});
        out.push_back({"pin_locked_refusals", static_cast<double>(_pin_locked), {}});
        out.push_back({"audit_dropped", static_cast<double>(dropped()), {}});
        out.push_back({"audit_ledger_pending", static_cast<double>(ledger_pending()), {}});
        return out;
    }

private:
    void count(const kythira::hsm::audit_event& e) {
        std::array<char, 24> mech{};
        if (e.mechanism) {
            std::snprintf(mech.data(), mech.size(), "0x%08lx", *e.mechanism);
        }
        const std::scoped_lock lock(_metrics_mu);
        ++_ops[{std::string(e.action), std::string(mech.data()), e.rv == CKR_OK ? "ok" : "error"}];
        auto& l = _latency[std::string(e.action)];
        ++l.first;
        l.second += static_cast<std::uint64_t>(e.elapsed.count());
        if (e.rv == CKR_PIN_INCORRECT) {
            ++_login_failures;
        }
        if (e.rv == CKR_PIN_LOCKED) {
            ++_pin_locked;
        }
    }

    void write(std::span<const std::string> lines) {
        const std::scoped_lock lock(_mu);
        for (const auto& l : lines) {
            if (_to_stderr) {
                std::cerr << l << '\n';
            }
            if (_file.is_open()) {
                _file << l << '\n';
            }
        }
        if (_file.is_open()) {
            _file.flush();
        }
        if (_ledger) {
            _ledger->send(lines);
        }
    }

    mutable std::mutex _metrics_mu;
    std::map<std::tuple<std::string, std::string, std::string>, std::uint64_t> _ops;
    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> _latency;  // count, sum µs
    std::uint64_t _login_failures = 0;
    std::uint64_t _pin_locked = 0;

    mutable std::mutex _mu;
    bool _to_stderr = false;
    std::ofstream _file;
    std::unique_ptr<kythira::hsm::ledger_audit_sink> _ledger;
    std::unique_ptr<kythira::audit_log> _log;  // last: its writer uses the sinks
};

}  // namespace kythira::hsm_node
