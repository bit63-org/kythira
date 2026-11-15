// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The audit log's ledger sink (.kiro/specs/virtual-hsm/ task 14,
// Requirement 11.2): each batch of audit lines becomes one transaction on a
// verifiable ledger (`.kiro/specs/verifiable-ledger/`), one document per
// line, through the ledger's native API:
//
//   POST /v1/ledgers/{L}/execute
//        {"statements": [{"op": "insert", "table": T, "id": <22 base62>,
//                         "value": <the audit line>}, ...]}
//
// The table is created on first use (a table that exists already is
// fine). A batch the ledger does not take is kept and sent ahead of the
// next one, up to `max_pending` lines; beyond that the oldest are dropped
// and counted, and the next batch that commits carries a
// {"audit":"ledger_dropped","lines":N} document saying so, so a gap in the
// ledger is itself recorded. The ledger's own hash chain is what makes the
// trail verifiable; this sink only has to get every line there in order.

#include <boost/json.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::hsm {

struct ledger_audit_config {
    std::string ledger = "hsm_audit";
    std::string table = "audit";
    /// Lines per transaction.
    std::size_t batch = 100;
    /// Lines kept while the ledger is unreachable.
    std::size_t max_pending = 10000;
};

class ledger_audit_sink {
public:
    /// POSTs `body` (JSON) to `target` on the ledger; the status and body,
    /// or nothing when the exchange failed.
    using poster = std::function<std::optional<std::pair<unsigned, std::string>>(
        const std::string& target, std::string body)>;

    ledger_audit_sink(ledger_audit_config config, poster post)
        : _cfg(std::move(config)), _post(std::move(post)) {}

    /// Sends `lines` (each one JSON object) after any still pending.
    void send(std::span<const std::string> lines) {
        for (const auto& l : lines) {
            _pending.push_back(l);
        }
        while (_pending.size() > _cfg.max_pending) {
            _pending.pop_front();
            ++_dropped;
        }
        if (!_table_ready && !create_table()) {
            return;
        }
        while (!_pending.empty()) {
            const auto n = std::min(_pending.size(), std::max<std::size_t>(_cfg.batch, 1));
            boost::json::array statements;
            if (_dropped != 0) {
                statements.push_back(
                    insert(boost::json::object{{"audit", "ledger_dropped"}, {"lines", _dropped}}));
            }
            for (std::size_t i = 0; i < n; ++i) {
                boost::system::error_code ec;
                auto v = boost::json::parse(_pending[i], ec);
                if (ec || !v.is_object()) {
                    v = boost::json::object{{"audit", "unparsed"}, {"line", _pending[i]}};
                }
                statements.push_back(insert(std::move(v)));
            }
            if (!execute(std::move(statements))) {
                return;  // kept for the next batch
            }
            _pending.erase(_pending.begin(), _pending.begin() + static_cast<std::ptrdiff_t>(n));
            _dropped = 0;
            ++_committed;
        }
    }

    /// Lines waiting for the ledger.
    [[nodiscard]] auto pending() const noexcept -> std::size_t { return _pending.size(); }
    /// Transactions the ledger took.
    [[nodiscard]] auto committed() const noexcept -> std::uint64_t { return _committed; }

private:
    [[nodiscard]] auto target() const -> std::string {
        return "/v1/ledgers/" + _cfg.ledger + "/execute";
    }

    auto create_table() -> bool {
        boost::json::object st{{"op", "create_table"}, {"table", _cfg.table}};
        const auto res = _post(
            target(),
            boost::json::serialize(boost::json::object{{"statements", boost::json::array{st}}}));
        if (!res) {
            return false;
        }
        // Created, or there already (409 table_exists).
        _table_ready = (res->first >= 200 && res->first < 300) ||
                       (res->first == 409 && res->second.find("table_exists") != std::string::npos);
        return _table_ready;
    }

    auto execute(boost::json::array statements) -> bool {
        const auto res = _post(
            target(),
            boost::json::serialize(boost::json::object{{"statements", std::move(statements)}}));
        return res && res->first >= 200 && res->first < 300;
    }

    [[nodiscard]] auto insert(boost::json::value value) const -> boost::json::object {
        return {
            {"op", "insert"}, {"table", _cfg.table}, {"id", new_id()}, {"value", std::move(value)}};
    }

    /// A document id: 22 base62 characters (about 131 bits).
    [[nodiscard]] static auto new_id() -> std::string {
        static constexpr std::string_view alphabet =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string id;
        id.reserve(22);
        while (id.size() < 22) {
            std::array<unsigned char, 32> r{};
            if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1) {
                throw std::runtime_error("ledger_audit_sink: no randomness for a document id");
            }
            for (const auto b : r) {
                if (b < 248 && id.size() < 22) {  // 248 = 4 * 62: no modulo bias
                    id.push_back(alphabet[b % 62]);
                }
            }
        }
        return id;
    }

    ledger_audit_config _cfg;
    poster _post;
    std::deque<std::string> _pending;
    std::uint64_t _dropped = 0;
    std::uint64_t _committed = 0;
    bool _table_ready = false;
};

}  // namespace kythira::hsm
