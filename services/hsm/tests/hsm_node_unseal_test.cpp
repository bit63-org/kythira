// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Node unseal (.kiro/specs/virtual-hsm/ task 8, requirements 4.4 and 13.5):
// the key-file sealer (owner-only key, shares bound to their master key),
// the share store (never overwritten, pruned only behind the current key),
// collection from peers (k needed, a peer's bad answer skipped, sealed with
// only k - 1 reachable), the member-only share routes, and init and rekey
// in node mode handing one share to each member before anything commits.

#define BOOST_TEST_MODULE hsm_node_unseal_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_store.hpp"

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_admin.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/node_unseal.hpp>
#include <kythira/hsm/shamir.hpp>

#include <boost/json.hpp>

#include <sys/stat.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace {

namespace hsm = kythira::hsm;
namespace fs = std::filesystem;

struct temp_dir {
    fs::path path;
    temp_dir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("hsm-node-unseal-" + std::to_string(rd()));
        fs::create_directories(path);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

struct split_key {
    hsm::secret_bytes mk{32};
    std::vector<hsm::shamir_share> shares;
    hsm::catalog_record catalog;

    split_key(std::uint8_t k, std::uint8_t n) {
        BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value());
        auto s = hsm::shamir_split(mk.view(), k, n);
        BOOST_REQUIRE(s.has_value());
        shares = std::move(*s);
        catalog.mode = hsm::unseal_mode::node_shares;
        catalog.k = k;
        catalog.n = n;
        catalog.mk_check = hsm::key_check_value(mk.view());
    }
};

/// One member: its sealer, store and vault.
struct member {
    temp_dir dir;
    hsm::key_file_sealer sealer{dir.path / "share.key"};
    hsm::share_store store{dir.path / "shares", sealer};
    hsm::key_vault vault;
    hsm::node_unseal unseal{vault, store};

    /// This member as another's peer: its share of `check`, binary.
    auto as_peer() -> hsm::node_unseal::fetch_fn {
        return [this](std::span<const std::uint8_t, 8> check) -> std::optional<hsm::secret_bytes> {
            auto s = store.find(check);
            if (!s) {
                return std::nullopt;
            }
            return hsm::shamir_encode_binary(*s);
        };
    }
};

auto unreachable() -> hsm::node_unseal::fetch_fn {
    return [](std::span<const std::uint8_t, 8>) -> std::optional<hsm::secret_bytes> {
        return std::nullopt;
    };
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_key_file_is_owner_only_and_binds_shares_to_their_key) {
    temp_dir dir;
    const auto key_path = dir.path / "share.key";
    hsm::key_file_sealer sealer(key_path);
    const std::array<std::uint8_t, 8> ctx{1, 2, 3, 4, 5, 6, 7, 8};
    const std::array<std::uint8_t, 8> other{8, 7, 6, 5, 4, 3, 2, 1};
    const std::array<std::uint8_t, 3> secret{0xAA, 0xBB, 0xCC};
    BOOST_TEST(!sealer.unseal(std::array<std::uint8_t, 40>{}, ctx).has_value());  // no key yet
    const auto sealed = sealer.seal(secret, ctx);
    BOOST_TEST(fs::exists(key_path));
    struct stat st{};
    BOOST_REQUIRE(::stat(key_path.c_str(), &st) == 0);
    BOOST_TEST((st.st_mode & 0777U) == 0600U);
    BOOST_TEST(fs::file_size(key_path) == 32U);
    auto back = sealer.unseal(sealed, ctx);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(hsm::constant_time_equal(back->view(), secret));
    // Bound to its key's check value: it does not open as another key's.
    BOOST_TEST(!sealer.unseal(sealed, other).has_value());
    // A key file others can read is refused, not used.
    fs::permissions(key_path, fs::perms::group_read, fs::perm_options::add);
    BOOST_CHECK_THROW((void)sealer.unseal(sealed, ctx), std::runtime_error);
    fs::permissions(key_path, fs::perms::group_read, fs::perm_options::remove);
    BOOST_TEST(sealer.unseal(sealed, ctx).has_value());
    // Another key file opens nothing.
    hsm::key_file_sealer stranger(dir.path / "other.key");
    (void)stranger.seal(secret, ctx);
    BOOST_TEST(!stranger.unseal(sealed, ctx).has_value());
}

BOOST_AUTO_TEST_CASE(shares_are_kept_sealed_never_overwritten_and_pruned_behind) {
    member m;
    split_key a(2, 3);
    split_key b(2, 3);
    BOOST_TEST(m.store.put(a.shares[0]));
    BOOST_TEST(!m.store.put(a.shares[1]));  // a share of this key is held
    auto got = m.store.find(a.catalog.mk_check);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST(got->index == 1U);
    BOOST_TEST(!m.store.find(b.catalog.mk_check).has_value());
    // No file holds the share in the clear.
    for (const auto& e : fs::recursive_directory_iterator(m.dir.path)) {
        if (!e.is_regular_file() || e.path().filename() == "share.key") {
            continue;
        }
        std::ifstream in(e.path(), std::ios::binary);
        const std::string bytes((std::istreambuf_iterator<char>(in)), {});
        const auto& raw = a.shares[0].bytes;
        const std::string needle(reinterpret_cast<const char*>(raw.data()), raw.size());
        BOOST_TEST(bytes.find(needle) == std::string::npos);
    }
    // A later key (a rekey's share, delivered before it commits) survives
    // pruning behind the current one; the older one goes once the newer
    // is current.
    BOOST_TEST(m.store.put(b.shares[0]));
    m.store.prune(a.catalog.mk_check);
    BOOST_TEST(m.store.find(b.catalog.mk_check).has_value());
    BOOST_TEST(m.store.find(a.catalog.mk_check).has_value());
    m.store.prune(b.catalog.mk_check);
    BOOST_TEST(!m.store.find(a.catalog.mk_check).has_value());
    BOOST_TEST(m.store.find(b.catalog.mk_check).has_value());
}

BOOST_AUTO_TEST_CASE(a_node_collects_k_shares_and_stays_sealed_below_k) {
    split_key key(3, 4);
    std::array<std::unique_ptr<member>, 4> m;
    for (std::size_t i = 0; i < m.size(); ++i) {
        m[i] = std::make_unique<member>();
        BOOST_REQUIRE(m[i]->store.put(key.shares[i]));
    }
    const std::optional<hsm::catalog_record> c = key.catalog;
    // k - 1 reachable (itself and one peer): sealed.
    BOOST_TEST(static_cast<int>(
                   m[0]->unseal.attempt(c, {m[1]->as_peer(), unreachable(), unreachable()})) ==
               static_cast<int>(hsm::node_unseal_outcome::too_few_shares));
    BOOST_TEST(m[0]->vault.sealed());
    // A peer answering garbage or another key's share is skipped.
    split_key other(3, 4);
    hsm::node_unseal::fetch_fn liar = [&](std::span<const std::uint8_t, 8>) {
        return std::optional<hsm::secret_bytes>(hsm::shamir_encode_binary(other.shares[2]));
    };
    hsm::node_unseal::fetch_fn echo = [&](std::span<const std::uint8_t, 8>) {
        return std::optional<hsm::secret_bytes>(hsm::shamir_encode_binary(key.shares[0]));
    };
    BOOST_TEST(static_cast<int>(m[0]->unseal.attempt(c, {liar, echo, m[2]->as_peer()})) ==
               static_cast<int>(hsm::node_unseal_outcome::too_few_shares));
    BOOST_TEST(
        static_cast<int>(m[0]->unseal.attempt(c, {liar, m[3]->as_peer(), m[2]->as_peer()})) ==
        static_cast<int>(hsm::node_unseal_outcome::unsealed));
    BOOST_TEST(!m[0]->vault.sealed());
    // Unsealed, or in operator mode, there is nothing to do.
    BOOST_TEST(static_cast<int>(m[0]->unseal.attempt(c, {})) ==
               static_cast<int>(hsm::node_unseal_outcome::idle));
    auto op = c;
    op->mode = hsm::unseal_mode::operator_shares;
    BOOST_TEST(static_cast<int>(m[1]->unseal.attempt(op, {m[0]->as_peer(), m[2]->as_peer()})) ==
               static_cast<int>(hsm::node_unseal_outcome::idle));
    // A member without its share cannot start the collection.
    member fresh;
    BOOST_TEST(static_cast<int>(fresh.unseal.attempt(c, {m[1]->as_peer()})) ==
               static_cast<int>(hsm::node_unseal_outcome::no_local_share));
}

BOOST_AUTO_TEST_CASE(the_share_routes_answer_members_only) {
    member m;
    split_key key(2, 3);
    const hsm::peer_policy policy{{"ca-cluster-node-2"}, false};
    const hsm::peer_caller peer{true, true, {}, {"ca-cluster-node-2"}};
    const hsm::peer_caller op{true, true, {"spiffe://ops/alice"}, {}};
    const auto bin = hsm::shamir_encode_binary(key.shares[1]);
    const std::string body(reinterpret_cast<const char*>(bin.data()), bin.size());
    const std::string check(key.catalog.mk_check.begin(), key.catalog.mk_check.end());

    BOOST_TEST(!hsm::serve_share_peer(m.store, policy, peer, "POST", "/v1/status", "").has_value());
    BOOST_TEST(hsm::serve_share_peer(m.store, policy, op, "POST", "/v1/peer/share", body)->status ==
               403U);
    BOOST_TEST(hsm::serve_share_peer(m.store, policy, op, "POST", "/v1/peer/share-request", check)
                   ->status == 403U);
    BOOST_TEST(
        hsm::serve_share_peer(m.store, policy, peer, "GET", "/v1/peer/share", body)->status ==
        405U);
    BOOST_TEST(
        hsm::serve_share_peer(m.store, policy, peer, "POST", "/v1/peer/share", "junk")->status ==
        400U);
    BOOST_TEST(hsm::serve_share_peer(m.store, policy, peer, "POST", "/v1/peer/share-request", check)
                   ->status == 404U);
    BOOST_TEST(
        hsm::serve_share_peer(m.store, policy, peer, "POST", "/v1/peer/share", body)->status ==
        200U);
    BOOST_TEST(
        hsm::serve_share_peer(m.store, policy, peer, "POST", "/v1/peer/share", body)->status ==
        409U);
    const auto answer =
        hsm::serve_share_peer(m.store, policy, peer, "POST", "/v1/peer/share-request", check);
    BOOST_REQUIRE(answer->status == 200U);
    BOOST_TEST(answer->body == body);
    BOOST_TEST(
        hsm::serve_share_peer(m.store, policy, peer, "POST", "/v1/peer/share-request", "short")
            ->status == 400U);
}

namespace {

/// The direct store with what the admin API needs from hsm_host.
struct admin_host {
    hsm::test::direct_store& store;
    [[nodiscard]] auto catalog() const { return store.catalog(); }
    [[nodiscard]] auto tokens() const { return store.tokens(); }
    [[nodiscard]] auto hosts(std::uint64_t id) const { return store.hosts(id); }
    auto propose_catalog(std::vector<std::byte> cmd) {
        return store.propose_catalog(std::move(cmd));
    }
    [[nodiscard]] static auto fits(std::uint64_t id) -> bool { return id != 0 && id <= 1000; }
    [[nodiscard]] static auto leads(std::uint64_t /*local*/) -> bool { return true; }
    [[nodiscard]] static auto catalog_barrier() -> hsm::ck_result<void> { return {}; }
};

const std::string k_operator = "spiffe://ops/alice";

/// Three members on one replicated store, each with its own share store.
struct cluster {
    hsm::test::direct_store store;
    admin_host host{store};
    std::array<std::unique_ptr<member>, 3> m;
    hsm::key_vault vault;  // the node the operator calls
    hsm::admin_api<admin_host> api{host, vault, hsm::admin_policy{{k_operator}}};
    std::size_t refuse = 99;  // a member that fails delivery

    cluster() {
        for (auto& p : m) {
            p = std::make_unique<member>();
        }
        hsm::node_share_delivery d;
        d.members = m.size();
        d.deliver = [this](std::size_t i, const hsm::shamir_share& s) {
            return i != refuse && m[i]->store.put(s);
        };
        api.set_node_share_delivery(std::move(d));
    }

    auto call(const std::string& method, const std::string& path, const std::string& body = "") {
        return api.handle({method, path, body, {k_operator}});
    }

    auto peers_of(std::size_t i) -> std::vector<hsm::node_unseal::fetch_fn> {
        std::vector<hsm::node_unseal::fetch_fn> out;
        for (std::size_t j = 0; j < m.size(); ++j) {
            if (j != i) {
                out.push_back(m[j]->as_peer());
            }
        }
        return out;
    }
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(init_in_node_mode_hands_each_member_one_share, cluster) {
    // n must be the member count.
    BOOST_TEST(call("POST", "/v1/init", R"({"mode": "node", "k": 2, "n": 4})").status == 400U);
    // A member that cannot take its share: nothing commits.
    refuse = 1;
    BOOST_TEST(call("POST", "/v1/init", R"({"mode": "node", "k": 2, "n": 3})").status == 503U);
    BOOST_TEST(!store.catalog().has_value());
    refuse = 99;
    const auto r = call("POST", "/v1/init", R"({"mode": "node", "k": 2, "n": 3})");
    BOOST_REQUIRE(r.status == 200U);
    const auto body = boost::json::parse(r.body).as_object();
    BOOST_TEST(!body.contains("shares"));  // the operator sees none
    BOOST_TEST(body.at("delivered").to_number<int>() == 3);
    const auto c = store.catalog();
    BOOST_REQUIRE(c.has_value());
    for (std::size_t i = 0; i < m.size(); ++i) {
        auto s = m[i]->store.find(c->mk_check);
        BOOST_REQUIRE(s.has_value());
        BOOST_TEST(s->index == i + 1);
    }
    // Every member unseals from its own share and one peer's.
    for (std::size_t i = 0; i < m.size(); ++i) {
        BOOST_TEST(static_cast<int>(m[i]->unseal.attempt(c, peers_of(i))) ==
                   static_cast<int>(hsm::node_unseal_outcome::unsealed));
    }
}

BOOST_AUTO_TEST_CASE(node_mode_needs_a_way_to_deliver) {
    hsm::test::direct_store store;
    admin_host host{store};
    hsm::key_vault v;
    hsm::admin_api<admin_host> bare{host, v, hsm::admin_policy{{k_operator}}};
    BOOST_TEST(
        bare.handle({"POST", "/v1/init", R"({"mode": "node", "k": 2, "n": 3})", {k_operator}})
            .status == 400U);
    BOOST_TEST(!store.catalog().has_value());
}

BOOST_FIXTURE_TEST_CASE(rekey_to_node_mode_redelivers_and_old_shares_retire, cluster) {
    // Start in operator mode, unsealed by the operator.
    const auto init =
        boost::json::parse(call("POST", "/v1/init", R"({"mode": "operator", "k": 2, "n": 2})").body)
            .as_object();
    for (const auto& s : init.at("shares").as_array()) {
        (void)call("POST", "/v1/unseal",
                   boost::json::serialize(boost::json::object{{"share", s.as_string()}}));
    }
    BOOST_REQUIRE(!vault.sealed());
    BOOST_REQUIRE(call("POST", "/v1/tokens", R"({"id": 3, "label": "kms"})").status == 201U);
    // Switch to node mode with a re-split: one entry, shares to the members.
    const auto r = call("POST", "/v1/rekey", R"({"mode": "node", "k": 2, "n": 3})");
    BOOST_REQUIRE(r.status == 200U);
    const auto c = store.catalog();
    BOOST_TEST(static_cast<int>(c->mode) == static_cast<int>(hsm::unseal_mode::node_shares));
    BOOST_TEST(c->generation == 2U);
    BOOST_TEST(!vault.sealed());
    for (std::size_t i = 0; i < m.size(); ++i) {
        BOOST_REQUIRE(static_cast<int>(m[i]->unseal.attempt(c, peers_of(i))) ==
                      static_cast<int>(hsm::node_unseal_outcome::unsealed));
        BOOST_TEST(m[i]->vault.with_token_key(*store.token(3), [](auto) { return 0; }).has_value());
    }
    // A second rekey in node mode: the members get new shares, and once
    // they unseal under the new key the old files are pruned.
    const auto old_check = c->mk_check;
    BOOST_REQUIRE(call("POST", "/v1/rekey").status == 200U);
    const auto c2 = store.catalog();
    for (std::size_t i = 0; i < m.size(); ++i) {
        BOOST_TEST(m[i]->vault.enforce(c2));  // rekeyed past: sealed
        BOOST_REQUIRE(static_cast<int>(m[i]->unseal.attempt(c2, peers_of(i))) ==
                      static_cast<int>(hsm::node_unseal_outcome::unsealed));
        BOOST_TEST(!m[i]->store.find(old_check).has_value());
    }
}
