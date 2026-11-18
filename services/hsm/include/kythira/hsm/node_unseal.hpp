// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Node unseal (.kiro/specs/virtual-hsm/ task 8, requirement 4.4): in node
// mode each member keeps one share of the master key on its own disk,
// sealed by a share sealer, and a sealed member collects k - 1 more from
// the other members over mutual TLS. Nobody types a share after a restart.
//
// What this trades (requirement 4.8, doc in services/hsm/README.md): every
// unsealed node holds the whole MK in memory, and a peer hands its share to
// any caller presenting a member's certificate, so a thief with one
// member's key and network reach to k - 1 others can rebuild the MK.
// Shamir still protects the disks, backups and snapshots: k disks and
// their sealing keys are needed offline.
//
// Pieces:
//   share_sealer      seals a share at rest. key_file_sealer is the
//                     built-in one: a 32-byte key in an owner-only file,
//                     AES-256-GCM. TPM 2.0 and cloud KMS sealers come
//                     with task 8b behind the same interface.
//   share_store       one sealed file per master key (named by its check
//                     value) in the module's data directory. A share is
//                     never overwritten, and older files are pruned only
//                     once this node unsealed with a newer one, so the
//                     shares a rekey delivers before it commits survive.
//   node_unseal       the collection: this node's share for the catalog's
//                     check value, then peers' until k, then combine and
//                     unseal the vault.
//   serve_share_peer  the two member routes on the module's listener:
//
//     POST /v1/peer/share           body: a share (binary form); store it
//     POST /v1/peer/share-request   body: the 8-byte check value; answer
//                                   this node's share of that key, or 404
//
// Shares are delivered by init and rekey in node mode (hsm_admin.hpp):
// share i to the i-th member in id order, every delivery before the
// catalog entry is proposed, so a failed delivery commits nothing.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_peer.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/sealing.hpp>
#include <kythira/hsm/secret_bytes.hpp>
#include <kythira/hsm/shamir.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kythira::hsm {

/// Seals one share at rest, bound to `context` (the key's check value), so
/// a sealed file cannot be renamed to stand for another key.
class share_sealer {
public:
    share_sealer() = default;
    share_sealer(const share_sealer&) = delete;
    auto operator=(const share_sealer&) -> share_sealer& = delete;
    share_sealer(share_sealer&&) = delete;
    auto operator=(share_sealer&&) -> share_sealer& = delete;
    virtual ~share_sealer() = default;

    [[nodiscard]] virtual auto name() const -> std::string_view = 0;
    [[nodiscard]] virtual auto seal(std::span<const std::uint8_t> share,
                                    std::span<const std::uint8_t> context) -> sealed_bytes = 0;
    /// Nothing when the bytes were not sealed by this sealer for `context`.
    [[nodiscard]] virtual auto unseal(std::span<const std::uint8_t> sealed,
                                      std::span<const std::uint8_t> context)
        -> std::optional<secret_bytes> = 0;
};

namespace node_unseal_detail {

inline auto share_ad(std::span<const std::uint8_t> context) -> std::vector<std::uint8_t> {
    constexpr std::string_view label = "kythira-hsm-node-share";
    std::vector<std::uint8_t> ad(label.begin(), label.end());
    ad.insert(ad.end(), context.begin(), context.end());
    return ad;
}

inline auto hex(std::span<const std::uint8_t> bytes) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (const auto b : bytes) {
        out.push_back(digits[b >> 4U]);
        out.push_back(digits[b & 0x0FU]);
    }
    return out;
}

/// Writes `bytes` to `path` with mode 0600 through a temporary file,
/// fsynced and renamed, so a crash leaves the old file or the new one.
inline void write_private_file(const std::filesystem::path& path,
                               std::span<const std::uint8_t> bytes) {
    const auto tmp = std::filesystem::path(path.string() + ".tmp");
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        throw std::system_error(errno, std::generic_category(), "open " + tmp.string());
    }
    std::size_t done = 0;
    while (done < bytes.size()) {
        const auto n = ::write(fd, bytes.data() + done, bytes.size() - done);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            const int err = errno;
            ::close(fd);
            throw std::system_error(err, std::generic_category(), "write " + tmp.string());
        }
        done += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) {
        const int err = errno;
        ::close(fd);
        throw std::system_error(err, std::generic_category(), "fsync " + tmp.string());
    }
    ::close(fd);
    std::filesystem::rename(tmp, path);
}

inline auto read_file(const std::filesystem::path& path)
    -> std::optional<std::vector<std::uint8_t>> {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), {});
}

}  // namespace node_unseal_detail

/// The built-in sealer: a random 32-byte key in a file only the owner may
/// read, created on first use. A key file that group or others can read is
/// refused rather than used.
class key_file_sealer final : public share_sealer {
public:
    explicit key_file_sealer(std::filesystem::path path) : _path(std::move(path)) {}

    [[nodiscard]] auto name() const -> std::string_view override { return "file"; }

    [[nodiscard]] auto seal(std::span<const std::uint8_t> share,
                            std::span<const std::uint8_t> context) -> sealed_bytes override {
        const auto key = load(true);
        return hsm::seal(key.view(), node_unseal_detail::share_ad(context), share);
    }

    [[nodiscard]] auto unseal(std::span<const std::uint8_t> sealed,
                              std::span<const std::uint8_t> context)
        -> std::optional<secret_bytes> override {
        const auto key = load(false);
        if (key.empty()) {
            return std::nullopt;
        }
        return hsm::unseal(key.view(), node_unseal_detail::share_ad(context), sealed);
    }

private:
    /// The key; created when `create` and the file is absent. Empty when
    /// absent and not created.
    auto load(bool create) -> secret_bytes {
        const std::scoped_lock lock(_mutex);
        struct stat st{};
        if (::stat(_path.c_str(), &st) != 0) {
            if (errno != ENOENT || !create) {
                if (errno == ENOENT) {
                    return {};
                }
                throw std::system_error(errno, std::generic_category(), "stat " + _path.string());
            }
            secret_bytes key(sealing_key_size);
            if (!generate_random(key.span())) {
                throw std::runtime_error("share key: no randomness");
            }
            node_unseal_detail::write_private_file(_path, key.view());
            return key;
        }
        if ((st.st_mode & 077U) != 0) {
            throw std::runtime_error("share key " + _path.string() +
                                     " is readable by group or others; chmod 600 it");
        }
        auto bytes = node_unseal_detail::read_file(_path);
        if (!bytes || bytes->size() != sealing_key_size) {
            throw std::runtime_error("share key " + _path.string() + " is not a 32-byte key");
        }
        secret_bytes key{std::span<const std::uint8_t>(*bytes)};
        OPENSSL_cleanse(bytes->data(), bytes->size());
        return key;
    }

    std::filesystem::path _path;
    std::mutex _mutex;
};

/// This node's shares, sealed, one file per master key.
class share_store {
public:
    share_store(std::filesystem::path dir, share_sealer& sealer)
        : _dir(std::move(dir)), _sealer(&sealer) {
        std::filesystem::create_directories(_dir);
    }

    /// Keeps `share`; false when a share of the same key is already held
    /// (a share is never overwritten, so a member cannot be talked out of
    /// its good one).
    auto put(const shamir_share& share) -> bool {
        const std::scoped_lock lock(_mutex);
        const auto path = path_of(share.check_value);
        if (std::filesystem::exists(path)) {
            return false;
        }
        const auto bin = shamir_encode_binary(share);
        node_unseal_detail::write_private_file(path, _sealer->seal(bin.view(), share.check_value));
        return true;
    }

    /// The share of the key with check value `check`, if held and intact.
    [[nodiscard]] auto find(std::span<const std::uint8_t, 8> check) -> std::optional<shamir_share> {
        const std::scoped_lock lock(_mutex);
        auto sealed = node_unseal_detail::read_file(path_of(check));
        if (!sealed) {
            return std::nullopt;
        }
        auto bin = _sealer->unseal(*sealed, check);
        if (!bin) {
            return std::nullopt;
        }
        auto share = shamir_decode_binary(bin->view());
        if (!share || !constant_time_equal(share->check_value, check)) {
            return std::nullopt;
        }
        return std::move(*share);
    }

    /// Removes the files older than the one for `current` (retired keys),
    /// keeping newer ones (shares a rekey delivered before it commits).
    void prune(std::span<const std::uint8_t, 8> current) {
        const std::scoped_lock lock(_mutex);
        std::error_code ec;
        const auto keep = path_of(current);
        const auto keep_time = std::filesystem::last_write_time(keep, ec);
        if (ec) {
            return;
        }
        for (const auto& entry : std::filesystem::directory_iterator(_dir, ec)) {
            const auto name = entry.path().filename().string();
            if (entry.path() == keep || !name.starts_with("share-") || !name.ends_with(".sealed")) {
                continue;
            }
            // Strictly older only: on a coarse clock a tie is kept, never a
            // newer share lost.
            if (entry.last_write_time(ec) < keep_time && !ec) {
                std::filesystem::remove(entry.path(), ec);
            }
        }
    }

    [[nodiscard]] auto sealer() -> share_sealer& { return *_sealer; }

private:
    [[nodiscard]] auto path_of(std::span<const std::uint8_t, 8> check) const
        -> std::filesystem::path {
        return _dir / ("share-" + node_unseal_detail::hex(check) + ".sealed");
    }

    std::filesystem::path _dir;
    share_sealer* _sealer;
    std::mutex _mutex;
};

enum class node_unseal_outcome : std::uint8_t {
    /// Nothing to do: unsealed already, not initialized, or operator mode.
    idle,
    unsealed,
    /// This node holds no share of the catalog's key.
    no_local_share,
    /// Fewer than k shares could be had; still sealed (requirement 13.5).
    too_few_shares,
    /// k shares did not combine into the catalog's key.
    wrong_key,
};

class node_unseal {
public:
    /// A peer's share of the key with `check`, as its binary form, or
    /// nothing (unreachable, refused, not held).
    using fetch_fn = std::function<std::optional<secret_bytes>(std::span<const std::uint8_t, 8>)>;

    node_unseal(key_vault& vault, share_store& store) : _vault(&vault), _store(&store) {}

    /// One attempt, with `peers` the other members' fetchers.
    auto attempt(const std::optional<catalog_record>& catalog, const std::vector<fetch_fn>& peers)
        -> node_unseal_outcome {
        if (!catalog || catalog->mode != unseal_mode::node_shares || !_vault->sealed()) {
            return node_unseal_outcome::idle;
        }
        auto mine = _store->find(catalog->mk_check);
        if (!mine) {
            return node_unseal_outcome::no_local_share;
        }
        std::vector<shamir_share> shares;
        shares.push_back(std::move(*mine));
        for (const auto& fetch : peers) {
            if (shares.size() >= catalog->k) {
                break;
            }
            auto bin = fetch(catalog->mk_check);
            if (!bin) {
                continue;
            }
            auto share = shamir_decode_binary(bin->view());
            if (!share || share->k != catalog->k || share->n != catalog->n ||
                !constant_time_equal(share->check_value, catalog->mk_check) ||
                has_index(shares, share->index)) {
                continue;  // a peer's bad answer is skipped, not trusted
            }
            shares.push_back(std::move(*share));
        }
        if (shares.size() < catalog->k) {
            return node_unseal_outcome::too_few_shares;
        }
        auto mk = shamir_combine(shares);
        if (!mk || _vault->unseal(std::move(*mk), catalog) != unseal_result::unsealed) {
            return node_unseal_outcome::wrong_key;
        }
        _store->prune(catalog->mk_check);
        return node_unseal_outcome::unsealed;
    }

private:
    [[nodiscard]] static auto has_index(const std::vector<shamir_share>& shares, std::uint8_t index)
        -> bool {
        for (const auto& s : shares) {
            if (s.index == index) {
                return true;
            }
        }
        return false;
    }

    key_vault* _vault;
    share_store* _store;
};

/// Whether `caller` may deliver or ask for a share: with the catalog's
/// crypto member list seeded, only an identity on it
/// (.kiro/specs/hsm-independent-layers/ Requirement 5.2); before that, a
/// member, as in every co-located cluster (Requirement 1.2).
[[nodiscard]] inline auto may_hold_share(const peer_policy& policy,
                                         const std::vector<std::string>& crypto_members,
                                         const peer_caller& caller) -> bool {
    if (crypto_members.empty()) {
        return is_member(policy, caller);
    }
    auto listed = policy;
    listed.identities = {crypto_members.begin(), crypto_members.end()};
    return is_member(listed, caller);
}

/// The share routes for the module's listener; nothing for other targets.
/// Only a crypto member may deliver or ask (may_hold_share): the members,
/// until `crypto_members` (the catalog's list) is seeded.
[[nodiscard]] inline auto serve_share_peer(share_store& store, const peer_policy& policy,
                                           const peer_caller& caller, std::string_view method,
                                           std::string_view target, std::string_view body,
                                           const std::vector<std::string>& crypto_members = {})
    -> std::optional<peer_answer> {
    const bool deliver = target == peer_share_route;
    if (!deliver && target != peer_share_request_route) {
        return std::nullopt;
    }
    if (!may_hold_share(policy, crypto_members, caller)) {
        return peer_answer{403, "not a member"};
    }
    if (method != "POST") {
        return peer_answer{405, "method not allowed"};
    }
    const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(body.data()),
                                              body.size());
    if (deliver) {
        auto share = shamir_decode_binary(bytes);
        if (!share) {
            return peer_answer{400, "not a share"};
        }
        return store.put(*share) ? peer_answer{200, "stored"}
                                 : peer_answer{409, "a share of this key is already held"};
    }
    if (bytes.size() != 8) {
        return peer_answer{400, "expected an 8-byte check value"};
    }
    std::array<std::uint8_t, 8> check{};
    std::copy_n(bytes.begin(), check.size(), check.begin());
    auto share = store.find(check);
    if (!share) {
        return peer_answer{404, "no share of this key"};
    }
    const auto bin = shamir_encode_binary(*share);
    return peer_answer{200, std::string(reinterpret_cast<const char*>(bin.data()), bin.size())};
}

}  // namespace kythira::hsm
