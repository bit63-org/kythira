// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Share sealers over a KMS key provider (.kiro/specs/virtual-hsm/ task 8b):
// the envelope round trip, the bindings (check value, sealer, data key),
// refusals and KMS failures, and a share store on top. Core's local
// provider stands in for AWS KMS, a PKCS#11 token and the clouds: the
// sealer sees only the provider interface.

#define BOOST_TEST_MODULE hsm_share_sealers_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/node_unseal.hpp>
#include <kythira/hsm/shamir.hpp>
#include <kythira/hsm/share_sealers.hpp>

#include <raft/kms_key_provider.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace hsm = kythira::hsm;
namespace kp = kythira::kms_provider;
namespace fs = std::filesystem;

constexpr std::array<std::uint8_t, 8> k_check{1, 2, 3, 4, 5, 6, 7, 8};
constexpr std::array<std::uint8_t, 8> k_other_check{8, 7, 6, 5, 4, 3, 2, 1};
constexpr std::array<std::uint8_t, 5> k_secret{0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

/// What the provider was asked, and a switch to make it fail.
struct provider_log {
    std::vector<kp::encryption_context> contexts;
    std::vector<std::string> key_ids;
    bool refuse = false;
};

/// The local provider, recording each call and failing on request; it
/// resolves "alias/share" to a full id as AWS KMS resolves an alias to
/// its ARN.
struct recording_provider {
    kp::local_kms_provider inner{"a passphrase of sixteen bytes or more"};
    std::shared_ptr<provider_log> log = std::make_shared<provider_log>();

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const kp::encryption_context& context) const
        -> kp::generated_data_key {
        log->contexts.push_back(context);
        log->key_ids.push_back(key_id);
        if (log->refuse) {
            throw kp::kms_error(kp::kms_failure::access_denied, "refused");
        }
        auto out = inner.generate_data_key(resolved(key_id), context);
        out._key_id = resolved(key_id);
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const kp::encryption_context& context) const
        -> kp::data_key_bytes {
        log->contexts.push_back(context);
        log->key_ids.push_back(key_id);
        if (log->refuse) {
            throw kp::kms_error(kp::kms_failure::unavailable, "unreachable");
        }
        return inner.decrypt_data_key(key_id, wrapped, context);
    }

    [[nodiscard]] static auto resolved(const std::string& id) -> std::string {
        return id == "alias/share" ? "key/1234" : id;
    }
};

struct temp_dir {
    fs::path path;
    temp_dir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("hsm-share-sealers-" + std::to_string(rd()));
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

}  // namespace

BOOST_AUTO_TEST_CASE(a_share_round_trips_bound_to_its_check_value) {
    recording_provider p;
    auto log = p.log;
    hsm::kms_share_sealer sealer("aws-kms", kp::key_provider(p), "alias/share");
    BOOST_TEST(sealer.name() == "aws-kms");
    const auto sealed = sealer.seal(k_secret, k_check);
    // The context names the share's key, as hex, under the sealer's key.
    BOOST_REQUIRE(log->contexts.size() == 1U);
    BOOST_TEST(log->contexts[0].at(hsm::kms_share_sealer::k_context_key) == "0102030405060708");
    auto back = sealer.unseal(sealed, k_check);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(hsm::constant_time_equal(back->view(), k_secret));
    BOOST_TEST(sealer.last_error().empty());
    // The resolved id is stored and used to open, not the alias.
    BOOST_TEST(log->key_ids.back() == "key/1234");
    // Another key's check value opens nothing.
    BOOST_TEST(!sealer.unseal(sealed, k_other_check).has_value());
    BOOST_TEST(!sealer.last_error().empty());
}

BOOST_AUTO_TEST_CASE(nothing_else_opens_and_nothing_is_echoed) {
    recording_provider p;
    hsm::kms_share_sealer sealer("aws-kms", kp::key_provider(p), "alias/share");
    const auto sealed = sealer.seal(k_secret, k_check);

    // Another sealer's share: named, not tried.
    hsm::kms_share_sealer pkcs11("pkcs11", kp::key_provider(p), "alias/share");
    BOOST_TEST(!pkcs11.unseal(sealed, k_check).has_value());
    BOOST_TEST(pkcs11.last_error().find("aws-kms") != std::string::npos);

    // The key file sealer's output, garbage and every truncation.
    temp_dir dir;
    hsm::key_file_sealer file(dir.path / "share.key");
    BOOST_TEST(!sealer.unseal(file.seal(k_secret, k_check), k_check).has_value());
    BOOST_TEST(!sealer.unseal(std::vector<std::uint8_t>(64, 0x41), k_check).has_value());
    for (std::size_t n = 0; n < sealed.size(); ++n) {
        const std::vector<std::uint8_t> cut(sealed.begin(),
                                            sealed.begin() + static_cast<std::ptrdiff_t>(n));
        BOOST_TEST(!sealer.unseal(cut, k_check).has_value(), "truncated at " << n);
    }
    // Every flipped byte: the header, the wrapped key or the sealed share.
    for (std::size_t i = 0; i < sealed.size(); ++i) {
        auto bad = sealed;
        bad[i] ^= 0x01U;
        BOOST_TEST(!sealer.unseal(bad, k_check).has_value(), "flipped byte " << i);
    }
    // The plaintext never appears in what is stored.
    const std::vector<std::uint8_t> secret(k_secret.begin(), k_secret.end());
    BOOST_TEST(
        (std::search(sealed.begin(), sealed.end(), secret.begin(), secret.end()) == sealed.end()));
}

BOOST_AUTO_TEST_CASE(a_kms_that_refuses_fails_sealing_and_reads_as_absent) {
    recording_provider p;
    auto log = p.log;
    hsm::kms_share_sealer sealer("aws-kms", kp::key_provider(p), "alias/share");
    const auto sealed = sealer.seal(k_secret, k_check);
    log->refuse = true;
    // A share that cannot be sealed must not be acknowledged.
    BOOST_CHECK_THROW((void)sealer.seal(k_secret, k_check), kp::kms_error);
    // A KMS away: the share reads as absent (the member asks its peers),
    // and the reason is kept for the log.
    BOOST_TEST(!sealer.unseal(sealed, k_check).has_value());
    BOOST_TEST(sealer.last_error().find("unreachable") != std::string::npos);
    log->refuse = false;
    BOOST_TEST(sealer.unseal(sealed, k_check).has_value());
}

BOOST_AUTO_TEST_CASE(a_share_store_keeps_shares_under_the_kms_sealer) {
    temp_dir dir;
    recording_provider p;
    hsm::kms_share_sealer sealer("aws-kms", kp::key_provider(p), "alias/share");
    hsm::secret_bytes mk(32);
    BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value());
    auto shares = hsm::shamir_split(mk.view(), 2, 3);
    BOOST_REQUIRE(shares.has_value());
    hsm::share_store store(dir.path / "shares", sealer);
    BOOST_TEST(store.put((*shares)[0]));
    auto got = store.find((*shares)[0].check_value);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST(got->index == (*shares)[0].index);
    // A store over another provider's key (another passphrase) finds
    // nothing in the same directory.
    struct stranger_provider : recording_provider {
        stranger_provider() { inner = kp::local_kms_provider("another passphrase, sixteen+"); }
    };
    hsm::kms_share_sealer stranger("aws-kms", kp::key_provider(stranger_provider{}), "alias/share");
    hsm::share_store other(dir.path / "shares", stranger);
    BOOST_TEST(!other.find((*shares)[0].check_value).has_value());
}

BOOST_AUTO_TEST_CASE(a_sealer_needs_a_name_a_provider_and_a_key) {
    recording_provider p;
    BOOST_CHECK_THROW(hsm::kms_share_sealer("", kp::key_provider(p), "k"), std::invalid_argument);
    BOOST_CHECK_THROW(hsm::kms_share_sealer("aws-kms", kp::key_provider{}, "k"),
                      std::invalid_argument);
    BOOST_CHECK_THROW(hsm::kms_share_sealer("aws-kms", kp::key_provider(p), ""),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(a_share_the_kms_cannot_seal_is_refused_not_held) {
    temp_dir dir;
    recording_provider p;
    auto log = p.log;
    hsm::kms_share_sealer sealer("aws-kms", kp::key_provider(p), "alias/share");
    hsm::share_store store(dir.path / "shares", sealer);
    hsm::secret_bytes mk(32);
    BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value());
    auto shares = hsm::shamir_split(mk.view(), 2, 3);
    BOOST_REQUIRE(shares.has_value());
    const auto bin = hsm::shamir_encode_binary((*shares)[1]);
    const std::string body(reinterpret_cast<const char*>(bin.data()), bin.size());
    const hsm::peer_policy policy{{"node-2"}, false};
    const hsm::peer_caller peer{true, true, {}, {"node-2"}};
    // A member whose KMS refuses answers 503 with the reason, so the
    // delivering member commits nothing; the share is not held.
    log->refuse = true;
    const auto refused = hsm::serve_share_peer(store, policy, peer, "POST", "/v1/peer/share", body);
    BOOST_REQUIRE(refused.has_value());
    BOOST_TEST(refused->status == 503U);
    BOOST_TEST(refused->body.find("refused") != std::string::npos);
    log->refuse = false;
    BOOST_TEST(!store.find((*shares)[1].check_value).has_value());
    // Once it answers, the same delivery is taken.
    BOOST_TEST(hsm::serve_share_peer(store, policy, peer, "POST", "/v1/peer/share", body)->status ==
               200U);
    BOOST_TEST(store.find((*shares)[1].check_value).has_value());
}
