// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The TPM 2.0 key provider and a share sealed to it
// (.kiro/specs/virtual-hsm/ task 8b), against swtpm (libtpms) through
// tpm2-tss's swtpm TCTI: the round trip under the owner hierarchy's
// storage key and a persistent one, the context binding, a PCR policy
// that stops opening once a PCR moves, another TPM's blob, and malformed
// input. Built only with KYTHIRA_HSM_TPM2 and swtpm installed.

#define BOOST_TEST_MODULE hsm_tpm2_sealer_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/share_sealers.hpp>
#include <kythira/hsm/tpm2_key_provider.hpp>

#include <test_ports.hpp>

#include <signal.h>  // NOLINT(modernize-deprecated-headers): kill(), which <csignal> lacks
#include <spawn.h>
#include <sys/wait.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace {

namespace hsm = kythira::hsm;
namespace kp = kythira::kms_provider;
namespace fs = std::filesystem;

constexpr std::array<std::uint8_t, 8> k_check{1, 2, 3, 4, 5, 6, 7, 8};
constexpr std::array<std::uint8_t, 8> k_other_check{8, 7, 6, 5, 4, 3, 2, 1};
constexpr std::array<std::uint8_t, 5> k_secret{0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
const kp::encryption_context k_ctx{{"kythira:hsm:share", "0102030405060708"}};

auto failure_of(const auto& f) -> std::optional<kp::kms_failure> {
    try {
        f();
    } catch (const kp::kms_error& e) {
        return e.failure();
    }
    return std::nullopt;
}

auto run(const std::vector<std::string>& argv) -> int {
    std::vector<char*> args;
    args.reserve(argv.size() + 1);
    for (const auto& a : argv) {
        args.push_back(
            const_cast<char*>(a.c_str()));  // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }
    args.push_back(nullptr);
    pid_t pid = 0;
    if (posix_spawnp(&pid, args[0], nullptr, nullptr, args.data(), environ) != 0) {
        return -1;
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/// One swtpm for the whole binary, manufactured fresh (a sha256 PCR bank
/// allocated, as firmware does) in a temporary directory, on free ports.
struct simulator {
    fs::path dir;
    std::string tcti;
    std::unique_ptr<hsm::tpm2_key_provider> plain;

    simulator() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("hsm-tpm2-" + std::to_string(rd()));
        fs::create_directories(dir);
        if (run({"swtpm_setup", "--tpm2", "--tpm-state", dir.string(), "--pcr-banks", "sha256",
                 "--overwrite", "--logfile", (dir / "setup.log").string()}) != 0) {
            throw std::runtime_error("swtpm_setup failed; see " + (dir / "setup.log").string());
        }
        const auto port = kythira::testing::free_port_block(2);
        const auto p = std::to_string(port);
        const auto c = std::to_string(port + 1);
        if (run({"swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + dir.string(), "--server",
                 "type=tcp,port=" + p + ",bindaddr=127.0.0.1", "--ctrl",
                 "type=tcp,port=" + c + ",bindaddr=127.0.0.1", "--flags",
                 "not-need-init,startup-clear", "--daemon", "--pid",
                 "file=" + (dir / "swtpm.pid").string(), "--log",
                 "file=" + (dir / "swtpm.log").string()}) != 0) {
            throw std::runtime_error("swtpm did not start; see " + (dir / "swtpm.log").string());
        }
        tcti = "swtpm:host=127.0.0.1,port=" + p;
        plain =
            std::make_unique<hsm::tpm2_key_provider>(hsm::tpm2_config{.tcti = tcti, .pcrs = ""});
    }
    simulator(const simulator&) = delete;
    simulator(simulator&&) = delete;
    auto operator=(const simulator&) -> simulator& = delete;
    auto operator=(simulator&&) -> simulator& = delete;
    ~simulator() {
        plain.reset();
        std::ifstream pid_file(dir / "swtpm.pid");
        pid_t pid = 0;
        if (pid_file >> pid && pid > 0) {
            (void)kill(pid, SIGTERM);
        }
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    /// Extends a resettable debug PCR (16) to move it.
    void extend_pcr16() const {
        plain->with_esys([](ESYS_CONTEXT* ctx) {
            TPML_DIGEST_VALUES v{};
            v.count = 1;
            v.digests[0].hashAlg = TPM2_ALG_SHA256;
            v.digests[0].digest.sha256[0] = 0x42;
            BOOST_REQUIRE(Esys_PCR_Extend(ctx, ESYS_TR_PCR16, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                          ESYS_TR_NONE, &v) == TSS2_RC_SUCCESS);
        });
    }

    void reset_pcr16() const {
        plain->with_esys([](ESYS_CONTEXT* ctx) {
            BOOST_REQUIRE(Esys_PCR_Reset(ctx, ESYS_TR_PCR16, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                         ESYS_TR_NONE) == TSS2_RC_SUCCESS);
        });
    }
};

auto sim() -> simulator& {
    static simulator s;
    return s;
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_data_key_seals_to_the_owner_storage_key) {
    const auto& p = *sim().plain;
    const auto made = p.generate_data_key("owner", k_ctx);
    BOOST_TEST(made._key_id == "owner");
    BOOST_TEST((p.decrypt_data_key("owner", made._wrapped, k_ctx) == made._plaintext));
    // The primary is derived again each call: a second seal opens too.
    const auto again = p.generate_data_key("owner", k_ctx);
    BOOST_TEST((again._plaintext != made._plaintext));
    BOOST_TEST((p.decrypt_data_key("owner", again._wrapped, k_ctx) == again._plaintext));
    // Bound to the context.
    const kp::encryption_context other{{"kythira:hsm:share", "0807060504030201"}};
    BOOST_TEST((failure_of([&] { (void)p.decrypt_data_key("owner", made._wrapped, other); }) ==
                kp::kms_failure::invalid_state));
    // The data key never appears in what is stored.
    const std::string key(made._plaintext.begin(), made._plaintext.end());
    BOOST_TEST(made._wrapped.find(key) == std::string::npos);
}

BOOST_AUTO_TEST_CASE(malformed_and_foreign_blobs_open_nothing) {
    const auto& p = *sim().plain;
    const auto made = p.generate_data_key("owner", k_ctx);
    for (std::size_t n = 0; n < made._wrapped.size(); n += 7) {
        BOOST_TEST(failure_of([&] {
                       (void)p.decrypt_data_key("owner", made._wrapped.substr(0, n), k_ctx);
                   }).has_value(),
                   "truncated at " << n);
    }
    // A flipped byte in the private part: the TPM's integrity check.
    auto bad = made._wrapped;
    bad[bad.size() - 5] = static_cast<char>(bad[bad.size() - 5] ^ 0x01);
    BOOST_TEST(failure_of([&] { (void)p.decrypt_data_key("owner", bad, k_ctx); }).has_value());
    BOOST_TEST((failure_of([&] { (void)p.decrypt_data_key("owner", "KTP1", k_ctx); }) ==
                kp::kms_failure::invalid_state));
    // Another TPM (another machine's disk copied here) opens nothing: its
    // storage key comes from another seed.
    {
        const simulator other;
        BOOST_TEST(failure_of([&] {
                       (void)other.plain->decrypt_data_key("owner", made._wrapped, k_ctx);
                   }).has_value());
    }
    // Key ids that name nothing.
    for (const char* id : {"", "endorsement", "0x80000001", "0x8100000", "0x81000001x"}) {
        BOOST_TEST((failure_of([&] { (void)p.generate_data_key(id, k_ctx); }) ==
                    kp::kms_failure::not_found),
                   id);
    }
    // A persistent handle nothing was made at.
    BOOST_TEST((failure_of([&] { (void)p.generate_data_key("0x81000099", k_ctx); }) ==
                kp::kms_failure::not_found));
}

BOOST_AUTO_TEST_CASE(a_persistent_storage_key_parents_seals) {
    const auto& p = *sim().plain;
    // Make the operator's persistent storage key at 0x81000001.
    p.with_esys([](ESYS_CONTEXT* ctx) {
        const TPM2B_SENSITIVE_CREATE none{};
        const auto tmpl = hsm::tpm2_detail::storage_key_template();
        const TPM2B_DATA outside{};
        const TPML_PCR_SELECTION creation{};
        ESYS_TR primary = ESYS_TR_NONE;
        BOOST_REQUIRE(Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                         ESYS_TR_NONE, &none, &tmpl, &outside, &creation, &primary,
                                         nullptr, nullptr, nullptr, nullptr) == TSS2_RC_SUCCESS);
        ESYS_TR persistent = ESYS_TR_NONE;
        BOOST_REQUIRE(Esys_EvictControl(ctx, ESYS_TR_RH_OWNER, primary, ESYS_TR_PASSWORD,
                                        ESYS_TR_NONE, ESYS_TR_NONE, 0x81000001,
                                        &persistent) == TSS2_RC_SUCCESS);
        (void)Esys_FlushContext(ctx, primary);
        (void)Esys_TR_Close(ctx, &persistent);
    });
    const auto made = p.generate_data_key("0x81000001", k_ctx);
    BOOST_TEST((p.decrypt_data_key("0x81000001", made._wrapped, k_ctx) == made._plaintext));
    // The same template under the same seed: the owner key is the same
    // key, so the blob loads under either.
    BOOST_TEST((p.decrypt_data_key("owner", made._wrapped, k_ctx) == made._plaintext));
}

BOOST_AUTO_TEST_CASE(a_pcr_bound_seal_stops_opening_when_the_pcr_moves) {
    auto& s = sim();
    // Bad selections fail when the provider is made.
    for (const char* bad : {"md5:1", "sha256:24", "sha256:", "sha256", "sha256:1,,2"}) {
        BOOST_CHECK_THROW(hsm::tpm2_key_provider(hsm::tpm2_config{.tcti = s.tcti, .pcrs = bad}),
                          std::invalid_argument);
    }
    // A bank the TPM has not allocated is refused: the policy would bind
    // nothing.
    const hsm::tpm2_key_provider sha1(hsm::tpm2_config{.tcti = s.tcti, .pcrs = "sha1:7"});
    BOOST_TEST((failure_of([&] { (void)sha1.generate_data_key("owner", k_ctx); }) ==
                kp::kms_failure::invalid_state));

    s.reset_pcr16();
    const hsm::tpm2_key_provider p(hsm::tpm2_config{.tcti = s.tcti, .pcrs = "sha256:7,16"});
    const auto made = p.generate_data_key("owner", k_ctx);
    BOOST_TEST((p.decrypt_data_key("owner", made._wrapped, k_ctx) == made._plaintext));
    // The selection travels with the sealed key: a provider with none
    // configured still checks it.
    BOOST_TEST((s.plain->decrypt_data_key("owner", made._wrapped, k_ctx) == made._plaintext));
    s.extend_pcr16();
    BOOST_TEST((failure_of([&] { (void)p.decrypt_data_key("owner", made._wrapped, k_ctx); }) ==
                kp::kms_failure::access_denied));
    BOOST_TEST((failure_of([&] {
                    (void)s.plain->decrypt_data_key("owner", made._wrapped, k_ctx);
                }) == kp::kms_failure::access_denied));
    s.reset_pcr16();
    BOOST_TEST((p.decrypt_data_key("owner", made._wrapped, k_ctx) == made._plaintext));
}

BOOST_AUTO_TEST_CASE(a_share_round_trips_through_the_tpm_sealer) {
    hsm::kms_share_sealer sealer("tpm2", kp::key_provider(*sim().plain), "owner");
    const auto sealed = sealer.seal(k_secret, k_check);
    const auto back = sealer.unseal(sealed, k_check);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(hsm::constant_time_equal(back->view(), k_secret));
    BOOST_TEST(!sealer.unseal(sealed, k_other_check).has_value());
    BOOST_TEST(!sealer.last_error().empty());
}
