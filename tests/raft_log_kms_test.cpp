// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file raft_log_kms_test.cpp
/// @brief A Raft log key ring under the shared `kms_key_provider`
///        (.kiro/specs/raft-log-encryption/ tasks 4 and 5): the settings a
///        service node reads, the adapter's encryption context, and one key
///        ring per data directory sealing every group's log.

#define BOOST_TEST_MODULE raft_log_kms_test
#include <boost/test/unit_test.hpp>

#include <raft/raft_log_kms.hpp>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

namespace fs = std::filesystem;
using engine_t = kythira::binary_file_persistence_engine<>;
using kythira::raft_log_encryption_settings;

namespace {

struct temp_dir {
    fs::path path;
    temp_dir() {
        static std::atomic<int> counter{0};
        path = fs::temp_directory_path() / ("kythira_rlk_" + std::to_string(::getpid()) + "_" +
                                            std::to_string(counter.fetch_add(1)));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

auto settings_from(const std::map<std::string, std::string>& env) -> raft_log_encryption_settings {
    return raft_log_encryption_settings::from([&env](const char* var) {
        const auto it = env.find(var);
        return it == env.end() ? std::string() : it->second;
    });
}

auto refusal(const std::map<std::string, std::string>& env) -> std::string {
    try {
        (void)settings_from(env);
    } catch (const std::invalid_argument& e) {
        return e.what();
    }
    return {};
}

auto command(const std::string& text) -> std::vector<std::byte> {
    std::vector<std::byte> out(text.size());
    std::transform(text.begin(), text.end(), out.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    return out;
}

auto entry(std::uint64_t index, const std::string& text) -> kythira::log_entry<> {
    kythira::log_entry<> e;
    e._term = 1;
    e._index = index;
    e._command = command(text);
    return e;
}

auto any_file_holds(const fs::path& dir, const std::string& needle) -> bool {
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        if (!e.is_regular_file()) {
            continue;
        }
        std::ifstream in(e.path(), std::ios::binary);
        const std::string bytes{std::istreambuf_iterator<char>(in), {}};
        if (bytes.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}  // namespace

BOOST_AUTO_TEST_CASE(settings_default_off_and_refuse_what_cannot_work) {
    BOOST_TEST(!settings_from({}).enabled());
    BOOST_TEST(refusal({{"KYTHIRA_RAFT_LOG_KMS", "vault"}}).find("expected off") !=
               std::string::npos);
    BOOST_TEST(refusal({{"KYTHIRA_RAFT_LOG_KMS", "local"}}).find("PASSPHRASE") !=
               std::string::npos);
    BOOST_TEST(refusal({{"KYTHIRA_RAFT_LOG_KMS", "aws"}}).find("KEY_ID") != std::string::npos);
    BOOST_TEST(refusal({{"KYTHIRA_RAFT_LOG_KMS", "kythira"}, {"KYTHIRA_RAFT_LOG_KMS_KEY_ID", "k"}})
                   .find("ENDPOINT") != std::string::npos);
    BOOST_TEST(refusal({{"KYTHIRA_RAFT_LOG_ENCRYPTION", "maybe"}}).find("decrypt_only") !=
               std::string::npos);

    const auto s = settings_from({{"KYTHIRA_RAFT_LOG_KMS", "local"},
                                  {"KYTHIRA_RAFT_LOG_PASSPHRASE", "pw"},
                                  {"KYTHIRA_RAFT_LOG_ENCRYPTION", "decrypt_only"}});
    BOOST_TEST(s.enabled());
    BOOST_TEST(s.key_id == "raft-log");
    BOOST_TEST(static_cast<int>(s.mode) ==
               static_cast<int>(kythira::log_encryption_mode::decrypt_only));
    const auto a = settings_from({{"KYTHIRA_RAFT_LOG_KMS", "aws"},
                                  {"KYTHIRA_RAFT_LOG_KMS_KEY_ID", "alias/raft"},
                                  {"AWS_REGION", "eu-west-1"}});
    BOOST_TEST(a.region == "eu-west-1");
}

BOOST_AUTO_TEST_CASE(adapter_binds_the_raft_log_context) {
    const kythira::kms_provider::key_provider provider(
        kythira::kms_provider::local_kms_provider("passphrase"));
    const auto source = kythira::raft_log_key_source_from_kms(provider, "raft-log", "node-1");
    const auto made = source._generate();
    BOOST_TEST(made._key_id == "raft-log");
    BOOST_CHECK(source._unwrap(made._key_id, made._wrapped) == made._plaintext);
    // The same wrapped key does not unwrap as another consumer's.
    BOOST_CHECK_THROW((void)provider.decrypt_data_key("raft-log", made._wrapped,
                                                      {{"kythira:purpose", "dynamodb"}}),
                      std::exception);
    // Nor for another node.
    const auto other = kythira::raft_log_key_source_from_kms(provider, "raft-log", "node-2");
    BOOST_CHECK_THROW((void)other._unwrap(made._key_id, made._wrapped), std::exception);
}

BOOST_AUTO_TEST_CASE(off_leaves_options_alone) {
    temp_dir d;
    kythira::binary_file_persistence_options base;
    base._segment_max_bytes = 4096;
    const auto o = kythira::raft_log_options_for(d.path, settings_from({}), base);
    BOOST_TEST(!o._key_ring);
    BOOST_TEST(o._segment_max_bytes == 4096U);
    BOOST_TEST(!fs::exists(d.path / "raft-log-keys"));
}

BOOST_AUTO_TEST_CASE(one_ring_per_data_dir_seals_every_group) {
    temp_dir d;
    const auto settings =
        settings_from({{"KYTHIRA_RAFT_LOG_KMS", "local"}, {"KYTHIRA_RAFT_LOG_PASSPHRASE", "pw"}});
    {
        const auto o1 = kythira::raft_log_options_for(d.path, settings);
        const auto o2 = kythira::raft_log_options_for(d.path, settings);
        BOOST_TEST(o1._key_ring == o2._key_ring);
        engine_t g1(d.path / "raft" / "1", o1);
        engine_t g2(d.path / "raft" / "2", o2);
        g1.append_log_entry(entry(1, "GROUP-ONE-VALUE"));
        g2.append_log_entry(entry(1, "GROUP-TWO-VALUE"));
    }
    BOOST_TEST(fs::exists(d.path / "raft-log-keys"));
    BOOST_TEST(!any_file_holds(d.path, "GROUP-ONE-VALUE"));
    BOOST_TEST(!any_file_holds(d.path, "GROUP-TWO-VALUE"));

    // A restart (the ring reopened from its file) reads both groups.
    const auto o = kythira::raft_log_options_for(d.path, settings);
    engine_t g1(d.path / "raft" / "1", o);
    BOOST_CHECK(g1.get_log_entry(1)->command() == command("GROUP-ONE-VALUE"));

    // Another passphrase cannot open the ring.
    temp_dir copy;
    fs::copy_file(d.path / "raft-log-keys", copy.path / "raft-log-keys");
    BOOST_CHECK_THROW((void)kythira::raft_log_options_for(
                          copy.path, settings_from({{"KYTHIRA_RAFT_LOG_KMS", "local"},
                                                    {"KYTHIRA_RAFT_LOG_PASSPHRASE", "other"}})),
                      kythira::persistence_exception);
}
