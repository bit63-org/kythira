// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 4 property tests (Requirement 3.5): random command streams applied
// to replicas leave identical engines, and so does a checkpoint restored
// into a new replica mid-stream; and no command can carry key material,
// because the format has only integers and UTF-8 text and random binary
// material is refused wherever text is expected.

#define BOOST_TEST_MODULE kms_catalog_property_test

#include <boost/test/unit_test.hpp>

#include <kythira/kms/kms_catalog.hpp>

#include <raft/memory_kv_engine.hpp>

#include <openssl/rand.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace kms = kythira::kms;

namespace {

struct temp_dir {
    std::filesystem::path path;
    temp_dir() {
        static std::atomic<int> n{0};
        path = std::filesystem::temp_directory_path() /
               ("kms_catalog_property_" + std::to_string(::getpid()) + "_" + std::to_string(++n));
        std::filesystem::create_directories(path);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

struct replica {
    kythira::memory_kv_engine engine;
    kms::kms_catalog_state_machine<> sm{"kms/"};
    replica() { sm.open(engine, sm.engine_range()); }

    [[nodiscard]] auto dump() const -> std::vector<std::pair<std::string, std::string>> {
        std::vector<std::pair<std::string, std::string>> out;
        for (const auto cf : {kythira::column_family::data, kythira::column_family::meta}) {
            const_cast<kythira::memory_kv_engine&>(engine).scan(
                cf, sm.engine_range(), kythira::scan_direction::forward,
                [&](std::string_view k, std::string_view v) {
                    out.emplace_back(std::string(k), std::string(v));
                    return true;
                });
        }
        return out;
    }
};

constexpr std::array<std::string_view, 2> accounts{"111122223333", "444455556666"};

// A random but well-formed command over a small universe of ids, so that
// commands collide (names taken, keys in the wrong state, versions out of
// order) as often as they succeed.
auto random_command(std::mt19937_64& rng, std::uint64_t& now) -> std::vector<std::byte> {
    auto pick = [&](std::size_t n) { return static_cast<std::size_t>(rng() % n); };
    char buf[37];
    std::snprintf(buf, sizeof buf, "%08zx-0000-4000-8000-000000000000", pick(6));
    const std::string id = buf;
    const auto acct = std::string(accounts[pick(2)]);
    const std::string alias = "alias/a" + std::to_string(pick(4));
    now += pick(10) * kms::k_ms_per_day;
    switch (pick(16)) {
        case 0:
        case 1: {
            kms::key_record k;
            k.key_id = id;
            k.account = acct;
            k.description = "d" + std::to_string(pick(3));
            const auto& spec = kms::k_key_specs[pick(kms::k_key_specs.size())];
            k.spec = spec.spec;
            k.usage = spec.usages[pick(2)];
            k.creation_ms = now;
            k.policy = "{}";
            return kms::make_create_key_command(k, {{"t", std::to_string(pick(3))}});
        }
        case 2:
            return kms::make_complete_key_command(id, rng(), now);
        case 3:
            return kms::make_set_enabled_command(id, pick(2) == 0);
        case 4:
            return kms::make_update_description_command(id, "u" + std::to_string(pick(5)));
        case 5:
            return kms::make_put_policy_command(id, "{\"v\":" + std::to_string(pick(5)) + "}");
        case 6:
            return kms::make_schedule_deletion_command(id, 7 + static_cast<std::uint32_t>(pick(24)),
                                                       now);
        case 7:
            return kms::make_cancel_deletion_command(id);
        case 8:
            return kms::make_destroy_key_command(id, now);
        case 9:
            return kms::make_add_version_command(
                id, 1 + static_cast<std::uint32_t>(pick(4)), rng(),
                pick(2) == 0 ? kms::rotation_type::automatic : kms::rotation_type::on_demand, now);
        case 10:
            return kms::make_set_rotation_command(id, pick(2) == 0,
                                                  90 + static_cast<std::uint32_t>(pick(400)), now);
        case 11:
            return kms::make_create_alias_command(acct, alias, id, false, now);
        case 12:
            return pick(2) == 0 ? kms::make_update_alias_command(acct, alias, id, now)
                                : kms::make_delete_alias_command(acct, alias);
        case 13:
            return pick(2) == 0
                       ? kms::make_tag_key_command(id, {{"t" + std::to_string(pick(4)), "v"}})
                       : kms::make_untag_key_command(id, {"t" + std::to_string(pick(4))});
        case 14: {
            kms::grant_record g;
            g.grant_id = "g" + std::to_string(pick(3));
            g.key_id = id;
            g.grantee_principal = "arn:aws:iam::" + acct + ":role/r";
            g.issuing_account = acct;
            g.operations = {"Decrypt"};
            g.created_ms = now;
            return pick(2) == 0 ? kms::make_create_grant_command(g)
                                : kms::make_remove_grant_command(id, g.grant_id);
        }
        default:
            return kms::make_set_account_limits_command(
                acct, {static_cast<std::uint32_t>(pick(5)), static_cast<std::uint32_t>(pick(5))});
    }
}

}  // namespace

BOOST_AUTO_TEST_CASE(replicas_and_restored_snapshots_agree) {
    for (std::uint64_t seed = 1; seed <= 20; ++seed) {
        std::mt19937_64 rng(seed);
        std::uint64_t now = 0;
        replica a;
        replica b;
        std::unique_ptr<replica> restored;
        std::vector<int> statuses(6, 0);
        for (std::uint64_t i = 1; i <= 400; ++i) {
            const auto c = random_command(rng, now);
            const auto ra = a.sm.apply(c, i);
            const auto rb = b.sm.apply(c, i);
            BOOST_REQUIRE(ra == rb);
            ++statuses[static_cast<std::size_t>(kms::catalog_reply_status(ra))];
            if (restored) {
                BOOST_REQUIRE(restored->sm.apply(c, i) == ra);
            }
            if (i == 200) {
                // A new replica catches up from a checkpoint, then follows
                // the log.
                temp_dir dir;
                const auto manifest = a.sm.checkpoint(dir.path / "checkpoint");
                restored = std::make_unique<replica>();
                restored->sm.ingest(dir.path / "checkpoint", manifest, i);
                BOOST_REQUIRE(restored->dump() == a.dump());
            }
        }
        BOOST_TEST_INFO("seed " << seed);
        BOOST_TEST((a.dump() == b.dump()));
        BOOST_TEST((restored->dump() == a.dump()));
        BOOST_TEST(a.sm.applied_index() == 400U);
        // The stream exercised both success and conflict.
        BOOST_TEST(statuses[0] > 0);
        BOOST_TEST(statuses[1] + statuses[3] + statuses[5] > 0);
    }
}

BOOST_AUTO_TEST_CASE(binary_key_material_cannot_be_a_command_field) {
    // Random 32-byte keys, as an AES-256 key's material would be, in
    // every text field of a command: the encoder refuses them, and a
    // command built with them spliced in raw does not apply.
    int refused = 0;
    const int n = 2000;
    for (int i = 0; i < n; ++i) {
        std::string material(32, '\0');
        BOOST_REQUIRE(RAND_bytes(reinterpret_cast<unsigned char*>(material.data()), 32) == 1);
        if (kms::valid_utf8(material)) {
            continue;  // about one in 10^9 (needs all 32 bytes to be well-formed)
        }
        ++refused;
        BOOST_CHECK_THROW((void)kms::make_update_description_command("id", material),
                          std::invalid_argument);
        BOOST_CHECK_THROW((void)kms::make_put_policy_command("id", material),
                          std::invalid_argument);
        BOOST_CHECK_THROW((void)kms::make_tag_key_command("id", {{"k", material}}),
                          std::invalid_argument);

        // Spliced past the encoder: the reader refuses it, and nothing is
        // applied.
        auto c = kms::make_update_description_command("id", std::string(32, 'x'));
        std::copy(material.begin(), material.end(),
                  reinterpret_cast<char*>(c.data()) + (c.size() - 32));
        replica r;
        BOOST_CHECK_THROW((void)r.sm.apply(c, 1), std::invalid_argument);
        BOOST_TEST(r.sm.applied_index() == 0U);
    }
    BOOST_TEST(refused > n - 2);

    // The only integer a version carries for its backing key is the HSM's
    // object id.
    kms::key_version v{1, 0xdeadbeef, 0, kms::rotation_type::initial};
    BOOST_TEST(v.encode().size() == 1 + 4 + 8 + 8 + 1);
}

BOOST_AUTO_TEST_CASE(utf8_validation_follows_the_standard) {
    BOOST_TEST(kms::valid_utf8(""));
    BOOST_TEST(kms::valid_utf8("plain ascii"));
    BOOST_TEST(kms::valid_utf8("caf\xc3\xa9"));
    BOOST_TEST(kms::valid_utf8("\xe2\x82\xac"));       // U+20AC
    BOOST_TEST(kms::valid_utf8("\xf0\x9f\x94\x91"));   // U+1F511
    BOOST_TEST(!kms::valid_utf8("\xc0\xaf"));          // overlong '/'
    BOOST_TEST(!kms::valid_utf8("\xe0\x80\xaf"));      // overlong
    BOOST_TEST(!kms::valid_utf8("\xed\xa0\x80"));      // surrogate
    BOOST_TEST(!kms::valid_utf8("\xf4\x90\x80\x80"));  // above U+10FFFF
    BOOST_TEST(!kms::valid_utf8("\xc3"));              // truncated
    BOOST_TEST(!kms::valid_utf8("\x80"));              // lone continuation
    BOOST_TEST(!kms::valid_utf8("\xff"));
}
