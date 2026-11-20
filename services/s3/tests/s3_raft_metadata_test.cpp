// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The object index on Raft (.kiro/specs/s3-compatible-storage/ task 16a):
// three metadata nodes on the in-process message fabric, each with its own
// engine, Raft logs on disk and change log store, voting in one index
// group. Any member takes any call: a follower forwards entries and read
// barriers to the leader, so every member reads every acknowledged write.
// A leader lost in the middle of a stream of PUTs loses no acknowledged
// write and leaves every reference count equal to a recount; the workers
// run on the leader only and follow it; change log cursors move with
// leadership; a member cut off throws metadata_unavailable (503 on the
// metadata route); restarted members keep their replicas; and a member
// brought back by a snapshot fetches the change log segment it names.

#define BOOST_TEST_MODULE s3_raft_metadata_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"

#include <kythira/s3/s3_index_state_machine.hpp>
#include <kythira/s3/s3_raft_metadata.hpp>
#include <kythira/s3/s3_remote_metadata.hpp>
#include <kythira/s3/s3_workers.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/memory_kv_engine.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/record_segment_store.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <unistd.h>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("s3_raft_metadata_test"), nullptr};
        char** argv = argv_data;
        init_ = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> init_;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

namespace fs = std::filesystem;
using namespace kythira::s3;
using kythira::chunk_sha;
using kythira::memory_kv_engine;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;
using kind = index_command::kind;

using index_sm = s3_index_state_machine<memory_kv_engine>;

struct host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = std::uint64_t;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using network_client_type = fabric_client;
    using network_server_type = fabric_server;

    using persistence_engine_type =
        kythira::binary_file_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = index_sm;

    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type, group_id_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type, group_id_type>;
    using append_entries_request_type =
        kythira::append_entries_request<node_id_type, term_id_type, log_index_type, log_entry_type,
                                        group_id_type>;
    using append_entries_response_type =
        kythira::append_entries_response<term_id_type, log_index_type, group_id_type>;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type,
                                          group_id_type>;
    using install_snapshot_response_type =
        kythira::install_snapshot_response<term_id_type, group_id_type>;
};

using raft_host = kythira::multi_raft<host_types, std::string, std::uint64_t>;
using raft_config = kythira::multi_raft_config<host_types, std::string, std::uint64_t>;
using metadata = raft_metadata<raft_host>;

static_assert(metadata_access<metadata>);
static_assert(change_log_access<metadata>);

constexpr std::uint64_t k_members = 3;
constexpr std::uint64_t k_group = 8;  // S3's module number, as a stand-alone node uses

auto sha_of(const std::string& s) -> chunk_sha {
    return kythira::sha256_of(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size()));
}

auto content_of(const std::string& tag) -> object_content {
    object_content c;
    c.manifest.push_back({sha_of(tag + "/0"), 100});
    c.manifest.push_back({sha_of("shared"), 100});
    c.etag = "e-" + tag;
    c.content_type = "text/plain";
    return c;
}

auto await(const std::function<bool()>& predicate,
           std::chrono::milliseconds budget = std::chrono::seconds{20}) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        try {
            if (predicate()) {
                return true;
            }
        } catch (const metadata_unavailable&) {
            // no leader yet: keep waiting
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    return predicate();
}

/// A temporary directory, removed with everything in it.
struct temp_dir {
    fs::path path;
    temp_dir() {
        static std::atomic<int> n{0};
        path = fs::temp_directory_path() /
               ("s3_raft_metadata_test-" + std::to_string(::getpid()) + "-" + std::to_string(++n));
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

/// One metadata node. The engine, the Raft logs and the change log store
/// outlive the host, so a restart finds what the node had.
struct member {
    std::uint64_t id = 0;
    fs::path dir;
    std::shared_ptr<memory_kv_engine> engine = std::make_shared<memory_kv_engine>();
    std::unique_ptr<kythira::record_segment_store> changes;
    std::unique_ptr<raft_host> raft;
    std::unique_ptr<metadata> meta;
    std::atomic<bool> driving{false};
    std::thread driver;
};

class cluster {
public:
    explicit cluster(std::uint64_t snapshot_threshold_bytes = 0)
        : _snapshot_threshold(snapshot_threshold_bytes) {
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            auto m = std::make_unique<member>();
            m->id = id;
            m->dir = _dir.path / ("node-" + std::to_string(id));
            fs::create_directories(m->dir / "raft");
            m->changes = std::make_unique<kythira::record_segment_store>(
                kythira::record_segment_store_options{._data_dir = m->dir / "changes",
                                                      ._max_segment_bytes = 4096});
            _members.push_back(std::move(m));
        }
        for (auto& m : _members) {
            open(*m);
        }
    }

    ~cluster() {
        for (auto& m : _members) {
            close(*m);
        }
        _fabric.shutdown();
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;
    cluster(cluster&&) = delete;
    auto operator=(cluster&&) -> cluster& = delete;

    [[nodiscard]] auto at(std::uint64_t id) -> member& { return *_members.at(id - 1); }
    [[nodiscard]] auto meta(std::uint64_t id) -> metadata& { return *at(id).meta; }

    /// The member leading the group, other than `except`.
    [[nodiscard]] auto leader(std::uint64_t except = 0) -> std::optional<std::uint64_t> {
        for (auto& m : _members) {
            if (m->id != except && m->meta && m->meta->leads()) {
                return m->id;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto await_leader(std::uint64_t except = 0) -> std::uint64_t {
        std::optional<std::uint64_t> l;
        BOOST_REQUIRE(await([&] { return (l = leader(except)).has_value(); }));
        return *l;
    }

    /// A member that does not lead, other than `except`.
    [[nodiscard]] auto follower(std::uint64_t except = 0) -> std::uint64_t {
        const auto l = await_leader();
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            if (id != l && id != except) {
                return id;
            }
        }
        BOOST_FAIL("no follower");
        return 0;
    }

    /// Cuts `id` off from the others, both ways, forwarding too.
    void isolate(std::uint64_t id) {
        const std::lock_guard lock(_cut_mutex);
        for (std::uint64_t other = 1; other <= k_members; ++other) {
            if (other != id) {
                _fabric.partition(id, other);
                _fabric.partition(other, id);
                _cut.insert({id, other});
                _cut.insert({other, id});
            }
        }
    }

    void heal() {
        const std::lock_guard lock(_cut_mutex);
        _fabric.heal_all();
        _cut.clear();
    }

    /// Stops member `id`'s host and opens a new one on the same engine,
    /// logs and change log store.
    void restart(std::uint64_t id) {
        close(at(id));
        open(at(id));
    }

    /// Stops every host, then opens them all again.
    void restart_all() {
        for (auto& m : _members) {
            close(*m);
        }
        for (auto& m : _members) {
            open(*m);
        }
    }

private:
    void reach(std::uint64_t from, std::uint64_t to) {
        const std::lock_guard lock(_cut_mutex);
        if (_cut.contains({from, to})) {
            throw std::runtime_error("partitioned");
        }
        if (!at(to).meta) {
            throw std::runtime_error("stopped");
        }
    }

    auto forwarder(std::uint64_t self) -> metadata::forwarder {
        metadata::forwarder f;
        f.propose = [this, self](const std::uint64_t& to, const std::vector<std::byte>& cmd) {
            reach(self, to);
            return meta(to).serve_propose(cmd);
        };
        f.read_index = [this, self](const std::uint64_t& to) {
            reach(self, to);
            return meta(to).serve_read_index();
        };
        f.segment = [this, self](const std::uint64_t& to, const std::string& stream,
                                 std::uint64_t first, std::uint64_t length) {
            reach(self, to);
            return meta(to).serve_segment(stream, first, length);
        };
        return f;
    }

    void open(member& m) {
        std::vector<std::uint64_t> ids;
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            ids.push_back(id);
        }
        auto fwd = forwarder(m.id);
        raft_config cfg{
            .node_id = m.id,
            .network_client = fabric_client{_fabric, m.id},
            .network_server = fabric_server{_fabric, m.id},
            .store_factory =
                [dir = m.dir / "raft"](const std::uint64_t& g) {
                    return host_types::persistence_engine_type{dir / std::to_string(g)};
                },
        };
        cfg.config._election_timeout_min = std::chrono::milliseconds{150};
        cfg.config._election_timeout_max = std::chrono::milliseconds{300};
        cfg.config._heartbeat_interval = std::chrono::milliseconds{30};
        cfg.config._snapshot_disk_margin_bytes = 0;
        cfg.config._snapshot_staging_directory = m.dir / "snapshots";
        if (_snapshot_threshold != 0) {
            cfg.config._snapshot_threshold_bytes = _snapshot_threshold;
        }
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.logger = kythira::console_logger(kythira::log_level::error);
        cfg.logger_factory = [](const std::uint64_t&) {
            return kythira::console_logger(kythira::log_level::error);
        };
        cfg.state_engine = m.engine;
        cfg.state_machine_factory = [store = m.changes.get(),
                                     fetch = make_change_log_fetcher<std::uint64_t>(
                                         m.changes.get(), ids, m.id, fwd)](const std::uint64_t&) {
            return metadata::make_state_machine<memory_kv_engine>(
                index_options{.min_part_bytes = 0, .max_parts = 10'000}, store, fetch);
        };
        cfg.automatic_split_merge_enabled = false;
        cfg.executor_stripes = 2;
        m.raft = std::make_unique<raft_host>(std::move(cfg));
        metadata::options o;
        o.members = ids;
        o.group = k_group;
        o.timeout = std::chrono::milliseconds{3000};
        o.forward = std::move(fwd);
        o.change_log = m.changes.get();
        auto meta = std::make_unique<metadata>(*m.raft, std::move(o));
        meta->bootstrap();
        m.raft->start();
        m.driving = true;
        m.driver = std::thread([raft = m.raft.get(), &m] {
            while (m.driving.load()) {
                raft->tick();
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
            }
        });
        m.meta = std::move(meta);
    }

    void close(member& m) {
        if (!m.raft) {
            return;
        }
        auto meta = std::move(m.meta);  // forwarders to it now fail
        m.driving = false;
        if (m.driver.joinable()) {
            m.driver.join();
        }
        m.raft->stop();
        meta.reset();
        m.raft.reset();
    }

    temp_dir _dir;
    std::uint64_t _snapshot_threshold;
    message_fabric _fabric;
    std::vector<std::unique_ptr<member>> _members;
    std::mutex _cut_mutex;
    std::set<std::pair<std::uint64_t, std::uint64_t>> _cut;
};

// ---- index entries --------------------------------------------------------

std::atomic<std::uint64_t> g_now{1'000'000};

auto create_bucket(metadata& m, const std::string& name) -> index_result {
    index_command c;
    c.op = kind::create_bucket;
    c.bucket = name;
    c.owner = "111122223333";
    c.region = "us-east-1";
    c.now_ms = ++g_now;
    return m.propose(c);
}

auto ref(metadata& m, const std::string& name, bool logged = false) -> bucket_ref {
    const auto b = m.bucket(name).value();
    bucket_ref r{b.id, b.versioning, b.object_lock};
    r.log_changes = logged;
    return r;
}

auto put(metadata& m, const bucket_ref& b, const std::string& key) -> index_result {
    index_command c;
    c.op = kind::put_object;
    c.target = b;
    c.key = key;
    c.owner = "111122223333";
    c.content = content_of(key);
    c.now_ms = ++g_now;
    return m.propose(c);
}

/// Every chunk's count, recounted from the versions and parts naming it.
auto recount(const index_sm& sm) -> std::map<chunk_sha, std::uint64_t> {
    std::map<chunk_sha, std::uint64_t> out;
    for (const auto& b : sm.list_buckets()) {
        for (const auto& e : sm.list_versions(b.id, "", "", "", "", 100'000).versions) {
            for (const auto& c : e.version.content.manifest) {
                ++out[c.sha];
            }
        }
        for (const auto& u : sm.list_uploads(b.id, "", "", "", 100'000).first) {
            for (const auto& [n, p] : u.parts) {
                for (const auto& c : p.manifest) {
                    ++out[c.sha];
                }
            }
        }
    }
    return out;
}

void check_refcounts(metadata& m) {
    const auto ok = m.inspect([](const index_sm& sm) {
        const auto expected = recount(sm);
        const auto stored = sm.all_refcounts();
        for (const auto& [sha, n] : expected) {
            const auto it = stored.find(sha);
            if (it == stored.end() || it->second.count != n) {
                return false;
            }
        }
        for (const auto& [sha, rec] : stored) {
            if (rec.count != 0 && !expected.contains(sha)) {
                return false;
            }
        }
        return true;
    });
    BOOST_TEST_REQUIRE(ok.has_value());
    BOOST_TEST(*ok);
}

auto applied(metadata& m) -> std::uint64_t {
    return m.inspect([](const index_sm& sm) { return sm.applied_index(); }).value_or(0);
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_member_reads_every_acknowledged_write) {
    cluster c;
    const auto f = c.follower();
    BOOST_REQUIRE(create_bucket(c.meta(f), "photos").ok());
    for (std::uint64_t writer = 1; writer <= k_members; ++writer) {
        const auto b = ref(c.meta(writer), "photos");
        const auto key = "from-" + std::to_string(writer);
        const auto res = put(c.meta(writer), b, key);
        BOOST_REQUIRE(res.ok());
        // Read at once on every member: the barrier makes each see it.
        for (std::uint64_t reader = 1; reader <= k_members; ++reader) {
            const auto v = c.meta(reader).version(b.id, key, std::nullopt);
            BOOST_TEST_REQUIRE(v.has_value());
            BOOST_TEST(v->content.etag == "e-" + key);
        }
    }
    const auto listing =
        c.meta(c.follower()).list_objects(ref(c.meta(1), "photos").id, "", "", "", 1000);
    BOOST_TEST(listing.contents.size() == k_members);
    std::uint64_t forwarded = 0;
    std::uint64_t barriers = 0;
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        forwarded += c.meta(id).stats().proposals_forwarded;
        barriers += c.meta(id).stats().read_indexes_forwarded;
    }
    BOOST_TEST(forwarded > 0U);
    BOOST_TEST(barriers > 0U);
    BOOST_TEST(c.meta(c.await_leader()).stats().proposals_served > 0U);
}

BOOST_AUTO_TEST_CASE(multipart_and_listings_through_followers) {
    cluster c;
    const auto l = c.await_leader();
    const auto f1 = c.follower();
    const auto f2 = c.follower(f1);
    BOOST_REQUIRE(create_bucket(c.meta(f1), "uploads").ok());
    const auto b = ref(c.meta(f2), "uploads");

    index_command create;
    create.op = kind::create_upload;
    create.target = b;
    create.key = "big";
    create.owner = "111122223333";
    create.content = content_of("big");
    create.content.manifest.clear();
    create.now_ms = ++g_now;
    const auto id = c.meta(f1).propose(create).upload_id;
    BOOST_REQUIRE(!id.empty());
    for (std::uint32_t n = 1; n <= 2; ++n) {
        index_command p;
        p.op = kind::upload_part;
        p.target = b;
        p.key = "big";
        p.upload_id = id;
        p.part.number = n;
        p.part.etag = std::string(32, static_cast<char>('a' + n));
        p.part.manifest = content_of("part-" + std::to_string(n)).manifest;
        p.now_ms = ++g_now;
        BOOST_REQUIRE((n == 1 ? c.meta(f2) : c.meta(l)).propose(p).ok());
    }
    const auto uploads = c.meta(f1).list_uploads(b.id, "", "", "", 100);
    BOOST_TEST_REQUIRE(uploads.first.size() == 1U);
    BOOST_TEST(uploads.first.front().parts.size() == 2U);

    index_command done;
    done.op = kind::complete_upload;
    done.target = b;
    done.key = "big";
    done.upload_id = id;
    done.parts = {{1, std::string(32, 'b')}, {2, std::string(32, 'c')}};
    done.now_ms = ++g_now;
    const auto res = c.meta(f2).propose(done);
    BOOST_REQUIRE_MESSAGE(res.ok(), res.error + ": " + res.message);
    for (std::uint64_t id2 = 1; id2 <= k_members; ++id2) {
        BOOST_TEST(c.meta(id2).list_uploads(b.id, "", "", "", 100).first.empty());
        const auto v = c.meta(id2).version(b.id, "big", std::nullopt);
        BOOST_TEST_REQUIRE(v.has_value());
        BOOST_TEST(v->content.manifest.size() == 4U);
        check_refcounts(c.meta(id2));
    }
}

BOOST_AUTO_TEST_CASE(a_leader_lost_during_puts_loses_no_acknowledged_write) {
    cluster c;
    const auto old = c.await_leader();
    const auto writer = c.follower();
    BOOST_REQUIRE(create_bucket(c.meta(writer), "stream").ok());
    const auto b = ref(c.meta(writer), "stream");

    std::vector<std::string> acknowledged;
    std::atomic<bool> stop{false};
    std::atomic<int> refused{0};
    std::thread puts([&] {
        for (int i = 0; !stop.load(); ++i) {
            const auto key = "k" + std::to_string(i);
            try {
                if (put(c.meta(writer), b, key).ok()) {
                    acknowledged.push_back(key);
                }
            } catch (const metadata_unavailable&) {
                ++refused;  // may or may not have committed: not acknowledged
            }
        }
    });
    BOOST_REQUIRE(await([&] { return applied(c.meta(writer)) > 20; }));
    c.isolate(old);
    const auto fresh = c.await_leader(old);
    BOOST_TEST(fresh != old);
    const auto before = applied(c.meta(fresh));
    BOOST_REQUIRE(await([&] { return applied(c.meta(fresh)) > before + 20; }));
    stop = true;
    puts.join();
    c.heal();
    BOOST_TEST(acknowledged.size() > 40U);

    for (std::uint64_t id = 1; id <= k_members; ++id) {
        BOOST_TEST_CONTEXT("member " << id) {
            auto& m = c.meta(id);
            BOOST_REQUIRE(await([&] {
                return m.list_objects(b.id, "", "", "", 100'000).contents.size() >=
                       acknowledged.size();
            }));
            for (const auto& key : acknowledged) {
                BOOST_TEST(m.version(b.id, key, std::nullopt).has_value());
            }
            check_refcounts(m);
        }
    }
    // Every replica agrees on the whole index.
    const auto dump = [&](std::uint64_t id) {
        return c.meta(id).inspect([](const index_sm& sm) { return sm.dump(); }).value();
    };
    BOOST_REQUIRE(await([&] {
        return applied(c.meta(1)) == applied(c.meta(2)) && applied(c.meta(2)) == applied(c.meta(3));
    }));
    BOOST_TEST((dump(1) == dump(2)));
    BOOST_TEST((dump(2) == dump(3)));
}

BOOST_AUTO_TEST_CASE(a_member_cut_off_answers_unavailable_never_a_stale_read) {
    cluster c;
    const auto f = c.follower();
    BOOST_REQUIRE(create_bucket(c.meta(f), "b").ok());
    const auto b = ref(c.meta(f), "b");
    BOOST_REQUIRE(put(c.meta(f), b, "before").ok());
    c.isolate(f);
    const auto other = c.follower(f) == f ? c.await_leader() : c.await_leader(f);
    BOOST_REQUIRE(put(c.meta(other), b, "while-cut").ok());
    BOOST_CHECK_THROW((void)c.meta(f).version(b.id, "while-cut", std::nullopt),
                      metadata_unavailable);
    BOOST_CHECK_THROW((void)put(c.meta(f), b, "refused"), metadata_unavailable);
    BOOST_TEST(c.meta(f).stats().unavailable >= 2U);

    // On the metadata route that is a 503, so a front end tries another node.
    metadata_server server(c.meta(f));
    auto w = metadata_wire::begin();
    w.str("b");
    const auto [status, body] =
        server.handle("POST", std::string(metadata_route_prefix) + "bucket", w.take());
    BOOST_TEST(status == 503U);

    c.heal();
    BOOST_TEST(
        await([&] { return c.meta(f).version(b.id, "while-cut", std::nullopt).has_value(); }));
}

BOOST_AUTO_TEST_CASE(workers_run_on_the_leader_only_and_follow_it) {
    cluster c;
    std::map<std::uint64_t, std::unique_ptr<worker_runner>> runners;
    std::map<std::uint64_t, int> passes;
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        runners[id] = std::make_unique<worker_runner>(
            role_set{role::data}, [&c, id] { return c.meta(id).leads(); },
            std::vector<worker_job>{{"sweep", std::chrono::milliseconds{1}, [&passes, id] {
                                         ++passes[id];
                                         return std::string();
                                     }}});
    }
    const auto old = c.await_leader();
    const auto start = worker_runner::clock::now();
    int ticks = 0;
    auto tick_all = [&](std::uint64_t except) {
        const auto now = start + std::chrono::seconds(++ticks);
        for (auto& [id, r] : runners) {
            if (id != except) {
                (void)r->tick(now);
            }
        }
    };
    tick_all(0);
    BOOST_TEST(passes[old] == 1);
    BOOST_TEST(passes.size() == 1U);

    c.isolate(old);
    const auto fresh = c.await_leader(old);
    passes.clear();
    tick_all(old);
    BOOST_TEST(passes[fresh] == 1);
    BOOST_TEST(passes.size() == 1U);
    BOOST_TEST(runners.at(6 - old - fresh)->stats("sweep").skipped_not_leader >= 2U);
    c.heal();
    // The old leader steps down once it hears the new term.
    BOOST_REQUIRE(await([&] { return !c.meta(old).leads(); }));
}

BOOST_AUTO_TEST_CASE(change_log_cursors_move_with_leadership) {
    cluster c;
    const auto old = c.await_leader();
    BOOST_REQUIRE(create_bucket(c.meta(old), "logged").ok());
    const auto b = ref(c.meta(old), "logged", true);
    for (int i = 0; i < 6; ++i) {
        BOOST_REQUIRE(put(c.meta(old), b, "o" + std::to_string(i)).ok());
    }
    const auto first = c.meta(old).read_changes(0, 100);
    BOOST_TEST_REQUIRE(first.size() == 6U);
    index_command adv;
    adv.op = kind::advance_change_log;
    adv.config_name = "notifications";
    adv.change_seq = first.at(3).seq;
    adv.now_ms = ++g_now;
    BOOST_REQUIRE(c.meta(old).propose(adv).ok());

    c.isolate(old);
    const auto fresh = c.await_leader(old);
    auto& m = c.meta(fresh);
    const auto cursor = m.change_cursor("notifications");
    BOOST_TEST(cursor == first.at(3).seq);
    const auto rest = m.read_changes(cursor, 100);
    BOOST_TEST_REQUIRE(rest.size() == 2U);
    BOOST_TEST(rest.front().seq == first.at(4).seq);
    BOOST_TEST(rest.front().record.key == "o4");
    c.heal();
}

BOOST_AUTO_TEST_CASE(restarted_members_keep_their_replicas) {
    cluster c;
    const auto f = c.follower();
    BOOST_REQUIRE(create_bucket(c.meta(f), "durable").ok());
    const auto b = ref(c.meta(f), "durable", true);
    for (int i = 0; i < 10; ++i) {
        BOOST_REQUIRE(put(c.meta(f), b, "d" + std::to_string(i)).ok());
    }
    index_command adv;
    adv.op = kind::advance_change_log;
    adv.config_name = "replication";
    adv.change_seq = 5;
    adv.now_ms = ++g_now;
    BOOST_REQUIRE(c.meta(f).propose(adv).ok());
    const auto before = applied(c.meta(f));

    c.restart(f);
    // The replica reopened from its engine at the index it had applied.
    BOOST_TEST(applied(c.meta(f)) >= before);
    BOOST_TEST(c.meta(f).version(b.id, "d9", std::nullopt).has_value());

    c.restart_all();
    c.await_leader();
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        auto& m = c.meta(id);
        BOOST_TEST(m.list_objects(b.id, "", "", "", 1000).contents.size() == 10U);
        BOOST_TEST(m.change_cursor("replication") == 5U);
        BOOST_TEST(m.read_changes(5, 100).size() == 5U);
    }
    // And it keeps taking writes.
    BOOST_TEST(put(c.meta(c.follower()), b, "after").ok());
}

BOOST_AUTO_TEST_CASE(a_member_restored_from_a_snapshot_fetches_its_change_log) {
    cluster c(/*snapshot_threshold_bytes=*/4096);
    const auto l = c.await_leader();
    BOOST_REQUIRE(create_bucket(c.meta(l), "snap").ok());
    const auto b = ref(c.meta(l), "snap", true);
    const auto lagging = c.follower();
    c.isolate(lagging);
    const auto writer = c.await_leader(lagging);
    for (int i = 0; i < 200; ++i) {
        BOOST_REQUIRE(put(c.meta(writer), b, "s" + std::to_string(i)).ok());
    }
    c.heal();
    BOOST_REQUIRE(await([&] { return applied(c.meta(lagging)) >= applied(c.meta(writer)); },
                        std::chrono::seconds{30}));
    auto& m = c.meta(lagging);
    BOOST_TEST(m.list_objects(b.id, "", "", "", 1000).contents.size() == 200U);
    check_refcounts(m);
    // Records from the active segment the snapshot named, fetched from a
    // peer, read back on the restored member.
    const auto tail = m.read_changes(195, 100);
    BOOST_TEST(tail.size() == 5U);
    std::uint64_t served = 0;
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        served += c.meta(id).stats().segments_served;
    }
    BOOST_TEST(served > 0U);
}
