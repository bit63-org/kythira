// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_layers_test.cpp
/// @brief S3's independent layers (.kiro/specs/s3-compatible-storage/
///        task 16): `KYTHIRA_S3_ROLES` and the layouts that serve, the
///        internal route rules, the metadata layer over the wire (remote and
///        hybrid against a local group, and the whole pipeline on remote
///        metadata), the leader-gated worker runner, the outbound SigV4
///        calls, and the daemon's settings.

#define BOOST_TEST_MODULE s3_layers_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_node_config.hpp>
#include <kythira/s3/s3_outbound.hpp>
#include <kythira/s3/s3_remote_metadata.hpp>
#include <kythira/s3/s3_roles.hpp>
#include <kythira/s3/s3_service.hpp>
#include <kythira/s3/s3_workers.hpp>

#include <raft/static_key_authorizer.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <unistd.h>

BOOST_TEST_DONT_PRINT_LOG_VALUE(kythira::layers::role_set)
BOOST_TEST_DONT_PRINT_LOG_VALUE(kythira::s3::metadata_call::kind)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::vector<kythira::chunk_sha>)

namespace {

namespace s3 = kythira::s3;
namespace sv4 = kythira::sigv4;
namespace az = kythira::aws_auth;
using kythira::chunk_read_result;
using kythira::chunk_read_status;
using kythira::chunk_sha;
using kythira::chunk_write_result;
using s3::role;
using s3::role_set;

/// Built at run time: test material, not a credential.
auto test_secret(int n) -> std::string {
    std::string out = "s";
    for (int i = 0; i < 20; ++i) {
        out.push_back(static_cast<char>('a' + ((n * 5 + i * 11) % 26)));
    }
    return out;
}

constexpr std::string_view k_owner = "111122223333";
constexpr std::string_view k_date = "20261119T120000Z";
const auto k_now = sv4::detail::parse_amz_date(k_date).value();
const sv4::credential_scope k_scope{"20261119", "us-east-1", "s3"};
constexpr std::string_view k_host = "s3.kythira.test";

// ---------------------------------------------------------------------------
// Roles and layouts
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(roles_parse_with_s3_names_and_map_to_the_shared_layers) {
    const auto r = s3::parse_s3_roles("front_end,metadata");
    BOOST_TEST(r.has(role::front_end));
    BOOST_TEST(r.has(role::data));
    BOOST_TEST(!r.has(role::gateway));
    BOOST_TEST(s3::s3_roles_string(r) == "front_end,metadata");
    BOOST_TEST(r.to_string() == "front_end,data");  // what a layer identity carries
    BOOST_TEST(s3::s3_roles_string(s3::parse_s3_roles("blobs,gateway,metadata,front_end")) ==
               "gateway,front_end,metadata,blobs");
    BOOST_TEST(s3::parse_s3_roles("gateway,front_end,metadata,blobs") == role_set::all());
}

BOOST_AUTO_TEST_CASE(bad_role_lists_are_refused_with_a_reason) {
    for (const auto* text : {"", "data", "front_end,", "gateway,gateway", "Metadata"}) {
        BOOST_CHECK_THROW((void)s3::parse_s3_roles(text), std::invalid_argument);
    }
}

BOOST_AUTO_TEST_CASE(layouts_that_cannot_serve_name_what_is_missing) {
    const auto why = [](role_set r, bool endpoints) {
        return s3::check_layout({r, endpoints}).value_or("");
    };
    BOOST_TEST(why(role_set::all(), false).empty());
    BOOST_TEST(why({role::gateway, role::front_end}, true).empty());
    BOOST_TEST(why({role::front_end}, true).empty());
    BOOST_TEST(why({role::data, role::segments}, false).empty());
    BOOST_TEST(why({role::front_end, role::data, role::segments}, false).empty());
    BOOST_TEST(why({}, false).find("at least one") != std::string::npos);
    BOOST_TEST(why({role::gateway}, true).find("task 17") != std::string::npos);
    BOOST_TEST(why({role::front_end}, false).find("KYTHIRA_S3_METADATA_ENDPOINTS") !=
               std::string::npos);
    BOOST_TEST(why({role::data}, false).find("task 18") != std::string::npos);
    BOOST_TEST(why({role::segments}, false).find("task 18") != std::string::npos);
    // A blob pool lifts the co-located rule (task 18 builds it).
    BOOST_TEST(!s3::check_layout({{role::data}, false, s3::placement_rule::rendezvous}));
}

BOOST_AUTO_TEST_CASE(internal_routes_are_open_to_the_layers_that_call_them) {
    kythira::layers::route_guard guard({"s3", "c", s3::internal_route_rules(), {}, {}});
    const auto* meta = guard.rule_for("/_kythira/s3/metadata/v1/propose");
    BOOST_REQUIRE(meta != nullptr);
    BOOST_TEST(meta->allowed.has(role::front_end));
    BOOST_TEST(meta->allowed.has(role::data));
    BOOST_TEST(!meta->allowed.has(role::gateway));
    BOOST_TEST(!meta->allowed.has(role::segments));
    const auto* chunks = guard.rule_for("/_kythira/chunks/v1/00");
    BOOST_REQUIRE(chunks != nullptr);
    BOOST_TEST(chunks->allowed == (role_set{role::front_end, role::data, role::segments}));
    BOOST_TEST(guard.rule_for("/bucket/key") == nullptr);  // the public API passes
}

// ---------------------------------------------------------------------------
// The metadata layer over the wire
// ---------------------------------------------------------------------------

auto create_bucket(const std::string& name, std::string_view owner = k_owner) -> s3::index_command {
    s3::index_command c;
    c.op = s3::index_command::kind::create_bucket;
    c.now_ms = 1000;
    c.owner = std::string(owner);
    c.bucket = name;
    c.region = "us-east-1";
    return c;
}

auto put_version(std::uint64_t bucket_id, const std::string& key, std::uint64_t now_ms)
    -> s3::index_command {
    s3::index_command c;
    c.op = s3::index_command::kind::put_object;
    c.now_ms = now_ms;
    c.owner = std::string(k_owner);
    c.target.id = bucket_id;
    c.key = key;
    c.content.etag = "\"e\"";
    c.content.content_type = "text/plain";
    c.content.storage_class = "STANDARD";
    c.written_ms = now_ms;
    return c;
}

/// A metadata server over a local group, reached through an in-process
/// transport that can be cut.
struct wire {
    s3::local_metadata local;
    s3::metadata_server<s3::local_metadata> server{local, [this] { return ready; }};
    bool up = true;
    bool ready = true;
    std::vector<std::string> calls;
    s3::remote_metadata remote{
        [this](std::string_view call,
               const std::string& body) -> std::optional<std::pair<unsigned, std::string>> {
            calls.emplace_back(call);
            if (!up) {
                return std::nullopt;
            }
            return server.handle("POST", std::string(s3::metadata_route_prefix) + std::string(call),
                                 body);
        }};
};

BOOST_AUTO_TEST_CASE(remote_metadata_answers_what_the_local_group_answers) {
    wire w;
    const auto made = w.remote.propose(create_bucket("photos"));
    BOOST_TEST(made.error.empty());
    const auto id = made.bucket_id;
    BOOST_TEST(id != 0);
    BOOST_TEST(w.remote.propose(put_version(id, "a/1.txt", 2000)).error.empty());
    BOOST_TEST(w.remote.propose(put_version(id, "a/2.txt", 3000)).error.empty());
    BOOST_TEST(w.remote.propose(put_version(id, "b.txt", 4000)).error.empty());
    // Another account's name: S3's BucketAlreadyExists, the same over the wire.
    const auto again = w.remote.propose(create_bucket("photos", "444455556666"));
    BOOST_TEST(again.status == w.local.propose(create_bucket("photos", "444455556666")).status);
    BOOST_TEST(!again.error.empty());

    BOOST_TEST(w.remote.bucket("photos")->id == w.local.bucket("photos")->id);
    BOOST_TEST(!w.remote.bucket("nothing"));
    BOOST_TEST(w.remote.list_buckets(k_owner).size() == 1);
    BOOST_TEST(w.remote.version(id, "b.txt", std::nullopt)->content.etag == "\"e\"");
    BOOST_TEST(!w.remote.version(id, "none", std::nullopt));

    const auto l = w.remote.list_objects(id, "", "/", "", 1000);
    const auto r = w.local.list_objects(id, "", "/", "", 1000);
    BOOST_TEST(l.contents.size() == r.contents.size());
    BOOST_TEST(l.common_prefixes == r.common_prefixes);
    BOOST_TEST(l.common_prefixes == std::vector<std::string>{"a/"});
    const auto page = w.remote.list_objects(id, "", "", "", 2);
    BOOST_TEST(page.truncated);
    BOOST_TEST(page.next_marker == w.local.list_objects(id, "", "", "", 2).next_marker);

    const auto v = w.remote.list_versions(id, "a/", "", "", "", 1000);
    BOOST_TEST(v.versions.size() == 2);
    BOOST_TEST(v.versions.front().is_latest);

    s3::index_command up;
    up.op = s3::index_command::kind::create_upload;
    up.now_ms = 5000;
    up.owner = std::string(k_owner);
    up.target.id = id;
    up.key = "big.bin";
    const auto made_upload = w.remote.propose(up);
    BOOST_TEST(made_upload.error.empty());
    BOOST_TEST(w.remote.upload(id, "big.bin", made_upload.upload_id).has_value());
    const auto [uploads, more] = w.remote.list_uploads(id, "", "", "", 10);
    BOOST_TEST(uploads.size() == 1);
    BOOST_TEST(!more);

    // The workers' calls.
    BOOST_TEST(w.remote.pending_deletions(10) == w.local.pending_deletions(10));
    BOOST_TEST(w.remote.pending_restores(10).empty());
    BOOST_TEST(w.remote.tier_garbage_list(10).empty());
    BOOST_TEST(w.remote.change_cursor(s3::notifications_consumer) == 0);
    BOOST_TEST(w.remote.read_changes(0, 10).empty());
    BOOST_TEST(!w.remote.refcount(chunk_sha{}));
    BOOST_TEST(w.server.served() == w.calls.size());
}

BOOST_AUTO_TEST_CASE(a_metadata_layer_that_does_not_answer_is_unavailable) {
    wire w;
    w.up = false;
    BOOST_CHECK_THROW((void)w.remote.bucket("x"), s3::metadata_unavailable);
    BOOST_CHECK_THROW((void)w.remote.propose(create_bucket("x")), s3::metadata_unavailable);
    w.up = true;
    w.ready = false;  // not the leader: 503, which is unavailable too
    BOOST_CHECK_THROW((void)w.remote.list_buckets(""), s3::metadata_unavailable);
}

BOOST_AUTO_TEST_CASE(the_metadata_server_refuses_what_it_cannot_answer) {
    wire w;
    const std::string prefix(s3::metadata_route_prefix);
    BOOST_TEST(w.server.handle("GET", prefix + "bucket", "").first == 405);
    BOOST_TEST(w.server.handle("POST", prefix + "drop_everything", "\x01").first == 404);
    BOOST_TEST(w.server.handle("POST", prefix + "bucket", "\x07garbage").first == 400);
    BOOST_TEST(w.server.handle("POST", prefix + "bucket", "\x01").first == 400);  // truncated
    BOOST_TEST(w.server.handle("POST", "/_kythira/chunks/v1/", "").first == 404);
    w.ready = false;
    BOOST_TEST(w.server.handle("POST", prefix + "list_buckets", "").first == 503);
}

BOOST_AUTO_TEST_CASE(the_endpoint_transport_fails_over_and_remembers_who_answered) {
    std::vector<std::string> tried;
    std::map<std::string, std::optional<unsigned>> answers{
        {"https://a", std::nullopt}, {"https://b", 503U}, {"https://c", 200U}};
    s3::endpoint_transport t(
        {"https://a", "https://b", "https://c"},
        [&](const std::string& url, const std::string& target,
            const std::string&) -> std::optional<std::pair<unsigned, std::string>> {
            tried.push_back(url);
            BOOST_TEST(target == std::string(s3::metadata_route_prefix) + "bucket");
            auto a = answers.at(url);
            if (!a) {
                return std::nullopt;
            }
            return std::pair<unsigned, std::string>{*a, "x"};
        });
    BOOST_TEST(t("bucket", "")->first == 200);
    BOOST_TEST(tried == (std::vector<std::string>{"https://a", "https://b", "https://c"}));
    tried.clear();
    BOOST_TEST(t("bucket", "")->first == 200);
    BOOST_TEST(tried == std::vector<std::string>{"https://c"});
    answers["https://c"] = 404U;  // an error answer is the call's, not a reason to move on
    tried.clear();
    BOOST_TEST(t("bucket", "")->first == 404);
    BOOST_TEST(tried == std::vector<std::string>{"https://c"});
    answers = {{"https://a", std::nullopt}, {"https://b", 503U}, {"https://c", std::nullopt}};
    BOOST_TEST(!t("bucket", ""));
}

BOOST_AUTO_TEST_CASE(hybrid_metadata_chooses_per_call) {
    wire far;  // the group on another node
    s3::local_metadata near;
    const auto here = near.propose(create_bucket("here")).bucket_id;
    const auto there = far.local.propose(create_bucket("there")).bucket_id;
    BOOST_TEST(here == there);  // two groups, so ids collide: the choice must use names
    std::vector<s3::metadata_call::kind> asked;
    s3::hybrid_metadata<s3::local_metadata, s3::remote_metadata> h(near, far.remote,
                                                                   [&](const s3::metadata_call& c) {
                                                                       asked.push_back(c.what);
                                                                       return c.bucket != "there";
                                                                   });
    BOOST_TEST(h.bucket("here").has_value());
    BOOST_TEST(h.bucket("there").has_value());
    BOOST_TEST(h.local_calls() == 1);
    BOOST_TEST(h.remote_calls() == 1);
    BOOST_TEST(far.calls == std::vector<std::string>{"bucket"});
    auto c = create_bucket("there", "444455556666");
    BOOST_TEST(!h.propose(c).error.empty());  // another account's name, over there
    BOOST_TEST(far.calls.back() == "propose");
    BOOST_TEST(asked.back() == s3::metadata_call::kind::write);
    (void)h.read_changes(0, 1);
    BOOST_TEST(asked.back() == s3::metadata_call::kind::worker);

    s3::hybrid_metadata<s3::local_metadata, s3::remote_metadata> all_local(near, far.remote, {});
    BOOST_TEST(!all_local.bucket("there"));
    BOOST_TEST(all_local.remote_calls() == 0);
}

// ---------------------------------------------------------------------------
// The pipeline on remote metadata
// ---------------------------------------------------------------------------

struct memory_copy {
    std::mutex mu;
    std::map<chunk_sha, std::vector<std::byte>> chunks;

    auto write(const chunk_sha& sha, std::span<const std::byte> bytes) -> chunk_write_result {
        const std::lock_guard lock(mu);
        return chunks.emplace(sha, std::vector<std::byte>(bytes.begin(), bytes.end())).second
                   ? chunk_write_result::created
                   : chunk_write_result::present;
    }
    auto read(const chunk_sha& sha) -> chunk_read_result {
        const std::lock_guard lock(mu);
        auto it = chunks.find(sha);
        if (it == chunks.end()) {
            return {chunk_read_status::missing, {}};
        }
        return {chunk_read_status::found, it->second};
    }
};

struct front_end {
    wire meta;
    memory_copy blob;
    std::vector<s3::chunk_copy> copies;
    std::vector<std::string> replicas{"m1"};
    std::unique_ptr<s3::data_path> data;
    az::static_key_authorizer auth{
        {{"AKIDLAYERS", test_secret(1), std::string(k_owner), "owner", az::static_role::admin}},
        "aws",
        [] { return std::chrono::system_clock::time_point(k_now); }};
    std::unique_ptr<s3::s3_service<s3::remote_metadata, az::static_key_authorizer>> svc;

    front_end() {
        auth.register_service(s3::s3_static_roles());
        copies.emplace_back("m1", blob);
        s3::data_path_options dp;
        dp.parallel_writes = false;
        data = std::make_unique<s3::data_path>(
            [this](const chunk_sha& sha) { return s3::place(s3::placement_map{}, sha, replicas); },
            s3::resolver_for(copies), dp);
        s3::service_options o;
        o.addressing.domains = {std::string(k_host)};
        o.clock = [] { return std::chrono::system_clock::time_point(k_now); };
        svc = std::make_unique<s3::s3_service<s3::remote_metadata, az::static_key_authorizer>>(
            meta.remote, *data, auth, std::move(o));
    }

    auto send(std::string method, std::string target, std::string body = {})
        -> std::pair<unsigned, std::string> {
        s3::header_list headers{{"Host", std::string(k_host)},
                                {"X-Amz-Date", std::string(k_date)},
                                {"x-amz-content-sha256", sv4::detail::sha256_hex(body)}};
        const std::string names = "host;x-amz-content-sha256;x-amz-date";
        const auto authz = [&](std::string_view sig) {
            return "AWS4-HMAC-SHA256 Credential=AKIDLAYERS/" + k_scope.text() +
                   ", SignedHeaders=" + names + ", Signature=" + std::string(sig);
        };
        headers.emplace_back("Authorization", authz(std::string(64, '0')));
        const auto q = target.find('?');
        const sv4::request view{
            method, std::string_view(target).substr(0, q),
            q == std::string::npos ? std::string_view{} : std::string_view(target).substr(q + 1),
            headers, std::nullopt};
        const auto parsed = sv4::parse(view, s3::s3_rules(), k_now);
        BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
        headers.back().second = authz(
            sv4::compute_signature(*parsed, sv4::derive_signing_key(test_secret(1), k_scope)));
        s3::http_request in;
        in.method = std::move(method);
        in.host = std::string(k_host);
        in.target = std::move(target);
        in.headers = std::move(headers);
        in.body = s3::memory_body(std::move(body));
        auto r = svc->serve(std::move(in));
        std::string out = r.body;
        if (r.stream) {
            (void)r.stream([&](std::span<const std::byte> b) {
                out.append(reinterpret_cast<const char*>(b.data()), b.size());  // NOLINT
                return true;
            });
        }
        return {r.status, out};
    }
};

BOOST_AUTO_TEST_CASE(the_pipeline_runs_unchanged_on_remote_metadata) {
    front_end f;
    BOOST_TEST(f.send("PUT", "/remote-bucket").first == 200);
    BOOST_TEST(f.send("PUT", "/remote-bucket/k.txt", "over the wire").first == 200);
    const auto got = f.send("GET", "/remote-bucket/k.txt");
    BOOST_TEST(got.first == 200);
    BOOST_TEST(got.second == "over the wire");
    const auto list = f.send("GET", "/remote-bucket?list-type=2");
    BOOST_TEST(list.second.find("<Key>k.txt</Key>") != std::string::npos);
    BOOST_TEST(f.meta.local.bucket("remote-bucket").has_value());  // it is the remote group's
    BOOST_TEST(!f.blob.chunks.empty());                            // and the bytes its node's
}

BOOST_AUTO_TEST_CASE(the_pipeline_answers_503_when_metadata_does_not_answer) {
    front_end f;
    BOOST_TEST(f.send("PUT", "/remote-bucket").first == 200);
    f.meta.up = false;
    const auto r = f.send("GET", "/remote-bucket/k.txt");
    BOOST_TEST(r.first == 503);
    BOOST_TEST(r.second.find("<Code>ServiceUnavailable</Code>") != std::string::npos);
    BOOST_TEST(f.send("PUT", "/remote-bucket/k.txt", "x").first == 503);
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(workers_run_only_on_metadata_nodes) {
    int runs = 0;
    const std::vector<s3::worker_job> jobs{
        {"count", std::chrono::seconds(1), [&] { return ++runs, std::string{}; }}};
    s3::worker_runner front({role::gateway, role::front_end}, {}, jobs);
    BOOST_TEST(!front.enabled());
    BOOST_TEST(front.tick(s3::worker_runner::clock::now()) == 0);
    front.start();
    BOOST_TEST(!front.running());
    s3::worker_runner meta({role::data, role::segments}, {}, jobs);
    BOOST_TEST(meta.enabled());
    BOOST_TEST(meta.tick(s3::worker_runner::clock::now()) == 1);
    BOOST_TEST(runs == 1);
}

BOOST_AUTO_TEST_CASE(workers_run_on_the_leader_on_their_schedule_and_survive_failures) {
    bool leader = false;
    int lifecycle = 0;
    int broken = 0;
    std::vector<std::string> lines;
    s3::worker_runner w(
        role_set::all(), [&] { return leader; },
        {{"lifecycle", std::chrono::seconds(10), [&] { return std::to_string(++lifecycle); }},
         {"broken", std::chrono::seconds(10),
          [&]() -> std::string {
              ++broken;
              throw std::runtime_error("destination down");
          }}},
        [&](bool, std::string_view l) { lines.emplace_back(l); });
    const auto t0 = s3::worker_runner::clock::now();
    BOOST_TEST(w.tick(t0) == 0);  // not the leader
    BOOST_TEST(w.stats("lifecycle").skipped_not_leader == 1);
    leader = true;
    BOOST_TEST(w.tick(t0 + std::chrono::seconds(1)) == 0);  // not due yet
    BOOST_TEST(w.tick(t0 + std::chrono::seconds(10)) == 2);
    BOOST_TEST(lifecycle == 1);
    BOOST_TEST(broken == 1);
    BOOST_TEST(w.stats("broken").failures == 1);
    BOOST_TEST(w.stats("broken").last_error == "destination down");
    BOOST_TEST(w.tick(t0 + std::chrono::seconds(20)) == 2);  // the failure did not stop either
    BOOST_TEST(lifecycle == 2);
    BOOST_TEST(lines.size() == 4);
    BOOST_TEST(lines.front() == "lifecycle: 1");
    BOOST_CHECK_THROW(s3::worker_runner(role_set::all(), {}, {{"", std::chrono::seconds(1), {}}}),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(the_worker_thread_starts_and_stops) {
    std::atomic<int> runs{0};
    s3::worker_runner w(role_set::all(), {}, {{"fast", std::chrono::milliseconds(5), [&] {
                                                   ++runs;
                                                   return std::string{};
                                               }}});
    w.start();
    BOOST_TEST(w.running());
    for (int i = 0; i < 400 && runs.load() < 3; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    w.stop();
    BOOST_TEST(!w.running());
    BOOST_TEST(runs.load() >= 3);
}

// ---------------------------------------------------------------------------
// Outbound calls
// ---------------------------------------------------------------------------

/// Checks a signed outbound request the way a receiving service would.
auto verifies(const s3::outbound_request& r, std::string_view service, const std::string& secret)
    -> bool {
    sv4::service_rules rules;
    rules.service = std::string(service);
    rules.s3_path_rules = service == "s3";
    rules.protocol = service == "s3" ? sv4::error_protocol::s3 : sv4::error_protocol::json;
    const std::string_view target(r.target);
    const auto q = target.find('?');
    const auto parsed = sv4::parse(
        sv4::request{r.method, target.substr(0, q),
                     q == std::string_view::npos ? std::string_view{} : target.substr(q + 1),
                     r.headers, r.body},
        rules, k_now);
    if (!parsed) {
        return false;
    }
    const auto expected = sv4::compute_signature(
        *parsed, sv4::derive_signing_key(secret, {"20261119", "us-east-1", std::string(service)}));
    return s3::find_header(r.headers, "Authorization")->ends_with("Signature=" + expected);
}

struct outbound_fixture {
    std::vector<s3::outbound_request> sent;
    s3::outbound_options options;

    outbound_fixture() {
        options.credentials = {"AKIDOUT", test_secret(2), ""};
        options.endpoints.by_service = {{"sqs", "http://sqs.local:9324"},
                                        {"kms", "https://kms.local:8443"},
                                        {"s3", "https://dest.local"}};
        options.clock = [] { return std::chrono::system_clock::time_point(k_now); };
        options.send =
            [this](
                const s3::outbound_request& r) -> std::optional<std::pair<unsigned, std::string>> {
            sent.push_back(r);
            return std::pair<unsigned, std::string>{200, "{}"};
        };
    }
};

BOOST_AUTO_TEST_CASE(event_api_calls_are_addressed_and_signed_per_service) {
    outbound_fixture f;
    auto call = s3::make_event_api_call(f.options);
    s3::event_api_request q{"sqs",
                            "us-east-1",
                            std::string(k_owner),
                            "AmazonSQS.SendMessage",
                            "application/x-amz-json-1.0",
                            R"({"QueueUrl":"q"})"};
    BOOST_TEST(call(q).status == 200);
    s3::event_api_request t{
        "sns",           "eu-west-1", std::string(k_owner), "", "application/x-www-form-urlencoded",
        "Action=Publish"};
    (void)call(t);
    BOOST_REQUIRE(f.sent.size() == 2);
    BOOST_TEST(f.sent[0].url == "http://sqs.local:9324");
    BOOST_TEST(*s3::find_header(f.sent[0].headers, "Host") == "sqs.local:9324");
    BOOST_TEST(*s3::find_header(f.sent[0].headers, "X-Amz-Target") == "AmazonSQS.SendMessage");
    BOOST_TEST(verifies(f.sent[0], "sqs", test_secret(2)));
    BOOST_TEST(f.sent[1].url == "https://sns.eu-west-1.amazonaws.com");  // AWS by default
    BOOST_TEST(!s3::find_header(f.sent[1].headers, "X-Amz-Target"));
    BOOST_TEST(s3::find_header(f.sent[1].headers, "Authorization")->find("/eu-west-1/sns/") !=
               std::string::npos);
    f.options.send = [](const s3::outbound_request&) {
        return std::optional<std::pair<unsigned, std::string>>{};
    };
    BOOST_CHECK_THROW((void)s3::make_event_api_call(f.options)(q), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(kms_calls_forward_the_principal_s3_serves) {
    outbound_fixture f;
    auto call = s3::make_kms_call(f.options);
    s3::kms_caller who;
    who.principal = az::principal_context{};
    who.principal->account = std::string(k_owner);
    who.principal->arn = "arn:aws:iam::111122223333:user/reader";
    BOOST_TEST(call("GenerateDataKey", R"({"KeyId":"k"})", who).status == 200);
    BOOST_REQUIRE(f.sent.size() == 1);
    const auto& r = f.sent[0];
    BOOST_TEST(r.url == "https://kms.local:8443");
    BOOST_TEST(*s3::find_header(r.headers, "X-Amz-Target") == "TrentService.GenerateDataKey");
    BOOST_TEST(*s3::find_header(r.headers, "x-kythira-via-service") == "s3");
    BOOST_TEST(s3::find_header(r.headers, "x-kythira-principal").has_value());
    const auto auth = s3::find_header(r.headers, "Authorization").value_or("");
    BOOST_TEST(auth.find("x-kythira-principal") != std::string::npos);  // signed
    BOOST_TEST(verifies(r, "kms", test_secret(2)));
    f.options.send = [](const s3::outbound_request&) {
        return std::optional<std::pair<unsigned, std::string>>{};
    };
    BOOST_TEST(s3::make_kms_call(f.options)("Decrypt", "{}", {}).status == 503);
}

BOOST_AUTO_TEST_CASE(replication_puts_are_path_style_with_encoded_keys) {
    outbound_fixture f;
    auto call = s3::make_replication_call(f.options, 1024);
    s3::replication_request req;
    req.method = "PUT";
    req.bucket = "dest-bucket";
    req.key = "dir/a key+é.txt";
    req.headers = {{"Content-Type", "text/plain"}, {"x-amz-replication-status", "REPLICA"}};
    req.length = 5;
    req.body = s3::memory_body("hello");
    BOOST_TEST(call(req).status == 200);
    BOOST_REQUIRE(f.sent.size() == 1);
    const auto& r = f.sent[0];
    BOOST_TEST(r.method == "PUT");
    BOOST_TEST(r.target == "/dest-bucket/dir/a%20key%2B%C3%A9.txt");
    BOOST_TEST(r.body == "hello");
    BOOST_TEST(*s3::find_header(r.headers, "X-Amz-Content-Sha256") ==
               sv4::detail::sha256_hex("hello"));
    BOOST_TEST(verifies(r, "s3", test_secret(2)));
    req.body = s3::memory_body(std::string(2048, 'x'));
    BOOST_CHECK_THROW((void)call(req), std::runtime_error);  // over the body limit
}

BOOST_AUTO_TEST_CASE(signing_needs_credentials) {
    s3::outbound_request r;
    r.url = "https://x";
    BOOST_CHECK_THROW(s3::sign_outbound(r, "sqs", "us-east-1", {}, k_now), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// The daemon's settings
// ---------------------------------------------------------------------------

auto env_of(std::map<std::string, std::string, std::less<>> vars) -> s3::env_lookup {
    return [vars = std::move(vars)](std::string_view n) -> std::optional<std::string> {
        auto it = vars.find(n);
        return it == vars.end() ? std::nullopt : std::optional<std::string>(it->second);
    };
}

struct keys_file {
    std::string path;
    keys_file() : path("s3_layers_test_keys_" + std::to_string(::getpid())) {
        std::ofstream(path) << "AKIDNODE " << test_secret(3) << " 111122223333 ci admin\n";
    }
    ~keys_file() { std::filesystem::remove(path); }
    keys_file(const keys_file&) = delete;
    auto operator=(const keys_file&) -> keys_file& = delete;
    keys_file(keys_file&&) = delete;
    auto operator=(keys_file&&) -> keys_file& = delete;
};

auto config_error(std::map<std::string, std::string, std::less<>> vars) -> std::string {
    auto r = s3::node_config_from_env(env_of(std::move(vars)));
    auto* e = std::get_if<std::string>(&r);
    return e != nullptr ? *e : std::string{};
}

BOOST_AUTO_TEST_CASE(a_co_located_node_needs_keys_and_tls_or_plaintext) {
    keys_file keys;
    auto r = s3::node_config_from_env(
        env_of({{"KYTHIRA_S3_INSECURE_PLAINTEXT", "1"},
                {"KYTHIRA_S3_STATIC_KEYS_FILE", keys.path},
                {"KYTHIRA_S3_LISTEN", "127.0.0.1:9100"},
                {"KYTHIRA_S3_WEBSITE_LISTEN", "[::1]:9101"},
                {"KYTHIRA_S3_WEBSITE_DOMAINS", "web.test, w2.test"},
                {"KYTHIRA_S3_SERVICE_ENDPOINTS", "sqs=http://q:1,kms=https://k:2"}}));
    BOOST_REQUIRE(std::holds_alternative<s3::node_config>(r));
    const auto& c = std::get<s3::node_config>(r);
    BOOST_TEST(c.roles == role_set::all());
    BOOST_TEST(c.api.port == 9100);
    BOOST_TEST(c.website->bind == "::1");
    BOOST_TEST(c.website_domains == (std::vector<std::string>{"web.test", "w2.test"}));
    BOOST_TEST(c.keys.size() == 1);
    BOOST_TEST(c.endpoints.url("sqs", "x") == "http://q:1");
    BOOST_TEST(c.endpoints.url("sns", "eu-west-1") == "https://sns.eu-west-1.amazonaws.com");

    BOOST_TEST(config_error({{"KYTHIRA_S3_STATIC_KEYS_FILE", keys.path}}).find("TLS_CERT") !=
               std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_INSECURE_PLAINTEXT", "1"}}).find("access key") !=
               std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_INSECURE_PLAINTEXT", "1"},
                             {"KYTHIRA_S3_STATIC_KEYS_FILE", keys.path},
                             {"KYTHIRA_S3_WEBSITE_LISTEN", "0.0.0.0:80"}})
                   .find("WEBSITE_DOMAINS") != std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_LISTEN", "nope"}}).find("host:port") !=
               std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_SERVICE_ENDPOINTS", "ftp=https://x"}}).find("kms|sqs") !=
               std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_OUTBOUND_ACCESS_KEY_ID", "A"}}).find("together") !=
               std::string::npos);
}

BOOST_AUTO_TEST_CASE(split_layouts_need_layer_identities_and_one_metadata_node) {
    keys_file keys;
    const std::map<std::string, std::string, std::less<>> tls{
        {"KYTHIRA_S3_INTERNAL_TLS_CERT", "c.pem"},
        {"KYTHIRA_S3_INTERNAL_TLS_KEY", "k.pem"},
        {"KYTHIRA_S3_INTERNAL_TLS_CA", "ca.pem"}};
    auto front = tls;
    front.insert({{"KYTHIRA_S3_ROLES", "gateway,front_end"},
                  {"KYTHIRA_S3_INSECURE_PLAINTEXT", "1"},
                  {"KYTHIRA_S3_STATIC_KEYS_FILE", keys.path},
                  {"KYTHIRA_S3_METADATA_ENDPOINTS", "m1=https://meta:9443"}});
    BOOST_TEST(config_error(front).empty());
    auto two = front;
    two["KYTHIRA_S3_METADATA_ENDPOINTS"] = "m1=https://a:1,m2=https://b:1";
    BOOST_TEST(config_error(two).find("name one metadata node") != std::string::npos);
    auto no_tls = front;
    no_tls.erase("KYTHIRA_S3_INTERNAL_TLS_CA");
    BOOST_TEST(config_error(no_tls).find("layer identity") != std::string::npos);

    auto meta = tls;
    meta.insert(
        {{"KYTHIRA_S3_ROLES", "metadata,blobs"}, {"KYTHIRA_S3_INTERNAL_LISTEN", "0.0.0.0:9443"}});
    BOOST_TEST(config_error(meta).empty());
    auto listener_less = meta;
    listener_less.erase("KYTHIRA_S3_INTERNAL_LISTEN");
    BOOST_TEST(config_error(listener_less).find("INTERNAL_LISTEN") != std::string::npos);
    auto hybrid = meta;
    hybrid["KYTHIRA_S3_METADATA_ENDPOINTS"] = "m2=https://b:1";
    BOOST_TEST(config_error(hybrid).find("hybrid") != std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_ROLES", "gateway"}}).find("task 17") !=
               std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_ROLES", "blobs"}}).find("task 18") != std::string::npos);
    BOOST_TEST(config_error({{"KYTHIRA_S3_NODE_ID", "a/b"}}).find("NODE_ID") != std::string::npos);
}

}  // namespace
