// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_routing_test.cpp
/// @brief S3's routing over the REST-XML codec (`s3_routes.hpp`;
///        .kiro/specs/s3-compatible-storage/ task 3, Requirement 4.1).
///
/// The main check replays the wire evidence: every request the seven
/// recorded clients sent (`tests/evidence/data/*.json`, task 1) is routed
/// from its method, `Host`, target and headers, and must reach the
/// operation and addressing style the recording names. The rest pins the
/// cases the evidence README calls out and the ones no client exercised.

#define BOOST_TEST_MODULE s3_routing_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_routes.hpp>

#include <boost/json.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace rx = kythira::aws_rest_xml;

const rx::addressing_config addressing{{"s3.kythira.test"}};

using headers = std::vector<std::pair<std::string, std::string>>;

auto has_in(const headers& h) -> rx::router::header_fn {
    return [&h](std::string_view name) {
        for (const auto& [k, v] : h) {
            if (rx::detail::iequals(k, name)) {
                return true;
            }
        }
        return false;
    };
}

/// The operation name, or the error code.
auto route(std::string_view method, std::string_view host, std::string_view target,
           const headers& h = {}) -> std::string {
    auto r = kythira::s3::route_request(method, host, target, addressing, has_in(h));
    if (!r) {
        return "error:" + r.error().code;
    }
    // The static analyzer loses track of the value inside `result`'s
    // std::variant across route_request and reports it as uninitialized.
    // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
    return std::string(r->operation->name);
}

auto evidence_dir() -> fs::path {
    if (const char* d = std::getenv("KYTHIRA_S3_EVIDENCE_DIR")) {
        return d;
    }
    return fs::path(KYTHIRA_S3_EVIDENCE_DIR_DEFAULT);
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_recorded_request_routes_to_the_recorded_operation) {
    const auto dir = evidence_dir();
    BOOST_REQUIRE(fs::is_directory(dir));
    std::size_t files = 0;
    std::size_t requests = 0;
    std::map<std::string, std::size_t> per_operation;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() != ".json") {
            continue;
        }
        ++files;
        std::ifstream in(entry.path());
        std::stringstream ss;
        ss << in.rdbuf();
        const auto doc = boost::json::parse(ss.str()).as_object();
        const auto client = std::string(doc.at("client").as_string());
        for (const auto& rv : doc.at("requests").as_array()) {
            const auto& r = rv.as_object();
            headers h;
            std::string host;
            for (const auto& hv : r.at("headers").as_array()) {
                const auto& pair = hv.as_array();
                h.emplace_back(std::string(pair.at(0).as_string()),
                               std::string(pair.at(1).as_string()));
                if (rx::detail::iequals(h.back().first, "host")) {
                    host = h.back().second;
                }
            }
            const auto method = std::string(r.at("method").as_string());
            const auto target = std::string(r.at("target").as_string());
            const auto expected = std::string(r.at("operation").as_string());
            auto routed = kythira::s3::route_request(method, host, target, addressing, has_in(h));
            BOOST_TEST_CONTEXT(client << ": " << method << " " << host << target) {
                BOOST_TEST_REQUIRE(routed.has_value(), (routed ? "" : routed.error().code));
                // As in route() above.
                // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
                BOOST_TEST(std::string(routed->operation->name) == expected);
                const auto style = std::string(r.at("addressing").as_string());
                if (style == "service") {
                    BOOST_TEST(routed->resource.bucket.empty());
                } else {
                    BOOST_TEST((routed->resource.style == rx::addressing_style::virtual_hosted) ==
                               (style == "virtual-hosted"));
                    BOOST_TEST(routed->resource.bucket == "evidence");
                }
            }
            ++requests;
            ++per_operation[expected];
        }
    }
    BOOST_TEST(files == 7U);
    BOOST_TEST(requests > 150U);
    BOOST_TEST_MESSAGE(requests << " requests, " << per_operation.size() << " operations");
}

BOOST_AUTO_TEST_CASE(operations_on_one_path_are_told_apart) {
    const std::string h = "bk1.s3.kythira.test";
    BOOST_TEST(route("PUT", h, "/k") == "PutObject");
    BOOST_TEST(route("PUT", h, "/k?partNumber=1&uploadId=u") == "UploadPart");
    BOOST_TEST(route("PUT", h, "/k", {{"x-amz-copy-source", "/b/o"}}) == "CopyObject");
    BOOST_TEST(route("PUT", h, "/k?partNumber=1&uploadId=u", {{"X-Amz-Copy-Source", "/b/o"}}) ==
               "UploadPartCopy");
    // One of the two UploadPart parameters is not enough.
    BOOST_TEST(route("PUT", h, "/k?uploadId=u") == "PutObject");
    BOOST_TEST(route("GET", h, "/k") == "GetObject");
    BOOST_TEST(route("GET", h, "/k?uploadId=u") == "ListParts");
    BOOST_TEST(route("DELETE", h, "/k") == "DeleteObject");
    BOOST_TEST(route("DELETE", h, "/k?uploadId=u") == "AbortMultipartUpload");
    BOOST_TEST(route("POST", h, "/k?uploads") == "CreateMultipartUpload");
    BOOST_TEST(route("POST", h, "/k?uploadId=u") == "CompleteMultipartUpload");
    BOOST_TEST(route("GET", h, "/") == "ListObjects");
    BOOST_TEST(route("GET", h, "/?list-type=2") == "ListObjectsV2");
    // A list-type other than 2 is not ListObjectsV2, and not quietly
    // ListObjects either: the sub-resource is refused.
    BOOST_TEST(route("GET", h, "/?list-type=3") == "error:MethodNotAllowed");
    BOOST_TEST(route("GET", h, "/?uploads") == "ListMultipartUploads");
    BOOST_TEST(route("GET", h, "/?versions") == "ListObjectVersions");
    BOOST_TEST(route("POST", h, "/?delete") == "DeleteObjects");
    BOOST_TEST(route("GET", h, "/?analytics") == "ListBucketAnalyticsConfigurations");
    BOOST_TEST(route("GET", h, "/?analytics&id=a") == "GetBucketAnalyticsConfiguration");
    BOOST_TEST(route("GET", h, "/k?select&select-type=2") == "error:MethodNotAllowed");
    BOOST_TEST(route("POST", h, "/k?select&select-type=2") == "SelectObjectContent");
}

BOOST_AUTO_TEST_CASE(deprecated_twins_route_to_their_replacement) {
    BOOST_TEST(route("GET", "s3.kythira.test", "/bk1?lifecycle") ==
               "GetBucketLifecycleConfiguration");
    BOOST_TEST(route("PUT", "s3.kythira.test", "/bk1?lifecycle") ==
               "PutBucketLifecycleConfiguration");
    BOOST_TEST(route("GET", "s3.kythira.test", "/bk1?notification") ==
               "GetBucketNotificationConfiguration");
    BOOST_TEST(route("PUT", "s3.kythira.test", "/bk1?notification") ==
               "PutBucketNotificationConfiguration");
}

BOOST_AUTO_TEST_CASE(service_requests_and_unrouted_operations) {
    BOOST_TEST(route("GET", "s3.kythira.test", "/") == "ListBuckets");
    BOOST_TEST(route("GET", "127.0.0.1:9000", "/") == "ListBuckets");
    BOOST_TEST(route("PUT", "s3.kythira.test", "/") == "error:MethodNotAllowed");
    // WriteGetObjectResponse's path is a bucket name S3 would refuse.
    BOOST_TEST(route("POST", "s3.kythira.test", "/WriteGetObjectResponse") ==
               "error:InvalidBucketName");
}

BOOST_AUTO_TEST_CASE(sdk_query_forms_route_like_the_plain_ones) {
    const std::string h = "bk1.s3.kythira.test";
    BOOST_TEST(route("PUT", h, "/k?x-id=PutObject") == "PutObject");
    BOOST_TEST(route("POST", h, "/k?uploads=&x-id=CreateMultipartUpload") ==
               "CreateMultipartUpload");
    BOOST_TEST(route("POST", h, "/?delete=") == "DeleteObjects");
    BOOST_TEST(route("GET", h, "/?versioning=") == "GetBucketVersioning");
    // x-id does not override the route: the request's shape decides.
    BOOST_TEST(route("PUT", h, "/k?x-id=UploadPart") == "PutObject");
}

BOOST_AUTO_TEST_CASE(a_sub_resource_the_method_does_not_have_is_refused) {
    const std::string h = "bk1.s3.kythira.test";
    // Not quietly CreateBucket, PutObject or GetObject.
    BOOST_TEST(route("PUT", h, "/?uploads") == "error:MethodNotAllowed");
    BOOST_TEST(route("PUT", h, "/k?uploads") == "error:MethodNotAllowed");
    BOOST_TEST(route("GET", h, "/k?delete") == "error:MethodNotAllowed");
    // Ordinary parameters do not count as sub-resources.
    BOOST_TEST(route("GET", h, "/k?versionId=v&response-content-type=text%2Fplain") == "GetObject");
    BOOST_TEST(route("PUT", h, "/k?unknown-param=1") == "PutObject");
}

BOOST_AUTO_TEST_CASE(model_routes_compile_without_a_surprise) {
    // Every model operation but the two unrouted ones has one of the three
    // path forms (the router throws otherwise, so building it is the test),
    // and the sub-resources include the ones the evidence README names.
    const auto& subs = kythira::s3::router().sub_resources();
    for (const auto* s : {"uploads", "delete", "versioning", "tagging", "acl", "list-type"}) {
        BOOST_TEST(subs.contains(s), s);
    }
    BOOST_TEST(!subs.contains("x-id"));
    BOOST_TEST(!subs.contains("uploadId"));
}
