// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// s3_gateway_node: the Amazon S3-compatible daemon
// (.kiro/specs/s3-compatible-storage/).
//
// A placeholder until the gateway (task 6) and the write and read path
// (task 5) arrive. Today it only links the module, so the target, its build
// flags and the module boundary are exercised from task 1 on, and it
// reports what it is when asked.

#include <kythira/s3/model/operations.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: s3_gateway_node [--help | --self-test]\n"
    "\n"
    "The Kythira Amazon S3-compatible daemon. Not implemented yet: the server\n"
    "arrives with .kiro/specs/s3-compatible-storage/ tasks 3-7.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  check the generated operation table, then exit\n";

using kythira::s3::model::operation_info;

auto find_operation(std::string_view name) -> const operation_info* {
    const auto& ops = kythira::s3::model::operations;
    const auto* it =
        std::find_if(ops.begin(), ops.end(), [&](const auto& o) { return o._name == name; });
    return it == ops.end() ? nullptr : it;
}

auto fail(const char* what) -> int {
    std::fprintf(stderr, "self-test: %s\n", what);
    return 1;
}

auto self_test() -> int {
    namespace m = kythira::s3::model;
    const auto& ops = m::operations;
    if (!std::is_sorted(ops.begin(), ops.end(),
                        [](const auto& a, const auto& b) { return a._name < b._name; })) {
        return fail("operation table is not sorted");
    }
    constexpr std::array<std::string_view, 5> methods{"GET", "HEAD", "PUT", "POST", "DELETE"};
    for (const auto& op : ops) {
        if (std::find(methods.begin(), methods.end(), op._method) == methods.end()) {
            return fail("an operation has an unknown HTTP method");
        }
        if (!op._request_uri.starts_with('/')) {
            return fail("an operation's request URI does not start with '/'");
        }
    }
    // The object body streams in on PutObject and UploadPart and out on
    // GetObject; the REST-XML codec (task 3) relies on these flags.
    const auto* put = find_operation("PutObject");
    if (put == nullptr || put->_method != "PUT" || !put->_streaming_input) {
        return fail("PutObject missing, not a PUT, or not a streaming upload");
    }
    const auto* part = find_operation("UploadPart");
    if (part == nullptr || !part->_streaming_input) {
        return fail("UploadPart missing or not a streaming upload");
    }
    const auto* get = find_operation("GetObject");
    if (get == nullptr || get->_method != "GET" || !get->_streaming_output) {
        return fail("GetObject missing, not a GET, or not a streaming download");
    }
    const auto* v2 = find_operation("ListObjectsV2");
    if (v2 == nullptr || v2->_request_uri != "/{Bucket}?list-type=2") {
        return fail("ListObjectsV2 missing or not told apart by ?list-type=2");
    }
    const auto* del = find_operation("DeleteObjects");
    if (del == nullptr || !del->_checksum_required) {
        return fail("DeleteObjects missing or not marked as needing a checksum");
    }
    const auto streaming = std::count_if(ops.begin(), ops.end(), [](const auto& o) {
        return o._streaming_input || o._streaming_output;
    });
    const auto deprecated =
        std::count_if(ops.begin(), ops.end(), [](const auto& o) { return o._deprecated; });
    std::printf(
        "self-test ok: %zu operations (%td streaming, %td deprecated), %.*s, botocore %.*s\n",
        ops.size(), streaming, deprecated, static_cast<int>(m::protocol.size()), m::protocol.data(),
        static_cast<int>(m::botocore_version.size()), m::botocore_version.data());
    return 0;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (argc == 2 && arg == "--self-test") {
        return self_test();
    }
    std::fputs(usage.data(), argc == 2 && arg == "--help" ? stdout : stderr);
    return argc == 2 && arg == "--help" ? 0 : 2;
}
