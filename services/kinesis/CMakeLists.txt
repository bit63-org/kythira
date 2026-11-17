# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Kinesis Data Streams-compatible module: the operation table from the
# pinned botocore model, kinesis_gateway_node, and later the front end,
# stream state machine and lease API
# (.kiro/specs/kinesis-compatible-streams/, services/README.md).
#
# Entered from the top level only when KYTHIRA_BUILD_KINESIS is on
# (CONFIG_KINESIS, services/kinesis/Kconfig), after the core targets and
# tests/, so every core target and helper used here already exists. The core
# targets and variables this file and its subdirectories use are listed in
# README.md.

# The module's headers, as <kythira/kinesis/...>. Header-only, like the other
# modules. OpenSSL for SigV4, segment digests and iterator tokens, and its
# TLS half for the peer client (KYTHIRA_BUILD_KINESIS requires it).
set(KYTHIRA_KINESIS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_KINESIS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_kinesis INTERFACE)
target_include_directories(kythira_kinesis INTERFACE "${KYTHIRA_KINESIS_INCLUDE_DIR}")
# dlopen: KINESIS_KMS=pkcs11 loads a PKCS#11 library (raft/pkcs11_module.hpp).
target_link_libraries(kythira_kinesis INTERFACE kythira_core_headers boost_json OpenSSL::SSL OpenSSL::Crypto
    ${CMAKE_DL_LIBS})
target_compile_features(kythira_kinesis INTERFACE cxx_std_23)
# HTTP/2 for SubscribeToShard (task 13), where nghttp2 is available.
if(TARGET kythira_nghttp2)
    target_link_libraries(kythira_kinesis INTERFACE kythira_nghttp2)
endif()

# Channel delivery (task 19, kinesis_channel_delivery.hpp): GZIP objects
# through zlib and ZSTD objects through libzstd, both optional. vcpkg builds
# have both (gRPC, Folly and proxygen pull them in); a node without one
# sets a channel asking for it to FAILED with the reason.
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
    target_link_libraries(kythira_kinesis INTERFACE ZLIB::ZLIB)
    target_compile_definitions(kythira_kinesis INTERFACE KYTHIRA_KINESIS_HAS_ZLIB)
endif()
find_package(zstd CONFIG QUIET)
if(TARGET zstd::libzstd_shared)
    set(_KYTHIRA_KINESIS_ZSTD zstd::libzstd_shared)
elseif(TARGET zstd::libzstd_static)
    set(_KYTHIRA_KINESIS_ZSTD zstd::libzstd_static)
elseif(TARGET zstd::libzstd)
    set(_KYTHIRA_KINESIS_ZSTD zstd::libzstd)
endif()
if(_KYTHIRA_KINESIS_ZSTD)
    target_link_libraries(kythira_kinesis INTERFACE ${_KYTHIRA_KINESIS_ZSTD})
    target_compile_definitions(kythira_kinesis INTERFACE KYTHIRA_KINESIS_HAS_ZSTD)
endif()
message(STATUS "kythira_kinesis: channel gzip ${ZLIB_FOUND}, zstd ${_KYTHIRA_KINESIS_ZSTD}")

# kinesis_gateway_node (task 1 placeholder; the daemon is task 6), before
# the tests, which run it.
add_subdirectory(cmd)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
