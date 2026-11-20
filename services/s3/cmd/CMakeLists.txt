# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The S3 module's composition root (.kiro/specs/s3-compatible-storage/):
# s3_gateway_node, the daemon (task 16). Like the other module daemons it
# runs from the build tree and is in no install target.
#
# The object index includes the core persistence headers, which need a
# future backend: network_simulator carries the selected one (Folly, stdexec
# or Boost.Thread). The listeners are core's Beast host
# (raft/beast_https_server.hpp), header-only over Boost.Asio and OpenSSL.
# Without either the daemon is not built, and the tests that run it are not
# registered (../tests/CMakeLists.txt).

if(NOT KYTHIRA_FUTURE_BACKEND_AVAILABLE OR NOT Boost_FOUND)
    message(STATUS "s3_gateway_node: skipped (needs a future backend and Boost)")
    return()
endif()

find_package(Threads REQUIRED)
add_executable(s3_gateway_node s3_gateway_node/main.cpp)
target_link_libraries(s3_gateway_node PRIVATE
    kythira_s3          # <kythira/s3/...>, the core headers, OpenSSL
    network_simulator   # the future backend
    Threads::Threads
)
if(TARGET boost_json)
    target_link_libraries(s3_gateway_node PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_gateway_node PRIVATE Boost::json)
endif()
target_compile_features(s3_gateway_node PRIVATE cxx_std_23)
set_target_properties(s3_gateway_node PROPERTIES
    JOB_POOL_COMPILE heavy_tu
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# --help documents every setting the daemon reads.
add_test(NAME s3_gateway_node_help COMMAND s3_gateway_node --help)
set_tests_properties(s3_gateway_node_help PROPERTIES
    PASS_REGULAR_EXPRESSION "KYTHIRA_S3_WEBSITE_DOMAINS"
    LABELS "unit;s3;s3-module" TIMEOUT 30)
