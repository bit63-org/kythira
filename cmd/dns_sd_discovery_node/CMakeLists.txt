# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# No folly_FOUND: main() initialises Folly through raft/process_init.hpp only
# where it is linked; the parent CMakeLists.txt requires a future backend.
if(NOT LIBLDNS_FOUND OR NOT httplib_FOUND)
    message(STATUS "dns_sd_discovery_node: skipped (requires libldns + httplib)")
    return()
endif()

add_executable(dns_sd_discovery_node main.cpp)
target_include_directories(dns_sd_discovery_node PRIVATE "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/cmd/discovery_node_common")
target_link_libraries(dns_sd_discovery_node PRIVATE network_simulator httplib::httplib)
target_compile_features(dns_sd_discovery_node PRIVATE cxx_std_23)
set_target_properties(dns_sd_discovery_node PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
message(STATUS "dns_sd_discovery_node target: enabled")
