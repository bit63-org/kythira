# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Redis gateway module: the RESP front end, the build cache it serves,
# redis_gateway_node and their tests (.kiro/specs/redis-gateway-module/).
#
# Entered from the top level only when KYTHIRA_BUILD_REDIS_GATEWAY is on
# (CONFIG_REDIS_GATEWAY, services/redis/Kconfig), after the core targets,
# tests/ and tests/docker_chaos/, so every core target and helper used here
# already exists. The core targets and variables this file and its
# subdirectories use are listed in README.md.

# The module's headers, as <kythira/redis/...>.
set(KYTHIRA_REDIS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_redis INTERFACE)
target_include_directories(kythira_redis INTERFACE "${KYTHIRA_REDIS_INCLUDE_DIR}")
# kythira_build_version: kythira_version in HELLO and INFO
# (kythira/redis/redis_server_identity.hpp).
target_link_libraries(kythira_redis INTERFACE kythira_core_headers kythira_build_version
                      OpenSSL::SSL OpenSSL::Crypto)

# The Lua script sandbox (.kiro/specs/redis-general-data-types/ task 25):
# kythira/redis/lua_sandbox.hpp over the lua51 overlay port
# (vcpkg-overlays/lua51/, a default dependency in vcpkg.json). A build
# without vcpkg has no lua51 and simply leaves the sandbox and its tests
# out; KYTHIRA_REDIS_LUA_SANDBOX records which, and the CI jobs that must
# have it assert it with scripts/check-build-config.py.
find_package(lua51 5.1.5 CONFIG QUIET)
if(lua51_FOUND)
    add_library(kythira_redis_lua INTERFACE)
    target_link_libraries(kythira_redis_lua INTERFACE kythira_redis lua51::lua51 OpenSSL::Crypto)
    set(KYTHIRA_REDIS_LUA_SANDBOX ON CACHE INTERNAL "lua51 found: the Redis Lua sandbox is built")
    message(STATUS "Redis module: Lua sandbox enabled (lua51 ${lua51_VERSION})")
else()
    set(KYTHIRA_REDIS_LUA_SANDBOX OFF CACHE INTERNAL "lua51 found: the Redis Lua sandbox is built")
    message(STATUS "Redis module: lua51 not found, Lua sandbox and its tests left out")
endif()

# The images' Dockerfiles, compose files and staging directories. Images
# build from KYTHIRA_IMAGE_CONTEXT (cmake/kythira_test_helpers.cmake), so
# their COPY lines name these paths from the source root.
set(KYTHIRA_REDIS_DOCKER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/docker")

# The daemon: not a coverage build, and a future backend (the subdirectory
# checks Boost and OpenSSL itself). Folly is not needed: main() initialises
# it through raft/process_init.hpp only where it is linked.
if(NOT ENABLE_COVERAGE AND KYTHIRA_FUTURE_BACKEND_AVAILABLE)
    add_subdirectory(cmd/redis_gateway_node)
endif()

# The tests, under the guard the top level enters tests/ with. tests/ defines
# kythira_test_pch, which add_raft_completion_test links, so its presence is
# the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
