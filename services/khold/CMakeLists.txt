# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The khold block service: khold_node, and later the block store, stripe
# group state machine, gateway and controller library
# (.kiro/specs/khold-block-service/, services/README.md).
#
# Entered from the top level only when KYTHIRA_BUILD_KHOLD is on
# (CONFIG_KHOLD, services/khold/Kconfig), after the core targets and tests/,
# so every core target and helper used here already exists. The core targets
# and variables this file and its subdirectories use are listed in README.md.

# The module's headers, as <kythira/khold/...>. Header-only, like the other
# modules. antikythera::proto (the antikythera-proto overlay port) carries
# hold wire versions 1 and 2, VolumeLayout and the reports; the top level
# found it before entering here.
set(KYTHIRA_KHOLD_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_KHOLD_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_khold INTERFACE)
target_include_directories(kythira_khold INTERFACE "${KYTHIRA_KHOLD_INCLUDE_DIR}")
target_link_libraries(kythira_khold INTERFACE kythira_core_headers antikythera::proto)
target_compile_features(kythira_khold INTERFACE cxx_std_23)

# khold_node (task 1 placeholder; the daemon grows from task 13 on), before
# the tests, which run it.
add_subdirectory(cmd)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
