# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Overlay port for antikythera's header-only wire formats
# (.kiro/specs/khold-block-service/ Requirement 1.4, and the overlay port
# .kiro/specs/ec2-compatible-api/ task 1 describes). See README.md.
#
# vcpkg_from_git rather than vcpkg_from_github: the commit id pins the
# content, so there is no archive hash to keep in step with GitHub's
# tarball generation (the same choice as the lua51 port).
vcpkg_from_git(
    OUT_SOURCE_PATH SOURCE_PATH
    URL https://github.com/bit63-org/antikythera.git
    # main after bit63-org/antikythera#117 (hold wire v2, VolumeLayout,
    # khold reports, test vectors 6 to 11).
    REF 7fe1f96d4c695ba0aa3224b5defd952556421afc
    FETCH_REF main
)

# Only the headers src/proto/ includes: every proto header, and the two
# src/common/ helpers they use (wire.hpp, crc32c.hpp). They keep their
# relative layout under include/antikythera/, so `#include "common/wire.hpp"`
# inside a proto header resolves against the one include directory the
# config file exports.
file(GLOB AK_PROTO_HEADERS "${SOURCE_PATH}/src/proto/*.hpp")
file(INSTALL ${AK_PROTO_HEADERS}
     DESTINATION "${CURRENT_PACKAGES_DIR}/include/antikythera/proto")
file(INSTALL
     "${SOURCE_PATH}/src/common/wire.hpp"
     "${SOURCE_PATH}/src/common/crc32c.hpp"
     DESTINATION "${CURRENT_PACKAGES_DIR}/include/antikythera/common")

file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/antikythera-proto-config.cmake"
     DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage"
     DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")

set(VCPKG_POLICY_EMPTY_PACKAGE enabled)
set(VCPKG_POLICY_HEADER_ONLY enabled)
