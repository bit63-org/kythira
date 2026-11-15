# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# libkythira_pkcs11.so (.kiro/specs/virtual-hsm/ task 10, requirement 5):
# the PKCS#11 client library, shipped to hosts that run no node. It is the
# wire client (wire_client.hpp) behind the PKCS#11 3.0 C interface.
#
# - kythira_pkcs11.map exports C_GetFunctionList, C_GetInterfaceList and
#   C_GetInterface only, and --exclude-libs keeps the symbols of every
#   static archive linked in (OpenSSL, where the build's is static, as
#   vcpkg's is) out of the dynamic table. The application, or OpenSSL's
#   pkcs11-provider loading this library into OpenSSL itself, keeps its
#   own OpenSSL.
# - -z nodelete: a dlclose leaves the library mapped. A static OpenSSL
#   registers exit handlers inside it, and a thread-local or handler that
#   outlives an unmapped library crashes the process at exit.
# - No -z defs: under KYTHIRA_SANITIZER the sanitizer runtime comes from
#   the executable that loads the library.
add_library(kythira_pkcs11 SHARED kythira_pkcs11.cpp)
target_link_libraries(kythira_pkcs11 PRIVATE kythira_hsm)
target_include_directories(kythira_pkcs11 PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(kythira_pkcs11 PRIVATE cxx_std_23)
set_target_properties(kythira_pkcs11 PROPERTIES
    OUTPUT_NAME kythira_pkcs11
    PREFIX lib
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/kythira_pkcs11.map"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_options(kythira_pkcs11 PRIVATE
    "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/kythira_pkcs11.map"
    "LINKER:--exclude-libs,ALL"
    "LINKER:-z,nodelete")
