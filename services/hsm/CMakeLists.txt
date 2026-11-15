# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The virtual HSM module (.kiro/specs/virtual-hsm/, services/README.md):
# the header-only library, its kythira_node module, the stand-alone
# hsm_node, hsm_ctl, libkythira_pkcs11.so and the tests.
#
# Entered from the top level only when KYTHIRA_BUILD_HSM is on (CONFIG_HSM,
# services/hsm/Kconfig), after the core targets and tests/, so every core
# target and helper used here already exists. The core targets and variables
# this file and its subdirectories use are listed in README.md.

# The module's headers, as <kythira/hsm/...>; the vendored OASIS headers
# come with kythira_core_headers (core's <raft/pkcs11.hpp>). OpenSSL
# for every mechanism (KYTHIRA_BUILD_HSM requires it), and its TLS library
# for forwarding between members (hsm_peer.hpp).
set(KYTHIRA_HSM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_HSM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_hsm INTERFACE)
target_include_directories(kythira_hsm INTERFACE "${KYTHIRA_HSM_INCLUDE_DIR}")
target_link_libraries(kythira_hsm INTERFACE kythira_core_headers OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(kythira_hsm INTERFACE cxx_std_23)

# The TPM 2.0 share sealer (task 8b, kythira/hsm/tpm2_key_provider.hpp),
# when tpm2-tss's ESAPI is installed (Debian/Ubuntu libtss2-dev): the
# module then takes KYTHIRA_HSM_SHARE_SEALER=tpm2. Off without it, and
# KYTHIRA_HSM_TPM2=OFF leaves it out even when installed.
option(KYTHIRA_HSM_TPM2 "Build the HSM's TPM 2.0 share sealer when tpm2-tss is found" ON)
set(KYTHIRA_HSM_TPM2_FOUND FALSE)
if(KYTHIRA_HSM_TPM2)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(KYTHIRA_TSS2 QUIET IMPORTED_TARGET
            tss2-esys tss2-tctildr tss2-mu tss2-rc)
    endif()
    if(KYTHIRA_TSS2_FOUND)
        set(KYTHIRA_HSM_TPM2_FOUND TRUE)
        target_compile_definitions(kythira_hsm INTERFACE KYTHIRA_HSM_TPM2)
        target_link_libraries(kythira_hsm INTERFACE PkgConfig::KYTHIRA_TSS2)
        # tpm2-tss needs the system libcrypto.so. With vcpkg's static
        # OpenSSL in the executable, a shared library referring to OpenSSL
        # makes the linker export the executable's copy, and every later
        # libcrypto call from a shared library (SoftHSM2's, dlopened) binds
        # to it instead of its own: the two builds' structures differ and
        # SoftHSM2 crashed in hsm_pkcs11_module_test and hsm_ca_cluster_test.
        # Keeping the static archives' symbols private leaves each copy to
        # its own callers. One flag per archive: mold 2.30 takes the
        # colon-separated list GNU ld allows and exhausts memory on it.
        target_link_options(kythira_hsm INTERFACE
            "LINKER:--exclude-libs,libcrypto.a" "LINKER:--exclude-libs,libssl.a")
        message(STATUS "HSM: TPM 2.0 share sealer on (tpm2-tss ${KYTHIRA_TSS2_tss2-esys_VERSION})")
    else()
        message(STATUS "HSM: TPM 2.0 share sealer off (tpm2-tss not found)")
    endif()
endif()

# hsm_node (the daemon, task 11) and the module, before the tests,
# which run it.
add_subdirectory(cmd)

# libkythira_pkcs11.so (task 10), before the tests, which load it.
add_subdirectory(pkcs11)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
