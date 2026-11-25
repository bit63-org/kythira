# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# antikythera::proto: antikythera's header-only wire formats, installed by
# kythira's antikythera-proto overlay port under include/antikythera/.
# Consumers include "proto/<name>.hpp"; the headers need C++23
# (std::expected), which GCC 13+ and Clang 19+ provide over libstdc++.

if(NOT TARGET antikythera::proto)
    get_filename_component(_ak_proto_prefix "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    add_library(antikythera::proto INTERFACE IMPORTED)
    set_target_properties(antikythera::proto PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_ak_proto_prefix}/include/antikythera"
        INTERFACE_COMPILE_FEATURES cxx_std_23)
    unset(_ak_proto_prefix)
endif()
set(antikythera-proto_FOUND TRUE)
