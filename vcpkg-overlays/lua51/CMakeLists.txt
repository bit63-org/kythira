# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Vendored build script for Valkey's deps/lua (Lua 5.1.5 plus cjson,
# cmsgpack, bit and struct). Copied into deps/lua by portfile.cmake and
# driven with vcpkg_cmake_configure / vcpkg_cmake_install. Valkey's own
# CMakeLists also compiles lua.c (the standalone interpreter, with a main())
# and offers no install rules, so it is not used.
cmake_minimum_required(VERSION 3.20)
project(lua51 VERSION 5.1.5 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(LUA_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src")

# The interpreter, its standard libraries, and the four libraries Redis
# scripts expect. Left out: lua.c and luac.c (programs), print.c (luac's
# listing), and nothing else. Plus deps/fpconv's fpconv_dtoa (Grisu2,
# Boost licence), which Valkey uses to turn a non-integral number argument
# of redis.call into text; the sandbox uses it for the same thing, so the
# bytes match Valkey's.
set(LUA_CORE_SOURCES
    lapi.c lcode.c ldebug.c ldo.c ldump.c lfunc.c lgc.c llex.c lmem.c
    lobject.c lopcodes.c lparser.c lstate.c lstring.c ltable.c ltm.c
    lundump.c lvm.c lzio.c
    lauxlib.c lbaselib.c ldblib.c liolib.c lmathlib.c loslib.c ltablib.c
    lstrlib.c loadlib.c linit.c
    lua_cjson.c strbuf.c fpconv.c lua_cmsgpack.c lua_bit.c lua_struct.c)
list(TRANSFORM LUA_CORE_SOURCES PREPEND "${LUA_SRC}/")
set(FPCONV_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../fpconv")
list(APPEND LUA_CORE_SOURCES "${FPCONV_SRC}/fpconv_dtoa.c")

add_library(lua51 STATIC ${LUA_CORE_SOURCES} kythira_lua_number.cpp)
set_target_properties(lua51 PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
    # std::to_chars for double.
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)

# Valkey's deps/Makefile flags: LUA_ANSI (no popen, no dlopen),
# ENABLE_CJSON_GLOBAL (luaopen_cjson also sets the global cjson, as the
# others do) and LUA_USE_MKSTEMP (os.tmpname, which the sandbox never
# exposes, without the tmpnam warning).
target_compile_definitions(lua51 PRIVATE LUA_ANSI ENABLE_CJSON_GLOBAL LUA_USE_MKSTEMP)

# Floating-point contraction off. GCC fuses a*b+c into one fma by default
# when the target has it (arm64 always does; x86-64 only with -mfma), and a
# fused result is rounded once instead of twice. Lua's modulo,
# a - floor(a/b)*b, would then give different bits on arm64 and amd64.
target_compile_options(lua51 PRIVATE -ffp-contract=off)

target_include_directories(lua51 PUBLIC
    "$<BUILD_INTERFACE:${LUA_SRC}>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${FPCONV_SRC}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/lua51>")
target_link_libraries(lua51 PUBLIC m)

install(TARGETS lua51
    EXPORT lua51-targets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

# Under include/lua51/ so they cannot shadow another Lua's lua.h.
# kythira_lua.h is the one consumers include: it wraps the others in
# extern "C" and declares the four libraries' luaopen_ functions.
install(FILES
    "${LUA_SRC}/lua.h" "${LUA_SRC}/luaconf.h" "${LUA_SRC}/lualib.h" "${LUA_SRC}/lauxlib.h"
    kythira_lua.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/lua51")

install(EXPORT lua51-targets
    FILE lua51-targets.cmake
    NAMESPACE lua51::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/lua51")

configure_package_config_file(lua51-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/lua51-config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/lua51")
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/lua51-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY ExactVersion)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/lua51-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/lua51-config-version.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/lua51")
