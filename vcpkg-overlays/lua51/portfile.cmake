# Overlay port for Lua 5.1.5, taken from Valkey's deps/lua rather than from
# lua.org (.kiro/specs/redis-general-data-types/ Requirement 30, design
# Component 13).
#
# Why Valkey's copy and not the lua.org tarball:
#   - Redis scripts are written against the interpreter Redis embeds, which
#     is Lua 5.1.5 plus the cjson, cmsgpack, bit and struct libraries. Valkey
#     carries the same tree (forked from Redis 7.2, BSD), so one pinned commit
#     supplies the interpreter and all four libraries.
#   - That tree has the security fixes Redis and Valkey made to Lua 5.1 and
#     to those libraries (cmsgpack/struct overflows, the parser
#     use-after-free fixed in October 2025, and others), which a plain 5.1.5
#     does not.
#   - It has lua_enablereadonlytable, which the sandbox uses to lock globals
#     and library tables against rawset as well as plain assignment.
#
# vcpkg_from_git rather than vcpkg_from_github: it pins the content by commit
# id and fetches that one commit, so there is no archive hash to keep in
# step with GitHub's tarball generation.
#
# Only deps/lua (and deps/fpconv's one file) is built. The vendored CMakeLists.txt replaces Valkey's (which
# also compiles the standalone lua.c interpreter, with its main()).
vcpkg_from_git(
    OUT_SOURCE_PATH SOURCE_PATH
    URL https://github.com/valkey-io/valkey.git
    # Tag 9.0.8.
    REF 825e3b1f590984ac91c90f65059c5f235072084a
    FETCH_REF 9.0.8
    PATCHES
        # Number formatting through std::to_chars, saturating number to
        # integer conversion, one NaN bit pattern. See the patch's comments
        # and README.md.
        0001-deterministic-numbers.patch
)

set(LUA_SOURCE_PATH "${SOURCE_PATH}/deps/lua")
file(COPY
    "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt"
    "${CMAKE_CURRENT_LIST_DIR}/kythira_lua_number.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/kythira_lua.h"
    "${CMAKE_CURRENT_LIST_DIR}/lua51-config.cmake.in"
    DESTINATION "${LUA_SOURCE_PATH}")

vcpkg_cmake_configure(SOURCE_PATH "${LUA_SOURCE_PATH}")
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME lua51 CONFIG_PATH lib/cmake/lua51)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

# The interpreter's MIT licence, then the notices of the libraries built
# with it, which live in their source files rather than in licence files:
# cjson, strbuf and fpconv (MIT, Mark Pulford) and bit (MIT, Mike Pall) open
# with theirs; cmsgpack (MIT, Redis Ltd.) and struct (MIT, Lua.org) close
# with theirs. README.md lists them too.
set(LUA_LICENSE_NOTES "${CURRENT_BUILDTREES_DIR}/lua51-licenses.txt")
file(READ "${LUA_SOURCE_PATH}/COPYRIGHT" LUA_COPYRIGHT)
file(WRITE "${LUA_LICENSE_NOTES}" "${LUA_COPYRIGHT}\n")
foreach(lib_source IN ITEMS lua_cjson.c strbuf.c fpconv.c lua_bit.c)
    file(READ "${LUA_SOURCE_PATH}/src/${lib_source}" lib_text)
    string(SUBSTRING "${lib_text}" 0 1500 lib_notice)
    file(APPEND "${LUA_LICENSE_NOTES}" "\n==== deps/lua/src/${lib_source} ====\n${lib_notice}\n")
endforeach()
foreach(lib_source IN ITEMS lua_cmsgpack.c lua_struct.c)
    file(READ "${LUA_SOURCE_PATH}/src/${lib_source}" lib_text)
    string(LENGTH "${lib_text}" lib_len)
    math(EXPR notice_start "${lib_len} - 1300")
    string(SUBSTRING "${lib_text}" ${notice_start} -1 lib_notice)
    file(APPEND "${LUA_LICENSE_NOTES}" "\n==== deps/lua/src/${lib_source} ====\n${lib_notice}\n")
endforeach()
file(READ "${SOURCE_PATH}/deps/fpconv/LICENSE.txt" FPCONV_LICENSE)
file(APPEND "${LUA_LICENSE_NOTES}" "\n==== deps/fpconv/LICENSE.txt ====\n${FPCONV_LICENSE}\n")
vcpkg_install_copyright(FILE_LIST "${LUA_LICENSE_NOTES}")
