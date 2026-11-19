// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/* The one header a consumer of the lua51 port includes, from C or C++.
** Lua 5.1's headers carry no extern "C" guards, and the four libraries
** Redis scripts expect have no headers at all; this supplies both. */
#ifndef KYTHIRA_LUA_H
#define KYTHIRA_LUA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

LUALIB_API int luaopen_cjson(lua_State *L);
LUALIB_API int luaopen_cmsgpack(lua_State *L);
LUALIB_API int luaopen_bit(lua_State *L);
LUALIB_API int luaopen_struct(lua_State *L);

/* deps/fpconv: the shortest text that reads back as fp (Grisu2), written
** to dest without a terminator; returns its length (at most 24). */
int fpconv_dtoa(double fp, char dest[24]);

#ifdef __cplusplus
}
#endif

#endif /* KYTHIRA_LUA_H */
