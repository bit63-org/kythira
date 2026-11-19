// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file lua_sandbox.hpp
/// @brief The Lua 5.1 sandbox that Redis scripts run in
///        (.kiro/specs/redis-general-data-types/ task 25, Requirement 30,
///        design Component 13).
///
/// One call to `run_lua_script` runs one script in a fresh interpreter and
/// returns its reply. The interpreter is the `lua51` overlay port
/// (vcpkg-overlays/lua51/: Valkey's Lua 5.1.5 with cjson, cmsgpack, bit and
/// struct). Nothing here knows about keys, groups or the log: `redis.call`
/// goes to a caller-supplied handler, which task 26 binds to the state
/// machine's command evaluator (single-shard, in `apply()`) and task 27 to a
/// transaction (cross-shard, on the front end).
///
/// Two modes, because the same script runs in two very different places:
///
/// - `lua_script_mode::replicated` is for `apply()`. Every replica runs the
///   script and must reach the same result, so nothing can reach a clock,
///   random source, file, socket or the environment (Requirement 30.2), and
///   the only limits are deterministic ones (30.3): a Lua instruction budget
///   and an allocation cap. Every replica stops an over-budget script at the
///   same instruction.
/// - `lua_script_mode::front_end` runs a script once, on one node. It also
///   gets `os.clock`, a wall-time limit and a kill flag for `SCRIPT KILL`
///   (30.4, 30.5).
///
/// What a script can see (30.4). Globals are the allow list Valkey uses,
/// minus `loadstring` and `load` (Redis keeps both; the spec removes them,
/// so a script can never compile code that was not in the log entry):
/// `assert collectgarbage coroutine error gcinfo getmetatable ipairs next
/// pairs pcall rawequal rawget rawset select setmetatable tonumber tostring
/// type unpack xpcall _G _VERSION`, the libraries `string table math cjson
/// cmsgpack bit struct`, `redis` (and Valkey's alias `server`), `KEYS`,
/// `ARGV`, and `os` with only `clock` on the front end. Gone: `print io
/// debug package require module dofile loadfile loadstring load newproxy
/// setfenv getfenv`. `_G`, every library table and the string metatable are
/// read-only (Valkey's `lua_enablereadonlytable`, which also stops
/// `rawset`), so a script cannot create a global or change a library; reading
/// a global that does not exist is an error, as in Redis. A chunk that is
/// precompiled bytecode is refused before it reaches the loader.
///
/// Determinism beyond the clock and the random source:
///
/// - `tostring(n)` is "%.14g" as in Redis, written by `std::to_chars`
///   (the port's patch), so it does not depend on the C library or locale.
///   Every NaN prints as "nan": 0/0 is a negative NaN on x86-64 ("-nan" in
///   Redis there) and a positive one on arm64.
/// - Number to integer conversions saturate and map NaN to 0 on every
///   architecture (a C cast is undefined out of range, and x86-64 and arm64
///   answer differently). A number returned from a script becomes an
///   integer reply the same way.
/// - A number argument of `redis.call` becomes text the way Valkey does it:
///   the integer if the number is integral and within +-2^62, otherwise the
///   shortest text that reads back as the same double (Grisu2, Valkey's
///   `fpconv_dtoa`, built into the port). This is the "shortest round trip"
///   formatter design Component 13 asks for; it applies to arguments, while
///   `tostring` keeps Redis's 14 digits.
/// - `math.random` is rand48, as Valkey's is, started from the call's seed
///   (design: derived from the entry's index and term), not from libc's
///   `rand()`. `math.randomseed(n)` is `srand48(n)`.
/// - `tostring` of a table, function, coroutine or userdata prints a
///   sequence number ("table: 0x00000001") instead of an address.
/// - The port is built with floating-point contraction off.
///
/// Limits of that determinism, stated rather than hidden:
///
/// - `pairs` over a table whose keys are tables or functions visits them in
///   an order that depends on their addresses. Redis has the same property.
///   String, number and boolean keys are visited in an order fixed by the
///   insertion sequence.
/// - `math.sin`, `math.exp`, `math.pow` and the other transcendental
///   functions are the C library's. `lua_sandbox_determinism_test` pins
///   their exact bits for a set of inputs on amd64 and arm64 CI; a C library
///   whose results differ between the two would fail it.
/// - A C function (a `string.find` with a pathological pattern, say) counts
///   as one instruction however long it runs. Its memory is still capped.
///
/// The budgets. The instruction hook fires every `k_lua_hook_interval`
/// instructions; the count is the number of firings times that interval, so
/// a script is stopped at the first firing past the budget. The allocation
/// cap counts what the interpreter asks the allocator for, measured from
/// the moment the script starts (the libraries are not charged). Once a
/// limit is hit the script cannot recover: `pcall` can catch the error, but
/// the hook then fires on every instruction and raises it again, and the
/// result reports the limit whatever the script did afterwards (Valkey does
/// the same for `SCRIPT KILL`). The reply a script returns is converted
/// against the same allocation cap, so a small table that references itself
/// or shares children cannot expand into a huge reply.
///
/// Implementation note: Lua reports errors with longjmp, which skips C++
/// destructors. Every C function the sandbox gives Lua therefore keeps the
/// objects that own memory in `lua_run_state` (which outlives the
/// interpreter), never on its own stack, and leaves every try block before
/// it can call back into Lua; setup and reply conversion run under
/// `lua_cpcall` so a memory error there is caught rather than reaching the
/// panic handler.

#include <kythira_lua.h>

#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira {

/// A reply crossing between a script and Redis, in RESP2 terms: what
/// `redis.call` hands back to a script, and what a script's return value
/// becomes. Task 26 maps it to and from the gateway's reply type.
struct lua_reply {
    enum class kind : std::uint8_t {
        nil,
        integer,
        bulk,
        status,
        error,
        array
    };

    kind type = kind::nil;
    std::int64_t integer = 0;
    /// The bytes of a bulk string, or the text of a status or error.
    std::string text;
    std::vector<lua_reply> elements;

    [[nodiscard]] static auto nil() -> lua_reply { return {}; }
    [[nodiscard]] static auto from_integer(std::int64_t v) -> lua_reply {
        lua_reply r;
        r.type = kind::integer;
        r.integer = v;
        return r;
    }
    [[nodiscard]] static auto bulk(std::string v) -> lua_reply {
        lua_reply r;
        r.type = kind::bulk;
        r.text = std::move(v);
        return r;
    }
    [[nodiscard]] static auto status(std::string v) -> lua_reply {
        lua_reply r;
        r.type = kind::status;
        r.text = std::move(v);
        return r;
    }
    [[nodiscard]] static auto error(std::string v) -> lua_reply {
        lua_reply r;
        r.type = kind::error;
        r.text = std::move(v);
        return r;
    }
    [[nodiscard]] static auto array(std::vector<lua_reply> v) -> lua_reply {
        lua_reply r;
        r.type = kind::array;
        r.elements = std::move(v);
        return r;
    }

    friend auto operator==(const lua_reply&, const lua_reply&) -> bool = default;
};

enum class lua_script_mode : std::uint8_t {
    /// In `apply()` on every replica: deterministic limits only, no clock.
    replicated,
    /// Once, on a front end: `os.clock`, a wall-time limit and a kill flag.
    front_end,
};

/// The instruction hook's period. The budget is counted in these steps.
inline constexpr std::uint64_t k_lua_hook_interval = 1000;

/// Deepest table nesting a script's return value may have (Redis stops at
/// the Lua stack limit; this is a fixed number so replicas agree).
inline constexpr std::size_t k_lua_reply_max_depth = 1000;

struct lua_script_limits {
    /// Lua VM instructions a script may execute. About a second of tight
    /// loop on current hardware; the point is a fixed number, not a time.
    std::uint64_t instruction_budget = 500'000'000;
    /// Bytes a script may have allocated at once, beyond what the
    /// libraries took, plus the size of its converted reply.
    std::size_t memory_cap = std::size_t{64} << 20;
    /// Front end only: wall time before the script is stopped. Zero means
    /// no limit. Ignored in replicated mode, where time cannot be used.
    std::chrono::milliseconds wall_time{0};
};

struct lua_sandbox_config {
    lua_script_mode mode = lua_script_mode::replicated;
    lua_script_limits limits{};
    /// `redis.REDIS_VERSION` and `redis.REDIS_VERSION_NUM`. The gateway
    /// passes k_redis_compat_version.
    std::string_view redis_version = "7.0.0";
};

/// One script run: its body, `KEYS`, `ARGV`, and the seed `math.random`
/// starts from (rand48's 48-bit state is the seed's low 48 bits).
struct lua_script_call {
    std::string_view body;
    std::span<const std::string> keys;
    std::span<const std::string> args;
    std::uint64_t seed = 0;
};

enum class lua_script_status : std::uint8_t {
    /// The script returned; `reply` is its value (which may itself be an
    /// error reply, from `return redis.error_reply(...)`).
    ok,
    /// The script did not compile, or raised an error; `reply` is the error.
    error,
    /// The instruction budget ran out.
    instruction_budget,
    /// The allocation cap was reached, while running or converting the reply.
    memory_cap,
    /// Front end only: the wall-time limit passed.
    wall_time,
    /// Front end only: the kill flag was set (SCRIPT KILL).
    killed,
};

struct lua_script_result {
    lua_script_status status = lua_script_status::ok;
    lua_reply reply;
    /// Instructions counted, in steps of k_lua_hook_interval.
    std::uint64_t instructions = 0;
    /// Highest allocation the script reached, beyond the libraries.
    std::size_t peak_memory = 0;
    /// What `redis.setresp` last asked for (2 unless the script called it).
    int resp_version = 2;
};

/// Runs one `redis.call` / `redis.pcall`. `argv[0]` is the command name as
/// the script wrote it. An error reply makes `redis.call` raise and
/// `redis.pcall` return it. The handler must not throw; if it does, the
/// script sees an error reply with the exception's text.
using lua_command_handler = std::function<lua_reply(std::span<const std::string> argv)>;

namespace lua_sandbox_detail {

enum class abort_reason : std::uint8_t {
    none,
    instruction_budget,
    memory_cap,
    wall_time,
    killed
};

[[nodiscard]] inline auto abort_message(abort_reason r) noexcept -> const char* {
    switch (r) {
        case abort_reason::instruction_budget:
            return "ERR Script exceeded its instruction budget";
        case abort_reason::memory_cap:
            return "ERR Script exceeded its memory limit";
        case abort_reason::wall_time:
            return "ERR Script exceeded its time limit";
        case abort_reason::killed:
            return "ERR Script killed by user with SCRIPT KILL";
        case abort_reason::none:
            break;
    }
    return "ERR Script stopped";
}

/// rand48 (the drand48 family's generator, which Valkey's serverLrand48
/// is): x' = (0x5DEECE66D * x + 0xB) mod 2^48, output x' >> 17.
struct rand48 {
    static constexpr std::uint64_t mask = (std::uint64_t{1} << 48) - 1;
    static constexpr std::int32_t max = 0x7fffffff;
    std::uint64_t x = 0;

    void seed_state(std::uint64_t s) noexcept { x = s & mask; }
    /// srand48(seed): the high 32 bits of the state are the seed.
    void srand(std::int32_t seed) noexcept {
        x = ((static_cast<std::uint64_t>(static_cast<std::uint32_t>(seed)) << 16) | 0x330E) & mask;
    }
    [[nodiscard]] auto next() noexcept -> std::int32_t {
        x = (0x5DEECE66DULL * x + 0xB) & mask;
        return static_cast<std::int32_t>(x >> 17);
    }
};

/// Everything a run owns. The interpreter's allocator user data, so every C
/// function reaches it with lua_getallocf.
struct lua_run_state {
    const lua_sandbox_config* config = nullptr;
    const lua_command_handler* handler = nullptr;
    const std::atomic<bool>* kill = nullptr;
    std::chrono::steady_clock::time_point deadline{};
    bool has_deadline = false;

    std::size_t allocated = 0;
    std::size_t baseline = 0;
    std::size_t peak = 0;
    bool cap_armed = false;

    std::uint64_t instructions = 0;
    abort_reason abort = abort_reason::none;

    rand48 random;
    double next_object_id = 0;
    int resp_version = 2;

    // Scratch owned here, not on a C function's stack (see the file note).
    std::vector<std::string> argv;
    lua_reply call_reply;
    bool call_failed = false;

    // Setup and conversion inputs and outputs.
    const lua_script_call* call = nullptr;
    std::string compile_error;
    lua_reply result;
    std::size_t result_budget = 0;
    bool result_too_big = false;
    bool result_too_deep = false;

    [[nodiscard]] auto in_use() const noexcept -> std::size_t {
        return allocated > baseline ? allocated - baseline : 0;
    }
};

[[nodiscard]] inline auto state_of(lua_State* L) noexcept -> lua_run_state& {
    void* ud = nullptr;
    (void)lua_getallocf(L, &ud);
    return *static_cast<lua_run_state*>(ud);
}

/// The allocator. Shrinking and freeing always succeed; growth past the cap
/// fails (Lua then raises "not enough memory") and marks the run aborted.
/// Lua's allocator contract is realloc and free, hence the raw calls.
inline auto sandbox_alloc(void* ud, void* ptr, std::size_t osize, std::size_t nsize) noexcept
    -> void* {
    auto& st = *static_cast<lua_run_state*>(ud);
    if (nsize == 0) {
        std::free(ptr);  // NOLINT(cppcoreguidelines-no-malloc)
        st.allocated -= osize;
        return nullptr;
    }
    if (st.cap_armed && nsize > osize) {
        const std::size_t after = st.allocated - osize + nsize;
        const std::size_t used = after > st.baseline ? after - st.baseline : 0;
        if (used > st.config->limits.memory_cap) {
            if (st.abort == abort_reason::none) {
                st.abort = abort_reason::memory_cap;
            }
            return nullptr;
        }
    }
    void* p = std::realloc(ptr, nsize);  // NOLINT(cppcoreguidelines-no-malloc)
    if (p == nullptr) {
        return nullptr;
    }
    st.allocated = st.allocated - osize + nsize;
    st.peak = std::max(st.peak, st.in_use());
    return p;
}

inline void count_hook(lua_State* L, lua_Debug* /*ar*/) {
    auto& st = state_of(L);
    if (st.abort == abort_reason::none) {
        st.instructions += k_lua_hook_interval;
        if (st.instructions > st.config->limits.instruction_budget) {
            st.abort = abort_reason::instruction_budget;
        } else if (st.config->mode == lua_script_mode::front_end) {
            if (st.kill != nullptr && st.kill->load(std::memory_order_relaxed)) {
                st.abort = abort_reason::killed;
            } else if (st.has_deadline && std::chrono::steady_clock::now() >= st.deadline) {
                st.abort = abort_reason::wall_time;
            }
        }
    }
    if (st.abort != abort_reason::none) {
        // From now on every instruction raises, so pcall cannot swallow it.
        lua_sethook(L, &count_hook, LUA_MASKCOUNT, 1);
        lua_pushstring(L, abort_message(st.abort));
        (void)lua_error(L);
    }
}

// ---------------------------------------------------------------------------
// Values between Lua and lua_reply.

/// Pushes {err=text} (or {ok=text}).
inline void push_field_table(lua_State* L, const char* field, const char* text, std::size_t len) {
    lua_createtable(L, 0, 1);
    lua_pushlstring(L, text, len);
    lua_setfield(L, -2, field);
}

/// Pushes a reply the way Redis hands one to a script (RESP2): integer ->
/// number, bulk -> string, nil -> false, status -> {ok=}, error -> {err=},
/// array -> table. `r` lives in lua_run_state, so a longjmp here leaks
/// nothing.
inline void push_reply(lua_State* L, const lua_reply& r, int depth) {
    if (depth > 64 || lua_checkstack(L, 4) == 0) {
        luaL_error(L, "reply nested too deeply");
    }
    switch (r.type) {
        case lua_reply::kind::nil:
            lua_pushboolean(L, 0);
            return;
        case lua_reply::kind::integer:
            lua_pushnumber(L, static_cast<lua_Number>(r.integer));
            return;
        case lua_reply::kind::bulk:
            lua_pushlstring(L, r.text.data(), r.text.size());
            return;
        case lua_reply::kind::status:
            push_field_table(L, "ok", r.text.data(), r.text.size());
            return;
        case lua_reply::kind::error:
            push_field_table(L, "err", r.text.data(), r.text.size());
            return;
        case lua_reply::kind::array: {
            lua_createtable(L, static_cast<int>(std::min<std::size_t>(r.elements.size(), 1U << 20)),
                            0);
            int index = 1;
            for (const auto& e : r.elements) {
                push_reply(L, e, depth + 1);
                lua_rawseti(L, -2, index++);
            }
            return;
        }
    }
}

/// The text Valkey sends for a number argument of redis.call: the integer
/// when the number is integral and within +-2^62 (Valkey's double2ll), else
/// the shortest round-trip text (fpconv_dtoa).
[[nodiscard]] inline auto number_argument(lua_Number n, char (&buf)[32]) noexcept -> std::size_t {
    constexpr double limit = 4611686018427387903.0;  // LLONG_MAX / 2
    if (n >= -limit && n <= limit) {
        const auto ll = static_cast<long long>(n);
        if (static_cast<double>(ll) == n) {
            const int len = std::snprintf(buf, sizeof buf, "%lld", ll);
            return static_cast<std::size_t>(len);
        }
    }
    // One NaN: fpconv_dtoa prints the sign bit, which x86-64 sets on 0/0.
    return static_cast<std::size_t>(fpconv_dtoa(kythira_lua_canonical_nan(n), buf));
}

/// redis.call (raise = true) and redis.pcall (raise = false).
inline auto generic_call(lua_State* L, bool raise) -> int {
    auto& st = state_of(L);
    const int argc = lua_gettop(L);
    const char* arg_error = nullptr;
    if (argc == 0) {
        arg_error = "ERR Please specify at least one argument for this redis lib call";
    } else {
        for (int i = 1; i <= argc; ++i) {
            const int t = lua_type(L, i);
            if (t != LUA_TSTRING && t != LUA_TNUMBER) {
                arg_error = "ERR Lua redis lib command arguments must be strings or integers";
                break;
            }
        }
    }
    if (arg_error != nullptr) {
        push_field_table(L, "err", arg_error, std::strlen(arg_error));
        if (raise) {
            return lua_error(L);
        }
        return 1;
    }

    // Collect the arguments and run the handler. No Lua call can happen
    // inside the try block, and nothing that owns memory lives on this
    // frame afterwards.
    st.call_failed = false;
    try {
        st.argv.clear();
        st.argv.reserve(static_cast<std::size_t>(argc));
        for (int i = 1; i <= argc; ++i) {
            if (lua_type(L, i) == LUA_TNUMBER) {
                char buf[32];
                const std::size_t len = number_argument(lua_tonumber(L, i), buf);
                st.argv.emplace_back(buf, len);
            } else {
                std::size_t len = 0;
                const char* s = lua_tolstring(L, i, &len);  // a string: no allocation
                st.argv.emplace_back(s, len);
            }
        }
        st.call_reply = (*st.handler)(std::span<const std::string>(st.argv));
    } catch (const std::exception& e) {
        st.call_failed = true;
        try {
            st.call_reply = lua_reply::error(std::string("ERR ") + e.what());
        } catch (...) {
            st.call_reply = lua_reply{};
        }
    } catch (...) {
        st.call_failed = true;
        st.call_reply = lua_reply{};
    }
    if (st.call_failed && st.call_reply.type != lua_reply::kind::error) {
        static constexpr const char* msg = "ERR command handler failed";
        push_field_table(L, "err", msg, std::strlen(msg));
        if (raise) {
            return lua_error(L);
        }
        return 1;
    }
    push_reply(L, st.call_reply, 0);
    if (raise && st.call_reply.type == lua_reply::kind::error) {
        return lua_error(L);
    }
    return 1;
}

inline auto lua_redis_call(lua_State* L) -> int {
    return generic_call(L, true);
}
inline auto lua_redis_pcall(lua_State* L) -> int {
    return generic_call(L, false);
}

inline auto lua_redis_error_reply(lua_State* L) -> int {
    if (lua_gettop(L) != 1 || lua_type(L, 1) != LUA_TSTRING) {
        return luaL_error(L, "wrong number or type of arguments");
    }
    std::size_t len = 0;
    const char* s = lua_tolstring(L, 1, &len);
    push_field_table(L, "err", s, len);
    return 1;
}

inline auto lua_redis_status_reply(lua_State* L) -> int {
    if (lua_gettop(L) != 1 || lua_type(L, 1) != LUA_TSTRING) {
        return luaL_error(L, "wrong number or type of arguments");
    }
    std::size_t len = 0;
    const char* s = lua_tolstring(L, 1, &len);
    push_field_table(L, "ok", s, len);
    return 1;
}

inline auto lua_redis_sha1hex(lua_State* L) -> int {
    if (lua_gettop(L) != 1) {
        return luaL_error(L, "wrong number of arguments");
    }
    std::size_t len = 0;
    const char* s = lua_tolstring(L, 1, &len);  // a number converts; anything else hashes as ""
    if (s == nullptr) {
        s = "";
        len = 0;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_Digest(s, len, digest, &digest_len, EVP_sha1(), nullptr) != 1) {
        return luaL_error(L, "sha1 failed");
    }
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    static constexpr char digits[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; ++i) {
        hex[2 * i] = digits[digest[i] >> 4];
        hex[2 * i + 1] = digits[digest[i] & 0xF];
    }
    lua_pushlstring(L, hex, 2 * static_cast<std::size_t>(digest_len));
    return 1;
}

/// redis.log: checked as Redis checks it, then dropped. A replicated script
/// runs on every replica, so writing its messages to each node's log would
/// say nothing the entry does not.
inline auto lua_redis_log(lua_State* L) -> int {
    if (lua_gettop(L) < 2) {
        return luaL_error(L, "redis.log() requires two arguments or more.");
    }
    if (lua_type(L, 1) != LUA_TNUMBER) {
        return luaL_error(L, "First argument must be a number (log level).");
    }
    const lua_Number level = lua_tonumber(L, 1);
    if (level < 0 || level > 3) {
        return luaL_error(L, "Invalid debug level.");
    }
    return 0;
}

inline auto lua_redis_setresp(lua_State* L) -> int {
    if (lua_gettop(L) != 1) {
        return luaL_error(L, "redis.setresp() requires one argument.");
    }
    const int v = static_cast<int>(lua_tointeger(L, 1));
    if (v != 2 && v != 3) {
        return luaL_error(L, "RESP version must be 2 or 3.");
    }
    state_of(L).resp_version = v;
    return 0;
}

/// redis.set_repl: a Kythira script is replicated as its body, never as
/// the commands it ran, so there is nothing to select. Checked, then a
/// no-op.
inline auto lua_redis_set_repl(lua_State* L) -> int {
    if (lua_gettop(L) != 1) {
        return luaL_error(L, "redis.set_repl() requires one argument.");
    }
    const lua_Number flags = lua_tonumber(L, 1);
    if (flags < 0 || flags > 3) {
        return luaL_error(
            L, "Invalid replication flags. Use REPL_AOF, REPL_REPLICA, REPL_ALL or REPL_NONE.");
    }
    return 0;
}

inline auto lua_redis_replicate_commands(lua_State* L) -> int {
    lua_pushboolean(L, 1);
    return 1;
}

inline auto lua_redis_breakpoint(lua_State* L) -> int {
    lua_pushboolean(L, 0);
    return 1;
}

inline auto lua_redis_debug(lua_State* /*L*/) -> int {
    return 0;
}

/// math.random as Valkey has it: Lua 5.1's own code with rand() replaced.
inline auto lua_math_random(lua_State* L) -> int {
    auto& st = state_of(L);
    const lua_Number r = static_cast<lua_Number>(st.random.next() % rand48::max) /
                         static_cast<lua_Number>(rand48::max);
    switch (lua_gettop(L)) {
        case 0:
            lua_pushnumber(L, r);
            break;
        case 1: {
            const int u = luaL_checkint(L, 1);
            luaL_argcheck(L, 1 <= u, 1, "interval is empty");
            lua_pushnumber(L, std::floor(r * u) + 1);
            break;
        }
        case 2: {
            const int l = luaL_checkint(L, 1);
            const int u = luaL_checkint(L, 2);
            luaL_argcheck(L, l <= u, 2, "interval is empty");
            lua_pushnumber(L, std::floor(r * (static_cast<lua_Number>(u) - l + 1)) + l);
            break;
        }
        default:
            return luaL_error(L, "wrong number of arguments");
    }
    return 1;
}

inline auto lua_math_randomseed(lua_State* L) -> int {
    state_of(L).random.srand(luaL_checkint(L, 1));
    return 0;
}

inline constexpr const char* k_object_ids_key = "kythira.object_ids";

/// tostring, with a sequence number in place of an address for objects
/// that have no __tostring. Upvalue 1 is the original tostring.
inline auto lua_sandbox_tostring(lua_State* L) -> int {
    luaL_checkany(L, 1);
    const int t = lua_type(L, 1);
    const bool by_address = t == LUA_TTABLE || t == LUA_TFUNCTION || t == LUA_TUSERDATA ||
                            t == LUA_TTHREAD || t == LUA_TLIGHTUSERDATA;
    if (by_address) {
        if (luaL_getmetafield(L, 1, "__tostring") != 0) {
            lua_pop(L, 1);
        } else {
            auto& st = state_of(L);
            lua_getfield(L, LUA_REGISTRYINDEX, k_object_ids_key);
            lua_pushvalue(L, 1);
            lua_rawget(L, -2);
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                st.next_object_id += 1;
                lua_pushvalue(L, 1);
                lua_pushnumber(L, st.next_object_id);
                lua_rawset(L, -3);
                lua_pushnumber(L, st.next_object_id);
            }
            const auto id = static_cast<unsigned long long>(lua_tonumber(L, -1));
            char buf[64];
            const int len = std::snprintf(buf, sizeof buf, "%s: 0x%08llx", lua_typename(L, t), id);
            lua_pushlstring(L, buf, static_cast<std::size_t>(len));
            return 1;
        }
    }
    lua_settop(L, 1);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, 1, 1);
    return 1;
}

/// Raised on reading a global that does not exist.
inline auto lua_global_missing(lua_State* L) -> int {
    const char* name = lua_tostring(L, 2);
    return luaL_error(L, "Script attempted to access nonexistent global variable '%s'",
                      name != nullptr ? name : "?");
}

/// Marks the table on top of the stack, every table reachable from it and
/// their metatables read-only (Valkey's luaSetTableProtectionRecursively).
inline void protect_recursively(lua_State* L) {
    if (lua_isreadonlytable(L, -1) != 0) {
        return;
    }
    lua_enablereadonlytable(L, -1, 1);
    luaL_checkstack(L, 3, "protecting tables");
    lua_pushnil(L);
    while (lua_next(L, -2) != 0) {
        if (lua_istable(L, -1)) {
            protect_recursively(L);
        }
        lua_pop(L, 1);
    }
    if (lua_getmetatable(L, -1) != 0) {
        protect_recursively(L);
        lua_pop(L, 1);
    }
}

inline void open_library(lua_State* L, const char* name, lua_CFunction open) {
    lua_pushcfunction(L, open);
    lua_pushstring(L, name);
    lua_call(L, 1, 0);
}

inline void set_number_field(lua_State* L, const char* name, lua_Number value) {
    lua_pushnumber(L, value);
    lua_setfield(L, -2, name);
}

inline void set_function_field(lua_State* L, const char* name, lua_CFunction f) {
    lua_pushcfunction(L, f);
    lua_setfield(L, -2, name);
}

[[nodiscard]] inline auto parse_version_num(std::string_view v) noexcept -> lua_Number {
    // "7.0.0" -> 0x070000, as Redis encodes REDIS_VERSION_NUM.
    unsigned parts[3] = {0, 0, 0};
    std::size_t part = 0;
    for (const char c : v) {
        if (c == '.') {
            if (++part == 3) {
                break;
            }
        } else if (c >= '0' && c <= '9') {
            parts[part] = parts[part] * 10 + static_cast<unsigned>(c - '0');
        } else {
            break;
        }
    }
    return static_cast<lua_Number>(((parts[0] & 0xFF) << 16) | ((parts[1] & 0xFF) << 8) |
                                   (parts[2] & 0xFF));
}

inline void push_string_array(lua_State* L, std::span<const std::string> values) {
    lua_createtable(L, static_cast<int>(std::min<std::size_t>(values.size(), 1U << 20)), 0);
    int index = 1;
    for (const auto& v : values) {
        lua_pushlstring(L, v.data(), v.size());
        lua_rawseti(L, -2, index++);
    }
}

inline constexpr const char* k_chunk_key = "kythira.chunk";

/// Builds the sandbox and compiles the body, under lua_cpcall. On success
/// leaves the compiled chunk in the registry slot k_chunk_key; on a compile
/// error records the message in st.compile_error instead (lua_cpcall
/// discards return values).
inline auto setup(lua_State* L) -> int {
    auto& st = *static_cast<lua_run_state*>(lua_touserdata(L, 1));
    lua_settop(L, 0);
    const bool front_end = st.config->mode == lua_script_mode::front_end;

    open_library(L, "", luaopen_base);
    open_library(L, LUA_TABLIBNAME, luaopen_table);
    open_library(L, LUA_STRLIBNAME, luaopen_string);
    open_library(L, LUA_MATHLIBNAME, luaopen_math);
    open_library(L, LUA_OSLIBNAME, luaopen_os);  // Valkey's: os.clock only
    open_library(L, "cjson", luaopen_cjson);
    open_library(L, "struct", luaopen_struct);
    open_library(L, "cmsgpack", luaopen_cmsgpack);
    open_library(L, "bit", luaopen_bit);

    // math.random / math.randomseed.
    lua_getglobal(L, LUA_MATHLIBNAME);
    set_function_field(L, "random", &lua_math_random);
    set_function_field(L, "randomseed", &lua_math_randomseed);
    lua_pop(L, 1);

    // tostring without addresses.
    lua_newtable(L);
    lua_createtable(L, 0, 1);
    lua_pushliteral(L, "k");
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
    lua_setfield(L, LUA_REGISTRYINDEX, k_object_ids_key);
    lua_getglobal(L, "tostring");
    lua_pushcclosure(L, &lua_sandbox_tostring, 1);
    lua_setglobal(L, "tostring");

    // The redis table, also as server.
    lua_newtable(L);
    set_function_field(L, "call", &lua_redis_call);
    set_function_field(L, "pcall", &lua_redis_pcall);
    set_function_field(L, "error_reply", &lua_redis_error_reply);
    set_function_field(L, "status_reply", &lua_redis_status_reply);
    set_function_field(L, "sha1hex", &lua_redis_sha1hex);
    set_function_field(L, "log", &lua_redis_log);
    set_function_field(L, "setresp", &lua_redis_setresp);
    set_function_field(L, "set_repl", &lua_redis_set_repl);
    set_function_field(L, "replicate_commands", &lua_redis_replicate_commands);
    set_function_field(L, "breakpoint", &lua_redis_breakpoint);
    set_function_field(L, "debug", &lua_redis_debug);
    set_number_field(L, "LOG_DEBUG", 0);
    set_number_field(L, "LOG_VERBOSE", 1);
    set_number_field(L, "LOG_NOTICE", 2);
    set_number_field(L, "LOG_WARNING", 3);
    set_number_field(L, "REPL_NONE", 0);
    set_number_field(L, "REPL_AOF", 1);
    set_number_field(L, "REPL_SLAVE", 2);
    set_number_field(L, "REPL_REPLICA", 2);
    set_number_field(L, "REPL_ALL", 3);
    lua_pushlstring(L, st.config->redis_version.data(), st.config->redis_version.size());
    lua_setfield(L, -2, "REDIS_VERSION");
    set_number_field(L, "REDIS_VERSION_NUM", parse_version_num(st.config->redis_version));
    lua_pushvalue(L, -1);
    lua_setglobal(L, "redis");
    lua_setglobal(L, "server");

    // Keep only the allow list.
    static constexpr std::string_view allowed[] = {
        "assert",   "collectgarbage", "coroutine",    "error",
        "gcinfo",   "getmetatable",   "ipairs",       "next",
        "pairs",    "pcall",          "rawequal",     "rawget",
        "rawset",   "select",         "setmetatable", "tonumber",
        "tostring", "type",           "unpack",       "xpcall",
        "_G",       "_VERSION",       "string",       "table",
        "math",     "cjson",          "cmsgpack",     "bit",
        "struct",   "redis",          "server",       "os",
    };
    lua_newtable(L);  // names to remove
    int removals = 0;
    lua_pushnil(L);
    while (lua_next(L, LUA_GLOBALSINDEX) != 0) {
        lua_pop(L, 1);
        bool keep = false;
        if (lua_type(L, -1) == LUA_TSTRING) {
            std::size_t len = 0;
            const char* name = lua_tolstring(L, -1, &len);
            const std::string_view sv(name, len);
            keep = std::find(std::begin(allowed), std::end(allowed), sv) != std::end(allowed);
            if (sv == "os" && !front_end) {
                keep = false;
            }
        }
        if (!keep) {
            lua_pushvalue(L, -1);
            lua_rawseti(L, -3, ++removals);
        }
    }
    for (int i = 1; i <= removals; ++i) {
        lua_rawgeti(L, -1, i);
        lua_pushnil(L);
        lua_rawset(L, LUA_GLOBALSINDEX);
    }
    lua_pop(L, 1);

    // Missing globals are errors; then everything reachable is read-only.
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    lua_createtable(L, 0, 1);
    lua_pushcfunction(L, &lua_global_missing);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);
    protect_recursively(L);
    lua_pop(L, 1);
    lua_pushliteral(L, "");
    if (lua_getmetatable(L, -1) != 0) {
        protect_recursively(L);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    // KEYS and ARGV: writable tables, set while _G is briefly writable.
    lua_enablereadonlytable(L, LUA_GLOBALSINDEX, 0);
    push_string_array(L, st.call->keys);
    lua_setglobal(L, "KEYS");
    push_string_array(L, st.call->args);
    lua_setglobal(L, "ARGV");
    lua_enablereadonlytable(L, LUA_GLOBALSINDEX, 1);

    // Compile. Bytecode is refused: the loader trusts it, and a crafted
    // chunk is a well-known way out of a Lua 5.1 sandbox.
    const std::string_view body = st.call->body;
    const char* compile_error = nullptr;
    std::size_t compile_error_len = 0;
    if (!body.empty() && body.front() == LUA_SIGNATURE[0]) {
        compile_error = "binary chunks are not allowed";
        compile_error_len = std::strlen(compile_error);
    } else if (luaL_loadbuffer(L, body.data(), body.size(), "@user_script") != 0) {
        compile_error = lua_tolstring(L, -1, &compile_error_len);
    } else {
        lua_setfield(L, LUA_REGISTRYINDEX, k_chunk_key);
        return 0;
    }
    try {
        st.compile_error.assign(compile_error != nullptr ? compile_error : "?",
                                compile_error != nullptr ? compile_error_len : 1);
    } catch (...) {
        st.compile_error.clear();
    }
    return 0;
}

/// Converts the value on top of the stack (index 2 of the cpcall frame) the
/// way Redis turns a script's return value into a reply (RESP2).
inline void convert_value(lua_State* L, lua_run_state& st, lua_reply& out, std::size_t depth) {
    const auto charge = [&](std::size_t bytes) {
        if (bytes > st.result_budget) {
            st.result_budget = 0;
            st.result_too_big = true;
            return false;
        }
        st.result_budget -= bytes;
        return true;
    };
    if (!charge(sizeof(lua_reply))) {
        return;
    }
    if (depth > k_lua_reply_max_depth || lua_checkstack(L, 3) == 0) {
        st.result_too_deep = true;
        return;
    }
    switch (lua_type(L, -1)) {
        case LUA_TSTRING: {
            std::size_t len = 0;
            const char* s = lua_tolstring(L, -1, &len);
            if (!charge(len)) {
                return;
            }
            out.type = lua_reply::kind::bulk;
            out.text.assign(s, len);
            return;
        }
        case LUA_TBOOLEAN:
            if (lua_toboolean(L, -1) != 0) {
                out.type = lua_reply::kind::integer;
                out.integer = 1;
            }
            return;
        case LUA_TNUMBER:
            out.type = lua_reply::kind::integer;
            out.integer = kythira_lua_num2ll(lua_tonumber(L, -1));
            return;
        case LUA_TTABLE: {
            for (const char* field : {"err", "ok"}) {
                lua_pushstring(L, field);
                lua_rawget(L, -2);
                if (lua_type(L, -1) == LUA_TSTRING) {
                    std::size_t len = 0;
                    const char* s = lua_tolstring(L, -1, &len);
                    if (charge(len)) {
                        out.type =
                            field[0] == 'e' ? lua_reply::kind::error : lua_reply::kind::status;
                        out.text.assign(s, len);
                    }
                    lua_pop(L, 1);
                    return;
                }
                lua_pop(L, 1);
            }
            out.type = lua_reply::kind::array;
            for (int j = 1;; ++j) {
                lua_rawgeti(L, -1, j);
                if (lua_isnil(L, -1)) {
                    lua_pop(L, 1);
                    break;
                }
                out.elements.emplace_back();
                convert_value(L, st, out.elements.back(), depth + 1);
                lua_pop(L, 1);
                if (st.result_too_big || st.result_too_deep) {
                    return;
                }
            }
            return;
        }
        default:  // nil, functions, userdata, threads
            return;
    }
}

/// Called under lua_pcall with (state, value): converts the value the
/// script returned. A C++ exception (allocation failure) is turned into
/// "too big" inside the try so it never crosses a Lua frame.
inline auto convert_result(lua_State* L) -> int {
    auto& st = *static_cast<lua_run_state*>(lua_touserdata(L, 1));
    lua_remove(L, 1);
    try {
        st.result = lua_reply{};
        convert_value(L, st, st.result, 0);
    } catch (...) {
        st.result_too_big = true;
    }
    return 0;
}

struct state_closer {
    void operator()(lua_State* L) const noexcept { lua_close(L); }
};

[[nodiscard]] inline auto error_text(lua_State* L, int index) -> std::string {
    // The script raised: a string (with position), or a table such as the
    // {err=...} redis.call raises.
    if (lua_type(L, index) == LUA_TSTRING) {
        std::size_t len = 0;
        const char* s = lua_tolstring(L, index, &len);
        return std::string(s, len);
    }
    if (lua_type(L, index) == LUA_TTABLE) {
        // rawget: a metamethod here would run script code with no budget.
        lua_pushvalue(L, index);
        lua_pushliteral(L, "err");
        lua_rawget(L, -2);
        std::string text;
        if (lua_type(L, -1) == LUA_TSTRING) {
            std::size_t len = 0;
            const char* s = lua_tolstring(L, -1, &len);
            text.assign(s, len);
        }
        lua_pop(L, 2);
        if (!text.empty()) {
            return text;
        }
    }
    return "ERR Script raised an error that is not a string";
}

}  // namespace lua_sandbox_detail

/// Runs one script in a fresh sandbox. `kill` (front end only) stops the
/// script at its next hook firing once it reads true.
[[nodiscard]] inline auto run_lua_script(const lua_sandbox_config& config,
                                         const lua_script_call& call,
                                         const lua_command_handler& handler,
                                         const std::atomic<bool>* kill = nullptr)
    -> lua_script_result {
    namespace d = lua_sandbox_detail;
    d::lua_run_state st;
    st.config = &config;
    st.handler = &handler;
    st.call = &call;
    st.random.seed_state(call.seed);
    if (config.mode == lua_script_mode::front_end) {
        st.kill = kill;
        if (config.limits.wall_time.count() > 0) {
            st.has_deadline = true;
            st.deadline = std::chrono::steady_clock::now() + config.limits.wall_time;
        }
    }

    lua_script_result result;
    const auto finish_aborted = [&](d::abort_reason reason) {
        switch (reason) {
            case d::abort_reason::instruction_budget:
                result.status = lua_script_status::instruction_budget;
                break;
            case d::abort_reason::memory_cap:
                result.status = lua_script_status::memory_cap;
                break;
            case d::abort_reason::wall_time:
                result.status = lua_script_status::wall_time;
                break;
            case d::abort_reason::killed:
                result.status = lua_script_status::killed;
                break;
            case d::abort_reason::none:
                break;
        }
        result.reply = lua_reply::error(d::abort_message(reason));
    };

    std::unique_ptr<lua_State, d::state_closer> owner(lua_newstate(&d::sandbox_alloc, &st));
    lua_State* L = owner.get();
    if (L == nullptr) {
        result.status = lua_script_status::error;
        result.reply = lua_reply::error("ERR could not create the Lua interpreter");
        return result;
    }

    // Setup and compile, protected.
    const int setup_rc = lua_cpcall(L, &d::setup, &st);
    if (setup_rc != 0) {
        result.status = lua_script_status::error;
        result.reply =
            lua_reply::error("ERR could not set up the Lua sandbox: " + d::error_text(L, -1));
        return result;
    }
    lua_getfield(L, LUA_REGISTRYINDEX, d::k_chunk_key);
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        result.status = lua_script_status::error;
        result.reply =
            lua_reply::error("ERR Error compiling script (new function): " + st.compile_error);
        return result;
    }

    // Run, under both budgets.
    st.baseline = st.allocated;
    st.peak = 0;
    st.cap_armed = true;
    lua_sethook(L, &d::count_hook, LUA_MASKCOUNT, static_cast<int>(k_lua_hook_interval));
    const int run_rc = lua_pcall(L, 0, 1, 0);

    result.instructions = st.instructions;
    result.resp_version = st.resp_version;
    if (st.abort != d::abort_reason::none) {
        result.peak_memory = st.peak;
        finish_aborted(st.abort);
        return result;
    }
    if (run_rc != 0) {
        lua_sethook(L, nullptr, 0, 0);
        st.cap_armed = false;
        result.peak_memory = st.peak;
        result.status = lua_script_status::error;
        result.reply = lua_reply::error(d::error_text(L, -1));
        return result;
    }

    // Convert the return value. The budget left for the reply is what the
    // script did not use of the cap; the interpreter's own allocations are
    // no longer limited (they are a few bytes of stack at most here).
    lua_sethook(L, nullptr, 0, 0);
    st.cap_armed = false;
    result.peak_memory = st.peak;
    const std::size_t used = st.in_use();
    st.result_budget = used < config.limits.memory_cap ? config.limits.memory_cap - used : 0;
    // lua_cpcall carries only a light userdata, so the converter runs under
    // lua_pcall with (state, value) instead.
    lua_pushcfunction(L, &d::convert_result);
    lua_insert(L, -2);  // function, value
    lua_pushlightuserdata(L, &st);
    lua_insert(L, -2);  // function, state, value
    const int convert_rc = lua_pcall(L, 2, 0, 0);
    if (convert_rc != 0 || st.result_too_big) {
        result.status = lua_script_status::memory_cap;
        result.reply = lua_reply::error(d::abort_message(d::abort_reason::memory_cap));
        return result;
    }
    if (st.result_too_deep) {
        result.status = lua_script_status::error;
        result.reply = lua_reply::error("ERR reached lua stack limit");
        return result;
    }
    result.status = lua_script_status::ok;
    result.reply = std::move(st.result);
    return result;
}

}  // namespace kythira
