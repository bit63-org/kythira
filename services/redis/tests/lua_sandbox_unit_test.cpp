// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file lua_sandbox_unit_test.cpp
/// @brief The Lua script sandbox (.kiro/specs/redis-general-data-types/
///        task 25, Requirement 30): what a script can and cannot reach,
///        the instruction and allocation budgets, the front end's wall-time
///        limit and kill flag, and the conversions between Lua values and
///        replies. Cross-architecture determinism has its own test,
///        lua_sandbox_determinism_test.

#define BOOST_TEST_MODULE lua_sandbox_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/lua_sandbox.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

using kythira::lua_command_handler;
using kythira::lua_reply;
using kythira::lua_sandbox_config;
using kythira::lua_script_call;
using kythira::lua_script_mode;
using kythira::lua_script_result;
using kythira::lua_script_status;
using kind = lua_reply::kind;

namespace {

struct recorded_calls {
    std::vector<std::vector<std::string>> argv;
};

/// A handler that records every call and answers from a small table of
/// commands, enough to exercise each reply type.
auto make_handler(recorded_calls& calls) -> lua_command_handler {
    return [&calls](std::span<const std::string> argv) -> lua_reply {
        calls.argv.emplace_back(argv.begin(), argv.end());
        const std::string& cmd = argv[0];
        if (cmd == "PING") {
            return lua_reply::status("PONG");
        }
        if (cmd == "GET") {
            return argv.size() > 1 && argv[1] == "missing" ? lua_reply::nil()
                                                           : lua_reply::bulk("value");
        }
        if (cmd == "SET") {
            return lua_reply::status("OK");
        }
        if (cmd == "INCR") {
            return lua_reply::from_integer(42);
        }
        if (cmd == "LRANGE") {
            return lua_reply::array(
                {lua_reply::bulk("a"), lua_reply::from_integer(7), lua_reply::nil(),
                 lua_reply::array({lua_reply::bulk("nested")}), lua_reply::error("ERR inner")});
        }
        if (cmd == "THROW") {
            throw std::runtime_error("boom");
        }
        return lua_reply::error("ERR unknown command '" + cmd + "'");
    };
}

auto run(std::string_view body, lua_sandbox_config config = {}, std::vector<std::string> keys = {},
         std::vector<std::string> args = {}, std::uint64_t seed = 0) -> lua_script_result {
    recorded_calls calls;
    const auto handler = make_handler(calls);
    const lua_script_call call{body, keys, args, seed};
    return kythira::run_lua_script(config, call, handler);
}

auto front_end() -> lua_sandbox_config {
    lua_sandbox_config c;
    c.mode = lua_script_mode::front_end;
    return c;
}

auto ok_bulk(const lua_script_result& r) -> std::string {
    BOOST_TEST_INFO("status " << static_cast<int>(r.status) << " reply " << r.reply.text);
    BOOST_REQUIRE(r.status == lua_script_status::ok);
    BOOST_REQUIRE(r.reply.type == kind::bulk);
    return r.reply.text;
}

auto ok_integer(const lua_script_result& r) -> std::int64_t {
    BOOST_TEST_INFO("status " << static_cast<int>(r.status) << " reply " << r.reply.text);
    BOOST_REQUIRE(r.status == lua_script_status::ok);
    BOOST_REQUIRE(r.reply.type == kind::integer);
    return r.reply.integer;
}

auto error_text(const lua_script_result& r) -> std::string {
    BOOST_REQUIRE(r.status == lua_script_status::error);
    BOOST_REQUIRE(r.reply.type == kind::error);
    return r.reply.text;
}

auto contains(const std::string& haystack, std::string_view needle) -> bool {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

// ---------------------------------------------------------------------------
// What a script can reach (Requirement 30.2, 30.4).

BOOST_AUTO_TEST_CASE(globals_are_exactly_the_allow_list, *boost::unit_test::timeout(30)) {
    const auto r = run(R"(
        local names = {}
        for k in pairs(_G) do names[#names + 1] = k end
        table.sort(names)
        return table.concat(names, ' ')
    )");
    BOOST_CHECK_EQUAL(
        ok_bulk(r),
        "ARGV KEYS _G _VERSION assert bit cjson cmsgpack collectgarbage coroutine error gcinfo "
        "getmetatable ipairs math next pairs pcall rawequal rawget rawset redis select server "
        "setmetatable string struct table tonumber tostring type unpack xpcall");
    // The front end also has os, with clock alone.
    const auto fe = run(R"(
        local names = {}
        for k in pairs(os) do names[#names + 1] = k end
        return table.concat(names, ' ') .. ' ' .. type(os.clock())
    )",
                        front_end());
    BOOST_CHECK_EQUAL(ok_bulk(fe), "clock number");
}

BOOST_AUTO_TEST_CASE(removed_functions_are_unreachable, *boost::unit_test::timeout(30)) {
    for (const char* name :
         {"loadstring", "load", "dofile", "loadfile", "print", "require", "module", "package", "io",
          "debug", "newproxy", "setfenv", "getfenv", "os"}) {
        BOOST_TEST_CONTEXT(name) {
            const auto r = run(std::string("return type(") + name + ")");
            BOOST_CHECK(
                contains(error_text(r),
                         std::string("Script attempted to access nonexistent global variable '") +
                             name + "'"));
        }
    }
}

BOOST_AUTO_TEST_CASE(globals_and_libraries_are_read_only, *boost::unit_test::timeout(30)) {
    BOOST_CHECK(contains(error_text(run("x = 1")), "Attempt to modify a readonly table"));
    BOOST_CHECK(
        contains(error_text(run("rawset(_G, 'x', 1)")), "Attempt to modify a readonly table"));
    BOOST_CHECK(
        contains(error_text(run("string.upper = nil")), "Attempt to modify a readonly table"));
    BOOST_CHECK(contains(error_text(run("redis.call = function() end")),
                         "Attempt to modify a readonly table"));
    BOOST_CHECK(
        contains(error_text(run("setmetatable(_G, nil)")), "Attempt to modify a readonly table"));
    BOOST_CHECK(contains(error_text(run("getmetatable('').__index = {}")),
                         "Attempt to modify a readonly table"));
    BOOST_CHECK(contains(error_text(run("math.random = function() return 4 end")),
                         "Attempt to modify a readonly table"));
    // Locals, new tables, KEYS and ARGV stay writable.
    BOOST_CHECK_EQUAL(
        ok_bulk(run("local t = {} t.x = 'y' KEYS[1] = 'k2' return t.x .. KEYS[1]", {}, {"k1"})),
        "yk2");
}

BOOST_AUTO_TEST_CASE(bytecode_is_refused, *boost::unit_test::timeout(30)) {
    std::string chunk = "\x1bLua";
    chunk.push_back('\x51');
    chunk += std::string(32, '\0');
    const auto r = run(chunk);
    BOOST_CHECK(contains(error_text(r), "binary chunks are not allowed"));
    // string.dump still exists, but nothing can load what it writes.
    const auto dumped = run("return string.dump(function() return 1 end)");
    BOOST_CHECK(dumped.status == lua_script_status::ok);
}

BOOST_AUTO_TEST_CASE(compile_errors_are_reported, *boost::unit_test::timeout(30)) {
    const auto r = run("return (");
    const std::string text = error_text(r);
    BOOST_CHECK(contains(text, "Error compiling script"));
    BOOST_CHECK(contains(text, "user_script:1:"));
}

BOOST_AUTO_TEST_CASE(runtime_errors_carry_the_script_position, *boost::unit_test::timeout(30)) {
    BOOST_CHECK_EQUAL(error_text(run("\n\nerror('bad thing')")), "user_script:3: bad thing");
    BOOST_CHECK_EQUAL(error_text(run("error({err='ERR custom'})")), "ERR custom");
}

BOOST_AUTO_TEST_CASE(keys_and_argv_are_set, *boost::unit_test::timeout(30)) {
    const auto r =
        run("return {#KEYS, #ARGV, KEYS[1], ARGV[2]}", {}, {"k1", "k2"}, {"a1", "a2", "a3"});
    BOOST_REQUIRE(r.status == lua_script_status::ok);
    BOOST_CHECK(r.reply == lua_reply::array({lua_reply::from_integer(2), lua_reply::from_integer(3),
                                             lua_reply::bulk("k1"), lua_reply::bulk("a2")}));
}

// ---------------------------------------------------------------------------
// redis.* and the conversions both ways.

BOOST_AUTO_TEST_CASE(call_converts_every_reply_type, *boost::unit_test::timeout(30)) {
    const auto r = run(R"(
        local out = {}
        local s = redis.call('PING')
        out[#out + 1] = type(s) .. ':' .. s.ok
        out[#out + 1] = redis.call('GET', 'k')
        out[#out + 1] = tostring(redis.call('GET', 'missing'))
        out[#out + 1] = redis.call('INCR', 'k') + 1
        local a = redis.call('LRANGE', 'l', 0, -1)
        out[#out + 1] = a[1] .. a[2] .. tostring(a[3]) .. a[4][1] .. a[5].err
        return table.concat(out, ',')
    )");
    BOOST_CHECK_EQUAL(ok_bulk(r), "table:PONG,value,false,43,a7falsenestedERR inner");
}

BOOST_AUTO_TEST_CASE(call_raises_and_pcall_returns_error_replies, *boost::unit_test::timeout(30)) {
    BOOST_CHECK_EQUAL(error_text(run("return redis.call('NOPE')")), "ERR unknown command 'NOPE'");
    const auto r = run("local e = redis.pcall('NOPE') return e.err");
    BOOST_CHECK_EQUAL(ok_bulk(r), "ERR unknown command 'NOPE'");
    // pcall around redis.call sees the same {err=} table Redis 7 raises.
    const auto p =
        run("local ok, e = pcall(redis.call, 'NOPE') return tostring(ok) .. ' ' .. e.err");
    BOOST_CHECK_EQUAL(ok_bulk(p), "false ERR unknown command 'NOPE'");
    // A handler that throws is an error reply, not a crash.
    BOOST_CHECK_EQUAL(error_text(run("return redis.call('THROW')")), "ERR boom");
}

BOOST_AUTO_TEST_CASE(call_arguments_are_checked_and_converted, *boost::unit_test::timeout(30)) {
    BOOST_CHECK(
        contains(error_text(run("return redis.call()")), "Please specify at least one argument"));
    BOOST_CHECK(contains(error_text(run("return redis.call('GET', {})")),
                         "Lua redis lib command arguments must be strings or integers"));
    BOOST_CHECK(contains(ok_bulk(run("return redis.pcall('GET', nil).err")),
                         "must be strings or integers"));

    recorded_calls calls;
    const auto handler = make_handler(calls);
    const lua_script_call call{
        "local inf = math.huge redis.call('SET', 'k', 3, 3.0, -7, 0.1, 1/3, 2^62, 2^63, 1e300, inf "
        "- inf, inf, "
        "-inf, -0.0)",
        {},
        {},
        0};
    const auto r = kythira::run_lua_script(lua_sandbox_config{}, call, handler);
    BOOST_TEST_INFO(r.reply.text);
    BOOST_REQUIRE(r.status == lua_script_status::ok);
    BOOST_REQUIRE_EQUAL(calls.argv.size(), 1U);
    // Integral and within 2^62: the integer. Otherwise the shortest text
    // that reads back as the same double, as Valkey writes it.
    const std::vector<std::string> expected{"SET",
                                            "k",
                                            "3",
                                            "3",
                                            "-7",
                                            "0.1",
                                            "0.3333333333333333",
                                            "4611686018427387904",
                                            "9223372036854776000",
                                            "1e+300",
                                            "nan",
                                            "inf",
                                            "-inf",
                                            "0"};
    BOOST_CHECK_EQUAL_COLLECTIONS(calls.argv[0].begin(), calls.argv[0].end(), expected.begin(),
                                  expected.end());
}

BOOST_AUTO_TEST_CASE(return_values_convert_as_in_redis, *boost::unit_test::timeout(30)) {
    BOOST_CHECK(run("return nil").reply == lua_reply::nil());
    BOOST_CHECK(run("return false").reply == lua_reply::nil());
    BOOST_CHECK(run("return true").reply == lua_reply::from_integer(1));
    BOOST_CHECK_EQUAL(ok_integer(run("return 3.99")), 3);
    BOOST_CHECK_EQUAL(ok_integer(run("return -3.99")), -3);
    // Out of range and NaN saturate / become 0 on every architecture.
    BOOST_CHECK_EQUAL(ok_integer(run("return 1e300")), INT64_MAX);
    BOOST_CHECK_EQUAL(ok_integer(run("return -1e300")), INT64_MIN);
    BOOST_CHECK_EQUAL(ok_integer(run("return 0/0")), 0);
    BOOST_CHECK(run("return redis.status_reply('FINE')").reply == lua_reply::status("FINE"));
    BOOST_CHECK(run("return {ok='FINE'}").reply == lua_reply::status("FINE"));
    BOOST_CHECK(run("return redis.error_reply('ERR mine')").reply == lua_reply::error("ERR mine"));
    BOOST_CHECK(run("return redis.error_reply('ERR mine')").status == lua_script_status::ok);
    // An array stops at the first nil.
    BOOST_CHECK(run("return {1, 'two', {3}, nil, 5}").reply ==
                lua_reply::array({lua_reply::from_integer(1), lua_reply::bulk("two"),
                                  lua_reply::array({lua_reply::from_integer(3)})}));
    BOOST_CHECK(run("return {}").reply == lua_reply::array({}));
    BOOST_CHECK(run("return function() end").reply == lua_reply::nil());
}

BOOST_AUTO_TEST_CASE(cyclic_and_exploding_replies_are_bounded, *boost::unit_test::timeout(60)) {
    BOOST_CHECK_EQUAL(error_text(run("local t = {} t[1] = t return t")),
                      "ERR reached lua stack limit");
    // 40 levels of a two-element table whose elements are the same child:
    // 2^40 leaves from a few kilobytes of Lua data.
    const auto r = run(R"(
        local t = {1}
        for i = 1, 40 do t = {t, t} end
        return t
    )");
    BOOST_CHECK(r.status == lua_script_status::memory_cap);
}

BOOST_AUTO_TEST_CASE(sha1hex_matches_redis, *boost::unit_test::timeout(30)) {
    BOOST_CHECK_EQUAL(ok_bulk(run("return redis.sha1hex('')")),
                      "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    BOOST_CHECK_EQUAL(ok_bulk(run("return redis.sha1hex('Pizza & Mandolino')")),
                      "74822d82031af7493c20eefa13bd07ec4fada82f");
    BOOST_CHECK(contains(error_text(run("return redis.sha1hex()")), "wrong number of arguments"));
}

BOOST_AUTO_TEST_CASE(redis_helpers_and_constants, *boost::unit_test::timeout(30)) {
    BOOST_CHECK_EQUAL(ok_bulk(run("return redis.REDIS_VERSION .. ' ' .. redis.REDIS_VERSION_NUM")),
                      "7.0.0 458752");
    BOOST_CHECK_EQUAL(ok_integer(run("return redis.LOG_WARNING + redis.REPL_ALL")), 6);
    BOOST_CHECK(run("redis.log(redis.LOG_NOTICE, 'hello')").status == lua_script_status::ok);
    BOOST_CHECK(contains(error_text(run("redis.log(9, 'x')")), "Invalid debug level."));
    BOOST_CHECK(contains(error_text(run("redis.log(1)")), "requires two arguments"));
    BOOST_CHECK(run("redis.set_repl(redis.REPL_NONE) return redis.replicate_commands()").reply ==
                lua_reply::from_integer(1));
    BOOST_CHECK_EQUAL(run("redis.setresp(3)").resp_version, 3);
    BOOST_CHECK(contains(error_text(run("redis.setresp(4)")), "RESP version must be 2 or 3."));
    BOOST_CHECK(run("return server.call == redis.call").reply == lua_reply::from_integer(1));
}

// ---------------------------------------------------------------------------
// Determinism inside one architecture (the cross-architecture half is
// lua_sandbox_determinism_test).

BOOST_AUTO_TEST_CASE(math_random_is_rand48_from_the_seed, *boost::unit_test::timeout(30)) {
    // math.randomseed(n) is srand48(n): the same sequence glibc's lrand48
    // gives, which is the one Valkey's serverLrand48 gives.
    srand48(12345);
    std::string expected;
    for (int i = 0; i < 5; ++i) {
        const long v = lrand48();
        const double r = static_cast<double>(v % 0x7fffffff) / 0x7fffffff;
        expected += std::to_string(static_cast<long long>(std::floor(r * 1000) + 1)) + " ";
    }
    const auto r = run(R"(
        math.randomseed(12345)
        local out = ''
        for i = 1, 5 do out = out .. math.random(1000) .. ' ' end
        return out
    )");
    BOOST_CHECK_EQUAL(ok_bulk(r), expected);

    // Without randomseed the sequence comes from the call's seed: equal
    // seeds agree, different seeds do not.
    const char* draw = "return math.random() .. ' ' .. math.random(10, 20)";
    BOOST_CHECK_EQUAL(ok_bulk(run(draw, {}, {}, {}, 7)), ok_bulk(run(draw, {}, {}, {}, 7)));
    BOOST_CHECK_NE(ok_bulk(run(draw, {}, {}, {}, 7)), ok_bulk(run(draw, {}, {}, {}, 8)));
}

// -0.0 gets a script of its own: Lua 5.1 keeps one constant per number
// value in a function, and 0 == -0, so -0.0 and a literal 0 in the same
// function share whichever was written first (1/0 can become -inf).
// Redis has the same quirk.
BOOST_AUTO_TEST_CASE(tostring_prints_numbers_like_redis, *boost::unit_test::timeout(30)) {
    const auto r = run(R"(
        return table.concat({tostring(0.1), tostring(1/3), tostring(100), tostring(1e15), tostring(1e100),
                             tostring(1/0), tostring(-1/0), tostring(0/0), tostring(-(0/0)),
                             tostring(123456789012345678), 2^53 .. '', tostring(5e-324)}, ' ')
    )");
    BOOST_CHECK_EQUAL(ok_bulk(r),
                      "0.1 0.33333333333333 100 1e+15 1e+100 inf -inf nan nan 1.2345678901235e+17 "
                      "9.007199254741e+15 4.9406564584125e-324");
    BOOST_CHECK_EQUAL(ok_bulk(run("return tostring(-0.0)")), "-0");
}

BOOST_AUTO_TEST_CASE(tostring_hides_addresses, *boost::unit_test::timeout(30)) {
    const auto r = run(R"(
        local a, b = {}, function() end
        return table.concat({tostring(a), tostring(b), tostring(a), tostring(coroutine.create(b)),
                             tostring(setmetatable({}, {__tostring = function() return 'custom' end}))}, ' ')
    )");
    BOOST_CHECK_EQUAL(
        ok_bulk(r),
        "table: 0x00000001 function: 0x00000002 table: 0x00000001 thread: 0x00000003 custom");
}

BOOST_AUTO_TEST_CASE(integer_conversions_saturate, *boost::unit_test::timeout(30)) {
    const auto r = run(R"(
        return table.concat({string.format('%d', 1e300), string.format('%d', -1e300), string.format('%d', 0/0),
                             string.format('%x', -1), string.format('%5.1f', 0/0), ('x'):rep(0/0),
                             string.sub('abcdef', 2^40), string.sub('abcdef', -2^40, 2)}, ',')
    )");
    BOOST_CHECK_EQUAL(ok_bulk(r),
                      "9223372036854775807,-9223372036854775808,0,ffffffffffffffff,  nan,,,ab");
}

// 2^63 packs as a float: it is not an int64. Before the port's patch the
// cast that decides was undefined, and arm64 packed it as INT64_MAX.
BOOST_AUTO_TEST_CASE(nan_packs_to_one_bit_pattern, *boost::unit_test::timeout(30)) {
    const auto r = run(R"(
        local function hex(s) return (s:gsub('.', function(c) return string.format('%02x', c:byte()) end)) end
        return hex(cmsgpack.pack(0/0)) .. ' ' .. hex(cmsgpack.pack(-(0/0))) .. ' ' ..
               hex(struct.pack('<d', 0/0)) .. ' ' .. hex(cmsgpack.pack(2^63)) .. ' ' .. cjson.encode({1.5, 'x'})
    )");
    BOOST_CHECK_EQUAL(
        ok_bulk(r),
        "cb7ff8000000000000 cb7ff8000000000000 000000000000f87f ca5f000000 [1.5,\"x\"]");
}

// ---------------------------------------------------------------------------
// Budgets (Requirement 30.3) and the front end's limits (30.5).

BOOST_AUTO_TEST_CASE(instruction_budget_stops_a_loop_at_a_fixed_point,
                     *boost::unit_test::timeout(60)) {
    lua_sandbox_config c;
    c.limits.instruction_budget = 1'000'000;
    const auto a = run("while true do end", c);
    BOOST_CHECK(a.status == lua_script_status::instruction_budget);
    BOOST_CHECK_EQUAL(a.reply.text, "ERR Script exceeded its instruction budget");
    BOOST_CHECK_EQUAL(a.instructions, 1'001'000U);
    // Same script, same point.
    const auto b = run("while true do end", c);
    BOOST_CHECK_EQUAL(a.instructions, b.instructions);
    // A finished script reports what it used, the same every time.
    const auto small = run("local s = 0 for i = 1, 10000 do s = s + i end return s", c);
    BOOST_CHECK_EQUAL(ok_integer(small), 50005000);
    BOOST_CHECK_EQUAL(
        small.instructions,
        run("local s = 0 for i = 1, 10000 do s = s + i end return s", c).instructions);
}

BOOST_AUTO_TEST_CASE(pcall_cannot_swallow_a_budget_error, *boost::unit_test::timeout(60)) {
    lua_sandbox_config c;
    c.limits.instruction_budget = 100'000;
    const auto r = run(R"(
        local caught = 0
        while true do
            pcall(function() while true do end end)
            caught = caught + 1
            if caught > 3 then return 'escaped' end
        end
    )",
                       c);
    BOOST_CHECK(r.status == lua_script_status::instruction_budget);
    // Nor can a coroutine.
    const auto co = run(R"(
        local co = coroutine.create(function() while true do end end)
        coroutine.resume(co)
        return 'escaped'
    )",
                        c);
    BOOST_CHECK(co.status == lua_script_status::instruction_budget);
}

BOOST_AUTO_TEST_CASE(memory_cap_stops_a_growing_script, *boost::unit_test::timeout(60)) {
    lua_sandbox_config c;
    c.limits.memory_cap = 1 << 20;
    const auto big_string = run("local s = string.rep('x', 4 * 1024 * 1024) return #s", c);
    BOOST_CHECK(big_string.status == lua_script_status::memory_cap);
    BOOST_CHECK_EQUAL(big_string.reply.text, "ERR Script exceeded its memory limit");
    const auto table = run("local t = {} for i = 1, 1e7 do t[i] = i end return #t", c);
    BOOST_CHECK(table.status == lua_script_status::memory_cap);
    // pcall catches "not enough memory" but the run still reports the cap.
    const auto caught =
        run("local ok = pcall(string.rep, 'x', 4 * 1024 * 1024) return tostring(ok)", c);
    BOOST_CHECK(caught.status == lua_script_status::memory_cap);
    // Under the cap, peak memory is reported and repeatable.
    const auto fits = run("local s = string.rep('x', 100000) return #s", c);
    BOOST_CHECK_EQUAL(ok_integer(fits), 100000);
    BOOST_CHECK_GE(fits.peak_memory, 100000U);
    BOOST_CHECK_EQUAL(fits.peak_memory,
                      run("local s = string.rep('x', 100000) return #s", c).peak_memory);
}

BOOST_AUTO_TEST_CASE(replicated_mode_ignores_wall_time, *boost::unit_test::timeout(60)) {
    lua_sandbox_config c;
    c.limits.wall_time = std::chrono::milliseconds(1);
    c.limits.instruction_budget = 20'000'000;
    const auto r = run("while true do end", c);
    BOOST_CHECK(r.status == lua_script_status::instruction_budget);
}

BOOST_AUTO_TEST_CASE(front_end_wall_time_limit, *boost::unit_test::timeout(60)) {
    auto c = front_end();
    c.limits.wall_time = std::chrono::milliseconds(50);
    c.limits.instruction_budget = UINT64_MAX;
    const auto start = std::chrono::steady_clock::now();
    const auto r = run("while true do end", c);
    const auto took = std::chrono::steady_clock::now() - start;
    BOOST_CHECK(r.status == lua_script_status::wall_time);
    BOOST_CHECK_EQUAL(r.reply.text, "ERR Script exceeded its time limit");
    BOOST_CHECK(took >= std::chrono::milliseconds(50));
    BOOST_CHECK(took < std::chrono::seconds(20));
}

BOOST_AUTO_TEST_CASE(front_end_kill_flag, *boost::unit_test::timeout(60)) {
    auto c = front_end();
    c.limits.instruction_budget = UINT64_MAX;
    std::atomic<bool> kill{false};
    recorded_calls calls;
    const auto handler = make_handler(calls);
    const lua_script_call call{
        "while true do pcall(function() while true do end end) end", {}, {}, 0};
    std::thread killer([&kill] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        kill.store(true);
    });
    const auto r = kythira::run_lua_script(c, call, handler, &kill);
    killer.join();
    BOOST_CHECK(r.status == lua_script_status::killed);
    BOOST_CHECK_EQUAL(r.reply.text, "ERR Script killed by user with SCRIPT KILL");
    // Replicated mode never looks at the flag.
    lua_sandbox_config rep;
    rep.limits.instruction_budget = 1'000'000;
    const auto r2 = kythira::run_lua_script(rep, call, handler, &kill);
    BOOST_CHECK(r2.status == lua_script_status::instruction_budget);
}
