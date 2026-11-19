// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file lua_sandbox_determinism_test.cpp
/// @brief Scripts must give the same results on amd64 and arm64
///        (.kiro/specs/redis-general-data-types/ task 25, Requirement 30.1
///        to 30.3): a replicated script runs on every replica, and replicas
///        of one group may be on different architectures.
///
/// Each case below runs a script in replicated mode and records what it
/// returned, how many instructions it used and how much it allocated. The
/// results are compared with golden/lua/determinism.txt, which was written
/// on amd64. ci.yml runs this test on its amd64 and arm64 legs, so the
/// golden is the cross-architecture check: a result that differs on either
/// architecture fails it there.
///
/// Floating-point results are recorded as their exact bits (struct.pack
/// '>d', in hex), not as text, so a last-bit difference cannot hide behind
/// rounding to 14 digits. The transcendental functions are the C
/// library's; if one of them differs between the architectures this test
/// says which.
///
/// To rewrite the golden after an intended change, run the test with
/// KYTHIRA_LUA_DETERMINISM_GOLDEN_UPDATE=1 and review the diff.

#define BOOST_TEST_MODULE lua_sandbox_determinism_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/lua_sandbox.hpp>

#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#ifndef KYTHIRA_LUA_GOLDEN_FILE
#error "KYTHIRA_LUA_GOLDEN_FILE must name golden/lua/determinism.txt"
#endif

using kythira::lua_reply;
using kythira::lua_sandbox_config;
using kythira::lua_script_call;
using kythira::lua_script_result;
using kythira::lua_script_status;

namespace {

/// Helpers every case can use, prepended to its body.
constexpr const char* prelude = R"(
local function hex(s)
    return (s:gsub('.', function(c) return string.format('%02x', c:byte()) end))
end
local function bits(x) return hex(struct.pack('>d', x)) end
local function list(t, f)
    local out = {}
    for i = 1, #t do out[i] = f(t[i]) end
    return table.concat(out, ' ')
end
)";

struct determinism_case {
    const char* name;
    const char* body;
    std::uint64_t instruction_budget = 50'000'000;
    std::size_t memory_cap = std::size_t{8} << 20;
};

const std::vector<determinism_case>& cases() {
    static const std::vector<determinism_case> all = {
        {"arithmetic", R"(
            local xs = {7.25, -7.25, 1e-300, 1e300, 3, -0.1}
            local ys = {2, -3.5, 1e-10, 0.3}
            local out = {}
            for _, x in ipairs(xs) do
                for _, y in ipairs(ys) do
                    out[#out + 1] = bits(x + y) .. bits(x - y) .. bits(x * y) .. bits(x / y) ..
                                    bits(x % y) .. bits(math.abs(x) ^ y)
                end
            end
            return table.concat(out, ' ')
        )"},
        {"math.sin",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, 100, 1e-5, -2.5, 1e6, 1e22}, function(x) return "
         "bits(math.sin(x)) end)"},
        {"math.cos",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, 100, 1e-5, -2.5, 1e6, 1e22}, function(x) return "
         "bits(math.cos(x)) end)"},
        {"math.tan",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, 100, 1e-5, -2.5, 1e6}, function(x) return "
         "bits(math.tan(x)) end)"},
        {"math.asin",
         "return list({0.1, 0.5, 0.99, -0.3, 1e-5}, function(x) return bits(math.asin(x)) end)"},
        {"math.acos",
         "return list({0.1, 0.5, 0.99, -0.3, 1e-5}, function(x) return bits(math.acos(x)) end)"},
        {"math.atan",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, 100, -2.5}, function(x) return bits(math.atan(x)) "
         "end)"},
        {"math.atan2",
         "return list({0.1, 0.5, 1, -2, 3.7}, function(x) return bits(math.atan2(x, 1.3)) .. "
         "bits(math.atan2(-1.3, x)) end)"},
        {"math.sinh",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, -2.5}, function(x) return bits(math.sinh(x)) end)"},
        {"math.cosh",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, -2.5}, function(x) return bits(math.cosh(x)) end)"},
        {"math.tanh",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, -2.5}, function(x) return bits(math.tanh(x)) end)"},
        {"math.exp",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, 100, -2.5, 700, -700}, function(x) return "
         "bits(math.exp(x)) end)"},
        {"math.log",
         "return list({0.1, 0.5, 1, 2, 3.7, 10, 100, 1e-300, 1e300}, function(x) return "
         "bits(math.log(x)) end)"},
        {"math.log10",
         "return list({0.1, 0.5, 2, 3.7, 10, 1000, 1e-300}, function(x) return bits(math.log10(x)) "
         "end)"},
        {"math.pow",
         "return list({0.1, 0.5, 2, 3.7, 10, 1e10}, function(x) return bits(math.pow(x, 1.7)) .. "
         "bits(x ^ -0.33) end)"},
        {"math.sqrt",
         "return list({0.1, 0.5, 2, 3.7, 10, 1e10}, function(x) return bits(math.sqrt(x)) end)"},
        {"math.fmod",
         "return list({7.5, -7.5, 1e10, 0.1}, function(x) return bits(math.fmod(x, 0.3)) end)"},
        {"math.exact", R"(
            return list({7.5, -7.5, 1e10, 0.1, 2^60 + 0.5}, function(x)
                local m, e = math.frexp(x)
                local i, f = math.modf(x)
                return bits(math.floor(x)) .. bits(math.ceil(x)) .. bits(m) .. e .. bits(math.ldexp(x, -3)) ..
                       bits(i) .. bits(f) .. bits(math.deg(x)) .. bits(math.rad(x))
            end)
        )"},
        {"tostring", R"(
            return list({0.1, 1/3, 2/3, 100, 1e14, 1e15, 1e100, -1e-100, 2^53, 2^63, 123456789.123456789,
                         5e-324, 1.7976931348623157e308, 1/0, -1/0, 0/0}, tostring)
        )"},
        {"string.format", R"(
            return list({0.1, 1/3, -2.5, 1e100, 12345.678, 0/0, 1/0}, function(x)
                return string.format('%.17g|%e|%.3f|%g|%10.4G', x, x, x, x, x)
            end) .. ' ' .. list({1, -1, 2^31, 2^53, -2^63, 1e300, 0/0}, function(x)
                return string.format('%d|%x|%o|%5.3d', x, x, x, x)
            end)
        )"},
        {"tonumber", R"(
            return list({'0.1', '1e400', '-1e-400', '0x10', '  42  ', '1e', 'inf', 'nan', '9007199254740993'},
                        function(s) local n = tonumber(s) return n and bits(n) or 'nil' end)
        )"},
        {"cjson", R"(
            local t = {a = 1.5, b = {1, 2, 3.25}, c = 'x"y', d = false, e = 1e100, f = 1/3}
            local s = cjson.encode(t)
            local u = cjson.decode('{"k":[1,2.5,"z",null,true],"n":-0.000001,"big":12345678901234567890}')
            return s .. ' ' .. cjson.encode(u) .. ' ' .. bits(u.n) .. ' ' .. bits(u.big)
        )"},
        {"cmsgpack", R"(
            local packed = cmsgpack.pack({1, -1, 300, -70000, 2^40, 1.5, 0.1, 2^63, 'str', true, {k = 'v'}, 0/0})
            local back = {cmsgpack.unpack(packed)}
            return hex(packed) .. ' ' .. #back .. ' ' .. bits(back[1][7])
        )"},
        {"bit", R"(
            return list({1, -1, 0x7fffffff, 2^32 + 5, -2^40, 3.7, 1e20}, function(x)
                return bit.tobit(x) .. '|' .. bit.band(x, 0xff00ff) .. '|' .. bit.bor(x, 1) .. '|' ..
                       bit.bxor(x, -1) .. '|' .. bit.lshift(x, 3) .. '|' .. bit.rshift(x, 3) .. '|' ..
                       bit.arshift(x, 3) .. '|' .. bit.rol(x, 7) .. '|' .. bit.tohex(x)
            end)
        )"},
        {"struct", R"(
            local p = struct.pack('<i4>i8Bhdfs', -2, 2^40, 255, -300, 0.1, 0.1, 'abc')
            local a, b, c, d, e, f, g = struct.unpack('<i4>i8Bhdfs', p)
            return hex(p) .. ' ' .. a .. ' ' .. b .. ' ' .. c .. ' ' .. d .. ' ' .. bits(e) .. ' ' .. bits(f) ..
                   ' ' .. g .. ' ' .. hex(struct.pack('<L', 1e300)) .. ' ' .. hex(struct.pack('<l', -1e300))
        )"},
        {"random.seed", R"(
            local out = {}
            for i = 1, 8 do out[#out + 1] = bits(math.random()) end
            for i = 1, 8 do out[#out + 1] = math.random(1, 1000000) end
            return table.concat(out, ' ')
        )"},
        {"random.randomseed", R"(
            math.randomseed(-123456)
            local out = {}
            for i = 1, 8 do out[#out + 1] = math.random(100) end
            return table.concat(out, ' ')
        )"},
        {"pairs.order", R"(
            local t = {}
            for i = 1, 60 do t['key' .. (i * 7919 % 1000)] = i end
            for i = 1, 20 do t[i * 1.5] = i end
            t[true] = 'b'
            local out = {}
            for k, v in pairs(t) do out[#out + 1] = tostring(k) .. '=' .. tostring(v) end
            return table.concat(out, ',')
        )"},
        {"strings", R"(
            local s = string.rep('abc', 50) .. 'Hello, World! 123'
            local words = {}
            for w in s:gmatch('%a+') do words[#words + 1] = w:upper() end
            local sorted = {}
            for i = 1, 30 do sorted[i] = tostring((i * 37) % 101) end
            table.sort(sorted, function(a, b) return #a == #b and a > b or #a < #b end)
            return #words .. ' ' .. s:find('World', 1, true) .. ' ' .. s:gsub('b', 'B'):sub(1, 20) .. ' ' ..
                   string.format('%q', 'a\n"b"\0c') .. ' ' .. table.concat(sorted, ',') .. ' ' ..
                   redis.sha1hex(s)
        )"},
        {"objects", R"(
            local a, b = {}, {}
            return tostring(a) .. ' ' .. tostring(rawget(_G, 'print') == nil) .. ' ' .. tostring(b) .. ' ' .. tostring(a) ..
                   ' ' .. tostring(function() end) .. ' ' .. tostring(coroutine.create(function() end))
        )"},
        {"workload", R"(
            local t = {}
            for i = 1, 2000 do t[i] = string.format('member:%06d:%s', (i * 7919) % 2000, tostring(i / 7)) end
            table.sort(t)
            local h = {}
            for i, v in ipairs(t) do h[v] = i end
            local sum = 0
            for i = 1, #t, 13 do sum = sum + h[t[i]] end
            return sum .. ' ' .. t[1] .. ' ' .. t[#t] .. ' ' .. redis.sha1hex(table.concat(t))
        )"},
        {"budget.instructions", "local i = 0 while true do i = i + 1 end", 2'500'000},
        {"budget.memory",
         "local t = {} for i = 1, 1e7 do t[#t + 1] = string.rep('m', 100) .. i end", 50'000'000,
         std::size_t{2} << 20},
        {"budget.collectgarbage", R"(
            local t = {}
            for i = 1, 5000 do t[i] = {i, tostring(i)} end
            t = nil
            local before = collectgarbage('count')
            collectgarbage('collect')
            return bits(before) .. ' ' .. bits(collectgarbage('count'))
        )"},
    };
    return all;
}

auto status_name(lua_script_status s) -> const char* {
    switch (s) {
        case lua_script_status::ok:
            return "ok";
        case lua_script_status::error:
            return "error";
        case lua_script_status::instruction_budget:
            return "instruction_budget";
        case lua_script_status::memory_cap:
            return "memory_cap";
        case lua_script_status::wall_time:
            return "wall_time";
        case lua_script_status::killed:
            return "killed";
    }
    return "?";
}

auto reply_text(const lua_reply& r) -> std::string {
    switch (r.type) {
        case lua_reply::kind::nil:
            return "nil";
        case lua_reply::kind::integer:
            return std::to_string(r.integer);
        case lua_reply::kind::bulk:
        case lua_reply::kind::status:
        case lua_reply::kind::error:
            return r.text;
        case lua_reply::kind::array: {
            std::string out = "[";
            for (const auto& e : r.elements) {
                out += reply_text(e) + ";";
            }
            return out + "]";
        }
    }
    return "?";
}

/// One golden line per case: name, status, instructions, peak bytes, reply.
auto run_case(const determinism_case& c) -> std::string {
    lua_sandbox_config config;
    config.limits.instruction_budget = c.instruction_budget;
    config.limits.memory_cap = c.memory_cap;
    const std::string body = std::string(prelude) + c.body;
    const lua_script_call call{body, {}, {}, 0x5eed'0000'0042ULL};
    const kythira::lua_command_handler handler = [](std::span<const std::string>) {
        return lua_reply::error("ERR no commands in this test");
    };
    const lua_script_result r = kythira::run_lua_script(config, call, handler);
    // One line per case: newlines and tabs in a reply are escaped.
    std::string text;
    for (const char ch : reply_text(r.reply)) {
        if (ch == '\n') {
            text += "\\n";
        } else if (ch == '\t') {
            text += "\\t";
        } else if (ch == '\\') {
            text += "\\\\";
        } else {
            text += ch;
        }
    }
    std::ostringstream line;
    line << c.name << '\t' << status_name(r.status) << '\t' << r.instructions << '\t'
         << r.peak_memory << '\t' << text;
    return line.str();
}

auto read_golden(const std::string& path) -> std::map<std::string, std::string> {
    std::map<std::string, std::string> golden;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        golden.emplace(line.substr(0, line.find('\t')), line);
    }
    return golden;
}

}  // namespace

BOOST_AUTO_TEST_CASE(results_match_the_golden_on_this_architecture,
                     *boost::unit_test::timeout(300)) {
    std::vector<std::string> lines;
    for (const auto& c : cases()) {
        lines.push_back(run_case(c));
    }

    if (const char* update = std::getenv("KYTHIRA_LUA_DETERMINISM_GOLDEN_UPDATE");
        update != nullptr && std::string(update) == "1") {
        std::ofstream out(KYTHIRA_LUA_GOLDEN_FILE);
        out << "# Copyright (c) 2026 Clark Rawlins\n"
               "# SPDX-License-Identifier: Apache-2.0\n"
               "\n"
               "# lua_sandbox_determinism_test's expected results, one case per line:\n"
               "# name, status, instructions, peak bytes, reply (tab separated).\n"
               "# Written on amd64; ci.yml checks it on amd64 and arm64. Regenerate\n"
               "# with KYTHIRA_LUA_DETERMINISM_GOLDEN_UPDATE=1 and review the diff.\n";
        for (const auto& l : lines) {
            out << l << '\n';
        }
        BOOST_TEST_MESSAGE("rewrote " << KYTHIRA_LUA_GOLDEN_FILE);
        return;
    }

    const auto golden = read_golden(KYTHIRA_LUA_GOLDEN_FILE);
    BOOST_REQUIRE_MESSAGE(!golden.empty(), "no golden at " << KYTHIRA_LUA_GOLDEN_FILE);
    BOOST_CHECK_EQUAL(golden.size(), lines.size());
    for (const auto& line : lines) {
        const std::string name = line.substr(0, line.find('\t'));
        BOOST_TEST_CONTEXT("case " << name) {
            const auto it = golden.find(name);
            BOOST_REQUIRE_MESSAGE(it != golden.end(), "no golden line for " << name);
            BOOST_CHECK_EQUAL(line, it->second);
        }
    }
}

// The same script twice in one process: nothing carries over between runs
// (a fresh interpreter each time), so even the allocation profile repeats.
BOOST_AUTO_TEST_CASE(runs_are_independent, *boost::unit_test::timeout(120)) {
    for (const auto& c : cases()) {
        BOOST_TEST_CONTEXT("case " << c.name) {
            BOOST_CHECK_EQUAL(run_case(c), run_case(c));
        }
    }
}
