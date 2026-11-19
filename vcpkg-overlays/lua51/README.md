# lua51 overlay port

Lua 5.1.5 for the Redis gateway's scripts
(`.kiro/specs/redis-general-data-types/` Requirement 30, design Component
13), consumed by `services/redis/include/kythira/redis/lua_sandbox.hpp` as
`lua51::lua51`. It is a default dependency in `vcpkg.json`: it builds in
seconds, and a default dependency is in every cached `vcpkg_installed` tree,
where an opt-in feature would be missing from the trees of jobs that never
asked for it.

## Source

Valkey's `deps/lua` at tag `9.0.8` (commit `825e3b1f`), fetched with
`vcpkg_from_git`, rather than the lua.org tarball:

- It is Lua 5.1.5 plus the four libraries Redis scripts expect: `cjson`,
  `cmsgpack`, `bit` and `struct`. Valkey is the BSD fork of Redis 7.2, so
  these are the same files Redis shipped under BSD.
- It carries the security fixes Redis and Valkey made to Lua 5.1 and to
  those libraries, which a plain 5.1.5 lacks.
- It has `lua_enablereadonlytable`, which the sandbox uses so a script can
  neither assign nor `rawset` a global or a library field.

The vendored `CMakeLists.txt` builds the interpreter, its standard libraries
and the four libraries as one static library, plus `deps/fpconv`'s
`fpconv_dtoa` (Grisu2), which Valkey uses to turn a non-integral number
argument of `redis.call` into text. Valkey's own CMakeLists is not used: it
also compiles the standalone `lua.c` (with a `main()`) and has no install
rules. Headers install under `include/lua51/`; consumers include
`<kythira_lua.h>`, which adds the `extern "C"` guards Lua 5.1's headers lack
and declares the libraries' `luaopen_*` functions and `fpconv_dtoa`.

To move to a newer Valkey, change `REF` and `FETCH_REF` in `portfile.cmake`,
check the patch still applies, and run `lua_sandbox_unit_test` and
`lua_sandbox_determinism_test`.

## The patch: the same results on amd64 and arm64

A replicated script runs on every replica, and replicas of one group may be
on different architectures. `0001-deterministic-numbers.patch` removes the
differences found between x86-64 and arm64 builds of this tree. Each was
seen to change `lua_sandbox_determinism_test`'s results on arm64 (cross-built
and run under qemu) before the fix:

| Where | Stock behaviour | Patched |
|---|---|---|
| `lua_number2str` (`tostring`, concatenation) | `sprintf("%.14g")`: C library and locale dependent; 0/0 prints `-nan` on x86-64, `nan` on arm64 | `std::to_chars(general, 14)`, the same text as `%.14g` in the C locale; every NaN prints `nan` |
| `lua_number2int`, `lua_number2integer` | a C cast, undefined out of range: x86-64 gives INT_MIN, arm64 saturates and maps NaN to 0 | saturate, NaN to 0, everywhere |
| `string.format` `%c %d %i %o %u %x %X` | the same undefined cast | the saturating conversion |
| `string.format` `%e %f %g` | prints the NaN sign bit | one NaN |
| `struct.pack` integers, `f`, `d` | undefined cast; NaN bits | saturating; one NaN |
| `cmsgpack.pack` | `(int64_t)x == x` decides int vs float: 2^63 packs as INT64_MAX on arm64 only; NaN bits | range check first; one NaN |
| everything (vendored `CMakeLists.txt`) | GCC contracts `a*b+c` into one fma on arm64, so Lua's `%` (`a - floor(a/b)*b`) differs in the last bit | `-ffp-contract=off` |

The transcendental functions (`math.sin`, `math.exp`, `math.pow`, ...) are
still the C library's. The determinism test pins their exact bits for a set
of inputs, and glibc 2.39's agree on the two architectures today.

## Licences

`share/lua51/copyright` collects them: Lua (MIT, Lua.org, PUC-Rio), `cjson`,
`strbuf` and `fpconv` (MIT, Mark Pulford), `bit` (MIT, Mike Pall),
`cmsgpack` (MIT, Redis Ltd.), `struct` (MIT, Lua.org) and `fpconv_dtoa`
(Boost Software License 1.0). The library notices live in their source
files, so the portfile copies them from there.
