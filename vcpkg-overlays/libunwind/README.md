# `libunwind` overlay port

The builtin-baseline's `libunwind` 1.8.3 port (vcpkg commit `9a7f7340`, the
`builtin-baseline` in `vcpkg.json`), copied unchanged apart from the source
archive's SHA512 and `port-version` 1.

## Why

GitHub's archive endpoint now serves different bytes for
`https://github.com/libunwind/libunwind/archive/v1.8.3.tar.gz` than the
baseline port expects, so any build that has to compile libunwind from
source fails at the download:

```
error: download from https://github.com/libunwind/libunwind/archive/v1.8.3.tar.gz had an unexpected hash
note: Expected: 0619716b2385375d...
note: Actual  : f761d5af15e8ab0f...
```

Builds that restore libunwind from a binary cache never download it, which
is why this first showed on 2026-11-20, on the first self-hosted runner jobs
with an empty cache. Upstream vcpkg made the same change on 2026-11-19 in
microsoft/vcpkg#55160 ("[libunwind] Fix SHA512 of source archive"); the new
hash here is that commit's. The tag itself has not moved
(`v1.8.3^{}` is still `7bda80a5`), only GitHub's tarball of it.

The newer upstream port (port-version 3) also moved to `vcpkg-make` and
added `coredump`/`ptrace` features. Those are not taken, so the build is
the baseline's.

## Removing it

Delete this directory and its `overlay-ports` entry in
`vcpkg-configuration.json` once `builtin-baseline` moves past
microsoft/vcpkg@9066d66e.
