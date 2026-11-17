#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
"""Name every object sccache did not serve from the cache.

`sccache --show-stats` counts misses but never says which compile missed.
The server's own log does, one line per lookup, when it runs with
`SCCACHE_LOG=sccache::compiler::compiler=debug` (start-sccache.sh sets that
up when KYTHIRA_SCCACHE_LOG is set):

    [<timestamp> DEBUG sccache::compiler::compiler] [foo.cpp.o]: Cache miss in 0.012 s
    [<timestamp> DEBUG sccache::compiler::compiler] [foo.cpp.o]: Hash key: 3f0a...

sccache prints only the object's file name, so the source behind it comes
from compile_commands.json. Two targets can build objects with one name;
then every candidate source is listed.

This is a report, never a gate: it exits 0 whatever it finds, including a
missing log, so a cache problem can never redden a job (oci-build-cache
Requirement 3.5).

Usage: sccache_misses.py <server-log> [compile_commands.json]
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Every lookup outcome that sends the compile to the compiler. "Cache none"
# and "Cache recache" are forced by flags CI never sets, but they are still
# compiles the cache did not serve, so they are reported rather than hidden.
_OUTCOME = re.compile(
    r"\]: (Cache miss|Cache read error|Cache timed out|Cache none|Cache recache)\b"
)
_OBJECT = re.compile(r"\] \[([^\]]+)\]: ")
_KEY = re.compile(r"\] \[([^\]]+)\]: Hash key: ([0-9a-f]+)")

# start-sccache.sh's probe compile runs before the statistics are zeroed,
# so it is not one of the build's misses either.
_IGNORED = {"probe.o"}


def _sources_by_object(compile_commands):
    sources = defaultdict(list)
    try:
        entries = json.loads(Path(compile_commands).read_text())
    except (OSError, ValueError):
        return sources
    for entry in entries:
        output = entry.get("output")
        source = entry.get("file")
        if output and source:
            sources[Path(output).name].append(source)
    return sources


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[-1])
        return 0
    try:
        log = Path(argv[1]).read_text(errors="replace").splitlines()
    except OSError as e:
        print(f"sccache_misses: no server log ({e}); misses cannot be named")
        return 0
    sources = _sources_by_object(argv[2]) if len(argv) > 2 else {}

    keys = {}
    misses = []
    for line in log:
        key = _KEY.search(line)
        if key:
            keys[key.group(1)] = key.group(2)
            continue
        outcome = _OUTCOME.search(line)
        obj = _OBJECT.search(line)
        if outcome and obj and obj.group(1) not in _IGNORED:
            misses.append((obj.group(1), outcome.group(1)))

    print(f"Compiles the cache did not serve: {len(misses)}")
    for obj, outcome in misses:
        candidates = sources.get(obj) or ["(source not in compile_commands.json)"]
        print(f"- {obj}: {outcome}, key {keys.get(obj, 'unknown')}")
        for source in candidates:
            print(f"    {source}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
