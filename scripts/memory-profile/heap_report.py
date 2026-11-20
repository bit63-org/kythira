#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Summarize one heaptrack file: heap over time and where the bytes live.

usage: heap_report.py HEAPTRACK_FILE [--cost peak|leaked|allocations] [--top N]

Prints heaptrack_print's totals, the heap at about 16 points in time (from
its massif output), and the top N innermost Kythira frames by the chosen
cost (peak by default: what was live at the heap's peak). Grouping by the
innermost Kythira frame, not the allocation site, is what makes the result
readable: most allocations happen inside std:: or Boost.
"""
import collections
import os
import re
import subprocess
import sys
import tempfile


def heaptrack_print(path, *args):
    return subprocess.run(["heaptrack_print", "-f", path, "-p", "0", "-a", "0", "-T", "0", *args],
                          capture_output=True, text=True, check=True).stdout


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    cost = sys.argv[sys.argv.index("--cost") + 1] if "--cost" in sys.argv else "peak"
    top = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 12
    with tempfile.TemporaryDirectory() as tmp:
        massif, stacks = os.path.join(tmp, "massif"), os.path.join(tmp, "stacks")
        summary = heaptrack_print(path, "-M", massif, "--massif-detailed-freq", "0",
                                  "-F", stacks, "--flamegraph-cost-type", cost)
        for line in summary.splitlines():
            if re.match(r"(total runtime|calls to allocation|temporary memory|peak heap|"
                        r"peak RSS|total memory leaked)", line):
                print(line)
        rows, t = [], 0.0
        with open(massif) as f:
            for line in f:
                if line.startswith("time="):
                    t = float(line.split("=")[1])
                elif line.startswith("mem_heap_B="):
                    rows.append((t, int(line.split("=")[1])))
        step = max(1, len(rows) // 16)
        print("heap over time:", " ".join(f"{t:.0f}s={b / 1048576:.1f}M" for t, b in rows[::step]))
        total, by_frame = 0, collections.Counter()
        with open(stacks) as f:
            for line in f:
                stack, _, n = line.rstrip().rpartition(" ")
                total += int(n)
                ours = [fr for fr in stack.split(";")
                        if fr.startswith(("kythira::", "dynamodb_gateway::"))
                        and "boost_backend" not in fr]
                by_frame[re.sub(r"\(.*", "", ours[-1])[:120] if ours else "(outside Kythira)"] += int(n)
    print(f"{cost} by innermost Kythira frame (total {total:,}):")
    for frame, n in by_frame.most_common(top):
        print(f"  {100 * n / max(total, 1):5.1f}%  {n:>14,}  {frame}")


if __name__ == "__main__":
    main()
