#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Prints one "[sample]" line every INTERVAL seconds (default 30) until it is
# killed: memory used and available, swap used, load, the number of live
# compiler processes, and the largest one's resident size and translation
# unit. CI runs it in the background of a compile step so that the job log
# shows which translation units were in flight when a runner came close to
# its memory limit.
#
# Usage: scripts/sample-build-memory.sh [INTERVAL]
#
# g++ compiles in a cc1plus process and clang in a clang-* one; both carry
# the source path on their command line. g++ also passes the basename
# (-dumpbase) and clang -cc1 passes -main-file-name, so the longest
# argument that names a C/C++ source is taken as the translation unit.
# Paths are printed relative to $GITHUB_WORKSPACE when set.
set -u

interval="${1:-30}"

while sleep "$interval"; do
    mem=$(free -m | awk '/^Mem:/{m=$3" used, "$7" avail"} /^Swap:/{s=$3} END{print m", swap "s}')
    count=0
    top_rss=0
    top_pid=
    while read -r rss pid comm; do
        case "$comm" in
            cc1plus | clang*) ;;
            *) continue ;;
        esac
        count=$((count + 1))
        if [ "$rss" -gt "$top_rss" ]; then
            top_rss=$rss
            top_pid=$pid
        fi
    done < <(ps -eo rss=,pid=,comm=)
    tu=
    if [ -n "$top_pid" ]; then
        tu=$(tr '\0' '\n' < "/proc/${top_pid}/cmdline" 2>/dev/null \
            | awk '/\.(c|cc|cpp|cxx)$/ { if (length($0) > length(best)) best = $0 } END { print best }')
        if [ -n "${GITHUB_WORKSPACE:-}" ]; then
            tu=${tu#"${GITHUB_WORKSPACE}/"}
        fi
    fi
    echo "[sample] $(date -u +%H:%M:%S) MiB ${mem}; load $(cut -d' ' -f1 /proc/loadavg);" \
        "compilers ${count}, largest $((top_rss / 1024)) MiB ${tu:--}"
done
