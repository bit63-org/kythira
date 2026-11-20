#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Run a build so that running out of memory fails the build, not the runner.
#
# Usage: bounded-build.sh [options] -- <command>...
#
#   --reserve-mib N    RAM kept back from the build for the runner agent and
#                      the kernel (default 2560). The build's cgroup gets
#                      memory.max = MemTotal - N and memory.high 1 GiB below
#                      that, so the kernel throttles and swaps the compilers
#                      before it ever has to starve anything outside them.
#   --time-limit DUR   Stop the command after DUR (a timeout(1) duration,
#                      default 230m) so a thrashing build ends on its own
#                      terms, inside the job's budget, and the `always()`
#                      steps after it still run.
#   --sample-secs N    Seconds between memory samples (default 10). A
#                      status line goes to stdout every third sample.
#   --adopt NAME       Also move running processes named NAME into the
#                      cgroup for the duration (repeatable). CI passes
#                      `sccache`: its server, started by an earlier step,
#                      is what actually forks the compilers, so without
#                      this the compilers would land in the server's cgroup
#                      and the limit would bound nothing but ninja.
#
# Why this exists. The Full suite legs of ci.yml compile with g++-13 under
# template-heavy backends, where single translation units reach 5-11 GiB of
# compiler RSS, on a 16 GiB runner. When three of those overlap, the runner
# VM runs out of memory and GitHub reports "The hosted runner lost
# communication with the server" -- with NO log at all, because the whole job
# log is lost with the runner. Every memory report inside the job was lost
# with it, which is why earlier regressions of this kind took days to place.
#
# Two things change that:
#
# 1. The command runs in its own cgroup v2 with memory.high/memory.max set
#    below physical RAM. The kernel then reclaims (swaps) the compilers'
#    pages instead of the runner agent's, so the agent keeps talking to
#    GitHub however hard the build thrashes. Worst case the build is slow
#    and --time-limit ends it, and the job fails with its log intact.
#
# 2. A sampler outside that cgroup prints, into the job log, the cgroup's
#    memory and swap, MemAvailable, and the heaviest live compilers by
#    source file. On exit it prints the peak RSS seen for each of the
#    heaviest translation units, which is the table that says which TU to
#    move into the `heavy_tu` Ninja pool (top-level CMakeLists.txt). Note it
#    only sees TUs that actually compile: sccache hits never start cc1plus.
#
# Without cgroup v2 or passwordless sudo (a developer machine, say) the
# command still runs, with the sampler and time limit but no cgroup.
set -uo pipefail

reserve_mib=2560
time_limit=230m
sample_secs=10
adopt=()

while [ $# -gt 0 ]; do
  case "$1" in
    --reserve-mib) reserve_mib=$2; shift 2 ;;
    --time-limit) time_limit=$2; shift 2 ;;
    --sample-secs) sample_secs=$2; shift 2 ;;
    --adopt) adopt+=("$2"); shift 2 ;;
    --) shift; break ;;
    *) echo "bounded-build: unknown option '$1'" >&2; exit 2 ;;
  esac
done
if [ $# -eq 0 ]; then
  echo "usage: $0 [--reserve-mib N] [--time-limit DUR] [--sample-secs N] -- <command>..." >&2
  exit 2
fi

mib() { echo $(( $1 / 1048576 )); }

# ── the cgroup ────────────────────────────────────────────────────────────
cg=""
cg_root=/sys/fs/cgroup
if grep -qw memory "$cg_root/cgroup.controllers" 2>/dev/null && sudo -n true 2>/dev/null; then
  mem_total_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  max_bytes=$(( mem_total_kib * 1024 - reserve_mib * 1048576 ))
  high_bytes=$(( max_bytes - 1073741824 ))
  cg="$cg_root/kythira-build-$$"
  if sudo mkdir "$cg" \
     && { grep -qw memory "$cg_root/cgroup.subtree_control" \
          || echo +memory | sudo tee "$cg_root/cgroup.subtree_control" >/dev/null; } \
     && echo "$high_bytes" | sudo tee "$cg/memory.high" >/dev/null \
     && echo "$max_bytes" | sudo tee "$cg/memory.max" >/dev/null; then
    echo "bounded-build: cgroup $cg: memory.high $(mib "$high_bytes") MiB," \
         "memory.max $(mib "$max_bytes") MiB of $(( mem_total_kib / 1024 )) MiB RAM"
  else
    echo "::warning::bounded-build: could not set up a memory cgroup; building without one"
    sudo rmdir "$cg" 2>/dev/null
    cg=""
  fi
else
  echo "bounded-build: no cgroup v2 memory controller or no passwordless sudo; building without a memory cgroup"
fi

# ── the sampler ───────────────────────────────────────────────────────────
# Started BEFORE this shell joins the cgroup, so it stays outside it and is
# never throttled along with the compilers it is watching.
sampler() {
  declare -A peak=()
  local n=0 start=$SECONDS
  # shellcheck disable=SC2329  # invoked by the TERM trap below
  report() {
    echo "── bounded-build: peak compiler RSS by translation unit (heaviest 25) ──"
    local tu
    for tu in "${!peak[@]}"; do
      printf '%8d MiB  %s\n' "$(( peak[$tu] / 1024 ))" "$tu"
    done | sort -rn | head -25
    exit 0
  }
  trap report TERM
  while :; do
    local line rss src top="" total=0 count=0
    while read -r line; do
      [ -n "$line" ] || continue
      rss=${line%% *}
      # cc1plus is handed the source path as an argument; the driver's -o
      # names a temporary .s, so the source is the useful label.
      src=$(awk '{for (i = 2; i <= NF; i++) if ($i ~ /\.(cpp|cc|cxx|c)$/) {print $i; exit}}' <<<"$line")
      src=${src#"$PWD"/}
      [ -n "$src" ] || src="?"
      total=$(( total + rss )); count=$(( count + 1 ))
      if [ "${peak[$src]:-0}" -lt "$rss" ]; then peak[$src]=$rss; fi
      if [ "$count" -le 3 ]; then top+=" $(( rss / 1024 ))M:${src##*/}"; fi
    done < <(ps -C cc1plus,cc1 -o rss=,args= --sort=-rss 2>/dev/null)
    if [ $(( n % 3 )) -eq 0 ]; then
      local cgm="-" cgs="-"
      if [ -n "$cg" ]; then
        cgm="$(mib "$(cat "$cg/memory.current" 2>/dev/null || echo 0)")M"
        cgs="$(mib "$(cat "$cg/memory.swap.current" 2>/dev/null || echo 0)")M"
      fi
      local avail swapfree
      avail=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
      swapfree=$(awk '/^SwapFree:/ {print int($2/1024)}' /proc/meminfo)
      printf '[mem %4dm] cg %s swap %s | avail %sM swapfree %sM | load %s | %d cc1plus %dM:%s\n' \
        "$(( (SECONDS - start) / 60 ))" "$cgm" "$cgs" "$avail" "$swapfree" \
        "$(cut -d' ' -f1 /proc/loadavg)" "$count" "$(( total / 1024 ))" "${top:- -}"
    fi
    n=$(( n + 1 ))
    sleep "$sample_secs" & wait $!
  done
}
sampler &
sampler_pid=$!

# Each process moved in is moved back to where it came from afterwards, so
# the cgroup can be removed and nothing outlives this step inside it.
declare -A home=()
join() {
  local pid=$1
  home[$pid]=$cg_root$(sed -n 's/^0:://p' "/proc/$pid/cgroup" 2>/dev/null)
  echo "$pid" | sudo tee "$cg/cgroup.procs" >/dev/null
}
if [ -n "$cg" ]; then
  join $$ || echo "::warning::bounded-build: could not join $cg; building without it"
  for name in "${adopt[@]}"; do
    for pid in $(pgrep -x "$name"); do
      if join "$pid"; then
        echo "bounded-build: moved $name (pid $pid) into the cgroup"
      fi
    done
  done
fi

# ── the build ─────────────────────────────────────────────────────────────
timeout --kill-after=2m "$time_limit" "$@"
rc=$?

kill -TERM "$sampler_pid" 2>/dev/null
wait "$sampler_pid" 2>/dev/null

if [ -n "$cg" ]; then
  peak_file="$cg/memory.peak"
  echo "── bounded-build: cgroup summary ──"
  [ -r "$peak_file" ] && echo "memory.peak $(mib "$(cat "$peak_file")") MiB"
  echo "memory.events: $(tr '\n' ' ' < "$cg/memory.events")"
  echo "memory.swap.current $(mib "$(cat "$cg/memory.swap.current" 2>/dev/null || echo 0)") MiB"
  # The cgroup can only be removed once empty: move everything back out.
  for pid in "${!home[@]}"; do
    echo "$pid" | sudo tee "${home[$pid]}/cgroup.procs" >/dev/null 2>&1 \
      || echo "$pid" | sudo tee "$cg_root/cgroup.procs" >/dev/null 2>&1
  done
  sudo rmdir "$cg" 2>/dev/null \
    || echo "bounded-build: $cg still holds: $(tr '\n' ' ' < "$cg/cgroup.procs")"
fi

if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
  echo "::error::bounded-build: the build exceeded its ${time_limit} limit and was stopped." \
       "The [mem] lines above show whether it was thrashing (cg at memory.max, swap growing)."
fi
exit "$rc"
