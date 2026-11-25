#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The client half of the disk-backed build cache's end-to-end test
# (.kiro/specs/disk-backed-build-cache/ task 9). One mode per `compose run`:
#
#   run.sh sccache      build project/ KYTHIRA_BUILDS times (default 2) from
#                       a clean build directory through sccache's WebDAV
#                       backend (Requirement 12.1)
#   run.sh vcpkg        install zlib KYTHIRA_INSTALLS times (default 2) from
#                       a clean tree through vcpkg's `http` binary source
#                       (Requirement 12.2)
#   run.sh throughput   PUT a KYTHIRA_MB (default 500) MB object to one node
#                       and GET it back from another, timing both
#                       (design.md Risks)
#   run.sh matrix       aggregate PUT throughput for every pairing of
#                       KYTHIRA_WRITERS concurrent writers (default
#                       "1 4 16 32") and KYTHIRA_SIZES object sizes (default
#                       "64K 2M"), plus KYTHIRA_LARGE_WRITERS (default "1 4")
#                       writers of KYTHIRA_LARGE_SIZE objects (default 256M);
#                       then each node's bytes written per byte stored
#                       (GitHub issue 942)
#
# Each mode prints KYTHIRA_* lines that tests/docker_chaos/
# cache_cluster_test.cpp parses, and exits 0 only if every build or install
# passed. The scenario test decides what the numbers have to be.
#
# Both clients are configured from their own documented environment
# variables and nothing else. sccache goes through CI's real gate,
# start-sccache.sh, which runs a probe compile and says whether sccache may
# be the compiler launcher; the build uses it only if it said yes. That gate
# is what makes a dead cache a slower build rather than a red one
# (Requirement 9.1), so the test runs it rather than a copy of its logic.
#
# Defaults suit the compose network. Every one can be overridden, which is
# how the script was exercised against daemons on a host.

set -uo pipefail

cache_url="${KYTHIRA_CACHE_URL:-http://cache-1:8080}"
peer_url="${KYTHIRA_PEER_URL:-http://cache-2:8080}"
user="${KYTHIRA_CACHE_USER:-ci-main}"
password="${KYTHIRA_CACHE_PASSWORD:-ci-main-secret}"
project="${KYTHIRA_PROJECT_DIR:-/work/project}"
scratch="${KYTHIRA_SCRATCH_DIR:-/tmp/kythira-client}"
vcpkg_root="${VCPKG_ROOT:-/opt/vcpkg}"

mkdir -p "$scratch"

# Wait up to KYTHIRA_REACH_SECONDS (default 20) for the cache to answer
# anything at all over HTTP, and report how long that took. A runner's
# cache is long-running, but this container is not: under rootless Podman
# a freshly started container could not yet reach the service name, and
# sccache, whose server start makes one request with a 10 s budget, gave
# up and was turned off. Every mode waits the same way. With the cluster
# stopped the wait runs out and the mode goes on, which is the point of
# that case.
wait_for_cache() {
    local limit="${KYTHIRA_REACH_SECONDS:-20}" begin code=000
    begin=$(date +%s.%N)
    for _ in $(seq 1 "$((limit * 2))"); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${cache_url}/" || true)
        [[ "$code" != 000 ]] && break
        sleep 0.5
    done
    echo "KYTHIRA_REACH url=${cache_url} http=${code} seconds=$(awk -v a="$begin" -v b="$(date +%s.%N)" 'BEGIN{printf "%.2f", b - a}')"
}

run_sccache() {
    export SCCACHE_WEBDAV_ENDPOINT="${SCCACHE_WEBDAV_ENDPOINT:-${cache_url}/sccache}"
    export SCCACHE_WEBDAV_USERNAME="${SCCACHE_WEBDAV_USERNAME:-$user}"
    export SCCACHE_WEBDAV_PASSWORD="${SCCACHE_WEBDAV_PASSWORD:-$password}"
    export SCCACHE_DIR="${scratch}/sccache-local"
    export SCCACHE_ERROR_LOG="${scratch}/sccache-server.log"
    export SCCACHE_LOG="${SCCACHE_LOG:-info}"

    local builds="${KYTHIRA_BUILDS:-2}" salt="${KYTHIRA_SALT:-0}" launcher=none
    local gate="${scratch}/gate.out"
    : > "$gate"
    wait_for_cache
    GITHUB_OUTPUT="$gate" start-sccache.sh
    if grep -qx 'launcher=sccache' "$gate"; then
        launcher=sccache
    elif [[ -s "$SCCACHE_ERROR_LOG" ]]; then
        echo "--- sccache server log (last 20 lines) ---"
        tail -20 "$SCCACHE_ERROR_LOG"
    fi
    echo "KYTHIRA_MODE launcher=${launcher}"

    local ok=0 i
    for ((i = 1; i <= builds; i++)); do
        local build="${scratch}/build"
        rm -rf "$build"
        local args=(-S "$project" -B "$build" -G Ninja "-DCMAKE_CXX_FLAGS=-DKYTHIRA_SALT=${salt}")
        if [[ "$launcher" == sccache ]]; then
            args+=(-DCMAKE_CXX_COMPILER_LAUNCHER=sccache)
            sccache --zero-stats >/dev/null
        fi
        local start end
        start=$(date +%s.%N)
        if cmake "${args[@]}" >"${scratch}/configure.log" 2>&1 \
            && cmake --build "$build" >"${scratch}/build.log" 2>&1 \
            && "${build}/kythira_cache_probe" >/dev/null; then
            ok=$((ok + 1))
            end=$(date +%s.%N)
            echo "KYTHIRA_BUILD build=${i} status=ok seconds=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.2f", b - a}')"
        else
            echo "KYTHIRA_BUILD build=${i} status=failed"
            sed 's/^/    /' "${scratch}/configure.log" "${scratch}/build.log" | tail -40
        fi
        if [[ "$launcher" == sccache ]]; then
            # One line, so the test can pair a build with its stats.
            echo "KYTHIRA_STATS build=${i} $(sccache --show-stats --stats-format=json | tr -d '\n')"
        fi
    done

    if [[ "$launcher" == sccache ]]; then
        sccache --stop-server >/dev/null 2>&1 || true
        if [[ -s "$SCCACHE_ERROR_LOG" ]]; then
            echo "--- sccache server log (last 40 lines) ---"
            tail -40 "$SCCACHE_ERROR_LOG"
        fi
    fi
    echo "KYTHIRA_RESULT builds=${builds} ok=${ok}"
    [[ "$ok" -eq "$builds" ]]
}

run_vcpkg() {
    local auth
    auth="Authorization: Basic $(printf '%s:%s' "$user" "$password" | base64 -w0)"
    # The template measured in task 1: {name}/{version}/{sha}, no triplet
    # and no extension. The fourth field is a header vcpkg adds to every
    # request it makes to this source.
    # (Not a ${VAR:-default}: the template's own braces would end it early.)
    if [[ -z "${VCPKG_BINARY_SOURCES:-}" ]]; then
        export VCPKG_BINARY_SOURCES="clear;http,${cache_url}/vcpkg/{name}/{version}/{sha},readwrite,${auth}"
    fi
    export VCPKG_DISABLE_METRICS=1 VCPKG_FORCE_SYSTEM_BINARIES=1

    local installs="${KYTHIRA_INSTALLS:-2}" ok=0 i
    wait_for_cache
    for ((i = 1; i <= installs; i++)); do
        rm -rf "${vcpkg_root}/installed" "${vcpkg_root}/packages" "${vcpkg_root}/buildtrees"
        local log="${scratch}/vcpkg-${i}.log" start end
        start=$(date +%s.%N)
        if "${vcpkg_root}/vcpkg" install zlib >"$log" 2>&1; then
            end=$(date +%s.%N)
            ok=$((ok + 1))
            # built=1 when vcpkg compiled zlib itself, 0 when it restored
            # zlib from the cache. "Restored N package(s)" also counts the
            # vcpkg-cmake host tool, so it is reported but not the signal.
            local restored submitted built=0
            restored=$(sed -n 's/.*Restored \([0-9][0-9]*\) package.*/\1/p' "$log" | head -1)
            submitted=$(grep -c 'Completed submission' "$log")
            if grep -q '^Building zlib:' "$log"; then
                built=1
            fi
            echo "KYTHIRA_VCPKG install=${i} status=ok built=${built} restored=${restored:-0} submitted=${submitted} seconds=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.2f", b - a}')"
        else
            echo "KYTHIRA_VCPKG install=${i} status=failed"
        fi
        # The lines that say what the binary source did, for the test log.
        grep -E 'Restored|Completed submission|binary cache|curl|warning|error' "$log" \
            | sed 's/^/    /' | head -20
    done
    echo "KYTHIRA_RESULT installs=${installs} ok=${ok}"
    [[ "$ok" -eq "$installs" ]]
}

run_throughput() {
    local mb="${KYTHIRA_MB:-500}"
    wait_for_cache
    local key="vcpkg/throughput/$(date +%s%N)"
    local src="${scratch}/blob" dst="${scratch}/blob.back"
    head -c "$((mb * 1024 * 1024))" /dev/urandom > "$src"
    local want
    want=$(sha256sum "$src" | cut -d' ' -f1)

    local put
    put=$(curl -sS -u "${user}:${password}" -T "$src" -o /dev/null \
        -w '%{http_code} %{time_total} %{size_upload}' "${cache_url}/${key}")
    read -r put_code put_s put_bytes <<<"$put"
    echo "KYTHIRA_THROUGHPUT op=put node=${cache_url} status=${put_code} bytes=${put_bytes} seconds=${put_s}"

    # The PUT's 201 means committed, not yet applied on every follower: a
    # follower asked at once can still answer 404, which every client takes
    # as a miss. Ask again until it has applied, for up to 30 s, and report
    # how long that took apart from the transfer itself.
    local get get_code get_s get_bytes waited=0 begin
    begin=$(date +%s.%N)
    for _ in $(seq 1 300); do
        get=$(curl -sS -u "${user}:${password}" -o "$dst" \
            -w '%{http_code} %{time_total} %{size_download}' "${peer_url}/${key}")
        read -r get_code get_s get_bytes <<<"$get"
        [[ "$get_code" == 404 ]] || break
        sleep 0.1
    done
    waited=$(awk -v a="$begin" -v b="$(date +%s.%N)" -v t="$get_s" 'BEGIN{printf "%.2f", b - a - t}')
    local match=0
    if [[ -f "$dst" ]] && [[ "$(sha256sum "$dst" | cut -d' ' -f1)" == "$want" ]]; then
        match=1
    fi
    echo "KYTHIRA_THROUGHPUT op=get node=${peer_url} status=${get_code} bytes=${get_bytes} seconds=${get_s} waited=${waited} match=${match}"
    rm -f "$src" "$dst"
    [[ "$put_code" == 201 && "$get_code" == 200 && "$match" == 1 ]]
}

# Bytes for a size written as N, NK or NM.
size_bytes() {
    local v="$1"
    case "$v" in
        *K) echo $((${v%K} * 1024)) ;;
        *M) echo $((${v%M} * 1024 * 1024)) ;;
        *) echo "$v" ;;
    esac
}

# One node's /_metrics value, or 0. Needs the admin user.
metric() {
    local url="$1" name="$2"
    curl -sS -u "${KYTHIRA_ADMIN_USER:-ops}:${KYTHIRA_ADMIN_PASSWORD:-ops-secret}" \
        "${url}/_metrics" 2>/dev/null | awk -v n="$name" '$1 == n { print $2; found = 1 } END { if (!found) print 0 }'
}

# PUT one object of fresh random bytes and print the status of every
# attempt on one line, first to last: matrix_put <url> <bytes> <key>.
# Fresh bytes because the chunk store keeps one copy of identical chunks,
# and repeated content would hide the store's writes from the amplification
# figure; real sccache objects are unique. Streamed, so the client never
# holds an object: curl sends it chunked.
#
# A 503 is the cache's "retry" answer (no leader here, or the proposal or
# commit did not go through), and sccache, vcpkg and rclone all retry it,
# so this does too, up to KYTHIRA_PUT_ATTEMPTS times with a short pause.
# The cell still reports every first answer, so refusals stay visible.
matrix_put() {
    local attempt code codes=""
    for ((attempt = 1; attempt <= ${KYTHIRA_PUT_ATTEMPTS:-4}; attempt++)); do
        code=$(head -c "$2" /dev/urandom |
            curl -sS -o /dev/null -w '%{http_code}' -u "${user}:${password}" -T - "$1/$3" \
                2>/dev/null) || code=000
        codes="${codes:+${codes} }${code}"
        [[ "$code" == 503 ]] || break
        sleep "0.$((RANDOM % 5 + 1))"
    done
    echo "$codes"
}

# The /_metrics counters that say why a PUT got 503, summed over the nodes,
# as name=value pairs on one line.
refusal_counters() {
    local n name line=""
    for name in put_no_leader put_chunk_failures put_commit_refused forward_failures \
        auth_failures connections_rejected; do
        local sum=0
        for n in "${nodes[@]}"; do
            sum=$(( sum + $(metric "$n" "kythira_cache_http_${name}") ))
        done
        line="${line:+${line} }${name}=${sum}"
    done
    echo "$line"
}

# One cell: matrix_cell <writers> <size>. Writes max(writers,
# KYTHIRA_CELL_MB / size) objects, spread round-robin over the nodes, keeps
# `writers` PUTs in flight, and deletes them afterwards so the cells do not
# add up against the disk budget. Every key is under `sccache/`, split over
# its sixteen hex prefixes, so both sides of the `sccache/8` cut take
# writes, as they do from a real CI run.
matrix_cell() {
    local writers="$1" size="$2" bytes count cell_bytes
    bytes=$(size_bytes "$size")
    cell_bytes=$(( ${KYTHIRA_CELL_MB:-128} * 1024 * 1024 ))
    count=$(( cell_bytes / bytes ))
    (( count < writers )) && count=$writers
    local run i=0 jobs="${scratch}/matrix-jobs"
    run="matrix/$(date +%s%N)"
    : > "$jobs"
    for ((i = 0; i < count; i++)); do
        echo "${nodes[i % ${#nodes[@]}]} $bytes sccache/$(printf '%x' $((i % 16)))/${run}/${i}" >> "$jobs"
    done
    local begin end attempts before
    before=$(refusal_counters)
    begin=$(date +%s.%N)
    attempts=$(xargs -P "$writers" -L 1 bash -c 'matrix_put "$@"' _ < "$jobs")
    end=$(date +%s.%N)
    # One line per PUT, its attempts' statuses first to last. ok counts PUTs
    # whose last attempt stored the object; retried counts PUTs that needed
    # more than one attempt.
    local ok retried
    ok=$(awk '$NF == 201' <<<"$attempts" | wc -l)
    retried=$(awk 'NF > 1' <<<"$attempts" | wc -l)
    # Every first answer and how often, e.g. 201:2037,503:11, so a cell
    # says how often the cache refused, failed or never answered (000) a
    # PUT the first time, even when a retry then stored it.
    local tally
    tally=$(awk '{print $1}' <<<"$attempts" | sort | uniq -c |
        awk '{printf "%s%s:%s", (NR > 1 ? "," : ""), $2, $1}')
    # Each last answer other than 201, with its count (000 is a curl
    # failure), so a short cell says why: "503x19" or "000x2,500x1";
    # "none" when every PUT was stored.
    local failed_codes
    failed_codes=$(awk '$NF != 201 {print $NF}' <<<"$attempts" | sort | uniq -c |
        awk '{ printf "%s%sx%s", (NR > 1 ? "," : ""), $2, $1 }')
    local seconds rate
    seconds=$(awk -v a="$begin" -v b="$end" 'BEGIN{printf "%.2f", b - a}')
    rate=$(awk -v n="$ok" -v s="$bytes" -v t="$seconds" 'BEGIN{printf "%.2f", (t > 0 ? n * s / t / 1048576 : 0)}')
    echo "KYTHIRA_MATRIX writers=${writers} size=${size} bytes=${bytes} puts=${count} ok=${ok} failed=${failed_codes:-none} seconds=${seconds} mib_per_s=${rate} statuses=${tally} retried=${retried}"
    # When any PUT was refused, which part of the path refused it: the
    # counters' growth over the cell, summed over the nodes.
    if (( retried > 0 || ok != count )); then
        local after_c delta="" pair
        after_c=$(refusal_counters)
        for pair in $after_c; do
            local name="${pair%%=*}" now="${pair#*=}" was
            was=$(tr ' ' '\n' <<<"$before" | awk -F= -v n="$name" '$1 == n {print $2}')
            delta="${delta:+${delta} }${name}=$(( now - ${was:-0} ))"
        done
        echo "KYTHIRA_MATRIX_REFUSALS writers=${writers} size=${size} ${delta}"
    fi
    while read -r node _ key; do
        curl -sS -o /dev/null -u "${user}:${password}" -X DELETE "${node}/${key}" 2>/dev/null || true
    done < "$jobs"
    rm -f "$jobs"
    [[ "$ok" == "$count" ]]
}

run_matrix() {
    read -r -a nodes <<<"${KYTHIRA_NODE_URLS:-http://cache-1:8080 http://cache-2:8080 http://cache-3:8080}"
    export -f matrix_put
    export user password
    wait_for_cache
    local -A disk0 store0
    local n
    for n in "${nodes[@]}"; do
        disk0[$n]=$(metric "$n" kythira_cache_disk_write_bytes)
        store0[$n]=$(metric "$n" kythira_cache_store_written_bytes)
    done
    local failed=0 w s
    for s in ${KYTHIRA_SIZES:-64K 2M}; do
        for w in ${KYTHIRA_WRITERS:-1 4 16 32}; do
            matrix_cell "$w" "$s" || failed=1
        done
    done
    for w in ${KYTHIRA_LARGE_WRITERS:-1 4}; do
        matrix_cell "$w" "${KYTHIRA_LARGE_SIZE:-256M}" || failed=1
    done
    # Bytes written per byte stored, per node, over the whole matrix: the
    # process's own write_bytes, so a RAID member or an overlay layer does
    # not count a write twice.
    for n in "${nodes[@]}"; do
        local disk store
        disk=$(( $(metric "$n" kythira_cache_disk_write_bytes) - ${disk0[$n]} ))
        store=$(( $(metric "$n" kythira_cache_store_written_bytes) - ${store0[$n]} ))
        echo "KYTHIRA_AMPLIFICATION node=${n} disk_bytes=${disk} store_bytes=${store} ratio=$(awk -v d="$disk" -v s="$store" 'BEGIN{printf "%.2f", (s > 0 ? d / s : 0)}')"
    done
    return "$failed"
}

case "${1:-}" in
    sccache) run_sccache ;;
    vcpkg) run_vcpkg ;;
    throughput) run_throughput ;;
    matrix) run_matrix ;;
    *)
        echo "usage: run.sh sccache|vcpkg|throughput|matrix" >&2
        exit 64
        ;;
esac
