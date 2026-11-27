#!/bin/sh
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Runs the selected tests of redis-py, go-redis and ioredis (Dockerfile in
# this directory) against one Kythira gateway, and exits non-zero if any
# selected test fails. Each library reads the endpoint and credentials its
# own way; nothing in the libraries or their tests is changed.
#
# Environment:
#   KYTHIRA_REDIS_HOST      gateway host (default kv1)
#   KYTHIRA_REDIS_PORT      gateway port (default 6379)
#   KYTHIRA_REDIS_USER      ACL user (default ops)
#   KYTHIRA_REDIS_PASSWORD  its secret (default ops-secret)
#   KYTHIRA_REDIS_TLS       1: connect with TLS, checking the server against
#                           the system CA store (ElastiCache and MemoryDB,
#                           for the AWS interop bundle)
#   KYTHIRA_CLIENT_SUITES   which to run (default "redis-py go-redis ioredis")
#   KYTHIRA_CLIENT_OUT      directory for each suite's report (default /out,
#                           when it exists)
#
# The redis-py tests run twice, in RESP2 and RESP3. go-redis runs in its
# Redis Enterprise mode, which is how its suite takes an endpoint with
# credentials from a file instead of starting its own servers; its version
# gates see 7.0, the compatibility level Kythira reports.

set -u

host=${KYTHIRA_REDIS_HOST:-kv1}
port=${KYTHIRA_REDIS_PORT:-6379}
user=${KYTHIRA_REDIS_USER:-ops}
password=${KYTHIRA_REDIS_PASSWORD:-ops-secret}
tls=${KYTHIRA_REDIS_TLS:-0}
scheme=redis
json_tls=false
if [ "$tls" = 1 ]; then
    scheme=rediss
    json_tls=true
fi
suites=${KYTHIRA_CLIENT_SUITES:-redis-py go-redis ioredis}
out=${KYTHIRA_CLIENT_OUT:-/out}
[ -d "$out" ] || out=$(mktemp -d)
lists=/opt/kythira

# The lines of a selection file that name a test.
selected() {
    grep -v -e '^#' -e '^[[:space:]]*$' "$1"
}

failed=""

run_redis_py() {
    cd /opt/redis-py || return 1
    ids=$(selected "$lists/redis-py.txt")
    status=0
    for protocol in 2 3; do
        echo "== redis-py, RESP$protocol"
        # shellcheck disable=SC2086
        /opt/redis-py-venv/bin/python -m pytest -p no:cacheprovider -q \
            --timeout 120 --protocol="$protocol" \
            --redis-url="$scheme://$user:$password@$host:$port/0" \
            --junitxml="$out/redis-py-resp$protocol.xml" \
            $ids || status=1
    done
    return $status
}

run_go_redis() {
    echo "== go-redis"
    cd /opt/go-redis || return 1
    endpoints=$(mktemp)
    printf '{"kythira": {"username": "%s", "password": "%s", "tls": %s, "endpoints": ["%s://%s:%s"]}}\n' \
        "$user" "$password" "$json_tls" "$scheme" "$host" "$port" > "$endpoints"
    # One alternation of the selected spec texts, each escaped and anchored
    # at its end (Ginkgo matches the focus against the full spec text).
    focus=$(selected "$lists/go-redis.txt" | python3 -c '
import re, sys
texts = [line.rstrip("\n") for line in sys.stdin]
print("(" + "|".join(re.escape(t).replace("\\ ", " ") for t in texts) + ")$")
')
    RE_CLUSTER=true REDIS_VERSION=7.0 REDIS_ENDPOINTS_CONFIG_PATH="$endpoints" \
        ./go-redis.test -test.run TestGinkgoSuite -ginkgo.no-color -ginkgo.timeout=30m \
        -ginkgo.junit-report="$out/go-redis.xml" -ginkgo.focus="$focus"
}

run_ioredis() {
    echo "== ioredis"
    cd /opt/ioredis || return 1
    files=""
    for f in transaction pipeline watch-exec hgetall scan_stream string_numbers send_command \
             autopipelining connection duplicate lazy_connect ready_check transformer; do
        files="$files test/functional/$f.ts"
    done
    # shellcheck disable=SC2086
    KYTHIRA_IOREDIS_TESTS="$lists/ioredis.txt" \
    KYTHIRA_REDIS_HOST="$host" KYTHIRA_REDIS_PORT="$port" \
    KYTHIRA_REDIS_USER="$user" KYTHIRA_REDIS_PASSWORD="$password" KYTHIRA_REDIS_TLS="$tls" \
    TS_NODE_TRANSPILE_ONLY=true NODE_ENV=test \
        npx mocha --no-experimental-strip-types --reporter spec \
        test/helpers/global.ts test/helpers/kythira-setup.ts $files
}

for suite in $suites; do
    case "$suite" in
        redis-py) run_redis_py || failed="$failed $suite" ;;
        go-redis) run_go_redis || failed="$failed $suite" ;;
        ioredis) run_ioredis || failed="$failed $suite" ;;
        *) echo "unknown suite '$suite'" >&2; failed="$failed $suite" ;;
    esac
done

if [ -n "$failed" ]; then
    echo "client suites failed:$failed" >&2
    exit 1
fi
echo "client suites passed: $suites"
