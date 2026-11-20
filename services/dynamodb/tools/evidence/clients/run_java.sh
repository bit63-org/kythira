#!/bin/sh
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Build and run one of the Java evidence clients (java-sdk, lock-client,
# kcl2, kcl3, streams-adapter) against the recording stub
# (`.kiro/specs/dynamodb-compatible-api/` task 1). Maven resolves the
# client's pinned dependencies; the client then runs on a plain classpath
# (exec:java's class loader loses SDK classes on shutdown).
#
# Usage: ENDPOINT=http://localhost:8000 run_java.sh <client>

set -eu

client="$1"
dir="$(cd "$(dirname "$0")/${client}" && pwd)"
cd "${dir}"

# Maven Central answers bursts of downloads with HTTP 429, and a run that
# loses that race fails before the client starts ("Non-resolvable import
# POM ... software.amazon.awssdk:bom ... 429 Too Many Requests", seen on
# #896 twice). Two layers of retry, as gradle_retry.sh does for the
# Kinesis clients:
#
# - The resolver's own per-request retry, raised from 3 tries to 8 and
#   from a 5 s to a 10 s initial wait (it already treats 429 and 503 as
#   retryable). Downloads run on one thread, since parallel ones are what
#   trip the limit.
# - Around that, the whole resolve up to 4 times, waiting 30 s, 60 s and
#   120 s between attempts. Later attempts pass -U: the resolver records a
#   failed download in the local repository and would otherwise answer
#   "(absent)" from that record without asking Central again, which is
#   how the first failure on #896 read. What did download stays in the
#   local repository, so a retry only fetches what is still missing.
#
# This retries dependency resolution and compilation only, never the
# client run below, so a failing client is never rerun until it passes.
attempts=4
delay=30
attempt=1
update=""
while :; do
    # shellcheck disable=SC2086 # $update is empty or one flag
    mvn -q -B ${update} \
        -Daether.connector.http.retryHandler.count=8 \
        -Daether.connector.http.retryHandler.interval=10000 \
        -Daether.connector.basic.threads=1 \
        compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt && break
    status=$?
    if [ "${attempt}" -ge "${attempts}" ]; then
        echo "run_java.sh: resolving ${client} failed ${attempts} times, giving up" >&2
        exit "${status}"
    fi
    echo "run_java.sh: resolving ${client} failed (attempt ${attempt} of ${attempts}," \
        "exit ${status}); retrying in ${delay}s" >&2
    sleep "${delay}"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
    update="-U"
done
# KCL's Kinesis client speaks CBOR unless told not to; the stub speaks JSON.
exec java -Daws.cborEnabled=false -cp "target/classes:$(cat target/cp.txt)" evidence.Main
