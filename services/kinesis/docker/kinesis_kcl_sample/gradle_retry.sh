#!/bin/sh
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# gradle_retry.sh TASK... -- run one Gradle build of the Kinesis Java
# clients, retrying when Maven Central rate-limits it.
#
# repo1.maven.org answers bursts of downloads with HTTP 429, and a CI run
# that loses that race fails before any test runs (seen on #836 and #851
# while building the kythira-kinesis-kcl image). Two layers of retry:
#
# - Gradle's own per-request retry, raised from 3 tries with a 125 ms
#   initial backoff (gone in well under a second, far too short for a rate
#   limit) to 6 tries starting at 2 s, doubling each time.
# - Around that, the whole build up to 5 times, waiting 20 s, 40 s, 80 s
#   and 160 s between attempts. Artifacts already downloaded stay in
#   GRADLE_USER_HOME, so a retry only fetches what is still missing.
#
# Retries do not help when repo1 answers 404 for artifacts it holds,
# which it did on every one of five attempts over five minutes on #840:
# Gradle does not cache that miss between builds, repo1 just kept
# answering it. The build.gradle files list Google's Maven Central mirror
# first and repo1 after it for that case.
#
# For tasks that build, never for `test`: retrying the whole build would
# also rerun a failing test until it happened to pass.
#
# One worker throughout: parallel downloads are what trip the limit.
# Shared by the image's Dockerfile and kinesis-module.yml's java job, so
# both resolve dependencies the same way.

set -u

attempts=5
delay=20
attempt=1
while :; do
    gradle --no-daemon --max-workers=1 -q \
        -Dorg.gradle.internal.repository.max.retries=6 \
        -Dorg.gradle.internal.repository.initial.backoff=2000 \
        "$@" && exit 0
    status=$?
    if [ "$attempt" -ge "$attempts" ]; then
        echo "gradle_retry.sh: gradle $* failed $attempts times, giving up" >&2
        exit "$status"
    fi
    echo "gradle_retry.sh: gradle $* failed (attempt $attempt of $attempts, exit $status);" \
        "retrying in ${delay}s" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
done
