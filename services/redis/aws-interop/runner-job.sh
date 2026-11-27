#!/bin/bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The AWS interop bundle's job on its runner instance inside the VPC
# (run.sh launches the instance with this script and its settings as user
# data; ElastiCache Serverless and MemoryDB answer only inside their VPC).
# It loads the two images run.sh built, then for every target:
#
#   1. checks an ElastiCache IAM auth token against the cache's `auth=iam`
#      style user (ElastiCache targets only; first, while the token, made
#      by run.sh, is fresh: tokens last 15 minutes);
#   2. records the differential streams (redis_differential_record);
#   3. runs the client library suites (services/redis/docker/clients/
#      run.sh) with TLS;
#
# then uploads /out as one tarball to a presigned URL and powers off (the
# instance terminates on shutdown). Nothing here holds AWS credentials.
#
# Settings, written above this script by run.sh:
#   IMAGES_URL    presigned GET of the saved images (gzip)
#   RESULTS_URL   presigned PUT for results.tar.gz
#   TARGETS       space-separated name:host:port:user:version entries, the
#                 version with '_' for spaces
#   PASSWORD      the password every target's app user has
#   IAM_TARGETS   space-separated name:host:port:user:token-variable
#   one variable per IAM token, named in IAM_TARGETS

set -u
mkdir -p /out/recs /out/clients /out/iam
exec > >(tee /out/runner.log) 2>&1

upload() {
    tar czf /tmp/results.tar.gz -C /out .
    curl -fsS --retry 5 -X PUT --upload-file /tmp/results.tar.gz "$RESULTS_URL" ||
        echo "upload failed"
}
trap 'upload; shutdown -h now' EXIT

dnf install -y docker
systemctl start docker
curl -fsS --retry 5 "$IMAGES_URL" | gunzip | docker load

for t in $IAM_TARGETS; do
    IFS=: read -r name host port user var <<<"$t"
    token=${!var}
    echo "== IAM auth token, $name"
    if docker run --rm -e T="$token" --entrypoint /opt/redis-py-venv/bin/python \
        kythira-redis-clients:interop -c "
import os, redis
r = redis.Redis(host='$host', port=$port, ssl=True, username='$user', password=os.environ['T'])
print('PING ->', r.ping())
" >"/out/iam/$name.txt" 2>&1; then
        echo "ok" >>"/out/iam/$name.txt"
    else
        echo "FAILED" >>"/out/iam/$name.txt"
    fi
    cat "/out/iam/$name.txt"
done

for t in $TARGETS; do
    IFS=: read -r name host port user version <<<"$t"
    echo "== record, $name"
    docker run --rm -e PASSWORD -v /out:/out kythira-redis-recorder:interop \
        --server "$name" --host "$host" --port "$port" --tls --user "$user" \
        --password-env PASSWORD --version "${version//_/ }" --out /out/recs ||
        echo "$name: recording failed" >>/out/failures.txt
    echo "== client suites, $name"
    mkdir -p "/out/clients/$name"
    docker run --rm -v /out:/out \
        -e KYTHIRA_REDIS_HOST="$host" -e KYTHIRA_REDIS_PORT="$port" \
        -e KYTHIRA_REDIS_USER="$user" -e KYTHIRA_REDIS_PASSWORD="$PASSWORD" \
        -e KYTHIRA_REDIS_TLS=1 -e KYTHIRA_CLIENT_OUT="/out/clients/$name" \
        kythira-redis-clients:interop >"/out/clients/$name/output.txt" 2>&1
    echo "exit $?" >>"/out/clients/$name/output.txt"
    tail -3 "/out/clients/$name/output.txt"
done
