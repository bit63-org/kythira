#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Re-record every client's evidence into data/. Needs, at the versions
# README.md lists:
#   aws            the AWS CLI v2 (AWS_CLI overrides the path)
#   EVIDENCE_PYTHON  a Python with requirements.txt installed (boto3)
#   java 17+ and mvn, go 1.24+, node 20+ and npm, rclone, mount-s3
# and the /etc/hosts line from README.md. The Mountpoint recording installs
# a throwaway CA in the system trust store for its run, so this script
# must run as root (or set SKIP_MOUNTPOINT=1). Every client talks only to
# the recorder on 127.0.0.1 with dummy keys.
set -euo pipefail
cd "$(dirname "$0")"
py=${EVIDENCE_PYTHON:-python3}
export EVIDENCE_PYTHON=$py
mkdir -p data

# Build first, while the network (and any proxy) is available; the runs
# themselves need none.
(cd clients/java-sdk-v2 && mvn -q -B compile dependency:build-classpath \
  -Dmdep.outputFile=target/cp.txt)
(cd clients/go-sdk-v2 && go build -o go-evidence .)
(cd clients/js-sdk-v3 && npm ci --no-audit --no-fund --silent)

aws_cli=${AWS_CLI:-aws}
./run_client.sh "aws-cli-$("$aws_cli" --version | cut -d' ' -f1 | cut -d/ -f2)" \
  data/aws-cli-v2.json env AWS_CLI="$aws_cli" clients/awscli_v2.sh
./run_client.sh "boto3-$("$py" -c 'import boto3; print(boto3.__version__)')" \
  data/boto3.json "$py" clients/boto3_client.py
./run_client.sh aws-sdk-java-v2-2.59.3 data/java-sdk-v2.json clients/run_java.sh
./run_client.sh "aws-sdk-go-v2-s3-$(sed -n 's#^\s*github.com/aws/aws-sdk-go-v2/service/s3 \(v[0-9.]*\)$#\1#p' clients/go-sdk-v2/go.mod)" \
  data/go-sdk-v2.json clients/go-sdk-v2/go-evidence
./run_client.sh "aws-sdk-js-v3-$(node -p 'require("./clients/js-sdk-v3/package.json").dependencies["@aws-sdk/client-s3"]')" \
  data/js-sdk-v3.json node clients/js-sdk-v3/main.mjs
./run_client.sh "rclone-$(${RCLONE:-rclone} version | sed -n '1s/^rclone v//p')" \
  data/rclone.json clients/rclone.sh
if [[ -z ${SKIP_MOUNTPOINT:-} ]]; then
  EVIDENCE_BUCKETS=evidence EVIDENCE_SYSTEM_CA=1 ./run_client.sh \
    "mountpoint-s3-$(${MOUNT_S3:-mount-s3} --version | cut -d' ' -f2)" \
    data/mountpoint.json clients/mountpoint.sh
fi
