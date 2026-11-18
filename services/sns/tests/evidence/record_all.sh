#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Re-record every client's evidence into data/. Needs the pinned clients:
#   AWS_CLI          the AWS CLI v2 binary (2.31.0)
#   EVIDENCE_PYTHON  a Python with requirements.txt installed (boto3)
#   java 21 and gradle, for clients/java-sdk-v2
#   node 22 and npm, for clients/js-sdk-v3 (npm ci installs the lock file)
#   go 1.24, for clients/go-sdk-v2
# Every client talks only to the recorder on 127.0.0.1 with dummy keys.
set -euo pipefail
cd "$(dirname "$0")"
py=${EVIDENCE_PYTHON:-python3}
export EVIDENCE_PYTHON=$py
mkdir -p data

aws_cli=${AWS_CLI:-aws}
./run_client.sh "awscli-$("$aws_cli" --version | cut -d' ' -f1 | cut -d/ -f2)" \
  data/awscli-v2.json env AWS_CLI="$aws_cli" clients/awscli_v2.sh
./run_client.sh "boto3-$("$py" -c 'import boto3; print(boto3.__version__)')" \
  data/boto3.json "$py" clients/boto3_client.py

(cd clients/java-sdk-v2 && gradle -q --no-daemon installDist)
./run_client.sh aws-sdk-java-v2-2.57.11 data/java-sdk-v2.json \
  clients/java-sdk-v2/build/install/sns-evidence-java-sdk-v2/bin/sns-evidence-java-sdk-v2

(cd clients/js-sdk-v3 && npm ci --no-audit --no-fund --silent)
./run_client.sh aws-sdk-js-v3-3.1166.0 data/js-sdk-v3.json node clients/js-sdk-v3/client.mjs

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
(cd clients/go-sdk-v2 && go build -o "$bin/sns-evidence-go" .)
./run_client.sh aws-sdk-go-v2-sns-1.47.10 data/go-sdk-v2.json "$bin/sns-evidence-go"

"$py" check_evidence.py ../../model/service-2.json data
