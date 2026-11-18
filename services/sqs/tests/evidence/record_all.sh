#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Re-record every client's evidence into data/. Needs the pinned clients:
#   AWS_CLI          the AWS CLI v2 binary (2.31.0)
#   EVIDENCE_PYTHON  a Python with requirements.txt installed
#   RECORDER_PYTHON  a Python with requirements-query.txt installed (the
#                    recorder and the query-protocol client run under it)
#   java 21 and gradle, for the Java project under clients/java
# Every client talks only to the recorder on 127.0.0.1 with dummy keys.
set -euo pipefail
cd "$(dirname "$0")"
py=${EVIDENCE_PYTHON:-python3}
export RECORDER_PYTHON=${RECORDER_PYTHON:?set RECORDER_PYTHON (requirements-query.txt)}
mkdir -p data

aws_cli=${AWS_CLI:-aws}
./run_client.sh "awscli-$("$aws_cli" --version | cut -d' ' -f1 | cut -d/ -f2)" \
  data/awscli-v2.json env AWS_CLI="$aws_cli" clients/awscli_v2.sh
./run_client.sh "boto3-$("$py" -c 'import boto3; print(boto3.__version__)')" \
  data/boto3.json "$py" clients/boto3_client.py
./run_client.sh "boto3-$("$RECORDER_PYTHON" -c 'import boto3; print(boto3.__version__)')-query" \
  data/boto3-query.json "$RECORDER_PYTHON" clients/boto3_client.py
./run_client.sh "kombu-$("$py" -c 'import kombu; print(kombu.__version__)')" \
  data/kombu.json "$py" clients/kombu_client.py

(cd clients/java && gradle -q --no-daemon installDist)
bin=clients/java/build/install/sqs-evidence-java/bin
./run_client.sh aws-sdk-java-v2-2.57.11 data/java-sdk-v2.json "$bin/sqs-evidence-java"
./run_client.sh sqs-java-messaging-lib-2.1.5 data/jms.json "$bin/sqs-evidence-jms"
