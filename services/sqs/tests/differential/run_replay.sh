#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Replays the SQS differential (.kiro/specs/sqs-compatible-queues/ task 13)
# against a fresh in-memory $SQS_NODE at SQS's default limits (the client
# suites turn the cool-downs off; this must not). First a self-check, the
# mix run twice against the node, which must answer alike; then every
# recordings/aws-seed-*.json compared against it.
#
# Usage: SQS_NODE=... SUITE_PYTHON=... run_replay.sh [SEED STEPS]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
py=${SUITE_PYTHON:-python3}
seed=${1:-7}
steps=${2:-120}

export AWS_ACCESS_KEY_ID=AKIDEXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1
unset AWS_SESSION_TOKEN AWS_PROFILE

port=$("$py" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
log=$(mktemp)
SQS_LISTEN=127.0.0.1:$port SQS_ALLOW_PLAINTEXT=1 SQS_STATIC_KEYS_FILE=$here/../clients/keys.txt \
  KYTHIRA_LOG_LEVEL=warning "${SQS_NODE:?set SQS_NODE}" >"$log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
  sleep 0.1
done
endpoint=http://127.0.0.1:$port

"$py" "$here/sqs_differential.py" self-check --endpoints "$endpoint,$endpoint" \
  --seed "$seed" --steps "$steps"
if compgen -G "$here/recordings/aws-seed-*.json" >/dev/null; then
  "$py" "$here/sqs_differential.py" compare --endpoint "$endpoint" \
    --recording "$here/recordings" --allow "$here/recordings/allow.json"
else
  echo "no recordings yet (recordings/README.md); self-check only"
fi
