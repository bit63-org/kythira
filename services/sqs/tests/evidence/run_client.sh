#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Run one evidence client against a fresh recorder and write its evidence.
# Usage: run_client.sh NAME OUT.json COMMAND... ; the client gets the
# endpoint URL as its last argument. Credentials are fixed dummies, so the
# signature is real SigV4 but nothing can reach AWS. The recorder runs under
# $RECORDER_PYTHON, which needs the query-era botocore of
# requirements-query.txt (recorder.py's docstring says why).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
name=$1 out=$2
shift 2
py=${RECORDER_PYTHON:-python3}
fifo=$(mktemp -u); mkfifo "$fifo"
"$py" "$here/recorder.py" --client "$name" --out "$out" >"$fifo" &
rec=$!
read -r port <"$fifo"; rm -f "$fifo"
endpoint="http://127.0.0.1:$port"
export AWS_ACCESS_KEY_ID=AKIDEXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1
unset AWS_SESSION_TOKEN AWS_PROFILE
rc=0
"$@" "$endpoint" || rc=$?
kill -TERM "$rec"; wait "$rec" || true
exit $rc
