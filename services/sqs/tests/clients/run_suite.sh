#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS client suites (.kiro/specs/sqs-compatible-queues/ task 12,
# Requirements 13.1 and 13.2): real SQS clients run their scenarios against
# Kythira, each failing on any error or wrong answer (boto3 and the Java SDK
# check every MD5 digest).
#
# Usage: run_suite.sh [CLIENT...]
#   With SQS_SUITE_ENDPOINT set, the clients talk to that endpoint (a split
#   layout someone else started; it must take keys.txt's key). Otherwise the
#   script starts $SQS_NODE (sqs_node, in-memory, one node) on a free port
#   with the deletion and purge cool-downs off, because every client reuses
#   its queue names, and stops it afterwards.
#
# Clients (all by default):
#   awscli       AWS CLI v2                          $AWS_CLI (default aws)
#   boto3        boto3, AWS JSON 1.0                 $SUITE_PYTHON with ../evidence/requirements.txt
#   boto3-query  boto3, query protocol               $QUERY_PYTHON with ../evidence/requirements-query.txt
#   kombu        Kombu, Celery's transport           $SUITE_PYTHON
#   go           aws-sdk-go-v2                       $SUITE_GO (default: go run ./go)
#   js           aws-sdk-js-v3                       node, after npm ci in ./js
#   java-sdk     aws-sdk-java-v2                     $JAVA_CLIENTS (installDist of ../evidence/clients/java)
#   jms          Amazon SQS Java Messaging Library   $JAVA_CLIENTS
#   java-v1      aws-sdk-java v1, query protocol     $SUITE_JAVA_CLIENTS (installDist of ./java)
#   spring       Spring Cloud AWS SQS listener       $SUITE_JAVA_CLIENTS
#   extended     Amazon SQS Extended Client (S3)     $SUITE_JAVA_CLIENTS, with $SUITE_PYTHON's moto as S3
#
# A client whose runtime is not configured fails the run; name the clients
# to run a subset.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
evidence=$here/../evidence/clients
py=${SUITE_PYTHON:-python3}
clients=("$@")
[ ${#clients[@]} -gt 0 ] || clients=(awscli boto3 boto3-query kombu go js java-sdk jms java-v1 spring extended)

export AWS_ACCESS_KEY_ID=AKIDEXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1
unset AWS_SESSION_TOKEN AWS_PROFILE

free_port() { "$py" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() {
  for _ in $(seq 1 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

endpoint=${SQS_SUITE_ENDPOINT:-}
if [ -z "$endpoint" ]; then
  port=$(free_port)
  log=$(mktemp)
  SQS_LISTEN=127.0.0.1:$port SQS_ALLOW_PLAINTEXT=1 SQS_STATIC_KEYS_FILE=$here/keys.txt \
    SQS_COMPAT=delete-cooldown=0,purge-cooldown=0 \
    "${SQS_NODE:?set SQS_NODE to the sqs_node binary, or SQS_SUITE_ENDPOINT}" >"$log" 2>&1 &
  pids+=($!)
  wait_port "$port" || { cat "$log"; exit 1; }
  endpoint=http://127.0.0.1:$port
fi

java_bin() { echo "${JAVA_CLIENTS:?set JAVA_CLIENTS to the evidence installDist bin directory}/$1"; }
suite_bin() { echo "${SUITE_JAVA_CLIENTS:?set SUITE_JAVA_CLIENTS to ./java installDist bin directory}/$1"; }

run() {
  case $1 in
    awscli) AWS_CLI=${AWS_CLI:-aws} "$evidence/awscli_v2.sh" "$endpoint" ;;
    boto3) "$py" "$evidence/boto3_client.py" "$endpoint" ;;
    boto3-query) "${QUERY_PYTHON:?set QUERY_PYTHON}" "$evidence/boto3_client.py" "$endpoint" ;;
    kombu) "$py" "$evidence/kombu_client.py" "$endpoint" ;;
    go)
      if [ -n "${SUITE_GO:-}" ]; then "$SUITE_GO" "$endpoint"
      else (cd "$here/go" && go run . "$endpoint"); fi
      ;;
    js) node "$here/js/suite.mjs" "$endpoint" ;;
    java-sdk) "$(java_bin sqs-evidence-java)" "$endpoint" ;;
    jms) "$(java_bin sqs-evidence-jms)" "$endpoint" ;;
    java-v1) "$(suite_bin sqs-suite-java-v1)" "$endpoint" ;;
    spring) "$(suite_bin sqs-suite-spring)" "$endpoint" ;;
    extended)
      s3_port=$(free_port)
      "$py" -m moto.server -H 127.0.0.1 -p "$s3_port" >/dev/null 2>&1 &
      pids+=($!)
      wait_port "$s3_port" || { echo "moto did not start" >&2; return 1; }
      "$(suite_bin sqs-suite-extended)" "$endpoint" "http://127.0.0.1:$s3_port"
      ;;
    *) echo "unknown client: $1" >&2; return 2 ;;
  esac
}

failed=()
for c in "${clients[@]}"; do
  echo "== $c"
  start=$(date +%s)
  if run "$c"; then
    echo "-- $c passed ($(( $(date +%s) - start )) s)"
  else
    echo "-- $c FAILED" >&2
    failed+=("$c")
  fi
done
if [ ${#failed[@]} -gt 0 ]; then
  echo "failed: ${failed[*]}" >&2
  exit 1
fi
echo "all ${#clients[@]} clients passed against $endpoint"
