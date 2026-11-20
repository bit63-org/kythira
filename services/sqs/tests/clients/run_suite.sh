#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS client suites (.kiro/specs/sqs-compatible-queues/ task 12,
# Requirements 13.1 and 13.2): real SQS clients run their scenarios against
# Kythira, each failing on any error or wrong answer (boto3 and the Java SDK
# check every MD5 digest).
#
# Usage: run_suite.sh [CLIENT...]
#   With SQS_SUITE_ENDPOINT set, the clients talk to that endpoint (a
#   layout someone else started; it must take keys.txt's key). Otherwise the
#   script starts $SQS_NODE with the deletion and purge cool-downs off,
#   because every client reuses its queue names, and stops it afterwards,
#   in the layout SQS_SUITE_LAYOUT names:
#     single     one in-memory node (the default)
#     split      three layers on five durable nodes (task 10): three data
#                nodes, a front end, and a gateway the clients talk to
#     split-tls  the same over TLS, each node holding a layer identity
#                (doc/configuration.md, "Layer identities") from a CA the
#                script makes with openssl; the clients trust that CA
#   The split layouts need a durable sqs_node (built with RocksDB).
#
#   With SQS_SUITE_REAL=1 they talk to real Amazon SQS in us-east-1 with
#   the caller's credentials, every client but the Extended Client
#   (tests/real_cloud/run_real_cloud.sh runs this; each run needs Clark's go).
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

export AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1
if [ "${SQS_SUITE_REAL:-}" = 1 ]; then
  # Real Amazon SQS (task 13's real-cloud bundle, tests/real_cloud/): the
  # caller's own credentials (AWS_PROFILE or the environment), us-east-1.
  # The Extended Client is left out: the bundle runs it on Kythira SQS
  # with real S3.
  SQS_SUITE_ENDPOINT=https://sqs.us-east-1.amazonaws.com
  for i in "${!clients[@]}"; do
    [ "${clients[$i]}" != extended ] || unset 'clients[i]'
  done
  clients=("${clients[@]}")
else
  export AWS_ACCESS_KEY_ID=AKIDEXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
  unset AWS_SESSION_TOKEN AWS_PROFILE
fi

free_port() { "$py" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() {
  for _ in $(seq 1 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

pids=()
scratch=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for d in "${scratch[@]}"; do rm -rf -- "$d"; done
}
trap cleanup EXIT

# A CA and one certificate per node, each with its layer identity, and the
# clients told to trust the CA (botocore, Go, Node and the JVM each their
# own way).
make_identities() {
  local d=$1
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/ca.key"
  openssl req -x509 -new -key "$d/ca.key" -subj /CN=sqs-suite-ca -days 2 -out "$d/ca.pem"
  local n id roles
  for spec in d1:1:data d2:2:data d3:3:data fe:4:front_end gw:5:gateway; do
    IFS=: read -r n id roles <<<"$spec"
    openssl ecparam -name prime256v1 -genkey -noout -out "$d/$n.key"
    openssl req -new -key "$d/$n.key" -subj "/CN=$n" -out "$d/$n.csr"
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,URI:kythira://sqs/suite/%s?roles=%s\nextendedKeyUsage=serverAuth,clientAuth\n' \
      "$id" "$roles" >"$d/$n.ext"
    openssl x509 -req -in "$d/$n.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial \
      -days 2 -extfile "$d/$n.ext" -out "$d/$n.crt" 2>/dev/null
  done
  cat /etc/ssl/certs/ca-certificates.crt "$d/ca.pem" >"$d/bundle.pem"
  keytool -importcert -noprompt -alias sqs-suite -file "$d/ca.pem" -keystore "$d/trust.p12" \
    -storetype PKCS12 -storepass changeit >/dev/null
  export AWS_CA_BUNDLE=$d/bundle.pem SSL_CERT_FILE=$d/bundle.pem NODE_EXTRA_CA_CERTS=$d/ca.pem
  export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djavax.net.ssl.trustStore=$d/trust.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12"
}

# Three data nodes, a front end over them and a gateway in front of it.
start_split() {
  local tls=$1 dir scheme
  dir=$(mktemp -d)
  scratch+=("$dir")
  scheme=http
  if [ "$tls" = 1 ]; then
    scheme=https
    make_identities "$dir" 2>/dev/null
  fi
  local api=() raft=() i
  for i in 1 2 3 4 5; do api+=("$(free_port)"); raft+=("$(free_port)"); done
  local gw_url=$scheme://127.0.0.1:${api[4]}
  # shellcheck disable=SC2054 # SQS_COMPAT takes a comma-separated list
  local common=(KYTHIRA_NODE_INSECURE_PLAINTEXT=1 SQS_STATIC_KEYS_FILE="$here/keys.txt"
    SQS_FORWARD_SECRET=suite-forwarding-secret-0123456789 KYTHIRA_LOG_LEVEL=warning
    SQS_COMPAT=delete-cooldown=0,purge-cooldown=0 SQS_ENDPOINT="$gw_url"
    KYTHIRA_NODE_RAFT_BIND=127.0.0.1)
  if [ "$tls" = 1 ]; then
    common+=(SQS_ALLOW_PLAINTEXT=off SQS_PEER_CA="$dir/ca.pem" SQS_IDENTITY_CLUSTER=suite)
  else
    common+=(SQS_ALLOW_PLAINTEXT=on)
  fi
  local peers="1=127.0.0.1:${raft[0]},2=127.0.0.1:${raft[1]},3=127.0.0.1:${raft[2]}"
  local listeners="1=$scheme://127.0.0.1:${api[0]},2=$scheme://127.0.0.1:${api[1]},3=$scheme://127.0.0.1:${api[2]}"
  local data="$scheme://127.0.0.1:${api[0]},$scheme://127.0.0.1:${api[1]},$scheme://127.0.0.1:${api[2]}"
  local names=(d1 d2 d3 fe gw)
  for i in 0 1 2 3 4; do
    local id=$((i + 1)) n=${names[$i]} own=()
    mkdir -p "$dir/$n"
    case $n in
      d*) own=(KYTHIRA_SQS_ROLES=data KYTHIRA_NODE_PEERS="$peers" SQS_PEER_ENDPOINTS="$listeners") ;;
      fe) own=(KYTHIRA_SQS_ROLES=front_end KYTHIRA_NODE_PEERS="$id=127.0.0.1:${raft[$i]}"
               SQS_DATA_ENDPOINTS="$data") ;;
      gw) own=(KYTHIRA_SQS_ROLES=gateway KYTHIRA_NODE_PEERS="$id=127.0.0.1:${raft[$i]}"
               SQS_FRONT_END_ENDPOINTS="$scheme://127.0.0.1:${api[3]}") ;;
    esac
    [ "$tls" = 1 ] && own+=(SQS_TLS_CERT="$dir/$n.crt" SQS_TLS_KEY="$dir/$n.key")
    env "${common[@]}" "${own[@]}" KYTHIRA_NODE_ID=$id KYTHIRA_NODE_DATA_DIR="$dir/$n" \
      KYTHIRA_NODE_RAFT_PORT="${raft[$i]}" SQS_LISTEN="127.0.0.1:${api[$i]}" \
      "$SQS_NODE" >"$dir/$n.log" 2>&1 &
    pids+=($!)
  done
  for i in 0 1 2 3 4; do
    wait_port "${api[$i]}" || { tail -n 20 "$dir"/*.log; exit 1; }
  done
  # Listening is not serving: wait until the data nodes have a leader.
  "$py" - "$gw_url" <<'PY' || { tail -n 20 "$dir"/*.log; exit 1; }
import sys, time
import boto3
sqs = boto3.client("sqs", endpoint_url=sys.argv[1])
end = time.monotonic() + 60
while True:
    try:
        sqs.list_queues()
        break
    except Exception as e:  # noqa: BLE001 - any failure means not yet
        if time.monotonic() > end:
            sys.exit(f"the split layout did not start serving: {e}")
        time.sleep(0.5)
PY
  endpoint=$gw_url
}

endpoint=${SQS_SUITE_ENDPOINT:-}
if [ -z "$endpoint" ]; then
  : "${SQS_NODE:?set SQS_NODE to the sqs_node binary, or SQS_SUITE_ENDPOINT}"
  case ${SQS_SUITE_LAYOUT:-single} in
    single)
      port=$(free_port)
      log=$(mktemp)
      SQS_LISTEN=127.0.0.1:$port SQS_ALLOW_PLAINTEXT=1 SQS_STATIC_KEYS_FILE=$here/keys.txt \
        SQS_COMPAT=delete-cooldown=0,purge-cooldown=0 "$SQS_NODE" >"$log" 2>&1 &
      pids+=($!)
      wait_port "$port" || { cat "$log"; exit 1; }
      endpoint=http://127.0.0.1:$port
      ;;
    split) start_split 0 ;;
    split-tls) start_split 1 ;;
    *) echo "unknown SQS_SUITE_LAYOUT: $SQS_SUITE_LAYOUT" >&2; exit 2 ;;
  esac
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
first=1
for c in "${clients[@]}"; do
  # Real SQS refuses to recreate a queue name for 60 s after its deletion,
  # and the evidence clients share theirs ("evidence"); Kythira's suite
  # turns that cool-down off.
  if [ "${SQS_SUITE_REAL:-}" = 1 ] && [ $first = 0 ]; then
    echo "(waiting 61 s: SQS's queue-name cool-down)"
    sleep 61
  fi
  first=0
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
