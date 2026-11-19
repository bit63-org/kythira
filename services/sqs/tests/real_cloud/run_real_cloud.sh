#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS module's real-cloud bundle (.kiro/specs/sqs-compatible-queues/
# task 13, Requirement 13.4). Every run spends money on Clark's AWS account
# and needs his go; it reports what it made and deletes it.
#
#   1. compare  the client suite (tests/clients/run_suite.sh) against real
#               Amazon SQS and against sqs_node, client by client;
#   2. extended the Amazon SQS Extended Client on Kythira SQS with its
#               payloads in a real S3 bucket the run creates and removes;
#   3. sns      a real SNS topic delivering through the bridge
#               (doc/sns-bridge.md) to a Kythira queue, wrapped and raw.
#               SNS needs a public HTTPS endpoint, so sqs_node is reached
#               through a Cloudflare quick tunnel (cloudflared, no account)
#               for the few minutes the part runs.
#
# Usage: run_real_cloud.sh [compare] [extended] [sns]     (all by default)
#
# Environment:
#   AWS_PROFILE (or AWS_* keys)  the account to spend on, us-east-1
#   SQS_NODE                     the sqs_node binary (in-memory is enough)
#   CLOUDFLARED                  cloudflared (default: on PATH; the sns part
#                                fails without it)
#   SUITE_PYTHON, QUERY_PYTHON, AWS_CLI, SUITE_GO, JAVA_CLIENTS,
#   SUITE_JAVA_CLIENTS           as run_suite.sh takes them
#   REAL_CLOUD_OUT               where logs and the report go (default:
#                                ./sqs-real-cloud-<run id>)
#
# The cost is a few thousand SQS requests, a dozen S3 requests and a
# handful of SNS publishes: well under one cent. The report counts what
# each part made and confirms it was deleted.

set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
suite=$here/../clients/run_suite.sh
keys=$here/../clients/keys.txt
py=${SUITE_PYTHON:-python3}
aws_cli=${AWS_CLI:-aws}
export AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1
# Kythira's key (tests/clients/keys.txt), for the local node only.
kythira_key=AKIDEXAMPLE
kythira_secret=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
kythira_account=111122223333

parts=("$@")
[ ${#parts[@]} -gt 0 ] || parts=(compare extended sns)
run_id=$(date -u +%Y%m%d%H%M%S)-$RANDOM
out=${REAL_CLOUD_OUT:-$PWD/sqs-real-cloud-$run_id}
mkdir -p "$out"
report=$out/report.md

: "${SQS_NODE:?set SQS_NODE to the sqs_node binary}"
account=$("$aws_cli" sts get-caller-identity --query Account --output text) || {
  echo "no AWS credentials (set AWS_PROFILE)" >&2
  exit 2
}

pids=()
cleanups=()
cleanup_failed=false
cleanup() {
  local i
  for (( i=${#cleanups[@]}-1; i>=0; i-- )); do
    echo "cleanup: ${cleanups[$i]}" >>"$out/cleanup.log"
    if ! eval "${cleanups[$i]}" >>"$out/cleanup.log" 2>&1; then
      echo "cleanup FAILED: ${cleanups[$i]}" | tee -a "$out/cleanup.log" >&2
      cleanup_failed=true
    fi
  done
  cleanups=()
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

free_port() { "$py" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() {
  for _ in $(seq 1 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# An in-memory sqs_node on a free port, into $node_port. Not called through
# $(...): the pid must reach the EXIT cleanup.
node_port=""
start_node() {
  local log=$1
  shift
  node_port=$(free_port)
  env -u KYTHIRA_NODE_DATA_DIR SQS_LISTEN="127.0.0.1:$node_port" SQS_ALLOW_PLAINTEXT=1 \
    KYTHIRA_NODE_INSECURE_PLAINTEXT=1 SQS_STATIC_KEYS_FILE="$keys" \
    SQS_COMPAT=delete-cooldown=0,purge-cooldown=0 KYTHIRA_LOG_LEVEL=warning "$@" \
    "$SQS_NODE" >"$log" 2>&1 &
  pids+=($!)
  wait_port "$node_port" || { echo "sqs_node did not start (see $log)" >&2; return 1; }
}

{
  echo "# SQS real-cloud run $run_id"
  echo
  echo "Account $account, us-east-1, parts: ${parts[*]}."
  echo
} >"$report"
status=0

# ---- 1. compare ---------------------------------------------------------
queues_before=""
# The queue-name prefixes the clients create: the suites' and the evidence
# clients' (evidence, evidence.fifo, evidence-jms, kombu's evidence-celery).
client_queue_prefixes=(suite- evidence)
client_queues() {
  local p
  for p in "${client_queue_prefixes[@]}"; do
    "$aws_cli" sqs list-queues --queue-name-prefix "$p" --query 'QueueUrls' --output text |
      tr '\t' '\n' | grep -v -e '^None$' -e '^$' || true
  done
}
# shellcheck disable=SC2329  # run through cleanups (eval)
delete_new_client_queues() {
  local q
  for q in $(client_queues); do
    grep -qxF -- "$q" <<<"$queues_before" && continue
    echo "deleting leftover $q"
    "$aws_cli" sqs delete-queue --queue-url "$q"
  done
}
part_compare() {
  local c real kyt
  # Queues a client leaves behind on SQS (a failure midway) are this run's
  # to delete; queues that were there before are not.
  queues_before=$(client_queues)
  cleanups+=("delete_new_client_queues")
  local clients=(awscli boto3 boto3-query kombu go js java-sdk jms java-v1 spring)
  echo "== compare: real SQS"
  SQS_SUITE_REAL=1 "$suite" "${clients[@]}" >"$out/compare-sqs.log" 2>&1
  echo "== compare: Kythira"
  env -u AWS_PROFILE "$suite" "${clients[@]}" >"$out/compare-kythira.log" 2>&1
  {
    echo "## 1. Client suite: real SQS and Kythira"
    echo
    echo "| Client | Real SQS | Kythira |"
    echo "|---|---|---|"
  } >>"$report"
  for c in "${clients[@]}"; do
    real=FAILED kyt=FAILED
    grep -q -- "^-- $c passed" "$out/compare-sqs.log" && real=passed
    grep -q -- "^-- $c passed" "$out/compare-kythira.log" && kyt=passed
    echo "| $c | $real | $kyt |" >>"$report"
    [ "$real" = passed ] && [ "$kyt" = passed ] || status=1
  done
  echo >>"$report"
}

# ---- 2. extended --------------------------------------------------------
part_extended() {
  local bucket=kythira-sqs-ext-$account-$run_id port result=FAILED
  bucket=${bucket:0:63}
  start_node "$out/extended-node.log" || { status=1; return; }
  port=$node_port
  "$aws_cli" s3api create-bucket --bucket "$bucket" >"$out/extended.log" 2>&1 || {
    printf '## 2. Extended Client\n\nCould not create bucket %s (see extended.log).\n\n' "$bucket" >>"$report"
    status=1
    return
  }
  cleanups+=("$aws_cli s3 rb --force s3://$bucket")
  echo "== extended: Kythira SQS, real S3 bucket $bucket"
  local bin=${SUITE_JAVA_CLIENTS:?set SUITE_JAVA_CLIENTS}/sqs-suite-extended
  if SUITE_EXTENDED_BUCKET=$bucket SUITE_SQS_ACCESS_KEY_ID=$kythira_key \
       SUITE_SQS_SECRET_ACCESS_KEY=$kythira_secret \
       "$bin" "http://127.0.0.1:$port" aws >>"$out/extended.log" 2>&1; then
    result=passed
  else
    status=1
  fi
  {
    echo "## 2. Extended Client on Kythira SQS with real S3"
    echo
    echo "$result: a 300 KiB body stored in s3://$bucket and read back, its object removed on delete, a small body inline. The bucket is removed at the end."
    echo
  } >>"$report"
}

# ---- 3. sns -------------------------------------------------------------
part_sns() {
  local cf=${CLOUDFLARED:-cloudflared} port url topic queue sub result
  if ! command -v "$cf" >/dev/null; then
    printf '## 3. SNS bridge\n\nNot run: cloudflared not found (set CLOUDFLARED).\n\n' >>"$report"
    status=1
    return
  fi
  start_node "$out/sns-node.log" SQS_SNS_BRIDGE=on || { status=1; return; }
  port=$node_port
  "$cf" tunnel --no-autoupdate --url "http://127.0.0.1:$port" >"$out/cloudflared.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 60); do
    url=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$out/cloudflared.log" | head -1)
    [ -n "$url" ] && break
    sleep 1
  done
  [ -n "${url:-}" ] || { printf '## 3. SNS bridge\n\nNo tunnel (see cloudflared.log).\n\n' >>"$report"; status=1; return; }
  # The tunnel answers once its edge has the route.
  for _ in $(seq 1 60); do
    curl -fsS -o /dev/null "$url/sns-bridge/" 2>/dev/null && break
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/sns-bridge/")" -lt 500 ] && break
    sleep 2
  done
  queue=real-sns-$run_id
  topic=$("$aws_cli" sns create-topic --name "kythira-sqs-bridge-$run_id" --query TopicArn --output text) || { status=1; return; }
  cleanups+=("$aws_cli sns delete-topic --topic-arn $topic")
  echo "== sns: topic $topic -> $url -> Kythira queue $queue"
  AWS_ACCESS_KEY_ID=$kythira_key AWS_SECRET_ACCESS_KEY=$kythira_secret \
    "$py" "$here/sns_bridge_check.py" setup "http://127.0.0.1:$port" "$queue" "$topic" \
    >>"$out/sns.log" 2>&1 || { status=1; return; }
  sub=$("$aws_cli" sns subscribe --topic-arn "$topic" --protocol https \
          --notification-endpoint "$url/sns-bridge/$kythira_account/$queue" \
          --return-subscription-arn --query SubscriptionArn --output text) || { status=1; return; }
  cleanups+=("$aws_cli sns unsubscribe --subscription-arn $sub")
  local confirmed=false
  for _ in $(seq 1 60); do
    if [ "$("$aws_cli" sns get-subscription-attributes --subscription-arn "$sub" \
             --query Attributes.PendingConfirmation --output text 2>/dev/null)" = false ]; then
      confirmed=true
      break
    fi
    sleep 2
  done
  check() {
    AWS_ACCESS_KEY_ID=$kythira_key AWS_SECRET_ACCESS_KEY=$kythira_secret \
      "$py" "$here/sns_bridge_check.py" "$1" "http://127.0.0.1:$port" "$queue" "$topic" \
      >>"$out/sns.log" 2>&1
  }
  publish() {
    "$aws_cli" sns publish --topic-arn "$topic" --message "$1" --message-attributes \
      '{"color":{"DataType":"String","StringValue":"blue"}}' >>"$out/sns.log" 2>&1
  }
  result=FAILED
  if $confirmed && publish wrapped-1 && publish wrapped-2 && publish wrapped-3 \
       && check wrapped && check raw-on && publish raw-1 && check raw; then
    result=passed
  else
    status=1
  fi
  {
    echo "## 3. Real SNS through the bridge"
    echo
    echo "$result: subscription confirmed by the bridge: $confirmed; three wrapped deliveries with message attributes and one raw delivery checked in Kythira queue $queue (sns.log). The topic and subscription are deleted at the end."
    echo
  } >>"$report"
}

for p in "${parts[@]}"; do
  case "$p" in
    compare) part_compare ;;
    extended) part_extended ;;
    sns) part_sns ;;
    *) echo "unknown part: $p" >&2; exit 2 ;;
  esac
done

cleanup
trap - EXIT
{
  echo "## Cleanup and cost"
  echo
  if $cleanup_failed; then
    echo "Some cleanup failed; see cleanup.log."
  else
    echo "Everything the run made was deleted (cleanup.log)."
  fi
  echo "Cost: a few thousand SQS requests, a dozen S3 requests and five SNS publishes, under \$0.01."
} >>"$report"
cat "$report"
exit $status
