#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The evidence scenario through the AWS CLI v2 (`aws` on PATH, or $AWS_CLI).
# Usage: awscli_v2.sh ENDPOINT
set -euo pipefail
endpoint=$1
aws=${AWS_CLI:-aws}
s() { "$aws" --endpoint-url "$endpoint" --no-cli-pager --output json sqs "$@"; }
url=$(s create-queue --queue-name evidence --attributes VisibilityTimeout=45 \
  --tags team=kythira --query QueueUrl --output text)
s get-queue-url --queue-name evidence >/dev/null
s get-queue-attributes --queue-url "$url" --attribute-names All >/dev/null
s list-queues >/dev/null
s send-message --queue-url "$url" --message-body hello \
  --message-attributes '{"s":{"DataType":"String","StringValue":"text"},"b":{"DataType":"Binary","BinaryValue":"AAEC"}}' \
  >/dev/null
s send-message-batch --queue-url "$url" \
  --entries Id=one,MessageBody=one Id=two,MessageBody=two >/dev/null
handle=$(s receive-message --queue-url "$url" --max-number-of-messages 1 \
  --message-attribute-names All --attribute-names All --wait-time-seconds 1 \
  --query 'Messages[0].ReceiptHandle' --output text)
s change-message-visibility --queue-url "$url" --receipt-handle "$handle" \
  --visibility-timeout 0 >/dev/null
s delete-message --queue-url "$url" --receipt-handle "$handle" >/dev/null
s purge-queue --queue-url "$url" >/dev/null
s delete-queue --queue-url "$url" >/dev/null
