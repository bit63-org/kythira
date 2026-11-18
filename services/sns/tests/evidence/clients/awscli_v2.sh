#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The evidence scenario through the AWS CLI v2 (`aws` on PATH, or $AWS_CLI).
# README.md lists the steps; every client runs the same ones.
# Usage: awscli_v2.sh ENDPOINT
set -euo pipefail
endpoint=$1
aws=${AWS_CLI:-aws}
s() { "$aws" --endpoint-url "$endpoint" --no-cli-pager --output json sns "$@"; }
q() { s "$@" >/dev/null; }
acct=arn:aws:sns:us-east-1:123456789012
topic=$acct:evidence fifo=$acct:evidence.fifo
token=deadbeefdeadbeefdeadbeefdeadbeef00000000000000000000000000000000
filter='{"color":["red",{"prefix":"bl"}],"size":[{"numeric":[">",3]}]}'

q create-topic --name evidence --attributes DisplayName=Evidence --tags Key=team,Value=kythira
q create-topic --name evidence.fifo \
  --attributes FifoTopic=true,ContentBasedDeduplication=true
q list-topics
q get-topic-attributes --topic-arn "$topic"
q set-topic-attributes --topic-arn "$topic" --attribute-name DisplayName \
  --attribute-value "Evidence 2"
queue_sub=$(s subscribe --topic-arn "$topic" --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:123456789012:evidence-queue \
  --attributes "$(printf '{"RawMessageDelivery":"true","FilterPolicy":%s}' \
    "$(printf '%s' "$filter" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')")" \
  --return-subscription-arn --query SubscriptionArn --output text)
q subscribe --topic-arn "$topic" --protocol http --notification-endpoint http://127.0.0.1:9/hook
q confirm-subscription --topic-arn "$topic" --token "$token" \
  --authenticate-on-unsubscribe true
q list-subscriptions-by-topic --topic-arn "$topic"
q set-subscription-attributes --subscription-arn "$queue_sub" \
  --attribute-name FilterPolicyScope --attribute-value MessageBody
q get-subscription-attributes --subscription-arn "$queue_sub"
q publish --topic-arn "$topic" --subject hello --message "hello, world" \
  --message-attributes '{"color":{"DataType":"String","StringValue":"red"},
    "size":{"DataType":"Number","StringValue":"4"},
    "blob":{"DataType":"Binary","BinaryValue":"AAH+/w=="},
    "tags":{"DataType":"String.Array","StringValue":"[\"a\",\"b\"]"}}'
q publish --topic-arn "$topic" --message-structure json \
  --message '{"default":"fallback","sqs":"to queues","http":"to endpoints"}'
q publish --topic-arn "$fifo" --message first --message-group-id g1
q publish-batch --topic-arn "$fifo" --publish-batch-request-entries \
  '[{"Id":"one","Message":"second","MessageGroupId":"g1"},
    {"Id":"two","Message":"third","MessageGroupId":"g2","MessageDeduplicationId":"dedup-3",
     "MessageAttributes":{"color":{"DataType":"String","StringValue":"blue"}}}]'
q tag-resource --resource-arn "$topic" --tags Key=env,Value=test
q list-tags-for-resource --resource-arn "$topic"
q untag-resource --resource-arn "$topic" --tag-keys env
q unsubscribe --subscription-arn "$queue_sub"
q delete-topic --topic-arn "$fifo"
q delete-topic --topic-arn "$topic"
