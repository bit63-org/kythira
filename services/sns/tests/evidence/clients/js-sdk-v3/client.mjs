// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The evidence scenario through the AWS SDK for JavaScript v3 (README.md).
// Usage: node client.mjs ENDPOINT

import assert from "node:assert/strict";
import * as sns from "@aws-sdk/client-sns";

const TOKEN = "deadbeefdeadbeefdeadbeefdeadbeef" + "0".repeat(32);
const QUEUE = "arn:aws:sqs:us-east-1:123456789012:evidence-queue";
const FILTER = JSON.stringify({ color: ["red", { prefix: "bl" }], size: [{ numeric: [">", 3] }] });

const c = new sns.SNSClient({ endpoint: process.argv[2], region: "us-east-1" });
const send = (Cmd, input) => c.send(new Cmd(input));

const { TopicArn: topic } = await send(sns.CreateTopicCommand, {
  Name: "evidence", Attributes: { DisplayName: "Evidence" },
  Tags: [{ Key: "team", Value: "kythira" }],
});
const { TopicArn: fifo } = await send(sns.CreateTopicCommand, {
  Name: "evidence.fifo", Attributes: { FifoTopic: "true", ContentBasedDeduplication: "true" },
});
await send(sns.ListTopicsCommand, {});
await send(sns.GetTopicAttributesCommand, { TopicArn: topic });
await send(sns.SetTopicAttributesCommand, {
  TopicArn: topic, AttributeName: "DisplayName", AttributeValue: "Evidence 2",
});
const { SubscriptionArn: queueSub } = await send(sns.SubscribeCommand, {
  TopicArn: topic, Protocol: "sqs", Endpoint: QUEUE,
  Attributes: { RawMessageDelivery: "true", FilterPolicy: FILTER }, ReturnSubscriptionArn: true,
});
await send(sns.SubscribeCommand, {
  TopicArn: topic, Protocol: "http", Endpoint: "http://127.0.0.1:9/hook",
});
await send(sns.ConfirmSubscriptionCommand, {
  TopicArn: topic, Token: TOKEN, AuthenticateOnUnsubscribe: "true",
});
await send(sns.ListSubscriptionsByTopicCommand, { TopicArn: topic });
await send(sns.SetSubscriptionAttributesCommand, {
  SubscriptionArn: queueSub, AttributeName: "FilterPolicyScope", AttributeValue: "MessageBody",
});
await send(sns.GetSubscriptionAttributesCommand, { SubscriptionArn: queueSub });
await send(sns.PublishCommand, {
  TopicArn: topic, Subject: "hello", Message: "hello, world",
  MessageAttributes: {
    color: { DataType: "String", StringValue: "red" },
    size: { DataType: "Number", StringValue: "4" },
    blob: { DataType: "Binary", BinaryValue: new Uint8Array([0, 1, 0xfe, 0xff]) },
    tags: { DataType: "String.Array", StringValue: '["a","b"]' },
  },
});
await send(sns.PublishCommand, {
  TopicArn: topic, MessageStructure: "json",
  Message: JSON.stringify({ default: "fallback", sqs: "to queues", http: "to endpoints" }),
});
const first = await send(sns.PublishCommand, {
  TopicArn: fifo, Message: "first", MessageGroupId: "g1",
});
assert.ok(first.SequenceNumber, "no sequence number from a FIFO topic");
await send(sns.PublishBatchCommand, {
  TopicArn: fifo,
  PublishBatchRequestEntries: [
    { Id: "one", Message: "second", MessageGroupId: "g1" },
    {
      Id: "two", Message: "third", MessageGroupId: "g2", MessageDeduplicationId: "dedup-3",
      MessageAttributes: { color: { DataType: "String", StringValue: "blue" } },
    },
  ],
});
await send(sns.TagResourceCommand, { ResourceArn: topic, Tags: [{ Key: "env", Value: "test" }] });
const { Tags: tags } = await send(sns.ListTagsForResourceCommand, { ResourceArn: topic });
assert.equal(tags.length, 2);
await send(sns.UntagResourceCommand, { ResourceArn: topic, TagKeys: ["env"] });
await send(sns.UnsubscribeCommand, { SubscriptionArn: queueSub });
await send(sns.DeleteTopicCommand, { TopicArn: fifo });
await send(sns.DeleteTopicCommand, { TopicArn: topic });
