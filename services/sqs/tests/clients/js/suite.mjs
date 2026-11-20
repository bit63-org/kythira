// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The aws-sdk-js-v3 SQS suite against Kythira (run_suite.sh client "js"):
// attributes, typed message attributes, batches, visibility, FIFO ordering
// and deduplication, the modelled QueueDoesNotExist error, purge and
// delete. The client's MD5 middleware checks every body and attribute set,
// so a wrong digest fails the run. Usage: node suite.mjs ENDPOINT

import {
  SQSClient, CreateQueueCommand, GetQueueUrlCommand, GetQueueAttributesCommand,
  SendMessageCommand, SendMessageBatchCommand, ReceiveMessageCommand,
  ChangeMessageVisibilityCommand, DeleteMessageCommand, DeleteMessageBatchCommand,
  PurgeQueueCommand, DeleteQueueCommand, QueueDoesNotExist,
} from "@aws-sdk/client-sqs";

const check = (ok, what) => {
  if (!ok) throw new Error(`js suite: ${what}`);
};

const c = new SQSClient({ endpoint: process.argv[2], region: "us-east-1" });
const send = (cmd) => c.send(cmd);

const { QueueUrl: url } = await send(new CreateQueueCommand({
  QueueName: "suite-js", Attributes: { VisibilityTimeout: "30" },
}));
const { QueueUrl: got } = await send(new GetQueueUrlCommand({ QueueName: "suite-js" }));
check(got === url, `GetQueueUrl ${got} != ${url}`);
const { Attributes: attrs } = await send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ["All"] }));
check(attrs.VisibilityTimeout === "30", `attributes ${JSON.stringify(attrs)}`);

await send(new SendMessageCommand({
  QueueUrl: url, MessageBody: "hello js",
  MessageAttributes: {
    color: { DataType: "String", StringValue: "blue" },
    count: { DataType: "Number", StringValue: "7" },
    blob: { DataType: "Binary", BinaryValue: Uint8Array.of(0, 1, 2) },
  },
}));
const sent = await send(new SendMessageBatchCommand({
  QueueUrl: url,
  Entries: [0, 1, 2].map((i) => ({ Id: `e${i}`, MessageBody: `batch-${i}` })),
}));
check(sent.Successful.length === 3, "batch send");

let msgs = [];
for (let i = 0; i < 10 && msgs.length < 4; ++i) {
  const out = await send(new ReceiveMessageCommand({
    QueueUrl: url, MaxNumberOfMessages: 10, WaitTimeSeconds: 1,
    MessageSystemAttributeNames: ["All"], MessageAttributeNames: ["All"],
  }));
  msgs = msgs.concat(out.Messages ?? []);
}
check(msgs.length === 4, `received ${msgs.length}`);
const hello = msgs.find((m) => m.Body === "hello js");
check(hello?.MessageAttributes.color.StringValue === "blue", "color attribute");
check(Buffer.from(hello.MessageAttributes.blob.BinaryValue).equals(Buffer.from([0, 1, 2])), "binary attribute");
check(hello.Attributes.ApproximateReceiveCount === "1", "receive count");

await send(new ChangeMessageVisibilityCommand({ QueueUrl: url, ReceiptHandle: hello.ReceiptHandle, VisibilityTimeout: 0 }));
const again = (await send(new ReceiveMessageCommand({ QueueUrl: url, WaitTimeSeconds: 5 }))).Messages ?? [];
check(again.length === 1 && again[0].Body === "hello js", "visibility reset");

const del = await send(new DeleteMessageBatchCommand({
  QueueUrl: url,
  Entries: msgs.filter((m) => m !== hello).map((m) => ({ Id: m.MessageId, ReceiptHandle: m.ReceiptHandle })),
}));
check((del.Failed ?? []).length === 0, "batch delete");
await send(new DeleteMessageCommand({ QueueUrl: url, ReceiptHandle: again[0].ReceiptHandle }));

const { QueueUrl: fifo } = await send(new CreateQueueCommand({
  QueueName: "suite-js.fifo", Attributes: { FifoQueue: "true" },
}));
for (const n of [0, 1, 2, 0]) { // the second f0 is a retry, dropped by deduplication
  await send(new SendMessageCommand({
    QueueUrl: fifo, MessageBody: `f${n}`, MessageGroupId: "g", MessageDeduplicationId: `d${n}`,
  }));
}
const order = [];
for (let i = 0; i < 10 && order.length < 3; ++i) {
  const out = await send(new ReceiveMessageCommand({ QueueUrl: fifo, MaxNumberOfMessages: 10, WaitTimeSeconds: 1 }));
  for (const m of out.Messages ?? []) {
    order.push(m.Body);
    await send(new DeleteMessageCommand({ QueueUrl: fifo, ReceiptHandle: m.ReceiptHandle }));
  }
}
check(order.join() === "f0,f1,f2", `FIFO order ${order}`);

try {
  await send(new GetQueueUrlCommand({ QueueName: "suite-js-missing" }));
  check(false, "GetQueueUrl of a missing queue succeeded");
} catch (e) {
  check(e instanceof QueueDoesNotExist, `GetQueueUrl of a missing queue: ${e}`);
}

await send(new SendMessageCommand({ QueueUrl: url, MessageBody: "to purge" }));
await send(new PurgeQueueCommand({ QueueUrl: url }));
const left = (await send(new ReceiveMessageCommand({ QueueUrl: url, WaitTimeSeconds: 1 }))).Messages ?? [];
check(left.length === 0, `purge left ${left.length}`);
await send(new DeleteQueueCommand({ QueueUrl: url }));
await send(new DeleteQueueCommand({ QueueUrl: fifo }));
