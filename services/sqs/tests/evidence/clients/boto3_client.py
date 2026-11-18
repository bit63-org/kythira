#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""The evidence scenario through boto3. Usage: boto3_client.py ENDPOINT

Run with boto3 1.43.100 it speaks AWS JSON 1.0; with the query-era
botocore of requirements-query.txt it speaks the query protocol. Both runs
use this one script, so the two recordings differ only by protocol. boto3
checks every MD5 digest the stub returns, so a wrong digest fails here.
"""

import sys

import boto3

sqs = boto3.client("sqs", endpoint_url=sys.argv[1], region_name="us-east-1")
url = sqs.create_queue(QueueName="evidence",
                       Attributes={"VisibilityTimeout": "45", "DelaySeconds": "0"},
                       tags={"team": "kythira"})["QueueUrl"]
assert sqs.get_queue_url(QueueName="evidence")["QueueUrl"] == url
sqs.set_queue_attributes(QueueUrl=url, Attributes={"ReceiveMessageWaitTimeSeconds": "1"})
sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])
sqs.list_queues(QueueNamePrefix="evi")
sqs.tag_queue(QueueUrl=url, Tags={"env": "evidence"})
sqs.list_queue_tags(QueueUrl=url)
sqs.untag_queue(QueueUrl=url, TagKeys=["env"])

sqs.send_message(
    QueueUrl=url, MessageBody="hello",
    MessageAttributes={
        "s": {"DataType": "String", "StringValue": "text"},
        "n": {"DataType": "Number.int", "StringValue": "42"},
        "b": {"DataType": "Binary", "BinaryValue": b"\x00\x01\x02"},
    },
    MessageSystemAttributes={"AWSTraceHeader": {
        "DataType": "String",
        "StringValue": "Root=1-5759e988-bd862e3fe1be46a994272793;Sampled=1"}})
sqs.send_message_batch(QueueUrl=url, Entries=[
    {"Id": "one", "MessageBody": "one"},
    {"Id": "two", "MessageBody": "two", "DelaySeconds": 0,
     "MessageAttributes": {"k": {"DataType": "String", "StringValue": "v"}}},
])
got = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
                          VisibilityTimeout=30, MessageAttributeNames=["All"],
                          AttributeNames=["All"])["Messages"]
assert [m["Body"] for m in got] == ["hello", "one", "two"], got
assert got[0]["MessageAttributes"]["b"]["BinaryValue"] == b"\x00\x01\x02"
sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=got[0]["ReceiptHandle"],
                              VisibilityTimeout=60)
sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
    {"Id": "one", "ReceiptHandle": got[1]["ReceiptHandle"], "VisibilityTimeout": 60}])
sqs.delete_message(QueueUrl=url, ReceiptHandle=got[0]["ReceiptHandle"])
sqs.delete_message_batch(QueueUrl=url, Entries=[
    {"Id": "one", "ReceiptHandle": got[1]["ReceiptHandle"]},
    {"Id": "two", "ReceiptHandle": got[2]["ReceiptHandle"]}])
assert "Messages" not in sqs.receive_message(QueueUrl=url, WaitTimeSeconds=0)
sqs.purge_queue(QueueUrl=url)

fifo = sqs.create_queue(QueueName="evidence.fifo", Attributes={
    "FifoQueue": "true", "ContentBasedDeduplication": "false"})["QueueUrl"]
sqs.send_message(QueueUrl=fifo, MessageBody="first", MessageGroupId="g1",
                 MessageDeduplicationId="d1")
fgot = sqs.receive_message(QueueUrl=fifo, AttributeNames=["MessageGroupId"],
                           ReceiveRequestAttemptId="attempt-1")["Messages"]
sqs.delete_message(QueueUrl=fifo, ReceiptHandle=fgot[0]["ReceiptHandle"])

sqs.delete_queue(QueueUrl=fifo)
sqs.delete_queue(QueueUrl=url)
try:
    sqs.get_queue_url(QueueName="evidence")
    raise SystemExit("GetQueueUrl of a deleted queue succeeded")
except sqs.exceptions.QueueDoesNotExist:
    pass
