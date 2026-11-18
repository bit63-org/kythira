#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""The evidence scenario through boto3 (README.md lists its steps).

Usage: boto3_client.py ENDPOINT
"""

import json
import sys

import boto3

TOKEN = "deadbeefdeadbeefdeadbeefdeadbeef" + "0" * 32
QUEUE = "arn:aws:sqs:us-east-1:123456789012:evidence-queue"
COMPACT = (",", ":")
FILTER = json.dumps({"color": ["red", {"prefix": "bl"}], "size": [{"numeric": [">", 3]}]},
                    separators=COMPACT)

sns = boto3.client("sns", endpoint_url=sys.argv[1], region_name="us-east-1")
topic = sns.create_topic(Name="evidence", Attributes={"DisplayName": "Evidence"},
                         Tags=[{"Key": "team", "Value": "kythira"}])["TopicArn"]
fifo = sns.create_topic(Name="evidence.fifo", Attributes={
    "FifoTopic": "true", "ContentBasedDeduplication": "true"})["TopicArn"]
assert any(t["TopicArn"] == topic for t in sns.list_topics()["Topics"])
sns.get_topic_attributes(TopicArn=topic)
sns.set_topic_attributes(TopicArn=topic, AttributeName="DisplayName",
                         AttributeValue="Evidence 2")
queue_sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=QUEUE,
                          Attributes={"RawMessageDelivery": "true", "FilterPolicy": FILTER},
                          ReturnSubscriptionArn=True)["SubscriptionArn"]
assert sns.subscribe(TopicArn=topic, Protocol="http",
                     Endpoint="http://127.0.0.1:9/hook")["SubscriptionArn"] == \
    "pending confirmation"
sns.confirm_subscription(TopicArn=topic, Token=TOKEN, AuthenticateOnUnsubscribe="true")
sns.list_subscriptions_by_topic(TopicArn=topic)
sns.set_subscription_attributes(SubscriptionArn=queue_sub, AttributeName="FilterPolicyScope",
                                AttributeValue="MessageBody")
sns.get_subscription_attributes(SubscriptionArn=queue_sub)
sns.publish(TopicArn=topic, Subject="hello", Message="hello, world", MessageAttributes={
    "color": {"DataType": "String", "StringValue": "red"},
    "size": {"DataType": "Number", "StringValue": "4"},
    "blob": {"DataType": "Binary", "BinaryValue": b"\x00\x01\xfe\xff"},
    "tags": {"DataType": "String.Array", "StringValue": '["a","b"]'},
})
sns.publish(TopicArn=topic, MessageStructure="json", Message=json.dumps(
    {"default": "fallback", "sqs": "to queues", "http": "to endpoints"}, separators=COMPACT))
assert sns.publish(TopicArn=fifo, Message="first", MessageGroupId="g1")["SequenceNumber"]
sns.publish_batch(TopicArn=fifo, PublishBatchRequestEntries=[
    {"Id": "one", "Message": "second", "MessageGroupId": "g1"},
    {"Id": "two", "Message": "third", "MessageGroupId": "g2",
     "MessageDeduplicationId": "dedup-3",
     "MessageAttributes": {"color": {"DataType": "String", "StringValue": "blue"}}},
])
sns.tag_resource(ResourceArn=topic, Tags=[{"Key": "env", "Value": "test"}])
tags = sns.list_tags_for_resource(ResourceArn=topic)["Tags"]
assert {t["Key"] for t in tags} == {"team", "env"}, tags
sns.untag_resource(ResourceArn=topic, TagKeys=["env"])
sns.unsubscribe(SubscriptionArn=queue_sub)
sns.delete_topic(TopicArn=fifo)
sns.delete_topic(TopicArn=topic)
