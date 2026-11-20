#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""The Kythira side of run_real_cloud.sh's SNS part: talks to the local
sqs_node with Kythira's key (from the environment), never to AWS.

  sns_bridge_check.py setup   ENDPOINT QUEUE TOPIC_ARN
      Create QUEUE and let it take TOPIC_ARN's deliveries (its tag).
  sns_bridge_check.py wrapped ENDPOINT QUEUE TOPIC_ARN
      Receive wrapped-1..3 as SNS notification envelopes from TOPIC_ARN,
      with the color attribute.
  sns_bridge_check.py raw-on  ENDPOINT QUEUE TOPIC_ARN
      Switch the queue to raw delivery.
  sns_bridge_check.py raw     ENDPOINT QUEUE TOPIC_ARN
      Receive raw-1 as the bare message, color as a message attribute.
"""

import json
import sys
import time

import boto3


def receive(sqs, url, want: int, timeout: float = 120.0):
    got, end = [], time.monotonic() + timeout
    while len(got) < want and time.monotonic() < end:
        r = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                MessageAttributeNames=["All"])
        for m in r.get("Messages", []):
            got.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


def main() -> int:
    cmd, endpoint, queue, topic = sys.argv[1:5]
    sqs = boto3.client("sqs", endpoint_url=endpoint, region_name="us-east-1")
    if cmd == "setup":
        url = sqs.create_queue(QueueName=queue)["QueueUrl"]
        sqs.tag_queue(QueueUrl=url, Tags={"kythira:sns-bridge-topics": topic})
        print(f"created {url}, taking {topic}")
        return 0
    url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]
    if cmd == "raw-on":
        sqs.tag_queue(QueueUrl=url, Tags={"kythira:sns-bridge-raw": "true"})
        return 0
    if cmd == "wrapped":
        got = receive(sqs, url, 3)
        bodies = sorted(json.loads(m["Body"])["Message"] for m in got)
        envs = [json.loads(m["Body"]) for m in got]
        ok = (bodies == ["wrapped-1", "wrapped-2", "wrapped-3"]
              and all(e["Type"] == "Notification" and e["TopicArn"] == topic
                      and e["MessageAttributes"]["color"]["Value"] == "blue" for e in envs))
        print(json.dumps({"wrapped": bodies, "ok": ok}))
        return 0 if ok else 1
    if cmd == "raw":
        got = receive(sqs, url, 1)
        ok = (len(got) == 1 and got[0]["Body"] == "raw-1"
              and got[0].get("MessageAttributes", {}).get("color", {}).get("StringValue") == "blue")
        print(json.dumps({"raw": [m["Body"] for m in got], "ok": ok}))
        return 0 if ok else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
