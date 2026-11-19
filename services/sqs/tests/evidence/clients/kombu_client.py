#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""The evidence scenario through Kombu's SQS transport (what Celery uses).

Kombu sends with boto3 and receives through its own asynchronous HTTP
client on pycurl (requests still serialised and signed by botocore). Kombu
puts a random delivery tag into every message body; it is replaced with a
counter here so that a rerun records the same body. Usage:
kombu_client.py ENDPOINT
"""

import itertools
import os
import sys
import urllib.parse

from kombu import Connection, Exchange, Queue
from kombu.transport.virtual import base

_tags = itertools.count(1)
base.Channel._next_delivery_tag = lambda self: f"delivery-tag-{next(_tags)}"

endpoint = urllib.parse.urlsplit(sys.argv[1])
port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
# Against real SQS (run_suite.sh's SQS_SUITE_REAL) no key in the URL, so
# boto3 takes the caller's own credentials.
creds = "" if os.environ.get("SQS_SUITE_REAL") == "1" else \
    f"AKIDEXAMPLE:{urllib.parse.quote('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', safe='')}"
url = f"sqs://{creds}@{endpoint.hostname}:{port}"
options = {"region": "us-east-1", "is_secure": endpoint.scheme == "https", "wait_time_seconds": 1,
           "polling_interval": 0.1, "queue_name_prefix": "evidence-"}
exchange = Exchange("evidence", type="direct")
queue = Queue("celery", exchange, routing_key="celery")
received = []
with Connection(url, transport_options=options) as conn:
    producer = conn.Producer(serializer="json")
    producer.publish({"task": "add", "args": [2, 3]}, exchange=exchange, routing_key="celery",
                     declare=[queue], headers={"origin": "evidence"})

    def on_message(body, message):
        received.append(body)
        message.ack()

    with conn.Consumer(queue, callbacks=[on_message], accept=["json"]):
        while not received:
            conn.drain_events(timeout=10)
    assert received == [{"task": "add", "args": [2, 3]}], received
    queue(conn.default_channel).delete()
