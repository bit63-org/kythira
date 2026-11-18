#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Load for the SQS migration-path container scenario
(.kiro/specs/sqs-compatible-queues/ task 11, Requirement 12.3).

  sqs_path_load.py wait URL...
      Wait until every URL answers ListQueues (90 s at most).
  sqs_path_load.py run
      Until SIGTERM: a standard producer and consumer, and a FIFO producer
      and consumer over two message groups, against the endpoints in
      $SQS_ENDPOINTS (comma separated), moving to the next endpoint
      whenever one fails. A message held at the start keeps its receipt
      handle until the end. On SIGTERM the producers stop, the consumers
      drain both queues, and one JSON line reports the outcome; the exit
      code is 0 only when:

        - every acknowledged send was received;
        - each FIFO group's messages arrived in the order they were sent
          (a message seen again is a redelivery after a failed delete,
          which at-least-once delivery allows);
        - the held message's receipt handle, issued before every step of
          the path, still deletes it.

Endpoints that are stopped, or not started yet, fail fast (their names do
not resolve), so one list can name every node the path ever serves from.
"""

import json
import os
import signal
import sys
import threading
import time

import boto3
from botocore.config import Config

REGION = "us-east-1"
GROUPS = ("g0", "g1")


def client(url: str):
    return boto3.client(
        "sqs",
        endpoint_url=url,
        region_name=REGION,
        config=Config(
            connect_timeout=2,
            read_timeout=30,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )


class Endpoints:
    """The endpoints, tried in turn: a call that fails moves on."""

    def __init__(self, urls):
        self._clients = [client(u) for u in urls]
        self._urls = urls
        self._next = 0
        self._lock = threading.Lock()
        self.failures = 0

    def call(self, op: str, deadline: float = 600.0, **kwargs):
        end = time.monotonic() + deadline
        while True:
            with self._lock:
                i = self._next
            try:
                return getattr(self._clients[i], op)(**kwargs)
            except Exception as e:  # noqa: BLE001 - any failure moves on
                with self._lock:
                    self.failures += 1
                    if self._next == i:
                        self._next = (i + 1) % len(self._clients)
                if time.monotonic() > end:
                    raise RuntimeError(f"{op} failed everywhere for {deadline}s: {e}") from e
                time.sleep(0.2)


def wait(urls) -> int:
    end = time.monotonic() + 90
    for url in urls:
        c = client(url)
        while True:
            try:
                c.list_queues()
                break
            except Exception as e:  # noqa: BLE001
                if time.monotonic() > end:
                    print(f"{url}: {e}", file=sys.stderr)
                    return 1
                time.sleep(0.5)
    return 0


def run() -> int:
    urls = [u for u in os.environ["SQS_ENDPOINTS"].split(",") if u]
    ep = Endpoints(urls)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())

    std = ep.call("create_queue", QueueName="path-std")["QueueUrl"]
    fifo = ep.call("create_queue", QueueName="path-fifo.fifo",
                   Attributes={"FifoQueue": "true"})["QueueUrl"]
    held_q = ep.call("create_queue", QueueName="path-held")["QueueUrl"]
    ep.call("send_message", QueueUrl=held_q, MessageBody="held")
    held = None
    while held is None:
        got = ep.call("receive_message", QueueUrl=held_q, VisibilityTimeout=3600,
                      WaitTimeSeconds=2).get("Messages", [])
        held = got[0]["ReceiptHandle"] if got else None
    print("ready", flush=True)

    acked_std, acked_fifo = set(), {g: [] for g in GROUPS}
    got_std = set()
    got_fifo = {g: [] for g in GROUPS}
    lock = threading.Lock()
    producers_done = threading.Event()

    def produce_std():
        i = 0
        while not stopping.is_set():
            body = f"s-{i}"
            ep.call("send_message", QueueUrl=std, MessageBody=body)
            with lock:
                acked_std.add(body)
            i += 1
            time.sleep(0.02)

    def produce_fifo():
        i = 0
        while not stopping.is_set():
            g = GROUPS[i % len(GROUPS)]
            body = f"{g}-{i // len(GROUPS)}"
            # A retry after a send that failed in transit carries the same
            # deduplication id, so it cannot enqueue the message twice.
            ep.call("send_message", QueueUrl=fifo, MessageBody=body, MessageGroupId=g,
                    MessageDeduplicationId=body)
            with lock:
                acked_fifo[g].append(body)
            i += 1
            time.sleep(0.02)

    def consume(url, record):
        empty = 0
        while True:
            if producers_done.is_set() and empty >= 5:
                return
            msgs = ep.call("receive_message", QueueUrl=url, MaxNumberOfMessages=10,
                           WaitTimeSeconds=1, VisibilityTimeout=10).get("Messages", [])
            empty = 0 if msgs else empty + 1
            for m in msgs:
                with lock:
                    record(m)
                try:
                    ep.call("delete_message", deadline=5, QueueUrl=url,
                            ReceiptHandle=m["ReceiptHandle"])
                except RuntimeError:
                    pass  # it comes back after its visibility timeout

    def record_fifo(m):
        got_fifo[m["Body"].split("-")[0]].append(m["Body"])

    producers = [threading.Thread(target=produce_std), threading.Thread(target=produce_fifo)]
    consumers = [
        threading.Thread(target=consume, args=(std, lambda m: got_std.add(m["Body"]))),
        threading.Thread(target=consume, args=(fifo, record_fifo)),
    ]
    for t in producers + consumers:
        t.start()
    stopping.wait()
    for t in producers:
        t.join()
    producers_done.set()
    for t in consumers:
        t.join()

    problems = []
    missing = sorted(acked_std - got_std)
    if missing:
        problems.append(f"{len(missing)} standard messages lost, first {missing[:5]}")
    for g in GROUPS:
        seen, order_ok = [], True
        for body in got_fifo[g]:
            if body in seen:
                continue
            seen.append(body)
        if seen != acked_fifo[g][:len(seen)]:
            order_ok = False
            problems.append(f"group {g} out of order: {seen[:10]}...")
        if order_ok and len(seen) < len(acked_fifo[g]):
            problems.append(f"group {g}: {len(acked_fifo[g]) - len(seen)} messages lost")
    try:
        ep.call("delete_message", deadline=30, QueueUrl=held_q, ReceiptHandle=held)
        attrs = ep.call("get_queue_attributes", QueueUrl=held_q, AttributeNames=[
            "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
        if attrs["ApproximateNumberOfMessages"] != "0" or \
                attrs["ApproximateNumberOfMessagesNotVisible"] != "0":
            problems.append(f"the held message is still there: {attrs}")
    except RuntimeError as e:
        problems.append(f"the held receipt handle no longer deletes: {e}")

    print(json.dumps({
        "sent_standard": len(acked_std),
        "sent_fifo": sum(len(v) for v in acked_fifo.values()),
        "received_standard": len(got_std),
        "received_fifo": sum(len(v) for v in got_fifo.values()),
        "endpoint_failures": ep.failures,
        "problems": problems,
    }), flush=True)
    return 1 if problems else 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "wait":
        return wait(sys.argv[2:])
    if len(sys.argv) == 2 and sys.argv[1] == "run":
        return run()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
