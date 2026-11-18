#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Send and receive throughput and latency of one queue
(.kiro/specs/sqs-compatible-queues/ Requirement 13.5, the measurement row).

Two phases against ENDPOINT (several, comma-separated, spread the threads
over the nodes of a cluster), on one fresh queue:

  send     PRODUCERS threads call SendMessage (one message each, BODY bytes)
           for SECONDS; reports messages a second and per-call latency.
  receive  the queue the send phase filled is drained by CONSUMERS threads,
           each looping ReceiveMessage (10 at most, 1 s wait) then
           DeleteMessageBatch; reports messages a second and the latency
           of the receive calls that returned messages (the empty polls
           that end the phase wait out their second).

With --fifo the queue is FIFO with content-based deduplication off and a
unique deduplication id per message, the producers spread over
4 x PRODUCERS message groups, and --high-throughput makes it a
high-throughput FIFO queue.

Credentials come from the usual AWS environment; the region defaults to
us-east-1. Prints one
JSON object, and with --markdown a table row for doc/measurements.md.
"""

import argparse
import json
import os
import statistics
import threading
import time
import uuid

import boto3
from botocore.config import Config


def client(endpoint):
    return boto3.client(
        "sqs", endpoint_url=endpoint,
        region_name=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1",
        config=Config(retries={"max_attempts": 10, "mode": "standard"},
                      max_pool_connections=64))


def pct(values, p):
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p / 100))] * 1000.0


def make_queue(sqs, args, phase):
    name = f"load-{phase}-{uuid.uuid4().hex[:8]}"
    attrs = {}
    if args.fifo:
        name += ".fifo"
        attrs = {"FifoQueue": "true", "ContentBasedDeduplication": "false"}
        if args.high_throughput:
            attrs.update(DeduplicationScope="messageGroup",
                         FifoThroughputLimit="perMessageGroupId")
    return sqs.create_queue(QueueName=name, Attributes=attrs)["QueueUrl"]


def send_phase(args, url):
    body = "x" * args.body
    stop = time.monotonic() + args.seconds
    lat, lock = [], threading.Lock()

    def producer(n):
        sqs = client(args.endpoints[n % len(args.endpoints)])
        mine, i = [], 0
        while time.monotonic() < stop:
            kw = {"QueueUrl": url, "MessageBody": body}
            if args.fifo:
                kw["MessageGroupId"] = f"g{n * 4 + i % 4}"
                kw["MessageDeduplicationId"] = f"{n}-{i}"
            t = time.monotonic()
            sqs.send_message(**kw)
            mine.append(time.monotonic() - t)
            i += 1
        with lock:
            lat.extend(mine)

    start = time.monotonic()
    threads = [threading.Thread(target=producer, args=(n,)) for n in range(args.producers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    took = time.monotonic() - start
    return {"messages": len(lat), "per_second": len(lat) / took,
            "p50_ms": pct(lat, 50), "p99_ms": pct(lat, 99),
            "mean_ms": statistics.fmean(lat) * 1000.0 if lat else 0.0}


def receive_phase(args, url, expected):
    lat, got, lock = [], [0], threading.Lock()
    done = threading.Event()

    def consumer(n):
        sqs = client(args.endpoints[n % len(args.endpoints)])
        mine, empty = [], 0
        while not done.is_set() and empty < 3:
            t = time.monotonic()
            msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=1).get("Messages", [])
            if not msgs:
                empty += 1
                continue
            mine.append(time.monotonic() - t)
            empty = 0
            sqs.delete_message_batch(QueueUrl=url, Entries=[
                {"Id": str(k), "ReceiptHandle": m["ReceiptHandle"]} for k, m in enumerate(msgs)])
            with lock:
                got[0] += len(msgs)
                if got[0] >= expected:
                    done.set()
        with lock:
            lat.extend(mine)

    start = time.monotonic()
    threads = [threading.Thread(target=consumer, args=(n,)) for n in range(args.consumers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    took = time.monotonic() - start
    return {"messages": got[0], "per_second": got[0] / took,
            "p50_ms": pct(lat, 50), "p99_ms": pct(lat, 99)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("endpoint")
    ap.add_argument("--fifo", action="store_true")
    ap.add_argument("--high-throughput", action="store_true")
    ap.add_argument("--producers", type=int, default=16)
    ap.add_argument("--consumers", type=int, default=16)
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--body", type=int, default=256)
    ap.add_argument("--label", default="")
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()
    args.endpoints = args.endpoint.split(",")

    sqs = client(args.endpoints[0])
    url = make_queue(sqs, args, "q")
    sent = send_phase(args, url)
    received = receive_phase(args, url, sent["messages"])
    sqs.delete_queue(QueueUrl=url)
    kind = ("FIFO (high throughput)" if args.high_throughput else "FIFO") if args.fifo else "standard"
    out = {"label": args.label, "queue": kind, "producers": args.producers,
           "consumers": args.consumers, "body_bytes": args.body,
           "send": sent, "receive": received}
    print(json.dumps(out, indent=2))
    if args.markdown:
        print(f"| {args.label} | {kind} | {args.producers}/{args.consumers} | "
              f"{sent['per_second']:.0f} | {sent['p50_ms']:.1f} / {sent['p99_ms']:.1f} | "
              f"{received['per_second']:.0f} | {received['p50_ms']:.1f} / {received['p99_ms']:.1f} |")
    if received["messages"] < sent["messages"]:
        raise SystemExit(f"lost messages: sent {sent['messages']}, received {received['messages']}")


if __name__ == "__main__":
    main()
