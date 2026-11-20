#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""A steady AWS SDK workload against a cluster.py cluster, sampling node RSS.

usage: workload.py dynamodb|kms OUTDIR SECONDS [--threads N] [--keys K]
                   [--payload BYTES]

dynamodb: one table; 40% PutItem, 30% GetItem, 10% Query, 15% UpdateItem,
          5% DeleteItem over K keys (5000) with PAYLOAD-byte items (512).
kms:      K keys (20); 30% GenerateDataKey, 30% Encrypt, 30% Decrypt,
          5% DescribeKey, 5% CreateKey.

Threads spread over every node. Writes OUTDIR/rss.csv (VmRSS in KiB of
each kythira_node every 5 s, never the heaptrack interpreter) and
OUTDIR/workload.json (operation counts). Needs boto3.
"""
import json
import os
import random
import sys
import threading
import time

import boto3
from botocore.config import Config

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cluster import ACCESS_KEY, SECRET_KEY, node_pid  # noqa: E402


def opt(name, default):
    return type(default)(sys.argv[sys.argv.index(name) + 1]) if name in sys.argv else default


def rss_kib(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def client(service, port, threads):
    return boto3.client(service, endpoint_url=f"http://127.0.0.1:{port}", region_name="us-east-1",
                        aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                        config=Config(retries={"max_attempts": 10, "mode": "standard"},
                                      max_pool_connections=threads + 2))


def retry_until(deadline, fn):
    while True:
        try:
            return fn()
        except Exception:  # the cluster is still electing
            if time.time() > deadline:
                raise
            time.sleep(1)


class dynamodb_mix:
    def __init__(self, ports, threads):
        self.keys, self.payload = opt("--keys", 5000), "x" * opt("--payload", 512)
        self.ports, self.threads = ports["dynamodb"], threads
        c = client("dynamodb", self.ports[0], threads)

        def create():
            try:
                c.create_table(
                    TableName="prof", BillingMode="PAY_PER_REQUEST",
                    AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                          {"AttributeName": "sk", "AttributeType": "N"}],
                    KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                               {"AttributeName": "sk", "KeyType": "RANGE"}])
            except c.exceptions.ResourceInUseException:
                pass
        retry_until(time.time() + 120, create)
        while c.describe_table(TableName="prof")["Table"]["TableStatus"] != "ACTIVE":
            time.sleep(0.5)

    def client(self, i):
        return client("dynamodb", self.ports[i % len(self.ports)], self.threads)

    def step(self, c, rnd, _state):
        k = rnd.randrange(self.keys)
        key = {"pk": {"S": f"user{k % 200}"}, "sk": {"N": str(k)}}
        op = rnd.random()
        if op < 0.4:
            c.put_item(TableName="prof", Item={**key, "v": {"S": self.payload},
                                               "n": {"N": str(rnd.randrange(10**6))}})
            return "put"
        if op < 0.7:
            c.get_item(TableName="prof", Key=key)
            return "get"
        if op < 0.8:
            c.query(TableName="prof", KeyConditionExpression="pk = :p",
                    ExpressionAttributeValues={":p": key["pk"]}, Limit=25)
            return "query"
        if op < 0.95:
            c.update_item(TableName="prof", Key=key, UpdateExpression="ADD c :one",
                          ExpressionAttributeValues={":one": {"N": "1"}})
            return "update"
        c.delete_item(TableName="prof", Key=key)
        return "delete"


class kms_mix:
    def __init__(self, ports, threads):
        self.ports, self.threads = ports["kms"], threads
        c = client("kms", self.ports[0], threads)
        deadline = time.time() + 120
        self.key_ids = [retry_until(deadline, lambda: c.create_key()["KeyMetadata"]["KeyId"])
                        for _ in range(opt("--keys", 20))]

    def client(self, i):
        return client("kms", self.ports[i % len(self.ports)], self.threads)

    def step(self, c, rnd, state):
        k = rnd.choice(self.key_ids)
        op = rnd.random()
        if op < 0.3:
            c.generate_data_key(KeyId=k, KeySpec="AES_256")
            return "generate_data_key"
        if op < 0.6 or "blob" not in state:
            state["blob"] = c.encrypt(KeyId=k, Plaintext=os.urandom(256))["CiphertextBlob"]
            return "encrypt"
        if op < 0.9:
            c.decrypt(CiphertextBlob=state["blob"])
            return "decrypt"
        if op < 0.95:
            c.describe_key(KeyId=k)
            return "describe_key"
        c.create_key()
        return "create_key"


def main():
    if len(sys.argv) < 4 or sys.argv[1] not in ("dynamodb", "kms"):
        sys.exit(__doc__)
    out, seconds, threads = sys.argv[2], float(sys.argv[3]), opt("--threads", 8)
    with open(os.path.join(out, "ports.json")) as f:
        ports = json.load(f)
    mix = (dynamodb_mix if sys.argv[1] == "dynamodb" else kms_mix)(ports, threads)
    counts, lock = {"error": 0}, threading.Lock()
    stop_at = time.time() + seconds

    def worker(i):
        c, rnd, state = mix.client(i), random.Random(i), {}
        while time.time() < stop_at:
            try:
                name = mix.step(c, rnd, state)
            except Exception:
                name = "error"
            with lock:
                counts[name] = counts.get(name, 0) + 1

    workers = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    t0 = time.time()
    for w in workers:
        w.start()
    pids = [node_pid(p) for p in ports["pids"]]
    with open(os.path.join(out, "rss.csv"), "w") as f:
        f.write("seconds," + ",".join(f"node{i + 1}_kib" for i in range(len(pids))) + "\n")
        while True:
            f.write(f"{time.time() - t0:.0f}," + ",".join(str(rss_kib(p)) for p in pids) + "\n")
            f.flush()
            if time.time() >= stop_at:
                break
            time.sleep(5)
    for w in workers:
        w.join()
    counts["seconds"] = round(time.time() - t0, 1)
    ok = sum(v for k, v in counts.items() if k not in ("error", "seconds"))
    counts["ops_per_second"] = round(ok / counts["seconds"], 1)
    with open(os.path.join(out, "workload.json"), "w") as f:
        json.dump(counts, f, indent=1)
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
