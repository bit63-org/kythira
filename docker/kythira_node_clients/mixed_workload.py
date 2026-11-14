#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Mixed DynamoDB, Kinesis and IAM workload for the composite-node scenario.

.kiro/specs/service-colocation/ task 10 (Requirement 10.3). Run inside the
scenario's `workload` service (docker/kythira_node_clients/Dockerfile) by
kythira_node_scenario_test, against every node of the three-node
kythira_node cluster by compose service name (docker/kythira-node-compose.yml):

    mixed_workload.py setup  --nodes kn-1,kn-2,kn-3
    mixed_workload.py run    --nodes kn-1,kn-2,kn-3 --seconds S --tag T
    mixed_workload.py verify --nodes kn-1,kn-2,kn-3 --tag T

All three APIs are HTTPS with the node certificates, which the scenario's
test CA (/pki/ca.pem) signs; IAM listens on :8443, Kinesis on :4567 and
DynamoDB on :8000 on every node.

`setup` signs as the account root (ROOT_KEY_ID / ROOT_SECRET): it creates
the user `mixed-app`, gives it an inline policy for DynamoDB, Kinesis and
IAM user writes, and a key; then, as that user, the table `mixed` and the
two-shard stream `mixed`. It prints the user's key as its last line, a JSON
object with key_id and secret. A second run reuses what exists, except the
key, which is made anew.

`run` signs as the user (APP_KEY_ID / APP_SECRET) and, for S seconds,
repeats: PutItem `T-i` into the table, PutRecord `T-i` into the stream, and
every tenth round CreateUser `T-u<i>`. Each call goes to the node that last
answered and moves to the next one when a node fails or refuses; a call is
retried until it is acknowledged or 30 s pass. Each acknowledged write is
appended to /work/acks-T.txt as `ddb|kin|iam <id>`, so the list survives
the container. Retrying a write whose answer was lost may apply it twice,
which every check below allows: items and users are keyed by name, and
records are counted as a set. It prints one JSON line with the counts and
fails if no write of some kind was acknowledged at all.

`verify` reads /work/acks-T.txt and checks, through any node that answers,
that every acknowledged item is in the table (a strongly consistent
GetItem), every acknowledged record is in the stream (every shard read from
TRIM_HORIZON) and every acknowledged user exists (GetUser). It prints one
JSON line with the counts; anything missing exits non-zero, naming it.
"""

import argparse
import json
import os
import sys
import time

import boto3
from botocore.config import Config

CA = "/pki/ca.pem"
REGION = "us-east-1"
TABLE = "mixed"
STREAM = "mixed"
USER = "mixed-app"
PORTS = {"iam": 8443, "kinesis": 4567, "dynamodb": 8000}

# Retries are this script's, across nodes: the SDK's own would spend the
# call's whole budget on a node that is down.
CONFIG = Config(retries={"max_attempts": 1}, connect_timeout=3, read_timeout=10)

POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:*", "kinesis:*", "iam:CreateUser", "iam:GetUser"],
                "Resource": "*",
            }
        ],
    }
)


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


class nodes:
    """One client per node and service, and the node that last answered."""

    def __init__(self, names, key_id, secret):
        self.names = names
        self.current = 0
        self.clients = {
            svc: [
                boto3.client(
                    svc,
                    endpoint_url=f"https://{n}:{port}",
                    region_name=REGION,
                    aws_access_key_id=key_id,
                    aws_secret_access_key=secret,
                    verify=CA,
                    config=CONFIG,
                )
                for n in names
            ]
            for svc, port in PORTS.items()
        }

    def call(self, svc, fn, budget=30.0, ok_errors=()):
        """fn(client) on the current node, moving on until one answers.

        An error code in ok_errors is an answer (the caller handles it);
        any other failure, including a follower's redirect, tries the next
        node after a short pause once every node has been tried.
        """
        deadline = time.time() + budget
        last = None
        tried = 0
        while time.time() < deadline:
            c = self.clients[svc][self.current]
            try:
                return fn(c)
            except Exception as e:  # noqa: BLE001 - every failure moves on
                if code_of(e) in ok_errors:
                    raise
                last = e
                self.current = (self.current + 1) % len(self.names)
                tried += 1
                if tried % len(self.names) == 0:
                    time.sleep(0.5)
        raise TimeoutError(f"{svc}: no node answered in {budget:.0f} s: {last}")


def code_of(e):
    """The AWS error code of `e`, or None.

    A ClientError carries the parsed response; a timeout or a dropped
    connection has none, or a `response` of None, and has no code.
    """
    response = getattr(e, "response", None) or {}
    return response.get("Error", {}).get("Code")


def setup(args):
    root = nodes(args.nodes.split(","), os.environ["ROOT_KEY_ID"], os.environ["ROOT_SECRET"])
    try:
        root.call("iam", lambda c: c.create_user(UserName=USER), ok_errors=("EntityAlreadyExists",))
    except Exception as e:  # noqa: BLE001
        if code_of(e) != "EntityAlreadyExists":
            raise
    root.call(
        "iam",
        lambda c: c.put_user_policy(UserName=USER, PolicyName="mixed", PolicyDocument=POLICY),
    )
    key = root.call("iam", lambda c: c.create_access_key(UserName=USER))["AccessKey"]

    # A new key and policy reach every node's evaluator through the IAM
    # group's log; retry until this one is accepted.
    app = nodes(args.nodes.split(","), key["AccessKeyId"], key["SecretAccessKey"])
    try:
        app.call(
            "dynamodb",
            lambda c: c.create_table(
                TableName=TABLE,
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST",
            ),
            budget=60,
            ok_errors=("ResourceInUseException",),
        )
    except Exception as e:  # noqa: BLE001
        if code_of(e) != "ResourceInUseException":
            raise
    try:
        app.call(
            "kinesis",
            lambda c: c.create_stream(StreamName=STREAM, ShardCount=2),
            budget=60,
            ok_errors=("ResourceInUseException",),
        )
    except Exception as e:  # noqa: BLE001
        if code_of(e) != "ResourceInUseException":
            raise
    deadline = time.time() + 60
    while True:
        t = app.call("dynamodb", lambda c: c.describe_table(TableName=TABLE))["Table"]
        s = app.call("kinesis", lambda c: c.describe_stream_summary(StreamName=STREAM))
        if (
            t["TableStatus"] == "ACTIVE"
            and s["StreamDescriptionSummary"]["StreamStatus"] == "ACTIVE"
        ):
            break
        if time.time() > deadline:
            fail("the table or the stream never became ACTIVE")
        time.sleep(1)
    print(json.dumps({"key_id": key["AccessKeyId"], "secret": key["SecretAccessKey"]}))


def run(args):
    app = nodes(args.nodes.split(","), os.environ["APP_KEY_ID"], os.environ["APP_SECRET"])
    counts = {"ddb": 0, "kin": 0, "iam": 0}
    failures = []
    end = time.time() + args.seconds
    path = f"/work/acks-{args.tag}.txt"
    with open(path, "a", encoding="utf-8") as acks:

        def ack(kind, ident):
            acks.write(f"{kind} {ident}\n")
            acks.flush()
            counts[kind] += 1

        i = 0
        while time.time() < end:
            ident = f"{args.tag}-{i}"
            try:
                app.call(
                    "dynamodb",
                    lambda c: c.put_item(
                        TableName=TABLE, Item={"pk": {"S": ident}, "n": {"N": str(i)}}
                    ),
                )
                ack("ddb", ident)
            except Exception as e:  # noqa: BLE001
                failures.append(f"ddb {ident}: {e}")
            try:
                app.call(
                    "kinesis",
                    lambda c: c.put_record(
                        StreamName=STREAM, Data=ident.encode(), PartitionKey=ident
                    ),
                )
                ack("kin", ident)
            except Exception as e:  # noqa: BLE001
                failures.append(f"kin {ident}: {e}")
            if i % 10 == 0:
                user = f"{args.tag}-u{i}"
                try:
                    app.call(
                        "iam",
                        lambda c: c.create_user(UserName=user),
                        ok_errors=("EntityAlreadyExists",),
                    )
                    ack("iam", user)
                except Exception as e:  # noqa: BLE001
                    if code_of(e) == "EntityAlreadyExists":
                        ack("iam", user)  # an earlier attempt landed
                    else:
                        failures.append(f"iam {user}: {e}")
            i += 1
    print(json.dumps({"rounds": i, "acknowledged": counts, "unacknowledged": len(failures)}))
    for f in failures[:20]:
        print(f"unacknowledged: {f}", file=sys.stderr)
    if min(counts.values()) == 0:
        fail(f"some service acknowledged no write: {counts}")


def read_stream(app):
    seen = set()
    shards = app.call("kinesis", lambda c: c.list_shards(StreamName=STREAM))["Shards"]
    for shard in shards:
        sid = shard["ShardId"]
        it = app.call(
            "kinesis",
            lambda c: c.get_shard_iterator(
                StreamName=STREAM, ShardId=sid, ShardIteratorType="TRIM_HORIZON"
            ),
        )["ShardIterator"]
        while it:
            out = app.call("kinesis", lambda c: c.get_records(ShardIterator=it, Limit=10000))
            for r in out["Records"]:
                seen.add(r["Data"].decode())
            it = out.get("NextShardIterator")
            if not out["Records"] and out.get("MillisBehindLatest", 0) == 0:
                break
    return seen


def verify(args):
    app = nodes(args.nodes.split(","), os.environ["APP_KEY_ID"], os.environ["APP_SECRET"])
    acked = {"ddb": set(), "kin": set(), "iam": set()}
    with open(f"/work/acks-{args.tag}.txt", encoding="utf-8") as f:
        for line in f:
            kind, _, ident = line.strip().partition(" ")
            if kind in acked:
                acked[kind].add(ident)
    missing = []
    for ident in sorted(acked["ddb"]):
        item = app.call(
            "dynamodb",
            lambda c: c.get_item(TableName=TABLE, Key={"pk": {"S": ident}}, ConsistentRead=True),
        )
        if "Item" not in item:
            missing.append(f"item {ident}")
    records = read_stream(app)
    missing += [f"record {r}" for r in sorted(acked["kin"] - records)]
    for user in sorted(acked["iam"]):
        try:
            app.call("iam", lambda c: c.get_user(UserName=user), ok_errors=("NoSuchEntity",))
        except Exception as e:  # noqa: BLE001
            if code_of(e) == "NoSuchEntity":
                missing.append(f"user {user}")
            else:
                raise
    print(
        json.dumps(
            {
                "items": len(acked["ddb"]),
                "records": len(acked["kin"]),
                "users": len(acked["iam"]),
                "missing": len(missing),
            }
        )
    )
    if missing:
        fail("acknowledged but missing: " + ", ".join(missing[:50]))


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--nodes", required=True)
    r = sub.add_parser("run")
    r.add_argument("--nodes", required=True)
    r.add_argument("--seconds", type=float, required=True)
    r.add_argument("--tag", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--nodes", required=True)
    v.add_argument("--tag", required=True)
    args = p.parse_args()
    {"setup": setup, "run": run, "verify": verify}[args.cmd](args)


if __name__ == "__main__":
    main()
