#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""boto3 producer and polling consumer for the Kinesis container scenario.

.kiro/specs/kinesis-compatible-streams/ task 7. Run inside the scenario's
`boto3` service (services/kinesis/docker/kinesis_clients/Dockerfile) by
kinesis_node_scenario_test, against the gateways by compose service name:

    kinesis_e2e.py create  --endpoint URL --stream S (--shards N | --on-demand)
    kinesis_e2e.py produce --endpoint URL --stream S --count N --tag T
    kinesis_e2e.py consume --endpoints URL,URL --stream S --expect N
    kinesis_e2e.py ordered-produce --endpoints URL,URL --stream S --count N --keys K --tag T
    kinesis_e2e.py lineage-consume --endpoints URL,URL --stream S --count N --keys K --tag T
    kinesis_e2e.py batch-produce --endpoints URL,URL --stream S --count N --keys K --tag T
    kinesis_e2e.py fan-out-consume --endpoints URL,URL --stream S --count N --keys K --tag T
    kinesis_e2e.py s3-control --url URL [--put-delay MS] [--fail-puts N --prefix P]
    kinesis_e2e.py channel-create --endpoint URL --stream S --channel C --bucket B
    kinesis_e2e.py channel-create --endpoint URL --stream S --channel C \
        --table-bucket ARN --namespace NS --table T --bucket DLQ
    kinesis_e2e.py channel-check --s3 URL --bucket B --channel C --count N --keys K --tag T
    kinesis_e2e.py tables-create --catalog URL --s3 URL --namespace NS --table T
    kinesis_e2e.py tables-check --catalog URL --s3 URL --namespace NS --table T --count N --tag T

`produce` writes records `T-0` .. `T-<N-1>` with PutRecords in batches of
100, retrying records that fail, and prints how many went to each shard.
`consume` reads every shard from TRIM_HORIZON with GetShardIterator and
GetRecords, each page from the next endpoint in turn (so one consumer's
iterators cross every node), until it holds `--expect` records or the
deadline passes. It checks that sequence numbers rise within each shard
and that no record arrives twice or goes missing, then prints one JSON
line with the counts. Credentials come from
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY. Any failure exits non-zero with
the reason on stderr.

The last two are the resharding case (task 11). `ordered-produce` writes
`T-0` .. `T-<N-1>` one PutRecord at a time over `K` partition keys
(`T-i` under key `i mod K`), waiting for each to succeed before the next,
and moves to the next endpoint when a node does not answer, so the stream
is written straight through a node kill and a reshard. A write retried
after a lost answer may land twice. `lineage-consume` reads every shard,
open or closed, from TRIM_HORIZON to its end or the stream's present, and
starts a child only once its parents are read to their ends, as KCL does;
it reads the stream again until every record is there or the deadline
passes. It fails unless, under each partition key, records arrived in the
order they were written. A record may arrive twice (a retried write), and
the two copies are then next to each other.

The last two are the chaos case (task 17). `batch-produce` is
`ordered-produce` with PutRecords: each batch holds the next `K` records,
one per key, and its failed entries are retried, through the next endpoint
when a call fails outright, before the next batch starts, so each key's
records still go in order. `fan-out-consume` registers a consumer (or
reuses one) and subscribes to every shard with SubscribeToShard, one
thread per shard. When a subscription ends, by its lifetime, an exception
event or a lost node, it subscribes again through the next endpoint, after
its continuation sequence number. It fails unless every record arrives,
in order under each key, by the deadline.

`s3-control` drives the S3 mock's control side for the tiering case (task
17): it optionally sets the PUT delay and arms a number of failing PUTs
under a key prefix, then prints the mock's counters as one JSON line.

`channel-create` makes a GZIP S3 channel from an on-demand stream to a
bucket (task 19). `channel-check` reads that bucket through S3 (the
scenario's mock), until every record `T-0` .. `T-<N-1>` written by
`batch-produce` has been delivered or the deadline passes, and fails
unless, within each shard, a key's records were delivered in the order
they were written.

The S3 Tables case (task 19) runs `batch-produce --json`, whose records are
JSON objects `{"id": i, "key": i mod K, "tag": T, "event_time": <ms>}`.
`tables-create` makes namespace NS and table T (format version 2,
partitioned by hour(event_time) and identity(key)) in the scenario's
Iceberg REST catalog, through pyiceberg. `channel-create` with
`--table-bucket` makes a GSR_JSON channel to that table instead of an S3
bucket, with `--bucket` as its dead-letter bucket. `tables-check` reads
the table back through the catalog and the S3 mock until every record
`T-0` .. `T-<N-1>` is a row or the deadline passes, and fails unless each
snapshot the channel committed covers its own sequence range: no two
snapshots name the same batch or overlap within a shard, so a batch
retried across a node kill was committed once.
"""

import argparse
import gzip
import json
import re
import sys
import threading
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

CONFIG = Config(
    retries={"max_attempts": 10, "mode": "standard"},
    connect_timeout=5,
    read_timeout=20,
)


def client(endpoint):
    return boto3.client(
        "kinesis", endpoint_url=endpoint, region_name="us-east-1", config=CONFIG
    )


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def create(args):
    c = client(args.endpoint)
    try:
        if args.on_demand:
            c.create_stream(
                StreamName=args.stream, StreamModeDetails={"StreamMode": "ON_DEMAND"}
            )
        else:
            c.create_stream(StreamName=args.stream, ShardCount=args.shards)
    except c.exceptions.ResourceInUseException as e:
        # botocore retries CreateStream when an attempt's answer is lost (a
        # read timeout, a dropped connection), and CreateStream is not
        # idempotent: if the lost attempt committed, the retry finds the
        # stream. AWS answers the same way. Accept it, as the AWS CLI step
        # of the scenario does, but only for a stream of the asked shape.
        if "already exists" not in str(e):
            raise
    deadline = time.time() + 60
    while time.time() < deadline:
        s = c.describe_stream_summary(StreamName=args.stream)["StreamDescriptionSummary"]
        if s["StreamStatus"] == "ACTIVE":
            if not args.on_demand and s["OpenShardCount"] != args.shards:
                fail(f"{args.stream} exists with {s['OpenShardCount']} shards, not {args.shards}")
            print(json.dumps({"stream": args.stream, "shards": s["OpenShardCount"]}))
            return
        time.sleep(1)
    fail(f"{args.stream} never became ACTIVE")


def produce(args):
    c = client(args.endpoint)
    pending = [(f"{args.tag}-{i}", f"pk-{args.tag}-{i}") for i in range(args.count)]
    per_shard = {}
    deadline = time.time() + 120
    while pending:
        if time.time() > deadline:
            fail(f"{len(pending)} records still failing after 120 s")
        batch, pending = pending[:100], pending[100:]
        out = c.put_records(
            StreamName=args.stream,
            Records=[{"Data": d.encode(), "PartitionKey": pk} for d, pk in batch],
        )
        retry = []
        for (d, pk), r in zip(batch, out["Records"]):
            if "ErrorCode" in r:
                retry.append((d, pk))
            else:
                per_shard[r["ShardId"]] = per_shard.get(r["ShardId"], 0) + 1
        if retry:
            # Order matters within a partition key; these keys are unique,
            # so a retried record can go last.
            time.sleep(0.5)
            pending = retry + pending
    print(json.dumps({"produced": args.count, "per_shard": per_shard}))


def consume(args):
    clients = [client(e) for e in args.endpoints.split(",")]
    first = clients[0]
    shards = [s["ShardId"] for s in first.list_shards(StreamName=args.stream)["Shards"]]
    iterators = {
        sid: first.get_shard_iterator(
            StreamName=args.stream, ShardId=sid, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        for sid in shards
    }
    seen = set()
    last_seq = {}
    per_shard = {sid: 0 for sid in shards}
    turn = 0
    deadline = time.time() + args.timeout
    while len(seen) < args.expect and time.time() < deadline:
        progressed = False
        for sid in shards:
            c = clients[turn % len(clients)]
            turn += 1
            out = c.get_records(ShardIterator=iterators[sid], Limit=args.limit)
            for r in out["Records"]:
                seq = int(r["SequenceNumber"])
                if seq <= last_seq.get(sid, -1):
                    fail(f"{sid}: sequence {seq} after {last_seq[sid]}")
                last_seq[sid] = seq
                data = r["Data"].decode()
                if data in seen:
                    fail(f"{data} arrived twice")
                seen.add(data)
                per_shard[sid] += 1
                progressed = True
            if "NextShardIterator" not in out:
                fail(f"{sid}: no NextShardIterator on an open shard")
            iterators[sid] = out["NextShardIterator"]
        if not progressed:
            time.sleep(0.5)
    if len(seen) < args.expect:
        fail(f"read {len(seen)} of {args.expect} records before the deadline")
    if len(seen) > args.expect:
        fail(f"read {len(seen)} records, expected {args.expect}")
    print(json.dumps({"consumed": len(seen), "per_shard": per_shard}))


def ordered_produce(args):
    clients = [client(e) for e in args.endpoints.split(",")]
    turn = 0
    retries = 0
    deadline = time.time() + args.timeout
    for i in range(args.count):
        while True:
            if time.time() > deadline:
                fail(f"record {i} still failing after {args.timeout} s")
            try:
                clients[turn % len(clients)].put_record(
                    StreamName=args.stream,
                    Data=f"{args.tag}-{i}".encode(),
                    PartitionKey=f"pk-{args.tag}-{i % args.keys}",
                )
                break
            except Exception:  # noqa: BLE001 - any failure: next node, again
                retries += 1
                turn += 1
                time.sleep(0.2)
    print(json.dumps({"produced": args.count, "retries": retries}))


def lineage_pass(clients, args):
    """One read of the whole stream in lineage order: per key, the indexes
    in arrival order. A closed shard is read to its end, an open one to the
    present."""
    turn = 0
    prefix = f"{args.tag}-"
    by_key = {}
    shards = clients[0].list_shards(StreamName=args.stream)["Shards"]
    done = set()
    pending = list(shards)
    while pending:
        ready = [
            s
            for s in pending
            if all(
                s[k] in done for k in ("ParentShardId", "AdjacentParentShardId") if k in s
            )
        ]
        if not ready:
            fail("shards whose parents are not listed: " + ",".join(s["ShardId"] for s in pending))
        for s in ready:
            pending.remove(s)
            sid = s["ShardId"]
            it = clients[turn % len(clients)].get_shard_iterator(
                StreamName=args.stream, ShardId=sid, ShardIteratorType="TRIM_HORIZON"
            )["ShardIterator"]
            while it:
                c = clients[turn % len(clients)]
                turn += 1
                out = c.get_records(ShardIterator=it, Limit=args.limit)
                for r in out["Records"]:
                    data = r["Data"].decode()
                    if data.startswith(prefix):
                        i = int(data[len(prefix):])
                        by_key.setdefault(i % args.keys, []).append(i)
                it = out.get("NextShardIterator")
                if not out["Records"] and out.get("MillisBehindLatest", 0) == 0:
                    break
            done.add(sid)
    return by_key, len(shards)


def lineage_consume(args):
    clients = [client(e) for e in args.endpoints.split(",")]
    deadline = time.time() + args.timeout
    while True:
        by_key, shards = lineage_pass(clients, args)
        seen = {i for got in by_key.values() for i in got}
        missing = sorted(set(range(args.count)) - seen)
        if not missing:
            break
        if time.time() > deadline:
            fail(f"{len(missing)} of {args.count} records never read, first {missing[0]}")
        time.sleep(2)
    # A write whose answer was lost (a 5 s propose timeout while its entry
    # still commits, a dropped connection) is retried by botocore, up to
    # ten attempts, and by the producer on the next node; each attempt can
    # commit, so a record can repeat any number of times. The producer
    # sends one write at a time, so the copies sit together in its key:
    # never an older record after a newer one, which also rules out a read
    # that returns a stretch twice.
    for key, got in by_key.items():
        for a, b in zip(got, got[1:]):
            if b < a:
                fail(f"key {key}: {b} arrived after {a}")
    dups = sum(len(g) - len(set(g)) for g in by_key.values())
    print(json.dumps({"consumed": len(seen), "shards": shards, "duplicates": dups}))


def batch_produce(args):
    clients = [client(e) for e in args.endpoints.split(",")]
    turn = 0
    retries = 0
    deadline = time.time() + args.timeout
    def data(i):
        if not args.json:
            return f"{args.tag}-{i}".encode()
        row = {"id": i, "key": i % args.keys, "tag": args.tag, "event_time": int(time.time() * 1000)}
        return json.dumps(row).encode()

    for start in range(0, args.count, args.keys):
        pending = [
            {"Data": data(i), "PartitionKey": f"pk-{args.tag}-{i % args.keys}"}
            for i in range(start, min(start + args.keys, args.count))
        ]
        while pending:
            if time.time() > deadline:
                fail(f"batch at {start} still failing after {args.timeout} s")
            try:
                out = clients[turn % len(clients)].put_records(
                    StreamName=args.stream, Records=pending
                )
            except Exception:  # noqa: BLE001 - any failure: next node, again
                retries += 1
                turn += 1
                time.sleep(0.2)
                continue
            pending = [r for r, res in zip(pending, out["Records"]) if "ErrorCode" in res]
            if pending:
                retries += 1
                time.sleep(0.1)
    print(json.dumps({"produced": args.count, "retries": retries}))


def fan_out_consume(args):
    clients = [client(e) for e in args.endpoints.split(",")]
    c0 = clients[0]
    arn = c0.describe_stream_summary(StreamName=args.stream)["StreamDescriptionSummary"][
        "StreamARN"
    ]
    name = f"chaos-{args.tag}"
    try:
        consumer = c0.register_stream_consumer(StreamARN=arn, ConsumerName=name)["Consumer"]
    except c0.exceptions.ResourceInUseException:
        consumer = c0.describe_stream_consumer(StreamARN=arn, ConsumerName=name)[
            "ConsumerDescription"
        ]
    consumer_arn = consumer["ConsumerARN"]
    prefix = f"{args.tag}-"
    lock = threading.Lock()
    by_key = {}
    seen = set()
    resubscribes = [0]
    deadline = time.time() + args.timeout
    done = threading.Event()

    def follow(shard_id, turn):
        position = {"Type": "TRIM_HORIZON"}
        while not done.is_set() and time.time() < deadline:
            c = clients[turn % len(clients)]
            turn += 1
            try:
                events = c.subscribe_to_shard(
                    ConsumerARN=consumer_arn, ShardId=shard_id, StartingPosition=position
                )["EventStream"]
                for ev in events:
                    e = ev.get("SubscribeToShardEvent")
                    if e is None:
                        break
                    with lock:
                        for r in e["Records"]:
                            data = r["Data"].decode()
                            if data.startswith(prefix):
                                i = int(data[len(prefix):])
                                by_key.setdefault(i % args.keys, []).append(i)
                                seen.add(i)
                        if len(seen) >= args.count:
                            done.set()
                    if e.get("ContinuationSequenceNumber"):
                        position = {
                            "Type": "AFTER_SEQUENCE_NUMBER",
                            "SequenceNumber": e["ContinuationSequenceNumber"],
                        }
                    elif "ChildShards" in e:
                        return
                    if done.is_set() or time.time() > deadline:
                        return
            except Exception:  # noqa: BLE001 - a lost node or busy slot: again elsewhere
                pass
            with lock:
                resubscribes[0] += 1
            time.sleep(0.5)

    shards = c0.list_shards(StreamName=args.stream)["Shards"]
    threads = [
        threading.Thread(target=follow, args=(s["ShardId"], n), daemon=True)
        for n, s in enumerate(shards)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(0.0, deadline - time.time()) + 30)
    done.set()
    with lock:
        missing = sorted(set(range(args.count)) - seen)
        if missing:
            fail(f"{len(missing)} of {args.count} records never pushed, first {missing[0]}")
        for key, got in by_key.items():
            for a, b in zip(got, got[1:]):
                if b < a:
                    fail(f"key {key}: {b} pushed after {a}")
        dups = sum(len(g) - len(set(g)) for g in by_key.values())
        print(
            json.dumps(
                {"consumed": len(seen), "duplicates": dups, "resubscribes": resubscribes[0]}
            )
        )


def s3_control(args):
    def call(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            args.url + path,
            data=data,
            method="GET" if body is None else "POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode()

    if args.put_delay is not None:
        call("/control/put_delay", {"ms": args.put_delay})
    if args.fail_puts is not None:
        call("/control/fail_puts", {"prefix": args.prefix, "count": args.fail_puts})
    print(call("/control"))


def channel_create(args):
    """A GZIP S3 channel from on-demand stream S to bucket B, or with
    --table-bucket a GSR_JSON channel to an Iceberg table with B for dead
    letters."""
    c = client(args.endpoint)
    arn = c.describe_stream_summary(StreamName=args.stream)["StreamDescriptionSummary"][
        "StreamARN"
    ]
    account = arn.split(":")[4]
    if args.table_bucket:
        out = c.create_channel(
            ChannelName=args.channel,
            ServiceExecutionRoleARN=f"arn:aws:iam::{account}:role/channel-delivery",
            # An S3 Tables source names its Glue schema; Kythira checks it is
            # there but validates records against the table's schema.
            StreamConfigurationList=[
                {
                    "StreamARN": arn,
                    "RecordConfiguration": {
                        "RecordFormatType": "GSR_JSON",
                        "GSRSchemaARN": f"arn:aws:glue:us-east-1:{account}:schema/scenario/events",
                    },
                }
            ],
            S3TablesDestinationConfiguration={
                "DeadLetterQueueS3Configuration": {
                    "BucketARN": f"arn:aws:s3:::{args.bucket}",
                    "ExpectedBucketOwner": account,
                },
                "S3TablesConfigurationList": [
                    {
                        "TableBucketARN": args.table_bucket,
                        "Namespace": args.namespace,
                        "TableName": args.table,
                        "CompressionType": "SNAPPY",
                    }
                ],
            },
        )
        print(json.dumps({"channel": args.channel, "arn": out["ChannelDescription"]["ChannelARN"]}))
        return
    out = c.create_channel(
        ChannelName=args.channel,
        ServiceExecutionRoleARN=f"arn:aws:iam::{account}:role/channel-delivery",
        StreamConfigurationList=[
            {"StreamARN": arn, "RecordConfiguration": {"RecordFormatType": "STRING"}}
        ],
        S3DestinationConfiguration={
            "StorageConfiguration": {
                "BucketARN": f"arn:aws:s3:::{args.bucket}",
                "ExpectedBucketOwner": account,
                "CompressionType": "GZIP",
            }
        },
    )
    print(json.dumps({"channel": args.channel, "arn": out["ChannelDescription"]["ChannelARN"]}))


CHANNEL_OBJECT = re.compile(r"-(shardId-\d+)-(\d+)-(\d+)(\.gz)?$")


def channel_pass(s3, args):
    """Every delivered record, per key in delivery order: objects grouped
    by shard and taken in sequence order, as a reader of the bucket would."""
    objects = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=args.bucket):
        for o in page.get("Contents", []):
            m = CHANNEL_OBJECT.search(o["Key"])
            if m and o["Key"].rsplit("/", 1)[-1].startswith(f"{args.channel}-shardId-"):
                objects.append((m.group(1), int(m.group(2)), int(m.group(3)), o["Key"]))
    objects.sort()
    prefix = f"{args.tag}-"
    by_shard_key = {}
    seen = set()
    total = 0
    for shard, _first, _last, key in objects:
        body = s3.get_object(Bucket=args.bucket, Key=key)["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        for line in body.decode().splitlines():
            if not line.startswith(prefix):
                continue
            i = int(line[len(prefix):])
            total += 1
            seen.add(i)
            by_shard_key.setdefault((shard, i % args.keys), []).append(i)
    return by_shard_key, seen, total, len(objects)


def channel_check(args):
    s3 = boto3.client(
        "s3",
        endpoint_url=args.s3,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    deadline = time.time() + args.timeout
    while True:
        try:
            by_shard_key, seen, total, objects = channel_pass(s3, args)
        except ClientError:
            by_shard_key, seen, total, objects = {}, set(), 0, 0
        missing = sorted(set(range(args.count)) - seen)
        if not missing:
            break
        if time.time() > deadline:
            fail(
                f"{len(missing)} of {args.count} records never delivered "
                f"({objects} objects), first {missing[0]}"
            )
        time.sleep(3)
    # Within a shard a key's records were written in order; delivery keeps
    # it. A batch delivered again after a lost checkpoint starts at the
    # same record and may hold more (records kept arriving), so it repeats
    # a stretch already seen: skip records seen before, and every new one
    # must come after the last new one.
    for (shard, key), got in by_shard_key.items():
        first_seen = []
        known = set()
        for i in got:
            if i not in known:
                known.add(i)
                first_seen.append(i)
        for a, b in zip(first_seen, first_seen[1:]):
            if b < a:
                fail(f"{shard} key {key}: {b} delivered after {a}")
    print(json.dumps({"delivered": len(seen), "lines": total, "objects": objects}))


def iceberg_catalog(args):
    """The scenario's Iceberg REST catalog, its data read through the S3
    mock (path style; the mock checks no signature)."""
    from pyiceberg.catalog import load_catalog

    return load_catalog(
        "scenario",
        **{
            "type": "rest",
            "uri": args.catalog,
            "s3.endpoint": args.s3,
            "s3.access-key-id": "scenario-s3-key",
            "s3.secret-access-key": "scenario-s3-secret",
            "s3.region": "us-east-1",
            "s3.force-virtual-addressing": "false",
        },
    )


def tables_create(args):
    from pyiceberg.exceptions import NamespaceAlreadyExistsError, TableAlreadyExistsError
    from pyiceberg.partitioning import PartitionField, PartitionSpec
    from pyiceberg.schema import Schema
    from pyiceberg.transforms import HourTransform, IdentityTransform
    from pyiceberg.types import IntegerType, LongType, NestedField, StringType, TimestamptzType

    deadline = time.time() + args.timeout
    while True:
        try:
            cat = iceberg_catalog(args)
            try:
                cat.create_namespace(args.namespace)
            except NamespaceAlreadyExistsError:
                pass
            break
        except Exception as e:  # noqa: BLE001 - the catalog may still be starting
            if time.time() > deadline:
                fail(f"the Iceberg REST catalog never answered: {e}")
            time.sleep(2)
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "key", IntegerType(), required=False),
        NestedField(3, "tag", StringType(), required=False),
        NestedField(4, "event_time", TimestamptzType(), required=True),
    )
    spec = PartitionSpec(
        PartitionField(source_id=4, field_id=1000, transform=HourTransform(), name="event_time_hour"),
        PartitionField(source_id=2, field_id=1001, transform=IdentityTransform(), name="key"),
    )
    try:
        t = cat.create_table(
            f"{args.namespace}.{args.table}",
            schema=schema,
            partition_spec=spec,
            properties={"format-version": "2"},
        )
    except TableAlreadyExistsError:
        t = cat.load_table(f"{args.namespace}.{args.table}")
    print(json.dumps({"table": f"{args.namespace}.{args.table}", "location": t.location()}))


BATCH_ID = re.compile(r"^(?P<channel>[^/]+)/(?P<shard>[^/]+)/(?P<first>\d+)-(?P<last>\d+)$")


def tables_pass(args):
    t = iceberg_catalog(args).load_table(f"{args.namespace}.{args.table}")
    batches = []
    for snap in t.snapshots():
        props = snap.summary.additional_properties if snap.summary else {}
        b = props.get("kythira.channel-batch")
        if b:
            m = BATCH_ID.match(b)
            if not m:
                fail(f"snapshot {snap.snapshot_id} names a malformed batch {b!r}")
            batches.append((m["shard"], int(m["first"]), int(m["last"]), b))
    rows = t.scan(row_filter=f"tag = '{args.tag}'", selected_fields=("id",)).to_arrow()
    return batches, rows.column("id").to_pylist()


def tables_check(args):
    deadline = time.time() + args.timeout
    while True:
        try:
            batches, ids = tables_pass(args)
        except Exception as e:  # noqa: BLE001 - not there yet: try again
            if time.time() > deadline:
                fail(f"cannot read {args.namespace}.{args.table}: {e}")
            time.sleep(3)
            continue
        missing = sorted(set(range(args.count)) - set(ids))
        if not missing:
            break
        if time.time() > deadline:
            fail(
                f"{len(missing)} of {args.count} records never committed "
                f"({len(batches)} snapshots), first {missing[0]}"
            )
        time.sleep(3)
    # Each batch was committed once, even when its node was killed between
    # the commit and the checkpoint: no repeated batch, no overlap in a shard.
    names = [b[3] for b in batches]
    if len(names) != len(set(names)):
        fail(f"a batch was committed twice: {sorted(n for n in names if names.count(n) > 1)[0]}")
    by_shard = {}
    for shard, first, last, _ in batches:
        by_shard.setdefault(shard, []).append((first, last))
    for shard, ranges in by_shard.items():
        ranges.sort()
        for (a0, a1), (b0, b1) in zip(ranges, ranges[1:]):
            if b0 <= a1:
                fail(f"{shard}: batches {a0}-{a1} and {b0}-{b1} overlap")
    # Only the producer's own retries (a PutRecords answer lost to a kill)
    # may repeat a record.
    duplicates = len(ids) - len(set(ids))
    print(
        json.dumps(
            {"delivered": len(set(ids)), "rows": len(ids), "snapshots": len(batches),
             "duplicates": duplicates}
        )
    )


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    c.add_argument("--endpoint", required=True)
    c.add_argument("--stream", required=True)
    shape = c.add_mutually_exclusive_group(required=True)
    shape.add_argument("--shards", type=int)
    shape.add_argument("--on-demand", action="store_true")
    pr = sub.add_parser("produce")
    pr.add_argument("--endpoint", required=True)
    pr.add_argument("--stream", required=True)
    pr.add_argument("--count", type=int, required=True)
    pr.add_argument("--tag", required=True)
    co = sub.add_parser("consume")
    co.add_argument("--endpoints", required=True)
    co.add_argument("--stream", required=True)
    co.add_argument("--expect", type=int, required=True)
    co.add_argument("--limit", type=int, default=37)
    co.add_argument("--timeout", type=int, default=120)
    for name in ("ordered-produce", "lineage-consume", "batch-produce", "fan-out-consume"):
        o = sub.add_parser(name)
        o.add_argument("--endpoints", required=True)
        o.add_argument("--stream", required=True)
        o.add_argument("--count", type=int, required=True)
        o.add_argument("--keys", type=int, required=True)
        o.add_argument("--tag", required=True)
        o.add_argument("--limit", type=int, default=100)
        o.add_argument("--timeout", type=int, default=600)
        if name == "batch-produce":
            o.add_argument("--json", action="store_true")
    s3 = sub.add_parser("s3-control")
    s3.add_argument("--url", required=True)
    s3.add_argument("--put-delay", type=int)
    s3.add_argument("--fail-puts", type=int)
    s3.add_argument("--prefix", default="")
    cc = sub.add_parser("channel-create")
    cc.add_argument("--endpoint", required=True)
    cc.add_argument("--stream", required=True)
    cc.add_argument("--channel", required=True)
    cc.add_argument("--bucket", required=True)
    cc.add_argument("--table-bucket")
    cc.add_argument("--namespace")
    cc.add_argument("--table")
    ck = sub.add_parser("channel-check")
    ck.add_argument("--s3", required=True)
    ck.add_argument("--bucket", required=True)
    ck.add_argument("--channel", required=True)
    ck.add_argument("--count", type=int, required=True)
    ck.add_argument("--keys", type=int, required=True)
    ck.add_argument("--tag", required=True)
    ck.add_argument("--timeout", type=int, default=300)
    for name in ("tables-create", "tables-check"):
        t = sub.add_parser(name)
        t.add_argument("--catalog", required=True)
        t.add_argument("--s3", required=True)
        t.add_argument("--namespace", required=True)
        t.add_argument("--table", required=True)
        t.add_argument("--timeout", type=int, default=120 if name == "tables-create" else 300)
        if name == "tables-check":
            t.add_argument("--count", type=int, required=True)
            t.add_argument("--tag", required=True)
    args = p.parse_args()
    {
        "create": create,
        "produce": produce,
        "consume": consume,
        "ordered-produce": ordered_produce,
        "lineage-consume": lineage_consume,
        "batch-produce": batch_produce,
        "fan-out-consume": fan_out_consume,
        "s3-control": s3_control,
        "channel-create": channel_create,
        "channel-check": channel_check,
        "tables-create": tables_create,
        "tables-check": tables_check,
    }[args.command](args)


if __name__ == "__main__":
    main()
