#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Differential test of Kythira's SQS API against recordings of Amazon SQS.

.kiro/specs/sqs-compatible-queues/ task 13 (Requirement 13.4), the CI part:
a seeded, reproducible operation mix is run once against real SQS and its
normalised answers are written to a recording; the same mix is replayed
against Kythira in CI and compared step by step. Same shape as the Kinesis
differential (services/kinesis/doc/differential.md).

    sqs_differential.py run --real-aws --seed N --steps M --out FILE
    sqs_differential.py run --endpoint URL --seed N --steps M --out FILE
    sqs_differential.py compare --endpoint URL --recording FILE|DIR [--allow FILE]
    sqs_differential.py self-check --endpoints URL,URL --seed N --steps M

SQS promises little about which messages a receive returns (a standard
queue samples, any receive may return fewer than asked), so the mix only
asks questions with one right answer:

- A standard queue holds at most one visible message when a single receive
  is compared. Batches are drained by a macro step that receives until
  every message is back, and the step's answer is the set, sorted by body.
- FIFO answers are compared per message group, in order.
- Approximate counts, timestamps, message ids, receipt handles, request
  ids and queue URLs become placeholders; the account and region are
  replaced in every string. MD5 digests are compared: they are a pure
  function of what was sent.
- An error compares as its code and HTTP status. Its message is a note,
  and fails only with --strict-messages.

A comparison stops at the first step whose request differs. Each run makes
its own queues (kythira-diff-<seed>-<hex>...) and deletes them at the end,
even after a failure.

--real-aws talks to SQS with the ambient credentials (AWS_PROFILE etc.). A
run is a few hundred requests, inside SQS's free tier, but it touches a
real account, so it needs Clark's go each time.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import sys
import time

TOOL_VERSION = 1
QUEUE_PREFIX = "kythira-diff"
# Fields whose value differs between any two runs.
PLACEHOLDERS = {
    "MessageId": "<message-id>",
    "ReceiptHandle": "<receipt>",
    "SequenceNumber": "<sequence>",
    "SentTimestamp": "<time>",
    "ApproximateFirstReceiveTimestamp": "<time>",
    "CreatedTimestamp": "<time>",
    "LastModifiedTimestamp": "<time>",
    "ApproximateNumberOfMessages": "<count>",
    "ApproximateNumberOfMessagesNotVisible": "<count>",
    "ApproximateNumberOfMessagesDelayed": "<count>",
    "SenderId": "<sender>",
    "TaskHandle": "<task>",
}
# Attributes SQS adds over time; a recording names the ones it saw.
VOLATILE_QUEUE_ATTRIBUTES = {"Policy"}


# ---- normalising ---------------------------------------------------------


class Normaliser:
    """Turns one run's raw answers into comparable values."""

    def __init__(self):
        self.replace = []  # (text, placeholder), longest first

    def learn(self, text, placeholder):
        if text and all(t != text for t, _ in self.replace):
            self.replace.append((text, placeholder))
            self.replace.sort(key=lambda p: -len(p[0]))

    def text(self, s):
        for t, p in self.replace:
            s = s.replace(t, p)
        return s

    def value(self, v, key=None):
        if isinstance(v, dict):
            return {k: self.value(x, k) for k, x in sorted(v.items())
                    if k != "ResponseMetadata" and k not in VOLATILE_QUEUE_ATTRIBUTES}
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if v is None:
            return None
        if key in PLACEHOLDERS:
            if key in ("ReceiptHandle", "MessageId") and isinstance(v, str):
                # Error messages quote them.
                self.learn(v, PLACEHOLDERS[key])
            return PLACEHOLDERS[key]
        if isinstance(v, (bytes, bytearray)):
            return "b64:" + base64.b64encode(bytes(v)).decode()
        if hasattr(v, "isoformat"):
            return "<time>"
        if isinstance(v, str):
            return self.text(v)
        return v

    def error(self, e):
        r = e.response
        return {
            "error": r.get("Error", {}).get("Code", "?"),
            "status": r.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            "message": self.text(r.get("Error", {}).get("Message", "") or ""),
        }


def by_body(messages):
    """Messages sorted by body, for answers whose order SQS leaves open."""
    return sorted(messages, key=lambda m: (m.get("Body", ""), json.dumps(m, sort_keys=True)))


def by_group(messages):
    """FIFO messages as {group: [message, ...]} in delivery order."""
    out = {}
    for m in messages:
        out.setdefault(m.get("Attributes", {}).get("MessageGroupId", ""), []).append(m)
    return out


# ---- the operation mix ---------------------------------------------------


class Mix:
    """Runs the seeded mix against one client, recording normalised steps."""

    def __init__(self, client, seed, steps, prefix, wait=2):
        self.c = client
        self.rng = random.Random(seed)
        self.n_steps = steps
        self.prefix = prefix
        self.wait = wait
        self.norm = Normaliser()
        self.norm.learn(prefix, "<prefix>")
        self.steps = []
        self.queues = {}  # role -> url
        self.counter = 0

    # -- plumbing

    def call(self, op, **req):
        """One request; returns (raw response or None, normalised answer)."""
        try:
            # The client sees resolved requests; the recording keeps the
            # symbolic ones.
            raw = getattr(self.c, op)(**resolve(req))
            return raw, self.norm.value(raw)
        except Exception as e:  # botocore ClientError, without importing it
            if not hasattr(e, "response"):
                raise
            return None, self.norm.error(e)

    def record(self, op, request, response):
        self.steps.append({"op": op, "request": symbolic(request, self.norm), "response": response})

    def step(self, op, **req):
        raw, ans = self.call(op, **req)
        self.record(op, req, ans)
        return raw

    def next_body(self, tag):
        self.counter += 1
        return "%s-%d-%s" % (tag, self.counter, self.rng.choice(["a", "bb", "ccc", "ü", "line\nbreak"]))

    def attrs(self):
        out = {}
        for _ in range(self.rng.randint(0, 3)):
            kind = self.rng.choice(["String", "Number", "Binary", "String.custom"])
            name = "a%d" % self.rng.randint(0, 9)
            if kind.startswith("String"):
                out[name] = {"DataType": kind, "StringValue": self.rng.choice(["x", "blue", "ünï"])}
            elif kind == "Number":
                out[name] = {"DataType": kind, "StringValue": str(self.rng.randint(-5, 1000))}
            else:
                out[name] = {"DataType": kind, "BinaryValue": bytes(self.rng.randint(0, 255) for _ in range(3))}
        return out

    def drain(self, op_name, url, want, fifo):
        """Macro step: receive until `want` messages are back (or 10 tries)."""
        got = []
        for _ in range(10):
            if len(got) >= want:
                break
            raw, ans = self.call("receive_message", QueueUrl=url, MaxNumberOfMessages=10,
                                 WaitTimeSeconds=self.wait, MessageAttributeNames=["All"],
                                 MessageSystemAttributeNames=["All"])
            if raw is None:
                self.record(op_name, {"QueueUrl": url, "want": want}, ans)
                return []
            got.extend(raw.get("Messages", []))
        norm = [self.norm.value(m) for m in got]
        self.record(op_name, {"QueueUrl": url, "want": want},
                    {"groups": by_group(norm)} if fifo else {"messages": by_body(norm)})
        return got

    # -- setup and teardown

    def setup(self):
        names = {
            "std": self.prefix + "-std",
            "fifo": self.prefix + "-f.fifo",
            "dlq": self.prefix + "-dlq",
        }
        raw, _ = self.call("create_queue", QueueName=names["std"])
        if raw is None:
            raise SystemExit("cannot create " + names["std"])
        self.queues["std"] = raw["QueueUrl"]
        # The URL embeds the host and account; learn them before recording.
        self.norm.learn(raw["QueueUrl"].rsplit("/", 2)[0], "<endpoint>")
        self.norm.learn(raw["QueueUrl"].rstrip("/").split("/")[-2], "<account>")
        self.record("create_queue", {"QueueName": names["std"]}, self.norm.value(raw))
        raw = self.step("create_queue", QueueName=names["fifo"],
                        Attributes={"FifoQueue": "true"})
        self.queues["fifo"] = raw["QueueUrl"]
        raw = self.step("create_queue", QueueName=names["dlq"])
        self.queues["dlq"] = raw["QueueUrl"]
        # The same name with other attributes is refused.
        self.step("create_queue", QueueName=names["std"], Attributes={"DelaySeconds": "5"})
        self.step("get_queue_url", QueueName=names["std"])

    def teardown(self):
        for url in self.queues.values():
            try:
                self.c.delete_queue(QueueUrl=url)
            except Exception:
                pass

    # -- the moves

    def m_single(self):
        url = self.queues["std"]
        body = self.next_body("s")
        a = self.attrs()
        req = {"QueueUrl": url, "MessageBody": body}
        if a:
            req["MessageAttributes"] = a
        self.step("send_message", **req)
        msgs = self.drain("receive_one", url, 1, False)
        if not msgs:
            return
        m = msgs[0]
        if self.rng.random() < 0.4:
            self.step("change_message_visibility", QueueUrl=url,
                      ReceiptHandle={"$receipt": m["ReceiptHandle"]}, VisibilityTimeout=0)
            again = self.drain("receive_again", url, 1, False)
            if again:
                # The first handle is stale now.
                self.step("change_message_visibility", QueueUrl=url,
                          ReceiptHandle={"$receipt": m["ReceiptHandle"]}, VisibilityTimeout=10)
                m = again[0]
        self.step("delete_message", QueueUrl=url, ReceiptHandle={"$receipt": m["ReceiptHandle"]})

    def m_batch(self):
        url = self.queues["std"]
        n = self.rng.randint(1, 10)
        entries = []
        for i in range(n):
            e = {"Id": "e%d" % i, "MessageBody": self.next_body("b")}
            if self.rng.random() < 0.3:
                e["MessageAttributes"] = self.attrs() or {"k": {"DataType": "String", "StringValue": "v"}}
            entries.append(e)
        bad = self.rng.random() < 0.3
        if bad:
            # An entry SQS refuses on its own: an attribute with no value.
            entries[-1]["MessageAttributes"] = {"empty": {"DataType": "String", "StringValue": ""}}
        raw = self.step("send_message_batch", QueueUrl=url, Entries=entries)
        ok = len(raw.get("Successful", [])) if raw else 0
        msgs = self.drain("drain_batch", url, ok, False)
        if msgs:
            ordered = sorted(msgs, key=lambda m: m["Body"])
            self.step("delete_message_batch", QueueUrl=url, Entries=[
                {"Id": "d%d" % i, "ReceiptHandle": {"$receipt": m["ReceiptHandle"]}}
                for i, m in enumerate(ordered)])

    def m_fifo(self):
        url = self.queues["fifo"]
        groups = ["g%d" % i for i in range(self.rng.randint(1, 3))]
        sent = 0
        for _ in range(self.rng.randint(1, 6)):
            g = self.rng.choice(groups)
            self.counter += 1
            dedup = "d%d" % self.counter
            body = self.next_body("f")
            self.step("send_message", QueueUrl=url, MessageBody=body, MessageGroupId=g,
                      MessageDeduplicationId=dedup)
            sent += 1
            if self.rng.random() < 0.25:
                # A retry inside the window: accepted, not delivered twice.
                self.step("send_message", QueueUrl=url, MessageBody=body, MessageGroupId=g,
                          MessageDeduplicationId=dedup)
        msgs = self.drain("drain_fifo", url, sent, True)
        for i in range(0, len(msgs), 10):
            self.step("delete_message_batch", QueueUrl=url, Entries=[
                {"Id": "d%d" % k, "ReceiptHandle": {"$receipt": m["ReceiptHandle"]}}
                for k, m in enumerate(msgs[i:i + 10])])

    def m_attributes(self):
        url = self.queues["std"]
        name, value = self.rng.choice([
            ("VisibilityTimeout", str(self.rng.choice([0, 30, 43200, 43201]))),
            ("MessageRetentionPeriod", str(self.rng.choice([59, 60, 345600, 1209601]))),
            ("DelaySeconds", str(self.rng.choice([0, 900, 901]))),
            ("MaximumMessageSize", str(self.rng.choice([1023, 1024, 262144, 1048576, 1048577]))),
            ("ReceiveMessageWaitTimeSeconds", str(self.rng.choice([0, 20, 21]))),
            ("FifoQueue", "true"),
            ("NoSuchAttribute", "1"),
        ])
        self.step("set_queue_attributes", QueueUrl=url, Attributes={name: value})
        # Put it back, so later moves see SQS's defaults.
        defaults = {"VisibilityTimeout": "30", "MessageRetentionPeriod": "345600",
                    "DelaySeconds": "0", "MaximumMessageSize": "1048576",
                    "ReceiveMessageWaitTimeSeconds": "0"}
        if name in defaults:
            self.step("set_queue_attributes", QueueUrl=url, Attributes={name: defaults[name]})
        self.step("get_queue_attributes", QueueUrl=url, AttributeNames=["All"])

    def m_redrive(self):
        url, dlq = self.queues["std"], self.queues["dlq"]
        dlq_arn = self.c.get_queue_attributes(QueueUrl=dlq, AttributeNames=["QueueArn"])[
            "Attributes"]["QueueArn"]
        self.norm.learn(dlq_arn.split(":")[3], "<region>")
        policy = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1})
        self.step("set_queue_attributes", QueueUrl=url, Attributes={"RedrivePolicy": policy})
        self.step("list_dead_letter_source_queues", QueueUrl=dlq)
        self.step("set_queue_attributes", QueueUrl=url, Attributes={"RedrivePolicy": ""})

    def m_tags(self):
        url = self.queues[self.rng.choice(["std", "fifo"])]
        k = "t%d" % self.rng.randint(0, 3)
        if self.rng.random() < 0.6:
            self.step("tag_queue", QueueUrl=url, Tags={k: self.rng.choice(["v", "", "x" * 256])})
        else:
            self.step("untag_queue", QueueUrl=url, TagKeys=[k])
        self.step("list_queue_tags", QueueUrl=url)

    def m_errors(self):
        url, fifo = self.queues["std"], self.queues["fifo"]
        choice = self.rng.randrange(12)
        if choice == 0:
            self.step("get_queue_url", QueueName=self.prefix + "-missing")
        elif choice == 1:
            self.step("receive_message", QueueUrl=url, MaxNumberOfMessages=11)
        elif choice == 2:
            self.step("change_message_visibility", QueueUrl=url, ReceiptHandle="not-a-handle",
                      VisibilityTimeout=10)
        elif choice == 3:
            self.step("delete_message", QueueUrl=url, ReceiptHandle="not-a-handle")
        elif choice == 4:
            self.step("send_message_batch", QueueUrl=url, Entries=[])
        elif choice == 5:
            self.step("send_message_batch", QueueUrl=url, Entries=[
                {"Id": "same", "MessageBody": "1"}, {"Id": "same", "MessageBody": "2"}])
        elif choice == 6:
            self.step("send_message_batch", QueueUrl=url, Entries=[
                {"Id": "e%d" % i, "MessageBody": "x"} for i in range(11)])
        elif choice == 7:
            self.step("send_message", QueueUrl=fifo, MessageBody="no group")
        elif choice == 8:
            self.step("send_message", QueueUrl=url, MessageBody="late", DelaySeconds=901)
        elif choice == 9:
            self.step("send_message", QueueUrl=fifo, MessageBody="no dedup", MessageGroupId="g")
        elif choice == 10:
            self.step("send_message", QueueUrl=url, MessageBody="x",
                      MessageAttributes={"aws.reserved": {"DataType": "String", "StringValue": "v"}})
        else:
            self.step("delete_message_batch", QueueUrl=url, Entries=[
                {"Id": "x", "ReceiptHandle": "not-a-handle"}])

    def m_list(self):
        self.step("list_queues", QueueNamePrefix=self.prefix)

    def run(self):
        moves = [(self.m_single, 4), (self.m_batch, 3), (self.m_fifo, 3), (self.m_attributes, 2),
                 (self.m_redrive, 1), (self.m_tags, 2), (self.m_errors, 4), (self.m_list, 1)]
        bag = [m for m, w in moves for _ in range(w)]
        try:
            self.setup()
            while len(self.steps) < self.n_steps:
                self.rng.choice(bag)()
            # Purge twice: the second inside the cool-down is refused.
            self.step("purge_queue", QueueUrl=self.queues["std"])
            self.step("purge_queue", QueueUrl=self.queues["std"])
        finally:
            self.teardown()
        return self.steps


def symbolic(req, n):
    """A request as recorded: handles abstract, long values summarised."""
    if isinstance(req, dict):
        if set(req) == {"$receipt"}:
            return "<receipt>"
        return {k: symbolic(v, n) for k, v in sorted(req.items())}
    if isinstance(req, list):
        return [symbolic(v, n) for v in req]
    if isinstance(req, (bytes, bytearray)):
        return "b64:" + base64.b64encode(bytes(req)).decode()
    if isinstance(req, str):
        if len(req) > 300:
            return {"$text": len(req), "sha256": hashlib.sha256(req.encode()).hexdigest()}
        return n.text(req)
    return req


def resolve(req):
    """The request to send: symbolic receipt handles back to their values."""
    if isinstance(req, dict):
        if set(req) == {"$receipt"}:
            return req["$receipt"]
        return {k: resolve(v) for k, v in req.items()}
    if isinstance(req, list):
        return [resolve(v) for v in req]
    return req


# ---- comparing -----------------------------------------------------------


# Batch answers whose entries SQS lists in no particular order (the
# recordings show Successful shuffled against the request): compared as
# sets, sorted by Id.
UNORDERED = {"Successful", "Failed"}


def by_id(xs):
    if isinstance(xs, list) and all(isinstance(x, dict) and "Id" in x for x in xs):
        return sorted(xs, key=lambda x: x["Id"])
    return xs


def diff(a, b, path=""):
    """Paths where `a` (the recording) and `b` differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        a = {k: by_id(v) if k in UNORDERED else v for k, v in a.items()}
        b = {k: by_id(v) if k in UNORDERED else v for k, v in b.items()}
        out = []
        for k in sorted(set(a) | set(b)):
            p = path + "." + k if path else k
            if k not in a:
                out.append((p, "<absent>", b[k]))
            elif k not in b:
                out.append((p, a[k], "<absent>"))
            else:
                out += diff(a[k], b[k], p)
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [(path + ".length", len(a), len(b))]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, "%s[%d]" % (path, i))
        return out
    return [] if a == b else [(path, a, b)]


def allowed_path(path, pattern):
    """`pattern` matches `path` with [n] indexes written as [*]."""
    return re.sub(r"\[\d+\]", "[*]", path) == pattern


def compare(recorded, got, allow=(), strict_messages=False):
    """(failures, notes) comparing two step lists."""
    failures, notes = [], []
    for i, (a, b) in enumerate(zip(recorded, got)):
        where = "step %d %s" % (i, a["op"])
        if a["op"] != b["op"] or a["request"] != b["request"]:
            failures.append("%s: requests diverge (recorded %s, got %s %s); stopping" % (
                where, json.dumps(a["request"])[:200], b["op"], json.dumps(b["request"])[:200]))
            return failures, notes
        for path, x, y in diff(a["response"], b["response"]):
            line = "%s: %s recorded %s, got %s" % (where, path, json.dumps(x)[:160], json.dumps(y)[:160])
            if any(x_["op"] == a["op"] and allowed_path(path, x_["path"]) for x_ in allow):
                notes.append("allowed " + line)
            elif path.endswith("message") and not strict_messages:
                notes.append(line)
            else:
                failures.append(line)
    if len(recorded) != len(got):
        failures.append("step counts differ: recorded %d, got %d" % (len(recorded), len(got)))
    return failures, notes


# ---- the command line ----------------------------------------------------


def make_client(endpoint, region):
    import boto3
    from botocore.config import Config

    cfg = Config(retries={"max_attempts": 1}, parameter_validation=False,
                 connect_timeout=5, read_timeout=30)
    if endpoint:
        return boto3.client("sqs", endpoint_url=endpoint, region_name=region, config=cfg)
    return boto3.client("sqs", region_name=region, config=cfg)


def run_mix(endpoint, region, seed, steps):
    prefix = "%s-%d-%s" % (QUEUE_PREFIX, seed, os.urandom(3).hex())
    return Mix(make_client(endpoint, region), seed, steps, prefix).run()


def recordings(path):
    """`path` itself, or every aws-seed-*.json in the directory `path`."""
    if not os.path.isdir(path):
        return [path]
    found = sorted(os.path.join(path, f) for f in os.listdir(path)
                   if f.startswith("aws-seed-") and f.endswith(".json"))
    if not found:
        raise SystemExit("no aws-seed-*.json recordings in " + path)
    return found


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--endpoint")
    r.add_argument("--real-aws", action="store_true")
    r.add_argument("--region", default="us-east-1")
    r.add_argument("--seed", type=int, required=True)
    r.add_argument("--steps", type=int, default=150)
    r.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    c.add_argument("--endpoint", required=True)
    c.add_argument("--region", default="us-east-1")
    c.add_argument("--recording", required=True)
    c.add_argument("--allow")
    c.add_argument("--strict-messages", action="store_true")
    s = sub.add_parser("self-check")
    s.add_argument("--endpoints", required=True)
    s.add_argument("--region", default="us-east-1")
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--steps", type=int, default=80)
    a = p.parse_args(argv)

    if a.cmd == "run":
        if bool(a.endpoint) == a.real_aws:
            p.error("give exactly one of --endpoint or --real-aws")
        steps = run_mix(a.endpoint, a.region, a.seed, a.steps)
        import botocore

        rec = {"version": TOOL_VERSION, "seed": a.seed, "steps_requested": a.steps,
               "target": "aws" if a.real_aws else "endpoint", "region": a.region,
               "botocore": botocore.__version__, "recorded_at": int(time.time()), "steps": steps}
        with open(a.out, "w") as f:
            json.dump(rec, f, indent=1, sort_keys=True, ensure_ascii=False)
            f.write("\n")
        print(json.dumps({"steps": len(steps), "out": a.out}))
        return 0
    if a.cmd == "compare":
        allow = []
        if a.allow:
            with open(a.allow) as f:
                allow = json.load(f)
        failures, notes = [], []
        for path in recordings(a.recording):
            with open(path) as f:
                rec = json.load(f)
            got = run_mix(a.endpoint, a.region, rec["seed"], rec["steps_requested"])
            fs, ns = compare(rec["steps"], got, allow, a.strict_messages)
            name = os.path.basename(path)
            failures += ["%s %s" % (name, x) for x in fs]
            notes += ["%s %s" % (name, x) for x in ns]
    else:
        e1, e2 = a.endpoints.split(",")[:2]
        first = run_mix(e1, a.region, a.seed, a.steps)
        second = run_mix(e2, a.region, a.seed, a.steps)
        failures, notes = compare(first, second, (), True)
    for n in notes:
        print("note: " + n)
    for f in failures:
        print("FAIL: " + f, file=sys.stderr)
    print(json.dumps({"failures": len(failures), "notes": len(notes)}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
