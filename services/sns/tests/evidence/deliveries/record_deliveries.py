#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Record what real Amazon SNS sends to an HTTPS subscriber.

`.kiro/specs/sns-compatible-notifications/` task 1: the delivery workers
(task 6) and message signatures (task 7) must send what SNS sends, header
for header and byte for byte in the signed body. AWS's documentation shows
examples; this records the real thing once and checks it in.

What it does, in one AWS account and region, with whatever credentials
boto3 finds (AWS_PROFILE, environment, or a CI role):

1. Deploys capture_lambda.py as a Lambda function behind a function URL
   (auth NONE), with a temporary execution role unless --role-arn names
   one.
2. Creates two standard topics, one signing with SignatureVersion 1 and
   one with 2, and subscribes the URL three times: /a/wrapped and /a/raw
   (RawMessageDelivery) on the first, /b/wrapped on the second.
3. Confirms each subscription with the token SNS delivered.
4. Publishes to the first topic: a plain message, one with a subject and
   String, Number and Binary attributes, one with MessageStructure json,
   and a PublishBatch of two; and a plain message to the second.
5. Unsubscribes /a/wrapped and waits a minute for an UnsubscribeConfirmation
   (none arrived on the first run; the file says whether one did).
6. Reads the captured requests back from the function's log group, fetches
   each SigningCertURL certificate, and writes deliveries.json.
7. Deletes everything it made (subscriptions, topics, the URL, the
   function, its log group, the temporary role), also on failure.

The output keeps SNS's bodies unchanged so their signatures still verify
against the saved certificates (check_deliveries.py does that). The capture
host is replaced with capture.example, and the headers the function URL
adds itself (trace id, forwarded-for, TLS details) are dropped. The topic
ARNs keep the real account id: AWS does not treat account ids as secrets,
and changing them would break the signatures. Tokens and URLs in the bodies
belong to subscriptions that no longer exist when the file is written.

Cost: a few Lambda invocations, a dozen SNS publishes and HTTP deliveries,
and a few kilobytes of logs; well under $0.01, and inside the free tier on
most accounts.

Usage:
    record_deliveries.py --region us-east-1 --out deliveries.json
"""

import argparse
import io
import json
import re
import sys
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path

import boto3

HERE = Path(__file__).resolve().parent
DROPPED_HEADERS = {
    "x-amzn-trace-id",
    "x-forwarded-for",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-amzn-tls-version",
    "x-amzn-tls-cipher-suite",
    "via",
}
CAPTURE_HOST = "capture.example"
EXPECTED = {"/a/wrapped": 7, "/a/raw": 6, "/b/wrapped": 2}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


class Run:
    def __init__(self, region, role_arn):
        self.region = region
        self.tag = "kythira-sns-evidence-" + uuid.uuid4().hex[:8]
        self.session = boto3.Session(region_name=region)
        self.iam = self.session.client("iam")
        self.lam = self.session.client("lambda")
        self.sns = self.session.client("sns")
        self.logs = self.session.client("logs")
        self.role_arn = role_arn
        self.made_role = None
        self.function = None
        self.url = None
        self.topics = []
        self.subscriptions = []
        self.labels = {}  # message id -> label

    # -- setup ---------------------------------------------------------

    def make_role(self):
        if self.role_arn:
            return
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role = self.iam.create_role(
            RoleName=self.tag,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Temporary: SNS delivery capture (kythira task 1)",
        )["Role"]
        self.made_role = self.tag
        self.iam.attach_role_policy(
            RoleName=self.tag,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        self.role_arn = role["Arn"]
        log("created role " + self.role_arn + "; waiting for it to propagate")
        time.sleep(12)

    def make_function(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.write(HERE / "capture_lambda.py", "capture_lambda.py")
        for attempt in range(6):
            try:
                self.lam.create_function(
                    FunctionName=self.tag,
                    Runtime="python3.12",
                    Role=self.role_arn,
                    Handler="capture_lambda.handler",
                    Code={"ZipFile": buf.getvalue()},
                    Timeout=10,
                    MemorySize=128,
                )
                break
            except self.lam.exceptions.InvalidParameterValueException:
                # A new role is not assumable for a few seconds.
                if attempt == 5:
                    raise
                time.sleep(5)
        self.function = self.tag
        self.lam.get_waiter("function_active_v2").wait(FunctionName=self.tag)
        self.url = self.lam.create_function_url_config(FunctionName=self.tag, AuthType="NONE")[
            "FunctionUrl"
        ].rstrip("/")
        self.lam.add_permission(
            FunctionName=self.tag,
            StatementId="public-url",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        # Function URLs created since October 2025 also need InvokeFunction
        # granted through the URL.
        try:
            self.lam.add_permission(
                FunctionName=self.tag,
                StatementId="public-url-invoke",
                Action="lambda:InvokeFunction",
                Principal="*",
                InvokedViaFunctionUrl=True,
            )
        except Exception as e:  # older botocore or region without the rule
            log("InvokeFunction via URL permission not added: %s" % e)
        log("function URL " + self.url)
        time.sleep(5)

    def make_topics(self):
        for suffix, version in (("a", "1"), ("b", "2")):
            arn = self.sns.create_topic(
                Name="%s-%s" % (self.tag, suffix),
                Attributes={"SignatureVersion": version, "DisplayName": "Kythira evidence"},
                Tags=[{"Key": "purpose", "Value": "kythira-sns-evidence"}],
            )["TopicArn"]
            self.topics.append(arn)

    def subscribe(self):
        a, b = self.topics
        for topic, path, raw in ((a, "/a/wrapped", False), (a, "/a/raw", True), (b, "/b/wrapped", False)):
            attrs = {"RawMessageDelivery": "true"} if raw else {}
            self.sns.subscribe(
                TopicArn=topic, Protocol="https", Endpoint=self.url + path, Attributes=attrs
            )

    # -- capture -------------------------------------------------------

    def captured(self):
        group = "/aws/lambda/" + self.function
        out, token = [], None
        try:
            while True:
                kw = {"logGroupName": group, "filterPattern": '"kythira_capture"'}
                if token:
                    kw["nextToken"] = token
                page = self.logs.filter_log_events(**kw)
                for e in page.get("events", []):
                    line = e["message"].strip()
                    if line.startswith("{"):
                        out.append((e["timestamp"], json.loads(line)))
                token = page.get("nextToken")
                if not token:
                    break
        except self.logs.exceptions.ResourceNotFoundException:
            return []
        out.sort(key=lambda t: t[0])
        return [c for _, c in out]

    def wait_for(self, predicate, what, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            caps = self.captured()
            if predicate(caps):
                return caps
            time.sleep(5)
        raise SystemExit("timed out waiting for " + what)

    def confirm(self):
        def confirmations(caps):
            found = {}
            for c in caps:
                if c["headers"].get("x-amz-sns-message-type") == "SubscriptionConfirmation":
                    found[c["path"]] = json.loads(c["body"])
            return found

        caps = self.wait_for(lambda cs: len(confirmations(cs)) == 3, "three confirmations")
        for path, msg in sorted(confirmations(caps).items()):
            arn = self.sns.confirm_subscription(TopicArn=msg["TopicArn"], Token=msg["Token"])[
                "SubscriptionArn"
            ]
            self.subscriptions.append((path, arn))
        log("confirmed " + ", ".join(p for p, _ in self.subscriptions))
        time.sleep(3)

    def publish(self):
        a, b = self.topics
        m = self.sns.publish(TopicArn=a, Message="Hello from the Kythira evidence run.")
        self.labels[m["MessageId"]] = "plain"
        m = self.sns.publish(
            TopicArn=a,
            Subject="Evidence subject",
            Message="With attributes: <xml> & \"quotes\" and unicode é中.",
            MessageAttributes={
                "color": {"DataType": "String", "StringValue": "red"},
                "size": {"DataType": "Number", "StringValue": "4.5"},
                "blob": {"DataType": "Binary", "BinaryValue": b"\x00\x01\x02\xff"},
            },
        )
        self.labels[m["MessageId"]] = "attributes"
        m = self.sns.publish(
            TopicArn=a,
            MessageStructure="json",
            Message=json.dumps(
                {"default": "default body", "https": "https body", "sqs": "sqs body"}
            ),
        )
        self.labels[m["MessageId"]] = "structure-json"
        r = self.sns.publish_batch(
            TopicArn=a,
            PublishBatchRequestEntries=[
                {"Id": "first", "Message": "batch entry one"},
                {"Id": "second", "Message": "batch entry two", "Subject": "Batch subject"},
            ],
        )
        for s in r["Successful"]:
            self.labels[s["MessageId"]] = "batch-" + s["Id"]
        if r.get("Failed"):
            raise SystemExit("PublishBatch failed: %s" % r["Failed"])
        m = self.sns.publish(TopicArn=b, Message="Signed with SignatureVersion 2.")
        self.labels[m["MessageId"]] = "plain-v2"

        def done(caps):
            seen = {}
            for c in caps:
                seen[c["path"]] = seen.get(c["path"], 0) + 1
            return all(seen.get(p, 0) >= n - (1 if p == "/a/wrapped" else 0) for p, n in EXPECTED.items())

        self.wait_for(done, "every notification")

    def unsubscribe(self):
        """Unsubscribes /a/wrapped and waits a while for the
        UnsubscribeConfirmation SNS may send. Best effort: the 2026-11-18
        run got none within three minutes of an owner's Unsubscribe call,
        so its absence is recorded rather than fatal."""
        for path, arn in self.subscriptions:
            if path == "/a/wrapped":
                self.sns.unsubscribe(SubscriptionArn=arn)
        self.subscriptions = [s for s in self.subscriptions if s[0] != "/a/wrapped"]

        def done(caps):
            return any(
                c["path"] == "/a/wrapped"
                and c["headers"].get("x-amz-sns-message-type") == "UnsubscribeConfirmation"
                for c in caps
            )

        try:
            return self.wait_for(done, "the unsubscribe confirmation", timeout=60), True
        except SystemExit:
            log("no UnsubscribeConfirmation arrived within 60 s; recording without it")
            return self.captured(), False

    # -- output --------------------------------------------------------

    def normalise(self, caps):
        host = re.sub(r"^https://", "", self.url)
        out, seen = [], set()
        for c in caps:
            headers = {
                k.lower(): v.replace(host, CAPTURE_HOST)
                for k, v in c["headers"].items()
                if k.lower() not in DROPPED_HEADERS
            }
            mid = headers.get("x-amz-sns-message-id", "")
            key = (c["path"], mid, headers.get("x-amz-sns-message-type"))
            if key in seen:
                continue  # an SNS retry of a delivery already captured
            seen.add(key)
            out.append(
                {
                    "path": c["path"],
                    "label": self.labels.get(mid, headers.get("x-amz-sns-message-type", "")),
                    "method": c["method"],
                    "query": c["query"],
                    "headers": dict(sorted(headers.items())),
                    "body": c["body"].replace(host, CAPTURE_HOST),
                }
            )
        order = {"SubscriptionConfirmation": 0, "Notification": 1, "UnsubscribeConfirmation": 2}
        labels = ["plain", "attributes", "structure-json", "batch-first", "batch-second", "plain-v2"]
        out.sort(
            key=lambda d: (
                d["path"],
                order.get(d["headers"].get("x-amz-sns-message-type"), 1),
                labels.index(d["label"]) if d["label"] in labels else -1,
            )
        )
        return out

    @staticmethod
    def certificates(deliveries):
        certs = {}
        for d in deliveries:
            try:
                msg = json.loads(d["body"])
            except ValueError:
                continue  # a raw delivery: the message itself
            url = msg.get("SigningCertURL") if isinstance(msg, dict) else None
            if url and url not in certs:
                if not re.match(r"^https://sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?/", url):
                    raise SystemExit("unexpected certificate host: " + url)
                with urllib.request.urlopen(url, timeout=30) as r:
                    certs[url] = r.read().decode("ascii")
        return certs

    # -- teardown ------------------------------------------------------

    def cleanup(self):
        steps = []
        for _, arn in self.subscriptions:
            steps.append(("unsubscribe", lambda arn=arn: self.sns.unsubscribe(SubscriptionArn=arn)))
        for arn in self.topics:
            steps.append(("delete topic", lambda arn=arn: self.sns.delete_topic(TopicArn=arn)))
        if self.function:
            steps.append(("delete url", lambda: self.lam.delete_function_url_config(FunctionName=self.function)))
            steps.append(("delete function", lambda: self.lam.delete_function(FunctionName=self.function)))
            steps.append(
                (
                    "delete log group",
                    lambda: self.logs.delete_log_group(logGroupName="/aws/lambda/" + self.function),
                )
            )
        if self.made_role:
            steps.append(
                (
                    "detach policy",
                    lambda: self.iam.detach_role_policy(
                        RoleName=self.made_role,
                        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                    ),
                )
            )
            steps.append(("delete role", lambda: self.iam.delete_role(RoleName=self.made_role)))
        failed = []
        for what, step in steps:
            try:
                step()
            except Exception as e:  # keep going: delete as much as possible
                if "ResourceNotFound" not in type(e).__name__ and "NotFound" not in str(e):
                    failed.append("%s: %s" % (what, e))
        for f in failed:
            log("CLEANUP FAILED " + f)
        log("cleanup done" if not failed else "cleanup left resources tagged " + self.tag)
        return not failed


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--role-arn", help="an existing Lambda execution role to use")
    ap.add_argument("--out", type=Path, default=HERE / "deliveries.json")
    args = ap.parse_args(argv)

    run = Run(args.region, args.role_arn)
    log("run " + run.tag + " in " + args.region)
    ok = False
    try:
        run.make_role()
        run.make_function()
        run.make_topics()
        run.subscribe()
        run.confirm()
        run.publish()
        caps, unsubscribe_confirmed = run.unsubscribe()
        deliveries = run.normalise(caps)
        certs = run.certificates(deliveries)
        doc = {
            "recorded": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "region": args.region,
            "topics": {"a": {"SignatureVersion": "1"}, "b": {"SignatureVersion": "2"}},
            "unsubscribe_confirmation_received": unsubscribe_confirmed,
            "deliveries": deliveries,
            "certificates": certs,
        }
        args.out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        log("wrote %d deliveries and %d certificates to %s" % (len(deliveries), len(certs), args.out))
        ok = True
    finally:
        clean = run.cleanup()
    return 0 if ok and clean else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
