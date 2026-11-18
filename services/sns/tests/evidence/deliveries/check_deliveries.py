#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Check the recorded SNS deliveries (record_deliveries.py's output).

For every delivery: the method is POST, the x-amz-sns-* headers agree with
the body, and each signed message verifies against the certificate saved
beside it, by the string SNS documents ("Verifying the signatures of Amazon
SNS messages"): SignatureVersion 1 is SHA1withRSA, 2 is SHA256withRSA, over
`Key\\nValue\\n` for

  Notification            Message, MessageId, Subject (when present),
                          Timestamp, TopicArn, Type
  (Un)SubscribeConfirmation  Message, MessageId, SubscribeURL, Timestamp,
                          Token, TopicArn, Type

A delivery's signature failing means either the recording was altered or
the documented string is wrong; task 7's signer must produce exactly what
passes here. Verification uses the `openssl` command, so the check needs no
Python packages.

Usage:
    check_deliveries.py DELIVERIES.json
    check_deliveries.py --self-test     (signs synthetic messages with a
                                         throwaway key and verifies them)
"""

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

NOTIFICATION_KEYS = ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
CONFIRMATION_KEYS = ("Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type")
DIGEST = {"1": "-sha1", "2": "-sha256"}


def string_to_sign(msg):
    keys = NOTIFICATION_KEYS if msg["Type"] == "Notification" else CONFIRMATION_KEYS
    out = ""
    for k in keys:
        if k in msg:
            out += k + "\n" + msg[k] + "\n"
    return out.encode("utf-8")


def verify(msg, cert_pem, work):
    digest = DIGEST.get(msg.get("SignatureVersion"))
    if digest is None:
        return "unknown SignatureVersion %r" % msg.get("SignatureVersion")
    cert = work / "cert.pem"
    cert.write_text(cert_pem)
    pub = work / "pub.pem"
    subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-pubkey", "-noout", "-out", str(pub)], check=True
    )
    data = work / "data"
    data.write_bytes(string_to_sign(msg))
    sig = work / "sig"
    sig.write_bytes(base64.b64decode(msg["Signature"]))
    r = subprocess.run(
        ["openssl", "dgst", digest, "-verify", str(pub), "-signature", str(sig), str(data)],
        capture_output=True,
        text=True,
    )
    return None if r.returncode == 0 else "signature does not verify: " + r.stdout + r.stderr


def check(doc):
    problems = []
    certs = doc.get("certificates", {})
    types = {}
    signed = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for i, d in enumerate(doc["deliveries"]):
            where = "delivery %d (%s %s)" % (i, d["path"], d["label"])
            h = d["headers"]
            mtype = h.get("x-amz-sns-message-type")
            types[mtype] = types.get(mtype, 0) + 1
            if d["method"] != "POST":
                problems.append(where + ": method " + str(d["method"]))
            if not h.get("x-amz-sns-message-id") or not h.get("x-amz-sns-topic-arn"):
                problems.append(where + ": missing x-amz-sns-message-id or -topic-arn")
            raw = h.get("x-amz-sns-rawdelivery") == "true" and mtype == "Notification"
            if raw:
                continue
            try:
                msg = json.loads(d["body"])
            except ValueError:
                problems.append(where + ": body is not JSON")
                continue
            if msg.get("Type") != mtype:
                problems.append(where + ": Type %r but header %r" % (msg.get("Type"), mtype))
            if msg.get("MessageId") != h.get("x-amz-sns-message-id"):
                problems.append(where + ": MessageId differs from its header")
            if msg.get("TopicArn") != h.get("x-amz-sns-topic-arn"):
                problems.append(where + ": TopicArn differs from its header")
            cert = certs.get(msg.get("SigningCertURL") or msg.get("SigningCertUrl"))
            if cert is None:
                problems.append(where + ": no saved certificate for its SigningCertURL")
                continue
            err = verify(msg, cert, work)
            if err:
                problems.append(where + ": " + err)
            else:
                signed += 1
    return problems, types, signed


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        key, cert = work / "k.pem", work / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
             "-out", str(cert), "-days", "1", "-subj", "/CN=sns.example"],
            check=True, capture_output=True,
        )
        url = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem"
        deliveries = []
        for version, mtype, extra in (
            ("1", "Notification", {"Subject": "s"}),
            ("2", "Notification", {}),
            ("1", "SubscriptionConfirmation", {"SubscribeURL": "https://x/?a=b", "Token": "t"}),
        ):
            msg = {
                "Type": mtype,
                "MessageId": "m-" + version,
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:t",
                "Message": "hello\nworld",
                "Timestamp": "2026-11-18T00:00:00.000Z",
                "SignatureVersion": version,
                "SigningCertURL": url,
                **extra,
            }
            data = work / "d"
            data.write_bytes(string_to_sign(msg))
            sig = subprocess.run(
                ["openssl", "dgst", DIGEST[version], "-sign", str(key), str(data)],
                check=True, capture_output=True,
            ).stdout
            msg["Signature"] = base64.b64encode(sig).decode()
            deliveries.append({
                "path": "/x", "label": mtype, "method": "POST", "query": "",
                "headers": {"x-amz-sns-message-type": mtype, "x-amz-sns-message-id": msg["MessageId"],
                            "x-amz-sns-topic-arn": msg["TopicArn"]},
                "body": json.dumps(msg),
            })
        doc = {"deliveries": deliveries, "certificates": {url: cert.read_text()}}
        problems, _, signed = check(doc)
        if problems or signed != 3:
            print("self-test failed:", problems, file=sys.stderr)
            return 1
        # A changed body must fail.
        tampered = json.loads(deliveries[0]["body"])
        tampered["Message"] = "hellO\nworld"
        deliveries[0]["body"] = json.dumps(tampered)
        problems, _, _ = check(doc)
        if len(problems) != 1:
            print("self-test failed: a tampered message verified", file=sys.stderr)
            return 1
    print("check_deliveries self-test ok")
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    doc = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    problems, types, signed = check(doc)
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print("%d deliveries ok (%s), %d signatures verified" % (
        len(doc["deliveries"]), ", ".join("%s %d" % kv for kv in sorted(types.items())), signed))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
