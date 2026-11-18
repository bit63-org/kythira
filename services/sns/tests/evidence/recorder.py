#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""A recording SNS stub: what clients put on the wire.

.kiro/specs/sns-compatible-notifications/ task 1 ("recorded wire evidence
from the CLI and SDKs"). Each client in clients/ runs one scripted scenario
against this stub; the stub answers just enough of the SNS API for the
scenario to finish (topics, subscriptions and tags kept in memory) and
records every request it receives, normalised so a rerun with the same
client version produces the same file:

- the request line, the HTTP version and every header, with the values that
  change per call (signature, date, invocation id) replaced by a placeholder
  that still shows the value's shape;
- the form body as an ordered list of [name, value] pairs, exactly as the
  client flattened it (`Attributes.entry.1.key`,
  `MessageAttributes.entry.1.Value.DataType`, `PublishBatchRequestEntries.
  member.1.Id`, ...), since the flattening is what the gateway's query codec
  has to accept;
- whether the client signed the payload (`x-amz-content-sha256`) and which
  headers it signed.

It answers in SNS's XML. An action it does not script gets the query
protocol's InvalidAction, which is also what the gateway returns for an
operation listed in doc/unsupported.md.

    recorder.py --port 0 --out FILE --client NAME   (prints the port)

The process records until it receives SIGTERM or SIGINT, then writes FILE.
"""

import argparse
import hashlib
import http.server
import json
import re
import signal
import sys
import threading
import urllib.parse
from xml.sax.saxutils import escape

FORM_CT = "application/x-www-form-urlencoded"
ACCOUNT = "123456789012"
REGION = "us-east-1"
NS = "http://sns.amazonaws.com/doc/2010-03-31/"
REQUEST_ID = "00000000-0000-0000-0000-000000000000"

# Header values that differ on every call. The placeholder keeps the shape.
VOLATILE = {
    "x-amz-date": "<amz-date>",
    "amz-sdk-invocation-id": "<uuid>",
    "x-amz-security-token": "<token>",
    "date": "<date>",
}
AUTH_RE = re.compile(r"Signature=[0-9a-f]+")
CRED_DATE_RE = re.compile(r"Credential=([^/]+)/\d{8}/")


def topic_arn(name):
    return f"arn:aws:sns:{REGION}:{ACCOUNT}:{name}"


class Stub:
    """Topics, subscriptions and tags, enough for the scripted scenarios."""

    def __init__(self):
        self.lock = threading.Lock()
        self.topics = {}  # arn -> {"attrs": {}, "tags": {}}
        self.subs = {}  # arn -> {"topic", "protocol", "endpoint", "attrs", "confirmed"}
        self.next_sub = 1
        self.next_msg = 1
        self.next_seq = 10000000000000000000

    def handle(self, action, form):
        with self.lock:
            return self._handle(action, form)

    @staticmethod
    def entries(form, prefix):
        """`prefix.entry.N.key` / `.value` pairs as a dict."""
        out, n = {}, 1
        while f"{prefix}.entry.{n}.key" in form:
            out[form[f"{prefix}.entry.{n}.key"]] = form.get(f"{prefix}.entry.{n}.value", "")
            n += 1
        return out

    @staticmethod
    def members(form, prefix, field=None):
        """`prefix.member.N[.field]` values as a list."""
        out, n = [], 1
        while True:
            key = f"{prefix}.member.{n}" + (f".{field}" if field else "")
            if key not in form:
                return out
            out.append(form[key])
            n += 1

    def message_id(self):
        mid = f"00000000-0000-4000-8000-{self.next_msg:012d}"
        self.next_msg += 1
        return mid

    def sequence(self, arn):
        if not arn.endswith(".fifo"):
            return None
        self.next_seq += 1
        return str(self.next_seq)

    def _handle(self, action, f):  # noqa: C901 (one branch per scripted action)
        if action == "CreateTopic":
            arn = topic_arn(f.get("Name", ""))
            t = self.topics.setdefault(arn, {"attrs": {}, "tags": {}})
            t["attrs"].update(self.entries(f, "Attributes"))
            n = 1
            while f"Tags.member.{n}.Key" in f:
                t["tags"][f[f"Tags.member.{n}.Key"]] = f.get(f"Tags.member.{n}.Value", "")
                n += 1
            return 200, f"<TopicArn>{arn}</TopicArn>"
        if action == "ListTopics":
            return 200, "<Topics>" + "".join(
                f"<member><TopicArn>{a}</TopicArn></member>" for a in sorted(self.topics)
            ) + "</Topics>"
        if action == "DeleteTopic":
            self.topics.pop(f.get("TopicArn"), None)
            return 200, None

        arn = f.get("TopicArn") or f.get("ResourceArn")
        if action in ("GetTopicAttributes", "SetTopicAttributes", "Subscribe",
                      "ListSubscriptionsByTopic", "Publish", "PublishBatch",
                      "TagResource", "UntagResource", "ListTagsForResource",
                      "ConfirmSubscription") and arn not in self.topics:
            return 404, ("NotFound", "Topic does not exist")
        if action == "GetTopicAttributes":
            t = self.topics[arn]
            attrs = {"TopicArn": arn, "Owner": ACCOUNT,
                     "SubscriptionsConfirmed": str(sum(
                         1 for s in self.subs.values() if s["topic"] == arn and s["confirmed"])),
                     "SubscriptionsPending": str(sum(
                         1 for s in self.subs.values()
                         if s["topic"] == arn and not s["confirmed"])),
                     "SubscriptionsDeleted": "0", **t["attrs"]}
            return 200, attributes_xml(attrs)
        if action == "SetTopicAttributes":
            self.topics[arn]["attrs"][f["AttributeName"]] = f.get("AttributeValue", "")
            return 200, None
        if action == "Subscribe":
            protocol, endpoint = f.get("Protocol"), f.get("Endpoint", "")
            sub = f"{arn}:{self.next_sub:08d}-0000-4000-8000-000000000000"
            self.next_sub += 1
            confirmed = protocol in ("sqs", "lambda", "firehose")
            self.subs[sub] = {"topic": arn, "protocol": protocol, "endpoint": endpoint,
                              "attrs": self.entries(f, "Attributes"), "confirmed": confirmed}
            shown = sub if confirmed or f.get("ReturnSubscriptionArn") == "true" else \
                "pending confirmation"
            return 200, f"<SubscriptionArn>{shown}</SubscriptionArn>"
        if action == "ConfirmSubscription":
            for sub, s in self.subs.items():
                if s["topic"] == arn and not s["confirmed"]:
                    s["confirmed"] = True
                    return 200, f"<SubscriptionArn>{sub}</SubscriptionArn>"
            return 400, ("InvalidParameter", "Invalid token")
        if action == "ListSubscriptionsByTopic":
            return 200, "<Subscriptions>" + "".join(
                "<member>"
                f"<SubscriptionArn>{sub if s['confirmed'] else 'PendingConfirmation'}"
                "</SubscriptionArn>"
                f"<Owner>{ACCOUNT}</Owner><Protocol>{s['protocol']}</Protocol>"
                f"<Endpoint>{escape(s['endpoint'])}</Endpoint><TopicArn>{arn}</TopicArn>"
                "</member>" for sub, s in self.subs.items() if s["topic"] == arn
            ) + "</Subscriptions>"
        if action in ("GetSubscriptionAttributes", "SetSubscriptionAttributes", "Unsubscribe"):
            sub = f.get("SubscriptionArn")
            if sub not in self.subs:
                return 404, ("NotFound", "Subscription does not exist")
            s = self.subs[sub]
            if action == "Unsubscribe":
                del self.subs[sub]
                return 200, None
            if action == "SetSubscriptionAttributes":
                s["attrs"][f["AttributeName"]] = f.get("AttributeValue", "")
                return 200, None
            attrs = {"SubscriptionArn": sub, "TopicArn": s["topic"], "Owner": ACCOUNT,
                     "Protocol": s["protocol"], "Endpoint": s["endpoint"],
                     "ConfirmationWasAuthenticated": "true",
                     "PendingConfirmation": "false" if s["confirmed"] else "true",
                     **s["attrs"]}
            return 200, attributes_xml(attrs)
        if action == "Publish":
            seq = self.sequence(arn)
            return 200, f"<MessageId>{self.message_id()}</MessageId>" + (
                f"<SequenceNumber>{seq}</SequenceNumber>" if seq else "")
        if action == "PublishBatch":
            ok = []
            for eid in self.members(f, "PublishBatchRequestEntries", "Id"):
                seq = self.sequence(arn)
                ok.append(f"<member><Id>{escape(eid)}</Id><MessageId>{self.message_id()}"
                          "</MessageId>" + (f"<SequenceNumber>{seq}</SequenceNumber>"
                                            if seq else "") + "</member>")
            return 200, "<Successful>" + "".join(ok) + "</Successful><Failed/>"
        if action == "TagResource":
            n = 1
            while f"Tags.member.{n}.Key" in f:
                self.topics[arn]["tags"][f[f"Tags.member.{n}.Key"]] = \
                    f.get(f"Tags.member.{n}.Value", "")
                n += 1
            return 200, ""
        if action == "UntagResource":
            for k in self.members(f, "TagKeys"):
                self.topics[arn]["tags"].pop(k, None)
            return 200, ""
        if action == "ListTagsForResource":
            return 200, "<Tags>" + "".join(
                f"<member><Key>{escape(k)}</Key><Value>{escape(v)}</Value></member>"
                for k, v in sorted(self.topics[arn]["tags"].items())) + "</Tags>"
        return 400, ("InvalidAction", f"The action {action} is not valid for this web service.")


def attributes_xml(attrs):
    return "<Attributes>" + "".join(
        f"<entry><key>{escape(k)}</key><value>{escape(v)}</value></entry>"
        for k, v in attrs.items()) + "</Attributes>"


def response_xml(action, status, result):
    if status != 200:
        code, message = result
        kind = "Receiver" if status >= 500 else "Sender"
        return (f'<ErrorResponse xmlns="{NS}"><Error><Type>{kind}</Type><Code>{code}</Code>'
                f"<Message>{escape(message)}</Message></Error>"
                f"<RequestId>{REQUEST_ID}</RequestId></ErrorResponse>\n")
    body = "" if result is None else f"<{action}Result>{result}</{action}Result>"
    return (f'<{action}Response xmlns="{NS}">{body}'
            f"<ResponseMetadata><RequestId>{REQUEST_ID}</RequestId></ResponseMetadata>"
            f"</{action}Response>\n")


def normalise_headers(items):
    out = []
    for name, value in items:
        low = name.lower()
        if low in VOLATILE:
            value = VOLATILE[low]
        elif low == "authorization":
            value = CRED_DATE_RE.sub(r"Credential=\1/<yyyymmdd>/", AUTH_RE.sub(
                "Signature=<hex>", value))
        elif low == "host":
            value = re.sub(r":\d+$", ":<port>", value)
        elif low in ("user-agent", "x-amz-user-agent"):
            value = re.sub(r"os/(linux|Linux)#\S+", r"os/\1#<kernel>", value)
            value = re.sub(r"(os/linux)/\S+", r"\1/<kernel>", value)
            # botocore lists its feature ids (m/...) in set order, which
            # changes between runs; sort them so a rerun is identical.
            value = re.sub(r"\bm/([A-Za-z0-9,]+)",
                           lambda m: "m/" + ",".join(sorted(m.group(1).split(","))), value)
        elif low == "x-amz-content-sha256" and re.fullmatch(r"[0-9a-f]{64}", value):
            value = "<sha256-hex>"
        out.append([name, value])
    return out


class Recorder:
    def __init__(self, client):
        self.client = client
        self.entries = []
        self.lock = threading.Lock()
        self.stub = Stub()
        self.done = threading.Event()

    def record(self, entry):
        with self.lock:
            self.entries.append(entry)

    def document(self):
        return {"client": self.client, "requests": self.entries,
                "summary": {"operations": [e["operation"] for e in self.entries],
                            "content_types": sorted({e["content_type"] for e in self.entries}),
                            "http_versions": sorted({e["http_version"] for e in self.entries})}}


def make_handler(rec):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):  # noqa: N802 (http.server's naming)
            length = int(self.headers.get("Content-Length", "0") or 0)
            if self.headers.get("Expect", "").lower() == "100-continue":
                self.send_response_only(100)
                self.end_headers()
            raw = self.rfile.read(length) if length else b""
            ct = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            pairs = urllib.parse.parse_qsl(raw.decode("utf-8"), keep_blank_values=True)
            form = dict(pairs)
            action = form.get("Action", "")
            status, result = rec.stub.handle(action, form)
            rec.record({
                "operation": action,
                "method": self.command,
                "path": self.path,
                "http_version": self.request_version,
                "content_type": ct,
                "content_type_header": self.headers.get("Content-Type"),
                "headers": normalise_headers(self.headers.items()),
                "body_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                "form": [list(p) for p in pairs],
                "response_status": status,
                "response_code": None if status == 200 else result[0],
            })
            payload = response_xml(action, status, result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("x-amzn-RequestId", REQUEST_ID)
            self.end_headers()
            self.wfile.write(payload)

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--client", required=True)
    args = ap.parse_args()
    rec = Recorder(args.client)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(rec))
    print(srv.server_address[1], flush=True)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: rec.done.set())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    rec.done.wait()
    srv.shutdown()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec.document(), f, indent=1)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
