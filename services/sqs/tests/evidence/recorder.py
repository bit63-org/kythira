#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""A recording SQS stub: what clients put on the wire.

.kiro/specs/sqs-compatible-queues/ task 1 ("recorded wire evidence"). Each
client in clients/ runs one scripted scenario against this stub; the stub
answers just enough of the SQS API for the scenario to finish (queues,
messages and visibility kept in memory) and records every request it
receives, normalised so a rerun with the same client version produces the
same file:

- the request line, the HTTP version and every header, with the values that
  change per call (signature, date, invocation id) replaced by a
  placeholder that still shows the value's shape;
- the body: AWS JSON 1.0 as sent, or for the query protocol both the form
  parameters as sent and the same request decoded into the JSON shape;
- the protocol, which the evidence tables summarise per client.

It answers in the protocol the request used. MD5 digests of bodies, message
attributes and system attributes are computed as SQS computes them, because
the SDKs check them and refuse a response that disagrees. An operation the
stub does not script gets UnsupportedOperation.

The query protocol is decoded and answered from the query-era botocore
model (botocore 1.31.40, the version requirements-query.txt pins; botocore
moved SQS to JSON shortly after), so this script must run under a Python
with that botocore.

    recorder.py --port 0 --out FILE --client NAME   (prints the port)

The process records until it receives SIGTERM or SIGINT, or a request to
POST /__evidence/stop, then writes FILE.
"""

import argparse
import base64
import hashlib
import http.server
import json
import re
import signal
import struct
import sys
import threading
import urllib.parse
from xml.sax.saxutils import escape

import botocore.session

JSON_CT = "application/x-amz-json-1.0"
FORM_CT = "application/x-www-form-urlencoded"
ACCOUNT = "123456789012"
REGION = "us-east-1"
REQUEST_ID = "00000000-0000-0000-0000-000000000000"
XMLNS = "http://queue.amazonaws.com/doc/2012-11-05/"
CREATED = "1794787200"  # 2026-11-18T00:00:00Z

# Header values that differ on every call. The placeholder keeps the shape.
VOLATILE = {
    "x-amz-date": "<amz-date>",
    "amz-sdk-invocation-id": "<uuid>",
    "x-amz-security-token": "<token>",
    "date": "<date>",
}
AUTH_RE = re.compile(r"Signature=[0-9a-f]+")
CRED_DATE_RE = re.compile(r"Credential=([^/]+)/\d{8}/")

# The query error codes SQS documents for the errors the scenarios can hit.
QUERY_CODES = {
    "QueueDoesNotExist": "AWS.SimpleQueueService.NonExistentQueue",
    "UnsupportedOperation": "AWS.SimpleQueueService.UnsupportedOperation",
    "ReceiptHandleIsInvalid": "ReceiptHandleIsInvalid",
}


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # noqa: S324 (SQS's digest, not security)


def md5_of_attributes(attrs: dict) -> str | None:
    """SQS's digest of message attributes (and of system attributes).

    For each attribute, sorted by name: the name, the data type and the
    value, each as a 4-byte big-endian length and its bytes, with a one-byte
    transport type (1 for String and Number, 2 for Binary) before the value.
    The SDKs recompute it and reject a mismatch.
    """
    if not attrs:
        return None
    out = bytearray()
    for name in sorted(attrs):
        a = attrs[name]
        data_type = a["DataType"]

        def field(b: bytes):
            out.extend(struct.pack(">I", len(b)))
            out.extend(b)

        field(name.encode())
        field(data_type.encode())
        if data_type.split(".", 1)[0] == "Binary":
            out.append(2)
            v = a["BinaryValue"]
            field(base64.b64decode(v) if isinstance(v, str) else v)
        else:
            out.append(1)
            field(a["StringValue"].encode())
    return md5_hex(bytes(out))


class Stub:
    """Queues in memory, enough for the scripted scenarios."""

    def __init__(self, endpoint_host):
        self.lock = threading.Lock()
        self.host = endpoint_host
        self.queues = {}  # name -> dict
        self.next_message = 1
        self.next_receive = 1

    def url(self, name):
        return f"http://{self.host}/{ACCOUNT}/{name}"

    def queue_of(self, req):
        url = req.get("QueueUrl", "")
        name = url.rstrip("/").rsplit("/", 1)[-1]
        return self.queues.get(name)

    def handle(self, op, req):
        with self.lock:
            return self._handle(op, req)

    def _send(self, q, entry):
        body = entry["MessageBody"]
        msg = {
            "MessageId": f"00000000-0000-4000-8000-{self.next_message:012d}",
            "Body": body,
            "MD5OfBody": md5_hex(body.encode()),
            "MessageAttributes": entry.get("MessageAttributes") or {},
            "SystemAttributes": entry.get("MessageSystemAttributes") or {},
            "ReceiveCount": 0,
            "Visible": True,
            "Receipt": None,
            "GroupId": entry.get("MessageGroupId"),
        }
        self.next_message += 1
        q["messages"].append(msg)
        out = {"MessageId": msg["MessageId"], "MD5OfMessageBody": msg["MD5OfBody"]}
        md5a = md5_of_attributes(msg["MessageAttributes"])
        if md5a:
            out["MD5OfMessageAttributes"] = md5a
        md5s = md5_of_attributes(msg["SystemAttributes"])
        if md5s:
            out["MD5OfMessageSystemAttributes"] = md5s
        if q["fifo"]:
            out["SequenceNumber"] = str(10_000_000_000_000_000_000 + self.next_message)
        return out

    def _find_receipt(self, q, handle):
        for m in q["messages"]:
            if m["Receipt"] == handle:
                return m
        return None

    def _handle(self, op, req):  # noqa: C901 (one branch per scripted operation)
        if op == "CreateQueue":
            name = req["QueueName"]
            attrs = req.get("Attributes") or {}
            if name not in self.queues:
                self.queues[name] = {"name": name, "attributes": dict(attrs),
                                     "tags": dict(req.get("tags") or {}),
                                     "messages": [], "fifo": name.endswith(".fifo")}
            return 200, {"QueueUrl": self.url(name)}
        if op == "ListQueues":
            prefix = req.get("QueueNamePrefix", "")
            return 200, {"QueueUrls": [self.url(n) for n in sorted(self.queues)
                                       if n.startswith(prefix)]}
        if op == "GetQueueUrl":
            if req.get("QueueName") not in self.queues:
                return 400, {"__type": "QueueDoesNotExist",
                             "message": "The specified queue does not exist."}
            return 200, {"QueueUrl": self.url(req["QueueName"])}
        q = self.queue_of(req)
        if q is None:
            return 400, {"__type": "QueueDoesNotExist",
                         "message": "The specified queue does not exist."}
        if op == "GetQueueAttributes":
            visible = sum(1 for m in q["messages"] if m["Visible"])
            attrs = {"QueueArn": f"arn:aws:sqs:{REGION}:{ACCOUNT}:{q['name']}",
                     "ApproximateNumberOfMessages": str(visible),
                     "ApproximateNumberOfMessagesNotVisible": str(len(q["messages"]) - visible),
                     "ApproximateNumberOfMessagesDelayed": "0",
                     "CreatedTimestamp": CREATED, "LastModifiedTimestamp": CREATED,
                     "VisibilityTimeout": "30", "MaximumMessageSize": "1048576",
                     "MessageRetentionPeriod": "345600", "DelaySeconds": "0",
                     "ReceiveMessageWaitTimeSeconds": "0", "SqsManagedSseEnabled": "true"}
            attrs.update(q["attributes"])
            names = req.get("AttributeNames") or []
            if "All" not in names:
                attrs = {k: v for k, v in attrs.items() if k in names}
            return 200, {"Attributes": attrs}
        if op == "SetQueueAttributes":
            q["attributes"].update(req.get("Attributes") or {})
            return 200, {}
        if op == "TagQueue":
            q["tags"].update(req.get("Tags") or {})
            return 200, {}
        if op == "UntagQueue":
            for k in req.get("TagKeys") or []:
                q["tags"].pop(k, None)
            return 200, {}
        if op == "ListQueueTags":
            return 200, ({"Tags": dict(q["tags"])} if q["tags"] else {})
        if op == "SendMessage":
            return 200, self._send(q, req)
        if op == "SendMessageBatch":
            ok = []
            for e in req.get("Entries") or []:
                r = self._send(q, e)
                r["Id"] = e["Id"]
                ok.append(r)
            return 200, {"Successful": ok, "Failed": []}
        if op == "ReceiveMessage":
            want = int(req.get("MaxNumberOfMessages") or 1)
            names = set(req.get("AttributeNames") or []) | set(
                req.get("MessageSystemAttributeNames") or [])
            attr_names = set(req.get("MessageAttributeNames") or [])
            out = []
            for m in q["messages"]:
                if len(out) == want:
                    break
                if not m["Visible"]:
                    continue
                m["Visible"] = False
                m["ReceiveCount"] += 1
                m["Receipt"] = base64.b64encode(
                    f"receipt-{self.next_receive}-{m['MessageId']}".encode()).decode()
                self.next_receive += 1
                msg = {"MessageId": m["MessageId"], "ReceiptHandle": m["Receipt"],
                       "MD5OfBody": m["MD5OfBody"], "Body": m["Body"]}
                system = {"SenderId": "AIDAEVIDENCE", "SentTimestamp": "1794787200000",
                          "ApproximateReceiveCount": str(m["ReceiveCount"]),
                          "ApproximateFirstReceiveTimestamp": "1794787200000"}
                if m["GroupId"]:
                    system["MessageGroupId"] = m["GroupId"]
                if "All" not in names:
                    system = {k: v for k, v in system.items() if k in names}
                if system:
                    msg["Attributes"] = system
                attrs = m["MessageAttributes"]
                if not ({"All", ".*"} & attr_names):
                    attrs = {k: v for k, v in attrs.items() if k in attr_names}
                if attrs:
                    msg["MessageAttributes"] = attrs
                    msg["MD5OfMessageAttributes"] = md5_of_attributes(attrs)
                out.append(msg)
            return 200, ({"Messages": out} if out else {})
        if op == "DeleteMessage":
            m = self._find_receipt(q, req.get("ReceiptHandle"))
            if m is not None:
                q["messages"].remove(m)
            return 200, {}
        if op == "DeleteMessageBatch":
            ok = []
            for e in req.get("Entries") or []:
                m = self._find_receipt(q, e.get("ReceiptHandle"))
                if m is not None:
                    q["messages"].remove(m)
                ok.append({"Id": e["Id"]})
            return 200, {"Successful": ok, "Failed": []}
        if op == "ChangeMessageVisibility":
            m = self._find_receipt(q, req.get("ReceiptHandle"))
            if m is None:
                return 400, {"__type": "ReceiptHandleIsInvalid",
                             "message": "The input receipt handle is invalid."}
            m["Visible"] = int(req.get("VisibilityTimeout") or 0) == 0
            return 200, {}
        if op == "ChangeMessageVisibilityBatch":
            ok = []
            for e in req.get("Entries") or []:
                m = self._find_receipt(q, e.get("ReceiptHandle"))
                if m is not None:
                    m["Visible"] = int(e.get("VisibilityTimeout") or 0) == 0
                ok.append({"Id": e["Id"]})
            return 200, {"Successful": ok, "Failed": []}
        if op == "PurgeQueue":
            q["messages"].clear()
            return 200, {}
        if op == "DeleteQueue":
            del self.queues[q["name"]]
            return 200, {}
        return 400, {"__type": "UnsupportedOperation", "message": f"{op} is not scripted"}


class QueryCodec:
    """The query protocol, decoded and encoded from the query-era model."""

    def __init__(self):
        self.model = botocore.session.get_session().get_service_model("sqs")
        if self.model.protocol != "query":
            raise SystemExit(f"recorder.py needs a query-protocol sqs model (botocore "
                             f"1.31.40); botocore here has protocol {self.model.protocol}")

    @staticmethod
    def _name(shape, default):
        return shape.serialization.get("name", default)

    def decode(self, op, form):
        shape = self.model.operation_model(op).input_shape
        return self._decode(shape, form, "") if shape is not None else {}

    def _decode(self, shape, form, prefix):  # noqa: C901 (inverse of botocore's serializer)
        t = shape.type_name
        if t == "structure":
            out = {}
            for name, member in shape.members.items():
                p = self._name(member, name)
                p = f"{prefix}.{p}" if prefix else p
                v = self._decode(member, form, p)
                if v is not None:
                    out[name] = v
            return out or None
        if t == "list":
            if shape.serialization.get("flattened"):
                base = prefix
                if shape.member.serialization.get("name"):
                    base = ".".join(prefix.split(".")[:-1] + [self._name(shape.member, "")])
            else:
                base = f"{prefix}.{shape.member.serialization.get('name', 'member')}"
            items, i = [], 1
            while any(k == f"{base}.{i}" or k.startswith(f"{base}.{i}.") for k in form):
                items.append(self._decode(shape.member, form, f"{base}.{i}"))
                i += 1
            if not items and prefix in form:
                return []
            return items or None
        if t == "map":
            base = prefix if shape.serialization.get("flattened") else f"{prefix}.entry"
            ks, vs = self._name(shape.key, "key"), self._name(shape.value, "value")
            out, i = {}, 1
            while f"{base}.{i}.{ks}" in form:
                out[form[f"{base}.{i}.{ks}"]] = self._decode(shape.value, form,
                                                             f"{base}.{i}.{vs}")
                i += 1
            return out or None
        if prefix not in form:
            return None
        v = form[prefix]
        if t in ("integer", "long"):
            return int(v)
        if t == "boolean":
            return v == "true"
        return v

    def encode(self, op, body):
        shape = self.model.operation_model(op).output_shape
        inner = ""
        if shape is not None:
            wrapper = shape.serialization.get("resultWrapper", f"{op}Result")
            inner = f"<{wrapper}>{self._encode_members(shape, body)}</{wrapper}>"
        return (f'<?xml version="1.0"?><{op}Response xmlns="{XMLNS}">{inner}'
                f"<ResponseMetadata><RequestId>{REQUEST_ID}</RequestId></ResponseMetadata>"
                f"</{op}Response>").encode()

    def _encode_members(self, shape, value):
        return "".join(self._encode(m, value[n], self._name(m, n))
                       for n, m in shape.members.items() if n in value)

    def _encode(self, shape, value, tag):
        t = shape.type_name
        if t == "structure":
            return f"<{tag}>{self._encode_members(shape, value)}</{tag}>"
        if t == "list":
            if shape.serialization.get("flattened"):
                name = self._name(shape.member, tag)
                return "".join(self._encode(shape.member, v, name) for v in value)
            name = self._name(shape.member, "member")
            return f"<{tag}>" + "".join(self._encode(shape.member, v, name)
                                        for v in value) + f"</{tag}>"
        if t == "map":
            ks, vs = self._name(shape.key, "key"), self._name(shape.value, "value")
            entries = [f"<{ks}>{escape(k)}</{ks}>{self._encode(shape.value, v, vs)}"
                       for k, v in value.items()]
            if shape.serialization.get("flattened"):
                return "".join(f"<{tag}>{e}</{tag}>" for e in entries)
            return f"<{tag}>" + "".join(f"<entry>{e}</entry>" for e in entries) + f"</{tag}>"
        if t == "boolean":
            value = "true" if value else "false"
        return f"<{tag}>{escape(str(value))}</{tag}>"

    @staticmethod
    def error(code, message):
        return (f'<?xml version="1.0"?><ErrorResponse xmlns="{XMLNS}"><Error>'
                f"<Type>Sender</Type><Code>{code}</Code><Message>{escape(message)}</Message>"
                f"<Detail/></Error><RequestId>{REQUEST_ID}</RequestId></ErrorResponse>").encode()


def sorted_maps(v):
    """JSON maps with sorted keys: clients emit maps (attributes, tags) in
    hash order, which would make every recording differ."""
    if isinstance(v, dict):
        return {k: sorted_maps(v[k]) for k in sorted(v)}
    if isinstance(v, list):
        return [sorted_maps(x) for x in v]
    return v


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
        elif low == "user-agent":
            value = re.sub(r"os/(linux|Linux)#\S+", r"os/\1#<kernel>", value)
            value = re.sub(r"Linux/\S+", "Linux/<kernel>", value)
            value = re.sub(r"md/arch#\S+", "md/arch#<arch>", value)
            # The SDK feature list (m/...) is emitted in set order; sort it.
            value = re.sub(r"\bm/([A-Za-z0-9,]+)",
                           lambda mm: "m/" + ",".join(sorted(mm.group(1).split(","))), value)
        elif low == "x-amz-content-sha256" and re.fullmatch(r"[0-9a-f]{64}", value):
            value = "<sha256-hex>"
        out.append([name, value])
    return out


class Recorder:
    def __init__(self, client):
        self.client = client
        self.entries = []
        self.lock = threading.Lock()
        self.stub = None
        self.query = QueryCodec()
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
            if self.path == "/__evidence/stop":
                self.reply(200, "text/plain", b"stopping\n")
                rec.done.set()
                return
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length else b""
            ct = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            entry = {"method": self.command, "path": self.path,
                     "http_version": self.request_version, "content_type": ct,
                     "headers": normalise_headers(self.headers.items())}
            if ct == FORM_CT:
                pairs = urllib.parse.parse_qsl(raw.decode(), keep_blank_values=True)
                form = dict(pairs)
                op = form.get("Action", "")
                try:
                    body = rec.query.decode(op, form)
                except Exception:  # noqa: BLE001 (an unknown action is evidence too)
                    body = None
                req = dict(body or {})
                if "QueueUrl" not in req and self.path not in ("", "/"):
                    # The query protocol may name the queue by path instead.
                    req["QueueUrl"] = self.path
                status, resp = rec.stub.handle(op, req)
                entry.update({"operation": op, "form": [list(p) for p in pairs],
                              "body": sorted_maps(body or {})})
                if status == 200:
                    payload = rec.query.encode(op, resp)
                else:
                    payload = QueryCodec.error(QUERY_CODES.get(resp["__type"], resp["__type"]),
                                               resp["message"])
                out_ct, extra = "text/xml", {}
            else:
                target = self.headers.get("X-Amz-Target", "")
                op = target.split(".", 1)[1] if "." in target else target
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = {"$undecodable": base64.b64encode(raw).decode()}
                status, resp = rec.stub.handle(op, body if isinstance(body, dict) else {})
                entry.update({"operation": op, "body": sorted_maps(body)})
                extra = {}
                if status != 200:
                    code = QUERY_CODES.get(resp["__type"], resp["__type"])
                    extra["x-amzn-query-error"] = f"{code};Sender"
                    resp = {"__type": f"com.amazonaws.sqs#{resp['__type']}",
                            "message": resp["message"]}
                payload, out_ct = json.dumps(resp).encode(), JSON_CT
            entry.update({"response_status": status,
                          "response_type": resp.get("__type") if status != 200 else None})
            rec.record(entry)
            extra["x-amzn-RequestId"] = REQUEST_ID
            self.reply(status, out_ct, payload, extra)

        def reply(self, status, ct, payload, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(payload)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
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
    # Queue URLs name the endpoint the client used; the port is normalised
    # in the evidence like the Host header.
    rec.stub = Stub(f"127.0.0.1:{srv.server_address[1]}")
    print(srv.server_address[1], flush=True)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: rec.done.set())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    rec.done.wait()
    srv.shutdown()
    text = json.dumps(rec.document(), indent=1, sort_keys=False)
    text = text.replace(f"127.0.0.1:{srv.server_address[1]}", "127.0.0.1:<port>")
    text = text.replace(urllib.parse.quote(f"127.0.0.1:{srv.server_address[1]}", safe=""),
                        urllib.parse.quote("127.0.0.1:<port>", safe=""))
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
