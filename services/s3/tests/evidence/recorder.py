#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""A recording S3 stub: what S3 clients put on the wire.

.kiro/specs/s3-compatible-storage/ task 1 ("recording stub and checked-in
wire evidence"). Each client under clients/ runs one scripted scenario
against this stub. The stub answers just enough of the S3 REST-XML API for
the scenario to finish (buckets, objects and multipart uploads kept in
memory) and records every request it receives, normalised so a rerun with
the same client version produces the same file:

- the request line, the HTTP version and every header, with the values
  that change per call (signature, date, invocation id, port, kernel)
  replaced by a placeholder that keeps the value's shape;
- the operation, found the way the gateway will find it: method, path,
  distinguishing query keys and headers (x-amz-copy-source, uploadId);
- the addressing style: virtual-hosted (`<bucket>.<domain>`), path, or
  service (no bucket, as `ListBuckets`);
- whether the client sent `Expect: 100-continue`;
- the body: XML request documents as text; object bytes as their length
  and SHA-256 after removing the `aws-chunked` framing, with the framing
  itself described (chunk sizes, whether chunks are signed, trailer names
  and whether the trailer is signed). Payloads are never stored.

An operation it does not script gets `NotImplemented` (HTTP 501), which is
also what the gateway returns for an operation listed in
doc/unsupported.md.

    recorder.py --out FILE --client NAME --domain D --tls-cert C --tls-key K

It prints the port it listens on, records until SIGTERM or SIGINT, then
writes FILE.
"""

import argparse
import collections
import datetime
import email.utils
import hashlib
import http.server
import json
import os
import re
import signal
import ssl
import sys
import threading
import urllib.parse
import xml.sax.saxutils

REGION = "us-east-1"
OWNER_ID = "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
CREATED = datetime.datetime(2026, 11, 18, tzinfo=datetime.timezone.utc)
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"

# Header values that differ on every call. The placeholder keeps the shape.
VOLATILE = {
    "x-amz-date": "<amz-date>",
    "amz-sdk-invocation-id": "<uuid>",
    "x-amz-security-token": "<token>",
    "date": "<date>",
    "x-amz-meta-mtime": "<epoch-seconds>",  # rclone's file modification time
}
AUTH_RE = re.compile(r"Signature=[0-9a-f]+")
CRED_DATE_RE = re.compile(r"(Credential=[^/,]+)/\d{8}/")
# Query-string authentication: SigV4 (X-Amz-*) and SigV2 (Signature, Expires).
PRESIGN_VOLATILE = {"X-Amz-Signature": "<hex>", "X-Amz-Date": "<amz-date>",
                    "Signature": "<base64>", "Expires": "<epoch>"}


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def esc(s):
    return xml.sax.saxutils.escape(s)


def md5_etag(data):
    return '"' + hashlib.md5(data, usedforsecurity=False).hexdigest() + '"'


class Store:
    """Buckets, objects and multipart uploads in memory."""

    def __init__(self):
        self.lock = threading.Lock()
        self.buckets = {}  # name -> {key: (bytes, etag, content type)}
        self.uploads = {}  # upload id -> (bucket, key, {part: (bytes, etag)})
        self.next_upload = 1


# --- operation identification -------------------------------------------------

def classify(method, bucket, key, query, headers):
    """The model operation for a request, as the gateway's router will
    decide it. Unknown combinations give None."""
    # x-id names the operation (aws-sdk-go-v2 and the JS SDK add it); it
    # never decides the route, as on S3.
    q = set(query) - {"x-id"}
    copy = "x-amz-copy-source" in headers
    if not bucket:
        return "ListBuckets" if method == "GET" else None
    if not key:
        bucket_subresources = {
            "location": "GetBucketLocation", "versioning": "GetBucketVersioning",
            "uploads": "ListMultipartUploads", "versions": "ListObjectVersions",
            "policy": "GetBucketPolicy", "acl": "GetBucketAcl", "tagging": "GetBucketTagging",
            "encryption": "GetBucketEncryption", "cors": "GetBucketCors",
            "lifecycle": "GetBucketLifecycleConfiguration",
            "object-lock": "GetObjectLockConfiguration",
            "ownershipControls": "GetBucketOwnershipControls",
            "publicAccessBlock": "GetPublicAccessBlock",
        }
        if method == "GET":
            for sub, op in bucket_subresources.items():
                if sub in q:
                    return op
            return "ListObjectsV2" if query.get("list-type") == "2" else "ListObjects"
        if method == "HEAD":
            return "HeadBucket"
        if method == "PUT":
            return "CreateBucket" if not q else None
        if method == "DELETE":
            return "DeleteBucket" if not q else None
        if method == "POST" and "delete" in q:
            return "DeleteObjects"
        return None
    if method == "PUT":
        if "partNumber" in q and "uploadId" in q:
            return "UploadPartCopy" if copy else "UploadPart"
        if "tagging" in q:
            return "PutObjectTagging"
        if not q:
            return "CopyObject" if copy else "PutObject"
        return None
    if method == "POST":
        if "uploads" in q:
            return "CreateMultipartUpload"
        if "uploadId" in q:
            return "CompleteMultipartUpload"
        return None
    if method == "GET":
        if "uploadId" in q:
            return "ListParts"
        if "tagging" in q:
            return "GetObjectTagging"
        if "attributes" in q:
            return "GetObjectAttributes"
        return "GetObject"
    if method == "HEAD":
        return "HeadObject"
    if method == "DELETE":
        return "AbortMultipartUpload" if "uploadId" in q else "DeleteObject"
    return None


# --- bodies ---------------------------------------------------------------------

def read_http_body(handler):
    """The request body as sent, undoing HTTP/1.1 chunked transfer coding
    (which some clients add on top of aws-chunked). Returns (bytes, how)."""
    te = (handler.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in te:
        out = bytearray()
        while True:
            line = handler.rfile.readline()
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            if size == 0:
                while handler.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
                break
            out += handler.rfile.read(size)
            handler.rfile.readline()
        return bytes(out), "transfer-encoding: chunked"
    length = int(handler.headers.get("Content-Length", "0") or 0)
    return (handler.rfile.read(length) if length else b""), "content-length"


def decode_aws_chunked(raw):
    """Undo the aws-chunked content coding. Returns (payload, framing)."""
    payload = bytearray()
    sizes = []
    signed = False
    pos = 0
    trailers = []
    trailer_signed = False
    while True:
        end = raw.index(b"\r\n", pos)
        header = raw[pos:end].decode("ascii")
        pos = end + 2
        size_hex, _, ext = header.partition(";")
        size = int(size_hex, 16)
        if ext.startswith("chunk-signature="):
            signed = True
        sizes.append(size)
        if size == 0:
            break
        payload += raw[pos:pos + size]
        pos += size + 2
    for line in raw[pos:].split(b"\r\n"):
        if not line:
            continue
        name = line.split(b":", 1)[0].decode("ascii").strip().lower()
        if name == "x-amz-trailer-signature":
            trailer_signed = True
        else:
            trailers.append(name)
    # Chunk sizes as runs, so a 20 MiB upload does not list 2,560 entries.
    runs = []
    for size in sizes:
        if runs and runs[-1][0] == size:
            runs[-1][1] += 1
        else:
            runs.append([size, 1])
    framing = {
        "chunk_sizes": [{"size": s, "count": c} for s, c in runs],
        "chunks_signed": signed,
        "trailers": trailers,
        "trailer_signed": trailer_signed,
    }
    return bytes(payload), framing


def body_record(raw, headers, op, transfer):
    """What the evidence keeps of a request body."""
    if not raw:
        return None
    encoding = headers.get("content-encoding", "")
    sha_mode = headers.get("x-amz-content-sha256", "")
    framing = None
    payload = raw
    if "aws-chunked" in encoding or sha_mode.startswith("STREAMING-"):
        payload, framing = decode_aws_chunked(raw)
    record = {"transfer": transfer}
    if op in ("PutObject", "UploadPart"):
        record.update({"kind": "object", "length": len(payload),
                       "sha256": hashlib.sha256(payload).hexdigest()})
    else:
        text = payload.decode("utf-8", "replace")
        record.update({"kind": "xml", "text": text})
    if framing is not None:
        record["aws_chunked"] = framing
        record["encoded_length"] = len(raw)
    return record, payload


# --- normalisation ---------------------------------------------------------------

def normalise_headers(items, port):
    out = []
    for name, value in items:
        low = name.lower()
        if low in VOLATILE:
            value = VOLATILE[low]
        elif low == "authorization":
            value = CRED_DATE_RE.sub(r"\1/<yyyymmdd>/", AUTH_RE.sub("Signature=<hex>", value))
        elif low == "host":
            value = value.replace(f":{port}", ":<port>")
        elif low == "user-agent":
            value = re.sub(r"os/(linux|Linux)#\S+", r"os/\1#<kernel>", value)
            value = re.sub(r"Linux/\S+", "Linux/<kernel>", value)
            value = value.replace(os.uname().release, "<kernel>")
            # The SDKs' feature-metrics list (m/A,B,...) is a set printed in
            # no fixed order.
            value = re.sub(r"\bm/([A-Za-z0-9,+-]+)",
                           lambda m: "m/" + ",".join(sorted(m.group(1).split(","))), value)
        elif low == "x-amz-content-sha256" and re.fullmatch(r"[0-9a-f]{64}", value):
            value = "<sha256-hex>"
        out.append([name, value])
    return out


def normalise_target(target):
    path, _, query = target.partition("?")
    if not query:
        return target
    parts = []
    for item in query.split("&"):
        k, eq, v = item.partition("=")
        if k in PRESIGN_VOLATILE:
            v = PRESIGN_VOLATILE[k]
        elif k == "X-Amz-Credential":
            v = re.sub(r"%2F\d{8}%2F", "%2F<yyyymmdd>%2F", v)
        parts.append(k + eq + v)
    return path + "?" + "&".join(parts)


# --- the stub --------------------------------------------------------------------

def xml_doc(root, inner):
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<{root} xmlns="{S3_NS}">{inner}</{root}>').encode()


def error(status, code, message):
    body = (f'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>{code}</Code>'
            f"<Message>{esc(message)}</Message><RequestId>0000000000000000</RequestId>"
            f"<HostId>evidence</HostId></Error>").encode()
    return status, {"Content-Type": "application/xml"}, body


def list_entries(objects, query, v2):
    prefix = query.get("prefix", "")
    delim = query.get("delimiter", "")
    url = query.get("encoding-type") == "url"
    start = query.get("start-after", "") if v2 else query.get("marker", "")

    def enc(s):
        return urllib.parse.quote(s, safe="/") if url else esc(s)

    keys, prefixes = [], []
    for key in sorted(objects):
        if not key.startswith(prefix) or key <= start:
            continue
        rest = key[len(prefix):]
        if delim and delim in rest:
            p = prefix + rest.split(delim, 1)[0] + delim
            if p not in prefixes:
                prefixes.append(p)
            continue
        keys.append(key)
    contents = "".join(
        f"<Contents><Key>{enc(k)}</Key><LastModified>{iso(CREATED)}</LastModified>"
        f"<ETag>{esc(objects[k][1])}</ETag><Size>{len(objects[k][0])}</Size>"
        f"<StorageClass>STANDARD</StorageClass></Contents>" for k in keys)
    common = "".join(f"<CommonPrefixes><Prefix>{enc(p)}</Prefix></CommonPrefixes>"
                     for p in prefixes)
    head = (f"<Prefix>{enc(prefix)}</Prefix><MaxKeys>1000</MaxKeys>"
            f"<IsTruncated>false</IsTruncated>")
    if delim:
        head += f"<Delimiter>{enc(delim)}</Delimiter>"
    if url:
        head += "<EncodingType>url</EncodingType>"
    if v2:
        head += f"<KeyCount>{len(keys) + len(prefixes)}</KeyCount>"
    return head + contents + common


def handle(store, op, bucket, key, query, headers, payload):  # noqa: C901 (one switch)
    """Answer one request. Returns (status, headers, body)."""
    with store.lock:
        objects = store.buckets.get(bucket)
        if op == "ListBuckets":
            inner = "".join(f"<Bucket><Name>{esc(b)}</Name><CreationDate>{iso(CREATED)}"
                            "</CreationDate></Bucket>" for b in sorted(store.buckets))
            return 200, {}, xml_doc("ListAllMyBucketsResult",
                                    f"<Owner><ID>{OWNER_ID}</ID></Owner><Buckets>{inner}"
                                    "</Buckets>")
        if op == "CreateBucket":
            store.buckets.setdefault(bucket, {})
            return 200, {"Location": f"/{bucket}"}, b""
        if objects is None:
            return error(404, "NoSuchBucket", "The specified bucket does not exist")
        if op == "HeadBucket":
            return 200, {"x-amz-bucket-region": REGION}, b""
        if op == "GetBucketVersioning":
            # Never enabled: the bucket is unversioned (rclone asks before purge).
            return 200, {}, xml_doc("VersioningConfiguration", "")
        if op == "GetBucketLocation":
            return 200, {}, xml_doc("LocationConstraint", "")
        if op == "DeleteBucket":
            if objects:
                return error(409, "BucketNotEmpty", "The bucket you tried to delete is not empty")
            del store.buckets[bucket]
            return 204, {}, b""
        if op in ("ListObjectsV2", "ListObjects"):
            inner = f"<Name>{esc(bucket)}</Name>" + list_entries(objects, query,
                                                                  op == "ListObjectsV2")
            return 200, {}, xml_doc("ListBucketResult", inner)
        if op == "PutObject":
            etag = md5_etag(payload)
            objects[key] = (payload, etag, headers.get("content-type",
                                                       "binary/octet-stream"))
            echo = {k: v for k, v in headers.items() if k.startswith("x-amz-checksum-")}
            return 200, {"ETag": etag, **echo}, b""
        if op == "CopyObject":
            src = urllib.parse.unquote(headers["x-amz-copy-source"].split("?")[0]).lstrip("/")
            sb, _, sk = src.partition("/")
            data = store.buckets.get(sb, {}).get(sk)
            if data is None:
                return error(404, "NoSuchKey", "The specified key does not exist.")
            objects[key] = data
            return 200, {}, xml_doc("CopyObjectResult",
                                    f"<LastModified>{iso(CREATED)}</LastModified>"
                                    f"<ETag>{esc(data[1])}</ETag>")
        if op in ("GetObject", "HeadObject"):
            data = objects.get(key)
            if data is None:
                if op == "HeadObject":
                    return 404, {}, b""
                return error(404, "NoSuchKey", "The specified key does not exist.")
            body, etag, ctype = data
            out = {"ETag": etag, "Content-Type": ctype, "Accept-Ranges": "bytes",
                   "Last-Modified": email.utils.format_datetime(CREATED, usegmt=True)}
            rng = headers.get("range", "")
            m = re.fullmatch(r"bytes=(\d+)-(\d*)", rng)
            if m:
                first = int(m.group(1))
                last = min(int(m.group(2)) if m.group(2) else len(body) - 1, len(body) - 1)
                out["Content-Range"] = f"bytes {first}-{last}/{len(body)}"
                return 206, out, body[first:last + 1]
            return 200, out, body
        if op == "DeleteObject":
            objects.pop(key, None)
            return 204, {}, b""
        if op == "DeleteObjects":
            keys = re.findall(r"<Key>(.*?)</Key>", payload.decode())
            inner = ""
            for k in keys:
                k = xml.sax.saxutils.unescape(k)
                objects.pop(k, None)
                inner += f"<Deleted><Key>{esc(k)}</Key></Deleted>"
            return 200, {}, xml_doc("DeleteResult", inner)
        if op == "CreateMultipartUpload":
            upload = f"evidence-upload-{store.next_upload:04d}"
            store.next_upload += 1
            store.uploads[upload] = (bucket, key, {})
            return 200, {}, xml_doc("InitiateMultipartUploadResult",
                                    f"<Bucket>{esc(bucket)}</Bucket><Key>{esc(key)}</Key>"
                                    f"<UploadId>{upload}</UploadId>")
        upload = store.uploads.get(query.get("uploadId", ""))
        if op in ("UploadPart", "UploadPartCopy", "CompleteMultipartUpload",
                  "AbortMultipartUpload", "ListParts") and upload is None:
            return error(404, "NoSuchUpload", "The specified upload does not exist.")
        if op == "UploadPart":
            etag = md5_etag(payload)
            upload[2][int(query["partNumber"])] = (payload, etag)
            echo = {k: v for k, v in headers.items() if k.startswith("x-amz-checksum-")}
            return 200, {"ETag": etag, **echo}, b""
        if op == "ListParts":
            inner = "".join(f"<Part><PartNumber>{n}</PartNumber><ETag>{esc(e)}</ETag>"
                            f"<Size>{len(d)}</Size></Part>"
                            for n, (d, e) in sorted(upload[2].items()))
            return 200, {}, xml_doc("ListPartsResult",
                                    f"<Bucket>{esc(bucket)}</Bucket><Key>{esc(key)}</Key>"
                                    f"<UploadId>{query['uploadId']}</UploadId>"
                                    f"<IsTruncated>false</IsTruncated>{inner}")
        if op == "CompleteMultipartUpload":
            numbers = [int(n) for n in re.findall(r"<PartNumber>(\d+)</PartNumber>",
                                                  payload.decode())]
            parts = upload[2]
            data = b"".join(parts[n][0] for n in numbers)
            digest = hashlib.md5(b"".join(
                bytes.fromhex(parts[n][1].strip('"')) for n in numbers),
                usedforsecurity=False).hexdigest()
            etag = f'"{digest}-{len(numbers)}"'
            objects[key] = (data, etag, "binary/octet-stream")
            del store.uploads[query["uploadId"]]
            return 200, {}, xml_doc("CompleteMultipartUploadResult",
                                    f"<Location>/{esc(bucket)}/{esc(key)}</Location>"
                                    f"<Bucket>{esc(bucket)}</Bucket><Key>{esc(key)}</Key>"
                                    f"<ETag>{esc(etag)}</ETag>")
        if op == "AbortMultipartUpload":
            del store.uploads[query["uploadId"]]
            return 204, {}, b""
        if op == "ListMultipartUploads":
            inner = "".join(f"<Upload><Key>{esc(k)}</Key><UploadId>{u}</UploadId>"
                            f"<Initiated>{iso(CREATED)}</Initiated></Upload>"
                            for u, (b, k, _) in sorted(store.uploads.items()) if b == bucket)
            return 200, {}, xml_doc("ListMultipartUploadsResult",
                                    f"<Bucket>{esc(bucket)}</Bucket>"
                                    f"<IsTruncated>false</IsTruncated>{inner}")
    return error(501, "NotImplemented",
                 "A header you provided implies functionality that is not implemented")


class Recorder:
    def __init__(self, client, domain):
        self.client = client
        self.domain = domain
        self.entries = []
        self.lock = threading.Lock()
        self.store = Store()
        self.done = threading.Event()
        self.port = 0

    def record(self, entry):
        with self.lock:
            self.entries.append(entry)

    def document(self):
        def distinct(field):
            return sorted({str(e[field]) for e in self.entries if e.get(field) is not None})

        framings = collections.Counter()
        for e in self.entries:
            body = e.get("body") or {}
            if body.get("kind") == "object":
                f = body.get("aws_chunked")
                framings[json.dumps({
                    "x-amz-content-sha256": e["content_sha256"],
                    "aws_chunked": bool(f),
                    "chunks_signed": bool(f and f["chunks_signed"]),
                    "trailers": f["trailers"] if f else [],
                    "transfer": body["transfer"],
                }, sort_keys=True)] += 1
        return {
            "client": self.client,
            "requests": self.entries,
            "summary": {
                "operations": [e["operation"] for e in self.entries],
                "addressing": sorted(set(distinct("addressing")) - {"service"}),
                "content_sha256": distinct("content_sha256"),
                "http_versions": distinct("http_version"),
                "expect_continue": distinct("expect_continue"),
                "object_uploads": [dict(json.loads(k), requests=n)
                                   for k, n in sorted(framings.items())],
            },
        }


def content_sha256_class(value):
    if not value:
        return "absent"
    if re.fullmatch(r"[0-9a-f]{64}", value) or value == "<sha256-hex>":
        return "hex"
    return value


def make_handler(rec):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def dispatch(self):
            # http.server has already answered 100 Continue by now; the
            # evidence is whether the client asked for it.
            self.expect_continue = (self.headers.get("Expect") or "").lower() == "100-continue"
            raw, transfer = read_http_body(self)
            headers = {k.lower(): v for k, v in self.headers.items()}
            host = headers.get("host", "").split(":")[0]
            path, _, qs = self.path.partition("?")
            query = dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))
            segs = urllib.parse.unquote(path).lstrip("/")
            if host.endswith("." + rec.domain):
                addressing = "virtual-hosted"
                bucket = host[: -len(rec.domain) - 1]
                key = segs
            else:
                addressing = "path"
                bucket, _, key = segs.partition("/")
            if not bucket:
                addressing = "service"  # ListBuckets names no bucket
            op = classify(self.command, bucket, key, query, headers)
            got = body_record(raw, headers, op, transfer)
            body, payload = got if got else (None, b"")
            status, out_headers, out_body = handle(
                rec.store, op, bucket, key, query, headers, payload) if op else error(
                501, "NotImplemented", "not scripted")
            rec.record({
                "operation": op or "<unrouted>",
                "method": self.command,
                "target": normalise_target(self.path),
                "addressing": addressing,
                "http_version": self.request_version,
                "expect_continue": self.expect_continue,
                "content_sha256": content_sha256_class(headers.get("x-amz-content-sha256")),
                "headers": normalise_headers(self.headers.items(), rec.port),
                "body": body,
                "response_status": status,
            })
            self.send_response(status)
            out_headers.setdefault("x-amz-request-id", "0000000000000000")
            for k, v in out_headers.items():
                self.send_header(k, v)
            if out_body and "Content-Type" not in out_headers:
                self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(out_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(out_body)

        do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = dispatch  # noqa: N815

    return Handler


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Clients close idle keep-alive connections however they like.
        if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--client", required=True)
    ap.add_argument("--domain", default="s3.kythira.test",
                    help="the endpoint's host name; <bucket>.<domain> is virtual-hosted")
    ap.add_argument("--bucket", action="append", default=[],
                    help="a bucket that exists from the start (Mountpoint mounts one)")
    ap.add_argument("--tls-cert", required=True)
    ap.add_argument("--tls-key", required=True)
    args = ap.parse_args()
    rec = Recorder(args.client, args.domain)
    for name in args.bucket:
        rec.store.buckets[name] = {}
    srv = Server(("127.0.0.1", args.port), make_handler(rec))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.tls_cert, args.tls_key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    rec.port = srv.server_address[1]
    print(rec.port, flush=True)
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
