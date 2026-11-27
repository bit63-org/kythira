#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""s3_gateway_node end to end (.kiro/specs/s3-compatible-storage/ task 16).

Starts the daemon and talks S3 to it over HTTP with SigV4 signed here
(standard library only, so the test needs no SDK):

  co-located  one node with every role: buckets, objects (HEAD keeps the
              object's Content-Length), listings, and a static website on
              the website listener.
  split       a metadata node (metadata,blobs) behind a front end
              (gateway,front_end) over the internal mutual-TLS listener,
              with certificates carrying layer identities; the same
              requests through the front end, a caller whose identity has
              the wrong role refused on the metadata route, and a front end
              whose metadata node is gone answering 503.

The split layout needs the openssl command to make its certificates and is
skipped (with a message) without it.

usage: s3_gateway_node_test.py <path to s3_gateway_node>
"""

import base64
import datetime
import hashlib
import hmac
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse

ACCESS_KEY = "AKIDS3NODETEST"
REGION = "us-east-1"
DOMAIN = "s3.kythira.test"
WEBSITE_DOMAIN = "s3-website.kythira.test"


def secret_key() -> str:
    # Built at run time: test material, not a credential.
    return "".join(chr(ord("a") + (i * 7) % 26) for i in range(24))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sign(method, path, query, headers, body):
    """Adds SigV4 headers for s3 to `headers` (a dict) in place."""
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    headers["x-amz-date"] = amz_date
    headers["x-amz-content-sha256"] = hashlib.sha256(body).hexdigest()
    names = sorted(k.lower() for k in headers)
    canonical_headers = "".join(
        f"{n}:{str(next(v for k, v in headers.items() if k.lower() == n)).strip()}\n"
        for n in names
    )
    signed = ";".join(names)
    pairs = sorted(urllib.parse.parse_qsl(query, keep_blank_values=True))
    canonical_query = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in pairs
    )
    canonical = "\n".join(
        [method, path, canonical_query, canonical_headers, signed,
         headers["x-amz-content-sha256"]]
    )
    scope = f"{date}/{REGION}/s3/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope,
         hashlib.sha256(canonical.encode()).hexdigest()]
    )
    key = ("AWS4" + secret_key()).encode()
    for part in (date, REGION, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, "
        f"SignedHeaders={signed}, Signature={sig}"
    )


def request(port, method, target, body=b"", headers=None, signed=True, host=None):
    headers = dict(headers or {})
    headers["Host"] = host or f"127.0.0.1:{port}"
    path, _, query = target.partition("?")
    if body and query:
        # Configuration documents carry their MD5, as S3 requires of most.
        headers["Content-MD5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
    if signed:
        sign(method, path, query, headers, body)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(method, target, body=body, headers=headers)
        res = conn.getresponse()
        data = res.read()
        return res.status, {k.lower(): v for k, v in res.getheaders()}, data
    finally:
        conn.close()


def wait_for(port, proc, what):
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{what} exited with {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{what} did not listen on {port}")


class Failure(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Failure(what)
    print(f"  ok: {what}")


def start(binary, env, log_path):
    full = {k: v for k, v in os.environ.items() if not k.startswith("KYTHIRA_S3_")}
    full.update(env)
    log = open(log_path, "wb")
    return subprocess.Popen([binary], env=full, stdout=log, stderr=subprocess.STDOUT)


def object_round_trip(port, bucket):
    status, _, _ = request(port, "PUT", f"/{bucket}")
    check(status == 200, f"CreateBucket {bucket}")
    payload = os.urandom(300_000)
    status, h, _ = request(port, "PUT", f"/{bucket}/dir/a%20key.bin", payload)
    check(status == 200 and h.get("etag", "").strip('"') == hashlib.md5(payload).hexdigest(),
          "PutObject answers the body's MD5 as its ETag")
    status, h, data = request(port, "HEAD", f"/{bucket}/dir/a%20key.bin")
    check(status == 200 and h.get("content-length") == str(len(payload)) and data == b"",
          "HeadObject keeps the object's Content-Length")
    status, _, data = request(port, "GET", f"/{bucket}/dir/a%20key.bin")
    check(status == 200 and data == payload, "GetObject returns the bytes")
    status, _, data = request(port, "GET", f"/{bucket}/dir/a%20key.bin",
                              headers={"Range": "bytes=10-19"})
    check(status == 206 and data == payload[10:20], "a ranged GetObject returns the range")
    status, _, data = request(port, "GET", f"/{bucket}?list-type=2&prefix=dir%2F")
    check(status == 200 and b"<Key>dir/a key.bin</Key>" in data, "ListObjectsV2 lists the key")
    status, _, data = request(port, "GET", f"/{bucket}/missing")
    check(status == 404 and b"<Code>NoSuchKey</Code>" in data, "a missing key is NoSuchKey")
    status, _, data = request(port, "GET", f"/{bucket}/dir/a%20key.bin", signed=False)
    check(status == 403, "an anonymous read of a private object is refused")


def website(port, website_port, bucket):
    status, _, _ = request(port, "PUT", f"/{bucket}")
    check(status == 200, f"CreateBucket {bucket}")
    status, _, _ = request(
        port, "PUT", f"/{bucket}?ownershipControls",
        b"<OwnershipControls><Rule><ObjectOwnership>ObjectWriter</ObjectOwnership></Rule>"
        b"</OwnershipControls>")
    check(status == 200, "PutBucketOwnershipControls ObjectWriter")
    status, _, _ = request(port, "DELETE", f"/{bucket}?publicAccessBlock")
    check(status == 204, "DeletePublicAccessBlock")
    page = b"<html>hello from kythira</html>"
    status, _, _ = request(port, "PUT", f"/{bucket}/index.html", page,
                           {"x-amz-acl": "public-read", "Content-Type": "text/html"})
    check(status == 200, "PutObject index.html, public-read")
    config = (b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix>"
              b"</IndexDocument></WebsiteConfiguration>")
    status, _, data = request(port, "PUT", f"/{bucket}?website", config)
    check(status == 200, f"PutBucketWebsite ({data[:200]!r})")
    status, h, data = request(website_port, "GET", "/", signed=False,
                              host=f"{bucket}.{WEBSITE_DOMAIN}:{website_port}")
    check(status == 200 and data == page and h.get("content-type") == "text/html",
          "the website endpoint serves the index document")
    status, _, data = request(website_port, "GET", "/nothing-here", signed=False,
                              host=f"{bucket}.{WEBSITE_DOMAIN}:{website_port}")
    check(status in (403, 404) and b"<html>" in data.lower(),
          "a missing page is S3's HTML error page")


def keys_file(work):
    path = os.path.join(work, "keys")
    with open(path, "w") as f:
        f.write(f"{ACCESS_KEY} {secret_key()} 111122223333 tester admin\n")
    return path


def colocated(binary, work):
    print("co-located")
    port, website_port = free_port(), free_port()
    env = {
        "KYTHIRA_S3_LISTEN": f"127.0.0.1:{port}",
        "KYTHIRA_S3_INSECURE_PLAINTEXT": "1",
        "KYTHIRA_S3_DOMAINS": DOMAIN,
        "KYTHIRA_S3_WEBSITE_LISTEN": f"127.0.0.1:{website_port}",
        "KYTHIRA_S3_WEBSITE_DOMAINS": WEBSITE_DOMAIN,
        "KYTHIRA_S3_STATIC_KEYS_FILE": keys_file(work),
        "KYTHIRA_S3_DATA_DIR": os.path.join(work, "colocated"),
    }
    proc = start(binary, env, os.path.join(work, "colocated.log"))
    try:
        wait_for(port, proc, "the co-located node")
        wait_for(website_port, proc, "the website listener")
        object_round_trip(port, "colocated")
        website(port, website_port, "site")
    finally:
        proc.terminate()
        code = proc.wait(timeout=30)
    check(code == 0, "the node stops cleanly on SIGTERM")


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_certs(work):
    """A CA and one certificate per layer identity, valid for 127.0.0.1."""
    d = os.path.join(work, "pki")
    os.makedirs(d)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=test-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)
    certs = {}
    for name, roles in (("meta", "data,segments"), ("front", "gateway,front_end"),
                        ("gw", "gateway")):
        node_id = name
        uri = f"kythira://s3/test/{node_id}?roles={roles}"
        with open(os.path.join(d, f"{name}.ext"), "w") as f:
            # A section, since the roles' commas would split an inline list.
            f.write("subjectAltName=@alt\n"
                    "extendedKeyUsage=serverAuth,clientAuth\n"
                    f"[alt]\nIP.1=127.0.0.1\nURI.1={uri}\n")
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}", cwd=d)
        openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", f"{name}.pem", "-days", "2",
                "-extfile", f"{name}.ext", cwd=d)
        certs[name] = (os.path.join(d, f"{name}.pem"), os.path.join(d, f"{name}.key"))
    return os.path.join(d, "ca.pem"), certs


def internal_call(port, ca, cert, path):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert[0], cert[1])
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=30)
    try:
        conn.request("POST", path, body=b"\x01\x00\x00\x00\x00")
        res = conn.getresponse()
        return res.status, res.read()
    finally:
        conn.close()


def split(binary, work):
    print("split: metadata,blobs behind gateway,front_end")
    if shutil.which("openssl") is None:
        print("  skipped: no openssl command to make layer identity certificates")
        return
    ca, certs = make_certs(work)
    keys = keys_file(work)
    internal = free_port()
    meta_env = {
        "KYTHIRA_S3_ROLES": "metadata,blobs",
        "KYTHIRA_S3_NODE_ID": "meta",
        "KYTHIRA_S3_CLUSTER": "test",
        "KYTHIRA_S3_INTERNAL_LISTEN": f"127.0.0.1:{internal}",
        "KYTHIRA_S3_INTERNAL_TLS_CERT": certs["meta"][0],
        "KYTHIRA_S3_INTERNAL_TLS_KEY": certs["meta"][1],
        "KYTHIRA_S3_INTERNAL_TLS_CA": ca,
        "KYTHIRA_S3_DATA_DIR": os.path.join(work, "meta"),
    }
    port = free_port()
    front_env = {
        "KYTHIRA_S3_ROLES": "gateway,front_end",
        "KYTHIRA_S3_NODE_ID": "front",
        "KYTHIRA_S3_CLUSTER": "test",
        "KYTHIRA_S3_LISTEN": f"127.0.0.1:{port}",
        "KYTHIRA_S3_INSECURE_PLAINTEXT": "1",
        "KYTHIRA_S3_STATIC_KEYS_FILE": keys,
        "KYTHIRA_S3_METADATA_ENDPOINTS": f"meta=https://127.0.0.1:{internal}",
        "KYTHIRA_S3_INTERNAL_TLS_CERT": certs["front"][0],
        "KYTHIRA_S3_INTERNAL_TLS_KEY": certs["front"][1],
        "KYTHIRA_S3_INTERNAL_TLS_CA": ca,
        "KYTHIRA_S3_DATA_DIR": os.path.join(work, "front"),
    }
    meta = start(binary, meta_env, os.path.join(work, "meta.log"))
    front = None
    try:
        wait_for(internal, meta, "the metadata node")
        front = start(binary, front_env, os.path.join(work, "front.log"))
        wait_for(port, front, "the front end")
        object_round_trip(port, "split")
        status, _ = internal_call(internal, ca, certs["gw"],
                                  "/_kythira/s3/metadata/v1/list_buckets")
        check(status == 403, "a gateway identity may not call the metadata routes")
        status, _ = internal_call(internal, ca, certs["front"],
                                  "/_kythira/s3/metadata/v1/list_buckets")
        check(status == 200, "a front-end identity may")
        meta.terminate()
        meta.wait(timeout=30)
        status, _, data = request(port, "GET", "/split?list-type=2")
        check(status == 503 and b"<Code>ServiceUnavailable</Code>" in data,
              "with its metadata node gone the front end answers 503 ServiceUnavailable")
    finally:
        for p in (front, meta):
            if p is not None and p.poll() is None:
                p.terminate()
                p.wait(timeout=30)


def refused_layouts(binary, work):
    print("layouts refused at start")
    for env, needle in (
        ({"KYTHIRA_S3_ROLES": "gateway"}, b"task 17"),
        ({"KYTHIRA_S3_ROLES": "front_end", "KYTHIRA_S3_INSECURE_PLAINTEXT": "1"},
         b"KYTHIRA_S3_METADATA_ENDPOINTS"),
        ({"KYTHIRA_S3_ROLES": "metadata"}, b"task 18"),
        ({"KYTHIRA_S3_ROLES": "storage"}, b"unknown S3 role"),
    ):
        full = {k: v for k, v in os.environ.items() if not k.startswith("KYTHIRA_S3_")}
        full.update(env)
        res = subprocess.run([binary], env=full, capture_output=True, timeout=30)
        check(res.returncode == 2 and needle in res.stderr,
              f"KYTHIRA_S3_ROLES={env['KYTHIRA_S3_ROLES']} stops with a reason")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    binary = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="s3-node-test-")
    try:
        refused_layouts(binary, work)
        colocated(binary, work)
        split(binary, work)
    except (Failure, RuntimeError, OSError, subprocess.SubprocessError) as e:
        print(f"FAILED: {e}")
        for name in sorted(os.listdir(work)):
            if name.endswith(".log"):
                print(f"--- {name}")
                with open(os.path.join(work, name), "rb") as f:
                    sys.stdout.write(f.read().decode(errors="replace")[-4000:])
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
