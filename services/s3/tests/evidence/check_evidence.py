#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Check the checked-in S3 wire evidence (ctest s3_wire_evidence).

Every file in data/ must name its client, record only operations the
pinned model has, show its scenario finishing (every request answered 2xx,
except a HeadObject probe for a key that is not there yet), keep no
unnormalised signature or date, and match the claims README.md makes for
it: addressing style, how object bodies are signed and framed, and which
checksum trailer they carry. A hand edit, a stale file or a re-recording
whose behaviour changed fails until README.md and EXPECTED below agree
with it.

    check_evidence.py MODEL DATA_DIR
"""

import json
import pathlib
import sys

# README.md's "What the gateway must accept" table, per file. Uploads are
# (x-amz-content-sha256, trailer names, transfer framing) of PutObject and
# UploadPart requests.
TRAILER = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
EXPECTED = {
    "aws-cli-v2.json": {
        "addressing": ["path"],
        "uploads": {(TRAILER, ("x-amz-checksum-crc64nvme",), "transfer-encoding: chunked")},
    },
    "boto3.json": {
        "addressing": ["path"],
        "uploads": {(TRAILER, ("x-amz-checksum-crc32",), "transfer-encoding: chunked"),
                    (TRAILER, ("x-amz-checksum-sha256",), "transfer-encoding: chunked")},
    },
    "java-sdk-v2.json": {
        "addressing": ["virtual-hosted"],
        "uploads": {(TRAILER, ("x-amz-checksum-crc32",), "content-length")},
    },
    "go-sdk-v2.json": {
        "addressing": ["virtual-hosted"],
        "uploads": {(TRAILER, ("x-amz-checksum-crc32",), "content-length")},
    },
    "js-sdk-v3.json": {
        "addressing": ["virtual-hosted"],
        "uploads": {("hex", (), "content-length")},
    },
    "rclone.json": {
        "addressing": ["virtual-hosted"],
        "uploads": {(TRAILER, ("x-amz-checksum-crc32",), "content-length")},
    },
    "mountpoint.json": {
        "addressing": ["virtual-hosted"],
        "uploads": {(TRAILER, ("x-amz-checksum-crc32c",), "content-length")},
    },
}
VOLATILE_HEADERS = {"x-amz-date", "amz-sdk-invocation-id", "date"}


def check(model_ops, path):
    problems = []
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not doc.get("client"):
        problems.append("no client name")
    reqs = doc.get("requests", [])
    if not reqs:
        problems.append("no requests recorded")
    uploads = set()
    for i, r in enumerate(reqs):
        op = r.get("operation", "")
        if op not in model_ops:
            problems.append(f"request {i}: {op!r} is not in the pinned model")
        status = r.get("response_status")
        probe = op == "HeadObject" and status == 404
        if not (200 <= status < 300 or probe):
            problems.append(f"request {i}: {op} was answered {status}, "
                            "so the scenario did not run as scripted")
        for name, value in r.get("headers", []):
            if name.lower() in VOLATILE_HEADERS and not value.startswith("<"):
                problems.append(f"request {i}: header {name} was not normalised")
            if name.lower() == "authorization" and "Signature=<hex>" not in value:
                problems.append(f"request {i}: signature was not normalised")
        target = r.get("target", "")
        for key in ("X-Amz-Signature=", "Signature="):
            if key in target and f"{key}<" not in target:
                problems.append(f"request {i}: query signature was not normalised")
        body = r.get("body") or {}
        if body.get("kind") == "object":
            framing = body.get("aws_chunked") or {}
            uploads.add((r.get("content_sha256"), tuple(framing.get("trailers", [])),
                         body.get("transfer")))
    want = EXPECTED.get(path.name)
    if want is None:
        problems.append("not listed in check_evidence.py's EXPECTED table")
        return problems
    addressing = doc.get("summary", {}).get("addressing")
    if addressing != want["addressing"]:
        problems.append(f"addressing {addressing} != {want['addressing']}")
    if uploads != want["uploads"]:
        problems.append(f"object uploads {sorted(uploads)} != {sorted(want['uploads'])}")
    return problems


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    model_ops = set(json.loads(pathlib.Path(sys.argv[1]).read_text())["operations"])
    data = pathlib.Path(sys.argv[2])
    failed = False
    files = sorted(data.glob("*.json"))
    for name in sorted(set(EXPECTED) - {f.name for f in files}):
        print(f"error: {name} is missing", file=sys.stderr)
        failed = True
    for f in files:
        for p in check(model_ops, f):
            print(f"error: {f.name}: {p}", file=sys.stderr)
            failed = True
    if not failed:
        print(f"{len(files)} evidence files ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
