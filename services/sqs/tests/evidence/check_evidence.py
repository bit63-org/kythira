#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Check the checked-in wire evidence (ctest sqs_wire_evidence).

Every file in data/ must name its client, record only operations the pinned
model has, show its scenario finishing (every request answered 200 except
the errors the scenario provokes on purpose, listed below), use only the
protocol README.md lists for it, and be normalised. A hand edit or a stale
file that breaks any of that fails.

    check_evidence.py MODEL DATA_DIR
"""

import json
import pathlib
import sys

JSON = "application/x-amz-json-1.0"
QUERY = "application/x-www-form-urlencoded"

# file: (protocol, errors the scenario asks for, in order, as (operation, type))
MISSING = ("GetQueueUrl", "QueueDoesNotExist")
EXPECTED = {
    "awscli-v2.json": (JSON, []),
    "boto3.json": (JSON, [MISSING]),
    "boto3-query.json": (QUERY, [MISSING]),
    "java-sdk-v2.json": (JSON, [MISSING]),
    # The messaging library asks GetQueueUrl whether the queue exists first.
    "jms.json": (JSON, [MISSING]),
    "kombu.json": (JSON, []),
}
VOLATILE_HEADERS = {"x-amz-date", "amz-sdk-invocation-id"}


def check(model_ops, path):
    problems = []
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not doc.get("client"):
        problems.append("no client name")
    reqs = doc.get("requests", [])
    if not reqs:
        problems.append("no requests recorded")
    want = EXPECTED.get(path.name)
    if want is None:
        return problems + ["not listed in check_evidence.py's EXPECTED table"]
    protocol, wanted_errors = want
    errors = []
    for i, r in enumerate(reqs):
        op = r.get("operation", "")
        if op not in model_ops:
            problems.append(f"request {i}: {op!r} is not in the pinned model")
        if r.get("response_status") != 200:
            errors.append((op, str(r.get("response_type") or "").rsplit("#", 1)[-1]))
        if r.get("content_type") != protocol:
            problems.append(f"request {i}: content type {r.get('content_type')!r} != {protocol}")
        if protocol == QUERY and not r.get("form"):
            problems.append(f"request {i}: a query request without its form parameters")
        for name, value in r.get("headers", []):
            low = name.lower()
            if low in VOLATILE_HEADERS and not value.startswith("<"):
                problems.append(f"request {i}: header {name} was not normalised")
            if low == "authorization" and "Signature=<hex>" not in value:
                problems.append(f"request {i}: signature was not normalised")
            if low == "host" and not value.endswith(":<port>"):
                problems.append(f"request {i}: host port was not normalised")
    if errors != wanted_errors:
        problems.append(f"errors {errors} != the scenario's {wanted_errors}, so it did not "
                        "run as scripted")
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
