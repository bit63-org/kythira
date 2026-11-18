#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Check the checked-in wire evidence (ctest sns_wire_evidence).

Every file in data/ must name its client, record only actions the pinned
model has, show its scenario finishing (every request answered 200), carry
the query protocol's Action and Version on every request, keep the volatile
headers normalised, and be one of the clients README.md lists.

Then the clients are compared with each other. Each request's form is
decoded the way the gateway's query codec has to decode it: `X.entry.N.key`
and `.value` (or `.Name` and `.Value...`) into a map keyed by name, and
`X.member.N...` into a list in N order, so a client that numbers map entries
differently (the Go SDK sorts them) or orders the parameters differently
still decodes to the same request. Every client must send the same sequence
of actions and, request by request, the same decoded parameters. A recording
that drifts from the shared scenario in README.md fails.

    check_evidence.py MODEL DATA_DIR
"""

import json
import pathlib
import re
import sys

FORM_CT = "application/x-www-form-urlencoded"
API_VERSION = "2010-03-31"
EXPECTED = ["awscli-v2.json", "boto3.json", "go-sdk-v2.json", "java-sdk-v2.json",
            "js-sdk-v3.json"]
VOLATILE_HEADERS = {"x-amz-date", "amz-sdk-invocation-id"}
INDEXED = re.compile(r"^(?P<head>.*?)\.(?P<kind>entry|member)\.(?P<n>[1-9][0-9]*)(?:\.(?P<rest>.+))?$")


def decode(pairs):
    """Flattened query parameters to a nested value.

    `A.member.N[.rest]` becomes a list under A, in N order; `A.entry.N.key`
    plus `.value` (attribute maps) or `.Name` plus `.Value.*` (message
    attribute maps) becomes a dict under A keyed by the name. Raises
    ValueError on a gap in the numbering or an entry without its name.
    """
    flat, groups = {}, {}
    for name, value in pairs:
        m = INDEXED.match(name)
        if not m:
            if name in flat:
                raise ValueError(f"{name} given twice")
            flat[name] = value
            continue
        groups.setdefault((m["head"], m["kind"]), {}).setdefault(int(m["n"]), []).append(
            (m["rest"] or "", value))
    for (head, kind), items in groups.items():
        if sorted(items) != list(range(1, len(items) + 1)):
            raise ValueError(f"{head}.{kind} is numbered {sorted(items)}")
        if kind == "member":
            out = []
            for n in sorted(items):
                fields = items[n]
                out.append(fields[0][1] if fields == [("", fields[0][1])] else decode(fields))
            flat[head] = out
            continue
        out = {}
        for n in sorted(items):
            fields = dict(items[n])
            key = fields.pop("key", None) or fields.pop("Name", None)
            if key is None:
                raise ValueError(f"{head}.entry.{n} has no key")
            if "value" in fields:
                out[key] = fields["value"]
            else:
                out[key] = decode([(k[len("Value."):], v) for k, v in fields.items()
                                   if k.startswith("Value.")])
        flat[head] = out
    return flat


def check(model_ops, path):
    problems = []
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not doc.get("client"):
        problems.append("no client name")
    reqs = doc.get("requests", [])
    if not reqs:
        problems.append("no requests recorded")
    decoded = []
    for i, r in enumerate(reqs):
        op = r.get("operation", "")
        if op not in model_ops:
            problems.append(f"request {i}: {op!r} is not in the pinned model")
        if r.get("response_status") != 200:
            problems.append(f"request {i}: {op} was answered {r.get('response_status')}, "
                            "so the scenario did not run as scripted")
        if r.get("content_type") != FORM_CT:
            problems.append(f"request {i}: content type {r.get('content_type')!r}")
        for name, value in r.get("headers", []):
            if name.lower() in VOLATILE_HEADERS and not value.startswith("<"):
                problems.append(f"request {i}: header {name} was not normalised")
            if name.lower() == "authorization" and "Signature=<hex>" not in value:
                problems.append(f"request {i}: signature was not normalised")
        try:
            form = decode(r.get("form", []))
        except ValueError as e:
            problems.append(f"request {i}: {e}")
            form = {}
        if form.get("Action") != op or form.get("Version") != API_VERSION:
            problems.append(f"request {i}: Action/Version are {form.get('Action')!r}/"
                            f"{form.get('Version')!r}")
        decoded.append(form)
    if path.name not in EXPECTED:
        problems.append("not listed in check_evidence.py's EXPECTED table")
    return problems, decoded


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
    decoded = {}
    for f in files:
        problems, decoded[f.name] = check(model_ops, f)
        for p in problems:
            print(f"error: {f.name}: {p}", file=sys.stderr)
            failed = True
    # Every client ran the same scenario: compare each with the first.
    if decoded:
        ref_name = sorted(decoded)[0]
        ref = decoded[ref_name]
        for name, reqs in sorted(decoded.items()):
            if [r.get("Action") for r in reqs] != [r.get("Action") for r in ref]:
                print(f"error: {name}: its actions differ from {ref_name}'s", file=sys.stderr)
                failed = True
                continue
            for i, (a, b) in enumerate(zip(ref, reqs)):
                if a != b:
                    keys = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
                    print(f"error: {name}: request {i} ({b.get('Action')}) decodes differently "
                          f"from {ref_name}'s in {keys}", file=sys.stderr)
                    failed = True
    if not failed:
        print(f"{len(files)} evidence files ok, one scenario of "
              f"{len(next(iter(decoded.values()), []))} requests")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
