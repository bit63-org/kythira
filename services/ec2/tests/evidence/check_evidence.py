#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Check the checked-in wire evidence (ctest ec2_wire_evidence).

Every file in data/ must name its client, record only actions the pinned
model has, show its scenario finishing, carry the query protocol's Action
and Version on every request, keep the volatile headers normalised, and be
one of the clients README.md lists. A request is answered 200, except the
two deliberate refusals of the scenario: a `DryRun=true` request answered
`DryRunOperation` and `CreateSecurityGroup` answered `UnsupportedOperation`.

Then the clients are compared with each other. Each request's form is
decoded the way the EC2 query codec has to decode it: a name segment that
is a positive number is a list index (`InstanceId.2`, `Filter.1.Value.2`,
`TagSpecification.2.Tag.1.Key`), so `A.N[.rest]` becomes a list under A in
N order, and the rest nests. A client that orders the parameters
differently (the Go SDK sorts them) still decodes to the same request.
Every client must send the same sequence of actions and, request by
request, the same decoded parameters. A recording that drifts from the
shared scenario in README.md fails.

    check_evidence.py MODEL DATA_DIR
"""

import json
import pathlib
import re
import sys

FORM_CT = "application/x-www-form-urlencoded"
API_VERSION = "2016-11-15"
EXPECTED = ["awscli-v2.json", "boto3.json", "go-sdk-v2.json", "java-sdk-v2.json",
            "js-sdk-v3.json"]
VOLATILE_HEADERS = {"x-amz-date", "amz-sdk-invocation-id"}
INDEX = re.compile(r"^[1-9][0-9]*$")


def decode(pairs):
    """Flattened EC2 query parameters to a nested value.

    Raises ValueError on a name given twice, a gap in a list's numbering, or
    a name that is both a value and a structure.
    """
    tree = {}
    for name, value in pairs:
        node = tree
        parts = name.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ValueError(f"{name}: a prefix is also a value")
        if parts[-1] in node:
            raise ValueError(f"{name} given twice")
        node[parts[-1]] = value
    return _lists(tree, "")


def _lists(node, path):
    if not isinstance(node, dict):
        return node
    keys = list(node)
    if keys and all(INDEX.match(k) for k in keys):
        numbers = sorted(int(k) for k in keys)
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError(f"{path or 'the form'} is numbered {numbers}")
        return [_lists(node[str(n)], f"{path}.{n}") for n in numbers]
    if any(INDEX.match(k) for k in keys):
        raise ValueError(f"{path} mixes list indices and names")
    return {k: _lists(v, f"{path}.{k}" if path else k) for k, v in node.items()}


def expected_refusal(op, form):
    """The error a request of the scenario is meant to get, or None for 200."""
    if form.get("DryRun") == "true":
        return 412, "DryRunOperation"
    if op == "CreateSecurityGroup":
        return 400, "UnsupportedOperation"
    return None


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
        refusal = expected_refusal(op, form)
        got = (r.get("response_status"), r.get("response_code"))
        if refusal is None and got[0] != 200:
            problems.append(f"request {i}: {op} was answered {got[0]}, so the scenario did "
                            "not run as scripted")
        elif refusal is not None and got != refusal:
            problems.append(f"request {i}: {op} was answered {got}, expected {refusal}")
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
