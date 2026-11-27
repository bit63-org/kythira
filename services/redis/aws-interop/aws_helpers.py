#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Helpers for the AWS interop bundle (run.sh), with botocore and boto3.

    aws_helpers.py iam-token --cache NAME --user USER --region R [--serverless]
        An ElastiCache IAM auth token, made the way the ElastiCache
        documentation builds one (the same generator
        services/iam/tests/docker/conformance/driver.py uses against
        Kythira's `auth=iam` users). Valid for 15 minutes.
    aws_helpers.py presign-put --bucket B --key K [--expires SECONDS]
        A presigned PUT URL, so the runner instance can upload its results
        without credentials of its own.
    aws_helpers.py compare-junit KYTHIRA_DIR AWS_DIR NAME
        Markdown: each client library test whose outcome differs between
        the Kythira run (redis-module.yml's artifact) and the AWS target.
    aws_helpers.py cost --started EPOCH --ended EPOCH
        Markdown: an estimate of what the run cost, from elapsed time and
        the us-east-1 on-demand prices below (Cost Explorer has the real
        figure a day later).
"""

import argparse
import pathlib
import sys
import xml.etree.ElementTree as ET
from urllib.parse import ParseResult, urlencode, urlunparse

# us-east-1 on-demand, November 2026. An estimate's inputs, not a bill.
HOURLY = {
    "ElastiCache Serverless Valkey (100 MB minimum stored)": 0.084 * 0.1,
    "ElastiCache Serverless Redis OSS (1 GB minimum stored)": 0.125,
    "MemoryDB db.t4g.small, Valkey, 1 node": 0.0336,
    "EC2 t3.small runner": 0.0208,
    "Public IPv4 address": 0.005,
}
# ECPUs: the streams and suites send well under ten million commands.
ECPU_ALLOWANCE = 10 * (0.0034 + 0.0023)


def iam_token(args):
    import botocore.session
    from botocore.model import ServiceId
    from botocore.signers import RequestSigner

    session = botocore.session.get_session()
    signer = RequestSigner(ServiceId("elasticache"), args.region, "elasticache", "v4",
                           session.get_credentials(), session.get_component("event_emitter"))
    query = {"Action": "connect", "User": args.user}
    if args.serverless:
        query["ResourceType"] = "ServerlessCache"
    url = urlunparse(ParseResult(scheme="https", netloc=args.cache, path="/",
                                 query=urlencode(query), params="", fragment=""))
    signed = signer.generate_presigned_url(
        {"method": "GET", "url": url, "body": {}, "headers": {}, "context": {}},
        operation_name="connect", expires_in=900, region_name=args.region)
    print(signed.removeprefix("https://"))


def presign_put(args):
    import boto3

    print(boto3.client("s3").generate_presigned_url(
        "put_object", Params={"Bucket": args.bucket, "Key": args.key},
        ExpiresIn=args.expires))


def outcomes(path):
    """test id -> passed / failed / skipped, from a JUnit XML file."""
    out = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        name = f"{case.get('classname', '')}::{case.get('name', '')}"
        if case.find("skipped") is not None:
            out[name] = "skipped"
        elif case.find("failure") is not None or case.find("error") is not None:
            out[name] = "failed"
        else:
            out[name] = "passed"
    return out


def compare_junit(args):
    kythira, aws = pathlib.Path(args.kythira), pathlib.Path(args.aws)
    print(f"## Client library suites: Kythira and {args.name}\n")
    for report in sorted(aws.glob("*.xml")):
        theirs = outcomes(report)
        mine_path = kythira / report.name
        if not mine_path.exists():
            print(f"- `{report.name}`: no Kythira report to compare with\n")
            continue
        mine = outcomes(mine_path)
        rows = [(t, mine.get(t, "absent"), theirs.get(t, "absent"))
                for t in sorted(set(mine) | set(theirs))
                if mine.get(t, "absent") != theirs.get(t, "absent")]
        passed = sum(1 for v in theirs.values() if v == "passed")
        print(f"### `{report.name}`: {passed} of {len(theirs)} pass on {args.name}, "
              f"{len(rows)} differ from Kythira\n")
        if rows:
            print("| test | Kythira | " + args.name + " |\n|---|---|---|")
            for t, m, a in rows:
                print(f"| `{t}` | {m} | {a} |")
            print()


def cost(args):
    hours = max(args.ended - args.started, 0) / 3600
    total = 0.0
    print(f"## Estimated cost\n\nElapsed: {hours:.2f} h (resources live at most this long).\n")
    print("| item | $/h | estimate |\n|---|---|---|")
    for item, rate in HOURLY.items():
        total += rate * hours
        print(f"| {item} | {rate:.4f} | ${rate * hours:.3f} |")
    total += ECPU_ALLOWANCE
    print(f"| ECPU allowance (10 M ECPUs per engine) | | ${ECPU_ALLOWANCE:.3f} |")
    print(f"| **total** | | **${total:.2f}** |\n")
    print("On-demand us-east-1 prices; Cost Explorer shows the billed amount a day later "
          "(tag `kythira:redis-interop`).")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("iam-token")
    p.add_argument("--cache", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--serverless", action="store_true")
    p.set_defaults(func=iam_token)
    p = sub.add_parser("presign-put")
    p.add_argument("--bucket", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--expires", type=int, default=10800)
    p.set_defaults(func=presign_put)
    p = sub.add_parser("compare-junit")
    p.add_argument("kythira")
    p.add_argument("aws")
    p.add_argument("name")
    p.set_defaults(func=compare_junit)
    p = sub.add_parser("cost")
    p.add_argument("--started", type=int, required=True)
    p.add_argument("--ended", type=int, required=True)
    p.set_defaults(func=cost)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
