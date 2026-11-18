#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""sqs_node's admin calls (.kiro/specs/sqs-compatible-queues/ task 11).

  sqs_admin.py peer URL... --id ID --raft RAFT_URL --sqs SQS_URL
      Tell each node at URL where node ID's Raft and SQS listeners are
      (every data node, before an evacuation adds ID to the group).
  sqs_admin.py evacuate URL --from ID --to ID
      Move node FROM's replica to node TO through the node at URL, and
      wait for it to finish (doc/migration.md).

Calls are signed with $SQS_FORWARD_SECRET, the cluster's secret. Over TLS,
--cert/--key present a certificate whose layer identity has the data role,
and --ca checks the node's.
"""

import argparse
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

PREFIX = "/_kythira/sqs/v1/admin/"


def sign(secret: str, body: bytes) -> str:
    t = int(time.time())
    mac = hmac.new(secret.encode(), f"{t}\n".encode() + body, hashlib.sha256).hexdigest()
    return f"{t}:{mac}"


def call(base: str, name: str, payload: dict, args, timeout: float) -> tuple[int, dict]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(base.rstrip("/") + PREFIX + name, data=body, method="POST")
    req.add_header("content-type", "application/json")
    secret = os.environ.get("SQS_FORWARD_SECRET", "")
    if secret:
        req.add_header("x-kythira-forward", sign(secret, body))
    ctx = None
    if base.startswith("https://"):
        ctx = ssl.create_default_context(cafile=args.ca)
        if args.cert:
            ctx.load_cert_chain(args.cert, args.key)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        text = e.read()
        try:
            return e.code, json.loads(text)
        except ValueError:
            return e.code, {"error": text.decode(errors="replace").strip()}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--ca", help="CA bundle that the nodes' certificates chain to")
    p.add_argument("--cert", help="client certificate (layer identity with the data role)")
    p.add_argument("--key", help="its private key")
    sub = p.add_subparsers(dest="command", required=True)
    peer = sub.add_parser("peer")
    peer.add_argument("urls", nargs="+")
    peer.add_argument("--id", required=True)
    peer.add_argument("--raft", required=True)
    peer.add_argument("--sqs", required=True)
    ev = sub.add_parser("evacuate")
    ev.add_argument("url")
    ev.add_argument("--from", dest="from_", required=True)
    ev.add_argument("--to", required=True)
    ev.add_argument("--timeout", type=float, default=330.0,
                    help="seconds to wait for the node's answer")
    args = p.parse_args()

    if args.command == "peer":
        failed = 0
        for url in args.urls:
            status, out = call(url, "peer", {"id": args.id, "raft": args.raft, "sqs": args.sqs},
                               args, 10)
            print(f"{url}: {status} {json.dumps(out)}")
            failed += status != 200
        return 1 if failed else 0

    status, out = call(args.url, "evacuate", {"from": args.from_, "to": args.to}, args,
                       args.timeout)
    for step in out.get("steps", []):
        print(f"  {step}")
    print(f"{status} {out.get('result', '')}: {out.get('what', out.get('error', ''))}")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
