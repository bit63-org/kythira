#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Run an N-node kythira_node cluster on 127.0.0.1, optionally under heaptrack.

usage: cluster.py KYTHIRA_NODE OUTDIR SERVICES N [--heaptrack]
                  [--engine memory|rocksdb]

SERVICES is KYTHIRA_SERVICES (dynamodb, kms, or both). Every port is picked
free by the kernel. Each node gets OUTDIR/node<id>/ for data and
OUTDIR/node<id>.log; OUTDIR/ports.json records the ports and pids for
workload.py. Runs until SIGINT or SIGTERM, then sends SIGTERM to each node
(not to the heaptrack wrapper, so heaptrack finishes its file) and waits.

Plaintext and static keys throughout: for profiling on one machine only.
The KMS module runs over SoftHSM2 (softhsm2-util and libsofthsm2.so on the
usual Debian/Ubuntu paths), one token per node. See doc/memory_profiling.md.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time

SOFTHSM2_LIBRARY = "/usr/lib/softhsm/libsofthsm2.so"
ACCESS_KEY, SECRET_KEY, ACCOUNT = "AKIDPROFILE", "secretprofile", "111122223333"


def free_ports(n):
    socks = []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def node_pid(pid):
    """The kythira_node process under `pid`, which may be heaptrack's wrapper."""
    cur = pid
    for _ in range(4):
        try:
            if open(f"/proc/{cur}/comm").read().startswith("kythira_node"):
                return cur
        except OSError:
            return cur
        r = subprocess.run(["pgrep", "-P", str(cur)], capture_output=True, text=True)
        kids = [int(k) for k in r.stdout.split()]
        if not kids:
            return cur
        # Never the interpreter: killing heaptrack_interpret kills the node
        # with SIGPIPE before heaptrack has written its data.
        named = [k for k in kids if open(f"/proc/{k}/comm").read().startswith("kythira_node")]
        cur = (named or kids)[0]
    return cur


def node_env(i, n, d, services, engine, raft, ddb, met, kms):
    env = dict(os.environ)
    env.update({
        "KYTHIRA_SERVICES": services,
        "KYTHIRA_NODE_ID": str(i + 1),
        "KYTHIRA_NODE_DATA_DIR": d,
        "KYTHIRA_NODE_PEERS": ",".join(f"{j + 1}=127.0.0.1:{raft[j]}" for j in range(n)),
        "KYTHIRA_NODE_RAFT_BIND": "127.0.0.1",
        "KYTHIRA_NODE_RAFT_PORT": str(raft[i]),
        "KYTHIRA_NODE_INSECURE_PLAINTEXT": "1",
        "KYTHIRA_NODE_METRICS_PORT": str(met[i]),
    })
    names = services.split(",")
    if "dynamodb" in names:
        env.update({
            "KYTHIRA_DYNAMODB_BIND": "127.0.0.1",
            "KYTHIRA_DYNAMODB_PORT": str(ddb[i]),
            "KYTHIRA_DYNAMODB_INSECURE_PLAINTEXT": "1",
            "KYTHIRA_DYNAMODB_STATIC_KEYS": f"{ACCESS_KEY}:{SECRET_KEY}:{ACCOUNT}:prof:admin",
            "KYTHIRA_DYNAMODB_ENGINE": engine,
            "KYTHIRA_DYNAMODB_DISK_FLOOR_BYTES": "0",
            "KYTHIRA_DYNAMODB_COMPAT": "throttling=off",
            "KYTHIRA_DYNAMODB_FORWARD_SECRET": "memory-profile-forward-secret",
            "KYTHIRA_DYNAMODB_PEER_GATEWAYS": ",".join(
                f"{j + 1}=127.0.0.1:{ddb[j]}" for j in range(n) if j != i),
        })
    if "kms" in names:
        tokens = os.path.join(d, "tokens")
        os.makedirs(tokens, exist_ok=True)
        conf = os.path.join(d, "softhsm2.conf")
        with open(conf, "w") as f:
            f.write(f"directories.tokendir = {tokens}\nobjectstore.backend = file\n"
                    "log.level = ERROR\n")
        subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "kms",
                        "--so-pin", "5678", "--pin", "1234"],
                       env={**env, "SOFTHSM2_CONF": conf}, check=True, stdout=subprocess.DEVNULL)
        with open(os.path.join(d, "pin"), "w") as f:
            f.write("1234\n")
        with open(os.path.join(d, "keys"), "w") as f:
            f.write(f"{ACCESS_KEY} {SECRET_KEY} {ACCOUNT} prof admin\n")
        env.update({
            "SOFTHSM2_CONF": conf,
            "KYTHIRA_KMS_API_URLS": ",".join(f"{j + 1}=http://127.0.0.1:{kms[j]}" for j in range(n)),
            "KYTHIRA_KMS_API_LISTEN": f"127.0.0.1:{kms[i]}",
            "KYTHIRA_KMS_INSECURE_PLAINTEXT": "1",
            "KYTHIRA_KMS_AUTH": "static",
            "KYTHIRA_KMS_STATIC_KEYS_FILE": os.path.join(d, "keys"),
            "KYTHIRA_KMS_PKCS11": SOFTHSM2_LIBRARY,
            "KYTHIRA_KMS_PIN_FILE": os.path.join(d, "pin"),
        })
    return env


def main():
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    binary, out, services, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    heaptrack = "--heaptrack" in sys.argv
    engine = sys.argv[sys.argv.index("--engine") + 1] if "--engine" in sys.argv else "memory"
    os.makedirs(out, exist_ok=True)
    ports = free_ports(4 * n)
    raft, ddb, met, kms = (ports[k * n:(k + 1) * n] for k in range(4))
    procs = []
    for i in range(n):
        d = os.path.join(out, f"node{i + 1}")
        os.makedirs(d, exist_ok=True)
        cmd = [binary]
        if heaptrack:
            cmd = ["heaptrack", "-o", os.path.join(out, f"heaptrack.node{i + 1}")] + cmd
        with open(os.path.join(out, f"node{i + 1}.log"), "w") as log:
            procs.append(subprocess.Popen(
                cmd, env=node_env(i, n, d, services, engine, raft, ddb, met, kms),
                stdout=log, stderr=subprocess.STDOUT))
    with open(os.path.join(out, "ports.json"), "w") as f:
        json.dump({"raft": raft, "dynamodb": ddb, "metrics": met, "kms": kms,
                   "pids": [p.pid for p in procs]}, f)

    stop = []
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    while not stop and all(p.poll() is None for p in procs):
        time.sleep(0.5)
    for p in procs:
        if p.poll() is None:
            os.kill(node_pid(p.pid), signal.SIGTERM)
    for p in procs:
        try:
            p.wait(timeout=300)
        except subprocess.TimeoutExpired:
            p.kill()
    print("exit codes", [p.returncode for p in procs])


if __name__ == "__main__":
    main()
