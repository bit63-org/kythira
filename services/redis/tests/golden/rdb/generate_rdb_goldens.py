#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the RDB golden files the codec tests read.

.kiro/specs/redis-migration-tooling/ task 1. For each reference server
this starts its container, writes a fixed data set that covers every value
encoding the server has (strings raw/int/LZF, quicklist lists with packed
and plain nodes, intset/listpack/hashtable sets, listpack and skiplist
sorted sets, listpack and hashtable hashes, hashes with field TTLs where the
server has HEXPIRE, streams with consumer groups and pending entries, module
values on Redis 8, keys with expiry, several databases and a function
library), runs SAVE and copies dump.rdb out as <name>.rdb.

Next to it goes <name>.keys, one line per key, sorted:

    <db> <key hex> <PEXPIRETIME> <DUMP hex>

DUMP's payload is the RDB type byte plus the value serialization, followed
by the 2-byte RDB version and the CRC64 footer, written by the same server
function that writes the value into dump.rdb. The codec test checks that
each key it reads from <name>.rdb carries exactly that type byte and
payload, so the listing pins the reader against the server's own encoder.

Only the container runtime is needed: $KYTHIRA_CONTAINER_RUNTIME (default
docker; rootless podman works, the server port is published on 127.0.0.1).
$KYTHIRA_RDB_IMAGE_PREFIX replaces "docker.io/" in the image names (for
example "mirror.gcr.io/" when Docker Hub rate-limits).

    generate_rdb_goldens.py [--only NAME ...] [--load-check FILE.rdb NAME]

--load-check starts NAME's server with FILE.rdb as its dump.rdb and prints
DBSIZE per database, failing if the server refuses the file. It checks the
codec's writer output against the real server.
"""

import argparse
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# name, image, flavour
SERVERS = [
    ("redis-7.2", "docker.io/library/redis:7.2", "redis"),
    ("redis-7.4", "docker.io/library/redis:7.4", "redis"),
    ("redis-8.0", "docker.io/library/redis:8.0", "redis"),
    ("redis-8.2", "docker.io/library/redis:8.2", "redis"),
    ("redis-8.4", "docker.io/library/redis:8.4", "redis"),
    ("valkey-7.2", "docker.io/valkey/valkey:7.2", "valkey"),
    ("valkey-8.0", "docker.io/valkey/valkey:8.0", "valkey"),
    ("valkey-8.1", "docker.io/valkey/valkey:8.1", "valkey"),
    ("valkey-9.0", "docker.io/valkey/valkey:9.0", "valkey"),
]


def runtime():
    return os.environ.get("KYTHIRA_CONTAINER_RUNTIME", "docker")


def image_name(image):
    prefix = os.environ.get("KYTHIRA_RDB_IMAGE_PREFIX")
    if prefix and image.startswith("docker.io/"):
        return prefix + image[len("docker.io/"):]
    return image


class Resp:
    """Just enough RESP2 to drive the server and read binary replies."""

    def __init__(self, port):
        deadline = time.time() + 30
        while True:
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=30)
                self.buf = b""
                if self.call("PING") == b"PONG":
                    return
            except (OSError, ConnectionError, RuntimeError):
                pass
            if time.time() > deadline:
                raise RuntimeError("server did not answer PING")
            time.sleep(0.2)

    def _line(self):
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _exact(self, n):
        while len(self.buf) < n + 2:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n + 2:]
        return data

    def _reply(self):
        line = self._line()
        kind, rest = line[:1], line[1:]
        if kind == b"+":
            return rest
        if kind == b"-":
            raise RuntimeError(rest.decode())
        if kind == b":":
            return int(rest)
        if kind == b"$":
            n = int(rest)
            return None if n < 0 else self._exact(n)
        if kind == b"*":
            n = int(rest)
            return None if n < 0 else [self._reply() for _ in range(n)]
        raise RuntimeError("bad reply " + repr(line))

    def call(self, *args):
        out = [b"*%d\r\n" % len(args)]
        for a in args:
            if isinstance(a, (int, float)):
                a = str(a)
            if isinstance(a, str):
                a = a.encode()
            out.append(b"$%d\r\n%s\r\n" % (len(a), a))
        self.sock.sendall(b"".join(out))
        return self._reply()


def has_command(r, name):
    info = r.call("COMMAND", "INFO", name)
    return bool(info) and info[0] is not None


def populate(r, flavour):
    rng = random.Random(20261118)
    word = lambda n: "".join(rng.choice("abcdefghij") for _ in range(n))

    r.call("SELECT", 0)
    # Strings: int-encoded, short raw, LZF-compressible, incompressible,
    # binary and empty.
    r.call("SET", "s:int8", "-7")
    r.call("SET", "s:int16", "1234")
    r.call("SET", "s:int32", "-2000000000")
    r.call("SET", "s:int64", "9000000000000000000")
    r.call("SET", "s:short", "hello")
    r.call("SET", "s:lzf", "abcabcabc" * 300)
    r.call("SET", "s:random", bytes(rng.getrandbits(8) for _ in range(300)))
    r.call("SET", "s:binary", b"\x00\xff\r\n\x80key")
    r.call("SET", "s:empty", "")
    r.call("SET", b"\xc3\xa9\x00k", "binary key")
    # Expiry far in the future so a load check years from now still sees it.
    r.call("SET", "s:expire", "v", "PXAT", 4102444800123)
    r.call("SET", "s:expire2", "w" * 40, "PXAT", 4102444800999)

    # Lists: one listpack node, many nodes, and a plain node (element larger
    # than list-max-listpack-size).
    r.call("RPUSH", "l:small", "a", "1", "-5", "bb")
    for i in range(0, 3000, 100):
        r.call("RPUSH", "l:big", *[f"item-{j}-{word(4)}" for j in range(i, i + 100)])
    r.call("RPUSH", "l:plain", "x", "P" * 20000, "y")

    # Sets: intset, listpack (7.2+), hashtable.
    r.call("SADD", "set:int", 1, 2, 3, -100, 70000, 5000000000)
    r.call("SADD", "set:small", "a", "b", "c")
    r.call("SADD", "set:big", *[f"m{i}" for i in range(300)])

    # Sorted sets: listpack and skiplist (ZSET_2 binary doubles).
    r.call("ZADD", "z:small", 1, "one", 2.5, "two", -3, "three", "inf", "top")
    args = []
    for i in range(200):
        args += [str(i * 1.25), f"zm{i}"]
    r.call("ZADD", "z:big", *args)

    # Hashes: listpack and hashtable.
    r.call("HSET", "h:small", "f1", "v1", "f2", "2", "f3", "")
    args = []
    for i in range(200):
        args += [f"field{i}", f"value{i}-{word(3)}"]
    r.call("HSET", "h:big", *args)
    # Past every version's hash-max-listpack-entries (128 before Redis 8,
    # 512 after), so the hashtable encoding is written everywhere.
    r.call("HSET", "h:huge", *[f"hf{i}" if j == 0 else str(i) for i in range(600) for j in (0, 1)])

    # Hash field TTLs (Redis 7.4+, Valkey 9.0+): a listpack-sized and a
    # hashtable-sized hash, each with some fields expiring.
    if has_command(r, "HPEXPIREAT"):
        r.call("HSET", "hx:small", "a", "1", "b", "2", "c", "3")
        r.call("HPEXPIREAT", "hx:small", 4102444800500, "FIELDS", 2, "a", "c")
        args = []
        for i in range(200):
            args += [f"xf{i}", f"xv{i}"]
        r.call("HSET", "hx:big", *args)
        r.call("HPEXPIREAT", "hx:big", 4102444801000, "FIELDS", 3, "xf1", "xf50", "xf199")
        r.call("HSET", "hx:huge", *[f"hf{i}" if j == 0 else str(i) for i in range(600) for j in (0, 1)])
        r.call("HPEXPIREAT", "hx:huge", 4102444801500, "FIELDS", 2, "hf7", "hf500")

    # Streams: entries, a deleted entry, two groups, pending entries, two
    # consumers.
    for i in range(50):
        r.call("XADD", "st", f"{1700000000000 + i}-0", "k", f"v{i}", "n", str(i))
    r.call("XDEL", "st", "1700000000003-0")
    r.call("XGROUP", "CREATE", "st", "g1", "0")
    r.call("XGROUP", "CREATE", "st", "g2", "$")
    r.call("XREADGROUP", "GROUP", "g1", "alice", "COUNT", 5, "STREAMS", "st", ">")
    r.call("XREADGROUP", "GROUP", "g1", "bob", "COUNT", 2, "STREAMS", "st", ">")
    r.call("XACK", "st", "g1", "1700000000001-0")
    r.call("XADD", "st:empty", "1-1", "a", "b")
    r.call("XDEL", "st:empty", "1-1")

    # Function library (FUNCTION2 opcode).
    r.call("FUNCTION", "LOAD", "REPLACE",
           "#!lua name=goldlib\n"
           "redis.register_function('gold', function(keys, args) return 1 end)")

    # Other databases.
    r.call("SELECT", 1)
    r.call("SET", "db1:key", "one")
    r.call("RPUSH", "db1:list", "x")
    r.call("SET", "db1:expire", "e", "PXAT", 4102444802000)
    r.call("SELECT", 9)
    r.call("HSET", "db9:hash", "f", "v")

    # Module values (the Redis 8 images bundle these modules).
    r.call("SELECT", 0)
    if has_command(r, "JSON.SET"):
        r.call("JSON.SET", "m:json", "$", '{"a":[1,2,{"b":"c"}],"n":null}')
    if has_command(r, "BF.ADD"):
        r.call("BF.ADD", "m:bloom", "x")
    if has_command(r, "TS.ADD"):
        r.call("TS.ADD", "m:ts", 1700000000000, 1.5)
    if has_command(r, "VADD"):
        r.call("VADD", "m:vset", "VALUES", 3, 0.1, 0.2, 0.3, "e1")


def listing(r):
    lines = []
    for db in range(16):
        r.call("SELECT", db)
        keys = []
        cursor = b"0"
        while True:
            cursor, batch = r.call("SCAN", cursor, "COUNT", 1000)
            keys += batch
            if cursor == b"0":
                break
        for key in sorted(set(keys)):
            exp = r.call("PEXPIRETIME", key)
            dump = r.call("DUMP", key)
            lines.append(f"{db} {key.hex()} {exp} {dump.hex()}")
    return lines


def start(image, name, data_dir=None):
    cname = f"kythira-rdb-golden-{name}-{os.getpid()}"
    cmd = [runtime(), "run", "-d", "--name", cname, "-p", "127.0.0.1::6379"]
    if data_dir:
        cmd += ["-v", f"{data_dir}:/data:Z"]
    cmd += [image_name(image), "--save", "", "--appendonly", "no"]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    out = subprocess.run([runtime(), "port", cname, "6379/tcp"], check=True,
                         capture_output=True, text=True).stdout
    port = int(out.strip().splitlines()[0].rsplit(":", 1)[1])
    return cname, port


def stop(cname):
    subprocess.run([runtime(), "rm", "-f", cname], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def generate(name, image, flavour):
    cname, port = start(image, name)
    try:
        r = Resp(port)
        version = r.call("INFO", "server").decode()
        populate(r, flavour)
        r.call("SAVE")
        lines = listing(r)
        subprocess.run([runtime(), "cp", f"{cname}:/data/dump.rdb", str(HERE / f"{name}.rdb")],
                       check=True)
        (HERE / f"{name}.keys").write_text("\n".join(lines) + "\n")
        ver = [l for l in version.splitlines() if l.startswith(("redis_version", "valkey_version"))]
        print(f"{name}: {', '.join(ver)}, {len(lines)} keys")
    finally:
        stop(cname)


def load_check(path, name):
    image = next(i for n, i, _ in SERVERS if n == name)
    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copy(path, tmp / "dump.rdb")
        os.chmod(tmp, 0o777)
        os.chmod(tmp / "dump.rdb", 0o666)
        cname, port = start(image, name, tmp)
        try:
            r = Resp(port)
            for db in range(16):
                r.call("SELECT", db)
                n = r.call("DBSIZE")
                if n:
                    print(f"db{db}: {n} keys")
                for key in sorted(r.call("KEYS", "kythira:*")):
                    if r.call("TYPE", key) == b"string":
                        value = r.call("GET", key)
                        print(f"  {key.decode()} = {value[:24]!r}{'...' if len(value) > 24 else ''}"
                              f" ({len(value)} bytes, ttl {r.call('PEXPIRETIME', key)})")
            libs = r.call("FUNCTION", "LIST")
            print("functions:", len(libs))
        except Exception:
            logs = subprocess.run([runtime(), "logs", cname], capture_output=True, text=True)
            print(logs.stdout[-4000:], logs.stderr[-4000:], file=sys.stderr)
            raise
        finally:
            stop(cname)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--load-check", nargs=2, metavar=("FILE", "NAME"))
    a = ap.parse_args()
    if a.load_check:
        load_check(a.load_check[0], a.load_check[1])
        return
    for name, image, flavour in SERVERS:
        if a.only and name not in a.only:
            continue
        generate(name, image, flavour)


if __name__ == "__main__":
    main()
