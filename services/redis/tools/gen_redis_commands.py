#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Generate <kythira/redis/redis_command_ids.hpp> from the command registry.

The input is services/redis/tools/redis_commands.yaml
(.kiro/specs/redis-general-data-types/ task 1, design Component 2). The
output holds:

- redis_command_id: one enumerator per registered command, with its stable
  id, the value a format-0x03 `exec` log record carries;
- k_redis_commands: every command's COMMAND INFO metadata (arity, flags,
  ACL categories, legacy key triple), its path, status and shipping task,
  sorted by name;
- k_redis_retired_commands: removed commands, whose ids stay taken;
- find_redis_command(): lookup by upper-case name or by id.

The registry is a strict YAML subset parsed here, so the build needs no
PyYAML: top-level `commands:` and `retired:` lists of flat maps whose values
are scalars or `[a, b]` flow lists. Anything else is an error, as are
duplicate names or ids, unknown flags or categories, and a retired id that
is still in use.

Usage:
    gen_redis_commands.py REGISTRY OUT [--check]
"""

import argparse
import pathlib
import re
import sys

FLAGS = [
    "write", "readonly", "denyoom", "admin", "noscript", "loading", "stale",
    "skip_slowlog", "fast", "no_auth", "movablekeys", "allow_busy", "no_multi",
    "blocking",
]
CATEGORIES = [
    "keyspace", "read", "write", "set", "list", "hash", "string", "admin",
    "fast", "slow", "blocking", "dangerous", "connection", "transaction",
]
PATHS = {"R": "read", "W": "write", "M": "multi_key", "F": "fan_out",
         "A": "admin", "L": "local"}
STATUSES = ["shipped", "planned"]
COMMAND_KEYS = ["name", "id", "group", "since", "arity", "flags", "acl", "keys",
                "path", "status", "task"]
# Optional: Redis's COMMAND INFO tips, copied from the reference server.
OPTIONAL_KEYS = ["tips"]
TIP_RE = re.compile(r"^[a-z_]+(:[a-z_]+)?$")
NAME_RE = re.compile(r"^[A-Z][A-Z0-9.]*$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


class RegistryError(Exception):
    pass


def parse_value(text, where):
    text = text.strip()
    if text.startswith("["):
        if not text.endswith("]"):
            raise RegistryError(f"{where}: unterminated list")
        inner = text[1:-1].strip()
        return [] if not inner else [v.strip() for v in inner.split(",")]
    if not text or text[0] in "{&*!|>'\"%@`":
        raise RegistryError(f"{where}: unsupported value {text!r}")
    return text


def parse_registry(text):
    """Return {'commands': [...], 'retired': [...]} from the YAML subset."""
    sections = {"commands": [], "retired": []}
    current = None
    entry = None
    for number, raw in enumerate(text.splitlines(), 1):
        where = f"line {number}"
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        if not line.startswith(" "):
            key, sep, rest = line.partition(":")
            if not sep or key not in sections:
                raise RegistryError(f"{where}: expected 'commands:' or 'retired:'")
            current = sections[key]
            entry = None
            if rest.strip():
                if parse_value(rest, where) != []:
                    raise RegistryError(f"{where}: only an empty inline list is allowed")
            continue
        if current is None:
            raise RegistryError(f"{where}: entry outside a section")
        stripped = line.strip()
        if stripped.startswith("- "):
            entry = {}
            current.append(entry)
            stripped = stripped[2:]
        elif entry is None:
            raise RegistryError(f"{where}: field before the first '- '")
        key, sep, rest = stripped.partition(":")
        key = key.strip()
        if not sep or not key:
            raise RegistryError(f"{where}: expected 'key: value'")
        if key in entry:
            raise RegistryError(f"{where}: duplicate field {key!r}")
        entry[key] = parse_value(rest, where)
    return sections


def to_int(value, where, lo, hi):
    if isinstance(value, list) or not re.fullmatch(r"-?\d+", value):
        raise RegistryError(f"{where}: {value!r} is not an integer")
    n = int(value)
    if not lo <= n <= hi:
        raise RegistryError(f"{where}: {n} is outside [{lo}, {hi}]")
    return n


def validate(sections):
    commands = []
    names = {}
    ids = {}
    for e in sections["commands"]:
        where = f"command {e.get('name', '?')}"
        if sorted(k for k in e if k not in OPTIONAL_KEYS) != sorted(COMMAND_KEYS):
            missing = set(COMMAND_KEYS) - set(e)
            extra = set(e) - set(COMMAND_KEYS) - set(OPTIONAL_KEYS)
            raise RegistryError(f"{where}: missing {sorted(missing)}, unknown {sorted(extra)}")
        name = e["name"]
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise RegistryError(f"{where}: name must be upper case")
        cid = to_int(e["id"], where, 1, 65535)
        if name in names:
            raise RegistryError(f"{where}: duplicate name")
        if cid in ids:
            raise RegistryError(f"{where}: id {cid} already used by {ids[cid]}")
        names[name] = cid
        ids[cid] = name
        for field, allowed in (("flags", FLAGS), ("acl", CATEGORIES)):
            if not isinstance(e[field], list):
                raise RegistryError(f"{where}: {field} must be a list")
            for v in e[field]:
                if v not in allowed:
                    raise RegistryError(f"{where}: unknown {field} value {v!r}")
        keys = e["keys"]
        if not isinstance(keys, list) or len(keys) != 3:
            raise RegistryError(f"{where}: keys must be [first, last, step]")
        first, last, step = (to_int(k, where, -1, 127) for k in keys)
        if (first, last, step) != (0, 0, 0) and (first < 1 or step < 1):
            raise RegistryError(f"{where}: keys must be all zero or start at 1 with step >= 1")
        if "movablekeys" in e["flags"] and (first, last, step) != (0, 0, 0):
            raise RegistryError(f"{where}: a movablekeys command has keys [0, 0, 0] here")
        if e["path"] not in PATHS:
            raise RegistryError(f"{where}: path must be one of {sorted(PATHS)}")
        if e["status"] not in STATUSES:
            raise RegistryError(f"{where}: status must be one of {STATUSES}")
        if not VERSION_RE.match(e["since"]):
            raise RegistryError(f"{where}: since must be major.minor.patch")
        if not re.fullmatch(r"[a-z]+", e["group"]):
            raise RegistryError(f"{where}: group must be lower-case letters")
        tips = e.get("tips", [])
        if not isinstance(tips, list) or any(not TIP_RE.match(t) for t in tips):
            raise RegistryError(f"{where}: tips must be a list of lower-case tips")
        commands.append({
            "name": name, "id": cid, "group": e["group"], "since": e["since"],
            "arity": to_int(e["arity"], where, -32768, 32767),
            "flags": e["flags"], "acl": e["acl"], "keys": (first, last, step),
            "path": PATHS[e["path"]], "status": e["status"],
            "task": to_int(e["task"], where, 0, 255),
            "tips": tips,
        })
    retired = []
    for e in sections["retired"]:
        where = f"retired {e.get('name', '?')}"
        if sorted(e) != ["id", "name"]:
            raise RegistryError(f"{where}: a retired entry has only name and id")
        cid = to_int(e["id"], where, 1, 65535)
        if cid in ids or e["name"] in names:
            raise RegistryError(f"{where}: retired name or id {cid} is still in use")
        ids[cid] = e["name"]
        retired.append({"name": e["name"], "id": cid})
    return sorted(commands, key=lambda c: c["name"]), sorted(retired, key=lambda r: r["id"])


def enumerator(name):
    return name.lower().replace(".", "_")


def mask(values, namespace):
    if not values:
        return "0U"
    return " | ".join(f"{namespace}::{v}" for v in values)


HEADER = """\
// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// GENERATED by services/redis/tools/gen_redis_commands.py from
// services/redis/tools/redis_commands.yaml. Do not edit; regenerate.

#pragma once

/// @file redis_command_ids.hpp
/// @brief The Redis command registry: stable command ids and each command's
///        COMMAND INFO metadata (.kiro/specs/redis-general-data-types/
///        task 1, design Component 2). Types: redis_command_types.hpp.

#include <kythira/redis/redis_command_types.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>

namespace kythira {

// clang-format off
"""

FOOTER = """\
// clang-format on

/// The entry for an upper-case command name, or nullptr when unregistered.
[[nodiscard]] constexpr auto find_redis_command(std::string_view upper_name) noexcept
    -> const redis_command_info* {
    const auto* it = std::lower_bound(
        k_redis_commands.begin(), k_redis_commands.end(), upper_name,
        [](const redis_command_info& e, std::string_view name) { return e.name < name; });
    return it != k_redis_commands.end() && it->name == upper_name ? it : nullptr;
}

/// The entry for a command id, or nullptr when no registered command has it
/// (an unknown or retired id).
[[nodiscard]] constexpr auto find_redis_command(redis_command_id id) noexcept
    -> const redis_command_info* {
    for (const auto& e : k_redis_commands) {
        if (e.id == static_cast<std::uint16_t>(id)) {
            return &e;
        }
    }
    return nullptr;
}

}  // namespace kythira
"""


def render(commands, retired):
    by_id = sorted(commands, key=lambda c: c["id"])
    out = [HEADER]
    out.append("/// Stable command ids (never renumbered or reused).\n")
    out.append("enum class redis_command_id : std::uint16_t {\n")
    for c in by_id:
        out.append(f"    {enumerator(c['name'])} = {c['id']},\n")
    out.append("};\n\n")
    out.append(f"inline constexpr std::array<redis_command_info, {len(commands)}> "
               "k_redis_commands{{\n")
    for c in commands:
        first, last, step = c["keys"]
        out.append(
            f"    {{\"{c['name']}\", {c['id']}, {c['arity']}, "
            f"{mask(c['flags'], 'redis_command_flag')}, "
            f"{mask(c['acl'], 'redis_acl_category')}, {first}, {last}, {step}, "
            f"redis_command_path::{c['path']}, redis_command_status::{c['status']}, "
            f"\"{c['group']}\", \"{c['since']}\", {c['task']}, "
            f"\"{' '.join(c['tips'])}\"}},\n")
    out.append("}};\n\n")
    out.append("/// Ids of removed commands, still taken.\n")
    out.append(f"inline constexpr std::array<redis_retired_command, {len(retired)}> "
               "k_redis_retired_commands{{\n")
    for r in retired:
        out.append(f"    {{\"{r['name']}\", {r['id']}}},\n")
    out.append("}};\n\n")
    out.append(FOOTER)
    return "".join(out)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("registry", type=pathlib.Path)
    parser.add_argument("out", type=pathlib.Path)
    parser.add_argument("--check", action="store_true",
                        help="fail if OUT differs from what REGISTRY generates")
    args = parser.parse_args(argv)
    try:
        commands, retired = validate(
            parse_registry(args.registry.read_text(encoding="utf-8")))
    except RegistryError as e:
        print(f"{args.registry}: {e}", file=sys.stderr)
        return 1
    text = render(commands, retired)
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"{args.out} is stale; regenerate it with\n"
                  f"  python3 {sys.argv[0]} {args.registry} {args.out}", file=sys.stderr)
            return 1
        return 0
    args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
