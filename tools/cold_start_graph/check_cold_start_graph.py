#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Check the cold-start dependency graph and render it for the runbook.

config/cold_start_graph.yaml lists every component an AZ needs to come back
from a full power outage, its tier and what it needs before it can serve
(.kiro/specs/az-cold-start/ Requirement 1). This check refuses a graph that
could not come back by itself, and a service module that has not said what
it needs. It needs no build: PyYAML and the source tree.

Rules, each printed as `<file>:<line>: [<rule>] <message>` (and as a GitHub
annotation when GITHUB_ACTIONS is set):

  schema               the graph or a declaration is malformed: a field is
                       missing, unknown or of the wrong type, a tier is not
                       0-3, `restart` is not `local` or `controller`, a need
                       is listed twice.
  unknown-need         a need names no component of the graph.
  cycle                the needs form a cycle; the message names it.
  tier-inversion       a component needs one of a higher tier number
                       (Requirement 1.3).
  tier0-local          a tier-0 component needs another tier-0 component and
                       one of them does not restart from local state
                       (Requirement 1.2).
  module-declaration   a services/<m>/ directory has no cold_start.yaml, or
                       the graph names a module that declares nothing while
                       its component is not `planned` (Requirement 1.4).
  module-number        a declaration's module_number disagrees with
                       include/raft/service_module.hpp.
  module-disagrees     a declaration's components or needs differ from the
                       graph's.
  stale-planned        a component is `planned` but its module already
                       declares it.
  rendered-stale       with --check-rendered, the runbook's generated section
                       is not what the graph renders to (Requirement 1.5).

The exit status is 1 if there is any violation, 0 otherwise.

    check_cold_start_graph.py                    check the tree
    check_cold_start_graph.py --check-rendered   also check the runbook
    check_cold_start_graph.py --render           rewrite the runbook section
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

GRAPH = Path("config/cold_start_graph.yaml")
RUNBOOK = Path("doc/runbooks/az-cold-start.md")
MODULE_NUMBERS = Path("include/raft/service_module.hpp")
DECLARATION = "cold_start.yaml"

BEGIN = "<!-- cold-start-graph:begin -->"
END = "<!-- cold-start-graph:end -->"

TIERS = range(4)
TIER_NAMES = {
    0: "Tier 0: bootstrap",
    1: "Tier 1: storage",
    2: "Tier 2: rest of the control plane",
    3: "Tier 3: customer workload",
}
RESTARTS = ("local", "controller")
COMPONENT_FIELDS = {"tier", "restart", "needs", "module", "repo", "planned",
                    "description"}
REQUIRED_FIELDS = ("tier", "restart", "needs")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
NUMBER_RE = re.compile(
    r"inline\s+constexpr\s+std::uint8_t\s+([a-z0-9_]+)\s*=\s*(\d+)\s*;")
RESERVED_RE = re.compile(r"///\s*(\d+)\s+is\s+reserved\s+for\s+the\s+(\w+)\s+module")


@dataclass(frozen=True, order=True)
class Violation:
    file: str
    line: int
    rule: str
    message: str

    def render(self) -> str:
        return f"{self.file}:{self.line}: [{self.rule}] {self.message}"


@dataclass
class Component:
    name: str
    line: int
    tier: int = 0
    restart: str = "local"
    needs: list[str] = field(default_factory=list)
    module: str | None = None
    repo: str | None = None
    planned: bool = False
    description: str = ""


def load_yaml(path: Path) -> tuple[object, dict[str, int]]:
    """Loads `path` and returns the data plus the line of each key of its
    top-level mapping's `components` mapping, so violations point at it."""
    text = path.read_text()
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    data = yaml.safe_load(text)
    lines: dict[str, int] = {}
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            if key.value == "components" and isinstance(value, yaml.MappingNode):
                for k, _v in value.value:
                    lines[str(k.value)] = k.start_mark.line + 1
    return data, lines


class Checker:
    def __init__(self, root: Path, graph: Path | None = None) -> None:
        self.root = root.resolve()
        self.graph_path = self.root / (graph or GRAPH)
        self.violations: list[Violation] = []
        self.components: dict[str, Component] = {}

    # ── helpers ──────────────────────────────────────────────────────────
    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def report(self, path: Path, line: int, rule: str, message: str) -> None:
        self.violations.append(Violation(self.rel(path), line, rule, message))

    def line_of(self, name: str) -> int:
        c = self.components.get(name)
        return c.line if c else 1

    # ── the graph ────────────────────────────────────────────────────────
    def load_graph(self) -> bool:
        g = self.graph_path
        if not g.is_file():
            self.report(g, 1, "schema", "the cold-start graph is missing")
            return False
        try:
            data, lines = load_yaml(g)
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            self.report(g, mark.line + 1 if mark else 1, "schema",
                        f"not valid YAML: {e}")
            return False
        if not isinstance(data, dict) or set(data) != {"components"} or \
                not isinstance(data["components"], dict) or not data["components"]:
            self.report(g, 1, "schema",
                        "the graph must be a mapping with one key, "
                        "`components`, holding a non-empty mapping")
            return False
        for name, body in data["components"].items():
            line = lines.get(str(name), 1)
            c = self.parse_component(g, str(name), line, body)
            if c:
                self.components[c.name] = c
        return True

    def parse_component(self, g: Path, name: str, line: int,
                        body: object) -> Component | None:
        if not NAME_RE.match(name):
            self.report(g, line, "schema",
                        f"component name `{name}` is not [a-z][a-z0-9_]*")
            return None
        if not isinstance(body, dict):
            self.report(g, line, "schema", f"`{name}` must be a mapping")
            return None
        ok = True
        for key in sorted(set(body) - COMPONENT_FIELDS):
            self.report(g, line, "schema", f"`{name}` has unknown field `{key}`")
            ok = False
        for key in REQUIRED_FIELDS:
            if key not in body:
                self.report(g, line, "schema", f"`{name}` has no `{key}`")
                ok = False
        if not ok:
            return None
        c = Component(name=name, line=line)
        tier = body["tier"]
        if isinstance(tier, bool) or not isinstance(tier, int) or tier not in TIERS:
            self.report(g, line, "schema", f"`{name}`: tier must be 0-3, not {tier!r}")
            ok = False
        else:
            c.tier = tier
        if body["restart"] not in RESTARTS:
            self.report(g, line, "schema",
                        f"`{name}`: restart must be `local` or `controller`, "
                        f"not {body['restart']!r}")
            ok = False
        else:
            c.restart = body["restart"]
        needs = self.parse_needs(g, line, name, body["needs"])
        if needs is None:
            ok = False
        else:
            c.needs = needs
        for key in ("module", "repo", "description"):
            if key in body:
                if not isinstance(body[key], str) or not body[key]:
                    self.report(g, line, "schema",
                                f"`{name}`: {key} must be a non-empty string")
                    ok = False
                else:
                    setattr(c, key, body[key])
        if "planned" in body:
            if not isinstance(body["planned"], bool):
                self.report(g, line, "schema", f"`{name}`: planned must be true or false")
                ok = False
            else:
                c.planned = body["planned"]
        if c.module and c.repo:
            self.report(g, line, "schema",
                        f"`{name}` names both a module and another repository")
            ok = False
        return c if ok else None

    def parse_needs(self, path: Path, line: int, name: str,
                    needs: object) -> list[str] | None:
        if not isinstance(needs, list) or \
                not all(isinstance(n, str) for n in needs):
            self.report(path, line, "schema",
                        f"`{name}`: needs must be a list of component names")
            return None
        seen: set[str] = set()
        ok = True
        for n in needs:
            if n in seen:
                self.report(path, line, "schema", f"`{name}` needs `{n}` twice")
                ok = False
            seen.add(n)
        return list(needs) if ok else None

    def check_edges(self) -> None:
        g = self.graph_path
        for c in self.components.values():
            for n in c.needs:
                d = self.components.get(n)
                if d is None:
                    self.report(g, c.line, "unknown-need",
                                f"`{c.name}` needs `{n}`, which the graph does "
                                f"not list")
                    continue
                if d.tier > c.tier:
                    self.report(g, c.line, "tier-inversion",
                                f"`{c.name}` (tier {c.tier}) needs `{n}` "
                                f"(tier {d.tier}); nothing may need a later tier")
                if c.tier == 0 and d.tier == 0 and \
                        (c.restart != "local" or d.restart != "local"):
                    worse = c.name if c.restart != "local" else n
                    self.report(g, c.line, "tier0-local",
                                f"`{c.name}` needs `{n}` within tier 0, but "
                                f"`{worse}` does not restart from local state; "
                                f"the bootstrap tier must need only power and "
                                f"itself")

    def check_cycles(self) -> None:
        # Iterative depth-first search; reports each cycle once, at the
        # component where the search first closes it.
        white, grey, black = 0, 1, 2
        color = dict.fromkeys(self.components, white)
        for start in sorted(self.components):
            if color[start] != white:
                continue
            stack: list[tuple[str, int]] = [(start, 0)]
            path: list[str] = [start]
            color[start] = grey
            while stack:
                node, i = stack[-1]
                needs = [n for n in self.components[node].needs
                         if n in self.components]
                if i < len(needs):
                    stack[-1] = (node, i + 1)
                    nxt = needs[i]
                    if color[nxt] == grey:
                        cycle = path[path.index(nxt):] + [nxt]
                        self.report(self.graph_path, self.line_of(node), "cycle",
                                    "cycle: " + " -> ".join(cycle))
                    elif color[nxt] == white:
                        color[nxt] = grey
                        stack.append((nxt, 0))
                        path.append(nxt)
                else:
                    color[node] = black
                    stack.pop()
                    path.pop()

    # ── module declarations ──────────────────────────────────────────────
    def module_numbers(self) -> dict[str, int]:
        path = self.root / MODULE_NUMBERS
        if not path.is_file():
            return {}
        text = path.read_text()
        out = {m.group(1): int(m.group(2)) for m in NUMBER_RE.finditer(text)}
        out.pop("max", None)
        for m in RESERVED_RE.finditer(text):
            out.setdefault(m.group(2).lower(), int(m.group(1)))
        return out

    def check_modules(self) -> None:
        services = self.root / "services"
        modules = sorted(p.name for p in services.iterdir()
                         if p.is_dir() and not p.name.startswith(".")) \
            if services.is_dir() else []
        numbers = self.module_numbers()
        declared: set[str] = set()
        by_module: dict[str, list[Component]] = {}
        for c in self.components.values():
            if c.module:
                by_module.setdefault(c.module, []).append(c)
        for m in modules:
            decl = services / m / DECLARATION
            if not decl.is_file():
                self.report(services / m, 1, "module-declaration",
                            f"module `{m}` has no {DECLARATION}; every module "
                            f"declares its cold-start needs next to its "
                            f"module number")
                continue
            declared.add(m)
            self.check_declaration(m, decl, numbers, by_module.get(m, []))
        for m, comps in sorted(by_module.items()):
            for c in comps:
                if m in declared and c.planned:
                    self.report(self.graph_path, c.line, "stale-planned",
                                f"`{c.name}` is planned, but module `{m}` "
                                f"declares it; drop `planned`")
                elif m not in declared and not c.planned:
                    self.report(self.graph_path, c.line, "module-declaration",
                                f"`{c.name}` belongs to module `{m}`, which "
                                f"declares nothing (services/{m}/{DECLARATION})")

    def check_declaration(self, m: str, decl: Path, numbers: dict[str, int],
                          comps: list[Component]) -> None:
        try:
            data, lines = load_yaml(decl)
        except yaml.YAMLError as e:
            self.report(decl, 1, "schema", f"not valid YAML: {e}")
            return
        if not isinstance(data, dict) or set(data) != {"module_number", "components"} \
                or not isinstance(data["components"], dict):
            self.report(decl, 1, "schema",
                        "a declaration is a mapping of `module_number` and "
                        "`components` (name: {needs: [...]})")
            return
        number = data["module_number"]
        want = numbers.get(m)
        if want is None:
            self.report(decl, 1, "module-number",
                        f"{MODULE_NUMBERS} gives module `{m}` no number")
        elif number != want:
            self.report(decl, 1, "module-number",
                        f"module_number is {number!r}; {MODULE_NUMBERS} says "
                        f"{want}")
        graph = {c.name: c for c in comps}
        for name, body in data["components"].items():
            line = lines.get(str(name), 1)
            if not isinstance(body, dict) or set(body) != {"needs"}:
                self.report(decl, line, "schema",
                            f"`{name}` must be a mapping with one key, `needs`")
                continue
            needs = self.parse_needs(decl, line, str(name), body["needs"])
            if needs is None:
                continue
            c = graph.pop(str(name), None)
            if c is None:
                where = self.components.get(str(name))
                why = (f"the graph gives it to module `{where.module}`"
                       if where and where.module else
                       "the graph does not give it to this module")
                self.report(decl, line, "module-disagrees",
                            f"declares `{name}`, but {why}")
                continue
            if set(needs) != set(c.needs):
                extra = sorted(set(needs) - set(c.needs))
                missing = sorted(set(c.needs) - set(needs))
                parts = []
                if extra:
                    parts.append("declares " + ", ".join(extra) +
                                 " the graph does not")
                if missing:
                    parts.append("the graph has " + ", ".join(missing) +
                                 " the declaration does not")
                self.report(decl, line, "module-disagrees",
                            f"`{name}` needs differ: " + "; ".join(parts))
        for name in sorted(graph):
            self.report(decl, 1, "module-disagrees",
                        f"the graph gives `{name}` to module `{m}`, but the "
                        f"declaration does not list it")

    # ── entry points ─────────────────────────────────────────────────────
    def run(self) -> list[Violation]:
        if self.load_graph():
            self.check_edges()
            self.check_cycles()
            self.check_modules()
        return sorted(set(self.violations))


# ── rendering ────────────────────────────────────────────────────────────

def start_order(components: dict[str, Component]) -> list[Component]:
    """Components in an order that respects every need: by tier, then by
    depth (the longest chain of needs below it), then name, so the table
    reads as waves. Assumes the graph passed the check; a component on a
    cycle gets the depth reached when the cycle is found."""
    depth: dict[str, int] = {}

    def depth_of(name: str, seen: frozenset[str]) -> int:
        if name in depth:
            return depth[name]
        if name in seen:
            return 0
        needs = [n for n in components[name].needs if n in components]
        d = 1 + max((depth_of(n, seen | {name}) for n in needs), default=-1)
        depth[name] = d
        return d

    return sorted(components.values(),
                  key=lambda c: (c.tier, depth_of(c.name, frozenset()), c.name))


def render(components: dict[str, Component]) -> str:
    order = start_order(components)
    lines = [
        BEGIN,
        "<!-- Generated from config/cold_start_graph.yaml by",
        "     tools/cold_start_graph/check_cold_start_graph.py --render.",
        "     Do not edit by hand; CI fails when this is stale. -->",
        "",
    ]
    for tier in TIERS:
        rows = [c for c in order if c.tier == tier]
        if not rows:
            continue
        lines += [f"### {TIER_NAMES[tier]}", "",
                  "| # | Component | Restarts | Needs | Owner | Notes |",
                  "|---|-----------|----------|-------|-------|-------|"]
        for i, c in enumerate(rows, 1):
            needs = ", ".join(f"`{n}`" for n in c.needs) or "power only"
            owner = (f"`services/{c.module}`" if c.module else
                     c.repo if c.repo else "core")
            notes = c.description.replace("|", "\\|")
            if c.planned:
                notes = "**planned.** " + notes
            restart = "locally" if c.restart == "local" else "by the controller"
            lines.append(f"| {i} | `{c.name}` | {restart} | {needs} | "
                         f"{owner} | {notes} |")
        lines.append("")
    lines += ["```mermaid", "flowchart BT"]
    for tier in TIERS:
        rows = [c for c in order if c.tier == tier]
        if not rows:
            continue
        lines.append(f'  subgraph t{tier}["{TIER_NAMES[tier]}"]')
        for c in rows:
            label = c.name + (" (planned)" if c.planned else "")
            lines.append(f'    {c.name}["{label}"]')
        lines.append("  end")
    for c in order:
        for n in c.needs:
            lines.append(f"  {c.name} --> {n}")
    lines += ["```", "", END]
    return "\n".join(lines) + "\n"


def splice(text: str, section: str) -> str | None:
    begin = text.find(BEGIN)
    end = text.find(END)
    if begin < 0 or end < begin:
        return None
    end += len(END)
    if text[end:end + 1] == "\n":
        end += 1
    return text[:begin] + section + text[end:]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--root", type=Path,
                    default=Path(__file__).resolve().parent.parent.parent,
                    help="source tree to check (default: this repository)")
    ap.add_argument("--graph", type=Path, default=None,
                    help=f"graph, relative to --root (default: {GRAPH})")
    ap.add_argument("--runbook", type=Path, default=RUNBOOK,
                    help=f"runbook, relative to --root (default: {RUNBOOK})")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check-rendered", action="store_true",
                      help="also fail if the runbook's generated section is stale")
    mode.add_argument("--render", action="store_true",
                      help="rewrite the runbook's generated section")
    args = ap.parse_args(argv)

    checker = Checker(args.root, args.graph)
    violations = checker.run()
    runbook = checker.root / args.runbook
    if not violations and (args.render or args.check_rendered):
        if not runbook.is_file():
            violations.append(Violation(checker.rel(runbook), 1, "rendered-stale",
                                        "the runbook is missing"))
        else:
            text = runbook.read_text()
            new = splice(text, render(checker.components))
            if new is None:
                violations.append(Violation(
                    checker.rel(runbook), 1, "rendered-stale",
                    f"the runbook has no {BEGIN} ... {END} section"))
            elif args.render:
                if new != text:
                    runbook.write_text(new)
                    print(f"check_cold_start_graph: rewrote {checker.rel(runbook)}")
            elif new != text:
                line = text[:text.find(BEGIN)].count("\n") + 1
                violations.append(Violation(
                    checker.rel(runbook), line, "rendered-stale",
                    "the generated section does not match the graph; run "
                    "tools/cold_start_graph/check_cold_start_graph.py --render"))
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    for v in violations:
        print(v.render())
        if gha:
            print(f"::error file={v.file},line={v.line}::[{v.rule}] {v.message}")
    if violations:
        print(f"check_cold_start_graph: {len(violations)} violation(s)",
              file=sys.stderr)
        return 1
    print(f"check_cold_start_graph: {len(checker.components)} components, "
          f"no cycles, tiers respected, every module declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
