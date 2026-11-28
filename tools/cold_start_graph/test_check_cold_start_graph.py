#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Tests for tools/cold_start_graph/check_cold_start_graph.py.

Each test writes a miniature source tree (a graph, a service_module.hpp,
services/<m>/cold_start.yaml declarations and a runbook) into a temporary
directory and checks the exact violations the checker reports. The last
tests run the checker on this repository, so the real graph is held to the
same rules.

Run: python3 tools/cold_start_graph/test_check_cold_start_graph.py
"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
import check_cold_start_graph as ccg  # noqa: E402

MODULE_NUMBERS = """\
namespace module_numbers {
inline constexpr std::uint8_t alpha = 1;
inline constexpr std::uint8_t beta = 2;
/// 3 is reserved for the GAMMA module (.kiro/specs/gamma/).
inline constexpr std::uint8_t max = 254;
}
"""

# A graph that passes: two local tier-0 components, a storage tier, a
# module that owns two components and a planned module.
GOOD = """\
components:
  power_box:
    tier: 0
    restart: local
    needs: []
  alpha:
    tier: 0
    restart: local
    module: alpha
    needs: [power_box]
  store:
    tier: 1
    restart: local
    needs: [alpha]
  beta_front:
    tier: 2
    restart: controller
    module: beta
    needs: [store, alpha]
  beta_back:
    tier: 2
    restart: controller
    module: beta
    needs: [store]
  delta:
    tier: 3
    restart: controller
    module: delta
    planned: true
    needs: [beta_front]
"""

DECLS = {
    "alpha": "module_number: 1\ncomponents:\n  alpha:\n    needs: [power_box]\n",
    "beta": ("module_number: 2\ncomponents:\n"
             "  beta_front:\n    needs: [alpha, store]\n"
             "  beta_back:\n    needs: [store]\n"),
}

RUNBOOK = f"# Runbook\n\nIntro.\n\n{ccg.BEGIN}\n{ccg.END}\n\nOutro.\n"


class Tree:
    """A temporary source tree. Paths are relative to its root."""

    def __init__(self, graph: str = GOOD, decls: dict[str, str] | None = None,
                 numbers: str = MODULE_NUMBERS, runbook: str = RUNBOOK) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.write("config/cold_start_graph.yaml", graph)
        self.write("include/raft/service_module.hpp", numbers)
        self.write("doc/runbooks/az-cold-start.md", runbook)
        for m, text in (DECLS if decls is None else decls).items():
            self.write(f"services/{m}/cold_start.yaml", text)

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text))

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text()

    def check(self) -> list[ccg.Violation]:
        return ccg.Checker(self.root).run()

    def main(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = ccg.main(["--root", str(self.root), *args])
        return rc, out.getvalue()

    def close(self) -> None:
        self._dir.cleanup()


def rules(violations: list[ccg.Violation]) -> list[str]:
    return [v.rule for v in violations]


def with_component(graph: str, text: str) -> str:
    return graph + textwrap.indent(textwrap.dedent(text), "  ")


class Base(unittest.TestCase):
    def tree(self, **kw) -> Tree:
        t = Tree(**kw)
        self.addCleanup(t.close)
        return t


class GraphRules(Base):
    def test_good_graph_passes(self) -> None:
        self.assertEqual(self.tree().check(), [])

    def test_cycle_is_refused_and_named(self) -> None:
        graph = with_component(GOOD, """\
            cyc_a:
              tier: 0
              restart: local
              needs: [power_box, cyc_c]
            cyc_b:
              tier: 0
              restart: local
              needs: [cyc_a]
            cyc_c:
              tier: 0
              restart: local
              needs: [cyc_b]
            """)
        v = self.tree(graph=graph).check()
        self.assertEqual(rules(v), ["cycle"], v)
        self.assertIn("cyc_a -> cyc_c -> cyc_b -> cyc_a", v[0].message)
        self.assertEqual(v[0].file, "config/cold_start_graph.yaml")

    def test_self_need_is_a_cycle(self) -> None:
        graph = GOOD.replace("needs: [alpha]", "needs: [alpha, store]")
        v = self.tree(graph=graph).check()
        self.assertEqual(rules(v), ["cycle"], v)
        self.assertIn("store -> store", v[0].message)

    def test_tier_inversion_is_refused(self) -> None:
        graph = GOOD.replace("needs: [store]", "needs: [store, delta]")
        v = self.tree(graph=graph).check()
        self.assertIn("tier-inversion", rules(v))
        msg = next(x for x in v if x.rule == "tier-inversion").message
        self.assertIn("`beta_back` (tier 2) needs `delta` (tier 3)", msg)
        # Points at beta_back's own line.
        line = next(x for x in v if x.rule == "tier-inversion").line
        self.assertEqual(GOOD.splitlines()[line - 1].strip(), "beta_back:")

    def test_tier0_need_on_a_controller_restart_is_refused(self) -> None:
        graph = GOOD.replace(
            "  power_box:\n    tier: 0\n    restart: local",
            "  power_box:\n    tier: 0\n    restart: controller")
        v = self.tree(graph=graph).check()
        self.assertEqual(rules(v), ["tier0-local"], v)
        self.assertIn("`power_box` does not restart from local state", v[0].message)

    def test_tier0_controller_component_with_no_tier0_edges_passes(self) -> None:
        # Requirement 1.2 restricts tier-0 to tier-0 edges only.
        graph = with_component(GOOD, """\
            lonely:
              tier: 0
              restart: controller
              needs: []
            """)
        self.assertEqual(self.tree(graph=graph).check(), [])

    def test_unknown_need_is_refused(self) -> None:
        graph = GOOD.replace("needs: [beta_front]", "needs: [beta_front, ghost]")
        v = self.tree(graph=graph).check()
        self.assertEqual(rules(v), ["unknown-need"], v)
        self.assertIn("`ghost`", v[0].message)


class Schema(Base):
    def assert_schema(self, graph: str, fragment: str) -> None:
        v = self.tree(graph=graph).check()
        self.assertTrue(any(x.rule == "schema" and fragment in x.message for x in v),
                        v)

    def test_bad_tier(self) -> None:
        self.assert_schema(GOOD.replace("tier: 3", "tier: 4"), "tier must be 0-3")

    def test_boolean_tier(self) -> None:
        self.assert_schema(GOOD.replace("tier: 3", "tier: true"), "tier must be 0-3")

    def test_bad_restart(self) -> None:
        self.assert_schema(GOOD.replace("restart: controller", "restart: maybe", 1),
                           "restart must be")

    def test_unknown_field(self) -> None:
        self.assert_schema(GOOD.replace("planned: true", "planed: true"),
                           "unknown field `planed`")

    def test_missing_needs(self) -> None:
        self.assert_schema(GOOD.replace("    needs: [beta_front]\n", ""),
                           "has no `needs`")

    def test_duplicate_need(self) -> None:
        self.assert_schema(GOOD.replace("needs: [store]", "needs: [store, store]"),
                           "needs `store` twice")

    def test_needs_not_a_list(self) -> None:
        self.assert_schema(GOOD.replace("needs: [store]", "needs: store"),
                           "needs must be a list")

    def test_bad_name(self) -> None:
        self.assert_schema(GOOD.replace("power_box", "Power-Box"),
                           "is not [a-z][a-z0-9_]*")

    def test_not_a_mapping(self) -> None:
        self.assert_schema("- just\n- a list\n", "one key, `components`")

    def test_invalid_yaml(self) -> None:
        self.assert_schema("components: [\n", "not valid YAML")

    def test_missing_graph(self) -> None:
        t = self.tree()
        (t.root / "config/cold_start_graph.yaml").unlink()
        self.assertEqual(rules(t.check()), ["schema"])


class Modules(Base):
    def test_module_without_declaration_is_refused(self) -> None:
        t = self.tree()
        (t.root / "services/epsilon").mkdir()
        v = t.check()
        self.assertEqual(rules(v), ["module-declaration"], v)
        self.assertEqual(v[0].file, "services/epsilon")

    def test_graph_module_that_declares_nothing_is_refused(self) -> None:
        decls = {"alpha": DECLS["alpha"]}
        v = self.tree(decls=decls).check()
        self.assertEqual(rules(v), ["module-declaration"] * 2, v)
        self.assertTrue(all("module `beta`" in x.message for x in v))

    def test_planned_module_may_declare_nothing(self) -> None:
        # GOOD's delta is planned and has no directory: no violation.
        self.assertEqual(self.tree().check(), [])

    def test_planned_component_whose_module_declares_it_is_stale(self) -> None:
        decls = dict(DECLS)
        decls["delta"] = "module_number: 3\ncomponents:\n  delta:\n    needs: [beta_front]\n"
        numbers = MODULE_NUMBERS.replace(
            "/// 3 is reserved", "inline constexpr std::uint8_t delta = 3;\n/// 9 is reserved")
        v = self.tree(decls=decls, numbers=numbers).check()
        self.assertEqual(rules(v), ["stale-planned"], v)

    def test_module_number_must_match(self) -> None:
        decls = dict(DECLS)
        decls["alpha"] = DECLS["alpha"].replace("module_number: 1", "module_number: 7")
        v = self.tree(decls=decls).check()
        self.assertEqual(rules(v), ["module-number"], v)
        self.assertIn("says 1", v[0].message)

    def test_reserved_module_number_counts(self) -> None:
        graph = with_component(GOOD, """\
            gamma:
              tier: 2
              restart: controller
              module: gamma
              needs: [alpha]
            """)
        decls = dict(DECLS)
        decls["gamma"] = "module_number: 3\ncomponents:\n  gamma:\n    needs: [alpha]\n"
        self.assertEqual(self.tree(graph=graph, decls=decls).check(), [])

    def test_module_with_no_number_is_refused(self) -> None:
        graph = with_component(GOOD, """\
            zeta:
              tier: 2
              restart: controller
              module: zeta
              needs: []
            """)
        decls = dict(DECLS)
        decls["zeta"] = "module_number: 12\ncomponents:\n  zeta:\n    needs: []\n"
        v = self.tree(graph=graph, decls=decls).check()
        self.assertEqual(rules(v), ["module-number"], v)

    def test_declared_needs_must_match_the_graph(self) -> None:
        decls = dict(DECLS)
        decls["beta"] = DECLS["beta"].replace("needs: [alpha, store]",
                                              "needs: [alpha, power_box]")
        v = self.tree(decls=decls).check()
        self.assertEqual(rules(v), ["module-disagrees"], v)
        self.assertIn("declares power_box the graph does not", v[0].message)
        self.assertIn("the graph has store the declaration does not", v[0].message)
        self.assertEqual(v[0].file, "services/beta/cold_start.yaml")
        self.assertEqual(v[0].line, 3)

    def test_need_order_does_not_matter(self) -> None:
        # DECLS lists beta_front's needs in another order than GOOD.
        self.assertEqual(self.tree().check(), [])

    def test_declaration_missing_a_component_is_refused(self) -> None:
        decls = dict(DECLS)
        decls["beta"] = "module_number: 2\ncomponents:\n  beta_back:\n    needs: [store]\n"
        v = self.tree(decls=decls).check()
        self.assertEqual(rules(v), ["module-disagrees"], v)
        self.assertIn("`beta_front`", v[0].message)

    def test_declaration_of_another_modules_component_is_refused(self) -> None:
        decls = dict(DECLS)
        decls["beta"] = DECLS["beta"] + "  alpha:\n    needs: [power_box]\n"
        v = self.tree(decls=decls).check()
        self.assertEqual(rules(v), ["module-disagrees"], v)
        self.assertIn("gives it to module `alpha`", v[0].message)

    def test_malformed_declaration_is_refused(self) -> None:
        decls = dict(DECLS)
        decls["alpha"] = "components:\n  alpha:\n    needs: [power_box]\n"
        v = self.tree(decls=decls).check()
        self.assertIn("schema", rules(v))


class Rendering(Base):
    def test_render_then_check_rendered(self) -> None:
        t = self.tree()
        rc, _ = t.main("--check-rendered")
        self.assertEqual(rc, 1)
        rc, _ = t.main("--render")
        self.assertEqual(rc, 0)
        text = t.read("doc/runbooks/az-cold-start.md")
        self.assertTrue(text.startswith("# Runbook\n\nIntro.\n\n" + ccg.BEGIN))
        self.assertTrue(text.endswith(ccg.END + "\n\nOutro.\n"))
        self.assertIn("### Tier 0: bootstrap", text)
        self.assertIn("| 1 | `power_box` | locally | power only | core |", text)
        self.assertIn("**planned.**", text)
        self.assertIn("  beta_front --> store", text)
        rc, out = t.main("--check-rendered")
        self.assertEqual(rc, 0, out)
        # Rendering twice changes nothing.
        t.main("--render")
        self.assertEqual(t.read("doc/runbooks/az-cold-start.md"), text)

    def test_stale_section_is_refused(self) -> None:
        t = self.tree()
        t.main("--render")
        t.write("config/cold_start_graph.yaml",
                GOOD.replace("needs: [beta_front]", "needs: [beta_front, store]"))
        rc, out = t.main("--check-rendered")
        self.assertEqual(rc, 1)
        self.assertIn("[rendered-stale]", out)

    def test_runbook_without_markers_is_refused(self) -> None:
        t = self.tree(runbook="# Runbook\n")
        rc, out = t.main("--check-rendered")
        self.assertEqual(rc, 1)
        self.assertIn("no <!-- cold-start-graph:begin -->", out)

    def test_render_does_not_run_on_a_bad_graph(self) -> None:
        t = self.tree(graph=GOOD.replace("needs: [store]", "needs: [store, delta]"))
        rc, out = t.main("--render")
        self.assertEqual(rc, 1)
        self.assertIn("[tier-inversion]", out)
        self.assertEqual(t.read("doc/runbooks/az-cold-start.md"), RUNBOOK)

    def test_start_order_respects_every_need(self) -> None:
        t = self.tree()
        checker = ccg.Checker(t.root)
        self.assertEqual(checker.run(), [])
        order = [c.name for c in ccg.start_order(checker.components)]
        for c in checker.components.values():
            for n in c.needs:
                self.assertLess(order.index(n), order.index(c.name), (n, c.name))


class ThisRepository(unittest.TestCase):
    def test_repository_graph_passes(self) -> None:
        v = ccg.Checker(REPO).run()
        self.assertEqual(v, [], "\n".join(x.render() for x in v))

    def test_repository_runbook_is_current(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = ccg.main(["--root", str(REPO), "--check-rendered"])
        self.assertEqual(rc, 0, out.getvalue())

    def test_bootstrap_tier_restarts_locally(self) -> None:
        # Requirement 2.1: the services the bootstrap tier must contain are
        # tier 0 and restart from local state.
        checker = ccg.Checker(REPO)
        checker.run()
        for name in ("helm", "hull", "time_sources", "hsm", "kms", "ca", "iam",
                     "ec2_data", "ec2_fleet", "metal_data"):
            c = checker.components[name]
            self.assertEqual((c.tier, c.restart), (0, "local"), name)


if __name__ == "__main__":
    unittest.main()
