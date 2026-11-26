#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/pick-runner.py (doc/ci_runner_pools.md).

Run: python3 scripts/tests/test_pick_runner.py
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "pick-runner.py"
spec = importlib.util.spec_from_file_location("pick_runner", SCRIPT)
pr = importlib.util.module_from_spec(spec)
sys.modules["pick_runner"] = pr  # dataclasses look their module up here
spec.loader.exec_module(pr)


def fake_api(repos: dict[str, list[list[tuple[list[str], str]]]],
             in_progress_ids=(), fail=()):
    """repos: name -> list of runs, each a list of (labels, status) jobs."""
    def get(api, path, token):
        for repo, runs in repos.items():
            if not path.startswith(f"/repos/{repo}/"):
                continue
            if repo in fail:
                raise urllib.error.URLError("refused")
            if "/jobs" in path:
                rid = int(path.split("/runs/")[1].split("/")[0])
                jobs = runs[rid - 1]
                return {"jobs": [{"labels": l, "status": s} for l, s in jobs]}
            want = "in_progress" if "in_progress" in path else "queued"
            listed = [{"id": i + 1} for i in range(len(runs))
                      if ((i + 1) in in_progress_ids) == (want == "in_progress")]
            return {"total_count": len(listed), "workflow_runs": listed}
        raise AssertionError(path)
    return get


BASE = {
    "PICK_EVENT": "schedule",
    "PICK_DEFAULT": "bit63",
    "PICK_REPOS": "o/a o/b",
    "PICK_SELF_HOSTED_CAPACITY": "6",
}


class PlaceTest(unittest.TestCase):
    def load(self, sr=0, sq=0, hr=0, hq=0, scap=6, hcap=20):
        return pr.Load(pr.Pool("bit63", scap, sr, sq),
                       pr.Pool("ubuntu-24.04", hcap, hr, hq))

    def test_free_bit63_slots_first_then_hosted(self):
        # 6 slots, 3 busy, 1 reserved: two jobs fit on bit63, the rest go hosted.
        out = pr.place([f"j{i}" for i in range(5)], self.load(sr=3), 1, set())
        self.assertEqual([out[f"j{i}"] for i in range(5)],
                         ["bit63", "bit63", "ubuntu-24.04", "ubuntu-24.04",
                          "ubuntu-24.04"])

    def test_reserve_keeps_slot_for_pr_ci(self):
        out = pr.place(["x"], self.load(sr=5), 1, set())
        self.assertEqual(out["x"], "ubuntu-24.04")

    def test_both_full_takes_shorter_backlog(self):
        # bit63: (6+30+1)/6 ~ 6.2; hosted: (20+40+1)/20 ~ 3.1.
        out = pr.place(["x"], self.load(sr=6, sq=30, hr=20, hq=40), 1, set())
        self.assertEqual(out["x"], "ubuntu-24.04")
        out = pr.place(["x"], self.load(sr=6, sq=2, hr=20, hq=200), 1, set())
        self.assertEqual(out["x"], "bit63")

    def test_wide_matrix_spreads_when_both_full(self):
        out = pr.place([f"s{i}" for i in range(6)],
                       self.load(sr=6, sq=6, hr=20, hq=20), 1, set())
        labels = sorted(out.values())
        self.assertIn("bit63", labels)
        self.assertIn("ubuntu-24.04", labels)

    def test_pinned_job_stays_on_bit63(self):
        out = pr.place(["heavy", "light"], self.load(sr=6, sq=50), 1, {"heavy"})
        self.assertEqual(out, {"heavy": "bit63", "light": "ubuntu-24.04"})

    def test_observed_running_raises_capacity(self):
        # Ten seen running on a "6-slot" pool: it has at least ten.
        self.assertEqual(self.load(sr=10).self_hosted.effective_capacity(), 10)


class DecideTest(unittest.TestCase):
    def test_pull_request_keeps_default(self):
        out, notes = pr.decide({**BASE, "PICK_EVENT": "pull_request",
                                "PICK_JOBS": "a b"})
        self.assertEqual(out, {"a": "bit63", "b": "bit63"})
        self.assertIn("not a background run", notes[0])

    def test_kill_switch_keeps_default(self):
        out, _ = pr.decide({**BASE, "PICK_DEFAULT": "ubuntu-24.04",
                            "PICK_JOBS": "a"})
        self.assertEqual(out, {"a": "ubuntu-24.04"})

    def test_mode_off_and_pin(self):
        out, _ = pr.decide({**BASE, "PICK_MODE": "off", "PICK_JOBS": "a"})
        self.assertEqual(out, {"a": "bit63"})
        out, _ = pr.decide({**BASE, "PICK_MODE": "ubuntu-24.04", "PICK_JOBS": "a"})
        self.assertEqual(out, {"a": "ubuntu-24.04"})

    def test_counts_both_repositories(self):
        # o/a: 4 bit63 running; o/b (antikythera): 2 bit63 queued. bit63 is
        # full, so the job goes hosted.
        api = fake_api({
            "o/a": [[(["bit63"], "in_progress")] * 4],
            "o/b": [[(["bit63"], "queued")] * 2],
        }, in_progress_ids={1})
        out, notes = pr.decide({**BASE, "PICK_JOBS": "x"}, get=api)
        self.assertEqual(out, {"x": "ubuntu-24.04"})
        self.assertTrue(any("4 running" in n for n in notes))

    def test_idle_pools_use_bit63(self):
        api = fake_api({"o/a": [], "o/b": []})
        out, _ = pr.decide({**BASE, "PICK_JOBS": "x"}, get=api)
        self.assertEqual(out, {"x": "bit63"})

    def test_default_bit63_capacity_is_the_scale_set_max(self):
        # Nine of ten slots busy and one reserved: full at the default 10.
        api = fake_api({"o/a": [[(["bit63"], "in_progress")] * 9], "o/b": []},
                       in_progress_ids={1})
        env = {k: v for k, v in BASE.items() if k != "PICK_SELF_HOSTED_CAPACITY"}
        out, notes = pr.decide({**env, "PICK_JOBS": "x"}, get=api)
        self.assertEqual(out, {"x": "ubuntu-24.04"})
        self.assertTrue(any("of 10" in n for n in notes))

    def test_one_repository_unreadable_still_picks(self):
        api = fake_api({"o/a": [[(["bit63"], "in_progress")] * 5],
                        "o/b": []}, in_progress_ids={1}, fail={"o/b"})
        out, notes = pr.decide({**BASE, "PICK_JOBS": "x"}, get=api)
        self.assertEqual(out, {"x": "ubuntu-24.04"})
        self.assertTrue(any("o/b: not read" in n for n in notes))

    def test_nothing_readable_alternates(self):
        api = fake_api({"o/a": [], "o/b": []}, fail={"o/a", "o/b"})
        out, _ = pr.decide({**BASE, "PICK_JOBS": "a b c"}, get=api)
        self.assertEqual(out, {"a": "bit63", "b": "ubuntu-24.04", "c": "bit63"})

    def test_arm_jobs_count_as_hosted(self):
        self.assertEqual(pr.classify(["ubuntu-24.04-arm"], "bit63"), "hosted")
        self.assertIsNone(pr.classify(["macos-14"], "bit63"))


class MainTest(unittest.TestCase):
    def test_writes_json_output_and_never_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            env = {**os.environ, "PICK_EVENT": "schedule", "PICK_DEFAULT": "bit63",
                   "PICK_JOBS": "a", "PICK_SELF_HOSTED_CAPACITY": "not-a-number",
                   "GITHUB_OUTPUT": str(out)}
            env.pop("GITHUB_STEP_SUMMARY", None)
            res = subprocess.run([sys.executable, str(SCRIPT)], env=env,
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(out.read_text(), 'runners={"a":"bit63"}\n')


if __name__ == "__main__":
    unittest.main()
