#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""Choose a runner pool for each background job (doc/ci_runner_pools.md).

Background runs -- scheduled and dispatched workflows -- can use either the
self-hosted bit63 scale set or GitHub's hosted ubuntu-24.04 runners. bit63
has few slots (ten) and is shared with bit63-org/antikythera; the hosted pool
is mostly idle once pull-request CI runs on bit63. This script looks at what
both pools are doing right now, across every repository that shares bit63,
and hands each named job the pool with room for it:

  1. a free bit63 slot, keeping `reserve` slots back for blocking
     pull-request CI;
  2. otherwise a free hosted slot;
  3. otherwise whichever pool has the shorter backlog per slot.

Jobs are placed one at a time, each placement counting as a queued job for
the next, so a wide matrix spreads across both pools instead of piling onto
whichever looked emptier first.

It only ever splits background runs. A pull request or push, a fork, or a
KYTHIRA_X64_RUNNER kill switch that already points away from bit63 gets the
caller's default runner for every job, unchanged.

Inputs come from the environment (see .github/actions/pick-runner); the
result is a JSON object {job name: runner label} written to $GITHUB_OUTPUT
as `runners`, plus a table in the step summary.

Run the tests: python3 scripts/tests/test_pick_runner.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

BACKGROUND_EVENTS = ("schedule", "workflow_dispatch")
# Statuses a job holds before it has a runner. "waiting" is an environment
# approval, which holds no slot yet but will want one.
QUEUED_STATES = ("queued", "waiting", "pending", "requested")
# Runs listed per (repository, status). Past this the job counts of the
# runs that were read are scaled up to the run total, which costs accuracy
# but caps the API calls a pick makes.
MAX_RUNS = 30


@dataclass
class Pool:
    label: str
    capacity: int
    running: int = 0
    queued: int = 0

    def effective_capacity(self) -> int:
        # A pool seen running more jobs than configured (the scale set was
        # raised, or the hosted limit is higher than assumed) has at least
        # that many slots.
        return max(self.capacity, self.running, 1)

    def free(self, reserve: int = 0) -> int:
        return self.effective_capacity() - self.running - self.queued - reserve

    def backlog(self) -> float:
        # Jobs ahead of a new one, per slot, counting the new one.
        return (self.running + self.queued + 1) / self.effective_capacity()


@dataclass
class Load:
    self_hosted: Pool
    hosted: Pool
    notes: list[str] = field(default_factory=list)


def classify(labels: list[str], self_label: str) -> str | None:
    """Which pool a job's runs-on labels put it in, or None."""
    if self_label in labels:
        return "self"
    # Every GitHub-hosted Linux job, arm64 included, counts against the same
    # account-wide concurrency limit.
    if any(label.startswith("ubuntu-") for label in labels):
        return "hosted"
    return None


def place(names: list[str], load: Load, reserve: int,
          pinned: set[str]) -> dict[str, str]:
    """Assign each job name a runner label, updating `load` as it goes."""
    sh, gh = load.self_hosted, load.hosted
    out: dict[str, str] = {}
    # Pinned jobs first, so they take bit63 room before anything that could
    # have gone elsewhere does.
    for name in sorted(names, key=lambda n: n not in pinned):
        if name in pinned:
            pool = sh
        elif sh.free(reserve) > 0:
            pool = sh
        elif gh.free() > 0:
            pool = gh
        else:
            # Both full: the shorter backlog per slot. A tie goes to bit63,
            # whose LAN build cache makes the same job faster.
            pool = sh if sh.backlog() <= gh.backlog() else gh
        pool.queued += 1
        out[name] = pool.label
    return out


def api_get(api: str, path: str, token: str | None) -> dict:
    def fetch(auth: str | None) -> dict:
        req = urllib.request.Request(api + path)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if auth:
            req.add_header("Authorization", f"Bearer {auth}")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.load(resp)
    try:
        return fetch(token)
    except urllib.error.HTTPError as exc:
        # A job token is scoped to its own repository. The other repositories
        # sharing bit63 are public, so their runs can still be read without
        # one (at the lower anonymous rate limit).
        if token and exc.code in (401, 403, 404):
            return fetch(None)
        raise


def measure(repos: list[str], load: Load, api: str, token: str | None,
            own_run: str, get=api_get) -> bool:
    """Add every repository's live jobs to `load`. False if none was read."""
    read_any = False
    for repo in repos:
        try:
            counts = _measure_repo(repo, load, api, token, own_run, get)
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            load.notes.append(f"{repo}: not read ({exc})")
            continue
        read_any = True
        load.notes.append(f"{repo}: {counts}")
    return read_any


def _measure_repo(repo, load, api, token, own_run, get) -> str:
    tally = {"self": [0, 0], "hosted": [0, 0]}  # [running, queued]
    for status in ("in_progress", "queued"):
        page = get(api, f"/repos/{repo}/actions/runs?status={status}"
                        f"&per_page={MAX_RUNS}", token)
        listed = page.get("workflow_runs", [])
        runs = [r for r in listed if str(r.get("id")) != own_run]
        # This run is in progress too; leave it out of the total as well.
        total = page.get("total_count", len(listed)) - (len(listed) - len(runs))
        total = max(total, len(runs))
        part = {"self": [0, 0], "hosted": [0, 0]}
        for run in runs:
            jobs = get(api, f"/repos/{repo}/actions/runs/{run['id']}/jobs"
                            f"?filter=latest&per_page=100", token)
            for job in jobs.get("jobs", []):
                pool = classify(job.get("labels", []),
                                load.self_hosted.label)
                if pool is None:
                    continue
                if job.get("status") == "in_progress":
                    part[pool][0] += 1
                elif job.get("status") in QUEUED_STATES:
                    part[pool][1] += 1
        scale = total / len(runs) if runs else 1.0
        for pool in part:
            tally[pool][0] += part[pool][0]
            # Only queued counts are extrapolated: running jobs are bounded
            # by the slots, and the first runs listed are the newest anyway.
            tally[pool][1] += round(part[pool][1] * scale)
    load.self_hosted.running += tally["self"][0]
    load.self_hosted.queued += tally["self"][1]
    load.hosted.running += tally["hosted"][0]
    load.hosted.queued += tally["hosted"][1]
    return (f"{load.self_hosted.label} {tally['self'][0]} running "
            f"{tally['self'][1]} queued, hosted {tally['hosted'][0]} running "
            f"{tally['hosted'][1]} queued")


def decide(env: dict[str, str], get=api_get) -> tuple[dict[str, str], list[str]]:
    names = env.get("PICK_JOBS", "").split()
    default = env.get("PICK_DEFAULT", "").strip() or "ubuntu-24.04"
    self_label = env.get("PICK_SELF_HOSTED", "").strip() or "bit63"
    hosted_label = env.get("PICK_HOSTED", "").strip() or "ubuntu-24.04"
    mode = env.get("PICK_MODE", "").strip() or "auto"
    event = env.get("PICK_EVENT", "")
    pinned = set(env.get("PICK_PIN_SELF_HOSTED", "").split())

    def everyone(label: str, why: str):
        return {n: label for n in names}, [why]

    if event not in BACKGROUND_EVENTS:
        return everyone(default, f"{event or 'unknown'} event: not a background run")
    if default != self_label:
        return everyone(default, f"default runner is {default}, not {self_label} "
                                 "(fork or KYTHIRA_X64_RUNNER kill switch)")
    if mode == "off":
        return everyone(default, "KYTHIRA_BACKGROUND_POOLS=off")
    if mode != "auto":
        return everyone(mode, f"KYTHIRA_BACKGROUND_POOLS pins background jobs to {mode}")

    load = Load(Pool(self_label, int(env.get("PICK_SELF_HOSTED_CAPACITY") or 10)),
                Pool(hosted_label, int(env.get("PICK_HOSTED_CAPACITY") or 20)))
    reserve = int(env.get("PICK_RESERVE") or 1)
    repos = env.get("PICK_REPOS", "").split() or [env.get("GITHUB_REPOSITORY", "")]
    api = env.get("GITHUB_API_URL", "https://api.github.com")
    ok = measure(repos, load, api, env.get("GH_TOKEN") or None,
                 env.get("GITHUB_RUN_ID", ""), get)
    if not ok:
        # No load figures at all: alternate, so the work still splits.
        out = {}
        for i, name in enumerate(names):
            out[name] = self_label if name in pinned or i % 2 == 0 else hosted_label
        return out, load.notes + ["no load read; alternating pools"]
    before = (f"before: {self_label} {load.self_hosted.running} running "
              f"{load.self_hosted.queued} queued of {load.self_hosted.effective_capacity()}; "
              f"{hosted_label} {load.hosted.running} running {load.hosted.queued} "
              f"queued of {load.hosted.effective_capacity()}; reserve {reserve}")
    return place(names, load, reserve, pinned), load.notes + [before]


def main() -> int:
    try:
        runners, notes = decide(dict(os.environ))
    except Exception as exc:  # noqa: BLE001 -- a pick must never fail a run
        default = os.environ.get("PICK_DEFAULT", "").strip() or "ubuntu-24.04"
        runners = {n: default for n in os.environ.get("PICK_JOBS", "").split()}
        notes = [f"pick failed ({exc!r}); every job keeps {default}"]
        print(f"::warning::runner pick failed ({exc!r}); using {default}")
    for note in notes:
        print(note)
    for name, label in runners.items():
        print(f"{name} -> {label}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"runners={json.dumps(runners, separators=(',', ':'))}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### Runner pools for this run\n\n")
            for note in notes:
                fh.write(f"- {note}\n")
            fh.write("\n| Job | Runner |\n|---|---|\n")
            for name, label in runners.items():
                fh.write(f"| {name} | {label} |\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
