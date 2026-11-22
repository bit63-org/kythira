# CI runner pools

Kythira's x86-64 jobs have two places to run:

| Pool | Label | Slots | Notes |
|---|---|---|---|
| bit63 | `bit63` | 10 (the ARC scale set's max) | Self-hosted on reliant-new, shared with bit63-org/antikythera. Reaches the LAN build cache, so a warm build is fast. No rootless Podman. |
| GitHub-hosted | `ubuntu-24.04` | about 20 assumed | Account-wide concurrency limit, shared with arm64 jobs. Uses the OCI build cache. |

Pull-request and `main` CI run on bit63 (`vars.KYTHIRA_X64_RUNNER || 'bit63'`,
see `doc/ci_build_cache.md`). That leaves the hosted pool nearly idle while
ten bit63 slots carry everything, so **background runs split across both**.

## What counts as background

A scheduled or manually dispatched run of:

| Workflow | Jobs placed | Picked in |
|---|---|---|
| `nightly.yml` | x86_64 build, publish | `gate` |
| `real-cloud-tests.yml` | every selected x86_64 job (arm64 legs stay hosted) | `run-plan` |
| `tidy-audit.yml` | the six uncached shards, the report | `pick-runner` |
| `container-tests.yml` | the docker leg (podman is always hosted) | `pick-runner` |

`prune-actions-caches.yml` makes API calls only and runs after every closed
pull request, so it always uses a hosted runner.

Not split, on purpose:

- **Push-to-`main` runs** of `ci.yml` and the module workflows. They write the
  LAN build cache that pull requests read; on a hosted runner they would warm
  only the OCI cache.
- **`cache-cluster-measure.yml`**, which measures the LAN cache itself.
- **`perf-cloud.yml` and `coap-flake-measure.yml`**, whose results depend on
  the machine they ran on. Mixing pools between runs would make them
  incomparable.
- The weekly scheduled runs of `ledger-module.yml` and `redis-module.yml`.
  Those workflows also run on every pull request that touches the module, and
  a picker job there would add a queue wait to each one.
- antikythera. It has no scheduled or dispatched work; its pull-request CI is
  on bit63 and its kernel tests need a GitHub VM. Its jobs do count toward
  bit63's load below.

A pull request that touches one of these workflow files still runs it, and
gets the usual runner for every job: the picker splits only `schedule` and
`workflow_dispatch` runs.

## How a pool is chosen

`scripts/pick-runner.py`, through `.github/actions/pick-runner`, runs in a
small job on the hosted pool before the work starts. It lists the queued and
in-progress runs of every repository sharing bit63 and counts their jobs by
label: `bit63` for bit63, any `ubuntu-*` for hosted. Then it places each job
in turn, counting each placement as queued for the next:

1. bit63, if it has a free slot beyond the **reserve** (default 1) kept for
   blocking pull-request CI;
2. otherwise hosted, if it has a free slot;
3. otherwise whichever has the shorter backlog per slot, with a tie going to
   bit63 for its warm cache.

A pool seen running more jobs than its configured slots is taken to have that
many. Only the first 30 runs per repository and status are read in detail;
past that, queued counts are scaled up to the run total. Jobs held back by
`needs:` also report `queued` in the API, so both backlogs read high, by
roughly the same amount.

The picker never fails a run. If one repository can't be read it is left out.
If none can, jobs alternate between the pools. If the script itself fails,
every job keeps its usual runner. The step summary of the picking job shows
the load it saw and where each job went.

## Settings

All are optional repository variables.

| Variable | Default | Effect |
|---|---|---|
| `KYTHIRA_BACKGROUND_POOLS` | `auto` | `off`: background jobs use the usual runner. A label such as `ubuntu-24.04`: pin every background job to it. |
| `KYTHIRA_SHARED_RUNNER_REPOS` | `bit63-org/kythira bit63-org/antikythera` | Repositories whose jobs count toward bit63's load. |
| `KYTHIRA_BIT63_CAPACITY` | `10` | bit63 slots. Raise it with the scale set's `maxRunners`. |
| `KYTHIRA_HOSTED_CAPACITY` | `20` | Hosted slots to assume. |
| `KYTHIRA_BIT63_RESERVE` | `1` | bit63 slots background jobs leave free. |

The existing kill switch still wins. With `KYTHIRA_X64_RUNNER=ubuntu-24.04`,
the default runner is no longer bit63, so the picker leaves every job on it.
Fork pull requests are never placed on bit63.

## Adding a workflow

1. Give it a cheap first job on `ubuntu-24.04` with `actions: read`, a sparse
   checkout of `.github/actions/pick-runner` and `scripts/pick-runner.py`,
   and a `pick-runner` step listing the job names to place. Copy
   `tidy-audit.yml`'s `pick-runner` job.
2. Make each placed job `needs:` it and use
   `runs-on: ${{ fromJSON(needs.<job>.outputs.runners || '{}')['<name>'] || <usual expression> }}`.
3. Pin to bit63, with the action's `pin-self-hosted` input, any job that needs
   the LAN or more memory than a hosted runner has.
