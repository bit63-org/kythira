# Implementation Plan — `ca_cluster_node` AMI retention

## Status: Done (7/7, 2026-11-26)

Clark gave the go to build it on 2026-11-20 and re-applied the CI role
policy on 2026-11-26. Task 7 ran that day: the dry run (run 45728117310)
planned keep 4 / remove 8 per architecture; with
`REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED=true`, run 45756783128 removed
exactly those 16 AMIs and their 16 snapshots, with no failed call. (It
also kept the previous run's chaos-node image as younger-than-7-days,
since that run's own build had become one of the newest two.)

Decisions made while building:

- The merged CI role policy was at 10,214 of IAM's 10,240 characters, so
  the new conditioned statement did not fit. `render-ci-policy.py` now
  drops, from an unconditioned `Resource: "*"` statement, actions an
  earlier such statement already grants. No permission changes; the nine
  bundles now render to about 8,200.
- Packer tags an AMI only after `CreateImage` returns, so under the
  narrowed grant a build that fails in that window cannot deregister its
  half-made image. It is untagged, so the pruner never touches it either;
  the README says how to find it.
- A launch template whose `ImageId` is a `resolve:ssm:` parameter is not
  matched, like one pinned to an old numbered version; both need the pin.
- With `--apply`, a snapshot is only attempted when its image was
  deregistered; otherwise its delete is certain to fail.

- [x] 1. Write `scripts/ami-retention/prune-amis.sh`
  - Argument parsing (`--arch`, `--keep`, `--min-age-days`, `--apply`), the
    checked `aws` wrapper, the three queries, the plan and its printout.
  - Dry run by default; `--apply` deregisters then deletes snapshots,
    continuing past failures and exiting 1 if any.
  - Copyright header after the shebang; `shellcheck` clean.
  - _Requirements: 1.1, 1.2, 2.1-2.5, 3.1-3.4_

- [x] 2. Write the stub-mode test
  - `scripts/ami-retention/test-prune-amis.sh`, fake `aws`, per-case
    fixtures, a call log; the ten cases of the design.
  - _Requirements: 5.1_

- [x] 3. Run the test and `shellcheck` in CI
  - Add both to ci.yml's `packer-ca-cluster-node` job.
  - _Requirements: 5.2, 5.4_

- [x] 4. Narrow and extend the CI role policy
  - `ami-build.json`: add `DescribeLaunchTemplates` and
    `DescribeLaunchTemplateVersions`; move `DeregisterImage` and
    `DeleteSnapshot` under a `kythira:component` resource-tag condition.
  - Hand Clark the re-provisioning command.
  - _Requirements: 1.3_

- [x] 5. Wire the step into `ami-build`
  - Last step, per arch, dry run unless
    `REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED` is `true`; plan into the job
    summary; `KEEP` / `MIN_AGE` variables.
  - _Requirements: 4.1-4.4_

- [x] 6. Documentation
  - `packer/ca_cluster_node/README.md`: the pruner, keep rules, the
    `kythira:retain=true` pin, the launch-template caveat, the enabling
    variable; keep the manual recipe as the fallback.
  - _Requirements: 5.3_

- [x] 7. First live run (needs Clark's go in his own words)
  - One `ami-build` dispatch with pruning still in dry-run; read the plan;
    then set `REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED=true` and confirm the
    next run removes exactly what the plan said.
  - _Requirements: 2.1, 4.2_
