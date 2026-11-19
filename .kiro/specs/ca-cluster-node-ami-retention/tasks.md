# Implementation Plan — `ca_cluster_node` AMI retention

## Status: Not started (spec only, written 2026-11-19)

Building it needs Clark's go: the script deletes AMIs and snapshots, the IAM
change needs his re-provisioning step, and its first live run is a real-cloud
`ami-build` run.

- [ ] 1. Write `scripts/ami-retention/prune-amis.sh`
  - Argument parsing (`--arch`, `--keep`, `--min-age-days`, `--apply`), the
    checked `aws` wrapper, the three queries, the plan and its printout.
  - Dry run by default; `--apply` deregisters then deletes snapshots,
    continuing past failures and exiting 1 if any.
  - Copyright header after the shebang; `shellcheck` clean.
  - _Requirements: 1.1, 1.2, 2.1-2.5, 3.1-3.4_

- [ ] 2. Write the stub-mode test
  - `scripts/ami-retention/test-prune-amis.sh`, fake `aws`, per-case
    fixtures, a call log; the ten cases of the design.
  - _Requirements: 5.1_

- [ ] 3. Run the test and `shellcheck` in CI
  - Add both to ci.yml's `packer-ca-cluster-node` job.
  - _Requirements: 5.2, 5.4_

- [ ] 4. Narrow and extend the CI role policy
  - `ami-build.json`: add `DescribeLaunchTemplates` and
    `DescribeLaunchTemplateVersions`; move `DeregisterImage` and
    `DeleteSnapshot` under a `kythira:component` resource-tag condition.
  - Hand Clark the re-provisioning command.
  - _Requirements: 1.3_

- [ ] 5. Wire the step into `ami-build`
  - Last step, per arch, dry run unless
    `REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED` is `true`; plan into the job
    summary; `KEEP` / `MIN_AGE` variables.
  - _Requirements: 4.1-4.4_

- [ ] 6. Documentation
  - `packer/ca_cluster_node/README.md`: the pruner, keep rules, the
    `kythira:retain=true` pin, the launch-template caveat, the enabling
    variable; keep the manual recipe as the fallback.
  - _Requirements: 5.3_

- [ ] 7. First live run (needs Clark's go in his own words)
  - One `ami-build` dispatch with pruning still in dry-run; read the plan;
    then set `REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED=true` and confirm the
    next run removes exactly what the plan said.
  - _Requirements: 2.1, 4.2_
