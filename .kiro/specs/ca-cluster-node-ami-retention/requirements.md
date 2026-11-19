# Requirements Document

## Introduction

`.kiro/specs/ca-cluster-node-ami/` builds a `ca_cluster_node` AMI on demand
through the `ami-build` bundle of `.github/workflows/real-cloud-tests.yml`.
Every run of that bundle registers two new AMIs (one per architecture) and
two EBS snapshots, and nothing ever removes them. Requirement 13 AC 5 of that
spec left retention out on purpose and named it a candidate follow-up; this
is that follow-up.

The cost is small per image (an 8 GiB gp3 snapshot is a few cents a month)
but it only grows. Every CI AMI is built `--with-chaos-node`, so the account
keeps every build since the bundle started, each tagged
`kythira:component=ca-cluster-node`, and the only cleanup today is the manual
`aws ec2 deregister-image` / `aws ec2 delete-snapshot` recipe in
`packer/ca_cluster_node/README.md`.

The other half of that AC 4, wiring a freshly built AMI into the real-EC2
bundles, is already done in a different form: the `aws` job's "Resolve
ca_cluster_node AMI ID" step (and the chaos-crash bundle's equivalent) picks
the newest image by `kythira:component`, `kythira:arch` and, for chaos-crash,
`kythira:chaos-node=true`. This spec does not change that; it makes sure
retention never removes an image those steps would pick.

Building this spec needs Clark's call: it deletes cloud resources, and its
first live run is real-cloud work.

## Glossary

- **Candidate**: an AMI owned by the account and tagged both
  `kythira:component=ca-cluster-node` and `kythira:built-by=packer`. Nothing
  else is ever considered.
- **Class**: the pair (`kythira:arch`, `kythira:chaos-node`) of a candidate.
  An image with no `kythira:chaos-node` tag (built before that tag existed)
  is class (`arch`, `false`).
- **Pruner**: the new script, `scripts/ami-retention/prune-amis.sh`.
- **Plan**: the list of candidates the pruner would keep and remove, with the
  rule that decided each one.

## Requirements

### Requirement 1: Only Kythira's own build images are touched

**User Story:** As the account owner, I want retention limited to images the
Packer build made, so that no other AMI in the account can be deleted by it.

#### Acceptance Criteria

1. THE Pruner SHALL list images with `--owners self` and both tag filters of
   the Candidate definition, and SHALL NOT consider any other image.
2. THE Pruner SHALL delete a snapshot only when it is named in a removed
   candidate's block device mappings AND carries
   `kythira:component=ca-cluster-node` itself; any other snapshot in the
   mappings SHALL be listed and left alone.
3. THE CI role's `ec2:DeregisterImage` and `ec2:DeleteSnapshot` grants in
   `scripts/ci-cloud-credentials/aws/policies/ami-build.json` SHALL be
   narrowed to resources tagged `kythira:component=ca-cluster-node`, so the
   rule holds even if the script is wrong.

### Requirement 2: What is always kept

**User Story:** As a test author, I want every image a resolve step could
pick, and every image something still runs, to survive retention.

#### Acceptance Criteria

1. THE Pruner SHALL keep the newest `KEEP` candidates of each class by
   `CreationDate` (default 2, `--keep N`, N >= 1). Keeping at least one per
   class guarantees both resolve steps still find an image.
2. THE Pruner SHALL keep any candidate younger than `MIN_AGE` (default 7
   days, `--min-age-days D`), so an image built minutes ago by a parallel run
   is never removed by another.
3. THE Pruner SHALL keep any candidate tagged `kythira:retain=true`, the
   operator's pin.
4. THE Pruner SHALL keep any candidate that an instance in any state other
   than `terminated` was launched from, or that any launch template version
   in the region names as its `ImageId`.
5. WHEN any of the queries behind AC 4 fails, THE Pruner SHALL remove
   nothing and exit non-zero. An unknown "in use" set means keep everything.

### Requirement 3: Dry run by default, loud on failure

**User Story:** As the account owner, I want to see a plan before anything
is deleted, and a failure to delete to fail the job.

#### Acceptance Criteria

1. THE Pruner SHALL print the Plan, one line per candidate with its id,
   class, creation date and deciding rule, before acting.
2. THE Pruner SHALL act only with `--apply`; without it, it SHALL print the
   Plan and exit 0.
3. WITH `--apply`, THE Pruner SHALL deregister each removed image before
   deleting its snapshots (EC2 refuses to delete a snapshot a registered
   image uses) and SHALL exit 1 if any deregister or delete fails, after
   attempting the rest.
4. THE Pruner SHALL treat unreadable `aws` output (jq parse failure) or an
   `aws` error as a failure, never as an empty result, the lesson
   `scripts/perf-cloud/test-audit-aws-leaks.sh` exists to enforce.

### Requirement 4: Wiring into the `ami-build` job

**User Story:** As a repo admin, I want retention to run after each
successful build, scoped so the two matrix legs cannot race.

#### Acceptance Criteria

1. THE `ami-build` job SHALL run the Pruner as its last step, only after the
   build step succeeded, restricted to the leg's own architecture
   (`--arch amd64|arm64`).
2. THE step SHALL pass `--apply` only when the repository variable
   `REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED` is `true`; otherwise it SHALL run
   as a dry run and print the Plan into the job summary.
3. `KEEP` and `MIN_AGE` SHALL be overridable through
   `REAL_CLOUD_TESTS_AWS_AMI_KEEP` and `REAL_CLOUD_TESTS_AWS_AMI_MIN_AGE_DAYS`.
4. A Pruner failure SHALL fail the job (the new AMI is already built and
   recorded in the manifest artifact, so nothing is lost by a red step).

### Requirement 5: Tests and documentation

**User Story:** As a maintainer, I want the keep rules proved without an AWS
account, and the manual recipe replaced by the script.

#### Acceptance Criteria

1. A stub-mode test (fake `aws` first on `PATH`, canned JSON, in the style of
   `scripts/perf-cloud/test-audit-aws-leaks.sh`) SHALL cover each keep rule
   of Requirement 2, the snapshot rule of Requirement 1 AC 2, the
   failed-query rule of Requirement 2 AC 5, the jq-failure rule of
   Requirement 3 AC 4, and that a dry run issues no mutating call.
2. The stub test SHALL run in CI on every change to `scripts/ami-retention/`.
3. `packer/ca_cluster_node/README.md` SHALL document the Pruner, its keep
   rules, the pin tag and the enabling variable, replacing the manual
   recipe as the primary path (the recipe stays as a fallback).
4. The script and test SHALL pass `shellcheck`.
