# Design Document — `ca_cluster_node` AMI retention

## Overview

One bash script, `scripts/ami-retention/prune-amis.sh`, computes a Plan from
three read-only queries and, with `--apply`, carries it out. The `ami-build`
job runs it after each successful build, per architecture. A stub-mode test
proves the keep rules without an AWS account. Bash and the `aws` CLI with
JMESPath and `jq`, because every other sweeper in the tree
(`scripts/aws-real-ec2-leaks.sh`, `scripts/aws-asg-leaks.sh`,
`scripts/perf-cloud/audit-aws-leaks.sh`) is written that way and the CI
runners already have both.

## Inputs

```
prune-amis.sh [--arch amd64|arm64] [--keep N] [--min-age-days D] [--apply]
```

| Query | Call | Used for |
|---|---|---|
| Candidates | `ec2 describe-images --owners self --filters tag:kythira:component=ca-cluster-node tag:kythira:built-by=packer [tag:kythira:arch=<arch>]` | the set, tags, `CreationDate`, block device mappings |
| Instances | `ec2 describe-instances --filters Name=image-id,Values=<candidate ids> Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped` | Req 2.4 |
| Launch templates | `ec2 describe-launch-templates` then `ec2 describe-launch-template-versions --versions '$Latest' '$Default'` per template | Req 2.4 |

Launch template versions are read only for `$Latest` and `$Default`. Older
versions can name any image, but an ASG or fleet launches from one of those
two unless pinned to a number; reading every version of every template is
unbounded. The trade-off is written down in the README: a template pinned to
an old numbered version must also carry `kythira:retain=true` on its image.

`--arch` is optional so an operator can run one plan for the whole account;
the CI step always passes it (Req 4.1), which keeps the two matrix legs on
disjoint image sets.

## The plan

For each class, sorted newest first:

```
for image in class (newest first):
    if rank < KEEP                         -> keep  "newest-N"
    elif age < MIN_AGE                     -> keep  "younger-than-D-days"
    elif tag kythira:retain == "true"      -> keep  "pinned"
    elif image in in-use set               -> keep  "in-use: i-... / lt-..."
    else                                   -> remove
```

The rule order only changes which reason is printed; any keep rule wins.
Ages come from `CreationDate` against `date -u`, both UTC.

For each removed image, snapshots come from
`BlockDeviceMappings[].Ebs.SnapshotId`; one `describe-snapshots --snapshot-ids`
call reads their tags, and only those tagged
`kythira:component=ca-cluster-node` are scheduled for deletion (Req 1.2).
Packer's `snapshot_tags = local.common_tags` stamps exactly that tag, so in
practice this keeps nothing; it exists for an image someone re-registered
over a shared snapshot.

## Acting

`deregister-image` for every removed image first, then `delete-snapshot` for
their snapshots. Each call's failure is recorded and the loop continues; the
script exits 1 at the end if any failed (Req 3.3). There is no waiter: a
deregistered image releases its snapshots immediately.

## Failure handling

Every `aws` call goes through one wrapper that captures stdout, checks the
exit status, and pipes the result through `jq -e .` before use. A non-zero
exit or a parse failure aborts the run before any mutation (Req 2.5, 3.4).
That is the same rule `audit-aws-leaks.sh` follows, for the reason its test
records: `gcloud compute list` once exited 0 under an auth failure and the
auditor reported clean.

## IAM

`ami-build.json` already grants every action the script needs except
`ec2:DescribeLaunchTemplates` and `ec2:DescribeLaunchTemplateVersions`, which
are added to the describe statement. `ec2:DeregisterImage` and
`ec2:DeleteSnapshot` move out of the `Resource: "*"` statement into one with
`"Condition": {"StringEquals": {"aws:ResourceTag/kythira:component":
"ca-cluster-node"}}` (Req 1.3). Packer only calls `DeregisterImage` with
`force_deregister`, which the template does not set (the default is off), so
the narrowing does not break the build. The policy change takes effect only when the role is re-provisioned
with `scripts/ci-cloud-credentials/aws/`, which is Clark's step, like every
other IAM mutation.

## Workflow step

```yaml
- name: Prune old ca_cluster_node AMIs
  if: ${{ success() }}
  env:
    PRUNE: ${{ vars.REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED == 'true' }}
    KEEP: ${{ vars.REAL_CLOUD_TESTS_AWS_AMI_KEEP || '2' }}
    MIN_AGE: ${{ vars.REAL_CLOUD_TESTS_AWS_AMI_MIN_AGE_DAYS || '7' }}
  run: |
    args=(--arch "${{ matrix.arch }}" --keep "$KEEP" --min-age-days "$MIN_AGE")
    [ "$PRUNE" = true ] && args+=(--apply)
    scripts/ami-retention/prune-amis.sh "${args[@]}" | tee -a "$GITHUB_STEP_SUMMARY"
```

Dry run until the variable is set, so the first real plan is read before
anything is deleted.

## Testing

`scripts/ami-retention/test-prune-amis.sh`, stub mode only. A fake `aws`
script earlier on `PATH` answers from a fixture directory chosen per case and
appends every invocation to a call log. Cases:

1. Three images of one class, all old: the newest two kept, the third
   removed with its snapshot.
2. Two classes (`chaos-node` true and false): each keeps its own newest two.
3. An old image younger than `MIN_AGE`: kept.
4. A pinned image: kept.
5. An image an instance runs, and one a launch template names: both kept.
6. A removed image whose mapping includes an untagged snapshot: that
   snapshot is listed, not deleted.
7. `describe-instances` exits 255: nothing removed, exit non-zero.
8. `describe-images` prints non-JSON: nothing removed, exit non-zero.
9. Dry run: the call log holds no `deregister-image` or `delete-snapshot`.
10. `--apply` with one failing `delete-snapshot`: the rest still run, exit 1.

The test joins the `shellcheck` step of ci.yml's `packer-ca-cluster-node`
job and runs as its own step there; that job runs on every pull request to
`main`.

No live mode. A live test would have to build an AMI to delete one, which is
a full `ami-build` run; the first real dry-run plan in the job summary is the
live check, read by a person before `--apply` is turned on.
