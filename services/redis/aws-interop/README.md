# Redis AWS interop bundle

Evidence that applications written for AWS's managed Redis work against
Kythira (`.kiro/specs/redis-general-data-types/` Requirement 25), without
paying AWS on every CI run.

| Part | Where | Spends money |
|---|---|---|
| Recorded ElastiCache and MemoryDB transcripts replayed against the gateway (25.1) | `redis_differential_replay_test`, case `aws_recordings_replay_against_the_gateway`, over `services/redis/tests/differential/recs/aws/` | no |
| ElastiCache access strings parsed by the ACL to the same permissions (25.3) | `redis_differential_replay_test`, case `elasticache_access_strings_grant_what_redis_grants`, over `recs/acl/access-strings.json` | no |
| Re-recording, client suites against AWS, IAM auth tokens, cost report (25.2) | this directory, run by `.github/workflows/redis-aws-interop.yml` | yes, well under $1 a run |

## What a run does

`run.sh`, on a GitHub runner with the interop role's credentials:

1. creates a security group in the default VPC, ElastiCache users and user
   groups (a password user `app` and an IAM user per engine), two
   ElastiCache Serverless caches (Valkey 8, Redis OSS 7; usage limits 1 GB
   and 5,000 ECPU/s) and a MemoryDB cluster (Valkey, one `db.t4g.small`
   node, TLS), all named `kyt-ri-<run id>` and tagged
   `kythira:redis-interop`;
2. uploads the client and recorder images to a bucket of its own and
   launches a `t3.small` runner in the same VPC, with presigned URLs to
   fetch them and to upload its results, so the runner holds no AWS
   credentials;
3. the runner (`runner-job.sh`) checks an ElastiCache IAM auth token, made
   by botocore exactly as Kythira's IAM conformance run makes one for
   Kythira's `auth=iam` users, against each cache; records the
   differential streams (seeds 1-3, RESP2 and RESP3, keys hash-tagged into
   one slot) with `redis_differential_record`; and runs the redis-py,
   go-redis and ioredis suites with TLS;
4. compares each suite's JUnit report with Kythira's latest run on main
   (`redis-module.yml`'s `redis-client-suites-docker` artifact), writes
   `report.md` and `cost.md`, and deletes everything, also on failure or
   cancellation. Anything it could not delete fails the run and is listed
   in `leftovers.txt`.

The artifact holds the recordings (`recs/`), the suite reports, the IAM
check results and the two reports. The recordings go into
`services/redis/tests/differential/recs/aws/` in a pull request; the replay
test then covers them on every CI run. If they show differences, each one
either becomes a row of the difference table or a fix.

The runner's user data carries the run's password and the IAM tokens.
Both die with the run: the users are deleted at the end, and a token lasts
15 minutes.

## Before the first run

Clark, once:

```sh
scripts/ci-cloud-credentials/aws/redis-interop/provision-role.sh \
    --github-org crawlins --github-repo kythira
gh variable set AWS_REDIS_INTEROP_ROLE_ARN --body <the ARN it prints>
gh variable set REDIS_AWS_INTEROP_ENABLED --body true
```

and create the `redis-aws-interop` environment with himself as required
reviewer. `REDIS_AWS_INTEROP_REGION` overrides the region (default
`us-east-1`; `aws_helpers.py cost` prices us-east-1).

## Each run

Each run needs Clark's go in his own words. Dispatch with the
`approved_by` input saying whose go and where; the environment then waits
for his review as well.

```sh
gh workflow run redis-aws-interop.yml -f approved_by="Clark, <where>"
```

MemoryDB takes about 20 minutes to create and as long to delete, so a run
takes about an hour.
