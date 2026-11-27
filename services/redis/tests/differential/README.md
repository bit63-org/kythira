# Redis differential suite

The scaffold for `.kiro/specs/redis-general-data-types/` task 14
(Requirement 23.2): one seeded command stream goes to Kythira's gateway and to
the reference servers, Redis 7.2 and Valkey 8, in RESP2 and RESP3, and every
reply is compared.

| File | What it is |
|---|---|
| `redis_differential.hpp` | reply parser, seeded generator (`shapes()`), comparison rules (`rules()`), recording format, difference table |
| `redis_differential_unit_test.cpp` | all of the above without containers, plus a check that `recs/` still matches the generator (in CTest) |
| `redis_differential_replay_test.cpp` | `recs/` replayed against an in-process three-node gateway cluster (snapshot isolation, shards cut at "e"), in CTest: the quick check for a command PR |
| `redis_differential_test.cpp` | the container run (`docker-redis-differential-tests`): the daemon, live reference servers, Docker and rootless Podman |
| `recs/` | what Redis 7.2 and Valkey 8 answered to the default streams (seeds 1-3, 600 commands) |
| `recs/aws/` | what ElastiCache Serverless (Valkey, Redis OSS) and MemoryDB answered to the same streams with hash-tagged keys (Requirement 25.1), from the AWS interop bundle; empty until its first run |
| `recs/acl/access-strings.json` | what Redis 7.2 and Valkey 8's `ACL DRYRUN` say of each ElastiCache access string and probe in `redis_acl_probes.hpp` (Requirement 25.3) |
| `redis_acl_probes.hpp` | the access strings, the probes (an argument vector per command) and that recording's format |
| `redis_differential_record.cpp` | the recorder the AWS bundle runs in the VPC: one endpoint, plaintext or TLS, password or IAM token (`services/redis/aws-interop/`) |
| `../../docker/differential/` | compose file, shared gateway settings (`kythira.env`), ACL |

## What counts as a match

A Kythira reply passes when it equals the Redis 7.2 reply **or** the Valkey 8
reply (the two disagree in places, for example the nested `MULTI` error), or
when a rule in `rules()` covers it:

- `clock`: a harness tolerance (positive `TTL` within 2 s, `PTTL` within
  2000 ms, any positive `EXPIRETIME`/`PEXPIRETIME`, since an absolute expiry
  depends on when the stream ran);
- `D<n>`: a row of the design's difference table (D1 float increments in
  binary128; D2 byte order for collections, `KEYS` and the `SCAN` family,
  compared as sets with the same cursor);
- `G<n>`: a known gap. Every gap names the task that closes it, and that task's
  PR deletes the rule. The unit test lists the rule ids, so a new gap is a
  visible change in review. There are none today: G1 (`STRLEN` in `MULTI`)
  closed with task 11 and G2 (`GETRANGE` end clamp) with task 3.

A gap that would abort a `MULTI` block is kept out of the general shapes and
given a shape of its own that leaves state unchanged (`multi_unsupported`
ends in `DISCARD`), so one gap does not make every later reply differ.

Anything else is `DIFFERS` and fails the run.

## Running it

CI runs `docker-redis-differential-tests` in `redis-module.yml`'s container
job, on Docker and rootless Podman, and uploads
`build/redis-differential-out/` (`difference-table.md`, `recs/`). Locally:

```sh
cmake --build build --target docker-redis-differential-tests
```

Environment knobs are documented at the top of `redis_differential_test.cpp`
(seeds, stream length, Kythira services, output directory,
`KYTHIRA_DIFF_KEEP_UP`). Where Docker Hub rate-limits `library/redis`, set
`KYTHIRA_DIFF_REGISTRY=mirror.gcr.io/`.

## Adding a command

Generator version 2 covers every shipped command but those listed, with a
reason, in `excluded_commands()` (identity, whole-server, random and
Kythira-only commands); the unit test fails when a shipped command is in
neither place. When a task ships a command, add its shape to `shapes()` (or
an exclusion) and bump `k_generator_version`, then regenerate `recs/` and
update the fingerprint in `seed_one_is_stable`. Delete any `G<n>` rule the
task closes.

Random commands are generated so their answers are deterministic: `SPOP`,
`SRANDMEMBER` and `HRANDFIELD` take a count past any collection's size, and
`SCAN`/`HSCAN`/`SSCAN` a `COUNT` past the stream's key space, so every server
answers in one call with cursor 0. Collection keys are `<letter>:h|s|l:<tag>`;
one key in twelve comes from another family, so `WRONGTYPE` is compared too.
Both the container run and the replay raise the format gate
(`KYTHIRA.FORMAT UPGRADE 3`) before streaming.

## AWS recordings and access strings

ElastiCache Serverless and MemoryDB are always clustered and refuse a
multi-key command across slots, so their streams use the tag `{s<seed>}`:
the same commands, every key in one slot. The replay compares each AWS
recording alone, with two allowances: the difference table's rules, and,
where Redis 7.2 and Valkey 8 themselves disagree (the nested `MULTI`
error), the other engine's answer taken from the local recordings of the
same seed. Anything else is `DIFFERS`.

The access strings are checked by logging in to the in-process cluster as
a user per string (`user asN <secret> none <access string>`) and sending
every probe, so the gateway's own key extraction is what is compared with
`ACL DRYRUN`. Adding a string or a probe makes the recording stale (the
case fails until it is regenerated as below).

## Regenerating recs/

The reference servers alone, no Kythira build needed:

```sh
KYTHIRA_DIFF_KYTHIRA_SERVICES= KYTHIRA_DIFF_OUT=/tmp/diff \
  build/tests/docker_chaos/docker_redis_differential_test
cp /tmp/diff/recs/redis-seed*.json /tmp/diff/recs/valkey-seed*.json \
  services/redis/tests/differential/recs/
cp /tmp/diff/recs/acl/access-strings.json services/redis/tests/differential/recs/acl/
```

`recs/aws/` comes only from the AWS interop bundle
(`services/redis/aws-interop/README.md`), which needs Clark's go per run.
