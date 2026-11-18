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
| `recs/` | what Redis 7.2 and Valkey 8 answered to the default streams (seeds 1-3, 400 commands) |
| `../../docker/differential/` | compose file, shared gateway settings (`kythira.env`), ACL |

## What counts as a match

A Kythira reply passes when it equals the Redis 7.2 reply **or** the Valkey 8
reply (the two disagree in places, for example the nested `MULTI` error), or
when a rule in `rules()` covers it:

- `clock`: a harness tolerance (positive `TTL` within 2 s);
- `D<n>`: a row of the design's difference table;
- `G<n>`: a known gap. Every gap names the task that closes it, and that task's
  PR deletes the rule. The unit test lists the rule ids, so a new gap is a
  visible change in review. Today: G1, `STRLEN` refused inside `MULTI`
  (task 11), and G2, `GETRANGE` not clamping an end index before the start of
  the string (task 3).

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

When a phase 1 task ships a command, add its shape to `shapes()` and bump
`k_generator_version`, then regenerate `recs/` and update the fingerprint in
`seed_one_is_stable`. Delete any `G<n>` rule the task closes.

## Regenerating recs/

The reference servers alone, no Kythira build needed:

```sh
KYTHIRA_DIFF_KYTHIRA_SERVICES= KYTHIRA_DIFF_OUT=/tmp/diff \
  build/tests/docker_chaos/docker_redis_differential_test
cp /tmp/diff/recs/redis-seed*.json /tmp/diff/recs/valkey-seed*.json \
  services/redis/tests/differential/recs/
```
