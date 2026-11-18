# Redis layers

The Redis module can be split into three layers, which run together on every
node by default (`.kiro/specs/redis-general-data-types/` Requirements 16-21
and 24, design Component 9):

| Layer | Runs |
|---|---|
| `gateway` | RESP2/RESP3, TLS, `AUTH`/`HELLO`, connection limits and per-connection state |
| `front_end` | authorization, planning (one group, fan-out or transaction), the transaction coordinator, `SCAN` cursors |
| `data` | the multi-Raft host and the Redis state machines, sweeps and evictions |

A node picks its layers with `KYTHIRA_REDIS_ROLES` (see
[redis-gateway.md](redis-gateway.md)). This build serves only the co-located
set, all three, which is the node as it has always been. The later tasks
(16 to 20) add the data-layer API, front ends without data, gateways apart
from front ends, layer membership, and the split and merge procedures. This
page gains the runbook with task 19.

## How the code is layered

The command path reaches data only through a data access object
(`services/redis/include/kythira/redis/redis_data_access.hpp`):
route a key, propose an entry, run a transaction participant message, read a
key at a consistency, allocate oracle timestamps. These are the operations of
the data-layer API. `redis_local_data_access` is the in-process
implementation, which makes the same host calls as before the split. The data
layer's own jobs (sweeps, evictions, advisories, per-node `INFO` and
`DBSIZE` counts) use the same object's `local_*` members, which only a node
with `data` has.

## Co-located baseline

Requirement 24.4 says the layer work must not make a co-located node slower
by more than measurement noise. The measurement is the disabled case
`colocated_measurement` in `redis_gateway_integration_test`. Run it by name on
two builds, alternating them:

```
redis_gateway_integration_test --run_test=colocated_measurement
```

It runs an in-process three-node cluster. It enters through the shard's
leader, then through a follower, which forwards. It measures sequential 1 KiB
`SET` and `GET` latency over 2000 keys, and then the operations per second of
eight clients doing 25% `SET` for 3 s.

Measured on 2026-11-18 (task 15, the data-access seam), on a 4-vCPU cloud
sandbox. The build was g++ 13 `-O2` on the Boost future backend, with values
in RAM. Each build ran 12 rounds, alternating. The table gives medians, with
each build's range in brackets:

| Entry | Metric | Before | After | Change |
|---|---|---|---|---|
| leader | `SET` p50 | 652 µs [625-691] | 657 µs [623-678] | +0.8% |
| leader | `SET` p99 | 1034 µs [931-1154] | 1034 µs [996-1459] | 0.0% |
| leader | `GET` p50 | 80 µs [73-95] | 82 µs [74-88] | +3.1% |
| leader | `GET` p99 | 233 µs [197-323] | 240 µs [221-296] | +2.8% |
| leader | 8 clients | 33,318 ops/s [30,934-36,871] | 33,740 ops/s [33,139-35,182] | +1.3% |
| follower | `SET` p50 | 740 µs [705-809] | 736 µs [722-769] | -0.5% |
| follower | `SET` p99 | 1148 µs [1072-1464] | 1099 µs [1040-1202] | -4.3% |
| follower | `GET` p50 | 162 µs [144-184] | 162 µs [152-173] | 0.0% |
| follower | `GET` p99 | 430 µs [344-486] | 422 µs [378-511] | -1.9% |
| follower | 8 clients | 35,372 ops/s [26,525-38,210] | 33,994 ops/s [25,856-39,481] | -3.9% |

Every change is well inside the range of rounds of the same build. Later
layer tasks add a section here.
