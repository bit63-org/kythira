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
[redis-gateway.md](redis-gateway.md)). This build serves three sets:

| Roles | The node |
|---|---|
| `gateway,front_end,data` (default) | co-located: the node as it has always been |
| `gateway,front_end` | a front end without data: serves clients, holds no replica, and reaches the data layer over the data-layer API (below) |
| `data` | a data node: holds replicas and serves the data-layer API to front ends; refuses clients |

The later tasks add gateways apart from front ends, layer membership, and the
split and merge procedures. This page gains the runbook with task 19.

## How the code is layered

The layers are separate classes in `services/redis/include/kythira/redis/`:

- `redis_front_end` (definitions in `redis_front_end_impl.hpp`) does
  everything past authentication: the transaction surface, the per-command
  handlers, authorization, planning, the transaction coordinator and the
  forward link.
- `redis_gateway` (`redis_gateway_impl.hpp`) extends it with the listeners,
  TLS, connection state and the connection commands (`AUTH`, `HELLO`,
  `CLIENT`, `QUIT`, `RESET`). Its `execute()` does the credential checks
  and then calls `execute_command()`. On a co-located node that call stays
  in-process, with no hop or copy. A gateway without `front_end` will send
  the command to a remote front end instead (task 17).

New command handlers are `redis_front_end` members.

The command path reaches data only through a data access object
(`services/redis/include/kythira/redis/redis_data_access.hpp`):
route a key, propose an entry, run a transaction participant message, read a
key at a consistency, allocate oracle timestamps. These are the operations of
the data-layer API. `redis_local_data_access` is the in-process
implementation, which makes the same host calls as before the split. The data
layer's own jobs (sweeps, evictions, advisories, per-node `INFO` and
`DBSIZE` counts) use the same object's `local_*` members, which only a node
with `data` has.

## The data-layer API

A node with `data` serves the data-layer API to other nodes as internal RESP
commands on the forward link, beside `KYTHIRA.TXN`. Only a connection that
authenticated as the internal identity may send them. A client that sends
one gets `NOPERM`, whatever its role.

| Command | Answers with |
|---|---|
| `KYTHIRA.DATA ROUTE <key>` | the route of the group that owns the key |
| `KYTHIRA.DATA ROUTES <range>` | every route overlapping the range, in key order |
| `KYTHIRA.DATA PROPOSE <group> <version> <conf_version> <entry>` | the state machine's result, or why not |
| `KYTHIRA.DATA READ <LEADER\|ANY\|LINEARIZABLE> <key>` | the key's bytes and deadline from this node's replica, a miss, or why not |

Every answer is one bulk string in the encoding of `redis_data_wire.hpp`.
A routes answer carries the `host:port` where each node it names takes these
calls. A route's leader hint is the leader the answering node's own replica
knows, which is fresher than its routing map.

A data node never forwards a refused proposal. It answers with what the
caller needs to try again: not the leader (with the leader it knows), a stale
route (with the current routes), an unknown group, a locked key, an unrouted
key, a timeout (the entry may still commit) or a failure. A split or merge in
flight answers "not the leader" naming the node itself, so the caller asks
again after a pause.

`redis_remote_data_access` (`redis_remote_data_access.hpp`) is the caller's
side. It keeps the shared route cache (`include/raft/route_cache.hpp`),
fetches routes from any data node it knows or from its seeds, sends a write
to the leader hint first and then the other voters, and corrects the cache
from every refusal. A proposal raises the same exceptions as the host's
`submit_command`, so a caller handles a local and a remote proposal the same
way.

A read answers from the answering node's own replica, never another's, at the
consistency the caller names: `LEADER` (a leader that has applied every write
its predecessor acknowledged), `ANY` (any replica, which may lag) or
`LINEARIZABLE` (the leader, after a committed no-op). A replica that cannot
serve at that consistency answers "not the leader" with the leader it knows.
A replica whose disk-backed value is not all there yet names the leader that
has it. The answer carries the value's deadline, and the front end decides
expiry on its own clock, as a co-located node does.

## Front ends without data

A node with `KYTHIRA_REDIS_ROLES=gateway,front_end` runs every command's
logic (authorization, planning, the transaction coordinator) and reaches the
data layer for each key:

- Routes come from `KYTHIRA.DATA ROUTES`, asked of the data nodes in
  `KYTHIRA_REDIS_DATA_NODES` at first and then of any node a route names.
  Each refusal corrects the cached route.
- `GET`, `EXISTS`, `STRLEN`, `GETRANGE` and `TTL` read with `KYTHIRA.DATA
  READ` at the node's `KYTHIRA_REDIS_READ_CONSISTENCY`. `SET`, `SETEX` and
  `DEL` read the leader's entry the same way where they check it (immutable
  values, `DEL`'s count), then send the encoded entry with `KYTHIRA.DATA
  PROPOSE`.
- Transactions (`MSET`, `MGET`, multi-key `DEL`, `MULTI`/`EXEC`) send each
  participant message and transactional read to the leader the routes name,
  over `KYTHIRA.TXN`, as a co-located node does for a group it holds no
  replica of. Under snapshot isolation the front end asks the data nodes in
  turn for timestamps, and the oracle's leader answers.
- The front end never hands a whole client command to another node, so the
  command logic stays on the front end.

The data layer is chosen per call: a key whose group has a replica on the
node goes in-process, and a key whose group has none goes to the data nodes.
A front end without data holds no replica, so every call goes remote. A node
with `data` never attaches the remote half: a key led elsewhere keeps the
one-hop forward of the whole command, and co-located latency pays only a null
check.

The replies are the bytes a co-located node gives. The differential replay
(`redis_differential_replay_test`) runs the recorded Redis and Valkey streams
through a front end without data as well as through co-located gateways.

The front end needs:

- `KYTHIRA_REDIS_DATA_NODES`, the data nodes' gateway addresses;
- the internal secret, and forwarding TLS (or plaintext forwarding allowed),
  because the data-layer API rides the forward link;
- the in-memory or engine store. The disk-backed store keeps a value's
  chunks on its data nodes, which a read answer cannot carry, so the node
  refuses to start with it.

`KYTHIRA_PEERS` still names the node itself; its host joins no group. `INFO`
and `DBSIZE` count local replicas, so on a front end without data they report
no keys. A front end without data keeps no LRU of its own, so a data node's
eviction sees the reads its own clients make, not the front end's.

## Data nodes

A node with `KYTHIRA_REDIS_ROLES=data` runs the multi-Raft host, the state
machines and the data layer's own jobs (sweeps, evictions). Its gateway's
listener is the internal listener: a connection authenticated as the internal
identity gets the data-layer API, `KYTHIRA.TXN` and the commands co-located
nodes forward, and any other connection gets `PING` and an error naming the
node's roles for everything else. A co-located node and a data node can share
a cluster, which is how a layout moves from one to the other (task 19).

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

### Task 16b: front ends without data

Measured on 2026-11-26 the same way, with the build before task 16b
against the build with it. A co-located node now pays one null check
per data access to learn that no remote half is attached:

| Entry | Metric | Before | After | Change |
|---|---|---|---|---|
| leader | `SET` p50 | 655 µs [604-719] | 662 µs [617-704] | +1.0% |
| leader | `SET` p99 | 1026 µs [830-1242] | 1023 µs [919-1182] | -0.3% |
| leader | `GET` p50 | 79 µs [64-99] | 82 µs [67-96] | +3.8% |
| leader | `GET` p99 | 234 µs [164-352] | 237 µs [199-321] | +1.1% |
| leader | 8 clients | 33,312 ops/s [28,452-39,144] | 32,446 ops/s [29,587-38,456] | -2.6% |
| follower | `SET` p50 | 741 µs [685-829] | 751 µs [674-851] | +1.3% |
| follower | `SET` p99 | 1136 µs [994-1372] | 1128 µs [919-1415] | -0.7% |
| follower | `GET` p50 | 166 µs [141-197] | 168 µs [130-215] | +1.2% |
| follower | `GET` p99 | 445 µs [391-561] | 426 µs [345-597] | -4.3% |
| follower | 8 clients | 35,602 ops/s [25,059-45,981] | 33,775 ops/s [21,977-43,866] | -5.1% |

Every change is again inside the range of rounds of the same build.
