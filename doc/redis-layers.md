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
[redis-gateway.md](redis-gateway.md)). Every non-empty set serves:

| Roles | The node |
|---|---|
| `gateway,front_end,data` (default) | co-located: the node as it has always been |
| `gateway,front_end` | a front end without data: serves clients, holds no replica, and reaches the data layer over the data-layer API (below) |
| `gateway` | a gateway apart: holds client connections and sends each command to a front end as an authenticated call (below) |
| `front_end`, `front_end,data` | a front end without a gateway: serves gateways' calls, never clients |
| `data` | a data node: holds replicas and serves the data-layer API to front ends; refuses clients |
| `gateway,data` | a gateway apart that also holds replicas |

A set without `data` needs `KYTHIRA_REDIS_DATA_NODES` when it has
`front_end`; a `gateway` without `front_end` needs
`KYTHIRA_REDIS_FRONT_ENDS`. Any node that is not co-located talks to the
other layers with a layer identity over mutual TLS (below).

Layer membership and the split and merge runbook are below
([Splitting and merging layers](#splitting-and-merging-layers)).

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
  in-process, with no hop or copy. A gateway without `front_end` sends the
  command to a remote front end instead (`call_front_end()`).

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
commands on the forward link, beside `KYTHIRA.TXN`. Only another node may
send them, and only with the `front_end` or `data` role (see "Layer
identities" below). A client that sends one gets `NOPERM`, whatever its role.

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
  Each refusal corrects the cached route. A node without `data`, such as
  one that left the data layer, answers `TRYAGAIN` instead of a route
  table, and so does a data node that knows no route for the range yet,
  so a stale seed never replaces good routes with an empty table.
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
- a layer identity and forwarding TLS (or `KYTHIRA_NODE_INSECURE_PLAINTEXT=1`
  and the internal secret), because the data-layer API rides the forward
  link;
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
listener is the internal listener: another node's connection gets the
data-layer API, `KYTHIRA.TXN` and the commands co-located nodes forward, and
any other connection gets `PING` and an error naming the node's roles for
everything else. A co-located node and a data node can share a cluster, which
is how a layout moves from one to the other
([Splitting and merging layers](#splitting-and-merging-layers)).

## Gateways apart from front ends

A node with `KYTHIRA_REDIS_ROLES=gateway` terminates RESP, TLS and `AUTH`
and holds each connection's state: protocol, user, isolation, the `MULTI`
queue and the `WATCH` token. It has no front end. Every other command goes
to a front end in `KYTHIRA_REDIS_FRONT_ENDS` as an authenticated call:

```
KYTHIRA.CALL <state> <command> <arg>...
```

`<state>` is the connection as the gateway holds it, and the answer is one
bulk string with the state as the front end left it and the reply bytes in
the client's protocol (`redis_call_wire.hpp`). The front end looks the
user up in its own ACL, so it decides the role and key scopes. It keeps
nothing between calls. While queuing inside `MULTI` the front end checks
each command and says whether it queued it, and the queue stays on the
gateway. The queue travels whole, once, with `EXEC`.

Each connection is pinned to one front end, chosen by rendezvous hashing of
its number over the front ends that have not failed lately. Only the
connections of a front end that leaves move. When a call cannot reach its
front end (refused, or no answer to the connect), nothing left the gateway,
so the next front end runs it and the connection is re-pinned. When the
request left and the answer did not come back, the front end may have run
it. The gateway answers

```
-ERR outcome unknown, front end lost; it may have applied
```

and never replays the call (Requirement 17.2). The connection moves at its
next command, and a `MULTI` in progress fails at `EXEC`. A pooled link is
checked for a peer close before it carries a call, so a front end that
restarted while the link was idle does not cause that error.

A gateway drains on shutdown (SIGTERM, `KYTHIRA_REDIS_DRAIN_TIMEOUT_MS`,
10 s by default; Requirement 17.4). It stops accepting connections, lets the
commands it already received finish and their replies leave, then closes the
connections. A command that outlives the bound is cut off with its
connection.

`INFO` through a gateway apart is the front end's. The gateway's own counters
(`front_end_calls`, `front_end_repins`, `front_end_lost`) are in its stats.

The replies are the co-located bytes. The differential replay runs the
recorded streams through three layers apart (a gateway over two front ends
without data over data nodes) with no difference.

## Layer membership

A gateway apart finds its front ends in one of three places
(Requirement 20):

| Source | Setting | What it gives |
|---|---|---|
| configuration | `KYTHIRA_REDIS_FRONT_ENDS` (`host:port` or `id=host:port`) | a fixed list |
| DNS discovery | `KYTHIRA_REDIS_FRONT_ENDS_DNS` (`name:port`) | every address the name resolves to, re-resolved every `KYTHIRA_REDIS_DISCOVERY_INTERVAL_MS` (5 s). A name that stops resolving keeps the last list |
| the layer membership group | `KYTHIRA_REDIS_MEMBERSHIP` (voter node ids) | every serving front end that reported in the last three rounds, falling back to `KYTHIRA_REDIS_FRONT_ENDS` while the group names none |

The group is the one the independent-layers specs share
(`include/raft/layer_membership.hpp`): one Raft group with a small fixed
voter set, holding each member's id, roles, address, placement group,
front-end index, drain state and load. Its voters are 1, 3 or 5 nodes of
`KYTHIRA_PEERS`. Each holds a replica on a second Raft host beside the Redis
one, on the same listener, with the last group id of the module's range. The
log is in memory: the group holds no data, and members re-announce
themselves to a group that lost its list. Every other node reaches the group
through a voter's gateway listener with the internal command
`KYTHIRA.MEMBERS LIST | PROPOSE <command>`, which any layer role may send.
A voter that cannot commit (it is not the leader) answers `-TRYAGAIN`, and
the caller asks the next. So the stateless layers grow without the group
growing. The call authenticates like any internal call: with a layer
identity over mutual TLS, or with `KYTHIRA_REDIS_INTERNAL_SECRET`. The
secret's user exists only in a node with an ACL file, so a node run with
`KYTHIRA_REDIS_ALLOW_ANONYMOUS` and no ACL file refuses it, and the members
other than the group's leader never appear.

Every node with `gateway` or `front_end` is a member. Every
`KYTHIRA_REDIS_MEMBERSHIP_INTERVAL_MS` (1 s) it reads the list, announces
itself when the list lacks it or has it wrong, and reports its load: open
connections, commands per second, bytes sent per second, and its share of
the machine's CPUs. Its address is `KYTHIRA_REDIS_ADVERTISE`, else its
listener's address when that names one, else the host name with the TLS port
(the plaintext port without TLS). Data-only nodes are not members; they
leave the data layer by evacuation.

A member follows the drain state the group holds for it:

- **draining**: gateways stop choosing it for new calls at their next
  round, and connections pinned to it move at their next command, which is
  safe because a front end keeps nothing between calls. A node without
  `data` that runs a gateway also stops accepting connections. Once nothing
  has been in flight for two rounds (or `KYTHIRA_REDIS_DRAIN_TIMEOUT_MS` has
  passed for a gateway's clients), it closes its client connections and
  sets itself **drained**. It may then be stopped.
- **serving** again: a front end takes calls again at the gateways' next
  round. A gateway whose listeners closed needs a restart.

An admin drives it from any gateway:

```
KYTHIRA.LAYERS LIST            one line per member: id, address, roles, drain, index, load
KYTHIRA.LAYERS DRAIN <id>      needs the group
KYTHIRA.LAYERS SERVE <id>
```

`INFO` reports `kythira_membership:` (`config`, `dns` or `group`),
`kythira_member_drain:`, `kythira_front_end_index:` and
`kythira_front_end_calls_served:` for the node that answers it.

Each front end takes a 14-bit index (`KYTHIRA_REDIS_FRONT_END_INDEX`, 1 to
16383; by default its node id when that is such a number) and publishes it
in the group. A `SCAN` cursor is `(front-end index : 14) | (cursor id :
50)` (`redis_layer_membership.hpp`), so a cursor presented to another front
end names the one that issued it, and the group gives its address. The
cursor walk itself lands with `SCAN` (phase 1 task 12).

### Scaling a stateless layer

With `KYTHIRA_REDIS_CAPACITY_LAYER=gateway` or `front_end`, the group's
leader runs the shared elastic capacity controller over that layer. Every
voter builds the loop, and only the one that leads the group acts. Its lease
is the group's Raft leadership, fenced by the term, so two voters never
provision at once. Each `KYTHIRA_REDIS_CAPACITY_INTERVAL_MS` (5 s) it hands
the controller one report per member of the layer that is serving and has
reported recently, then lets the controller decide.

The policy is the shared `layer_capacity_policy`, with three signals:

- commands per second per member (`_REQUESTS_HIGH` / `_LOW`, 2000 / 600);
- open connections per member (`_CONNECTIONS_HIGH` / `_LOW`, off by
  default);
- the share of members whose CPU share has reached `_OVERLOAD_CPU` (0.85).

Any one signal that stays above its high mark for `_SUSTAINED_MS` (2 min)
adds one member. Every signal must stay at or below its low mark for
`_SCALE_IN_SUSTAINED_MS` (15 min) before one goes. Between decisions there
is a `_COOLDOWN_MS` (5 min), and the layer stays within `_MIN_MEMBERS` (2)
and `_MAX_MEMBERS`.

Removing a member drains it first:

1. The controller marks it draining in the group.
2. Gateways stop choosing it, and it closes its clients as described above.
3. It sets itself drained.
4. Only then does the quorum manager remove the machine, or once
   `_DRAIN_DEADLINE_MS` passes, the drain is abandoned and the member serves
   again.

A member an operator drained is out of service, and the loop does not count
it.

A new member is admitted once it reports to the group. It never holds a
Raft replica, so it does not wait for one (the controller's
`admit_on_join`).

The provider is `docker` for now, configured by `_DOCKER_URL`,
`_DOCKER_IMAGE`, `_DOCKER_NETWORK` and `_DOCKER_CLUSTER`. Each new container
gets `KYTHIRA_NODE_ID` from the provider and the
`KYTHIRA_REDIS_CAPACITY_JOIN_ENV` entries (`KEY=VALUE;...`): its roles, the
voters, the peer list and secrets. A node without `data` may be missing from
`KYTHIRA_PEERS`, since the voters never dial it, so one fixed join
environment fits every member the loop adds.

`KYTHIRA_REDIS_CAPACITY_DRY_RUN` is on by default. In a dry run the loop
decides and logs, but calls no provider; turn it off once the decisions
look right.

The ledger is in memory, like the group's log. A new leader reconciles from
what the provider labelled. A member that leaves the group without the
controller removing it stays in the controller's view as a stale machine
until it is decommissioned.

## Layer identities

Calls between nodes that are not both co-located carry layer identities over
mutual TLS (Requirement 19). A node's identity is a URI SAN in its forwarding
client certificate (`KYTHIRA_REDIS_FORWARD_TLS_CERT`, or the listener's
certificate):

```
kythira://redis/<cluster>/<node id>?roles=gateway,front_end
```

`<cluster>` is `KYTHIRA_REDIS_CLUSTER` (default `KYTHIRA_CLUSTER`, then
`default`). A certificate naming another cluster carries no identity. The
receiving node reads the identity from the verified client certificate in the
TLS handshake. The connection is then internal, with that node's roles, and
needs no `AUTH`. Each internal command checks the caller's roles:

| Command | Caller needs |
|---|---|
| `KYTHIRA.CALL` | `gateway` |
| `KYTHIRA.DATA`, `KYTHIRA.TXN` | `front_end` or `data` |
| `KYTHIRA.MEMBERS` | any role |
| a whole command a co-located peer forwards | `front_end` or `data` |

The internal user and secret (`KYTHIRA_REDIS_INTERNAL_USER`) stay valid
between co-located nodes and imply the `data` role only, so they can never
make an authenticated call. A node that is not co-located refuses the secret,
and so does any node whose caller presented an identity that is not
co-located (Requirement 19.3).

A node that is not co-located refuses to start without layer TLS: forwarding
TLS, a client certificate whose identity names exactly its roles, and (when
it has `front_end` or `data`) a TLS listener with a CA to verify callers
against (Requirement 19.4). `KYTHIRA_NODE_INSECURE_PLAINTEXT=1` lifts that
for tests and isolated networks. The nodes then authenticate each other with
the internal secret, which stands in for every role, over plaintext.

Certificates rotate without a restart (Requirement 19.5). The listener's and
the forwarding certificate, key and CA files are checked at most once a
second, on a new connection. A change rebuilds the TLS context for new
connections, and open connections finish on the old one. A half-written pair
fails to load and is tried again at the next check.

## Splitting and merging layers

A cluster moves between layouts one node at a time, while it serves
(Requirement 21). Every step below leaves a mixed deployment that serves,
so a migration can stop after any step, wait, or go back the way it came.
Clients may see retryable errors (`TRYAGAIN`, a closed connection from a
draining gateway) during a step. They never see a lost or doubled
acknowledged write: writes are Raft entries, and a node changes role only
after nothing it accepted is still in flight.

Before any step, and after each one:

- `KYTHIRA.LAYERS LIST` (with `KYTHIRA_REDIS_MEMBERSHIP`) shows every
  gateway and front end, serving, with the expected roles.
- `INFO` on a node shows `kythira_roles:` as intended.
- A client `SET`/`GET` through each remaining gateway succeeds.
- `KYTHIRA.EVACUATE STATUS` shows no running job, unless a step below
  started one.

### Adding or removing `gateway` or `front_end`

These layers hold no data, so changing them is a drain and a restart
(Requirement 21.2):

1. `KYTHIRA.LAYERS DRAIN <id>` on any member. Gateways stop calling a
   draining front end; a draining gateway accepts no new connection and
   closes each client once its command finishes.
2. Wait for `KYTHIRA.LAYERS LIST` to show the node `drained`. A front end
   also waits for its open `SCAN` cursors, up to
   `KYTHIRA_REDIS_CURSOR_DRAIN_MS` (60 s); a cursor still open after that
   answers `-ERR invalid cursor` on its next page, never a skipped or
   repeated key.
3. Restart the node with the new `KYTHIRA_REDIS_ROLES`, plus what the new
   set needs (`KYTHIRA_REDIS_DATA_NODES` for a front end without data,
   `KYTHIRA_REDIS_FRONT_ENDS` or the group for a gateway apart, and layer
   certificates for anything not co-located).
4. `KYTHIRA.LAYERS SERVE <id>` if it came back still marked draining.

To reverse, do the same with the old role set. Without the membership
group, step 1 is taking the node out of the load balancer (gateway) or out
of every gateway's `KYTHIRA_REDIS_FRONT_ENDS` (front end), and step 2 is
`KYTHIRA_REDIS_DRAIN_TIMEOUT_MS` on shutdown.

### Removing `data` from a node (evacuation)

A node that holds replicas will not start without `data`, unless told to
discard them (Requirement 21.3). `KYTHIRA.EVACUATE` moves them first:

1. On any data node, as an admin:

   ```
   KYTHIRA.EVACUATE START <node> [TO <id>...] [REPLICAS <n>]
   ```

   Without `TO`, every other data node the node knows
   (`KYTHIRA_REDIS_PEER_GATEWAYS`) is a target. The node fans the job out
   to each of them; `TRYAGAIN started here, not on ...` means a peer
   refused it, and running the same `START` again is safe. A peer that
   does not answer at all (down, or not started yet) is only logged, and
   a node without `data` answers that it has no part, so neither holds
   the start back; if a silent peer still leads a group, `STATUS` stays
   short of done until `START` runs again. Each data node
   then works on the groups it leads: it adds a target as a learner, lets
   it catch up, promotes it, hands leadership away when the evacuee leads,
   and removes the evacuee. `REPLICAS` is the voter count to keep
   (`KYTHIRA_REDIS_REPLICAS`, else the number of founding voters; on a
   node that joined, which founded nothing, the most voters a group it
   holds has, and `START` asks for `REPLICAS` if it holds none).
2. Poll `KYTHIRA.EVACUATE STATUS` until its first line is `done 1`. Each
   node's lines show what it holds, what it leads, the action on each led
   group and any error. Writes and reads keep working throughout.
3. On the evacuee, `KYTHIRA.EVACUATE RELEASE`. It refuses while the node
   still leads a group or any data node has not finished; once it
   answers `OK`, the node's copies no longer count anywhere.
4. Restart the evacuee without `data`. It deletes the released replicas,
   records that it left, and serves its other roles.

To reverse before step 4, run `KYTHIRA.EVACUATE CANCEL` (the groups keep
whatever voters they have, all valid) and, if replicas already moved, the
merge below with the evacuee as the target; `START` with the evacuee as a
target also withdraws its release. After step 4 the node has no data
left, so reversing it is the merge below.

A node that is down can be evacuated too: start the evacuation on any
live data node, as above. `STATUS` counts a data node it cannot reach as
not done only while that node is still a voter or learner of a group
some live node leads, so the job finishes once the dead node is removed
from every group. Skip `RELEASE`; the node is gone, and if it comes back
it must come back as a new node (a memory store) or with
`KYTHIRA_REDIS_DISCARD_REPLICAS=true`.

If a node lost its replicas some other way (a replaced disk, a group
re-seeded elsewhere), `KYTHIRA_REDIS_DISCARD_REPLICAS=true` lets it start
without `data` and delete what it holds. The groups still count it until
an evacuation or a placement operator removes it, so use this only for a
node the groups no longer need.

### Adding `data` to a node

A data node either founds the groups (a new cluster) or joins existing
ones (Requirement 21.4):

1. Start the node with `data` in its roles and with
   `KYTHIRA_REDIS_JOIN=true`. It founds no group. A node that left the
   data layer by step 4 above joins without the flag, because it recorded
   that it left; a node with a memory store keeps no record and needs it.
   Add it to every data node's `KYTHIRA_PEERS` and
   `KYTHIRA_REDIS_PEER_GATEWAYS`, or pass it in the next step.
2. On any data node, move replicas onto it by evacuating a node that is
   leaving: `KYTHIRA.EVACUATE START <leaving node> TO <new node>`.
   `ADDRESS <id> <raft-url> <host:port>` names a target the settings
   lack. The new node learns each group from a
   peer's `KYTHIRA.EVACUATE DESCRIPTOR` answer as soon as the leader adds
   it as a learner, catches up, and is promoted.
3. `KYTHIRA.EVACUATE STATUS` until `done 1`, then
   `KYTHIRA.EVACUATE CANCEL` to end the job.

A joining node that also runs `gateway` and `front_end` serves clients
only once it holds the groups: a node with `data` reaches no data
remotely, so until then its commands fail or time out. Keep it out of
the client rotation from step 1 until step 3.

To reverse, evacuate the node again.

### Whole layouts

Each layout change is a sequence of the steps above, checked between each:

| From | To | Steps |
|---|---|---|
| co-located | gateway apart | for each node to become a gateway: drain, restart as `gateway` with `KYTHIRA_REDIS_FRONT_ENDS` |
| co-located | front ends without data | add data nodes (`KYTHIRA_REDIS_JOIN`), evacuate each co-located node onto them, release, restart it as `gateway,front_end` |
| co-located | three-way | the two rows above, data first |
| three-way | co-located | restart each front end with `data` and `KYTHIRA_REDIS_JOIN`, evacuate each data node onto them, release, then retire the data nodes and restart the gateways with every role |
| gateway + front end apart from data | co-located | add `data` to the front ends (as above), evacuate the data nodes |

The in-process test `redis_layer_migration_test` evacuates a founding data
node onto a joined one under writes, releases it, and brings it back.

`redis_layer_paths_test` walks one in-process cluster through every row of
the table both ways, under writes: co-located, a data split stopped and
reversed midway, gateway and front end apart from data, three-way, and
back. It checks every acknowledged write after each step. The container
scenario `layer_paths_chaos_test` (`docker-layer-paths-tests`, on Docker
and rootless Podman) walks the same path with the real daemon. On the way
it kills a data node for good and evacuates it while it is down, and it
kills and restarts the only gateway and a front end.

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

### Task 20: the layer work as a whole

Measured on 2026-11-26 the same way, with the build before task 16b
against the build with tasks 16b to 20 (every layer split, the
evacuation and the fixes the migration path tests found). Each build ran
12 times, alternating, three rounds each, so 36 rounds:

| Entry | Metric | Before | After | Change |
|---|---|---|---|---|
| leader | `SET` p50 | 663 µs [611-720] | 653 µs [593-725] | -1.6% |
| leader | `SET` p99 | 992 µs [848-1316] | 990 µs [810-1311] | -0.3% |
| leader | `GET` p50 | 81 µs [65-103] | 83 µs [65-103] | +2.5% |
| leader | `GET` p99 | 233 µs [172-303] | 232 µs [167-335] | -0.4% |
| leader | 8 clients | 33,478 ops/s [25,623-39,442] | 32,978 ops/s [27,514-39,481] | -1.5% |
| follower | `SET` p50 | 732 µs [607-846] | 742 µs [672-809] | +1.4% |
| follower | `SET` p99 | 1108 µs [938-1727] | 1122 µs [930-2030] | +1.3% |
| follower | `GET` p50 | 161 µs [137-205] | 172 µs [137-199] | +6.5% |
| follower | `GET` p99 | 417 µs [317-561] | 443 µs [357-549] | +6.2% |
| follower | 8 clients | 35,629 ops/s [22,340-42,114] | 34,513 ops/s [26,391-44,750] | -3.1% |

Every change is inside the range of rounds of the same build. The
largest, a follower's forwarded `GET`, is +6.5% on the median with the
two ranges almost the same; it is the row to watch if a later task adds
work to the forward path.
