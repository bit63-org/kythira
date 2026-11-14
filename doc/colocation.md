# Running services together in `kythira_node`

`kythira_node` runs any of Kythira's services in one process, each as a
module (`.kiro/specs/service-colocation/`). `KYTHIRA_SERVICES` names them;
`kythira_node --help` lists the ones compiled in. Each stand-alone daemon
(`redis_gateway_node`, `dynamodb_gateway_node`, `kinesis_gateway_node`,
`ledger_node`, `iam_node`) is still built and runs the same module code on
its own.

This page covers resource isolation (task 9), IAM's group in both
layouts (task 8) and the container image (task 10). Moving a service
between layouts follows with task 11.

## What each module has to itself

Every module keeps its own:

- **Raft host.** Each module runs its own `multi_raft` host, with its own
  executor stripes, tick thread, placement driver and Raft logs, in its
  own group-id range (`m << 56`), behind the node's one Raft listener. One
  module's backlog of proposals does not queue behind another's.
- **Request threads.** Each module serves its API on its own listener,
  one thread per connection, up to its own connection cap. A flood that
  fills one module's cap is refused at that module's listener and holds no
  other module's threads.
- **Disk floor and memory limits**, enforced as the stand-alone daemon
  enforces them, against the module's own data directory under
  `KYTHIRA_NODE_DATA_DIR`.

| Module | Request threads | Raft tuning prefix | Disk and memory |
|---|---|---|---|
| Redis (`redis`) | `KYTHIRA_REDIS_IO_THREADS`, `_WORKER_THREADS` | `KYTHIRA_REDIS_` | `KYTHIRA_CACHE_MAX_DISK_BYTES`, `KYTHIRA_REDIS_MAX_VALUE_BYTES` |
| DynamoDB (`dynamodb`) | `KYTHIRA_DYNAMODB_MAX_CONNECTIONS` (256) | none read | `KYTHIRA_DYNAMODB_DISK_FLOOR_BYTES` |
| Kinesis (`kinesis`) | `KINESIS_MAX_CONNECTIONS` (256) | `KINESIS_` | `KINESIS_DISK_FLOOR_BYTES`, `KINESIS_MAX_BODY_BYTES` |
| Ledger (`ledger`) | `KYTHIRA_LEDGER_MAX_CONNECTIONS` (512) | `KYTHIRA_LEDGER_` | `KYTHIRA_LEDGER_SNAPSHOT_DISK_MARGIN_BYTES`, `KYTHIRA_LEDGER_MAX_BODY_BYTES` |
| IAM (`iam`) | `KYTHIRA_IAM_MAX_CONNECTIONS` (256) | none read | none |

The stand-alone daemons read their Raft tuning under bare names
(`KYTHIRA_EXECUTOR_STRIPES`, `KYTHIRA_ELECTION_TIMEOUT_MIN_MS`,
`_MAX_MS`, `KYTHIRA_HEARTBEAT_INTERVAL_MS`, `KYTHIRA_RPC_TIMEOUT_MS`,
`KYTHIRA_TICK_INTERVAL_MS`, `KYTHIRA_POLICY_INTERVAL_MS`,
`KYTHIRA_LOG_LEVEL`). In `kythira_node` each module looks first for the
name under its own prefix (`KINESIS_EXECUTOR_STRIPES`,
`KYTHIRA_REDIS_HEARTBEAT_INTERVAL_MS`) and then for the bare name, which
so stays a node-wide default. `KYTHIRA_SHARD_CUTS` names one service's
keys, so in `kythira_node` only the prefixed form is read
(`KINESIS_SHARD_CUTS`, `KYTHIRA_REDIS_SHARD_CUTS`).

Every module reports `kythira_<module>_raft_term_sum` on the node's
`/metrics`: the sum of the current terms of its groups on that member. It
rises with every election one of them starts, so an alert on its rate
catches a module whose heartbeats stall. `kythira_node_iam_test` holds
every Kinesis request thread busy for twenty seconds and checks that
neither Kinesis's nor IAM's sum moves on any member (Requirement 6.3).

## IAM in either layout

IAM's Raft group is one group on a multi-raft host in both layouts, at
the same group id (`(5 << 56) | 1`), so `iam_node` and the IAM module of
`kythira_node` keep the same files: `iam_node --data-dir` holds exactly
what `kythira_node` keeps in `KYTHIRA_NODE_DATA_DIR/iam/`. Read replicas,
`iam_node --replica` or a stand-alone gateway's embedded one, join either.
`iam_node` from before task 8 kept a plain Raft group's files instead;
`iam_node --convert-data-dir` converts them, with the whole cluster
stopped (`services/iam/README.md`).

One difference: `iam_node` binds each Raft certificate to one node id,
from the reserved peer SAN it carries, while `kythira_node`'s one Raft
listener accepts every certificate its CA chains, for every module. Give
`kythira_node` a CA that issues only node certificates.

## The container image and a composite cluster

`docker/kythira_node/Dockerfile` builds `kythira-node:dev`: `kythira_node`
with every module the build linked, and IAM's `kythira-iam` and
`iam_test_certs` when the IAM module is built. `cmake --build build
--target docker-kythira-node-image` stages the binaries from the host
build and builds it; the per-service images stay as they are.

`docker/kythira-node-compose.yml` runs three such nodes, `kn-1` to `kn-3`,
with DynamoDB (`:8000`), Kinesis (`:4567`) and IAM (`:8443`) on each,
every module's Raft groups on the node's one listener (`:7100`). Nodes,
Raft peers, forwarded writes and clients all go by service name, so it
runs under Docker and rootless Podman alike. Everything is TLS with a
throwaway test PKI that a one-shot `certs` service writes, and DynamoDB
and Kinesis authorize through the co-located IAM module, so a key IAM
issues works on all three at once. Use it as the starting point for a
deployment: replace the test PKI, the unseal passphrase and the
forwarding secrets with your own.

`cmake --build build --target docker-kythira-node-tests` runs the
scenario against it (`cmd/kythira_node/kythira_node_scenario_test.cpp`,
`.github/workflows/composite-node.yml` in CI): it creates an account with
`kythira-iam`, then a user, a table and a stream, and runs a mixed
PutItem, PutRecord and CreateUser workload
(`docker/kythira_node_clients/mixed_workload.py`) while it kills the node
holding IAM's leader, restarts it, and cuts another node off the network
and back. Every write a node acknowledged must read back afterwards.

## What co-location does not isolate

Modules in one process share that process. Choose stand-alone daemons
when any of this matters:

- **Faults.** A crash, an abort or memory corruption in one module takes
  every module on the node down with it. Raft keeps each service
  available through the loss of one member, but every service loses that
  member at once.
- **Secrets.** Any module can read any other module's memory: IAM's
  unsealing key and decrypted secrets, a gateway's forwarding secret, the
  ledger's signing key, and (once it exists) the virtual HSM's key
  material (the virtual HSM's Requirement 2.5). In-process calls between
  modules are authorized like network requests, but nothing stops code in
  one module from reading another's memory.
- **CPU and memory.** Threads and executors are per module, but the cores,
  the memory allocator and the page cache are the node's. A module that
  spends every core, or exhausts memory, slows or kills the others; the
  caps above bound a module's request threads, not its CPU time. Container
  or cgroup limits apply to the node as a whole.
- **Disk bandwidth.** Each module's disk floor protects its own free
  space check, but every module writes to the same volume unless
  `KYTHIRA_NODE_DATA_DIR`'s subdirectories are mounted separately.
- **Upgrades.** Every module on a node restarts together, on one binary.
