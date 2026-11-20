# Moving between layouts

Every layer of `sqs_node` can run co-located or on its own nodes
([configuration.md](configuration.md#layers)). This page describes how to move
a running cluster from one layout to another and back, without stopping it
and without losing messages (`.kiro/specs/sqs-compatible-queues/`
Requirement 12).

During every step below:

- no acknowledged message is lost;
- FIFO order and deduplication hold;
- visibility timeouts keep their deadlines;
- receipt handles issued before a step still work after it.

Each path is tested in both directions under standard and FIFO load by
`tests/sqs_migration_test.cpp`. The whole path, co-located to split and
back with one node of every layer killed on the way, runs again in
containers under Docker and rootless Podman (`tests/docker/`, the
`docker-sqs-node-tests` target).

## Stateless layers: drain and restart

Gateways and front ends hold no queue state. To move one, start its
replacement, point clients (or the load balancer) at it, then stop the old
node.

- **Stopping a front end** first answers its parked long polls with empty
  receives, which SQS clients treat as an ordinary empty poll. Then it
  closes its listener.
- **A gateway without the front-end role** cannot end a poll parked on a
  front end. Stopping it waits up to 25 seconds for those polls to be
  answered before it closes.

Some changes to what a node knows also take a restart, one node at a time:

- a front end's `SQS_DATA_ENDPOINTS`;
- a gateway's `SQS_FRONT_END_ENDPOINTS`.

## The data layer: evacuate

A data replica moves with `evacuate`, which takes four steps on the group's
leader:

1. Add the new node as a learner. It catches up without counting toward
   quorum.
2. Promote it once its log is within 64 entries of the leader's.
3. If the old node leads, hand leadership to the new one.
4. Remove the old node.

Each step is an ordinary Raft configuration change. The new replica
receives the queues whole, with every message, receipt key and deadline.

`services/sqs/tools/sqs_admin.py` makes the calls. They are signed with
`SQS_FORWARD_SECRET`. Over TLS, pass `--cert`/`--key` with a layer identity
that holds `data`, and `--ca`.

```
# 1. Start the new data node as a learner of the running group.
SQS_JOIN=on KYTHIRA_SQS_ROLES=data KYTHIRA_NODE_ID=4 \
  KYTHIRA_NODE_PEERS=1=d1:7000,2=d2:7000,3=d3:7000,4=d4:7000 \
  SQS_PEER_ENDPOINTS=1=https://d1:9324,2=https://d2:9324,3=https://d3:9324,4=https://d4:9324 \
  ... sqs_node

# 2. Tell every data node where it listens.
sqs_admin.py peer https://d1:9324 https://d2:9324 https://d3:9324 https://d4:9324 \
  --id 4 --raft https://d4:7000 --sqs https://d4:9324

# 3. Move node 1's replica to it. The call returns when the move is done.
sqs_admin.py evacuate https://d2:9324 --from 1 --to 4
```

How the steps behave:

- **Starting a joiner.** `SQS_JOIN=on` makes the node a learner that never
  campaigns. Its `KYTHIRA_NODE_PEERS` names the group's current members and
  itself. The leader's snapshot replaces that first configuration, and a
  restart keeps the stored one.
- **Announcing.** Announce each new node to every data node, the other new
  ones included. A node keeps what it was told in its data directory
  (`peers.json`), so after a restart it still reaches members that joined
  after its `KYTHIRA_NODE_PEERS` was written.
- **Running an evacuation.** `evacuate` runs on any data node, which finds
  the leader. It answers:
  - 200 when done, listing the steps it took;
  - 409 when the move is impossible;
  - 504 when it ran out of time (`SQS_EVACUATE_TIMEOUT_MS`, 300 s). The move
    stays where it stood.
- **Calling it again** carries the move forward from wherever it stands. It
  makes no difference whether the move stopped because of a timeout, a lost
  leader or a crashed node.
- **Reversing.** `evacuate --from 4 --to 1` reverses a move from any point.
  A learner that was added is removed again. A promoted node is removed
  while the original is still voting.
- **Retiring the old node.** After its replica has gone, stop it and delete
  its `raft` directory (`$KYTHIRA_NODE_DATA_DIR/raft` for `sqs_node`,
  `$KYTHIRA_NODE_DATA_DIR/sqs/raft` in `kythira_node`) before restarting it without the data role. A node
  refuses to start without `data` while that directory holds a replica,
  because the group would still count it toward quorum. To bring it back as
  a data node, start it fresh with `SQS_JOIN=on`.

Front ends try the data nodes they know in turn, and only the leader
answers. A front end that is co-located with a data node learns about new
data nodes from `peer`. A front end on its own node must be restarted with
the new nodes in `SQS_DATA_ENDPOINTS`, before their old ones go.

## Co-located to split

Starting from three nodes with every role:

1. Start the data nodes with `SQS_JOIN=on` and `KYTHIRA_SQS_ROLES=data`, and
   `peer` each one to every data node.
2. Start the front ends: `KYTHIRA_SQS_ROLES=front_end`, with
   `SQS_DATA_ENDPOINTS` naming the old nodes and the new ones.
3. Start the gateways: `KYTHIRA_SQS_ROLES=gateway`, with
   `SQS_FRONT_END_ENDPOINTS`. Move clients to them.
4. Evacuate each old node to a data node. The old nodes keep serving any
   clients that still reach them, through the data nodes.
5. Stop the old nodes, or restart them as gateways or front ends after
   deleting their `raft` directories. Restart the front ends with only
   the data nodes in `SQS_DATA_ENDPOINTS`.

**Split back to co-located** is the same in reverse:

1. Start nodes with every role and `SQS_JOIN=on`, and `peer` them.
2. Evacuate each data node to one of them.
3. Move clients back to the co-located nodes.
4. Stop the gateways, the front ends and the data nodes.

**Stopping midway.** You can stop at any point, and reverse by evacuating
the other way.
