# Configuring sqs_node

`.kiro/specs/sqs-compatible-queues/` Requirement 14.1. `sqs_node` reads
every setting from its environment and checks all of them before it binds
a port; a refusal names the variable. The authoritative table is the
header of `../include/kythira/sqs/sqs_node_options.hpp`; this page explains
how the settings fit together.

## Two modes

| Mode | When | What it is for |
|---|---|---|
| Durable | `KYTHIRA_NODE_DATA_DIR` is set (builds with the durable module) | Production. The SQS module of `kythira_node` alone on a node: queues in RocksDB under `multi_raft`, one or more nodes, a send acknowledged once committed. |
| In memory | otherwise | Development and the client suites (`../tests/clients/`). One node, queues in `local_queue_cluster`, lost when it stops. |

The same SQS settings apply to both. `kythira_node` with
`KYTHIRA_SERVICES=sqs` (module number 9) runs the durable module beside
other services and takes the same variables.

## The listener

| Variable | Default | Notes |
|---|---|---|
| `SQS_LISTEN` | `0.0.0.0:9324` | Port 0 picks one, which a multi-node cluster can only use with `SQS_PEER_ENDPOINTS`. |
| `SQS_TLS_CERT`, `SQS_TLS_KEY` | | Required unless `SQS_ALLOW_PLAINTEXT` is set. |
| `SQS_ALLOW_PLAINTEXT` | off | HTTP instead of HTTPS. Development only: receipt handles and SigV4-signed requests then cross the network in the clear. |
| `SQS_ENDPOINT` | derived from the listener | The scheme and host queue URLs are minted on. Set it behind a load balancer, so URLs name the address clients use. |
| `SQS_REGION`, `SQS_PARTITION` | `us-east-1`, `aws` | What SigV4 scopes and ARNs name. |
| `SQS_MAX_BODY_BYTES` | 4194304 | The largest request body read. Raise it with `message-size` (below) past 4 MiB. |

## Identity and secrets

| Variable | Notes |
|---|---|
| `SQS_STATIC_KEYS_FILE` | Required. Access keys, one per line: `access-key-id secret account name role` (core's `static_keys_file.hpp`); `#` starts a comment. |
| `SQS_FORWARD_SECRET` | The cluster's shared secret. It authenticates node-to-node forwarding, and derives the receipt-handle and SSE-SQS keys when their files are not given. Every node needs the same value. |
| `SQS_RECEIPT_KEYS_FILE` | Receipt-handle keys (`sqs_receipts.hpp`). Handles are signed with the first key and checked with whichever key they name: rotate by putting a new key first and keeping the old one for at least 12 hours, the longest visibility timeout. |
| `SQS_SSE_KEY_FILE` | The SSE-SQS master secret, at least 16 bytes ([encryption.md](encryption.md)). |

A durable node refuses to start without either `SQS_RECEIPT_KEYS_FILE` or
`SQS_FORWARD_SECRET`, and without either `SQS_SSE_KEY_FILE` or
`SQS_FORWARD_SECRET`: a node that invented its own keys would mint handles
and seal bodies no other node can open.

## A durable cluster

The node's own settings are core's: `KYTHIRA_NODE_ID`,
`KYTHIRA_NODE_PEERS`, `KYTHIRA_NODE_RAFT_BIND`, `KYTHIRA_NODE_RAFT_PORT`,
`KYTHIRA_NODE_TLS_CERT`, `_TLS_KEY`, `_TLS_CA` and
`KYTHIRA_NODE_INSECURE_PLAINTEXT`. SQS adds:

| Variable | Default | Notes |
|---|---|---|
| `SQS_PEER_ENDPOINTS` | every peer's host on this node's SQS port | `id=scheme://host:port` of each node's SQS listener, comma-separated. A follower forwards writes to the leader's listener. Set it when nodes listen on different ports (one host, tests). |
| `SQS_PEER_CA` | `KYTHIRA_NODE_TLS_CA` | The CA a forward checks the leader's certificate against. |
| `SQS_PROPOSE_TIMEOUT_MS` | 5000 | How long a write waits to commit before the client gets a retryable error. |

Every node of `KYTHIRA_NODE_PEERS` is a voter of the one SQS group.

## Layers

A node runs every layer by default. `KYTHIRA_SQS_ROLES` splits them.
[layers.md](layers.md) covers choosing a layout and sizing each layer.

| Variable | Default | Notes |
|---|---|---|
| `KYTHIRA_SQS_ROLES` | `gateway,front_end,data` | The layers this node runs, comma-separated. Anything but all three needs `SQS_FORWARD_SECRET`, which signs the calls between layers. |
| `SQS_DATA_ENDPOINTS` | | Base URLs of the data nodes' SQS listeners, comma-separated. Required by a front end without `data`. |
| `SQS_FRONT_END_ENDPOINTS` | | Base URLs of the front ends' SQS listeners, comma-separated. Required by a gateway without `front_end`. |
| `SQS_IDENTITY_CLUSTER` | `default` | The cluster part of the layer identities this node accepts over TLS (below). |
| `SQS_JOIN` | off | A data node that joins a running group as a learner, to receive a replica by evacuation ([migration.md](migration.md)). |
| `SQS_EVACUATE_TIMEOUT_MS` | 300000 | How long one `evacuate` admin call runs before it answers 504. Calling it again carries the move on. |

- **gateway** checks clients' SigV4 signatures. With `front_end` it
  serves the API in-process. Without it, it hands each request with the
  verified caller to a front end, taking them in turn; when the front end
  cannot be reached the client gets `ServiceUnavailable` (503), which SDKs
  retry. A node without `gateway` serves no client API.
- **front_end** runs the SQS handlers and authorization. It serves
  gateways' calls at `/_kythira/sqs/v1/call`. Without `data`, its writes and
  reads go to the data nodes over `SQS_DATA_ENDPOINTS`. It tries them in
  turn from the one that last answered, and only the leader answers, so a
  client reads its own writes. Its long polls park locally, woken by a
  stream from every data node (any one of them suffices).
- **data** holds a replica of the queues, runs the leader-side workers
  (delays and visibility ends, message moves, partition growth) and serves
  the internal endpoints under `/_kythira/sqs/v1/`: propose, named reads,
  and the availability stream. On a co-located cluster a follower reaches
  the leader the same way, through the other nodes' `SQS_PEER_ENDPOINTS`.

The gateway and front end hold no queue state, and need
`SQS_STATIC_KEYS_FILE` (the gateway authenticates with it, the front end
authorizes) but no `KYTHIRA_NODE_PEERS` beyond themselves. Queue URLs are
minted by the front end, so set its `SQS_ENDPOINT` to the address clients
use, the gateways' load balancer.

Stopping a front end drains it first: parked long polls answer
empty at once, which clients treat as an ordinary empty receive.

```
# data nodes 1-3: the durable cluster above, plus
KYTHIRA_SQS_ROLES=data
# front ends
KYTHIRA_SQS_ROLES=front_end
SQS_DATA_ENDPOINTS=https://d1:9324,https://d2:9324,https://d3:9324
SQS_ENDPOINT=https://sqs.example.com
# gateways, behind https://sqs.example.com
KYTHIRA_SQS_ROLES=gateway
SQS_FRONT_END_ENDPOINTS=https://f1:9324,https://f2:9324
# everywhere: the same SQS_FORWARD_SECRET and SQS_STATIC_KEYS_FILE
```

### Layer identities

Over TLS with a peer CA (`SQS_PEER_CA` or `KYTHIRA_NODE_TLS_CA`, which a
node running only some layers requires), each node presents its
listener's certificate (`SQS_TLS_CERT`) when it calls another, and checks
callers of the internal routes against the identity in theirs: a URI SAN
`kythira://sqs/<SQS_IDENTITY_CLUSTER>/<node id>?roles=<roles>`, which
Kythira's CA issues (core's `layer_identity.hpp`) or you put in a
certificate yourself. The listener asks for a client certificate but does
not require one, so SDK clients connect as before.

| Route | Open to |
|---|---|
| `/_kythira/sqs/v1/propose`, `/query`, `/availability` | `front_end`, `data` |
| `/_kythira/sqs/v1/call` | `gateway` |
| `/_kythira/sqs/v1/admin/...` (`peer`, `evacuate`, `step`) | `data` |

A front end's certificate therefore cannot make a gateway's call, which
names any principal it likes, and a gateway's cannot read or write
queues. A refusal is a 403 naming the reason; to the client behind a
gateway it is `ServiceUnavailable`. A caller whose certificate names no
identity of this cluster (a co-located cluster whose certificates predate
identities) may still prove `SQS_FORWARD_SECRET`, and then holds `data`
alone: it reaches what replicas call each other on, never `/call`. So a
gateway on its own nodes needs an identity with `gateway`. On plaintext
(`SQS_ALLOW_PLAINTEXT`) the forwarding secret opens every internal route:
there is nothing else to tell the layers apart by, which is one more
reason plaintext is for development only.

The forwarding secret is still needed with identities: it derives the
receipt-handle and SSE-SQS keys unless their files are given.

## Encryption with KMS keys

| Variable | Default | Notes |
|---|---|---|
| `SQS_KMS` | `none` | `none`: queues with `KmsMasterKeyId` refuse sends with `KmsNotFound`. `local`: data keys wrapped under a key derived from a passphrase. |
| `SQS_KMS_PASSPHRASE_FILE` | | `local`'s passphrase; every node needs the same one. |

## The SNS bridge

| Variable | Default | Notes |
|---|---|---|
| `SQS_SNS_BRIDGE` | `off` | `on` serves `/sns-bridge/<account>/<queue>` ([sns-bridge.md](sns-bridge.md)). |
| `SQS_SNS_CERT_HOSTS` | `sns.<region>.amazonaws.com` | Hosts signing certificates and subscribe URLs may come from. |
| `SQS_SNS_CA` | `/etc/ssl/certs/ca-certificates.crt` | The roots those hosts chain to. |

## Compatibility switches

Every limit defaults to SQS's value. `SQS_COMPAT` moves one for the whole
cluster (`name=value`, comma-separated), and a queue tag
`kythira:compat:<name>` moves it for one queue; the queue's value wins.
No switch changes an error code, message or status: a request past a moved
limit fails exactly as it would past SQS's.

| Switch | SQS value | Range | Bounds |
|---|---|---|---|
| `message-size` | 1048576 | 1024-16777216 | body plus attributes, bytes |
| `retention-min` | 60 | 1-1209600 | `MessageRetentionPeriod` floor, s |
| `retention-max` | 1209600 | 60-31536000 | `MessageRetentionPeriod` ceiling, s |
| `batch-size` | 10 | 1-100 | entries per batch request |
| `inflight-standard` | 120000 | 1-10000000 | in-flight messages, standard queues |
| `inflight-fifo` | 120000 | 1-10000000 | in-flight messages, FIFO queues |
| `fifo-throughput` | `on` | `on`, `off` | FIFO request rates |
| `long-poll-max` | 20 | 0-300 | `WaitTimeSeconds` ceiling, s |
| `delete-cooldown` | 60 | 0-3600 | recreating a name after `DeleteQueue`, s |
| `purge-cooldown` | 60 | 0-3600 | between `PurgeQueue` calls, s |

Every numeric switch also takes `aws`. An unknown switch or a value out of
range is refused, so a typo in a tag fails at `CreateQueue` or `TagQueue`
instead of silently keeping SQS's value. The client suites run with both
cool-downs at 0 because each client reuses its queue names.
