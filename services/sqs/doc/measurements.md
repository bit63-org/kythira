# Measurements

`.kiro/specs/sqs-compatible-queues/` Requirement 13.5: send and receive
throughput and latency for standard and FIFO queues, co-located and split.
`../tools/sqs_load.py` takes them.

## How a row is taken

```
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
  services/sqs/tools/sqs_load.py http://n1:9324,http://n2:9324,http://n3:9324 \
  [--fifo [--high-throughput]] --producers 16 --consumers 16 --seconds 10 --markdown
```

- **Send**: the producers call `SendMessage` (one 256-byte message each)
  for the duration. Throughput is messages a second; latency is per call.
- **Receive**: consumers drain what the send phase left, each looping
  `ReceiveMessage` (10 at most, 1 s wait) and `DeleteMessageBatch`.
  Throughput is messages a second; latency is per receive call that
  returned messages.
- Threads spread round robin over the endpoints given, so on a cluster
  two thirds of the calls land on followers and are forwarded.
- The tool fails if fewer messages come back than were sent.

## Rows

All rows so far come from one 4-vCPU development container (Xeon 2.1 GHz,
15 GiB), with the load generator (Python, boto3) on the same host. The
generator saturates the CPU first, so these are lower bounds on what the
nodes sustain, useful for comparing modes and catching regressions, not
for sizing. The durable rows use the module with the in-memory key-value
engine in place of RocksDB, so they include Raft replication and
forwarding over loopback but no disk.

| Layout | Queue | Producers / consumers | Send msg/s | Send p50 / p99 ms | Receive msg/s | Receive p50 / p99 ms |
|---|---|---|---|---|---|---|
| in-memory, 1 node | standard | 16/16 | 703 | 20.1 / 65.3 | 2208 | 21.5 / 69.6 |
| in-memory, 1 node | FIFO | 16/16 | 261 | 2.7 / 938.8 | 1471 | 21.9 / 70.6 |
| in-memory, 1 node | FIFO (high throughput) | 16/16 | 691 | 20.5 / 66.4 | 2090 | 21.6 / 75.9 |
| co-located, 3 nodes | standard | 16/16 | 509 | 29.4 / 68.3 | 1645 | 30.0 / 75.9 |
| co-located, 3 nodes | FIFO | 16/16 | 509 | 29.6 / 66.8 | 1581 | 32.1 / 69.6 |
| co-located, 3 nodes | FIFO (high throughput) | 16/16 | 504 | 29.9 / 68.3 | 1455 | 35.9 / 120.8 |
| split | | | | | | |

Taken 2026-11-18. Reading them:

- The one-node FIFO row is SQS's limit at work: 300 `SendMessage` calls a
  second per queue without batching. Calls past it answer
  `RequestThrottled` and the SDK backs off, hence the 939 ms p99. On three
  nodes each front end counts its own calls ([unsupported.md](unsupported.md)),
  so the same load passes.
- A receive costs one Raft round trip, like a send, and returns up to ten
  messages, so receive throughput runs about three times send throughput
  at the same call latency.
- The split row waits for task 10 (independent layers).

A row on production hardware (RocksDB on local NVMe, the generator on
other machines, real TLS) belongs in this table before anyone sizes a
cluster from it.
