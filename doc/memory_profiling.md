# Memory profiling pass (November 2026)

The last open item in `doc/TODO.md` was an optional memory-usage
profiling pass. This file records what was run, what it found, the two
fixes it led to, and how to run it again.

## Summary

- **One unbounded-growth bug, fixed.** A persistent Raft group whose
  state machine did not offer `sync_durable()` never compacted its log on
  RocksDB, so the log grew in memory (and in the log file) until the node
  restarted. DynamoDB's group, catalog and item state machines lacked it.
  KMS, HSM and ledger had it on the inner state machine, but their group
  wrappers, which are what the Raft node holds, did not pass it on. Under
  a steady DynamoDB workload on RocksDB the leader's heap reached 176 MB
  in five minutes and was still climbing. After the fix it is a sawtooth
  between about 7 and 70 MB, almost all of it RocksDB memtable.
- **One small waste, fixed.** The JSON, CBOR, Protobuf and Ion
  serializers returned `media_type()` as a new `std::string`. The
  transports call it on every RPC (`supports()`), and
  `"application/json"` is one character past the small-string buffer, so
  every check was a heap allocation: about 14 per DynamoDB request on
  each node. They now return a reference to a constant. Allocations per
  request across a three-node cluster fell by about 4%.
- **No leaks.** Every clean shutdown left at most 21 KB unfreed, all of
  it the iostream buffer and thread-local or thread-start state that
  lives as long as the process.
- **The in-memory DynamoDB engine is bounded.** With a fixed key set its
  heap stays a sawtooth between 4 and 28 MB, set by the 10 MB snapshot
  threshold.
- **KMS is small.** A three-node KMS cluster over SoftHSM2 ran at 7.5 MB
  of live heap after five minutes. What grew was key objects inside
  SoftHSM2, one per `CreateKey`, and the RocksDB memtable.

## What was profiled

All runs used `kythira_node` built from `main` at `c3b1b0c` with the
Boost future backend and no Folly (`configs/ci_no_folly_defconfig` plus
`CONFIG_ENGINE_ROCKSDB=y`), `-O2 -g1`, GCC 13, Boost 1.83, RocksDB 8.9,
on a 4-core, 16 GB cloud sandbox. Three nodes on 127.0.0.1, plaintext,
static keys. Each run was five minutes of steady load from boto3 with 8
client threads spread over the nodes.

| Run | Services | Engine | Workload |
|-----|----------|--------|----------|
| DynamoDB, memory | `dynamodb` | memory | 40% Put, 30% Get, 10% Query, 15% Update, 5% Delete; 5000 keys, 512 B items |
| DynamoDB, memory, bounded set | `dynamodb` | memory | same mix, 200 keys, 8 KB items |
| DynamoDB, RocksDB | `dynamodb` | rocksdb | same as the first, and the 200 key, 8 KB variant under heaptrack |
| KMS | `kms` | RocksDB (module default) over SoftHSM2 | 30% GenerateDataKey, 30% Encrypt, 30% Decrypt, 5% DescribeKey, 5% CreateKey over 20 keys |

Each workload ran once without instrumentation, sampling every node's
RSS every five seconds, and once under heaptrack 1.5.

Not covered, and why:

- **Kinesis and Redis**: on `main` their daemons and `kythira_node`
  modules still need Folly, which this sandbox does not have
  (`services/kinesis/cmd/CMakeLists.txt` and
  `services/redis/cmd/redis_gateway_node/CMakeLists.txt` return early
  without it). They are worth a run once the Folly-free daemons land.
- **SQS and SNS**: on `main` `sqs_node` and `sns_node` are still
  stubs; the services arrive with their open pull requests.
- **IAM and HSM on their own**: IAM needs a TLS PKI and an unseal key,
  and the HSM module an initialization and unseal ceremony. Neither was
  set up here. Both modules were compiled into the profiled binary, and
  the HSM got the same `sync_durable()` fix by inspection (below).

## Results

RSS is `VmRSS` of each `kythira_node` process; heap is heaptrack's
figure for the busiest node.

| Run | Throughput | RSS at start → after 5 min | Peak heap | Live heap shape |
|-----|-----------:|----------------------------|----------:|-----------------|
| DynamoDB, memory | 566 ops/s | 20 → 52-80 MB | 28 MB | rises until the first snapshot, then flat |
| DynamoDB, memory, 200 keys × 8 KB | 82 ops/s (heaptrack) | n/a | 28 MB | sawtooth 4-22 MB |
| DynamoDB, RocksDB, **before** | 504 ops/s | 34 → 144 MB, rising | 176 MB | rising sawtooth, no plateau |
| DynamoDB, RocksDB, **after** | 525 ops/s | 34 → 99-110 MB | 85 MB | sawtooth 7-70 MB |
| KMS over SoftHSM2 | 35 ops/s | 31 → 34-38 MB | 7.9 MB | slow rise with key count |

`MALLOC_ARENA_MAX=2` made no difference to the in-memory DynamoDB run
(52-62 MB against 52-80 MB), so RSS above the live heap is freed memory
glibc keeps, not per-thread arenas.

The KMS run hit AWS's default per-account request quotas
(`KYTHIRA_KMS_THROTTLING=on`), which is why its throughput is low; the
throttled answers are cheap and did not affect the heap.

### Where the heap goes

In-memory DynamoDB, at the peak: the Raft log twice over, once in the
node's `_log` and once in `memory_persistence_engine`, about 9.5 MB each
(the snapshot threshold), then the item store. Both copies are freed at
each snapshot.

DynamoDB on RocksDB, after the fix, at the peak: 82% RocksDB memtable
(`rocksdb_kv_engine::impl::write_locked`), 12% the Raft log (under the
10 MB threshold), then RocksDB reads. `rocksdb_kv_engine` leaves
`write_buffer_size` at RocksDB's 64 MB default, so the memtable alone can
take tens of MB per node before a flush. If a smaller footprint matters,
that is the setting to expose; it is a trade against write
amplification, not a defect.

KMS, live at the end: 53% SoftHSM2's own key objects (allocated inside
`C_GenerateKey`, one per key the run created), 34% the RocksDB memtable
and engine, the rest small.

### Allocation rate

Under heaptrack a three-node DynamoDB cluster made about 2,300
allocations per client request across its nodes. The largest groups,
by innermost Kythira frame: the future continuations of the Boost
backend (`via`, `thenValue`, `thenError`, `thenTry`, promises; about a
quarter together), the Beast Raft client and server (`send_rpc`,
connection reads and writes), SigV4 verification (`hmac_sha256`, 2.7%:
OpenSSL 3's one-shot `HMAC()` allocates a context each call and a
request needs five), and DynamoDB key decoding. None of these is a leak
or growth. Caching the derived SigV4 signing key per access key and day
would remove four of the five HMACs per request; that, and fewer
allocations in the future backend, are the candidates if allocation rate
ever matters.

## The log-compaction bug

`raft::node` compacts a persistent group's log only up to the state
machine's `durable_applied_index()` (persistent-state-machine Requirement
3.1). RocksDB writes its WAL unsynced, so that index moves only when
something calls `SyncWAL`. For that the node calls the state machine's
`sync_durable()` before compacting, when the state machine has one
(Requirement 3.3, `persistent_sync_lag_entries`). It is optional in the
`persistent_state_machine` concept and found with a `requires`
expression, so a state machine without it compiles and runs, and its log
is simply never compacted.

The symptom in the node's log was the line `Applied log reached the
snapshot threshold, snapshotting` on every applied entry once a group
passed 10 MB: 20,552 times in five minutes on one node, with
`bytes_applied_since_snapshot` reaching 100 MB. No snapshot was ever
saved, because the durable index never passed the last snapshot.

Why tests never saw it: `memory_kv_engine`, which every in-process test
uses, treats every write as durable unless a test calls
`hold_durability()`. Only the RocksDB engine shows the gap.

The fix adds `sync_durable()` to `dynamo_item_state_machine`,
`dynamo_catalog_state_machine`, `basic_ledger_state_machine` and
`basic_ledger_catalog`, and forwards it from `dynamo_group_state_machine`,
`kms_group_state_machine`, `hsm_group_state_machine` and
`basic_ledger_group_state_machine`. Each group wrapper's test now asserts
that it offers `sync_durable()`, so a wrapper that drops it again fails
to compile, and `dynamodb_item_state_machine_test` checks that the call
makes every applied entry durable. After the fix the same run logged
the threshold line once per snapshot, each followed by `Persistent
snapshot metadata saved`.

## Running it again

The tools are in `scripts/memory-profile/`:

- `cluster.py KYTHIRA_NODE OUTDIR SERVICES N [--heaptrack] [--engine memory|rocksdb]`
  starts the cluster, every port picked free by the kernel, and stops it
  cleanly on SIGINT. It signals each node itself, never the heaptrack
  wrapper: killing `heaptrack_interpret` kills the node with SIGPIPE
  before heaptrack writes its data.
- `workload.py dynamodb|kms OUTDIR SECONDS [--threads N] [--keys K] [--payload BYTES]`
  drives it with boto3 and writes `rss.csv` and `workload.json`. It
  samples `kythira_node` itself; under heaptrack the interpreter process
  is about 900 MB and easy to mistake for the node.
- `heap_report.py HEAPTRACK_FILE [--cost peak|leaked|allocations]` prints
  heaptrack's totals, the heap over time, and the top innermost Kythira
  frames for that cost.

For example, the RocksDB run under heaptrack:

```sh
scripts/memory-profile/cluster.py build/kythira_node /tmp/ddb dynamodb 3 \
    --heaptrack --engine rocksdb &
scripts/memory-profile/workload.py dynamodb /tmp/ddb 300 --payload 8192 --keys 200
kill -INT %1; wait
scripts/memory-profile/heap_report.py /tmp/ddb/heaptrack.node1.gz
```

Give heaptrack about 1 GB per node for its interpreter, and do not run
it beside a build of the large module translation units: some of them
take 14 GB to compile.
