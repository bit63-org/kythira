# Implementation Plan — Multi-Raft message batching

## Status: In progress (tasks 1-5 done, 2026-11-20)

Follow-up to `.kiro/specs/multi-raft/` design §2.3 and Phase 9. Clark gave
the go to build it on 2026-11-20. Task 9's measurement decides whether
batching is turned on anywhere; until then `batching_config::_enabled`
defaults to false and no binary turns it on.

- [x] 1. Message types and concepts
  - `append_entries_batch_request` / `_response`, `batch_member_error`, the
    client and server concepts in `network.hpp`.
  - _Requirements: 1.1_

- [x] 2. The batcher
  - `include/raft/append_entries_batcher.hpp`: per-destination queues, size
    and count flushes, oversized bypass, `flush_all`, the off-tick timer,
    per-member completion, fallback and probe.
  - Unit tests over a fake shared client.
  - _Requirements: 2.1-2.5, 3.2-3.4, 4.1, 4.2, 7.2_

- [x] 3. Host wiring
  - `batching_config`; `group_scoped_client` routes AppendEntries through the
    batcher when both concepts hold and batching is enabled; `tick()` calls
    `flush_all` at the end of the send phase; `tick_report` counters.
  - _Requirements: 1.2-1.4, 3.1, 3.5, 6.1_

- [x] 4. Server dispatch
  - The batch lambda in `multi_group_network_server::start()`, per-member
    group lookup on its stripe, unknown-group as a member error.
  - _Requirements: 2.3, 2.6_

- [x] 5. Test fabric
  - `message_fabric` batching mode and an older-build mode; run the
    multi-raft integration suites with batching on; the rolling-upgrade case.
  - _Requirements: 4.3, 7.1_
  - Done: `fabric_client`/`fabric_server` speak the batch RPC, and
    `KYTHIRA_TEST_BATCHING=1` turns batching on in the static-cluster, split,
    merge and placement-driver suites, which CMake registers a second time as
    `<suite>_batching`. A block of "append_entries" also blocks batches of
    them, so a suite's partition means the same thing in both runs. The
    rolling-upgrade case is in the static-cluster suite. The older-build mode
    is the fabric's existing `set_not_implemented`, plus
    `clear_not_implemented` for the upgrade.

- [x] 6. JSON and CBOR encodings
  - Batch request and response; round-trip tests with member byte equality.
  - Done: each member is encoded by the existing standalone encoder and
    spliced in, so a member's bytes inside a batch are its lone bytes
    (`tests/append_entries_batch_serializer_test.cpp`). Registries gained
    `handles<T>`; a transport offers batches only when every serializer in
    its registry encodes them, so protobuf and Ion builds fall back.
  - _Requirements: 5.1, 7.3_

- [x] 7. HTTP transports
  - `POST /v1/raft/append_entries_batch` on cpp-httplib, Beast and Proxygen,
    client and server; 404 to `rpc_not_implemented_exception`; member-count
    and body limits; conformance tests.
  - Done: `max_append_entries_batch_members` (256) on each server config;
    over it, or over the body limit, the server answers 413 and the client
    raises `rpc_payload_too_large_exception`, which makes the batcher resend
    the members alone without marking the peer. Beast also refuses (400) a
    batch whose members name different leaders, because its certificate
    binding checks one sender. `tests/http_append_entries_batch_test.cpp`
    covers the wire behaviour on cpp-httplib and a 3-host multi_raft
    cluster on each transport the build has.
  - _Requirements: 5.2, 5.4_

- [x] 8. Metrics
  - Members per batch, batches, fallbacks, marked destinations.
  - Done: `batching_metrics_emitter` publishes the batcher's counters to the
    host's metrics at the end of each tick, as the change since the last
    tick: `kythira.multiraft.batching.batches`, `.fallbacks`,
    `.members_per_batch` (one count per bucket, `max_members` dimension) and
    the `.marked_destinations` gauge (emitted when it moves).
    `multi_raft::batching_statistics()` gives the same totals to a caller
    without a sink.
  - _Requirements: 6.2_

- [ ] 9. Measure, then decide
  - `multi_raft_bench` on Beast, 3 hosts, 100 and 1000 busy groups, batching
    off and on: wire requests per second, CPU per committed entry, p99 commit
    latency. Record here. Turn batching on in `cmd/multi_raft_node` only if
    CPU per committed entry drops at 1000 groups.
  - _Requirements: 7.4_
  - Tooling: `multi_raft_node --batching 0|1 --count-rpcs 0|1`, the control
    port's `/stats` (process CPU, sent and wire RPCs, batch counters), and
    `scripts/run-tier-c-row.sh --batching 0|1 --host-stats`, which reads
    `/stats` around the driver and prints host CPU per committed write and
    wire requests per second.
  - 2026-11-20, Tier C in a 4-core cloud sandbox (Xeon 2.1 GHz, 3 host
    processes plus the driver on one machine, Beast + JSON, memory
    persistence, tick 2 ms, heartbeat 50 ms, 16 in flight, 5 x 2000 writes
    of 128 B plus 50 warm-up each). Host figures cover the whole driver run,
    readiness wait included.

    | groups | batching | result | ops/sec (median) | p99 | host CPU per write | wire req/s | RPCs/s |
    |---|---|---|---|---|---|---|---|
    | 100 | off | run 1: unstable (45.5% spread) | 331.4 | 158.8 ms | 19.2 ms | 2826 | 2826 |
    | 100 | off | runs 2, 3: not every group led within 60 s, no load offered | n/a | n/a | n/a | 2583, 2970 | same |
    | 100 | on | stable (4.9% spread) | 524.3 | 100.3 ms | 6.4 ms | 978 | 6272 |
    | 1000 | off | not every group led within 60 s | n/a | n/a | n/a | 55 | 55 |
    | 1000 | on | not every group led within 60 s | n/a | n/a | n/a | 48 | 119 |

  - Reading: at 100 groups batching cuts host CPU per committed write about
    3x and p99 by a third, carries about 6 RPCs per wire request, and is
    the only arm that reliably reaches a led cluster
    on this machine (the hosts sit at about 3.3 of 4 cores either way). At
    1000 groups neither arm gets every group led on 4 cores: with 55 RPCs a
    second the hosts are still CPU-bound, which points at per-group work in
    the hosts rather than the wire (not profiled), and this machine cannot answer the
    1000-group question. Batching stays off in `cmd/multi_raft_node` until
    a 1000-group run on larger hardware shows the drop this task requires.
  - 2026-11-20, Tier C on a 48-thread host (EPYC 7443, CI runners paused,
    1-minute load 11 to 28), same harness and flags as above, boost future
    backend, before the completion-thread fix. All rows stable, no
    readiness timeouts.

    | groups | batching | ops/sec (median) | p99 | elections | host CPU per write | wire req/s | RPCs/s |
    |---|---|---|---|---|---|---|---|
    | 100 | off | 2786 | 15.5 ms | 0 of 5 | 8.0 ms | 12795 | 12795 |
    | 100 | on | 4289 | 10.3 ms | 0 of 5 | 4.5 ms | 5312 | 21263 |
    | 1000 | off | 2127 | 18.9 ms | 5 of 5 | 11.1 ms | 10300 | 10300 |
    | 1000 | on | 798 | 95.4 ms | 4 of 5 | 22.6 ms | 1939 | 26495 |

  - Reading: at 100 groups batching gives 54% more throughput and cuts CPU
    per write by 43%. At 1000 groups it doubled CPU per write. gdb on the
    stalled hosts showed every asio I/O thread in `pthread_create` on a
    glibc lock, reached from the batch completion: the boost backend
    starts a thread per continuation, and one batch reply resolved every
    member future on the I/O thread. Lone AppendEntries escape this
    because the Beast client `.via()`s each response onto its strand.
  - A first fix completed batches on one dedicated thread. Same host, batching
    on: 100 groups rose to 5172 ops/s (p99 6.9 ms, CPU per write 4.1 ms),
    but 1000 groups stalled outright (0.2 ops/s, then no progress for
    10 min), since one thread could no longer keep up with the thread
    creation. The batcher now `.via()`s member futures onto a small pool
    instead, so no thread is created per member. In the 4-core sandbox at
    100 groups that gives 1291 ops/s and 2.7 ms CPU per write (was 524 and
    6.4 ms). Pool fix on the 48-thread host, 1000-group rows the mean of 3
    alternating runs per arm with load below 3 before each:

    | groups | batching | ops/sec | p99 | elections | host CPU per write | wire req/s | RPCs/s |
    |---|---|---|---|---|---|---|---|
    | 100 | on | 6135 | 5.5 ms | 0 of 5 | 3.6 ms | 6923 | 27166 |
    | 1000 | off | 2419 | 15.5 ms | 15 of 15 | 10.9 ms | 12231 | 12231 |
    | 1000 | on | 2087 (unstable, 16-22% spread) | 26.5 ms | 0 of 15 | 14.4 ms | 6052 | ~39900 |

  - Reading: the pool fix ends the stall. At 100 groups batching more than
    doubles throughput (6135 vs 2786 ops/s) at 45% of the CPU per write.
    At 1000 groups batching costs 32% more CPU per write, so by this task's
    rule it stays off in `cmd/multi_raft_node`. But the two arms are not
    doing the same work. With 1000 groups, two followers each and a 50 ms
    heartbeat, Raft asks for about 40k AppendEntries a second. The batching
    arm sends that (about 39.9k RPCs/s in 6k wire requests). The off arm sends
    12k, so most heartbeats are late or missing, and every one of its
    measured windows had an election. Its lower CPU per write comes from
    doing less than the protocol requires, so turning batching on is left
    to the project owner.

- [ ] 10. Other transports and serializers (optional)
  - gRPC with protobuf, the CoAP backends, TCP RPC, Ion: each on its own,
    only if task 9 shows a benefit. Until then they fall back unchanged.
  - _Requirements: 5.3_
