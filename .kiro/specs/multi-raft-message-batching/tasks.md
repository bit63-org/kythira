# Implementation Plan — Multi-Raft message batching

## Status: Not started (spec only, written 2026-11-19)

Follow-up to `.kiro/specs/multi-raft/` design §2.3 and Phase 9. Building it
needs Clark's call. Task 9's measurement decides whether batching is turned
on anywhere.

- [ ] 1. Message types and concepts
  - `append_entries_batch_request` / `_response`, `batch_member_error`, the
    client and server concepts in `network.hpp`.
  - _Requirements: 1.1_

- [ ] 2. The batcher
  - `include/raft/append_entries_batcher.hpp`: per-destination queues, size
    and count flushes, oversized bypass, `flush_all`, the off-tick timer,
    per-member completion, fallback and probe.
  - Unit tests over a fake shared client.
  - _Requirements: 2.1-2.5, 3.2-3.4, 4.1, 4.2, 7.2_

- [ ] 3. Host wiring
  - `batching_config`; `group_scoped_client` routes AppendEntries through the
    batcher when both concepts hold and batching is enabled; `tick()` calls
    `flush_all` at the end of the send phase; `tick_report` counters.
  - _Requirements: 1.2-1.4, 3.1, 3.5, 6.1_

- [ ] 4. Server dispatch
  - The batch lambda in `multi_group_network_server::start()`, per-member
    group lookup on its stripe, unknown-group as a member error.
  - _Requirements: 2.3, 2.6_

- [ ] 5. Test fabric
  - `message_fabric` batching mode and an older-build mode; run the
    multi-raft integration suites with batching on; the rolling-upgrade case.
  - _Requirements: 4.3, 7.1_

- [ ] 6. JSON and CBOR encodings
  - Batch request and response; round-trip tests with member byte equality.
  - _Requirements: 5.1, 7.3_

- [ ] 7. HTTP transports
  - `POST /v1/raft/append_entries_batch` on cpp-httplib, Beast and Proxygen,
    client and server; 404 to `rpc_not_implemented_exception`; member-count
    and body limits; conformance tests.
  - _Requirements: 5.2, 5.4_

- [ ] 8. Metrics
  - Members per batch, batches, fallbacks, marked destinations.
  - _Requirements: 6.2_

- [ ] 9. Measure, then decide
  - `multi_raft_bench` on Beast, 3 hosts, 100 and 1000 busy groups, batching
    off and on: wire requests per second, CPU per committed entry, p99 commit
    latency. Record here. Turn batching on in `cmd/multi_raft_node` only if
    CPU per committed entry drops at 1000 groups.
  - _Requirements: 7.4_

- [ ] 10. Other transports and serializers (optional)
  - gRPC with protobuf, the CoAP backends, TCP RPC, Ion: each on its own,
    only if task 9 shows a benefit. Until then they fall back unchanged.
  - _Requirements: 5.3_
