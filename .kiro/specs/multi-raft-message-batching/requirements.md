# Requirements Document

## Introduction

`.kiro/specs/multi-raft/` design §2.3 named one transport refinement and
deferred it (to its Phase 6 in §2.3, to Phase 9 in the §11 table, and again
in the tasks file's "Deliberately deferred" note): coalescing many groups'
`AppendEntries` to the same destination into one payload.

Today every group's `node` sends through its own `group_scoped_client`, which
stamps the group id and forwards to the host's one shared client
(`include/raft/group_transport.hpp`). Connections are shared (multi-raft
Requirement 4.6), but messages are not: a host leading `G` groups whose
replicas sit on the same two peers sends `2G` AppendEntries requests per
heartbeat interval, each a separate HTTP request (or gRPC call, or CoAP
exchange) with its own headers, framing, serializer pass and handler
dispatch. Hibernation (`hibernation_mode`) silences idle groups, which helps
when most groups are idle; it does nothing for a host whose groups are all
busy, which is the case batching addresses.

This spec adds an optional batched AppendEntries RPC, negotiated per peer,
with a per-message fallback that keeps every existing transport and every
older peer working unchanged.

Building this spec needs Clark's call; it is spec only.

## Glossary

- **Batch**: one request carrying the AppendEntries requests of several
  groups for one destination node, and its one response carrying their
  responses in the same order.
- **Batcher**: the host-level component that holds outgoing AppendEntries
  per destination and flushes them as batches.
- **Flush**: sending everything a batcher holds for one destination.
- **Batching transport**: a client satisfying the new
  `network_client_with_append_entries_batch` concept, and a server satisfying
  `network_server_with_append_entries_batch`.

## Requirements

### Requirement 1: Optional, detected at compile time

**User Story:** As a transport author, I want batching to be an extension a
transport may implement, not a new obligation.

#### Acceptance Criteria

1. `network.hpp` SHALL gain `network_client_with_append_entries_batch` and
   `network_server_with_append_entries_batch`, in the style of
   `network_client_with_timeout_now`.
2. THE host SHALL use batching only when its shared client and server satisfy
   both concepts, detected with `if constexpr`; otherwise it SHALL send
   exactly as today.
3. `node<Types>` and `raft.hpp` SHALL NOT change. Batching lives below
   `group_scoped_client` and above the shared client.
4. `multi_raft_config` SHALL gain `batching_config` with `_enabled{false}`;
   batching SHALL be off unless enabled, even on a batching transport.

### Requirement 2: Semantics identical to separate sends

**User Story:** As a maintainer, I want a batch to mean exactly what its
member messages would have meant sent one by one.

#### Acceptance Criteria

1. Each member's future SHALL complete with that member's own response, or
   with the exception it would have seen sent alone.
2. A transport failure of the whole batch (connection refused, timeout,
   unreachable) SHALL fail every member with that exception.
3. A member whose group has no replica at the destination SHALL get the same
   unknown-group outcome it gets today (multi-raft Requirement 14), and SHALL
   NOT fail the other members.
4. Two messages of one group to one destination SHALL be delivered to the
   group's handler in the order they were sent.
5. A batch's timeout SHALL be the shortest of its members' timeouts.
6. The server SHALL dispatch each member to its group's handler through the
   existing `multi_group_network_server` lookup, so the per-group serial
   execution invariant is kept.

### Requirement 3: When to flush

**User Story:** As an operator, I want batching to cut message counts without
adding latency a client can see.

#### Acceptance Criteria

1. THE host SHALL flush every destination at the end of the send phase of
   `tick()`, so heartbeats and tick-driven replication never wait past the
   tick that produced them.
2. AppendEntries sent outside the send phase (a proposal's replication on
   the client's thread, a follower-driven retry) SHALL be flushed after at
   most `_max_delay` (default 500 us), or immediately when batching is
   disabled for that destination.
3. A destination SHALL be flushed as soon as it holds `_max_messages`
   (default 256) members or `_max_bytes` (default 1 MiB) of serialized
   entries.
4. A member larger than `_max_bytes` on its own SHALL be sent alone through
   the ordinary path.
5. `InstallSnapshot`, `RequestVote`, `RequestPreVote` and `TimeoutNow` SHALL
   NOT be batched: they are rare, large, or latency-critical.

### Requirement 4: Mixed versions

**User Story:** As an operator rolling out a new build, I want old and new
nodes to keep replicating to each other.

#### Acceptance Criteria

1. WHEN a batch to a destination fails with `rpc_not_implemented_exception`,
   THE batcher SHALL resend every member individually, SHALL mark that
   destination as not batching, and SHALL log it once at info level.
2. THE batcher SHALL retry batching to a marked destination after
   `_probe_interval` (default 5 min), so an upgraded peer is picked up.
3. A rolling-upgrade test SHALL run a cluster of mixed old and new hosts with
   batching on and show every group making progress throughout.

### Requirement 5: Wire formats

**User Story:** As a transport author, I want the batch encoded the way each
transport already encodes its messages.

#### Acceptance Criteria

1. THE JSON and CBOR serializers SHALL encode and decode a batch request and
   response as an array of the existing group-stamped AppendEntries
   encodings, so a member's bytes are the same as when sent alone.
2. THE HTTP transports used by `cmd/multi_raft_node` (cpp-httplib, Beast,
   Proxygen) SHALL implement both concepts on a new endpoint beside the
   existing AppendEntries endpoint.
3. Transports not listed in AC 2 (gRPC, the three CoAP backends, TCP RPC)
   and serializers not listed in AC 1 (protobuf, Ion) MAY implement batching
   later; until they do, they fall back per Requirement 1.2 with no change.
4. A server SHALL refuse a batch above `_max_messages` or above its existing
   request body limit (`http-server-request-limits`) with a 413-class error,
   which the batcher SHALL treat as Requirement 4.1's fallback for that
   batch only, without marking the destination.

### Requirement 6: Observability

**User Story:** As an operator, I want to see whether batching is working.

#### Acceptance Criteria

1. `tick_report` SHALL gain the number of batches and batched members sent
   in the tick.
2. THE host's metrics SHALL expose members per batch (a histogram), batches
   sent, fallbacks taken, and destinations currently marked not batching.

### Requirement 7: Tests and measurement

**User Story:** As a maintainer, I want the semantics proved and the benefit
measured.

#### Acceptance Criteria

1. The in-memory `message_fabric` (`tests/multi_raft_test_fabric.hpp`) SHALL
   gain a batching mode, and the multi-raft integration suites SHALL pass
   with it on.
2. Unit tests SHALL cover each criterion of Requirement 2, the flush rules of
   Requirement 3, and the fallback and probe of Requirement 4.
3. Serializer round-trip tests SHALL show a member's bytes inside a batch
   equal to its bytes alone (Requirement 5.1).
4. `multi_raft_bench` SHALL record requests per second on the wire, CPU per
   committed entry and p99 commit latency with batching off and on, at 100
   and 1000 busy groups across 3 hosts, on Beast; the results go into this
   spec's tasks file. Batching that does not reduce CPU per committed entry
   at 1000 groups SHALL be reported as such, not shipped on.
