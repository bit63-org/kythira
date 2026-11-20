# Design Document — Multi-Raft message batching

## Overview

```
node (group A) ─┐ group_scoped_client::send_append_entries(target, req)
node (group B) ─┼──▶ append_entries_batcher<Client>   ── per destination queue ──┐
node (group C) ─┘        │ (batching off / not supported / too big)              │ flush
                         ▼                                                       ▼
                 shared client::send_append_entries      shared client::send_append_entries_batch
                                                                     │  one request
                                                                     ▼
                     peer: multi_group_network_server  ── batch handler ── for each member:
                                                          lookup group, run its handler,
                                                          collect response (in order)
```

The batcher sits between the scoped views and the shared client. `node`
still calls `send_append_entries` and still gets back a future of one
response; it cannot tell whether that message travelled alone.

## Concepts (`network.hpp`)

```cpp
template<typename Messages>
struct append_entries_batch_request {
    std::vector<typename Messages::append_entries_request_type> _members;  // group-stamped
};
template<typename Messages>
struct append_entries_batch_response {
    // One slot per member, same order. A member the peer could not deliver
    // (no replica, handler threw) carries the error instead of a response.
    std::vector<std::variant<typename Messages::append_entries_response_type,
                             batch_member_error>> _members;
};

template<typename C, typename Messages>
concept network_client_with_append_entries_batch = requires(
    C c, typename Messages::node_id_type t,
    const append_entries_batch_request<Messages>& r, std::chrono::milliseconds to) {
    { c.send_append_entries_batch(t, r, to) }
        -> kythira::future<append_entries_batch_response<Messages>>;
};
template<typename S, typename Messages>
concept network_server_with_append_entries_batch = requires(
    S s, std::function<append_entries_batch_response<Messages>(
             const append_entries_batch_request<Messages>&)> h) {
    { s.register_append_entries_batch_handler(h) } -> std::same_as<void>;
};
```

`batch_member_error` is `{kind, message}` with `kind` in
`{unknown_group, handler_failed}`. `unknown_group` maps back to whatever the
unknown-group handler would have produced for a lone message (Req 2.3); the
batcher reconstructs that outcome on the sending side so a member's future
sees the same exception type as today.

## The batcher (new: `include/raft/append_entries_batcher.hpp`)

```cpp
template<typename Client, typename Messages>
class append_entries_batcher {
    struct pending {
        typename Messages::append_entries_request_type req;
        std::chrono::milliseconds timeout;
        kythira::promise<typename Messages::append_entries_response_type> done;
        std::size_t bytes;                 // serializer's size estimate
    };
    struct destination {
        std::mutex mu;
        std::vector<pending> queue;
        std::size_t bytes{0};
        clock::time_point first_enqueued;
        clock::time_point not_batching_until{};   // Req 4.1 / 4.2
    };
    Client* _inner;
    batching_config _cfg;
    kythira::synchronized<std::unordered_map<node_id_type, std::unique_ptr<destination>>> _dests;
public:
    auto send(node_id_type target, const request_type&, std::chrono::milliseconds)
        -> kythira::future<response_type>;
    auto flush_all() -> void;          // end of the send phase (Req 3.1)
    auto flush_due(clock::time_point) -> void;   // timer for off-tick sends (Req 3.2)
};
```

`group_scoped_client::send_append_entries` calls `batcher->send(...)` when
the host was built with a batcher, and the shared client directly otherwise.
The choice is made once, at type level (`if constexpr` on the concepts) and
at config level (`_enabled`), so the disabled path is today's path.

**Enqueue.** `send` takes the destination's lock, appends, and flushes
inline if the queue reached `_max_messages` or `_max_bytes` (Req 3.3). A
member bigger than `_max_bytes` bypasses the queue (Req 3.4). A destination
inside `not_batching_until` bypasses it too.

**Ordering (Req 2.4).** Members leave a queue in arrival order, and a flush
swaps the whole queue out under the lock, so a group's later message can
only join a later batch. Batches to one destination are sent from the flush
that created them, in order, but may complete out of order on the wire; that
is no weaker than today, where two separate AppendEntries from one group can
already overtake each other, and Raft's `prev_log_index` check makes either
order safe. The server dispatches members in array order on the receiving
group's stripe.

**Off-tick flush (Req 3.2).** Sends that arrive outside the send phase are
flushed by `flush_due`, driven from a small timer thread the batcher owns,
waking every `_max_delay`. Each wake flushes every destination whose oldest
member would pass `_max_delay` before the next wake, so no member waits
longer than `_max_delay` for the timer. The thread sleeps on a condition variable while
every queue is empty, so an idle host pays nothing. The tick's own
`flush_all` covers everything enqueued during the send phase, so most
heartbeats never wait for the timer.

**Futures.** `group_scoped_client::send_append_entries` returns either the
batcher's future or the shared client's, so they must be one type. The
batcher makes its futures from the project's default promise
(`promise_default<T>` for `future_default<T>`), which is what every batching
transport returns; a client returning any other future type does not satisfy
`append_entries_batching_client` and never batches.

**Completion.** A batch's response is matched to members by position. A
whole-batch exception fails every member (Req 2.2). A batch that fails with
`rpc_not_implemented_exception` is resent member by member and marks the
destination for `_probe_interval` (Req 4.1, 4.2). A 413-class refusal
resends that batch's members alone without marking (Req 5.4).

## Server side

`multi_group_network_server::start()` already registers one lambda per RPC
type on the inner server. When the inner server satisfies the batch concept,
it registers one more: for each member, look up `request.group_id()` in the
group table exactly as the single-message lambda does, run the handler, and
collect the result. A handler that throws yields
`batch_member_error{handler_failed}` for that member only.

**As built (task 4), two departures from the draft above.**

- Members run one after another, in array order, on the transport's thread
  that received the batch. A lone AppendEntries runs its handler on the
  transport's thread too: the demultiplexer has no stripe of its own to run
  on, and the node's lock is what serialises a group. Sequential dispatch
  keeps every guarantee the single-message path gives (Req 2.4, 2.6) at the
  cost of a batch completing at the sum of its members' handler times rather
  than the slowest. Task 9's p99 commit latency is where that shows; posting
  members to their groups' stripes is the remedy if it does.
- A member for a group with no replica goes through the demultiplexer's own
  fallback (tombstone check, lazy creation, then the refusal at the sender's
  term), so its answer is a normal response byte for byte equal to what a
  lone message gets (Req 2.3). `batch_member_error{unknown_group}` stays in
  the wire format for a server that cannot build that refusal; the batcher
  rebuilds the same refusal from it on the sending side.

## Wire

- **JSON / CBOR.** A batch request is `{"members": [<AppendEntries as sent
  alone>, ...]}`; the response is `{"members": [{"ok": <response>} |
  {"err": {"kind": "...", "message": "..."}}, ...]}`. Reusing each member's
  standalone encoding is what makes Req 5.1 hold and keeps one encoder per
  message type.
- **HTTP transports.** A new endpoint, `POST /v1/raft/append_entries_batch`,
  beside the existing AppendEntries one, with the same content negotiation
  (`transport-multi-serializer`). An older build answers 404, which the
  client maps to `rpc_not_implemented_exception` exactly as the pre-vote and
  TimeoutNow endpoints already do.
- **Limits.** The server checks member count before dispatch and relies on
  its existing body limit (`http-server-request-limits`) for bytes.

## Configuration

```cpp
struct batching_config {
    bool _enabled{false};
    std::size_t _max_messages{256};
    std::size_t _max_bytes{1u << 20};
    std::chrono::microseconds _max_delay{500};
    std::chrono::milliseconds _probe_interval{std::chrono::minutes{5}};
};
```

## What is not batched, and why

`InstallSnapshot` is large and already streamed; `RequestVote` and
`RequestPreVote` happen on elections, where a delay of even one tick is a
longer outage; `TimeoutNow` is a leadership transfer's last step. None of
them is frequent enough per destination to matter. Responses from a follower
are the replies to batched requests, so they are batched by construction.

## Risks

1. **Head-of-line blocking.** One slow group handler on the receiver holds
   the whole batch's response. Members run on their own stripes, so the
   batch completes at the slowest member's time, not the sum. The benchmark
   (Req 7.4) reports p99 commit latency to catch this; if it shows, the
   response can be split into early and late halves, which this spec leaves
   out.
2. **Timeout coupling.** The batch timeout is the shortest member's (Req
   2.5). All groups on a host share one `raft_configuration`, so in practice
   every member's timeout is the same.
3. **Benefit unproven.** multi-raft-performance found per-RPC overhead
   significant on the HTTP transports but did not isolate it from
   serialization. Task 9 measures before batching is turned on anywhere, and
   Req 7.4 says a null result is reported, not shipped.

## Testing

- `append_entries_batcher_unit_test` over a fake shared client: per-member
  results, whole-batch failure, unknown group, ordering, size and count
  flushes, the oversized bypass, off-tick flush within `_max_delay`,
  fallback and probe, 413 handling.
- Serializer round trips for JSON and CBOR with the byte-equality check.
- `message_fabric` batching mode, then the static-cluster, split, merge and
  placement-driver integration suites with it on.
- A rolling-upgrade case: a fabric host that answers batches with
  `rpc_not_implemented` (the fabric already models an older build), mixed
  with batching hosts.
- Per-transport conformance for cpp-httplib, Beast and Proxygen.
