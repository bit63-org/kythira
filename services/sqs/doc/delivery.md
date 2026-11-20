# Delivery semantics and clocks

`.kiro/specs/sqs-compatible-queues/` Requirements 5 and 14.1. What a
client can rely on, and where Kythira's time comes from.

## Every change is a committed entry

A send, a receive, a delete and a visibility change are each a Raft entry,
applied in the same order on every replica of the queue's group. A receive
is a write: `apply()` picks the messages, marks them in flight until
`now + VisibilityTimeout`, bumps their receive counts and gives each the
partition's next receive sequence, which its receipt handle names. The
answer goes back only once the entry has committed.

What follows from that:

- **A send is durable when acknowledged.** It is on a majority of the
  group's nodes.
- **A leader change never re-delivers a message received before it.** The
  receive that made the message invisible is committed, so the new leader
  has it.
- **A receipt handle is valid for its own receive only.** A handle from
  an earlier receive of the same message is stale: `DeleteMessage`
  accepts it and does nothing, `ChangeMessageVisibility` refuses it, as
  SQS does. Handles are stateless HMAC-SHA256 tokens naming the queue id,
  partition, sequence and receive sequence, so any node checks one
  without a lookup, and a handle for a deleted and recreated queue is
  refused.
- **A receive that times out may still have happened.** If the client gives
  up before the answer arrives, the entry may commit anyway; the messages
  come back after their visibility timeout. This is SQS's at-least-once
  delivery, not a Kythira addition.

## Standard queues

At-least-once delivery, oldest first within a partition. A queue spreads
over partitions (more as its send rate rises, task 8), so order across the
queue is approximate, as on SQS. A receive takes from partitions in turn,
and within a partition shares the messages fairly between message groups
(SQS's fair queues): one busy group cannot starve the others.

## FIFO queues

- A message group's messages come out in send order, and a group is locked
  while its first message is in flight: nobody receives the group's next
  message until that one is deleted or its timeout ends.
- Deduplication records are replicated state, so a retried send within the
  five-minute window is accepted and dropped even across a leader change.
  Content-based deduplication hashes the plaintext body, before encryption.
- A high-throughput queue (`DeduplicationScope=messageGroup`,
  `FifoThroughputLimit=perMessageGroupId`) spreads groups over partitions;
  a group always maps to one partition, which keeps its order.

## Counts

`ApproximateNumberOfMessages`, `...NotVisible` and `...Delayed` are exact
as of each partition's last applied entry. A message whose timeout ends
between entries is counted in flight until the next one. The tick worker
(below) keeps that lag short by proposing an entry as soon as a deadline
passes.

## Clocks

Visibility timeouts, delays, retention, deduplication windows and the
purge and delete cool-downs are enforced from times carried in committed
entries, never from a replica's clock while applying:

- The node that proposes an entry stamps it with its clock. A follower
  that forwards an entry to the leader has it stamped again by the leader,
  so in practice every entry carries the leader's time.
- Every replica applies the same time, so all replicas agree on which
  messages are visible.
- Nothing becomes visible between entries. The leader's tick worker
  proposes a `tick` entry when a partition's earliest deadline passes, so
  an ended delay or timeout becomes a committed fact and wakes long polls
  waiting on that partition.

Kythira trusts the leader's wall clock, so keep nodes in sync (NTP or
chrony). Times are not forced to move forward across a leader change:

| New leader's clock | Effect until clocks agree |
|---|---|
| Behind the old leader's by *s* | Timeouts, delays and retention end up to *s* late. Nothing is delivered twice. |
| Ahead by *s* | Timeouts end up to *s* early, so a message still being processed can be received again, and a FIFO group can unlock early. |

Both are bounded by the skew, and a skew of a few milliseconds, which NTP
keeps, is far inside SQS's own one-second timer granularity.

## Long polls

A receive with `WaitTimeSeconds` parks on the node that took it, subscribed
to the queue's partitions, and is woken when a committed entry leaves one
of them with visible messages: a send, an ended timeout (through a
`tick`), or a visibility change to 0. It answers early with whatever one
receive entry returns, and empty at the deadline. A node that is draining
(stopping) answers its parked polls empty at once, so clients move to
another node instead of waiting out their timeout.
