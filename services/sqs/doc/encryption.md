# Encryption

`.kiro/specs/sqs-compatible-queues/` Requirements 8 and 14.1, task 7. The
code and the sealed-body format are in `../include/kythira/sqs/sqs_sse.hpp`.

## What is encrypted, and where

A queue with SSE-SQS (on by default for new queues, as on SQS) or SSE-KMS
(`KmsMasterKeyId` set) has each message's body and message attributes
sealed by the front end that takes the send, before the entry is proposed.
The Raft log, the RocksDB engine, snapshots and every replica therefore
hold only ciphertext, and the data layer never holds a key. The front end
that serves a receive opens the message before answering.

The MD5 digests and the content-based deduplication hash are computed over
the plaintext first and stored beside the sealed body, so clients that
check digests see SQS's values.

Queue names, attributes, tags and message ids are not encrypted, as on
SQS. Neither are system attributes such as `AWSTraceHeader`.

## Envelope keys

As on SQS, a front end asks the queue's key provider for a 256-bit data key
and reuses it for the queue's `KmsDataKeyReusePeriodSeconds` (60 s to 24 h,
default 300 s), then asks again. Each message carries its data key wrapped
by the provider, with the queue's ARN as the encryption context
(`aws:sqs:arn`). So:

- any front end opens any message;
- a message moved to another queue (a dead-letter move, a move task)
  still opens;
- changing a queue's encryption, or turning it off, leaves the messages
  already stored readable;
- a busy queue costs one provider call per reuse period on each front
  end, not one per message.

Bodies are sealed with AES-256-GCM. The additional data binds the format,
the message id, the key id and the context ARN, so a sealed body copied
onto another message does not open.

## Key providers

| Queue setting | Provider | Keys from |
|---|---|---|
| `SqsManagedSseEnabled=true` (default) | the cluster's SSE-SQS key | `SQS_SSE_KEY_FILE` (at least 16 bytes), else derived from `SQS_FORWARD_SECRET`. Every node needs the same one. |
| `KmsMasterKeyId` set, `SQS_KMS=local` | a key derived from a passphrase | `SQS_KMS_PASSPHRASE_FILE`, the same on every node. Any key id is accepted and bound into the wrapping. |
| `KmsMasterKeyId` set, `SQS_KMS=none` | none | Sends to the queue fail with `KmsNotFound`. |

Provider failures are answered as SQS's errors of the same meaning
(`KmsAccessDenied`, `KmsDisabled`, `KmsInvalidKeyUsage`,
`KmsInvalidState`, `KmsNotFound`, `KmsOptInRequired`, `KmsThrottled`), on
the send or on the receive that needed the key.

The provider interface has the shape of the shared `kms_key_provider`
(two calls: generate a data key, decrypt one). When the KMS spec moves
that library out of the Kinesis module, Kythira KMS and AWS KMS become
providers here without a change to the sealed format.

## Rotating keys

- **SSE-SQS master key.** Not rotatable in place yet: every stored
  message's data key is wrapped under it. Changing `SQS_SSE_KEY_FILE`
  makes every message sealed under the old key unreadable: a receive of
  one answers `KmsInvalidState`. Drain queues first.
- **Data keys** rotate on their own every reuse period.
- **Receipt keys** are separate ([configuration.md](configuration.md)).
