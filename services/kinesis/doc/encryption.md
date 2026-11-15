# Encryption at rest

Task 14 of `.kiro/specs/kinesis-compatible-streams/` (Requirement 14.1).

## What gets encrypted

`StartStreamEncryption` turns on encryption for a stream. After that, every
new record is sealed with AES-256-GCM before the gateway proposes it. That
covers the partition key and the data. Everything downstream only ever sees
ciphertext:

- the Raft log;
- the segments on every replica;
- segment fetches between peers;
- tiered objects in S3.

Sealing happens once, on the node that takes the write. So the replicas
stay byte-identical, as the segment store requires.

A sealed record is stored like this:

    u16 0xFFFF | u32 generation | 12-byte nonce | ciphertext | 16-byte tag

How it works:

- **Telling sealed records from plain ones.** A plaintext record starts with
  its partition key's length, which is at most 256, so it can never start
  with `0xFFFF`. That means one shard can hold both kinds, before and after
  a start or stop.
- **What the tag protects.** The GCM additional data is the shard's routing
  key and the generation. A record moved to another shard, or relabelled
  with another generation, will not open.
- **Nonces.** Each record gets a random 96-bit nonce.
- **What the log checks.** The state machine refuses a sealed record that
  lacks the marker or is too short to be one.

## Data keys

Data keys are tracked per stream:

- **New keys.** Each `StartStreamEncryption` that changes the key makes a
  fresh 256-bit data key. The key provider wraps it under the caller's
  `KeyId`.
- **Generations.** The catalog keeps every wrapped data key with its
  generation (1, 2, ...). The generation is assigned when the entry
  applies, so two racing starts each get their own.
- **Plaintext keys.** A plaintext data key is never replicated. Each node
  unwraps a generation the first time it needs it, then keeps it in memory.
- **The encryption context.** Data keys are bound to
  `{"kythira:kinesis:stream": "<account>/<name>/<stream id>"}`.
- **`StopStreamEncryption`.** Stopping keeps every data key, so records
  sealed earlier stay readable. New records are stored in the clear again.
- **Re-keying.** Starting with another `KeyId` re-keys the stream. Records
  already written keep their old data key.

The catalog keeps every generation for the life of the stream. Each one
costs about 80 bytes (local provider) or about 200 bytes (AWS KMS). Nothing
prunes generations yet, even once retention has dropped every record under
one.

## The calls

- **`StartStreamEncryption`.** Needs `EncryptionType` `KMS` and a
  `KeyId`, on an ACTIVE stream.
  - If no key provider is configured, it answers
    `InvalidArgumentException`.
  - Starting with the key the stream already uses changes nothing.
  - The change is one catalog entry, so the stream stays ACTIVE throughout
    (AWS shows UPDATING for a few seconds). A write racing the change may
    land on either side of it.
- **`StopStreamEncryption`.** Needs `EncryptionType` `KMS` and the
  stream's `KeyId`; any other key gets `InvalidArgumentException`. Stopping
  a stream that is not encrypted changes nothing.
- **What callers see.**
  - `DescribeStream` and `DescribeStreamSummary` show `EncryptionType` and
    `KeyId` as the caller named it.
  - `PutRecord` and `PutRecords` answer `EncryptionType` `KMS` for sealed
    records.
  - `GetRecords` marks each sealed record with `EncryptionType` `KMS`.
- **Write limits.** A sealed record costs its partition key and data
  against the shard's write limits, as a plaintext one does. The 36 bytes
  sealing adds are not billed.

## Key providers

`kinesis_kms.hpp` defines the `kms_key_provider` concept. A provider needs
two calls:

- `generate_data_key(key_id, context)`;
- `decrypt_data_key(key_id, wrapped, context)`.

A failure throws `kms_error`. The service answers it with the matching
Kinesis exception:

| Provider failure | Answer |
|---|---|
| `not_found`, or no provider on this node | `KMSNotFoundException` |
| `access_denied` | `KMSAccessDeniedException` |
| `disabled` | `KMSDisabledException` |
| `invalid_state` | `KMSInvalidStateException` |
| `throttling` | `KMSThrottlingException` |
| `opt_in_required` | `KMSOptInRequired` |

A sealed record whose tag fails is corruption, not a key problem, and gets
`InternalFailure`.

`KINESIS_KMS` picks the provider:

- **`off`** (the default). There is no provider: `StartStreamEncryption`
  is refused.
- **`local`**: `local_kms_provider`. It seals data keys the way
  `encrypt_ca_private_key` seals the CA key:
  - AES-256-GCM, under a key derived with PBKDF2-HMAC-SHA256 (200 000
    iterations, a fresh random salt per data key);
  - the passphrase comes from `KINESIS_KMS_PASSPHRASE` or
    `KINESIS_KMS_PASSPHRASE_FILE`, at least 16 bytes, and must be the same
    on every node;
  - any `KeyId` names a key. The id and the encryption context are bound
    to the wrapped key, so it does not unwrap under another id or for
    another stream;
  - a node with a different passphrase answers `KMSInvalidStateException`.
- **`aws`**: `aws_kms_provider` in `kinesis_kms_aws.hpp`. It talks to AWS
  KMS directly over the JSON 1.1 protocol, signed with SigV4, so it needs
  no AWS SDK component:
  - it calls `GenerateDataKey` (`AES_256`) and `Decrypt`, with the
    encryption context;
  - the catalog stores the key ARN that `GenerateDataKey` returns, so
    moving an alias later does not affect reads;
  - the region is `KINESIS_KMS_REGION` (default `KINESIS_REGION`);
  - the endpoint is `KINESIS_KMS_ENDPOINT` as host:port (default AWS's);
  - credentials come from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
    `AWS_SESSION_TOKEN`, read at startup.

- **`pkcs11`**: `pkcs11_kms_provider` in `kinesis_kms_pkcs11.hpp`. Data
  keys are protected by a key pair on a PKCS#11 token: the co-located
  virtual HSM (`services/hsm/`), or any library such as a YubiHSM 2,
  CloudHSM or SoftHSM2:
  - `KINESIS_KMS_PKCS11_URI` names the token, for example
    `pkcs11:token=kinesis?pin-source=/run/secrets/kinesis-pin`. With
    `module-path=` the node loads that library; without it the virtual
    HSM module must run in the same `kythira_node`, and Kinesis uses it
    in process as the application `KINESIS_KMS_PKCS11_IDENTITY` (default
    `kinesis`). That identity needs a binding to the token and the PIN,
    exactly as a network client would;
  - a `KeyId` is the label of an RSA private key made for decryption on
    that token, or a `pkcs11:` URI with `object=` or `id=` (a URI naming
    another token, a library or a PIN is refused);
  - to stay within what the YubiHSM 2 and CloudHSM both offer, there is
    no AES key wrap: data keys are sealed with RSA-OAEP in software on
    the public half, together with a SHA-256 of the key id and the
    encryption context, and opened by one decryption on the token
    (`include/raft/pkcs11_envelope.hpp`);
  - `KINESIS_KMS_PKCS11_OAEP` is the OAEP hash for new data keys,
    `sha256` (default) or `sha1` for a library that takes only SHA-1
    (SoftHSM2 2.6). Each sealed key records its hash;
  - the module opens on first use. A call that finds its session gone
    (the module restarted, the HSM failed over) opens a new session and
    tries once more.

- **`kythira`**: `kythira_kms_provider` in `kinesis_kms_kythira.hpp`,
  Kythira's own KMS (`services/kms/`, `.kiro/specs/kms-compatible-api/`
  task 15). It is the default in a `kythira_node` that runs the KMS
  module, unless `KINESIS_KMS` says otherwise:
  - calls go through `kms.client`: in process to the co-located KMS
    module, or, with `KINESIS_KMS_ENDPOINT` (host:port), over HTTPS to a
    KMS on another cluster, signed with `AWS_ACCESS_KEY_ID` and friends
    and verified against `KINESIS_KMS_CA`. That signer must be one of the
    KMS's `KYTHIRA_KMS_TRUSTED_SERVICES`;
  - every call is made for the Kinesis request's own caller, with
    `kms:ViaService` `kinesis.<region>.amazonaws.com`. The KMS evaluates
    the key policy, grants and identity policies for that caller, never
    for the gateway, so a key policy that denies a role denies it through
    Kinesis too;
  - as on AWS, producers need `kms:GenerateDataKey` on the stream's key
    and consumers (`GetRecords`, `SubscribeToShard`) need `kms:Decrypt`.
    A producer's records are sealed under the newest data key of the
    stream's KMS key that the node holds; a node that holds none (just
    started, or another node) makes the producer's own `GenerateDataKey`
    another generation, so it never needs a `Decrypt` the producer may
    not have. Each node adds at most one generation per key while it
    runs;
  - an answer stands for one caller and stream for
    `KINESIS_KMS_CALLER_TTL_MS` (five minutes, as AWS reuses data keys);
    after that the caller is asked about again. A data key another caller
    unwrapped proves nothing about the next one. So disabling the key, or
    changing its policy, takes effect within that bound, with
    `KMSDisabledException` or `KMSAccessDeniedException`;
  - `alias/aws/kinesis` is the account's AWS managed key, made on first
    use.

  Another cloud's key service would be one more class that satisfies the
  concept: `generate_data_key` and `decrypt_data_key` with the two
  arguments above, or with a third, the caller (`kms_caller`), for a
  provider that authorizes each one.

## Moving to another provider

Each data key records the provider that wrapped it (`local`, `aws`,
`pkcs11` or `kythira`). A node that moves to another provider sets
`KINESIS_KMS_PREVIOUS` to the old one, with the old one's settings
(its passphrase, region or token), and keeps opening the old keys:

- records sealed before the move read as before;
- a stream keeps writing under its current key, through the old
  provider, until `StartStreamEncryption` names a key again (the same
  key re-keys here, where it otherwise changes nothing). The new data
  key is the new provider's, and says so;
- keys written before the tag existed are the previous provider's when
  `KINESIS_KMS_PREVIOUS` is set, else this node's own;
- a node that lacks the provider a key names answers
  `KMSNotFoundException`, naming it.

The tag changes the stored encoding (stream record and command version
2) only once a key names a provider, so a node not yet upgraded reads
the catalog and the log until the first tagged key. Upgrade every node
before starting encryption with a tagged provider. Every node of a
stream's cluster needs the providers its keys name.

## Not yet checked against AWS

Each of these is our reading of AWS's documentation. None has been checked
against a recording of AWS:

- the refusals and their messages;
- `StopStreamEncryption` on a stream that is not encrypted, and with a
  different `KeyId`;
- whether `GetRecords` puts `EncryptionType` on every record.

The AWS KMS adapter is tested against a fake KMS that checks its SigV4
signatures with the gateways' own verifier. It has not been run against
real KMS. That run needs a KMS key, which costs money, so it waits for
Clark's go.

## Tests

`kinesis_encryption_test` has 10 cases:

- the local provider, with its bindings, refusals and type erasure;
- sealed records opening only in their shard, under their key and
  generation;
- the log refusing malformed sealed records;
- an encrypted stream end to end:
  - start, re-key and stop;
  - the segment files holding no plaintext from the encrypted stretch;
  - a second gateway that shares only the passphrase reading every record;
  - the KMS errors from a gateway with a wrong passphrase or with no
    provider;
- the refusals and the error mapping;
- the AWS adapter against a fake KMS: signature checks, request shape and
  error mapping;
- the encryption entries and data keys surviving the codec;
- no plaintext data key in a snapshot or a segment file;
- a node that moves from `local` to another provider: old keys open
  through `KINESIS_KMS_PREVIOUS`, writes stay under the old key until
  re-keyed, the same key re-keys, the new key is tagged, and a node without the previous
  provider answers `KMSNotFoundException`;
- the tag leaving the version 1 encoding of untagged records and
  commands unchanged.

`kinesis_kms_kythira_test` runs the `kythira` provider against a fake
`kms.client` with per-principal permissions: the caller and
`kms:ViaService` on every call, producers with only `GenerateDataKey`
and consumers with only `Decrypt`, a reader refused although the node
holds the key, the caller TTL and a disabled key, and a second gateway
adding one generation.

`kinesis_kms_pkcs11_test` runs the `pkcs11` provider against a software
token: round trips, the key id and context bindings, refused key ids, a
wrong PIN, a dropped session and SHA-1 seals.
