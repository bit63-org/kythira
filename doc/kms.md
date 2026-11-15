# KMS: operator guide

Kythira's KMS speaks AWS KMS's API (JSON 1.1, `TrentService`), so the AWS
CLI, the SDKs and the AWS Encryption SDK work against it unchanged. It keeps
key metadata (keys, aliases, policies, grants, tags) in a Raft group, and
every key's material is a non-extractable object on a PKCS#11 token: the
virtual HSM (`doc/hsm.md`) or a real HSM. Kinesis and DynamoDB encrypt
through it.

Check what that buys before you rely on it:

| Protects against | Does not protect against |
|---|---|
| A stolen disk, backup or data directory of a KMS member: the catalog holds no key material (its codec has no byte fields), and the HSM's own store is sealed under its master key | Root on a host where the virtual HSM is unsealed: key material is in that process's memory while in use (`doc/hsm.md`). Use a real HSM for keys out of root's reach |
| A caller reading a key: keys never leave the token, only what they encrypt, decrypt or sign | A compromised service in the same `kythira_node` process as the HSM and the KMS |
| A caller using a key it should not: with IAM, every request is judged against the key's policy, grants and the caller's identity policies, as AWS judges it | With static keys, key policies and grants: the static roles decide alone (below) |
| A ciphertext moved to another key, another context or edited: AES-256-GCM binds the key ARN, the backing version and the encryption context | Traffic analysis: request sizes and timing |

A consumer's data is only as private as the consumer keeps it. Kinesis
seals records before they reach its Raft log; DynamoDB seals item values
when it applies a write, so its Raft log holds each write in the clear
until the log is compacted, and item keys stay in the clear always (see
[What reaches disk](#what-reaches-disk)).

The module's design is in `services/kms/README.md` and
`.kiro/specs/kms-compatible-api/`.

## Layouts

The KMS is module 7 of `kythira_node` (`KYTHIRA_SERVICES` naming `kms`).
Run three or five members; every member must reach the same token, because
every member answers cryptographic requests itself.

### With the virtual HSM in the same process

The simplest layout: each node runs the HSM and the KMS, and the KMS uses
the co-located HSM in process (`KYTHIRA_KMS_PKCS11=hsm`, the default).

    KYTHIRA_SERVICES=hsm,kms            # add iam, dynamodb, kinesis as needed
    KYTHIRA_KMS_API_LISTEN=0.0.0.0:8443
    KYTHIRA_KMS_API_URLS=1=https://kms-1.example:8443,2=https://kms-2.example:8443,3=https://kms-3.example:8443
    KYTHIRA_KMS_PEER_IDENTITIES=spiffe://example/node-1,spiffe://example/node-2,spiffe://example/node-3
    KYTHIRA_KMS_PKCS11=hsm
    KYTHIRA_KMS_PKCS11_IDENTITY=kms     # who the KMS is on the HSM (default kms)
    KYTHIRA_KMS_TOKEN_LABEL=kms         # the token holding backing keys (default kms)
    KYTHIRA_KMS_PIN_FILE=/run/secrets/kms-pin
    KYTHIRA_KMS_AUTH=iam                # needs iam in KYTHIRA_SERVICES

Once the HSM is initialized and unsealed (`doc/hsm.md`), the operator makes
the token and binds the KMS's identity to it, then sets the token's PINs
once from any client bound to it (the KMS in process has no certificate, so
a short-lived operator client does it):

    curl --cert operator.pem --key operator.key --cacert ca.pem \
      -X POST https://hsm-1.example:9443/v1/tokens -d '{"id": 7, "label": "kms"}'
    curl --cert operator.pem --key operator.key --cacert ca.pem \
      -X PUT https://hsm-1.example:9443/v1/tokens/7/bindings/kms
    curl --cert operator.pem --key operator.key --cacert ca.pem \
      -X PUT https://hsm-1.example:9443/v1/tokens/7/bindings/spiffe%3A%2F%2Fexample%2Fkms-setup
    # as spiffe://example/kms-setup, through libkythira_pkcs11.so:
    pkcs11-tool --module /usr/lib/libkythira_pkcs11.so --slot 7 \
      --init-token --label kms --so-pin "$SO_PIN"
    pkcs11-tool --module /usr/lib/libkythira_pkcs11.so --slot 7 \
      --login --login-type so --so-pin "$SO_PIN" --init-pin --pin "$(cat kms-pin)"
    curl --cert operator.pem --key operator.key --cacert ca.pem \
      -X DELETE https://hsm-1.example:9443/v1/tokens/7/bindings/spiffe%3A%2F%2Fexample%2Fkms-setup

The KMS waits for the token: until it exists, is unsealed and takes the
PIN, requests that need key material answer `KMSInternalException` ("The
HSM is sealed or unreachable") and the rest work. A member restarted later
serves again as soon as its HSM is unsealed.

### Stand-alone, with any PKCS#11 module

`kms_node` (or `kythira_node` without `hsm`) loads a PKCS#11 library
instead: `KYTHIRA_KMS_PKCS11=/usr/lib/libkythira_pkcs11.so` for a virtual
HSM cluster elsewhere (its configuration file names the nodes and the
client certificate), or a YubiHSM 2, AWS CloudHSM or SoftHSM2 library. The
token is found by `KYTHIRA_KMS_TOKEN_LABEL` and opened with the PIN in
`KYTHIRA_KMS_PIN_FILE`. Every member must reach the same token.

`kms_node` can also run the HSM and an IAM replica in its own process
(`KYTHIRA_SERVICES` picks among `kms`, `hsm` and `iam`).
`kms_node --help` lists every setting; the important ones:

| Setting | What |
|---|---|
| `KYTHIRA_KMS_API_LISTEN` | the KMS API (default `0.0.0.0:8443`), TLS with the node's certificate unless `KYTHIRA_KMS_TLS_CERT` and `_KEY` say otherwise |
| `KYTHIRA_KMS_API_URLS` | every member's API URL by node id: the catalog's voters, and where a member forwards writes to the leader |
| `KYTHIRA_KMS_PEER_IDENTITIES` | the members' certificate identities: only they may forward |
| `KYTHIRA_KMS_AUTH` | `iam` (default), `static` or `both` |
| `KYTHIRA_KMS_STATIC_KEYS_FILE` | `access-key-id secret account name role` per line, for `static` and `both` |
| `KYTHIRA_KMS_TRUSTED_SERVICES` | user or role ARNs of consumers on other clusters that may forward the caller they serve |
| `KYTHIRA_KMS_REGION`, `_PARTITION` | the region and partition in key ARNs and SigV4 (`us-east-1`, `aws`) |
| `KYTHIRA_KMS_AUDIT` | `stderr` (default), `off` or `file:<path>` |
| `KYTHIRA_KMS_THROTTLING`, `_QUOTAS`, `_ACCOUNT_QUOTAS` | AWS's per-account request quotas |
| `KYTHIRA_KMS_ACCOUNT_LIMITS` | an account's key and alias counts |

## A walkthrough with the AWS CLI

Point the CLI at any member. Writes go to the catalog's leader on their
own; reads and cryptographic calls are answered where they land.

    export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
    export AWS_CA_BUNDLE=/etc/kythira/ca.pem
    kms() { aws --endpoint-url https://kms-1.example:8443 kms "$@"; }

    KEY=$(kms create-key --description demo --query KeyMetadata.KeyId --output text)
    kms create-alias --alias-name alias/demo --target-key-id "$KEY"

    # Encrypt and decrypt with an encryption context: the context must match.
    kms encrypt --key-id alias/demo --plaintext fileb://secret.txt \
      --encryption-context app=demo --query CiphertextBlob --output text | base64 -d > secret.enc
    kms decrypt --ciphertext-blob fileb://secret.enc --encryption-context app=demo \
      --query Plaintext --output text | base64 -d

    # Envelope encryption: a data key in the clear and wrapped.
    kms generate-data-key --key-id alias/demo --key-spec AES_256

    # Signing.
    SIGN=$(kms create-key --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
      --query KeyMetadata.KeyId --output text)
    kms sign --key-id "$SIGN" --message fileb://doc.txt --signing-algorithm ECDSA_SHA_256 \
      --query Signature --output text | base64 -d > doc.sig
    kms verify --key-id "$SIGN" --message fileb://doc.txt --signature fileb://doc.sig \
      --signing-algorithm ECDSA_SHA_256

    # Rotation, a grant, and deletion with a waiting period.
    kms enable-key-rotation --key-id "$KEY"
    kms create-grant --key-id "$KEY" --operations Decrypt \
      --grantee-principal arn:aws:iam::111122223333:role/app
    kms schedule-key-deletion --key-id "$KEY" --pending-window-in-days 7
    kms cancel-key-deletion --key-id "$KEY"

The AWS Encryption SDK works the same way with a boto3 session whose KMS
client has `endpoint_url` set. `services/kms/tests/clients/kms_clients.py`
runs all three (CLI, boto3, Encryption SDK) against a cluster in CI; read
it for a complete, working example of each operation.

The operations Kythira does not implement (custom key stores, imported key
material, multi-Region keys and a few recent additions) answer
`UnsupportedOperationException`; `services/kms/doc/unsupported.md` lists
them and the behaviour that differs inside implemented ones.

## Authorization

### With IAM (`KYTHIRA_KMS_AUTH=iam`)

Every request is authorized by Kythira IAM (`services/iam/`, co-located in
the same `kythira_node`) as AWS authorizes it: the key's policy, the
caller's identity policies, grants, and the condition keys AWS documents
(`kms:ViaService`, `kms:CallerAccount`, `kms:EncryptionContext:*`,
`kms:GrantOperations` and the rest). A key made without a policy gets AWS's
default key policy, which lets the account's IAM policies decide; the
lockout safety check refuses a policy that would lock out the caller. Other
accounts use a key when its policy names them and their own IAM allows it.

### With static keys (`KYTHIRA_KMS_AUTH=static`)

Without IAM the static key file decides alone, by role:

- `read-only`: describe and list, including `GetKeyPolicy`;
- `read-write`: also every cryptographic operation;
- `admin`: everything.

Key policies are stored, returned and checked for form, but not evaluated,
so a policy that would deny the admin does not. Grants are stored and
listed but allow nothing. Turn IAM on before relying on either.

One exception: a co-located consumer's own call as an account's root (no
access key, `kms:ViaService` set, a key in that same account) is allowed.
DynamoDB makes such calls to open a table's key on each replica and after
restarts, long after the request that chose the key; no static key names
the root, so without the exception an encrypted table could not be read
anywhere but the node that created it. The request that chose the key was
judged by the static roles when it was made
(`front_end_config::admit_consumer_root`).

`both` sends requests signed with a key from the file to the static roles
and every other request to IAM; an access key id both know is refused.

## Kinesis and DynamoDB

Both share core's key providers (`include/raft/kms_key_provider*.hpp`). In
a `kythira_node` that runs the KMS module, both use it by default
(`KINESIS_KMS=kythira`, `KYTHIRA_DYNAMODB_KMS=kythira`); from another
cluster they reach it over HTTPS with `KINESIS_KMS_ENDPOINT` or
`KYTHIRA_DYNAMODB_KMS_ENDPOINT`, signing as a principal the KMS lists in
`KYTHIRA_KMS_TRUSTED_SERVICES`.

- Every call is made for the consumer's own caller, with `kms:ViaService`
  `kinesis.<region>.amazonaws.com` or `dynamodb.<region>.amazonaws.com`. A
  key policy that denies a role denies it through Kinesis and DynamoDB too.
- `alias/aws/kinesis` and `alias/aws/dynamodb` are the account's AWS
  managed keys, made on first use with AWS's managed key policy.
- A DynamoDB table that names no key uses DynamoDB's owned key
  (`alias/aws/dynamodb/owned`), which only DynamoDB can name and nobody can
  list, as AWS's owned keys are invisible to the account.
- Producers need `kms:GenerateDataKey` and consumers `kms:Decrypt` on a
  stream's key. Whoever creates or re-keys a table under a named key must
  be allowed to use that key; reading and writing items needs nothing on
  it, because DynamoDB holds the table key, as on AWS.

The consumers' own documents say how they use the keys:
`services/kinesis/doc/encryption.md` and `services/dynamodb/README.md`
("Tables are encrypted at rest").

## What reaches disk

| Where | What is there |
|---|---|
| KMS catalog (`kms/` in the data directory) | key metadata, aliases, policies, grants, tags; no key material, no plaintext, no ciphertext |
| The HSM's store | backing keys sealed under the HSM's master key (`doc/hsm.md`) |
| KMS audit log | one CloudTrail-shaped line per request: caller, key ARN, encryption context keys (never values), outcome; no data |
| Kinesis | records sealed before the gateway proposes them: the Raft log, segments and tiered objects hold ciphertext only |
| DynamoDB engine | item values, LSI and GSI entries sealed; partition, sort and index key values in the clear |
| DynamoDB Raft log, transaction intents | each write in the clear until the log is compacted and the transaction settles |
| DynamoDB backups, archives, change records | sealed under the table's key |
| DynamoDB exports | sealed under the KMS key `S3SseKmsKeyId` names when `S3SseAlgorithm=KMS`; otherwise as the bucket stores them (a Kythira bucket directory: in the clear) |

The container scenario that checks this
(`services/hsm/tests/docker/hsm_chaos_test.cpp`,
`encrypted_services_in_kythira_node`, run by `hsm-module.yml` under Docker
and rootless Podman) writes to an encrypted table and stream and asks the
KMS for data keys while one member is killed and another cut off, then
searches every member's data directory: no data key or plaintext the KMS
handled may appear anywhere, and no item or record value outside
DynamoDB's Raft logs. It reports the Raft log files that hold values.

## Operating

- **Audit and metrics.** Each request is one JSON line on
  `KYTHIRA_KMS_AUDIT` and is counted in `kms_api_requests` and
  `kms_api_latency_seconds_*`; `kms_audit_dropped` counts lines the bounded
  queue dropped.
- **Quotas.** AWS's per-account quotas, counted on each member at the
  account's rate divided by the members, so a client bursting to every
  member at once can briefly exceed a quota by up to the member count.
- **Rotation and deletion.** The catalog's leader runs the jobs every
  `KYTHIRA_KMS_JOB_INTERVAL_MS`: scheduled rotation, deletion at the end of
  the waiting period (destroying every backing key), settling keys a dead
  leader left `Creating`, and sweeping backing keys no key accounts for
  after `KYTHIRA_KMS_GRACE_MS`.
- **Losing members.** The catalog needs a majority to change keys.
  Cryptographic calls write nothing, but each first passes a read barrier
  through the catalog's leader (so a disabled key is never used from a
  stale replica), so they too need a leader, and a member whose HSM is
  unsealed. A member cut off from the leader answers
  `DependencyTimeoutException` until it rejoins.

## Not yet checked against AWS

Request validation and error messages follow AWS's documentation and the
botocore model. A differential run against real AWS KMS, recorded as
fixtures CI replays, is written but not yet recorded: it costs a little
money and waits for the maintainer's approval.
