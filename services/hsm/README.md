# HSM module

A virtual HSM for Kythira: a software token that keeps its keys in Kythira
Raft groups, sealed under a master key split with Shamir's scheme, and serves
them through PKCS#11. Consumers (the CA, Kinesis, IAM, and anything that loads
a PKCS#11 module) see only the PKCS#11 interface, so moving them to a
YubiHSM 2 or CloudHSM is a configuration change. Keys are in host memory while
they are in use: this is not a hardware boundary, and the documentation says
so. The spec is `.kiro/specs/virtual-hsm/`; this directory follows
`services/README.md`.

Built when `CONFIG_HSM=y` (`services/hsm/Kconfig`, off by default, needs
OpenSSL 3). `configs/ci_full_defconfig` turns it on, so ci.yml builds and
tests it; `configs/ci_no_hsm_defconfig` is the module-off configuration
`.github/workflows/hsm-module.yml` checks.

## Stand-alone or co-located

The HSM is a service module. `hsm_node` runs it alone; `kythira_node` with
`KYTHIRA_SERVICES` naming `hsm` runs it next to other services. Both take
the same settings (`hsm_node --help` lists them), and both keep the HSM's
groups at the same ids under `KYTHIRA_NODE_DATA_DIR/hsm/`, so a cluster
moves between the layouts in place: stop every member, start each one in
the other layout with the same node id and data directory.

Run it stand-alone for production secrets. Co-located, the HSM shares its
process with the other services, so a memory disclosure in any of them
discloses the master key and every opened token key; stand-alone, nothing
else runs where the keys are.

## Unsealing: what each mode protects

The master key (MK) is never written anywhere. `hsm_ctl init` splits it into
`n` Shamir shares, any `k` of which rebuild it, and the mode chosen there
(changed only by `hsm_ctl rekey`, which re-splits) decides who holds them:

- **Operator unseal** (`--mode operator`): the shares are printed once for
  people to keep. After every restart `k` operators each enter one with
  `hsm_ctl unseal` on every node. No disk holds anything that opens the
  keys, at the price of a person at each restart.
- **Node unseal** (`--mode node`, `n` = the member count): each member keeps
  one share on its own disk, sealed with its share key
  (`KYTHIRA_HSM_SHARE_KEY_FILE`, owner-only; TPM 2.0 and cloud KMS sealing
  follow in task 8b), and a starting member asks the others for `k - 1` more
  over mutual TLS. Peers answer only a member's certificate. With fewer than
  `k` members reachable a member stays sealed.

**In node unseal mode every unsealed node holds the whole MK in memory, and
Shamir protects the data at rest, not a running node.** Stealing the data
of fewer than `k` members (disks, backups, snapshots) yields nothing; but a
member's certificate and key, with network reach to `k - 1` other members,
are enough to collect `k` shares. In either mode an unsealed node's memory
holds the MK and the keys in use, which root on that host can read
(requirement 2.5). `hsm_ctl seal` makes every node discard them.

## Clients in other processes

A PKCS#11 client reaches a node over mutual TLS 1.3
(`KYTHIRA_HSM_CLIENT_LISTEN`, 9444 by default) or, on the same host, a
Unix socket (`KYTHIRA_HSM_SOCKET`). Each connection is one PKCS#11
application acting as an identity: over TLS, the client certificate's
first URI SAN (its first DNS SAN when it has no URI), checked against
`KYTHIRA_HSM_APP_CA`; over the socket, the identity
`KYTHIRA_HSM_SOCKET_ALLOW` gives the connecting uid (`root=local-app,
1001=spiffe://example/app`); any other uid is closed unanswered. An
operator binds a token to an identity (`PUT /v1/tokens/N/bindings/<id>`);
every other token answers `CKR_TOKEN_NOT_PRESENT` to that client whether
it exists or not, and the token's PIN is still needed to log in
(requirement 8).

With `KYTHIRA_HSM_INSECURE_PLAINTEXT` there is no client identity, so the
TLS client listener stays off and only the socket serves.

Applications load `libkythira_pkcs11.so` (`pkcs11/README.md`), which speaks
this protocol to the nodes `KYTHIRA_PKCS11_CONF` lists and fails over between
them.

## Kythira's own consumers, and moving to hardware

Kythira services that use a key (the CA, Kinesis, IAM) go through core's
`kythira::pkcs11::module` (`include/raft/pkcs11_module.hpp`), which finds a
token and a key by RFC 7512 URI, `pkcs11:token=ca;object=issuing?pin-source=/run/secrets/pin&module-path=/usr/lib/libkythira_pkcs11.so`.
Beside the HSM in one process it binds to the HSM directly
(`pkcs11_native_backend.hpp`); otherwise it dlopens the URI's
`module-path`. Pointing that at `yubihsm_pkcs11.so`, CloudHSM's library or
SoftHSM2 needs no code change, because the wrapper lets a consumer use only
what the YubiHSM 2 and AWS CloudHSM (Client SDK 5) libraries both
implement:

| Operation | Mechanism | Keys |
|---|---|---|
| generate a key pair | `CKM_EC_KEY_PAIR_GEN` | P-256, P-384 |
| generate a key pair | `CKM_RSA_PKCS_KEY_PAIR_GEN` | 2048, 3072, 4096 bits, e = 65537 |
| sign a SHA-256/384/512 digest | `CKM_ECDSA` | EC |
| sign a SHA-256/384/512 digest | `CKM_RSA_PKCS` (DigestInfo built by the wrapper) | RSA |
| sign a SHA-256/384/512 digest | `CKM_RSA_PKCS_PSS` (MGF1 with the same hash, salt = hash length) | RSA |
| decrypt | `CKM_RSA_PKCS_OAEP` (SHA-1 or SHA-2, MGF1 with the same hash) | RSA |

Verifying and encrypting use the public key in software. Not in the subset:
AES-GCM (the YubiHSM 2 has none and CloudHSM chooses the IV itself),
standard AES key wrap (both use vendor wrap mechanisms), HMAC (their
secret-key types differ) and the hashing sign mechanisms such as
`CKM_ECDSA_SHA256`. Labels of at most 40 bytes and ids of at most 2 bytes
keep the YubiHSM 2 from storing them in a separate meta object.
`hsm_pkcs11_module_test` runs one consumer scenario in process, through
`libkythira_pkcs11.so` and on SoftHSM2.

The consumers built on it so far:

- **Kinesis** (`KINESIS_KMS=pkcs11`, `services/kinesis/doc/encryption.md`):
  stream data keys sealed with RSA-OAEP on a decryption key pair
  (`include/raft/pkcs11_envelope.hpp`); beside the HSM in `kythira_node` it
  uses the published `hsm.pkcs11` interface as its own application.
- **The cluster CA** (`ca_cluster_node --ca-key-uri URI`): the root key is
  an EC (P-256, P-384) or RSA key pair on the token
  (`include/raft/pkcs11_signing_key.hpp`). The bootstrapping node signs the
  root certificate with it, and every leader signs certificates and CRLs
  through `certificate_authority::from_external`. The Raft log records
  `pkcs11:` and the key's URI instead of a sealed key, so a node without
  `--ca-key-uri` refuses to lead.
- **The OIDC issuer** (`ca_cluster_node --oidc-key-uri TOKEN-URI`): each
  signing key the rotation makes is a new key pair on the token (RSA 2048
  for RS256, P-256 for ES256), and the state records its URI instead of a
  sealed key. Every node needs the flag, since whichever leads signs. The
  unseal key is still needed for peer enrollment (see the next item).
- **Unseal passphrases** (`hsm_ctl seal-secret --key-uri URI --out FILE`):
  what IAM's STS keys (AES-256-GCM) and the CA's peer enrollment key (HMAC)
  are cannot live on a YubiHSM 2 or CloudHSM, so instead the passphrase
  they are derived from is sealed with RSA-OAEP under a decryption key on
  the token (`include/raft/pkcs11_sealed_secret.hpp`). The file names the
  key, its library and its PIN file (never the PIN); `ca_cluster_node`,
  `iam_node` and every embedded IAM replica open it on the token at
  startup when given it as their unseal key file. The token protects the
  passphrase at rest only: the keys derived from it are in the node's
  memory while it runs, as before.

Moving keys there: `hsm_ctl migrate --from URI --to URI` (each URI with
`module-path` and `pin-source`; `--dry-run` first) copies every
extractable key, wrapped end to end (RSA-OAEP for a session transport key,
then RFC 5649 key wrap), and lists the keys that are not extractable as
`needs_reissue`: make new ones on the target and move their users. The
virtual HSM makes keys non-extractable unless asked, so plan on re-issuing
most. The target must unwrap with RSA-OAEP and RFC 5649 key wrap (SoftHSM2
does; the YubiHSM 2 does not, and needs its vendor's tools).

## Audit and metrics

Every login, PIN change, token initialization, object creation (generate,
create, copy, unwrap, derive), attribute change, destruction and wrap is
one audit line, as is every operator action (init, unseal, seal, rekey,
token and binding changes) and every refusal. Signing, verification,
encryption and decryption are counted per client, token, key and
operation: the first call is logged and then one in every
`KYTHIRA_HSM_AUDIT_SAMPLE_EVERY` (default 1000), each line carrying the
calls it stands for. A line names who, the token, the object's handle and
label, the mechanism and the result:

    {"hsm_audit":"sign","time":1700000000,"identity":"spiffe://apps/ca",
     "result":"ok","rv":"0x00000000","elapsed_us":42,"token":7,
     "object":4660,"label":"root","mechanism":"0x00001044","calls":1000}

It never carries a key, PIN, share or data. `KYTHIRA_HSM_AUDIT` sends the
lines to `stderr` (the default), `file:PATH` or `off`. With
`KYTHIRA_HSM_AUDIT_LEDGER_URL` set they also go to a verifiable ledger
(`KYTHIRA_HSM_AUDIT_LEDGER`, default `hsm_audit`, table
`KYTHIRA_HSM_AUDIT_LEDGER_TABLE`, default `audit`), one transaction per
batch over mutual TLS with the node's certificate unless
`KYTHIRA_HSM_AUDIT_LEDGER_CERT`, `_KEY` and `_CA` say otherwise. The
ledger's hash chain is what makes the trail verifiable. Lines are queued,
so a slow sink never holds up a PKCS#11 call; a full queue drops lines and
says how many, and a ledger that is down keeps up to 10 000 lines and then
records the gap as a `ledger_dropped` document.

Metrics (prefixed `hsm_`): `operations` by action, mechanism and result,
`operation_latency_seconds_count` and `_sum` by action, `login_failures`,
`pin_locked_refusals`, `audit_dropped`, `audit_ledger_pending`,
`replica_lag_entries` and `replica_wait_seconds_total`.

## IAM authorization

A token's clients are normally named by the catalog's bindings
(`PUT /v1/tokens/N/bindings/<identity>`). With `KYTHIRA_HSM_IAM=true` and
IAM in the same `kythira_node` (`KYTHIRA_SERVICES` naming `iam`), a client
whose identity is an IAM user or role ARN is decided by IAM's policies
instead. The identity is the client certificate's first URI SAN, so the CA
the node trusts for clients vouches for the ARN as it does for any other
name: issue the certificate with `URI:arn:aws:iam::111122223333:role/signer`.
A role ARN acts as a session of that role, a user ARN as that user, and the
PKCS#11 PIN is still needed on top.

The actions act on `arn:<partition>:hsm:<region>:<account>:token/<id>`,
where the account is the principal's own (`KYTHIRA_HSM_IAM_PARTITION`,
default `aws`; `KYTHIRA_HSM_IAM_REGION`, default `local`):

| Action | Asked for |
|---|---|
| `hsm:OpenToken` | listing the token in `C_GetSlotList`, and every call naming its slot |
| `hsm:InitToken`, `hsm:InitPIN`, `hsm:SetPIN` | the token's PINs |
| `hsm:GenerateKey` | `C_GenerateKey`, `C_GenerateKeyPair` |
| `hsm:CreateObject`, `hsm:CopyObject`, `hsm:UnwrapKey`, `hsm:DeriveKey` | the other ways an object is made |
| `hsm:WrapKey` | `C_WrapKey` |
| `hsm:SetAttributeValue`, `hsm:DestroyObject` | changing or destroying an object |
| `hsm:Sign`, `hsm:Verify`, `hsm:Encrypt`, `hsm:Decrypt` | starting the operation |

A refused call answers `CKR_ACTION_PROHIBITED`; a token without
`hsm:OpenToken` is not there (`CKR_TOKEN_NOT_PRESENT`), as for an unbound
identity. A policy granting a signer one token:

    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
      "Action": ["hsm:OpenToken", "hsm:Sign"],
      "Resource": "arn:aws:hsm:local:111122223333:token/1"}]}

Decisions are kept for `KYTHIRA_HSM_IAM_CACHE_MS` (10 000), so a revoked
grant stops working within that time. Every other identity (a SPIFFE or DNS
name, a socket uid's name, a co-located module) keeps its bindings, and a
binding never speaks for an ARN while IAM is on. A stand-alone `hsm_node`
has no IAM to ask and refuses `KYTHIRA_HSM_IAM=true`.

## What is here

| Path | What | Task |
|---|---|---|
| `include/kythira/hsm/pkcs11.hpp` | PKCS#11 for the module: core's `<raft/pkcs11.hpp>` (the five platform macros, then the OASIS v3.0 headers vendored unchanged in the top-level `third_party/pkcs11/`, with their licence and checksums) and the Cryptoki version | 1, 12 |
| `include/kythira/hsm/shamir.hpp` | Shamir sharing over GF(2^8) (constant-time arithmetic, AES polynomial), the share format (version, `k`, `n`, index, check value, checksum) and its `khs1-` text form | 2 |
| `include/kythira/hsm/secret_bytes.hpp` | a move-only byte buffer in the secure arena, wiped on release, and `constant_time_equal` | 2, 3 |
| `include/kythira/hsm/secure_arena.hpp` | locked (`mlock`), `MADV_DONTDUMP` and `MADV_WIPEONFORK` key memory wiped on release; `harden_process()` (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`); `prepare_key_memory()`, where a lock failure is a startup error unless explicitly allowed | 3 |
| `include/kythira/hsm/attributes.hpp` | `attribute_map`: PKCS#11 attribute values as replicable bytes, with template attributes flattened | 4 |
| `include/kythira/hsm/mechanisms.hpp` | every key type and mechanism of requirement 6.1-6.2 on OpenSSL 3 EVP (AES-GCM/CBC-PAD/KW/KWP, SHA-2 and HMAC, RSA v1.5/PSS/OAEP, ECDSA on P-256/384/521, Ed25519, ECDH, HKDF), the mechanism table, and the exclusions of 6.5 | 4 |
| `include/kythira/hsm/attribute_policy.hpp` | the attribute rules of 6.3-6.4, one function each (table at the top of the file) | 4 |
| `include/kythira/hsm/sealing.hpp` | AES-256-GCM sealing with the binding additional data (MK over token keys, TK over objects: token, handle, attribute digest), and scrypt PIN verifiers | 5 |
| `include/kythira/hsm/catalog_state_machine.hpp` | the catalog group: tokens and their sealed keys, client bindings, MK check value and generation, unseal mode | 5 |
| `include/kythira/hsm/token_state_machine.hpp` | a token group: token record, PIN verifiers, replicated login counters, objects with sealed material and versions | 5 |
| `include/kythira/hsm/key_store.hpp` | the leader's side: generate or re-seal material and build the entry that carries it, sealed | 5 |
| `include/kythira/hsm/persistent_group.hpp`, `codec.hpp` | the engine plumbing both groups share, and the command and record encoding | 5 |
| `include/kythira/hsm/key_vault.hpp` | what an unsealed node holds: the MK (accepted only when its check value is the catalog's) and the token keys opened with it; `seal()` wipes both | 6 |
| `include/kythira/hsm/hsm_store.hpp` | the interface the session layer reads and proposes through: this replica's catalog and token groups, proposals, and the read-index barrier | 6 |
| `include/kythira/hsm/session_layer.hpp` | PKCS#11 applications, logins, sessions, session objects and multi-part operations on this node; a read-index round before every use of a token key; opened keys cached by handle and version | 6 |
| `include/kythira/hsm/native_client.hpp` | the in-process PKCS#11 client co-located modules use, authorized by the catalog's bindings like any other | 6 |
| `include/kythira/hsm/pkcs11_native_backend.hpp` | core's `kythira::pkcs11::backend` over a `native_client`, so a co-located module uses the HSM through the same wrapper as an external module; CK_INFO and token strings match `libkythira_pkcs11.so` (`client_types.hpp`) | 12 |
| `include/kythira/hsm/object_import.hpp` | builds objects from a `C_CreateObject` template, an unwrapped key or a derived value: RSA, EC and Ed25519 keys from their components, secret keys, data objects (value sealed) and X.509 certificates (value public) | 6 |
| `include/kythira/hsm/hsm_group_state_machine.hpp` | the one state machine type multi_raft builds for every HSM group: the catalog on `c/`, token `t` on `t/<t>/`; never splits | 6 |
| `include/kythira/hsm/hsm_host.hpp` | `hsm_store` on the node's multi-raft host: the catalog and every token group on every member, created and destroyed from the catalog; proposals and read-index rounds forwarded from a follower to the leader | 6 |
| `include/kythira/hsm/hsm_peer.hpp` | forwarding between members: the `forward_reply` wire format, `serve_peer` for the listener (only a verified member certificate gets in), and `peer_client`, which presents this node's certificate and checks the leader's | 6 |
| `include/kythira/hsm/hsm_admin.hpp` | the operator API, transport-free: status; init, unseal, seal and rekey; creating, deleting, binding and unbinding tokens | 6, 7 |
| `include/kythira/hsm/unseal.hpp` | operator unseal: shares checked on arrival (encoding, split, duplicates), held in memory until `k` arrive or the timeout | 7 |
| `include/kythira/hsm/node_unseal.hpp` | node unseal: the share sealer interface and the key-file sealer, the sealed share store, collection from peers, and the member-only share routes | 8 |
| `include/kythira/hsm/wire.hpp`, `client_types.hpp` | the client wire protocol: frames, op numbers, mechanism parameters field by field (never a raw structure with pointers), and the values calls return | 9 |
| `include/kythira/hsm/wire_server.hpp` | the dispatcher (one request, one `native_client` call) and the listeners: mutual TLS 1.3, where a client is its certificate's first URI SAN (else DNS SAN), and a Unix socket served only to the uids `KYTHIRA_HSM_SOCKET_ALLOW` names; a thread per connection up to a cap | 9 |
| `include/kythira/hsm/wire_client.hpp` | a connection (TLS with the node's name checked, or the socket) and `wire_client`, `native_client`'s calls over the wire, which the client library builds on | 9 |
| `include/kythira/hsm/mtls_client.hpp` | one blocking HTTPS request with a client certificate (TLS 1.3, server name checked), for forwarding and `hsm_ctl` | 6, 7 |
| `include/kythira/hsm/expected.hpp` | `expected`/`unexpected`, the part of `std::expected` the module uses (clang 18 has none over libstdc++ 13) | 2 |
| `cmd/hsm_node/hsm_module.hpp`, `hsm_config.*`, `hsm_module_registrar.cpp` | the service module (`KYTHIRA_SERVICES=hsm` in `kythira_node`): RocksDB-backed groups on the node's transport, one HTTPS listener for the operator API and the members' forwarding routes, the PKCS#11 client listener and socket, the session layer published as `hsm.session_layer`; configuration from `KYTHIRA_HSM_*` (`usage_text()` lists it) | 6 |
| `include/kythira/hsm/audit.hpp`, `audit_json.hpp`, `audit_ledger.hpp`; `cmd/hsm_node/hsm_audit.hpp` | the audit event the session layer and operator API report (never a key, PIN, share or data), its JSON line, the ledger sink (one transaction per batch, gaps recorded), and the module's pipeline: the queue (`raft/audit_log.hpp`) to stderr, a file or a ledger, and every event into the metrics | 14 |
| `include/kythira/hsm/hsm_iam.hpp` | IAM authorization for tokens: the `hsm` action table, which identities are IAM users or roles, and the session layer's authorizer over IAM's evaluation with a decision cache | 14 |
| `cmd/hsm_ctl/` | `hsm_ctl status|init|unseal|seal|rekey`: one request to a node's operator API with the operator's certificate; init and rekey print each share once. `hsm_ctl migrate`: copy a token's keys to an external module (`migrate.hpp`) | 7, 12 |
| `include/kythira/hsm/migrate.hpp` | the copy `hsm_ctl migrate` makes: an RSA-OAEP transport key, then every extractable key under RFC 5649 key wrap; non-extractable keys reported for re-issue | 12 |
| `cmd/hsm_node/main.cpp` | `hsm_node`, the stand-alone daemon: `kythira_node` with only the HSM module (the same `KYTHIRA_NODE_*` and `KYTHIRA_HSM_*` settings, Raft listener, metrics and health endpoint), in the module's `kythira_node` group space and data directory so a cluster moves between layouts in place; `--self-test [--allow-unlocked-memory]` prepares key memory and exits. Where RocksDB, OpenSSL or the Beast transport is missing it is the self-test only | 1, 3, 11 |
| `tests/` | `hsm_pkcs11_headers_test` (the vendored headers' version, ABI types and 3.0 function table) and `hsm_node_self_test`; `hsm_node_cluster_test` (three `hsm_node` processes: the token group's leader killed during key generation and the catalog's leader killed during rekeys, then every replica agreeing on whole key pairs that all still sign and verify; and no key value, PIN or share in any member's data directory after a rekey), `hsm_node_help` and `hsm_node_refuses_other_services`; `docker/hsm_chaos_test` (the docker-chaos scenario, `docker-hsm-chaos-tests`: three members from `docker/hsm-chaos-compose.yml`, stand-alone and co-located beside Redis, under Docker and rootless Podman, with the token leader killed and partitioned during key generation and the catalog leader killed during rekeys); `hsm_test_cluster.hpp` holds the scenarios both run; `hsm_shamir_test` (split and combine properties, encoding and every refusal); `hsm_secure_arena_test` (smaps flags, wiping, lock failures under a real zero `RLIMIT_MEMLOCK`, hardening); `hsm_mechanisms_test` (published vectors, round trips, tampering, exclusions); `hsm_attribute_policy_test` (one test per rule); `hsm_key_store_test` (both state machines, persistence, the no-plaintext scan); `hsm_session_layer_test` (the vault, bindings, session states, replicated PIN counters, read-index checks against a destroy or narrowing elsewhere, the key cache, sealing, multi-part operations); `hsm_object_import_test` (create, copy, wrap and unwrap rules, ECDH on both sides, the RFC 5869 HKDF vector); `hsm_host_test` (three members on the in-process fabric: groups on every member, forwarding, a destroy seen everywhere, a partitioned member answering `CKR_DEVICE_ERROR`, a leader change, deleted token ids); `hsm_peer_test` (the wire format, membership, refusals before the host is asked, mutual TLS against a real listener, plaintext only when both sides ask); `hsm_admin_test` (operators only, status, tokens sealed under the master key, bindings, refusals, init, unseal, a seal reaching another node, rekey keeping tokens and retiring old shares, shares answered when a commit is uncertain); `hsm_unseal_test` (k shares and no fewer, checks on arrival, expiry, the vault sealing after a seal or rekey); `hsm_node_unseal_test` (the owner-only key file, shares bound to their key and never overwritten, pruning, k needed and bad peer answers skipped, member-only routes, init and rekey delivering one share per member before committing); `hsm_wire_test` (every call through the dispatcher, mechanism parameters, malformed and forged requests refused, the socket's allow list, TLS identities, connection and frame limits); `hsm_pkcs11_library_test` (`libkythira_pkcs11.so` through `dlopen`: interfaces, sessions and logins, the length query, AES-GCM, attribute rules, find, wrap and unwrap, failover, many threads, the configuration file); `hsm_pkcs11_consumers_test` (pkcs11-tool, OpenSSL's pkcs11-provider with a TLS handshake, p11-kit and GnuTLS, Go's crypto11, Java's SunPKCS11 and pkcs11test against a served node; opt-in, `pkcs11/README.md`); `hsm_pkcs11_module_test` (core's consumer wrapper on three backends, in process, `libkythira_pkcs11.so` and SoftHSM2: every common-subset key pair, lookup by URI, every signature scheme and hash verified in software, RSA-OAEP, envelope sealing, a CA whose root key is on the token, RS256 and ES256 JWS signed by keys made on the token, the refusals; an unseal file sealed by `hsm_ctl seal-secret` on SoftHSM2 and opened by the nodes' reader; and `hsm_ctl migrate` to SoftHSM2, as a library call and as the command); `hsm_iam_test` (user and role ARNs as principals, the action table, the token ARN asked about, the cache); `hsm_audit_test` (the line, the queue's batches and drops, the ledger sink's order, ids, retries and gaps, the file sink, the metrics); `hsm_ca_cluster_test` (three `ca_cluster_node` processes with the CA's root key on one SoftHSM2 token: the root made on the token, certificates verified before and after a leader kill, no private key or PIN in any data directory; and an OIDC issuer whose ES256 key is made on the token and whose unseal passphrase is sealed under a token key, a token minted over mTLS verifying under the JWKS); `hsm_test_pki.hpp` issues the TLS tests' certificates; `hsm_test_node.hpp` and `hsm_test_store.hpp` are the shared fixtures | 1-14 |
| `pkcs11/` | `libkythira_pkcs11.so`, the PKCS#11 client library, as its own target: the entry points, the configuration file, failover, the exported-symbol map (`pkcs11/README.md`) | 10 |
| `docker/` | the chaos image (`hsm-chaos/Dockerfile`: `hsm_node` and `kythira_node`) and `hsm-chaos-compose.yml`, three members addressed by service name in either layout | 11 |

TPM and cloud KMS share sealing and the documentation follow in tasks
8b and 15 (`.kiro/specs/virtual-hsm/tasks.md`).

## Core targets and variables used

This is the list a split into its own repository would need a Kythira
package to export.

| From core | Used for |
|---|---|
| `kythira_core_headers` | `include/` and `generated/`, and the vendored OASIS PKCS#11 headers (`third_party/pkcs11/`, as `<raft/pkcs11.hpp>`), through `kythira_hsm`; `raft/pkcs11_module.hpp` and `raft/pkcs11_uri.hpp` for the consumer wrapper |
| `OpenSSL::Crypto` | every mechanism, through `kythira_hsm` |
| `kythira_test_pch` | the guard the tests are entered under, and what the C++ tests link |
| `kythira_test_support` | `tests/` and `tests/docker_chaos/` on the docker-chaos scenario's include path (`test_ports.hpp`, `os_faults.hpp`) |
| `cmake/kythira_test_helpers.cmake` | `add_raft_completion_test`, `kythira_scale_test_timeouts`, and for the docker-chaos scenario `add_docker_chaos_scenario_test` and `kythira_detect_container_runtime` |
| `kythira_node` (target) | the co-located layout of the docker-chaos image, named only in generator expressions |

## What a split would still need

Nothing beyond the table above yet. The module includes no core
`*_impl.hpp` header (`boundary-allow.txt` is empty) and no other module.
