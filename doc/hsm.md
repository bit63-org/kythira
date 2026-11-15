# Virtual HSM: operator guide

The virtual HSM is a software token that keeps its keys in Kythira Raft
groups and serves them through PKCS#11. Before you rely on it, check what it
protects against and what it does not:

| Protects against | Does not protect against |
|---|---|
| A stolen disk, backup, Raft snapshot or data directory: every key on disk is sealed under the master key (MK), and the MK is never written anywhere | Root on a host where a node is unsealed: the MK and every key in use are in that process's memory |
| A lost or retired node: its data opens nothing without the MK, and `hsm_ctl rekey` makes its old share useless | A hypervisor, or anyone who can read the VM's memory |
| Fewer than `k` share holders, or the disks of fewer than `k` members in node unseal mode | Memory dumps taken by someone with that access (core dumps and ptrace are turned off, and key memory is locked and kept out of dumps, but that only stops accidents) |
| Consumers that should use a key without reading it: keys are made non-extractable unless asked, and a client sees only the tokens it is bound to | Side channels (timing, cache, power) on the host |
| A client without a token's PIN, and guessing it: failures count on every node and lock the PIN | A compromised service in the same `kythira_node` process when the HSM is co-located |
| Keys silently changed or misused: every key change, operator action and refusal is audited, optionally to a verifiable ledger | A member's certificate and key in node unseal mode, with network reach to `k - 1` other members: that is enough to collect `k` shares |

This is not a hardware boundary. Each node says so in its log at startup:

    hsm: this is a software HSM: keys are in this host's memory while in use, ...

If you need the keys out of reach of root on the serving hosts, use a real
HSM (a YubiHSM 2 or AWS CloudHSM). Kythira's consumers work with those
unchanged; see [Moving to an external module](#moving-to-an-external-module).

The module's design is in `services/hsm/README.md` and
`.kiro/specs/virtual-hsm/`.

## Running a cluster

Run three or five members. Each runs either `hsm_node` (the HSM alone) or
`kythira_node` with `KYTHIRA_SERVICES` naming `hsm` (beside other
services). Run it stand-alone for production secrets: co-located, a memory
disclosure in any other service in the process discloses the MK. Both
layouts keep the same data under `KYTHIRA_NODE_DATA_DIR/hsm/`, so you can
switch by stopping every member and starting each in the other layout with
the same node id and data directory.

The settings every member needs (`hsm_node --help` lists them all):

| Setting | What it is |
|---|---|
| `KYTHIRA_NODE_ID`, `KYTHIRA_NODE_*` | the node's id, Raft listener, peers and TLS files, as for any Kythira node |
| `KYTHIRA_HSM_API_URLS` | `id=https://host:port` for every member, this one included |
| `KYTHIRA_HSM_API_LISTEN` | the operator API and the members' forwarding routes (`0.0.0.0:9443`) |
| `KYTHIRA_HSM_PEER_IDENTITIES` | the members' certificate SANs |
| `KYTHIRA_HSM_OPERATORS` | the operators' certificate SANs; never a member's |
| `KYTHIRA_HSM_CLIENT_LISTEN` | the PKCS#11 clients' mutual TLS listener (`0.0.0.0:9444`) |
| `KYTHIRA_HSM_APP_CA` | the CA client certificates chain to |
| `KYTHIRA_HSM_SOCKET`, `KYTHIRA_HSM_SOCKET_ALLOW` | a Unix socket for clients on the host, and which uids it serves under which identity |

The node refuses to start where it cannot lock key memory
(`RLIMIT_MEMLOCK`): raise the limit (`LimitMEMLOCK=` in a systemd unit,
`--ulimit memlock=-1` for a container). `KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY`
starts it anyway, for development only.

`hsm_ctl` talks to one node's operator API with an operator's
certificate. Set it up once:

    export HSM_CTL_URL=https://hsm-1.example:9443
    export HSM_CTL_CERT=/etc/kythira/operator.pem
    export HSM_CTL_KEY=/etc/kythira/operator.key
    export HSM_CTL_CA=/etc/kythira/ca.pem

## Choosing an unseal mode

A new cluster is sealed: it answers every cryptographic call with
`CKR_DEVICE_ERROR` until it is initialized and unsealed. `hsm_ctl init`
makes the MK, splits it into `n` Shamir shares of which any `k` rebuild it,
and the mode you choose decides who holds the shares.

| | Operator unseal | Node unseal |
|---|---|---|
| Who holds the shares | `n` people, printed once | each member, one share on its own disk |
| After a restart | `k` operators enter a share on each node | the node asks the others for `k - 1` shares over mutual TLS and unseals itself |
| A stolen disk or backup | opens nothing | opens nothing unless `k` members' disks are taken |
| A stolen member certificate | opens nothing | with reach to `k - 1` members, collects `k` shares |
| Cost | a person at every restart | none |

**In node unseal mode every unsealed node holds the whole MK in memory, and
Shamir protects the data at rest, not a running node.** The same is true of
an unsealed node in operator mode: in either mode, root on an unsealed host
can read the MK.

### Operator unseal

Initialize once, on any node:

    hsm_ctl init --mode operator --k 3 --n 5

The five shares are printed once and nothing keeps them. Hand each to its
holder and never store two together; losing more than `n - k` of them
loses every key, since nothing else can rebuild the MK.

Then, on every node, `k` holders each enter their share:

    HSM_CTL_URL=https://hsm-1.example:9443 hsm_ctl unseal    # reads the share from stdin

A node holds the shares entered so far for `KYTHIRA_HSM_UNSEAL_TIMEOUT_S`
(600 s) and drops them after; `hsm_ctl unseal --reset` drops them at once.
`hsm_ctl status` shows whether the node is sealed. After a restart, repeat
the unseal on the restarted node.

### Node unseal

`n` must be the member count:

    hsm_ctl init --mode node --k 2 --n 3

Each member stores its share under `data_dir/shares`, sealed with its share
key (`KYTHIRA_HSM_SHARE_KEY_FILE`, created owner-only on first use; keep it
off the data volume if you can). A starting member asks the others for
shares and unseals once it has `k`. With fewer than `k` members reachable
it stays sealed and keeps asking. Members answer only a certificate named
in `KYTHIRA_HSM_PEER_IDENTITIES`.

### Sealing and rekeying

`hsm_ctl seal` makes every node drop the MK and every opened key within a
maintenance pass. Use it when a host may be compromised. In operator mode
the nodes stay sealed until unsealed again; in node mode they unseal
themselves again from their peers, so to keep a node mode cluster sealed,
stop the members.

`hsm_ctl rekey [--k K] [--n N] [--mode operator|node]` makes a new MK,
re-seals every token key under it in one Raft entry, and hands out new
shares in the chosen mode. The old shares stop working, and every other
node is sealed until it is unsealed with the new ones. Rekey after a
holder leaves, a member is retired, or to change the mode or `k` and `n`.
Both init and rekey print the shares even when the commit is uncertain
(a 503 with shares): if it did commit, those are the only shares that
work, and `hsm_ctl status` shows the current generation.

## Tokens and clients

An operator creates a token and binds client identities to it through the
operator API (`services/hsm/include/kythira/hsm/hsm_admin.hpp`):

    curl --cert operator.pem --key operator.key --cacert ca.pem \
      -X POST https://hsm-1.example:9443/v1/tokens -d '{"id": 1, "label": "ca"}'
    curl --cert operator.pem --key operator.key --cacert ca.pem \
      -X PUT https://hsm-1.example:9443/v1/tokens/1/bindings/spiffe%3A%2F%2Fexample%2Fca

A client's identity is its certificate's first URI SAN (else its first DNS
SAN), or the identity `KYTHIRA_HSM_SOCKET_ALLOW` gives its uid on the
socket. A client sees only the tokens it is bound to: any other answers
`CKR_TOKEN_NOT_PRESENT`, whether it exists or not. The first client sets
the token's SO PIN with `C_InitToken`, and the SO sets the user PIN with
`C_InitPIN`, for example with `pkcs11-tool`:

    export KYTHIRA_PKCS11_CONF=/etc/app/kythira-pkcs11.conf
    pkcs11-tool --module /usr/lib/libkythira_pkcs11.so --slot 1 \
      --init-token --label ca --so-pin "$SO_PIN"
    pkcs11-tool --module /usr/lib/libkythira_pkcs11.so --slot 1 \
      --login --login-type so --so-pin "$SO_PIN" --init-pin --pin "$USER_PIN"

Applications load `libkythira_pkcs11.so`; its configuration file lists the
nodes and the client certificate (`services/hsm/pkcs11/README.md`). It fails
over between nodes on its own.

With IAM in the same `kythira_node`, `KYTHIRA_HSM_IAM=true` lets a client
named by an IAM user or role ARN be authorized by IAM policies (`hsm:Sign`
and so on, on `arn:aws:hsm:<region>:<account>:token/<id>`) instead of
bindings; see "IAM authorization" in `services/hsm/README.md`.

## Audit and metrics

Every login, PIN change, key creation, change, destruction and wrap, every
operator action and every refused call is one JSON line. Signing,
verification, encryption and decryption are sampled (the first call, then
one in `KYTHIRA_HSM_AUDIT_SAMPLE_EVERY`), each line saying how many calls it
stands for. Lines go to stderr by default (`KYTHIRA_HSM_AUDIT=file:PATH` or
`off` otherwise). Send them to a verifiable ledger as well with
`KYTHIRA_HSM_AUDIT_LEDGER_URL` to get a trail whose hash chain shows if
anything was removed. Metrics on the node's endpoint are prefixed `hsm_`:
operations by action, mechanism and result, latency, failed logins,
locked-PIN refusals, dropped audit lines and replica lag. Details are in
`services/hsm/README.md`, "Audit and metrics".

## Backups and recovery

The data directory, Raft snapshots and backups of either hold token keys
sealed under the MK and nothing that opens them. Back them up as you would
any Kythira data. To restore, you need the data and `k` shares of the MK
that sealed it: a backup taken before a rekey needs the shares from before
that rekey, which no longer work on the live cluster. Keep each share set
for as long as you keep backups that need it, or rekey and take a new
backup when a share set is retired.

Deleting a token destroys its token key, so its objects cannot be recovered
from backups taken after the next rekey.

## Moving to an external module

Kythira's own consumers reach keys only through PKCS#11, by RFC 7512 URI,
and use only what the YubiHSM 2 and AWS CloudHSM both implement (EC P-256
and P-384, RSA PKCS#1 v1.5 and PSS signing, RSA-OAEP decryption). Moving a
consumer is a configuration change:

| Consumer | Setting |
|---|---|
| The cluster CA's root key | `ca_cluster_node --ca-key-uri URI` |
| The OIDC issuer's signing keys | `ca_cluster_node --oidc-key-uri TOKEN-URI` |
| Kinesis stream encryption | `KINESIS_KMS=pkcs11`, `KINESIS_KMS_PKCS11_URI` |
| IAM's and the CA's unseal passphrases | an unseal key file made by `hsm_ctl seal-secret --key-uri URI` |

Each URI names the token, the key, the library (`module-path`) and a PIN
file (`pin-source`), never the PIN itself, for example
`pkcs11:token=ca;object=root?module-path=/usr/lib/libyubihsm_pkcs11.so&pin-source=/run/secrets/pin`.

To bring existing keys, first see what would move:

    hsm_ctl migrate --dry-run \
      --from 'pkcs11:token=ca?module-path=/usr/lib/libkythira_pkcs11.so&pin-source=/run/pin' \
      --to   'pkcs11:token=ca?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-source=/run/pin2'

Then run it without `--dry-run`. Every extractable key is copied wrapped
end to end (RSA-OAEP for a transport key made on the target, then RFC 5649
key wrap), with public halves and certificates. Keys that are not
extractable are listed as `needs_reissue`: make new keys on the target and
move their users to them (for the CA, a new root or an intermediate signed
by the old one). The virtual HSM makes keys non-extractable unless asked,
so expect to re-issue most. The target must unwrap with RSA-OAEP and RFC
5649 key wrap: SoftHSM2 does, and the YubiHSM 2 does not and needs its
vendor's tools.

## TPM and cloud KMS sealing

In node unseal mode each member's share is sealed at rest. By default the
key is a file beside the data (`KYTHIRA_HSM_SHARE_KEY_FILE`), so a copy of
the whole disk carries both. `KYTHIRA_HSM_SHARE_SEALER` puts the key
somewhere a copied disk does not reach:

| Sealer | The share's data key is wrapped by | Key id (`KYTHIRA_HSM_SHARE_KEY_ID`) |
|---|---|---|
| `file` | the key file (default) | (none) |
| `aws-kms` | an AWS KMS key | key id, ARN or alias |
| `pkcs11` | an RSA key on an external PKCS#11 token (YubiHSM 2, CloudHSM, SoftHSM2) | the key's label |
| `azure-key-vault` | an Azure Key Vault or Managed HSM key | the key's URL |
| `gcp-kms` | a GCP Cloud KMS key | `projects/.../cryptoKeys/<key>` |
| `tpm2` | this machine's TPM 2.0, optionally bound to PCRs | `owner` (default) or a persistent handle |

Every sealer but `file` works the same way: a fresh 256-bit data key seals
the share with AES-256-GCM, and the key service wraps the data key, bound to
the share's check value (an encryption context for AWS KMS, additional
authenticated data for Cloud KMS, a digest wrapped beside the key for Key
Vault and the TPM). The file stores the key id the service resolved (an
AWS KMS ARN, a versioned Key Vault key), so moving an alias or rotating the
key later does not strand a share. The `pkcs11` sealer cannot use the
co-located HSM: its token opens only once the HSM is unsealed.

A share that does not open, because the key service refuses or is
unreachable, a PCR moved, or the file came from another sealer, reads as
absent: the member asks its peers for `k` shares instead and logs why. With
fewer than `k` members able to open their shares, the cluster needs
operators (`hsm_ctl unseal`). A key service that refuses a seal fails `init`
and `rekey` rather than leave a member without its share.

Settings:

- `aws-kms`: `KYTHIRA_HSM_SHARE_KMS_REGION` (required),
  `KYTHIRA_HSM_SHARE_KMS_ENDPOINT` (host:port) and `KYTHIRA_HSM_SHARE_KMS_CA`;
  credentials from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
  `AWS_SESSION_TOKEN`. The key policy must allow `kms:GenerateDataKey` and
  `kms:Decrypt`, and can require the `kythira:hsm:share` encryption context
  key.
- `pkcs11`: `KYTHIRA_HSM_SHARE_PKCS11_URI`, a `pkcs11:` URI with
  `module-path` and `pin-source`; `KYTHIRA_HSM_SHARE_PKCS11_OAEP` is
  `sha256` (default) or `sha1` for tokens with SHA-1 OAEP only.
- `azure-key-vault`: `KYTHIRA_HSM_SHARE_AZURE_ALGORITHM` is `RSA-OAEP-256`
  (default, an RSA key) or `A256KW` (a Managed HSM's AES key). The identity
  needs the `wrapKey` and `unwrapKey` key permissions (the Key Vault Crypto
  User role). The token comes from `AZURE_ACCESS_TOKEN`, else a service
  principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
  and `AZURE_AUTHORITY_HOST` for a sovereign cloud), else the VM's managed
  identity (`AZURE_CLIENT_ID` picks a user-assigned one).
- `gcp-kms`: a symmetric `ENCRYPT_DECRYPT` key; the identity needs
  `roles/cloudkms.cryptoKeyEncrypterDecrypter` on it. The token comes from
  `GOOGLE_OAUTH_ACCESS_TOKEN`, else `GOOGLE_APPLICATION_CREDENTIALS` (a
  service account key file), else the metadata server.
  `KYTHIRA_HSM_SHARE_KMS_ENDPOINT` (an `https://` URL) reaches a private
  endpoint.
- `tpm2`: `KYTHIRA_HSM_SHARE_TPM2_TCTI` names the TPM
  (`device:/dev/tpmrm0` by default; the node's user needs access to it,
  usually the `tss` group), and `KYTHIRA_HSM_SHARE_TPM2_PCRS` the PCRs a
  new seal is bound to, such as `sha256:0,2,4,7`. `owner` derives the
  owner hierarchy's storage key again on every call, so nothing is
  provisioned, but the owner hierarchy's authorization must be empty. A
  bank the TPM has not allocated is refused, since a policy over it would
  bind nothing. Commands run in sessions salted to the storage key, so the
  data key never crosses the bus in the clear. Built when CMake finds
  tpm2-tss (`libtss2-dev`); `KYTHIRA_HSM_TPM2=OFF` leaves it out.

With PCRs bound, a firmware, boot loader or kernel update changes them and
the member's share stops opening. The member then unseals from its peers,
and the next `hsm_ctl rekey` seals new shares against the new values: roll
updates one member at a time, and rekey after each wave.

Changing a member's sealer takes effect at the next `init` or `rekey`; a
share sealed by another sealer reads as absent until then.

