# Design Document

## Overview

```
 PKCS#11 consumers (OpenSSL, Go, Java, pkcs11-tool, KMS, CA, Kinesis, IAM)
        │ TLS 1.3 + client cert (or Unix socket, same node only)
        ▼
 endpoint   layer-4 relay, pins each connection to an unsealed crypto
            node, never terminates TLS                     (optional)
        │ same TLS stream, end to end
        ▼
 crypto     wire server, session layer, key vault (MK, token keys),
            key cache, mechanisms, generation and wrapping, unseal,
            node-unseal shares (sealed at rest)
        │ hsm_store: reads, proposals, read_barrier (+ seal state)
        │ mTLS, role=crypto
        ▼
 store      catalog group (tokens, bindings, wrapped TKs, MK check value,
            seal epoch, crypto member list) and one group per token
            (objects, attributes, wrapped material, PIN verifiers,
            counters): ciphertext only, never unsealed
```

## Key design decisions

### The seam already exists

`hsm_store` is a virtual interface with reads, two kinds of proposal and
`read_barrier`, and the session layer depends on nothing else from the
store. `basic_hsm_host` already forwards proposals and read-index requests
to leaders over `hsm_peer.hpp` with mutual TLS. A remote store is that
forwarding with every read sent too, because a crypto-only node has no
replica: `remote_hsm_store` sends reads with the barrier rather than
reading a local replica after it. One round trip per barrier, the same a
follower pays now.

### Seal state rides on every barrier

A co-located node learns of a `seal` or rekey by applying the catalog
entry, and `key_vault::enforce` drops its keys. A crypto-only node applies
nothing. So every barrier answer carries the catalog's seal epoch and MK
generation, checked before the call proceeds, and an idle crypto node
watches the catalog with the store API (bounded by the maintenance
interval) so it does not hold keys after a seal just because nobody called
it. The guarantee "no key used after a seal committed" therefore holds on
every call path.

### Store nodes are never unsealed

The state machines never touch the vault, generation and wrapping happen
on the node that serves the client (only wrapped bytes are proposed), and
the store holds only ciphertext. So a store-only node needs no MK, no
share and no unseal. That is the security gain of splitting: the nodes
with durable key material have nothing that opens it. The plaintext scan
proves it per node.

### Crypto membership is a catalog fact, not a soft list

Node unseal currently trusts "a current member of the HSM groups". In a
split layout crypto nodes are not members, and the Kinesis spec's layer
membership group is a soft, self-announced list unfit to authorize share
release. So the catalog gets a crypto member list, changed only by admin
commands with today's authorization. Shares go only to identities on it
that present the `crypto` role. A removed member still holds its old
share, so removal is completed by a rekey; the tooling does both in one
step.

### The endpoint does not terminate TLS

PKCS#11 frames carry PINs and, for `C_UnwrapKey` and secret-key creation,
key bytes. A relay that terminated TLS would see them and would also have
to assert the client's identity to the crypto node, widening trust. A
layer-4 relay sees neither, and sessions stay pinned because the
connection is. Its value is health-aware placement (only unsealed crypto
nodes) and drain; any layer-4 balancer can stand in.

### Migration keeps shares inside the crypto set

Store migration moves only ciphertext, using the ordinary learner,
promote, transfer and remove steps. Crypto migration moves the MK only
through Shamir shares, and only to admitted crypto members, by a rekey.
The crypto member list is seeded from the co-located members before any
split, so there is no step where the list and the set of unsealed nodes
disagree.

## Components

| Component | Location | Notes |
|---|---|---|
| `remote_hsm_store` | `services/hsm/include/kythira/hsm/` | `hsm_store` over the store API |
| store API | `hsm_peer.hpp` extended | reads with barrier, seal state |
| crypto member list | `catalog_state_machine.hpp`, `hsm_admin.hpp`, `hsm_ctl` | admit, remove with rekey |
| endpoint relay | `cmd/hsm_node` role `endpoint` | L4, health-aware, drain |
| role wiring | `cmd/hsm_node/hsm_config.cpp`, `hsm_module.hpp` | `KYTHIRA_HSM_ROLES` |
| docs | `services/hsm/README.md` | exposure-by-role table, runbook |

## Error handling

- Barrier unreachable: `CKR_DEVICE_ERROR`.
- Newer seal state seen: seal, then `CKR_DEVICE_ERROR`.
- A store or endpoint node asked to unseal or for a share: refused and
  logged.
- A share request from an identity not on the crypto member list: refused
  and logged, as today for non-members.

## Testing strategy

The PKCS#11 suites and consumer tests on a split layout; one migration
path test per path both ways and a docker-chaos run with a seal mid-path;
the per-role plaintext scan; CloudHSM interoperability through the
consumer wrapper in a dispatch-only run.

## Open questions

1. Should a crypto node be allowed without any store-role node in its
   placement group? It works (barriers cross placement groups), but every
   key use pays the cross-zone round trip. The design allows it and
   documents the cost.
