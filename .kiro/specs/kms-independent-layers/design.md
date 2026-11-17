# Design Document

## Overview

```
 AWS CLI / SDK / Encryption SDK          Kinesis, DynamoDB
        │ HTTPS, SigV4, JSON 1.1          │ kms.client (in-process where a
        ▼                                 │ KMS front end is co-located,
 gateway    framing, limits, SigV4        │ else HTTPS)
        │ authenticated call              ▼
        ▼
 front end  IAM + grants, handlers, blob/AAD, throttling, job lease,
            HSM token PIN ─── hsm.client / PKCS#11 ──► HSM (own layers)
        │ catalog access (consistent reads, proposals)
        ▼
 data       KMS catalog group: keys, versions, aliases, policies,
            grants, tags, job state, the job lease record
```

## Key design decisions

### Data nodes never touch the HSM

The KMS design runs jobs on the catalog leader and every node can call the
HSM. In a split layout that would put the HSM token PIN on data nodes,
whose job is metadata. Moving jobs to a leased front end keeps every HSM
credential in one layer. The lease is a catalog record with a fencing
token checked in `apply()`, so a holder that stalls past its expiry cannot
commit a stale job step. Co-located, the holder is simply one of the
nodes, so nothing an operator sees changes.

### Consistency first, staleness by choice

The KMS design reads metadata at a read-index point for every operation,
which is stricter than AWS (AWS documents KMS as eventually consistent).
A remote front end keeps that: one round trip to the catalog leader per
operation, the same cost a co-located follower pays today. Because the
catalog is a single small group, a leader read-index round is cheap and
can be batched across concurrent operations. A bounded-staleness cache is
a profile switch for deployments that want AWS's behaviour and fewer round
trips; it is off by default.

### Build it layered from the start

None of the KMS exists yet, so the seam costs nothing now:
`kms_catalog_access` is the only way handlers and jobs see the catalog,
and the local implementation is what a co-located node uses. Building the
handlers against the replica directly and adding the seam later is the
rewrite Kinesis needs (its spec's task 2) and DynamoDB avoided by having
`dynamo_backend` from the start.

### One catalog group, no route cache needed in practice

The catalog is one group, so the route cache holds one entry. The shared
route cache is still used, so leader changes and the epoch check work as
for the other services.

### HSM placement is the HSM's business

A KMS front end needs an HSM crypto node, co-located or remote. Where the
HSM's own layers run is decided by the HSM spec; the KMS front end only
needs `hsm.client` or the PKCS#11 network client.

## Components

| Component | Location | Notes |
|---|---|---|
| `kms_catalog_access` | `services/kms/include/kythira/kms/` | local and remote |
| job lease | `kms_catalog.hpp`, `kms_jobs.hpp` | record, token check in apply |
| role wiring | `cmd/kms_node/`, module adapter | `KYTHIRA_KMS_ROLES` |
| bounded-staleness switch | compat profile | off by default |
| docs and runbook | `services/kms/doc/independent-layers.md` | |

## Error handling

- Catalog unreachable at a read-index point: `KMSInternalException`.
- HSM unreachable from a front end: `KMSInternalException` or
  `DependencyTimeoutException`, as the KMS design maps them.
- A job command with a stale fencing token: refused in apply; the former
  holder stops its jobs.

## Testing strategy

The KMS suites on a split layout; one migration path test per path both
ways plus docker-chaos; real-AWS interoperability through recorded
fixtures in CI and a dispatch-only bundle (Encryption SDK multi-keyring,
provider switching in Kinesis and DynamoDB); the plaintext scan extended
to every layer.

## Open questions

1. Should the job lease holder be pinned to a front end co-located with an
   HSM crypto node when one exists, to save the HSM round trip for
   rotation? The design takes "any front end".
