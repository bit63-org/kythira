# Design Document — AZ cold start after a full power outage

## Overview

```
 power returns (possibly domain by domain, possibly flapping)
   │
   │  every host waits tier_delay + slot × interval + jitter, locally
   ▼
 T0  helm boots → hull from LKG ─► standing set ─► pinned VMs start
     time sources                       │  instance secrets (HSM shares,
     (GNSS/PTP/RTC NTP)                 │  bootstrap identity keys)
                                        ▼
                         bootstrap tier forms quorums:
                         HSM unseals itself → KMS → CA → IAM →
                         EC2 data + fleet (khold controller) → metal data
   │                                    ▲
 T1  khold / S3 storage hosts boot LKG  │ volumes of pinned VMs reattach
     Raft groups elect from what is     │ via standing attachments
     durable; serve data they hold ─────┘ (no controller needed)
   │
 T2  rest of the control plane: hosts boot LKG, links come up,
     controller in RECOVERY MODE restarts non-pinned control-plane VMs
   │
 T3  customer hosts: links, inventories, re-enrollment of expired certs,
     instances restarted in waves with `system-reboot` events
   │
 ≥95 % hosts reported (or 30 min, or EndRecovery) → normal mode,
 remaining silence handled by the rate-limited rules
```

Nothing in this picture waits for a lower tier to say it is healthy.
Tiers are a time ordering plus retries: a component that starts before
its dependency backs off and tries again. That is what lets the AZ come
back when a tier-0 host is dead.

## Where each piece lives

| Piece | Lives in | Spec |
|-------|----------|------|
| Cold-start graph and its CI check | `config/cold_start_graph.yaml`, `tools/cold_start_graph/` | this spec, Req 1 |
| `PinnedForColdStart`, standing sets, placement across power domains | EC2 module data layer | this spec, Req 2; EC2 |
| Standing records, sealed store, LKG boot on hull hosts, local power-on policy | helm | antikythera `cold-start` |
| LKG boot-cache partition on Kythira host image hosts | Kythira host image + metal boot layer | this spec, Req 4; metal |
| Tier, power domain, slot, power budget, `DescribeRecovery` | metal registry | this spec, Req 5, 13; metal |
| Recovery mode | EC2 controller, khold controller library, metal | this spec, Req 7; builds on `ec2-controller-scale` mass-silence suspension |
| Standing attachments | khold | this spec, Req 6.4; khold |
| Bootstrap intermediate and identity certificates | CA | this spec, Req 3.4, 9.4 |
| Time floor | bootstrap tier (metal data layer commits it) | this spec, Req 10 |
| Break-glass snapshots and restore | `tools/coldstart/` | this spec, Req 12 |
| Content-addressed images, per-cell and per-rack caches | metal boot layer | `fleet-cells` Req 8 |

No new service module number: the work extends metal, EC2, khold and
the CA, plus a tool.

## Key design decisions

### Pinned VMs, not a separate bare-metal control plane

Two ways out of the cycle were weighed:

- **A bare-metal bootstrap tier**: a few hosts run the control plane as
  native processes on the Kythira host image, outside EC2. Simple to
  reason about, but it is a second deployment, upgrade and monitoring
  path for the most important services, and it needs dedicated hardware.
- **Pinned instances** (chosen): the same VMs as the rest of the control
  plane, with a flag that makes their host restart them from signed,
  sealed records with no controller. One deployment; the extra machinery
  is in helm, which is small and already verifies signatures.

External seed machines remain the break-glass path (Requirement 12),
because a design that can only recover from its own hardware cannot
recover from losing too much of it.

### Standing records instead of replaying commands

hull refuses replayed sequence numbers, and after power loss nothing
remembers what was replayed. So a pinned instance is not restarted by
replaying the controller's old `launch` envelope. The controller signs a
**standing set** per tier-0 host: the full configuration of each pinned
instance on that host, its volumes and standing attachments, its
instance secrets (wrapped to the host's secure element), and a
`standing_generation`. helm accepts a set only with a higher generation
than the one it holds, and the generation is anchored in the secure
element's monotonic counter, so an old set cannot be replayed after a
newer one was accepted. hull accepts standing starts only from helm,
only before the first live controller envelope of a boot, and only for
instances the set names (antikythera `cold-start` Requirement 4).

Once the controller is up it reconciles: it sees the pinned instances in
the host's inventory, adopts them, and continues their command sequence
from what the host reports (EC2 Requirement 5.5).

### Standing attachments keep khold out of the cycle

khold already recovers from all replicas losing power without the
controller, and fences by attachment generation. A standing attachment
is an ordinary attachment that the controller marks "survives power
loss": khold keeps it granted, and the initiator on the restarted host
reconnects with the same attachment ID and generation from the standing
record, with the volume key from the record's sealed key blob. If the
volume was attached elsewhere meanwhile, the generation is retired and
the reconnect is refused, which is the fencing we want.

### Bootstrap identity certificates

Short-lived certificates are good everywhere except in the cycle: the CA
is a Raft group whose members authenticate with certificates the CA
issues. After an outage longer than seven days, every member's
certificate would have expired and the CA could not form a quorum to
issue new ones. Rather than accept expired certificates (Requirement 9.1
forbids it), the bootstrap tier uses certificates from a separate
bootstrap intermediate, valid 400 days, whose keys never leave the
instance secrets. They are used only among the bootstrap tier, so a
long-lived credential's reach is limited to a few instances. Outages
longer than that are break-glass.

### Local boot first

`metal-host-lifecycle` netboots every host on every boot so that an
upgrade is a reboot. That makes the boot layer and S3 cold-start
dependencies of every host, and a whole-AZ power event a full image
download for every host at once (the scaling audit's 500 TB at a million
hosts). Keeping the LKG image locally removes both: a host boots its LKG
when nothing changed, which is the common case after an outage. The
image is still signed, measured and immutable; the cache is not an
install, and a host whose registry entry names a new image still
fetches it. The change is written as an amendment to metal Requirement 4
and folded into that draft.

### Power-on is local and time-based

A controller-driven power-on sequence would make the controller a
dependency of powering on, which is the cycle again. helm (and the BMC
for hosts without one) applies the policy itself: tier delay, slot,
jitter. The delays spread inrush and give lower tiers a head start; they
are not gates.

### Recovery mode is the mass-silence rule at start-up

`ec2-controller-scale` Requirement 8 suspends silence-driven actions when too much of
a cell goes silent at once. A cold start is the extreme case: the
controller starts with every host silent. Recovery mode is that
suspension, entered at start-up, with explicit exit criteria and a
broader list of withheld actions (no drains, no layout changes, no
automatic enrollment windows). Exiting hands the remaining silent hosts
to the ordinary rate-limited rules, so a host that never comes back is
handled, slowly.

### Time floor

A host whose RTC battery died boots in 1970 or 2000; one with a bad
RTC can boot in the future. Raft does not care (monotonic timers), but
certificates do. The bootstrap tier commits the time floor every ten
minutes and helm stores the newest one it has seen, so a node can tell
"my clock is obviously wrong" without the internet. Issuing anything
with a clock below the floor is refused. Local time sources (two, in
different power domains) give a correct time without the internet.

## The standing set

Committed in the EC2 data layer, signed like every other frame, and
sent to the tier-0 host's outbox:

| Field | Meaning |
|-------|---------|
| `server_id` | target server |
| `standing_generation` | strictly increasing; anchored in helm's monotonic counter |
| `key_id`, signature | controller key, as every frame |
| `instances[]` | instance ID, type, image digest, CPU and memory, ENIs with fixed private IPs, metadata records |
| `volumes[]` | volume ID, attachment ID, generation, khold group endpoints, wrapped volume key |
| `instance_secrets[]` | per instance, opaque blobs wrapped to the host's secure element |
| `time_floor` | newest committed time floor |

The wire encoding and link type are antikythera's (`cold-start`
Requirement 4, link type 23).

## Recovery report

`DescribeRecovery` returns a document built from the registry's events:
for each tier, counts and lists; for each phase, start, end and target;
the recovery-mode exit reason; hosts still silent; groups still without
quorum; instances not restarted and why. A metric per phase feeds the
drill dashboards.

## Testing

- **Graph check**: unit tests with acyclic, cyclic and tier-inverted
  graphs; runs on every PR.
- **Simulated AZ** (`tests/docker_chaos/az_cold_start/`): harbor's
  simulated helm and hull, the simulated metal driver, khold, the
  bootstrap tier in containers, two customer hosts. A scenario kills
  every container at once and restarts them under the power-on policy,
  then checks the invariants of Requirement 14.1. Fault cases from
  Requirement 14.2. Docker and rootless Podman, names not IPs,
  `container_runtime()` and `compose_prefix()` only.
- **QEMU AZ** (weekly): OVMF + Secure Boot + `swtpm`, software helm,
  netboot and LKG, khold on virtual NVMe. Records phase durations.
- **Real hardware**: runbook-driven drill on Clark's go.

## Open questions

1. **Recovery priority for customer accounts.** The default restarts
   every customer instance at equal priority after the non-pinned
   control plane. An account-level priority is specified but has no API
   yet.
2. **Boot-cache partition on storage hosts.** Using a slice of a data
   drive for signed images means a drive that holds data also holds boot
   images. A small separate boot device (SATA DOM, M.2) is cleaner if the
   hardware has one.
3. **Bootstrap identity lifetime.** 400 days covers any outage but the
   longest; shortening it narrows a stolen key's use but turns more
   outages into break-glass.
