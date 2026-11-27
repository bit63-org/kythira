# Design Document — Bare-metal host lifecycle

## Overview

```
 kythira-metal CLI / scripts
        │ HTTPS, JSON, SigV4
        ▼
 gateway     framing, limits, SigV4
        ▼
 front end   metal: action table, validation, client tokens
        ▼
 data        multi_raft, host registry on RocksDB:
             hosts │ images + expected measurements │ boot-node assignments
             leader workers: lifecycle workflows, cert renewal, drain polls
        │ mTLS, dialled out from the LAN
        ▼
 boot        (on the hosts' LAN, stateless)
             proxyDHCP │ TFTP (iPXE only) │ HTTPS: scripts, images,
             discovery, enrollment, reports │ power drivers
        │ DHCP/PXE, HTTPS                 │ Redfish / IPMI / helm link
        ▼                                 ▼
 hosts: discovery image → role image (hull, or the Kythira host image) → wipe image
```

The module is service module 13 (`METAL` Kconfig option,
`services/metal/`), opt-in like every other. The first AZ's seed is a
co-located node on a machine outside the fleet (reliant, tikhov or a
cloud instance), with the boot layer split out onto one small machine
on the hosts' LAN. Every later AZ or region is seeded from an AZ that
already exists, including a region that will be disconnected, which is
made self-sufficient before the link is cut.

## Key design decisions

### One lifecycle, two classes, two kinds

Class (storage or diskless) is a fact about the hardware; role is what
the operator chose; kind follows from the role. A `vm_host` is an
antikythera server (helm and hull) whatever its class: a storage
`vm_host` offers instance-store volumes from its drives, a diskless one
does not. `khold` and `s3_storage` run on the **Kythira host image**: a
signed, read-only UKI built the same way as hull's (no shell, no sshd,
no package manager, no writable root) that runs one Kythira node binary
with its data on the local drives. Building it like hull keeps one
image pipeline, one measurement scheme and one attestation path.

### Signed images only, data on disk only

No host installs an operating system on a drive. Every boot runs the
image the registry names for the host: fetched over the network when it
changes, otherwise from the host's local last-known-good copy
(`.kiro/specs/az-cold-start/` Requirement 4), so an upgrade is a reboot, a
role change is a drain, a wipe and a reboot, and a stolen drive holds
only data that is encrypted at rest. With the local copy a host
whose image is unchanged boots without the boot layer; the boot layer
still keeps its last committed copy of every in-service host's script
and image (Requirement 14.5) for hosts whose local copy is missing or
being replaced.

### proxyDHCP, not DHCP

A home lab's router owns DHCP, and taking it over would break the
operator's network the first time the boot node is down. proxyDHCP
answers only the PXE boot options, on UDP 67 and 4011, beside the
existing server. The boot layer runs **dnsmasq** in proxy mode with TFTP
enabled as a supervised child, configured from a file it writes, rather
than a DHCP implementation of our own: dnsmasq's PXE handling is the
best-tested there is, and keeping our own code out of the DHCP parser
removes an untrusted-input surface. Its configuration answers only MAC
addresses the data layer assigned to this boot node, plus a catch-all
that serves discovery.

TFTP serves one file, an iPXE `snponly.efi` built with Kythira's CA and
a script that fetches `https://<boot>/v1/boot?mac=${net0/mac}`. From
there everything is HTTPS. UEFI HTTP Boot clients get the same URL from
the proxyDHCP answer and skip TFTP.

### Per-host settings in a measured provisioning file

The image is the same for every host of a role; the host's identity is
not baked in. The boot script passes a small provisioning file (server
ID, role, boot node address, data and front-end addresses, enrollment
nonce) as an extra initrd. The image's init measures it into a PCR
before reading it, which is what hull's `server-id file` mode already
requires, so the quote at enrollment covers the settings as well as the
image.

### Enrollment

```
host                              boot node                 data layer
 │ discovery report (EK hash) ───►│──────────────────────────►│ match registration
 │◄── role image + provisioning ──│◄── script, expected PCRs ─│
 │ create AK in TPM               │                           │
 │ EK cert/pub, AK pub ──────────►│──────────────────────────►│ MakeCredential(EK, AK name)
 │◄── credential blob ────────────│◄──────────────────────────│
 │ ActivateCredential, quote(PCRs, nonce), CSR ──────────────►│ check secret, quote vs expected
 │◄── certificate (host_id, server_id), 7 days ───────────────│ CA issues
```

Credential activation proves the attestation key lives in the TPM whose
endorsement key the operator registered; the quote proves the image and
provisioning file that booted. Expected PCR values are recorded per
image when the image is published (the build computes PCR 11 for a UKI
with `systemd-measure`; PCRs 0, 2 and 7 are learned at the host's first
attested boot and pinned from then on, since they depend on firmware).
Renewal repeats the quote over mTLS every few days, so a host whose
firmware or image changed without the registry knowing loses its
credentials within a week and is cordoned at once (Requirement 9.2).

Hosts with no TPM are a home-lab concession: an operator-opened, one-use
window bound to a MAC address, with an optional console fingerprint
check. They can run `khold` and `s3_storage`, never `vm_host`.

For an antikythera host, helm is the enrolling party (its secure element
is the TPM on the control slot, backplane Requirement 3.2) and hull
takes its server ID from the provisioning file; the antikythera
`server-provisioning` spec covers that side.

### Power drivers run on the boot node

BMCs sit on the LAN, so the drivers run where the boot layer runs. The
data layer's workflow commits "power cycle host 7 for step N", the boot
node assigned to host 7 performs it, reads the power state back and
reports. A step that already reports done is not repeated after a leader
change. `redfish` uses HTTPS with the BMC's certificate pinned at
registration (most BMCs ship self-signed ones); `ipmi` runs `ipmitool
-I lanplus -C 17` as a child; `helm` sends the host power record on the
host's own management link (the boot node asks the EC2 fleet layer to
send it); `manual` turns the step into an operator task.

### Drains ask the owning service

Metal never moves data. It cordons, asks, and polls:

| Role | Ask | Done when |
|---|---|---|
| `vm_host` | EC2: exclude from placement; scheduled events with a deadline; volume live moves for hold/khold replicas on the host; stop remaining instances at the deadline | EC2 reports no instance, reservation or replica on the server |
| `khold` | khold `evacuate` | khold reports the node holds no replica |
| `s3_storage` | S3 re-places the host's blobs | S3 reports every object at its replica count without the host |
| diskless `vm_host` | as `vm_host`, no local data | no instance |

The refusal of Requirement 10.5 is the owning service's own answer to
"can you lose this node now?", so metal holds no model of replica
placement.

### Wipe order

Credentials go first: the certificate is revoked before the wipe image
boots, so a host that stops halfway can never rejoin with its old
identity. The wipe image authenticates with a one-use wipe token from the
provisioning file instead. On each data drive it destroys the key
material first (the data is encrypted at rest, so this alone makes it
unreadable), then runs NVMe Sanitize with crypto erase (block erase if
not supported, ATA Secure Erase on SATA), reads the sanitize log back,
and reports per drive. Then it clears the TPM owner hierarchy and powers
off. On an antikythera host helm does the equivalent for its secure
element and its storage roles (`server-provisioning`).

### State and layout

| Prefix | Contents | Group |
|---|---|---|
| `h/<host_id>` | host record, workflow step, event history | hash of `host_id` |
| `i/<image_id>` | image: role, S3 location, digest, expected PCR 11 | catalog |
| `b/<boot_node_id>` | boot node identity, assigned hosts, last seen | catalog |
| `u/<mac>` | unclaimed discovery reports, expiring after 7 days | catalog |

A boot node holds a stream of its assigned hosts' scripts and settings
and keeps the last committed copy on its own disk, encrypted, for
Requirement 14.5.

## Failure handling

| Failure | Effect |
|---|---|
| Boot node down | hosts in service keep running; netboots wait; no workflow step advances for its hosts; the operator can reassign hosts to another boot node |
| Data layer unreachable from boot node | boot scripts served from the last copy; no enrollment, no power action |
| Host hangs in a step | step deadline (per role, default 30 minutes) moves it to `failed`; retry starts the step again |
| Attestation mismatch | `failed`, measurements recorded, nothing issued |
| Drive fails sanitize | retire continues; drive serial listed for destruction |
| BMC unreachable | step fails with the driver error; no blind retry |

## Testing strategy

- State machine: property tests over every transition with injected
  leader changes, boot-node crashes and driver failures; workflow steps
  checked for idempotence by replaying each one twice.
- Parsers (discovery reports, quotes, CSRs, the boot HTTP surface):
  unit tests and fuzz targets. dnsmasq is a dependency, not our parser.
- Docker and rootless Podman: every workflow with the `simulated` driver
  and simulated hosts; layer migrations both ways under load. DHCP is
  not in these tests (it needs broadcast between real interfaces).
- QEMU end to end (OVMF with Secure Boot, `swtpm`, a bridge in a network
  namespace, a dnsmasq-backed boot node): discovery, enrollment with a
  real TPM quote, a role image booting, wipe with emulated NVMe sanitize.
  Runs in CI where nested KVM is available, else on tikhov on Clark's go.
- Drivers: recorded Redfish (iDRAC 9) and IPMI exchanges replayed; a real
  R640-class run on Clark's go.

## Open questions

Settled with Clark on 2026-11-27: `khold` and `s3_storage` hosts run
the Kythira host image; a storage host carries one role at a time; an
AZ's first hosts are provisioned by a seed control plane (an existing AZ
where there is one, Requirement 14).

1. Where does the hull UKI come from on a real backplane? The host has no
   NIC of its own, so `server-provisioning` proposes a read-only boot
   function presented by helm; harbor uses OVMF HTTP Boot as a stand-in.
2. Default drain deadline for `vm_host`: AWS gives about two weeks for
   retirements; 24 hours suits a home lab. Configurable either way.
