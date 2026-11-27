# Requirements Document — Bare-metal host lifecycle

## Introduction

Kythira's services and antikythera's servers run on physical machines,
and nothing yet brings a machine into the fleet or takes it out. Pieces
exist: hull boots one signed, measured image with no writable disk
(antikythera `hull-host-agent` Requirement 1); helm holds the host's
power and reset (antikythera `backplane-hardware` Requirement 2.3); the
EC2 module serves helm's management link with a certificate that names
the server (`.kiro/specs/ec2-compatible-api/` Requirement 5); khold and
the EC2 data role have an `evacuate` call; an operator can declare a
server lost (EC2 Requirement 5.6). What is missing is the lifecycle that
joins them: how a new machine is found, booted, given an identity and put
to work, and how it is drained, wiped, stripped of its credentials and
retired.

This spec adds a **metal** service module that owns that lifecycle for
every physical host, and a stateless **boot** layer that runs on the
hosts' LAN and netboots them. Antikythera's
`.kiro/specs/server-provisioning/` specifies the helm and hull side of
the same contract.

The fleet has two kinds of host, told apart by whether they have local
drives:

- **Storage hosts** have local drives and take one role at a time: a
  khold storage node, an S3 storage node, or a customer VM host whose
  instances may have instance-store volumes.
- **Diskless hosts** run only customer VMs (internal customers included)
  and keep every volume on the network.

Every host boots an immutable signed image that the registry chooses.
No host has an operating system installed on a disk, and reprovisioning
never means reinstalling. `.kiro/specs/az-cold-start/` Requirement 4
amends the boot path: each host keeps its last-known-good signed image
locally (in helm's sealed store on hull hosts, in a boot-cache partition
on Kythira host image hosts), boots it when its assigned image is
unchanged or the boot layer cannot be reached within 30 seconds, and
netboots only to change images.

The reference deployment is home-lab scale: one LAN behind a single
dynamic public IPv4 address, a home router that owns DHCP, a handful of
servers with or without a BMC, and 25 GbE between them (1 GbE floor).

### What this spec does not cover

- Bare-metal instances offered to tenants (EC2 `*.metal` types) and EC2
  dedicated hosts. They stay refused (EC2 Requirement 14).
- Firmware and BIOS updates. Firmware settings are checked, not changed
  (Requirement 9).
- The image contents of hull, helm and the oars (antikythera specs).
- Physical procurement, racking and cabling.

## Glossary

The Kinesis independent-layers glossary applies, with the boot layer
added to the layers. In addition:

- **Host**: one physical machine known to the metal registry by its
  `host_id`.
- **Host class**: `storage` (has local data drives) or `diskless`.
- **Role**: what a host does once in service: `khold`, `s3_storage` or
  `vm_host` on a storage host; `vm_host` on a diskless host.
- **Kind**: how the host runs its role: `antikythera` (helm + hull, VMs
  through the mailbox) or `linux` (the Kythira host image running Kythira
  node binaries directly). A `vm_host` is always `antikythera`.
- **Power driver**: the component that powers a host on or off and sets
  its next boot source: `helm`, `redfish`, `ipmi`, `manual` or
  `simulated`.
- **Boot layer**: the stateless LAN-side layer: proxyDHCP, TFTP for the
  iPXE binary, HTTPS for boot scripts, images and enrollment, and the
  power drivers.
- **Enrollment**: the step in which a booted host proves it is the
  registered machine and receives its server ID and certificate.
- **Seed control plane**: the Kythira control plane (metal, IAM, KMS,
  the CA, and EC2 once VM hosts exist) that provisions an AZ's first
  hosts: an existing AZ's control plane where one exists (Clark,
  2026-11-27), otherwise machines outside the fleet.

## Requirements

### Requirement 1: Host registry and states

**User Story:** As the operator, I want every physical host recorded
with its state, so that I always know what each machine is doing and
nothing joins or leaves the fleet unrecorded.

#### Acceptance Criteria

1. The data layer SHALL keep one record per host: `host_id`, class,
   role, kind, the expected identity (TPM endorsement key hash, MAC
   addresses, serial number), power driver and its encrypted credentials,
   state, the image it should boot, its certificate's serial, and an
   append-only event history.
2. A host SHALL be in exactly one of these states: `registered`,
   `discovered`, `booting`, `enrolling`, `checking`, `ready`,
   `in_service`, `cordoned`, `draining`, `drained`, `wiping`, `retired`,
   `failed`, `lost`.
3. Only these transitions SHALL be allowed: the provisioning path
   `registered → discovered → booting → enrolling → checking → ready →
   in_service`; `in_service ⇄ cordoned`; `cordoned → draining →
   drained`; `drained → booting` (reprovision, keeping `host_id`);
   `drained → wiping → retired`; any state to `failed` with a reason, and
   `failed` back to the state it failed from on retry; any state after
   `enrolling` to `lost` by an operator declaration, and `lost → retired`.
4. `host_id` SHALL be allocated by the data layer, unique, and never
   reused, including after retirement. For an `antikythera` host it SHALL
   also be the antikythera `server_id`.
5. Every transition SHALL be committed before its side effects start, and
   every side effect SHALL be idempotent, so a leader change or a crashed
   boot node resumes a step without repeating its effect.
6. A retired host's record SHALL be kept as a tombstone with its history;
   registering the same machine again SHALL create a new `host_id`.

### Requirement 2: Admin API and authorization

**User Story:** As the operator, I want one authenticated API and CLI for
every lifecycle step, so that scripts and people use the same path.

#### Acceptance Criteria

1. The gateway SHALL serve a Kythira-specific JSON API over HTTPS with
   SigV4, authorized through `iam-compatible-auth` with the action prefix
   `metal:`. No AWS API manages a provider's own hosts, so none is
   emulated.
2. The API SHALL offer `RegisterHost`, `UpdateHost`, `DescribeHosts`,
   `DescribeHostEvents`, `OpenEnrollmentWindow`, `ProvisionHost`,
   `ReprovisionHost`, `CordonHost`, `UncordonHost`, `DrainHost`,
   `DeprovisionHost` (drain, wipe and retire), `DeclareHostLost` and
   `RetireHost`.
3. Every mutating call SHALL take a client token and return the same
   result when retried with it.
4. A `kythira-metal` CLI SHALL wrap every call.
5. BMC credentials SHALL be encrypted with a KMS key before they are
   committed, decrypted only by the boot node that drives that host, and
   never returned, logged or written to an event.

### Requirement 3: Discovery

**User Story:** As the operator, I want a newly cabled machine to show up
on its own, so that I only need to say what it is for.

#### Acceptance Criteria

1. WHEN an unknown machine netboots on the LAN THEN the boot layer SHALL
   answer it with a discovery image only, which reports its MAC
   addresses, serial number, TPM endorsement key hash (if a TPM is
   present), CPU, memory, drives, NICs and link speeds, and then powers
   the machine off.
2. A discovered machine that matches no registration SHALL be listed as
   `unclaimed`, SHALL get no credentials, and SHALL be netbooted again
   only into discovery.
3. `RegisterHost` SHALL accept an unclaimed machine or a pre-registration
   by MAC address, serial or endorsement key hash; a registered host
   found by discovery SHALL move to `discovered`.
4. The class SHALL be derived from discovery (a host with at least one
   data drive outside the boot path is `storage`) and SHALL be
   confirmed by the operator; a role that does not suit the class SHALL
   be refused.

### Requirement 4: Netboot on a LAN the module does not own

**User Story:** As the operator of a home lab, I want hosts to netboot
without handing DHCP to Kythira, so that the rest of my network keeps
working as it does.

Where this requirement and `.kiro/specs/az-cold-start/` Requirement 4
differ, az-cold-start governs when a host boots its local last-known-good
image instead of netbooting.

#### Acceptance Criteria

1. The boot layer SHALL answer PXE and UEFI HTTP Boot clients with
   proxyDHCP, adding boot options only and never offering addresses, so
   an existing DHCP server keeps assigning them.
2. TFTP SHALL serve only the iPXE binary. Everything after it SHALL be
   fetched over HTTPS, with Kythira's CA built into the iPXE binary.
   Clients with UEFI HTTP Boot SHALL skip TFTP.
3. The boot script each host gets SHALL depend on its state: discovery
   for unclaimed hosts, its signed role image while provisioning or in
   service, the wipe image while wiping, and nothing (exit to local
   firmware, then off) for a retired host.
4. Images SHALL be signed UKIs, verified by UEFI Secure Boot where the
   host has it. Image bytes SHALL be served from Kythira S3 and cached on
   the boot node.
5. The boot layer SHALL dial out to the data and front-end layers over
   mutually authenticated TLS, so the LAN needs no inbound port from the
   internet and works behind one dynamic IPv4 address.
6. An image SHALL take its per-host settings (server ID, role, layer
   addresses) from a provisioning file that the image measures before
   use, as hull's `server-id file` does, so one image serves many hosts.

### Requirement 5: Power and boot drivers

**User Story:** As the operator, I want the same workflow to drive a
server with a BMC, a server with only IPMI, an antikythera backplane and a
box with no BMC at all.

#### Acceptance Criteria

1. Every power driver SHALL offer: power on, power off, power cycle, set
   the next boot source (network once, or local), and read power state.
2. The `redfish` driver SHALL use `ComputerSystem.Reset` and a one-time
   boot source override, and SHALL read Secure Boot state, TPM presence
   and serial number where the BMC exposes them.
3. The `ipmi` driver SHALL use IPMI 2.0 over LAN with cipher suite 17
   and SHALL refuse cipher suite 0.
4. The `helm` driver SHALL send antikythera's host power records over
   the management link (`.kiro/specs/server-provisioning/`).
5. The `manual` driver SHALL post an operator task ("power on host 7 and
   choose network boot") and SHALL wait for the operator to confirm it,
   with no deadline unless one is configured.
6. The `simulated` driver SHALL drive virtual hosts for tests.
7. A driver call that times out SHALL fail the step with the driver's
   error, never retry a power action without reading the state first.

### Requirement 6: Enrollment and identity

**User Story:** As the operator, I want a host to receive credentials only
after it proves it is the machine I registered and is running the image
I approved.

#### Acceptance Criteria

1. A host with a TPM 2.0 SHALL enroll by proving its attestation key is
   bound to the registered endorsement key (credential activation) and by
   a quote over the boot measurements; the data layer SHALL compare the
   quote with the expected values recorded for the image it served.
2. A host without a TPM SHALL enroll only inside an enrollment window the
   operator opened for that host (`OpenEnrollmentWindow`, at most 60
   minutes, one use), from a registered MAC address, with the key
   fingerprint shown on the host's console and confirmed by the operator
   when `confirm_fingerprint` is set. Such a host SHALL be recorded with
   `trust = window`.
3. An `antikythera` host SHALL enroll only with `trust = tpm`, so EC2
   never places a customer VM on a host whose image was not attested.
4. Enrollment SHALL issue a certificate from Kythira's CA that names the
   `host_id` (and the `server_id` for antikythera hosts), valid for at
   most 7 days by default, renewed over mTLS with a fresh quote.
5. The private key SHALL be generated on the host, in the TPM or the
   secure element where present, and SHALL never leave it.
6. A failed attestation SHALL leave the host `failed` with the mismatched
   measurements recorded and SHALL issue nothing.

### Requirement 7: Checks before service

#### Acceptance Criteria

1. Before `ready`, the host SHALL report a self-check: memory size, CPU
   count, every data drive's health (SMART or NVMe health log), NIC link
   speeds, IOMMU state, and Secure Boot state.
2. The role SHALL define minimums (for example IOMMU on and Secure Boot
   on for `vm_host`; 25 GbE storage link on a `khold` host, refusable
   down to the 1 GbE floor by an explicit override), and a host below them
   SHALL go to `failed` with the failing checks listed.
3. `ProvisionHost` with `auto_service = true` SHALL move a `ready` host to
   `in_service`; otherwise the operator moves it.

### Requirement 8: Joining a service

**User Story:** As the operator, I want a host in service to be known to
the service that uses it, and nothing else.

#### Acceptance Criteria

1. Entering `in_service` SHALL hand the host to its role's service: an
   EC2 server record for `vm_host`, a khold node for `khold`, an S3 blob
   store for `s3_storage`.
2. EC2 SHALL place instances only on hosts the metal registry reports
   `in_service`; a `cordoned` or later host SHALL be excluded from
   placement while its existing instances keep running.
3. khold and S3 SHALL add a storage node only when metal reports it
   `in_service`, and SHALL treat `cordoned` as "accept no new replicas or
   blobs".
4. A service SHALL keep authority over its own data: metal never moves a
   volume, replica or blob itself; it asks the owning service and waits.

### Requirement 9: Firmware and settings are checked, not changed

#### Acceptance Criteria

1. Where the driver can read them, Secure Boot state, TPM presence and
   the IOMMU setting SHALL be recorded at discovery and at every boot.
2. A change in any of them since enrollment SHALL cordon the host and
   raise an event.

### Requirement 10: Drain

**User Story:** As the operator, I want to empty a host without losing
data or surprising customers, so that I can repair, repurpose or retire
it.

#### Acceptance Criteria

1. `DrainHost` SHALL cordon the host first, then ask its role's service
   to move everything off it, and SHALL reach `drained` only when every
   service reports the host empty.
2. A `vm_host` drain SHALL publish an EC2 scheduled event
   (`system-maintenance` or `instance-retirement`) with a deadline
   (default 24 hours, configurable per call), move network volumes'
   replicas through the volume services' live moves, and at the deadline
   stop each remaining instance and leave it to start elsewhere. An
   instance with instance-store volumes SHALL be stopped with them lost
   unless the operator converts them first (EC2 `convert-volume`, EC2
   open question 5).
3. A `khold` drain SHALL call khold's `evacuate` and wait for every
   replica to move.
4. An `s3_storage` drain SHALL ask S3 to re-place the host's blobs and
   wait until every object is back at its replica count elsewhere.
5. A drain SHALL be refused, unless forced, when completing it would
   leave a volume, Raft group or object below its replica count with no
   target to move to; a forced drain SHALL list what it left degraded.
6. A diskless host SHALL reach `drained` when it runs no instances.

### Requirement 11: Wipe and retirement

**User Story:** As the operator, I want a retired machine to leave with
no data and no credentials, so that I can sell or recycle it safely.

#### Acceptance Criteria

1. Leaving `drained` towards `wiping` SHALL revoke the host's certificate
   in Kythira's CA and stop its renewal before any wipe step starts.
2. On a storage host the wipe SHALL crypto-erase every encrypted volume
   key, then run NVMe Sanitize (crypto erase, else block erase) or ATA
   Secure Erase on every data drive, read back each drive's sanitize
   status, and report per-drive results.
3. Every host SHALL clear its TPM owner hierarchy (or, on an antikythera
   host, have helm destroy its secure-element keys) before `retired`.
4. The wipe image SHALL run with a one-use wipe token instead of the
   revoked certificate.
5. A drive that cannot be sanitized SHALL be reported by serial number
   as needing physical destruction, and the host SHALL still retire with
   that recorded.
6. `RetireHost` on a `lost` host SHALL record that its media were not
   wiped.
7. A retired host SHALL be powered off and SHALL get no boot script but
   discovery's refusal.

### Requirement 12: Reprovisioning and role changes

#### Acceptance Criteria

1. `ReprovisionHost` SHALL drain the host, then boot it again with a new
   image or a new role, keeping `host_id` and its enrollment identity.
2. A role change on a storage host SHALL wipe its data drives between
   the drain and the new boot.
3. An image upgrade with the same role SHALL keep data drives, and SHALL
   be refused for a `khold` or `s3_storage` host unless that service
   reports it can tolerate the host's absence for the reboot.

### Requirement 13: Lost hosts

#### Acceptance Criteria

1. `DeclareHostLost` SHALL tell every service using the host to treat it
   as lost at once (EC2 Requirement 5.6, khold's server loss), revoke its
   certificate, and move it to `lost`.
2. A lost host that reappears SHALL be answered only with discovery
   until the operator registers it again.

### Requirement 14: The seed control plane

**User Story:** As the operator, I want to bring up the first hosts of an
AZ or region before any host there exists to run its control plane.

#### Acceptance Criteria

1. The very first AZ SHALL be seeded by the metal module and the
   services it depends on (IAM, KMS, the CA) running on machines outside
   the fleet, such as existing Linux hosts or cloud instances.
2. A new AZ or region that will stay connected to the fleet SHALL be
   seeded from an AZ that already exists: that AZ's control plane runs
   the new AZ's metal data layer until the new AZ's own control plane is
   up, and the new AZ runs only its boot layer locally at first.
3. A region that will be disconnected SHALL, when possible, be seeded
   from an existing AZ before it is disconnected, and SHALL have its
   whole control plane moved onto its own hosts and verified (every host
   enrolled and renewing against the region's own CA chain) before the
   link is cut. A region that cannot be reached at all SHALL be seeded
   from machines outside the fleet as in criterion 1.
4. Moving the control plane from its seed onto VMs in the fleet, and
   back, SHALL use the services' own layer migrations (Requirement 15)
   with no lifecycle state lost.
5. The boot layer SHALL keep serving boot scripts for hosts already in
   service while it cannot reach the data layer, from its last committed
   copy, and SHALL make no state change until it reconnects.

### Requirement 15: Independent layers

**User Story:** As an operator, I want each layer runnable on its own,
and co-located by default.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_METAL_ROLES`, a subset of
   `gateway`, `front_end`, `data`, `boot`; default all four.
2. The boot layer SHALL be stateless and SHALL run on the hosts' LAN; the
   other layers MAY run anywhere it can reach.
3. Every layer SHALL move between co-located and independent placements
   in both directions with no lost acknowledged change and no repeated
   power action, and these migrations SHALL be tested.
4. Two boot nodes on one LAN SHALL never both answer the same host:
   the data layer SHALL assign each host to one boot node, and a boot
   node SHALL answer only hosts assigned to it.

### Requirement 16: Testing

#### Acceptance Criteria

1. The state machine SHALL be property-tested with leader changes, boot
   node crashes, duplicated and lost reports, and driver failures injected
   at every step.
2. Every parser of host-supplied data (discovery reports, quotes, DHCP
   and TFTP requests) SHALL have unit tests and a libFuzzer target.
3. Workflows SHALL be tested end to end with the `simulated` driver in
   Docker and rootless Podman.
4. Netboot, TPM enrollment and wipe SHALL be tested in QEMU with OVMF,
   Secure Boot and `swtpm`.
5. The `redfish` and `ipmi` drivers SHALL be tested against recorded BMC
   exchanges, and on real hardware only on Clark's go.
