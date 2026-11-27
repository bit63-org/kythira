# Requirements Document — AZ cold start after a full power outage

## Introduction

Kythira's control plane (IAM, KMS and the virtual HSM, the certificate
authority, the EC2 module's data and fleet layers, khold's controller,
the metal registry) is meant to run as VMs on the fleet it controls:
antikythera servers whose VMs are launched by EC2. That is a circular
dependency, and a full power outage of an AZ is the moment it bites.
After the power returns:

- every hull host has forgotten everything, because hull has no writable
  disk (antikythera `hull-host-agent` Requirement 1) and helm has no
  persistent store in any spec;
- a host starts a VM only when the controller sends it signed commands
  (antikythera `controller-interface` Requirement 1), and the controller
  is one of those VMs;
- every host netboots from the boot layer (`metal-host-lifecycle`
  Requirement 4), whose images live in Kythira S3, which runs on storage
  hosts that also netboot;
- the VMs' volumes are khold volumes, attached by the controller, whose
  keys KMS seals;
- the certificates every link uses are short-lived, and the CA that
  renews them is a Raft group that runs on the same VMs;
- the clock may be wrong and the internet may be unreachable.

Nothing today says what happens in that order, so an AZ that loses power
cannot be trusted to come back by itself. This spec is the **reboot
stability plan**: a declared dependency graph with no cycle, a small
bootstrap tier that restarts with no control plane at all, cold-start
rules for every stateful piece, staggered power-on, a recovery mode in
which the control plane does nothing it would regret, and cold-start
drills that run as tests.

The antikythera half (helm's sealed store, local boot from a
last-known-good image, standing instances, power-on staggering on the
backplane) is `.kiro/specs/cold-start/` in `bit63-org/antikythera`.

### Principles

1. **No cycles.** Every component that must run for the AZ to recover
   has a declared cold-start dependency set, and the graph of those sets
   is acyclic once the bootstrap tier's local restart is counted as
   depending on nothing but power.
2. **Static stability.** A host keeps doing what it was last told; a
   control plane that has just started does nothing destructive until
   it has heard from the fleet.
3. **Local first.** Everything the bootstrap tier needs to restart is on
   the hosts it runs on: signed images, signed standing records, sealed
   keys. The network is needed only between those hosts.
4. **One deployment.** The bootstrap tier is the ordinary control plane
   in ordinary VMs with a pin on them, not a second way to deploy.
5. **Prove it often.** A cold start that is not drilled does not work.

### What this spec does not cover

- Building the power infrastructure (UPS, generators, PDUs). The spec
  assumes power returns, possibly in pieces, and sets budgets the
  operator configures.
- A whole region with several AZs failing over to each other. Today the
  AZ is the region; when a region has several AZs, a neighbour AZ is an
  extra recovery source (Requirement 12), not a replacement for this
  plan.
- Data lost on media that did not survive. Recovery never invents data;
  it reports what it could not recover.

## Glossary

The `metal-host-lifecycle` and `khold-block-service` glossaries apply.
In addition:

- **Cold start**: the AZ's hosts start with no control-plane process
  running anywhere in the AZ. A full power outage is the main cause; a
  bad deploy that stops every control-plane VM is another.
- **Power domain**: the set of hosts that lose power together (one PDU,
  one UPS, one circuit). The operator records each host's domain in the
  metal registry.
- **Tier**: a host's place in the cold-start order. Tier 0 hosts carry
  the bootstrap tier; tier 1 hosts are storage (`khold`, `s3_storage`);
  tier 2 hosts carry the rest of the control plane; tier 3 hosts carry
  only customer VMs.
- **Bootstrap tier**: the pinned instances of the control-plane services
  that the AZ needs to recover, with enough replicas to form every one of
  their Raft quorums.
- **Pinned instance**: an EC2 instance marked as part of the bootstrap
  tier. Its host restarts it after power returns, from a standing record,
  with no controller.
- **Standing record**: a record signed by the controller and kept by
  helm in its sealed store that says "after power returns, start this
  instance with this configuration and these volumes". Antikythera
  `cold-start` Requirement 4 defines the record.
- **Standing attachment**: a khold attachment of a pinned instance's
  volume that stays granted across power loss, so the instance reattaches
  with its existing attachment ID and generation.
- **Last-known-good image (LKG)**: the newest signed host image that a
  host booted and passed its checks with, cached on the host
  (antikythera `cold-start` Requirement 2 for hull hosts; Requirement 4
  here for Kythira host image hosts).
- **Recovery mode**: the state the EC2 controller, khold controller and
  metal registry start in after a cold start, in which no silence-driven
  or destructive action runs.
- **Time floor**: the latest wall-clock time the AZ has committed. No
  node may treat a clock earlier than it as correct.
- **Cold-start graph**: the machine-readable dependency graph of
  Requirement 1.

## Requirements

### Requirement 1: The cold-start dependency graph

**User Story:** As the operator, I want the order in which the AZ comes
back written down and checked, so that a new dependency cannot silently
create a cycle that only a power outage would reveal.

#### Acceptance Criteria

1. The repository SHALL keep `config/cold_start_graph.yaml`, which lists
   every component that must run for the AZ to recover (services, their
   layers, the boot layer, khold storage nodes, S3 storage nodes, time
   sources, helm, hull) with its tier and the components it needs before
   it can start serving.
2. A CI check SHALL refuse a graph with a cycle. A dependency of a
   tier-0 component on another tier-0 component SHALL be allowed only
   when both restart from local state (standing records, LKG images,
   sealed keys) and need only each other over the network.
3. A component SHALL never depend on a component of a higher tier number.
4. Each service module SHALL declare its cold-start dependencies next to
   its module number, and the CI check SHALL refuse a module whose
   declaration is missing or disagrees with the graph.
5. The graph SHALL be rendered into the runbook (Requirement 14) so the
   documented order is the checked order.

### Requirement 2: The bootstrap tier

**User Story:** As the operator, I want a small, named set of control-
plane instances that can come back on their own, so that everything else
can be started by the control plane as usual.

#### Acceptance Criteria

1. The bootstrap tier SHALL contain a quorum-capable replica set of
   every service the AZ's recovery needs before the controller can launch
   anything: the virtual HSM and KMS, the CA, IAM, the EC2 data and fleet
   layers (which host khold's controller library), and the metal data
   layer.
   Nothing else SHALL be pinned.
2. The tier SHALL run in ordinary EC2 instances, launched through the
   ordinary EC2 API with `PinnedForColdStart = true`, using the same
   images and configuration as the rest of the control plane.
3. Pinning SHALL be allowed only for accounts the operator lists as
   control-plane accounts, and only by an IAM principal with
   `ec2:PinInstanceForColdStart`.
4. The pinned replicas of each Raft group SHALL be placed so that no
   power domain holds a majority of them, and the controller SHALL refuse
   a placement or a host retirement that would break this, unless the
   operator forces it with a reason that is recorded.
5. Pinned instances SHALL use khold volumes with standing attachments
   (Requirement 6), never instance-store volumes for state that must
   survive the loss of a host.
6. The default size SHALL be three pinned replicas per group in a
   home-lab AZ and five once the AZ has five or more power domains.
7. The controller SHALL keep each tier-0 host's standing records current:
   every change to a pinned instance's configuration, volumes or keys
   SHALL be followed by a new signed standing set to its host before the
   change is reported complete.

### Requirement 3: Restarting the bootstrap tier with no controller

**User Story:** As the operator, I want the bootstrap tier back within
minutes of the power returning, without any machine outside the AZ.

#### Acceptance Criteria

1. WHEN a tier-0 host powers on THEN its helm SHALL boot hull from the
   LKG image and start every instance in its stored standing set with no
   controller link (antikythera `cold-start` Requirements 2 and 4).
2. A pinned instance SHALL find its peers by the addresses recorded in
   its configuration, which SHALL not depend on DNS served by the control
   plane or on DHCP leases that change.
3. The virtual HSM in the bootstrap tier SHALL use node unseal
   (`virtual-hsm` Requirement 4.4) with each share held as an **instance
   secret**: sealed to the host's secure element, kept in helm's sealed
   store, and delivered to the instance only when helm starts it from its
   standing record (antikythera `cold-start` Requirement 5), so `k`
   pinned HSM replicas unseal one another with no person. Operator unseal
   SHALL remain the break-glass path.
4. The bootstrap tier SHALL authenticate to one another with
   **bootstrap identity certificates**: certificates from the CA's
   bootstrap intermediate, valid for 400 days, whose private keys are
   instance secrets, used only for the bootstrap tier's Raft, unseal
   and CA traffic, and renewed when a third of their lifetime is left.
   Every other certificate keeps its short lifetime.
5. A pinned instance SHALL start serving its service as soon as its
   group has a quorum; it SHALL NOT wait for the rest of the AZ.
6. In the reference configuration (three tier-0 hosts in three power
   domains, 25 GbE), the bootstrap tier SHALL be serving within 10
   minutes of the last of a quorum of tier-0 hosts receiving power.

### Requirement 4: Booting without the boot layer

**User Story:** As the operator, I want hosts to boot after a power
outage even though the boot layer and S3 are not up yet, and without a
netboot storm.

#### Acceptance Criteria

1. Every host SHALL keep its LKG image locally: a hull host in helm's
   sealed store (antikythera `cold-start` Requirement 2), a Kythira host
   image host in a dedicated boot-cache partition on a data drive that
   holds only signed images and is not otherwise an operating system
   install.
2. On power-on a host SHALL boot its LKG image when the registry's
   assigned image for it is unchanged or the boot layer cannot be reached
   within 30 seconds, and SHALL netboot only to change images.
3. An image SHALL become a host's LKG only after the host booted it,
   enrolled or renewed with a quote over it, and passed its role's checks
   (`metal-host-lifecycle` Requirement 7). Each host SHALL keep the LKG
   and the one before it.
4. This requirement amends `metal-host-lifecycle` Requirement 4 ("every
   host netboots"): a host still runs only immutable signed images and
   its drives still hold no operating system install, but it boots from
   its local copy when nothing has changed.
5. When many hosts do need new images at once, they SHALL be served
   through the content-addressed boot images and per-cell and per-rack
   caches of `.kiro/specs/fleet-cells/` Requirement 8, never directly from S3 by every
   host.

### Requirement 5: Staggered power-on

**User Story:** As the operator, I want hosts to come back in tier order
and spread in time, so that the power returning does not trip breakers
and the tiers that others need start first.

#### Acceptance Criteria

1. The registry SHALL record for each host its tier, power domain and
   power-on slot; slots within a power domain SHALL be assigned so that
   at most a configured number of hosts (default 4) start per slot.
2. Each host's power-on policy SHALL be: wait `tier_delay[tier] +
   slot × slot_interval + jitter`, then power on. Defaults: tier delays
   0 s, 60 s, 180 s, 300 s; slot interval 5 s; jitter uniform 0-2 s.
3. The policy SHALL be enforced locally, by helm on antikythera servers
   (antikythera `cold-start` Requirement 3) and by the BMC's power-restore
   setting plus the power driver's delayed power-on where the host has no
   helm. It SHALL NOT need the control plane.
4. A higher tier SHALL NOT wait for a lower tier to report healthy before
   powering on; ordering comes from the delays, and readiness from each
   component retrying its dependencies (Requirement 6.5). This keeps a
   failed tier-0 host from holding the whole AZ off.
5. The operator SHALL be able to set a per-power-domain budget in watts
   and a measured or rated per-host inrush; the registry SHALL refuse a
   slot assignment that would exceed it.
6. Metal SHALL push changed policies to helm and to BMCs; a host SHALL
   keep its last policy while it cannot reach metal.
7. Hosts whose BMC is set to restore power on their own while the
   registry says they should wait SHALL be reported by the settings check
   of `metal-host-lifecycle` Requirement 9.

### Requirement 6: Stateful pieces after a cold start

**User Story:** As a tenant, I want no acknowledged write lost and no
split brain when the whole AZ restarts at once.

#### Acceptance Criteria

1. Every Raft group (control plane, khold stripe groups, S3, the
   services' data layers) SHALL recover by electing a leader once a
   majority of its voters is back, from what each voter made durable,
   with no acknowledged write lost (`durable-append-barrier`;
   `khold-block-service` design "Power loss on all replicas").
2. No group SHALL shrink its membership, replace a member, or drop a
   witness automatically during recovery mode. A group without a majority
   SHALL wait.
3. A group that cannot reach a majority because voters are gone for good
   SHALL recover only through an explicit operator action
   (`RecoverGroupFromSurvivors`), which records which acknowledged writes
   may be lost, and which is refused while any lost voter's host is
   merely unreachable rather than declared lost.
4. A khold stripe group SHALL keep its standing attachments: a pinned
   instance reattaching with the same attachment ID and generation SHALL
   be served without the controller, and fencing (`khold-block-service`
   Requirement 6.5) SHALL still refuse a retired generation.
5. Every component SHALL retry its cold-start dependencies with capped
   exponential backoff and jitter (initial 1 s, cap 30 s) and SHALL never
   exit because a dependency is not up yet.
6. S3 and other services' storage hosts SHALL serve reads as soon as
   their own group has quorum; they SHALL NOT need the control plane to
   serve data they already hold.

### Requirement 7: Recovery mode

**User Story:** As the operator, I want a control plane that has just
started to wait until it can see the fleet, so that it does not mistake
hosts still booting for hosts that died.

#### Acceptance Criteria

1. The EC2 controller, khold's controller and the metal registry SHALL
   enter recovery mode WHEN they start and more than the mass-silence
   threshold of `.kiro/specs/ec2-controller-scale/` Requirement 8 (default 5 %) of
   in-service hosts have no link, or WHEN the operator starts a drill
   with `BeginRecovery`.
2. In recovery mode they SHALL NOT: declare a host lost or failed,
   replace a replica, mark a status check `impaired` for silence, stop or
   retire an instance, start a drain, open a new enrollment window
   automatically, or change a volume's layout except to restore a standing
   attachment.
3. In recovery mode they SHALL: accept links and inventories, reconcile
   records with what hosts report (EC2 Requirement 5.4), renew
   certificates, serve read APIs, and serve control-plane mutations
   (launches, attaches) for hosts that have reported.
4. Recovery mode SHALL end WHEN at least 95 % of in-service hosts have
   reported an inventory, or a configured time (default 30 minutes)
   has passed since the controller started, or the operator calls
   `EndRecovery`. Hosts still silent at the end SHALL then be handled by
   the rate-limited silence rules of `.kiro/specs/ec2-controller-scale/` Requirement 8,
   never all at once.
5. Recovery mode, its start, its exit reason and the list of hosts still
   silent at exit SHALL be recorded as events and exported as metrics.

### Requirement 8: Customer instances after a cold start

**User Story:** As a tenant, I want my instances back after an outage in
the state I left them, and told what happened.

#### Acceptance Criteria

1. An instance whose desired state was `running` when its host lost
   power SHALL be started again on the same host once the host reports,
   in waves of at most a configured number of instance starts per second
   per cell (default 50), pinned instances excepted.
2. Instances SHALL be restarted in priority order: control-plane
   instances that are not pinned, then customer instances by the account's
   recovery priority (default equal), then by launch time.
3. An instance with instance-store volumes SHALL get its volumes back
   intact when its host's drives survived and its keys are still sealed
   in helm's secure element; otherwise it SHALL be started with empty
   instance-store volumes only if its launch allowed that, and stopped
   otherwise.
4. Each restarted instance SHALL show an EC2 event of code
   `system-reboot` with a description naming the power event, and
   `DescribeInstanceStatus` SHALL show the reboot time.
5. An instance whose host does not report by the end of recovery mode
   SHALL be handled as for any lost host after recovery mode ends
   (EC2 Requirement 5.6): an EBS-backed instance stopped and startable
   elsewhere, an instance-store-backed one terminated with the event
   `instance-retirement`.

### Requirement 9: Certificates and keys across a long outage

**User Story:** As the operator, I want the AZ to come back after an
outage longer than any short-lived certificate, without weakening
certificate checks in normal running.

#### Acceptance Criteria

1. No component SHALL accept an expired certificate, in recovery or not.
2. A host whose link or role certificate expired while it was off SHALL
   re-enroll through the attested path of `metal-host-lifecycle`
   Requirement 6 (a fresh quote and credential activation for TPM hosts,
   the secure element for helm), which SHALL be allowed for a host in
   `in_service` without changing its lifecycle state.
3. A host with `trust = window` (no TPM) whose certificate expired SHALL
   wait for the operator to open an enrollment window, and SHALL be
   listed in the recovery report.
4. The CA SHALL have an offline root (valid 20 years), an online
   intermediate for ordinary certificates (valid one year, renewed with
   three months left), and the bootstrap intermediate of Requirement 3.4
   (valid five years). An outage longer than a bootstrap identity
   certificate's lifetime SHALL be recovered through operator unseal and
   the break-glass path of Requirement 12.
5. Every key that the bootstrap tier needs to start (instance secrets,
   HSM shares, volume keys of pinned instances) SHALL be unsealable on its
   host with no service of the bootstrap tier running.
6. Signing keys used for standing records SHALL be rotated like every
   other controller key (EC2 Requirement 6.2), and a standing set signed
   by a retired key SHALL still be honoured until the host receives a new
   one, unless the key was revoked for compromise.

### Requirement 10: Time

**User Story:** As the operator, I want certificate checks and Raft
timers to behave after an outage even if the internet is unreachable and
a host's clock is wrong.

#### Acceptance Criteria

1. Each AZ SHALL have at least two local time sources in different power
   domains (GNSS or PTP grandmasters, or hosts with a trusted RTC acting
   as NTP servers), declared in the cold-start graph as tier 0.
   Internet NTP MAY be used in addition, never alone.
2. The bootstrap tier SHALL commit the time floor every 10 minutes, and
   helm SHALL store the newest time floor it has seen in its sealed store.
3. A node SHALL refuse to issue a certificate, sign a standing record or
   accept a certificate's `not_before` while its clock is below the
   newest time floor it knows, and SHALL report the skew.
4. A node whose clock is more than 5 minutes ahead of the median of its
   time sources SHALL refuse to issue certificates until corrected.
5. Raft and lease timers SHALL use monotonic clocks only; wall-clock
   steps during recovery SHALL not change elections or leases.

### Requirement 11: Partial outages

#### Acceptance Criteria

1. Losing one power domain SHALL need no cold start: the bootstrap tier
   keeps a majority, the domain's hosts come back through Requirements 4
   and 5, and the silence rules of `.kiro/specs/ec2-controller-scale/` Requirement 8
   apply.
2. Power that returns domain by domain SHALL work with any order of
   domains; tier delays apply from each host's own power-on.
3. Power that drops again during recovery SHALL restart the plan with no
   operator action and no state lost.

### Requirement 12: Break-glass recovery

**User Story:** As the operator, I want a way back even when the
bootstrap tier cannot form a quorum.

#### Acceptance Criteria

1. Every bootstrap-tier Raft group SHALL export a snapshot at least
   hourly, encrypted with a key the HSM wraps under a break-glass key
   held by operators, to an object store outside the AZ (another AZ's
   S3, a cloud bucket, or removable media), with retention of 7 days.
2. A `kythira-coldstart restore` tool SHALL restore the bootstrap tier
   from those snapshots onto seed machines outside the fleet (the same
   seed path as `metal-host-lifecycle` Requirement 14.1) or onto a
   neighbouring AZ's control plane, with operator unseal, and SHALL then
   sign fresh standing sets for the tier-0 hosts.
3. The restore SHALL report what changed after the snapshot it used and
   may be lost, and SHALL refuse to run while a quorum of the original
   bootstrap tier is reachable.
4. Moving the control plane back from the seed onto pinned instances
   SHALL use the services' layer migrations (`metal-host-lifecycle`
   Requirement 14.4).

### Requirement 13: Observability

#### Acceptance Criteria

1. Metal SHALL offer `DescribeRecovery`, listing per tier: hosts powered,
   hosts booted (LKG or netboot), hosts reporting, Raft groups with and
   without quorum, standing instances started, certificates re-enrolled,
   instances restarted and instances still waiting, with timestamps.
2. Each host SHALL report its power-on time, boot source and standing
   start results (antikythera `cold-start` Requirement 6) once its link
   is up.
3. A recovery SHALL produce a timeline report, kept with the registry's
   events, comparing each phase with its target.

### Requirement 14: Cold-start drills and testing

**User Story:** As the operator, I want the cold start exercised
regularly, so that I find out it is broken in a drill and not in an
outage.

#### Acceptance Criteria

1. A simulated AZ (simulated metal driver, harbor-simulated helm and
   hull, khold, the bootstrap tier and two tiers of hosts in containers)
   SHALL be cold-started in CI on every pull request that touches a
   component in the cold-start graph, under Docker and rootless Podman,
   with no fixed IP addresses, and SHALL check: no acknowledged write
   lost, every running instance back, recovery mode entered and left, no
   silence-driven action during it.
2. The same suite SHALL inject: a tier-0 host that never returns, power
   returning domain by domain in random order, power dropping again
   mid-recovery, clocks off by days in both directions, an outage longer
   than every short certificate, and a boot layer that never comes up.
3. A weekly scheduled run SHALL cold-start a QEMU AZ (OVMF, Secure Boot,
   `swtpm`, a software helm) with real netboot, LKG boot and khold
   storage, and SHALL record each phase's duration against the targets
   of Requirement 3.6.
4. A real-hardware drill (cut power to every host of the home-lab AZ)
   SHALL be a documented procedure run only on Clark's go, at most
   monthly, and its timeline SHALL be kept with the results.
5. The CI check of Requirement 1 SHALL run on every pull request.
6. `doc/runbooks/az-cold-start.md` SHALL describe the order, what each
   phase looks like when healthy, what to do when it is stuck, and the
   break-glass restore.
