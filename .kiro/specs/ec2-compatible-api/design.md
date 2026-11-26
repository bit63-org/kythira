# Design Document

## Overview

```
 AWS CLI / SDKs / Terraform / aws_ec2_quorum_manager
        │ HTTPS, EC2 query protocol, SigV4
        ▼
 gateway     framing, limits, SigV4
        │ authenticated call
        ▼
 front end   authorization (ec2 action table), validation, DryRun,
             ClientToken lookup, filters and pagination, throttling
        │ data-layer API (route cache)
        ▼
 data        multi_raft, EC2 state machines on RocksDB:
             catalog + allocators │ instances │ volumes (volume master)
             snapshots, images │ VPCs, subnets, ENIs │ servers + outboxes
             leader workers: workflows, volume master ticks, rebuild,
             GC, metering; KMS Sign / GenerateDataKey / Decrypt-for-recipient
        │ outbox streams, report submission, lease requests
        ▼
 fleet       mTLS management link (antikythera link framing)
        │
        ▼
 helm (server 1) … helm (server N)     or the simulated backend
```

Antikythera's `controller-interface` and `block-volume-service` specs
define everything on and below the link. This design covers what the
controller does with it.

## Key design decisions

### Four layers, the fourth is the link

The link to helm is long-lived, latency sensitive (leases renew every
`lease_ms / 4`, one second by default) and exposed on the management
network, so it is its own layer. A fleet node is stateless: it reads each
connected server's outbox from the data layer as a stream and writes, in
order; it submits reports for commit and acknowledges them to helm only
when the data layer says they are committed; it forwards lease requests
to the leader of the volume's group and relays the grant. Losing a fleet
node costs a reconnect, which helm's link already handles (capped
backoff, replay of unacknowledged reports, idempotent snapshots).

Co-located, the fleet role reads the outbox and submits reports
in-process. Split, the same calls go over the data-layer API with layer
identities, and a fleet node may connect any server, because the route
cache finds the server's group.

### Only the data layer signs, and signs before it sends

Command decisions are made by workflows on data-node leaders. A step that
sends a command:

1. commits the step and the server's next sequence number;
2. builds the slot image with antikythera's encoder and asks KMS (or the
   HSM) to sign it;
3. commits the signed envelope to the server's outbox;
4. waits for the `command_outcome` report with that sequence number.

Step 1 records the command's full content with its sequence number, so a
leader change between 1 and 3 leaves a recorded command with no signed
envelope; the new leader signs that same command again (Ed25519 is
deterministic, so the bytes match) and the server's sequence never has a
hole. Frames (`MapUpdate`,
`GroupPolicy`, `TunnelPeers`, `ReplicaConfig`) carry their own versions
and are full snapshots, so the outbox keeps only the newest per key and a
superseded frame is never sent.

Fleet nodes never hold signing rights (Requirement 6.4). This is why
the outbox stores signed bytes: a fleet node can be compromised without
the attacker being able to issue a command, and a resend after any crash
is the same bytes, which hull refuses as a replay if it already ran.

### Workflows are committed sagas

Each multi-step operation is a workflow record in the group of its
primary resource (an instance for `RunInstances`, a volume for
`CreateVolume`), holding the steps, the step reached, and each step's
result. A leader-side worker advances it: it issues the step's side
effect (a command, a KMS call, a cross-group change), commits the result,
and moves on. Every side effect is idempotent by construction: commands
by sequence number, frames by version, volume ops by `op_id`, KMS calls
by the workflow's recorded result, cross-group changes as tier-1
transactions keyed by the workflow ID. So a worker restarted on a new
leader re-issues the last step safely and Requirement 16.4's "no step
twice with a different result" holds without distributed locking.

Failures run the recorded compensation steps in reverse (antikythera
design "Sequencing RunInstances"): destroy the VM, release the device
functions, delete the volumes created for the launch, free the capacity
reservation, release addresses.

### Placement reserves before it commands

Each server record holds its inventory and the controller's reservations
(cores, 1 GiB pages, functions by type). Placement picks a server and
commits the reservation in the server's group before `CREATE_VM`; a
launch spanning groups uses a tier-1 transaction between the instance's
group and the server's. Inventory reconciles reservations: a reservation
for a VM the server reports is consumed; one for a VM the server never
created is released when its workflow compensates. The first policy
follows antikythera's "Placement inputs": local (instance-store) volumes
pin the server; otherwise most free whole cores with a free blk function
per network attachment and a free NIC function per interface; an
opted-in multicast subnet's flood-list cap is an admission check.

### The volume master runs on the volume group's leader

Antikythera specifies the volume master by code (`ak_hold_master`:
single-threaded, deterministic, time passed in, output only through a
transport). Two ways to replicate it were considered:

- run it inside `apply()`, with every report and tick as a log entry; or
- run it on the leader, committing its decisions.

Replica status reports arrive per volume every `lease_ms / 4`, so the
first would log four entries per second per volume for information that
is only useful to the current leader. The design takes the second, the
Physalia shape block-volume-service describes: the master runs on the
leader of each volume group over the group's committed state; every
decision that changes a ReplicaConfig (epoch, members, roles,
attachments, size, QoS, flags), every snapshot cut and every erasure is
committed before the master's transport publishes it; reports and lease
acknowledgement times stay in leader memory.

On leader change, the new leader rebuilds the master from committed
state, publishes nothing older than what is committed, and treats every
primary as holding a lease until `lease_ms × 1.1` after it took
leadership (Requirement 9.5). Promotion decisions therefore never depend
on a previous leader's memory. Epochs are committed values, so they only
grow.

This needs `ak_hold_master` to restore from an exported state and to
report the decisions it wants committed before acting on them. Task 9
adds that interface in antikythera (or ports the master into
`services/ec2/` if the interface would distort it), and the simulation
`hold_sim_test` keeps checking the rules on the antikythera side.

### Leases

```
hold ── replica_status ──► helm ──► fleet ──► volume group leader
                                                │ master.on_status(now)
hold ◄── lease_grant ◄──── helm ◄── fleet ◄─────┘  (if still primary
                                                    at this epoch)
```

The leader measures lease time from when it decided the grant, and the
primary from when it sent the request (block-volume-service design
"Epochs, leases and fencing"), so the fleet hop and its queues only
shorten the primary's view of its own lease. A fleet node that crashes
drops requests; the primary renews four times per lease, and helm
reconnects within the first backoff step, so a fleet failure costs no
lease unless it lasts more than about three seconds. Leases and reports
ride the control traffic class (controller-interface Requirement 2.4) on
helm's side; fleet nodes put lease traffic ahead of outbox bulk.

### Restores and conversions

oar-blk's hydration and copier run on the servers; the controller only
decides when a volume is ready and drives the copy as a workflow.

**Hydration.** A volume restored from an image (the root of
`RunInstances`) or re-keyed from a source is attachable as soon as its
replica set is in sync; oar-blk fills it behind the guest. Every
`replica_status` entry carries `total_bytes` and `hydrated_bytes`, and
the volume group's leader keeps the newest pair per replica in memory,
as it keeps the other report fields. When every in-sync replica at the
current epoch reports `hydrated_bytes == total_bytes`, the leader commits
`hydrated` on the volume record; it is never cleared, so a replica
rebuilt later, or a report from a lagging replica, cannot make a
finished volume look unfinished. The volume's EC2 state reads from it:
a fast-restored volume stays `creating` until `hydrated`; any other is
`available` or `in-use` with `DescribeVolumeStatus` `warning` and
`InitializationStatusDetails` (`Progress` from the least-hydrated in-sync
replica, `EstimatedTimeToCompleteInSeconds` from the remaining bytes and
`VolumeInitializationRate`) until then. A new leader starts with no
pairs and keeps reporting the volume as initializing until fresh reports
arrive, so a leader change can delay `hydrated` by one report interval
but never sets it early.

**Conversion.** An admin call, `convert-volume` (an instance ID, a local
or network volume ID, an optional MiB/s), runs a `convert_volume`
workflow in the volume's group. The instance must be `stopped`, so both
volumes are detached, as `CONVERT_VOLUME` requires. Its steps:

1. Create the target. To network: place a new replica set with a new
   lineage (its KMS key and wrapped data key as `CreateVolume` makes
   them), size and block size from the local volume, wait for every
   member's `replica_status`, then publish a ReplicaConfig with a
   read-write utility attachment for the local volume's server and send
   that server the attachment's `VolumeKey`. To local: send
   `CREATE_VOLUME` to a server placement picks for the instance (it
   reserves the instance's cores there, since the server becomes its
   pin), sized
   from the network volume, and publish a ReplicaConfig adding a
   read-only utility attachment of the network volume for that server
   with its `VolumeKey`.
2. Wait for `hydrated` if the network volume is the source; a copy of an
   unhydrated source fails with `not_hydrated`, so the workflow does not
   send one.
3. Send `CONVERT_VOLUME` with both IDs, the instance as `owner_vm`, the
   direction and the rate. Its outcome only says the copy was accepted.
4. Follow `conversion_progress` reports matched on the volume pair:
   commit `done_bytes` for the admin describe call, and finish on
   `completed` or `failed`.
5. On `completed`: replace the instance's block-device mapping entry
   (an `ephemeralN` local volume becomes an `Ebs` network volume with
   `DeleteOnTermination = true`, and the reverse), which moves or adds
   the instance's server pin (Requirement 7.4); retire the utility
   attachment; delete the old volume (`DELETE_VOLUME` for a local one,
   the network delete otherwise). On `failed`: retire the utility
   attachment and delete the target; the instance keeps its old volume.

Cancelling (an admin `cancel-conversion`, the server lost, or no report
for the server's silence window) publishes a ReplicaConfig without the
utility attachment, which stops the copy on the server, then runs the
`failed` branch. Step 5's record switch and deletes are committed
together before any delete is sent, so a leader change between them
re-sends the deletes, never the copy. While the workflow runs the
volume group refuses attach, delete, a second conversion and
`StartInstances` for the instance with `IncorrectInstanceState`.

### Planned fleet moves do not look like failures

The volume master and the instance status checks both use server silence
(10 s for hold roles). A fleet drain first tells the data layer which
servers it is about to disconnect; their silence clocks restart at the
reconnection deadline (the drain time plus helm's first backoff steps,
15 s by default), and only then does the node close the connections.
An unplanned fleet crash gets no such grace, which is right: the data
layer cannot tell it from a partition, and the master's rules (lease
expiry before promotion) already make a false failover safe, merely
unneeded.

### Keys: the controller never sees a data key

```
CreateVolume:   L = KMS CreateKey (per lineage, non-exportable,
                    policy: only the EC2 service principal)
                W = KMS GenerateDataKeyWithoutPlaintext(L, ctx)
                [tenant KmsKeyId T: grant on T; W' = KMS Encrypt(T, W)]
                store W (or W')

AttachVolume:   [W = KMS Decrypt(T, W') under the grant]
                VolumeKey = KMS Decrypt(L, W, Recipient = {
                    X25519 transport key of the attaching helm,
                    aad = server_id | volume_id | attachment_id | generation,
                    info = "antikythera volume key v1" })
```

The inner blob `W` is a KMS ciphertext, so peeling the tenant layer gives
the controller nothing usable; only KMS ever sees plaintext, and it
leaves KMS sealed to one helm's secure element for one attachment
generation. Revoking the grant or disabling `T` stops every later attach
of the lineage, which is EBS's behaviour for a disabled CMK. Deleting the
lineage schedules `L` for deletion, which makes every copy of `W` in Raft
snapshots and backups unreadable.

The recipient form of `Decrypt` is a Kythira extension: AWS's `Recipient`
takes a Nitro attestation document and returns `CiphertextForRecipient`
under an RSA key. Kythira's takes a `KeyEncryptionAlgorithm` of
`KYTHIRA_HPKE_X25519_SHA256_AES256GCM`, the public key and the AAD, and
returns the HPKE encapsulation and ciphertext in the same field. It is
authorized by the key policy, the encryption context, and a new
condition key on the recipient's registered identity. Task 8 adds it to
the KMS module with the CFRG HPKE vectors and antikythera's
`volume_key` vectors.

Local volumes keep antikythera's helm key hierarchy; they come only from
`ephemeralN` mappings, which have no `KmsKeyId`, so the tenant layer
never applies to them.

### Identifiers

Every resource has a 64-bit ID from a per-kind counter in the regional
catalog group, allocated in blocks to each group so allocation does not
round-trip to the catalog per call. The EC2 form is the prefix, `0`, and
16 lower-case hex digits of the ID, so it has EC2's 17-digit shape and
decodes back to the ID antikythera carries. Counters never go back, so
IDs are never reused (Requirement 4.1). VNIs (24 bits) and MACs (the
configured locally administered prefix, 24 or 32 bits of counter) are
counters in the catalog too; running out is an error, never a wrap.

### Partitioning

| Group kind | Holds | Key |
|---|---|---|
| catalog | allocators, accounts' defaults, instance types, signing key table, ClientToken index | one group |
| instance | instances, their workflows, metadata records | `i/<id>` hash |
| volume | volumes, attachments, lineages, snapshots, the volume master's committed state | `v/<lineage>` hash, so a lineage's clones and snapshots share a group |
| network | VPCs, subnets, ENIs, address pools, mapping and peer-set versions | `n/<vni>` |
| server | server records, reservations, inventory, report windows, outbox, sequence numbers, metering readings | `s/<server_id>` hash |
| image | images, launch permissions | `a/<id>` hash |

Groups split and merge as elsewhere in Kythira; the volume group of a
lineage never splits it.

### EC2 query protocol

`aws_ec2_protocol.hpp` sits beside `aws_query_protocol.hpp` and reuses its
form decoder, XML writer and marker sealer. It differs where EC2 differs:
lists flatten as `Name.N` (no `.member`), requests use the model's
`queryName` / capitalized `locationName`, responses use the lower-camel
`locationName`s inside `<ActionResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">`
with `requestId` and `<item>` list elements, and errors are
`<Response><Errors><Error><Code/><Message/></Error></Errors><RequestID/></Response>`.
The handler table is generated from the pinned model, like the other
modules', and the generator's coverage check fails on any operation that
is neither implemented nor listed as unsupported.

### Metering and the multicast setting

Tags with the reserved `kythira:multicast:` prefix (`mode`,
`rate-frames`, `burst-frames`, `rate-bytes`, `burst-bytes`,
`max-servers`, `max-groups-per-nic`) carry the setting because every SDK
and the CLI can already set and read tags, where an extension action
would need a patched client. `CreateTags` validates them against the
region's maxima and refuses out-of-range values; the network group turns
an accepted change into a new `GroupPolicy` version for the VNI.

`group_usage` readings are committed to the server group with their
series key; a metering worker turns consecutive readings into deltas per
account and hour and writes them, with enablement hours from the
committed policy history, to an S3 export and to Prometheus. A reading
below the previous one in the same series is recorded as a fault and
billed as zero.

## Components

| Component | Location | Notes |
|---|---|---|
| Model and coverage | `services/ec2/include/kythira/ec2/model/` | pinned botocore `ec2` |
| EC2 query codec | `include/raft/aws_ec2_protocol.hpp` | core, beside the query codec |
| Action table | `ec2_actions.hpp` | resources and condition keys per action |
| Catalog and allocators | `ec2_catalog.hpp` | IDs, VNIs, MACs, ClientTokens, instance types |
| State machines | `ec2_instance_state_machine.hpp`, `ec2_volume_state_machine.hpp`, `ec2_network_state_machine.hpp`, `ec2_server_state_machine.hpp`, `ec2_image_state_machine.hpp` | one per group kind |
| Workflows | `ec2_workflows.hpp` | steps, compensation, worker |
| Placement | `ec2_placement.hpp` | reservations, policy |
| Volume master adapter | `ec2_volume_master.hpp` | `ak_hold_master` over committed state |
| Signing | `ec2_signer.hpp` | KMS / HSM, key table, rotation |
| Fleet | `ec2_fleet.hpp` | link server, outbox streams, report submit, lease relay |
| Simulated backend | `ec2_sim_fleet.hpp` | fake helms over the real link codecs |
| Metadata records | `ec2_metadata.hpp` | per-NIC records for helm's IMDS |
| Metering | `ec2_metering.hpp` | deltas, exports |
| Handlers | `ec2_service.hpp` | through the codec |
| Daemon | `cmd/ec2_node/` | roles, TLS, link listener |

## Error handling

- A call whose workflow cannot be committed in time answers a retryable
  `RequestLimitExceeded` or `InternalError`; with a `ClientToken` the
  retry returns the workflow's result.
- A command refused by hull (`command_outcome` not `ok`) fails the step
  and runs compensation; `wrong_server` or a signature refusal is a
  controller bug and raises an alarm as well.
- A server lost mid-workflow fails the workflow's next step after the
  server-lost decision; volumes on it fail over through the master, and
  instances on it go to `stopped` with `Server.InternalError` (EC2's
  retirement behaviour), not `terminated`.
- KMS refusing a tenant key puts the volume in `error` (on create) or
  fails `AttachVolume`, with the state reason and error code EC2 gives
  for an inaccessible KMS key (taken from the recorded fixtures).

## Testing strategy

- Codecs: antikythera's vectors reproduced; the EC2 query codec's
  round-trip and fuzz targets.
- State machines and workflows: property tests with leader changes,
  fleet reconnects, dropped and duplicated reports, failed commands, and
  server loss injected at every step, checking sequence and epoch
  monotonicity, no lost acknowledged change, every workflow finishing or
  compensating, and no two leased primaries.
- Client suites against the simulated backend, co-located and split;
  Kythira's own EC2 clients pointed at Kythira EC2.
- Migration path tests in both directions plus docker-chaos.
- Recorded real-EC2 fixtures; a dispatch-only real-EC2 bundle.
- Harbor end to end on antikythera (tikhov), on Clark's go.

## Open questions

1. Port `ak_hold_master` into `services/ec2/`, or link antikythera's
   library with an export/restore interface? The design prefers linking
   (one set of rules, checked by antikythera's simulation); task 9
   decides once the interface is drafted.
2. Should `RebootInstances` wait for a hull reset command, or be
   implemented as stop and start on the same server? The spec refuses it
   until hull has a reset.
3. Usage export format: CSV in the shape of AWS Cost and Usage Reports,
   or Parquet? CSV first.
4. The metadata record type on the link (Requirement 13.2) is a change to
   antikythera's controller-interface spec; it is drafted there as part of
   task 14 here.
5. Should a compute-server drain convert its stopped instances' local
   volumes to network volumes automatically, so they can start
   elsewhere? Task 13a builds only the admin call; a drain policy would
   call the same workflow.
