# Requirements Document

## Introduction

This spec adds an **Amazon EC2-compatible compute API** to Kythira. The
AWS CLI, the AWS SDKs, Terraform's AWS provider and Kythira's own EC2
clients (`aws_ec2_quorum_manager`, `aws_ec2_peer_discovery`) point their
EC2 endpoint at a Kythira cluster and launch, stop, start and terminate
instances, create and attach EBS-style volumes, take snapshots, and make
VPCs and network interfaces.

The instances run on **antikythera** servers (`bit63-org/antikythera`).
This module is antikythera's **controller**: every VM, device, volume and
VPC change originates here and reaches a server's helm as a signed
command or frame over a mutually authenticated link. The contract this
module drives is antikythera's `.kiro/specs/controller-interface/`; this
spec implements its Requirement 6 (the EC2 action mapping) and
Requirement 9 (the EBS mapping of network volumes, written in antikythera
PR #99), and the controller side of Requirements 1-5, 7 and 8 (envelopes,
the link, inventory, identifiers, mappings, multicast policy and
metering, tunnel keys). It also takes the controller role of
antikythera's `.kiro/specs/block-volume-service/` (the volume master,
leases, keys and snapshots), whose rules are specified by code in
antikythera's `ak_hold_master`.

It follows Clark's rules of 2026-11-17 for new Kythira services:

- **Independent layers** (`.kiro/specs/kinesis-independent-layers/`):
  each layer can run as its own process or cluster, co-located operation
  is the default and is never required, and a running deployment can
  migrate from co-located to independent and back. This service is
  layered from the start and reuses that spec's shared core pieces.
- **Migration tests**: tasks that test every migration path, both ways.
- **Interoperability**: tasks that test interoperability with real
  Amazon EC2 as far as AWS allows.

It follows the module conventions of the DynamoDB, KMS, S3 and SQS specs
(opt-in module, pinned botocore model with a coverage test, compatibility
profile, SigV4 and IAM, the shared `kms_key_provider`).

There is no EC2 service in the tree today. Kythira's EC2 code is client
side only (quorum management and peer discovery against real AWS).

### Layers

1. **Gateway**: the EC2 query protocol (`Action=…&Version=2016-11-15`,
   form-encoded, XML answers), TLS, request limits, SigV4.
2. **Front end**: authorization (IAM, EC2's per-resource checks and
   condition keys), validation, `DryRun`, idempotency tokens, filters and
   pagination for `Describe*`, throttling.
3. **Data**: the multi-Raft host and the EC2 state machines on the
   persistent `kv_engine`: the regional catalog and identifier
   allocators, instances, volumes and the volume master, snapshots,
   images, VPCs, subnets and network interfaces, server records,
   placement, per-server command outboxes, and the leader-side workers
   that run each multi-step operation.
4. **Fleet**: the controller side of antikythera's management link. It
   terminates helm's mTLS connections, delivers committed envelopes and
   frames in order, relays reports and lease requests to the data layer,
   and answers lease grants. It holds no signing key and no durable
   state.

### What this spec does not cover

- Antikythera's own wire formats, hull, helm and the oars. They are
  specified in antikythera; this module consumes its `src/proto/` codecs
  and test vectors.
- Security groups, Elastic IPs, internet and NAT gateways, routes to
  anything but a network interface, Spot, Auto Scaling, load balancers,
  placement groups and dedicated hosts. They are refused (Requirement 14) until antikythera
  backs them.
- Prices. Usage is metered and exported (Requirement 12); prices are
  billing configuration.

## Glossary

The Kinesis independent-layers glossary applies, with the fleet role
added to the layers. In addition:

- **Pinned model**: the botocore `ec2` `service-2.json` at a pinned
  version.
- **Server**: one antikythera server, known by its helm's `server_id`
  and its inventory.
- **Envelope**: a signed mailbox slot image addressed to one server's
  hull (controller-interface Requirement 1).
- **Frame**: a signed, versioned, per-server snapshot sent on the link
  other than an envelope: `MapUpdate`, `VpcConfig`, `GroupPolicy`,
  `TunnelPeers`, `ReplicaConfig`; and the unsigned `VolumeOp`, `VolumeKey`,
  `lease_grant` and `role_certificate` records.
- **Outbox**: a server's committed, ordered list of envelopes and frames
  not yet acknowledged by that server's reports.
- **Workflow**: a multi-step EC2 operation (for example `RunInstances`)
  recorded as committed steps and run by a leader-side worker, with
  compensation steps for failure.
- **Volume master**: the controller's volume state machine
  (block-volume-service design "Controller reference model"), ported
  from or linked to antikythera's `ak_hold_master`.
- **Lineage**: a network volume, its snapshots, restores and clones,
  which share one data key.
- **Backend**: what the data layer drives: `antikythera` (real helm
  links) or `simulated` (an in-process fleet of fake servers that speak
  the same link protocol).

## Requirements

### Requirement 1: Opt-in module

#### Acceptance Criteria

1. The service SHALL live under `services/ec2/`, be built only with a
   Kconfig option `EC2` (default off), include only core public headers,
   and leave every existing target unchanged when off.
2. It SHALL be a service module with module number 11, runnable in
   `kythira_node` and as a stand-alone `ec2_node`.
3. A path-filtered `.github/workflows/ec2-module.yml` SHALL build and test
   it under Docker and rootless Podman.
4. Antikythera's `src/proto/` codecs SHALL be consumed as a pinned,
   header-only dependency (an overlay port, listed in `DEPENDENCIES.md`),
   and the module's tests SHALL reproduce antikythera's
   `src/proto/test_vectors.hpp` byte for byte.

### Requirement 2: Coverage and compatibility

#### Acceptance Criteria

1. Every operation in the pinned model SHALL be implemented or listed in
   `services/ec2/doc/unsupported.md` with its error; a generated test SHALL
   fail on an operation that is neither.
2. The `aws` profile SHALL be the default and reproduce EC2's
   identifiers, states, limits and error codes for every implemented
   operation.
3. Switches settable per cluster and per account: instance and vCPU
   quotas, volume count and capacity quotas, snapshot quotas, the
   terminated-instance retention for `Describe*` (one hour), the
   idempotency token retention, and request throttling (on by default,
   as for every Kythira service).
4. Instance types SHALL come from a configured catalog that maps each
   type name to whole cores, 1 GiB pages, and device functions by type;
   the default catalog SHALL name Kythira types, and an operator MAY alias
   AWS type names so tools that hard-code them run unchanged.
   `DescribeInstanceTypes` SHALL be served from it.

### Requirement 3: Protocol and authentication

#### Acceptance Criteria

1. The gateway SHALL accept the EC2 query protocol over HTTPS (POST
   form bodies and GET query strings), with EC2's list flattening
   (`Name.N`, `Name.N.Member`), and answer with EC2's XML documents
   (`<ActionResponse>` with `requestId`, lists as `<item>`) and EC2's
   error shape (`<Response><Errors><Error>…</Errors><RequestID>`), through
   a core `aws_ec2_protocol.hpp` built beside `aws_query_protocol.hpp`.
2. Every request SHALL be authenticated with SigV4 through core
   `sigv4_verifier`.
3. Authorization SHALL go through `aws_request_authorizer` with an `ec2`
   action table that names, per action, every resource EC2 authorizes
   (for `RunInstances`: the instance, image, subnet, network interfaces,
   volumes and key pair), with EC2's condition keys (`ec2:ResourceTag/*`,
   `aws:RequestTag/*`, `ec2:InstanceType`, `ec2:Encrypted`,
   `ec2:VolumeType` and the others the model's actions use), and
   `iam:PassRole` for instance profiles. Static keys without IAM SHALL
   work as for the other modules.
4. `DryRun` SHALL answer `DryRunOperation` when authorization and
   validation pass and `UnauthorizedOperation` when authorization fails,
   changing nothing.
5. `UnauthorizedOperation` messages SHALL carry an encoded authorization
   message that `sts:DecodeAuthorizationMessage` on Kythira's IAM module
   decodes.

### Requirement 4: Identifiers, idempotency and tags

#### Acceptance Criteria

1. Instance, volume, snapshot, image, VPC, subnet, route-table and
   network-interface IDs, and the IDs of route-table and CIDR-block
   associations, SHALL be allocated by the data layer, unique across the
   region and never reused, in EC2's shapes (`i-`, `vol-`, `snap-`,
   `ami-`, `vpc-`, `subnet-`, `rtb-`, `eni-`, `rtbassoc-`,
   `vpc-cidr-assoc-`, `subnet-cidr-assoc-` followed by 17 lower-case hex
   digits), each a reversible encoding of the 64-bit identifier
   antikythera carries (controller-interface Requirement 4.1). The
   rendering SHALL be antikythera's `proto::ec2_id` and `parse_ec2_id`
   (`src/proto/ec2_id.hpp`), so a subnet ID reads the same in the API and
   in the instance metadata service.
2. VNIs SHALL be allocated per VPC from the 24-bit space, never reused;
   MAC addresses SHALL be allocated from a configured locally
   administered range and never reused (controller-interface
   Requirement 4.2).
3. `ClientToken` SHALL make `RunInstances`, `CreateVolume`,
   `CreateSnapshot`, `CreateVpc`, `CreateNetworkInterface` and the other
   operations the model gives one idempotent as EC2 documents, across
   leader changes and front-end failover: a retry with the same token and
   parameters SHALL return the original result, and with other
   parameters `IdempotentParameterMismatch`.
4. Tags (`CreateTags`, `DeleteTags`, `DescribeTags`, `TagSpecifications`
   on create) SHALL behave as EC2, with EC2's limits, and SHALL be usable
   in filters and IAM conditions.
5. Every `Describe*` operation SHALL support the filters, ID lists,
   `MaxResults` and sealed `NextToken` values EC2 documents for it, with
   one consistent read per page.

### Requirement 5: Servers, the link and inventory

**User Story:** As the operator, I want antikythera servers to register
with the controller and stay reconciled with it, whatever happens to the
link.

#### Acceptance Criteria

1. The fleet layer SHALL serve antikythera's management link
   (controller-interface Requirement 2, design "Link framing"): TLS 1.3
   only, mutual authentication with a server certificate issued by
   Kythira's certificate authority, and the `hello` → reports → inventory
   sequence helm sends on every connection.
2. A server SHALL be known by its `server_id`, which its certificate
   SHALL name; a connection whose `hello` names another server SHALL be
   closed.
3. The data layer SHALL keep, per server, the newest inventory and every
   report since, deduplicated by `(boot_id, report_seq)`, and SHALL
   acknowledge reports only after they are committed, so a fleet node
   crash never loses a report helm has forgotten.
4. The controller SHALL treat a server as authoritative only for state it
   reported, and SHALL reconcile its records with each new inventory:
   VMs, functions, local volumes and applied mapping versions the server
   no longer reports SHALL be repaired or reported as faults, never
   assumed (controller-interface Requirement 3.3).
5. Per-server command sequence numbers SHALL be committed before an
   envelope is signed, strictly increasing, and SHALL resume after a
   leader change or reconnect from the larger of the committed number
   and the server's reported `last_command_seq`.
6. Losing a link SHALL change nothing on the server, and a server whose
   link is down SHALL keep its instances `running` with status checks
   `insufficient-data` until it reconnects or the operator declares it
   lost.
7. Storage-role enrollment SHALL be served: `cert_request` reports SHALL
   be answered with `role_certificate` records signed by the storage CA,
   naming only the reporting server and, for a hold role, its storage
   endpoints' addresses (block-volume-service design "VolumeKey");
   `enrollment` reports SHALL record each helm's secure-element transport
   key.

### Requirement 6: Signing

#### Acceptance Criteria

1. Envelopes, `MapUpdate`, `VpcConfig`, `GroupPolicy`, `TunnelPeers`
   and `ReplicaConfig` frames SHALL be signed with Ed25519 over exactly the
   bytes antikythera verifies, by a key held in Kythira KMS
   (`ECC_NIST_EDWARDS25519`, `Sign` with `ED25519_SHA_512`) or in the
   virtual HSM, never in the EC2 module's memory or state.
2. Each frame SHALL carry the signing key's `key_id`; the key table SHALL
   support rotation by adding a key, moving signing to it, and retiring
   the old one only after every server's hull and roles accept the new
   one.
3. Only the data layer SHALL sign. A signed frame SHALL be committed to
   the target server's outbox before any fleet node sends it, so a resend
   after a crash or reconnect is the same bytes.
4. Fleet nodes SHALL hold no signing rights: a compromised fleet node
   SHALL be able to delay, drop or reorder what it relays, never forge a
   command.

### Requirement 7: Instances

#### Acceptance Criteria

1. `RunInstances` SHALL place each instance, create its root volume from
   the image, create the VM, attach its volumes and attach a NIC per
   network interface, in controller-interface Requirement 6.1's order,
   each step acknowledged by the server's outcome report before the next;
   a failed step SHALL run the compensation steps in reverse order and
   leave the instance `terminated` with EC2's state reason.
2. `MinCount` and `MaxCount` SHALL be honoured as EC2 honours them: the
   call fails with `InsufficientInstanceCapacity` when fewer than
   `MinCount` can be placed, and launches as many as fit up to `MaxCount`
   otherwise.
3. `TerminateInstances` SHALL send `DESTROY_VM` with `persist_volumes`
   set from each volume's `DeleteOnTermination`, delete the volumes that
   carry it and leave the rest `available`.
4. `StopInstances` SHALL send `DESTROY_VM {persist_volumes = true}` and
   retire every network-volume attachment's generation before the
   instance can start anywhere else; `StartInstances` SHALL place the
   instance on any server with capacity, unless it has a local
   (instance-store) volume, which SHALL pin it to that volume's server.
5. Instance states (`pending`, `running`, `stopping`, `stopped`,
   `shutting-down`, `terminated`), state transition reasons and
   `DescribeInstanceStatus`'s system and instance checks SHALL be derived
   from committed workflow steps and server reports.
6. A VM exit the controller did not cause (`vm_exited`) SHALL move the
   instance as EC2 would for the exit reason: a guest power-off to
   `stopped` (or `terminated` with
   `InstanceInitiatedShutdownBehavior = terminate`), a host fault to
   `stopped` with `Server.InternalError`.
7. `DescribeInstances` SHALL be served from controller state, with
   reservations, block-device mappings, network interfaces, private
   addresses, placement and tags as EC2 shapes them.
8. `ModifyInstanceAttribute` and `DescribeInstanceAttribute` SHALL serve
   at least instance type (stopped instances only), user data,
   `DisableApiTermination`, `DisableApiStop` and
   `InstanceInitiatedShutdownBehavior`.

### Requirement 8: Images

#### Acceptance Criteria

1. `RegisterImage` SHALL register an image whose root is a snapshot
   (`BlockDeviceMapping` with `SnapshotId`) or a plaintext image manifest
   in S3-compatible storage (antikythera's image format v2, named by
   `ImageLocation`), with its architecture, boot mode and block-device
   mappings.
2. `CreateImage` SHALL take a multi-volume snapshot of an instance's
   network volumes and register an image from it; `NoReboot` SHALL be
   honoured as a crash-consistent cut.
3. `DescribeImages` (owners, executable users, filters),
   `DeregisterImage`, and `ModifyImageAttribute` launch permissions within
   the cluster SHALL behave as EC2.
4. Images SHALL be stored in the S3-compatible store the operator
   configures: Kythira S3 when built, or any S3 endpoint.

### Requirement 9: Network volumes (EBS)

**User Story:** As a Kythira user, I want EBS calls to drive
antikythera's replicated network volumes with EBS's parameters, states
and errors (controller-interface Requirement 9).

#### Acceptance Criteria

1. `CreateVolume`, `DeleteVolume`, `AttachVolume`, `DetachVolume`,
   `ModifyVolume`, `DescribeVolumes`, `DescribeVolumeStatus`,
   `DescribeVolumesModifications`, `EnableVolumeIO`,
   `ModifyVolumeAttribute`, `DescribeVolumeAttribute`, `CreateSnapshot`,
   `CreateSnapshots`, `DeleteSnapshot`, `DescribeSnapshots`,
   `EnableFastSnapshotRestores`, `DisableFastSnapshotRestores`,
   `DescribeFastSnapshotRestores` and `CopyVolumes` SHALL behave as
   controller-interface Requirement 9.1-9.8 states, with the parameter,
   volume-state, attachment-state and status-check tables of its design
   "Network volumes in EC2".
2. `RunInstances` `Ebs` block-device mappings SHALL create and attach one
   network volume each, honouring `DeleteOnTermination` (default true for
   the root from the image); `VirtualName` `ephemeralN` mappings SHALL
   create local volumes, the instance-store analogue, sized by the
   instance type (controller-interface Requirement 6.2).
3. The data layer SHALL own every network volume's replica set as the
   volume master: placement in distinct failure domains, epochs,
   attachment generations, leases, failure handling, rebuild, moves,
   snapshot cuts, garbage collection and lineage erasure, following
   `ak_hold_master`'s rules (block-volume-service Requirements 5-8,
   11-12).
4. Every change to a volume's ReplicaConfig SHALL be committed through
   Raft before any member or initiator sees it, and every epoch SHALL be
   strictly greater than every epoch published before it, across leader
   changes.
5. A primary's lease SHALL be granted only by the leader of the volume's
   group, measured from its own monotonic clock; a new leader SHALL grant
   nothing it cannot back and SHALL promote no other replica until
   `lease_ms × 1.1` after it took leadership, so no two primaries can
   serve reads at once across a leader change.
6. Snapshot data SHALL be stored in the configured S3-compatible store in
   antikythera's image format v2; the controller SHALL keep the mapping
   from snapshot ID to manifest.
7. Volume operations with no backing SHALL be refused as
   controller-interface Requirement 9.10 lists.
8. A volume restored with oar-blk hydration (a root volume from an image
   at `RunInstances`, or a volume whose source is re-keyed) SHALL be
   attachable at once. The controller SHALL record each replica's
   `total_bytes` and `hydrated_bytes` from `replica_status`, SHALL treat
   the volume as hydrated only when every in-sync replica at the current
   epoch reports the two equal, and SHALL commit that once, never
   clearing it. Until then a fast-restored volume SHALL stay `creating`,
   any other SHALL report `DescribeVolumeStatus` `warning` with
   `InitializationStatusDetails` `Progress` from the least-hydrated
   in-sync replica (controller-interface design "Network volumes in
   EC2").
9. A stopped instance's local volume SHALL be convertible into a network
   volume, and a network volume into a local one, through an admin call
   (EC2 has no action for it), as a volume workflow
   (block-volume-service Requirement 8.6, controller-interface design
   `CONVERT_VOLUME`): the controller SHALL create the target and the
   utility attachment, SHALL wait for a restored network source to be
   hydrated (9.8), SHALL send `CONVERT_VOLUME` and follow
   `conversion_progress` to `completed` or `failed`, and SHALL then
   switch the instance's records to the new volume and delete the old
   one, or delete the target, retiring the utility attachment either way.

### Requirement 10: Keys and encryption

#### Acceptance Criteria

1. Every network volume SHALL be encrypted and report `Encrypted = true`;
   each lineage SHALL have its own non-exportable Kythira KMS key and a
   data key generated under it, of which the controller stores only the
   wrapped blob.
2. At attach the controller SHALL obtain a `VolumeKey` from Kythira KMS:
   the data key opened by KMS and sealed with HPKE (RFC 9180,
   DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, info
   `"antikythera volume key v1"`) to the attaching helm's enrolled
   transport key, with the frame's other fields as associated data. The
   controller SHALL never hold the plaintext data key.
3. Kythira KMS SHALL gain the recipient operation this needs, as a
   Kythira extension of `Decrypt`'s `Recipient` parameter (an X25519
   public key and the associated data in place of a Nitro attestation
   document), usable only by the EC2 service principal and only with
   the lineage's encryption context.
4. IF `KmsKeyId` names a tenant key THEN the lineage's wrapped data key
   SHALL additionally be encrypted under that key, through a grant the
   controller creates on it at `CreateVolume` as EBS does, so disabling
   the tenant key or revoking the grant makes every volume of the
   lineage unattachable (controller-interface Requirement 6.3).
5. When a lineage's last volume and snapshot are gone, its KMS key SHALL
   be scheduled for deletion with the shortest window the KMS module
   allows (block-volume-service Requirement 12.4).
6. `EnableEbsEncryptionByDefault`, `GetEbsEncryptionByDefault`,
   `ModifyEbsDefaultKmsKeyId` and `GetEbsDefaultKmsKeyId` SHALL be served;
   encryption cannot be turned off, so the default always reads `true`.

### Requirement 11: VPCs, subnets, route tables and network interfaces

**User Story:** As a Kythira user, I want EC2's VPC model: address
blocks, subnets cut from them, route tables that join the subnets or
send traffic through an appliance, and interfaces placed in a subnet
(antikythera vpc-subnets-routing Requirements 1, 2, 4 and 7).

#### Acceptance Criteria

1. `CreateVpc` and `DeleteVpc` SHALL allocate and release a VNI and send
   `CREATE_NETWORK` and `DELETE_NETWORK` where needed; `DeleteVpc` SHALL
   be refused with `DependencyViolation` while the VPC has subnets,
   interfaces or route tables other than its main one.
2. A VPC SHALL have a primary IPv4 CIDR block from /16 to /28, up to
   four secondary IPv4 blocks (`AssociateVpcCidrBlock`,
   `DisassociateVpcCidrBlock`), none overlapping, and at most one IPv6
   /56 from the region's pool. A block SHALL NOT be disassociated while
   a subnet uses it, refused with EC2's error for a block in use.
3. A VPC SHALL have at most 200 subnets. A subnet's IPv4 prefix, from
   /16 to /28, SHALL lie inside one of the VPC's IPv4 blocks, and its
   optional IPv6 /64 (`AssociateSubnetCidrBlock`,
   `DisassociateSubnetCidrBlock`) inside the VPC's /56; no two subnets
   of a VPC SHALL overlap in either family. `DeleteSubnet` SHALL be
   refused with `DependencyViolation` while the subnet holds an
   interface, and `ModifySubnetAttribute` SHALL accept the attributes
   antikythera backs (`AssignIpv6AddressOnCreation`) and refuse the rest
   with `UnsupportedOperation`.
4. In every subnet the controller SHALL reserve the network address,
   the next three (the gateway at base + 1, the DNS resolver at
   base + 2, and base + 3) and the IPv4 broadcast address, and SHALL
   allocate interface addresses from the subnet's prefixes outside them.
5. Each account SHALL get a default VPC and subnet on first use
   (`CreateDefaultVpc` also), so `RunInstances` without a subnet works as
   on EC2.
6. A VPC SHALL have one main route table, created with it, and at most
   200 tables in all (`CreateRouteTable`, `DeleteRouteTable`,
   `DescribeRouteTables`). A subnet SHALL be associated with at most one
   table (`AssociateRouteTable`, `DisassociateRouteTable`, and
   `ReplaceRouteTableAssociation`, which also moves the main
   association) and uses the main table without one. `DeleteRouteTable`
   SHALL be refused with `DependencyViolation` for the main table or a
   table with associations.
7. Every table SHALL hold one `local` route per VPC CIDR block, added
   and removed with the block, which `CreateRoute`, `ReplaceRoute` and
   `DeleteRoute` SHALL NOT change. Those calls SHALL accept routes whose
   target is a network interface in the VPC (`NetworkInterfaceId`, or
   `InstanceId` for an instance with one interface), at most 1,000 per
   table and 4,096 across the VPC's tables (the `VpcConfig` frame's
   bound; beyond either, `RouteLimitExceeded`), with any destination
   prefix: a default route, or a prefix
   inside a VPC block longer than its `local` route (middlebox routing).
   A route with exactly a `local` route's prefix SHALL be refused.
8. `DescribeRouteTables` SHALL report a network-interface route as
   `blackhole` while its target interface is detached or deleted, and
   `active` otherwise; the route stays until it is deleted.
9. `CreateNetworkInterface`, `DeleteNetworkInterface`,
   `AttachNetworkInterface`, `DetachNetworkInterface` and
   `DescribeNetworkInterfaces` SHALL allocate NIC IDs, MACs and addresses
   in the interface's subnet, send `ATTACH_DEVICE` and `DETACH_DEVICE`,
   and send the VPC's new `MapUpdate` (version 4, naming each NIC's
   subnet) to every server hosting a NIC in it.
10. The VPC's blocks, subnets, route tables, routes and associations
    SHALL be sent as one signed `VpcConfig` version 2 frame, with its own
    committed version, to every server hosting a NIC in the VPC whenever
    any of them changes, so each change takes effect atomically on each
    server. A new subnet's configuration SHALL be sent before the first
    `MapUpdate` that places a NIC in it (antikythera fails closed in the
    other order, vpc-subnets-routing Requirement 2.6).
11. `MapUpdate` versions SHALL be committed per VPC, and a VPC SHALL be
    reported converged only when every member server has reported
    `map_applied` for the newest version (controller-interface
    Requirement 5.3).
12. `TunnelPeers` frames SHALL be sent to every VTEP whose peer set or
    peer keys change, choosing WireGuard for every pair until both ends
    advertise another mode (controller-interface Requirement 8).
13. `DescribeVpcs`, `DescribeSubnets`, `DescribeRouteTables`,
    `DescribeAvailabilityZones` (one zone) and `DescribeRegions` (one
    region) SHALL be served from controller state.

### Requirement 12: Multicast policy, admission and metering

**User Story:** As a Kythira user, I want to turn multicast on for a
subnet and see what it costs; as the operator, I want to charge for it
and keep it from being abused (controller-interface Requirement 7).

#### Acceptance Criteria

1. The controller SHALL record a per-subnet multicast setting (applied
   to the whole VPC until antikythera's `GroupPolicy` version 2 carries
   one entry per subnet, vpc-subnets-routing task 12) with its limits, bounded by
   region-wide defaults and maxima, and SHALL expose it through tags with
   the reserved prefix `kythira:multicast:` on the subnet, validated on
   `CreateTags` and refused with `InvalidParameterValue` out of bounds.
2. The controller SHALL send the setting as a signed, versioned
   `GroupPolicy` frame to every server hosting a NIC in the VNI, and
   SHALL not let the first NIC of an opted-in subnet send before its
   server has applied it.
3. Turning multicast on for a subnet that spans more servers than its
   flood-list cap, and a placement that would push an opted-in subnet
   past it, SHALL be refused with a clear error.
4. `group_usage` readings SHALL become per-attachment deltas, keyed by
   `(server_id, boot_id, slot, nic_id, attachment)`, attributed to the
   NIC's account; a reading lower than the previous one SHALL be recorded
   as a fault and never billed negatively.
5. Billable usage (remote replica bytes and frames, and enablement time
   per opted-in subnet) SHALL be exported per account and hour to the
   configured S3-compatible store and as Prometheus metrics.

### Requirement 13: Instance metadata

#### Acceptance Criteria

1. The controller SHALL keep, per instance, what the instance metadata
   service serves: instance identity (and its signed identity document),
   placement, network interfaces and addresses, block-device mapping,
   user data, the key pair's public key, tags when allowed, and instance
   profile credentials issued through Kythira's STS.
2. It SHALL hand those records to the server hosting the instance, keyed
   by NIC ID, over the link (a record type to be added to antikythera's
   controller-interface spec), for helm's IMDSv2 service behind oar-net's
   metadata intercept (oar-net Requirement 13).
3. `ImportKeyPair`, `CreateKeyPair`, `DescribeKeyPairs` and
   `DeleteKeyPair` SHALL be served; private keys made by `CreateKeyPair`
   SHALL be returned once and never stored.

### Requirement 14: Refusals

#### Acceptance Criteria

1. Features with no backing yet SHALL be refused with
   `UnsupportedOperation`, never silently accepted: security groups
   (`CreateSecurityGroup`, and `SecurityGroupIds` on launch or on an
   interface), routes to targets other than a network interface
   (`GatewayId`, `NatGatewayId`, `VpcPeeringConnectionId`,
   `TransitGatewayId`, `VpcEndpointId`, `EgressOnlyInternetGatewayId` and
   the rest), Elastic IPs, internet, NAT and transit gateways, Spot, placement groups, dedicated hosts,
   `RebootInstances` until hull has a reset command, and the EBS
   features of controller-interface Requirement 9.10.
2. Read-only calls for refused features (`DescribeSecurityGroups`,
   `DescribeAddresses`, `DescribeInternetGateways` and the like) SHALL
   answer empty lists, so tools that list before they act keep working.

### Requirement 15: Independent layers

**User Story:** As an operator, I want each layer runnable on its own,
and co-located by default.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_EC2_ROLES`, a non-empty
   subset of `gateway`, `front_end`, `data`, `fleet`; default all four.
   No deployment SHALL require a split.
2. Handlers SHALL reach the data layer only through a value-returning
   interface with local, remote and hybrid implementations, chosen per
   call; the route cache SHALL find each resource's group.
3. The gateway SHALL verify SigV4 and hand front ends an authenticated
   call; internal calls SHALL use layer identities with `ec2` as the
   service and per-route role checks.
4. Fleet nodes SHALL reach the data layer through the same interface: an
   outbox stream per server (in order, from a given position), report
   submission, and lease-request forwarding to the volume group's leader.
5. Workflows, the volume master, rebuild and garbage-collection workers,
   and KMS and signing calls SHALL run on data-node leaders only.
6. A co-located node SHALL serve local operations, outbox delivery and
   lease forwarding in-process.
7. The backend SHALL be selectable (`antikythera` or `simulated`)
   independently of the layout.

### Requirement 16: Live migration

#### Acceptance Criteria

1. Stateless roles (gateway, front end) SHALL move with a drain and a
   restart, finishing or failing each request with a retryable error.
2. The fleet role SHALL move with a drain that closes each helm
   connection so helm reconnects to another fleet node; the data layer
   SHALL count a drained server's silence from its reconnection deadline,
   not from the drain, so a planned fleet move never triggers volume
   failover, a lease loss or a lost-server decision.
3. The data role SHALL move through learner, promote, leadership transfer
   and remove, and an `evacuate` admin call.
4. During a migration no acknowledged EC2 change SHALL be lost, no
   workflow SHALL run a step twice with a different result or stop
   without finishing or compensating, no command sequence number SHALL
   be reused, no epoch SHALL go backwards, no two primaries of a volume
   SHALL hold leases at once, and running instances and attached volumes
   SHALL keep serving.

### Requirement 17: Testing and conformance

#### Acceptance Criteria

1. Unit, property and in-process cluster tests SHALL cover identifier
   allocation, idempotency, every workflow and its compensation, outbox
   ordering and resend, sequence and epoch monotonicity, leases across
   leader changes, report deduplication and reconciliation, with leader
   changes and fleet reconnects injected at every step.
2. The simulated backend SHALL speak the real link protocol with
   antikythera's codecs, and SHALL be able to fail any command, drop any
   report, lose a server and partition a server from the controller.
3. The AWS CLI, boto3, aws-sdk-java-v2, aws-sdk-go-v2, aws-sdk-js-v3,
   Terraform's AWS provider (`aws_instance`, `aws_ebs_volume`,
   `aws_volume_attachment`, `aws_vpc`, `aws_network_interface`) and
   Kythira's own `aws_ec2_quorum_manager` and `aws_ec2_peer_discovery`
   SHALL run in CI against the simulated backend, co-located and split.
4. Every migration path SHALL have its own test in both directions:
   gateway role, front-end role, fleet role (with reports and lease
   requests in flight), data role (with workflows in flight), and the
   whole co-located to split path and back with a stop and reversal
   midway, under a launch, attach, snapshot and terminate load, checking
   Requirement 16.4; and a docker-chaos run of the full path killing one
   node per layer, on Docker and rootless Podman.
5. Interoperability with real Amazon EC2 SHALL be tested as far as AWS
   allows: recorded EC2 responses replayed in CI as differential fixtures
   (shapes, errors and pagination); and a dispatch-only real-cloud bundle
   that runs the same client and Terraform suites against EC2 and Kythira
   and compares what the clients observe. Each run needs Clark's go in
   his own words, reports its cost and deletes what it made.
6. End to end on antikythera: the AWS CLI's `run-instances` against
   Kythira SHALL land an instance in a harbor server, boot from a network
   volume, attach and detach a second volume, stop, start on another
   server and terminate (antikythera controller-interface task 7); runs on
   tikhov need Clark's go.
7. A measurement row SHALL record launch latency (API call to `running`)
   and control-plane throughput, co-located and split.

### Requirement 18: Documentation

#### Acceptance Criteria

1. `services/ec2/doc/` SHALL cover configuration, the layers and sizing,
   the link and its certificates, signing keys and rotation, instance
   types, images, volumes and keys, the refusals, metering exports and
   the migration runbook.
