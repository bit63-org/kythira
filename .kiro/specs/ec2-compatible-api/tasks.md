# Implementation Plan

Depends on IAM (SigV4, authorizer, STS), service colocation (module
interface), the KMS module (signing keys, per-lineage keys, the recipient
extension of task 8), multi-raft transactions (placement and cross-group
workflow steps), and the shared core pieces of
`.kiro/specs/kinesis-independent-layers/` (a task that needs one first
builds it to that design). On the antikythera side it consumes
`src/proto/` and `ak_hold_master` from `bit63-org/antikythera`, and
unblocks that repository's controller-interface tasks 7 and 12. Each task
is one PR unless noted.

- [ ] 1. Module skeleton and evidence
  - `EC2` Kconfig option, `services/ec2/`, module number 11 in
    `module_numbers`, boundary list, `configs/ci_no_ec2_defconfig`,
    `ec2-module.yml` (Docker and rootless Podman)
  - Pinned botocore `ec2` model, generated operation table with its
    `--check` test, coverage test with every operation listed in
    `services/ec2/doc/unsupported.md` against its task
  - Overlay port for antikythera's header-only `src/proto/` at a pinned
    commit, in `DEPENDENCIES.md`; a test that reproduces
    `src/proto/test_vectors.hpp` byte for byte
  - Recorded wire evidence (AWS CLI v2, boto3, aws-sdk-java-v2,
    aws-sdk-go-v2, aws-sdk-js-v3, Terraform's AWS provider) from a
    recording stub
  - _Requirements: 1.1-1.4, 2.1_

- [ ] 2. EC2 query protocol codec
  - Core `aws_ec2_protocol.hpp`: `Name.N` flattening, EC2 response and
    error documents, reusing the query codec's form decoder, XML writer
    and marker sealer; unit tests against the recorded evidence and a
    fuzz target
  - _Requirements: 3.1_

- [ ] 3. Gateway, authorization and profile
  - SigV4; `ec2` action table with every resource and condition key per
    action from the IAM service reference; `iam:PassRole` for instance
    profiles; static keys; `DryRun`; encoded authorization messages that
    Kythira STS decodes; the `aws` profile, quotas and throttling
  - _Requirements: 2.2, 2.3, 3.2-3.5_

- [ ] 4. Catalog, identifiers, idempotency, tags and describes
  - Catalog group: per-kind ID counters with block allocation, EC2 ID
    encoding, VNI and MAC counters, the instance-type catalog and
    `DescribeInstanceTypes`, `DescribeRegions`,
    `DescribeAvailabilityZones`
  - `ClientToken` index with `IdempotentParameterMismatch`
  - Tags, `TagSpecifications`, the filter engine and sealed `NextToken`
    pagination shared by every `Describe*`
  - Property tests: IDs never reused across leader changes and group
    splits; a retried token returns the original result
  - _Requirements: 2.4, 4.1-4.5_

- [ ] 5. Fleet layer, server records and the simulated backend
  - Link server over core TLS (TLS 1.3, client certificates from Kythira's
    CA naming the `server_id`), antikythera link framing, `hello`,
    reports, acks after commit, `(boot_id, report_seq)` dedup
  - Server group: inventory, reconciliation, silence clocks, the
    server-lost decision (operator-confirmed by default)
  - Storage-role enrollment: `cert_request` → `role_certificate` from the
    storage CA; `enrollment` transport keys recorded
  - `ec2_sim_fleet`: fake helms that speak the link with antikythera's
    codecs, run commands against a model of hull and the roles, and can
    fail commands, drop reports, lose and partition servers
  - _Requirements: 5.1-5.4, 5.6, 5.7, 15.7, 17.2_

- [ ] 6. Signing and outboxes
  - Ed25519 through Kythira KMS (`ECC_NIST_EDWARDS25519`) or the virtual
    HSM; the signing key table, `key_id`s and a rotation procedure
  - Per-server sequence numbers committed with the recorded command
    before signing; re-signing after a leader change
  - Per-server outbox: envelopes in order, frames newest-per-key, trimmed
    by outcome and applied reports; fleet streams from a position
  - Tests: signatures verify with antikythera's verifier; a fleet node
    with no KMS rights can relay but never produce an accepted command;
    no sequence hole or reuse under injected leader changes
  - _Requirements: 5.5, 6.1-6.4_

- [ ] 7. Workflows and placement
  - Workflow records, the leader-side worker, idempotent steps,
    compensation in reverse; cross-group steps as tier-1 transactions
  - Server reservations and the first placement policy; `MinCount` /
    `MaxCount`; `InsufficientInstanceCapacity`
  - Property tests: every workflow finishes or compensates under leader
    changes, fleet reconnects and failed commands at every step
  - _Requirements: 7.1, 7.2, 16.4_

- [ ] 8. KMS recipient decrypt
  - In `services/kms/`: the Kythira extension of `Decrypt`'s `Recipient`
    (`KYTHIRA_HPKE_X25519_SHA256_AES256GCM`, public key, AAD), key
    policy and condition key, CFRG HPKE vectors and antikythera's
    `volume_key` vectors; documented as a Kythira extension in the KMS
    module's docs
  - _Requirements: 10.2, 10.3_

- [ ] 9. Volume master
  - Decide port versus link (design open question 1); add the
    export/restore and decisions-before-actions interface to
    `ak_hold_master` in antikythera if linking
  - `ec2_volume_master`: the master on each volume group's leader,
    decisions committed before publication, rebuild from committed state
    on leader change, the `lease_ms × 1.1` rule after taking leadership,
    lease requests from fleet nodes and grants back
  - Property tests on the simulated backend: epochs only grow; no two
    primaries hold leases across leader changes and fleet failover; a
    planned fleet drain triggers no failover
  - _Requirements: 9.3-9.5, 16.2_

- [ ] 10. VPCs, subnets, route tables and network interfaces
  - `CreateVpc` / `DeleteVpc` with VNIs and `CREATE_NETWORK` /
    `DELETE_NETWORK`; primary and secondary IPv4 blocks and one IPv6 /56
    (`AssociateVpcCidrBlock`, `DisassociateVpcCidrBlock`); default VPC
    per account and `CreateDefaultVpc`
  - Subnets, up to 200 per VPC: `CreateSubnet`, `DeleteSubnet`,
    `DescribeSubnets`, `ModifySubnetAttribute`,
    `AssociateSubnetCidrBlock` / `DisassociateSubnetCidrBlock`; overlap
    checks; address pools with the five reserved addresses
  - Route tables: the main table, `CreateRouteTable`,
    `DeleteRouteTable`, `DescribeRouteTables` (`blackhole` state),
    `AssociateRouteTable`, `DisassociateRouteTable`,
    `ReplaceRouteTableAssociation`; `local` routes per block;
    `CreateRoute`, `ReplaceRoute`, `DeleteRoute` with
    `NetworkInterfaceId` / `InstanceId` targets and the limits; other
    targets refused
  - `VpcConfig` version 2 frames with committed versions, sent before
    the `MapUpdate` that first uses a subnet; IDs rendered with
    antikythera's `proto::ec2_id`
  - Network interfaces: NIC IDs, MACs, addresses from the subnet's
    pool, `ATTACH_DEVICE` / `DETACH_DEVICE`, `MapUpdate` version 4
    (subnet per NIC) versions and convergence
  - `TunnelPeers` per VTEP on peer-set or key change
  - Tests against antikythera's codecs and test vectors: frames at the
    limits, the config-before-mapping order, a NIC route going
    `blackhole` on detach and `active` again on attach
  - _Requirements: 4.1, 11.1-11.13, 14.1_

- [ ] 11. Network volumes and keys
  - `CreateVolume`, `DeleteVolume`, `AttachVolume`, `DetachVolume`
    (cooperative, `busy`, forced with fencing), `ModifyVolume` and
    `DescribeVolumesModifications`, `DescribeVolumes`,
    `DescribeVolumeStatus`, `EnableVolumeIO`, `AutoEnableIO`, per
    antikythera's parameter and state tables
  - Per-lineage KMS keys, tenant `KmsKeyId` grants and the outer layer,
    `VolumeKey` through task 8, lineage key deletion, the EBS
    encryption-by-default calls
  - _Requirements: 9.1, 9.7, 10.1, 10.4-10.6_

- [ ] 12. Snapshots and images
  - `CreateSnapshot`, `CreateSnapshots`, `DeleteSnapshot`,
    `DescribeSnapshots`, fast snapshot restores, `CopyVolumes`; snapshot
    manifests in the configured S3-compatible store
  - `RegisterImage` (snapshot root or `ImageLocation` manifest),
    `CreateImage`, `DescribeImages`, `DeregisterImage`, launch
    permissions
  - _Requirements: 8.1-8.4, 9.1, 9.6_

- [ ] 13. Instances
  - `RunInstances` (placement, root from the image, `Ebs` and
    `ephemeralN` mappings, NICs), `TerminateInstances`, `StopInstances`,
    `StartInstances`, `DescribeInstances`, `DescribeInstanceStatus`,
    instance attributes; `vm_exited` handling; server loss
  - The refusals of Requirement 14 and the empty describes for refused
    features
  - _Requirements: 5.6, 7.1-7.8, 9.2, 14.1, 14.2_

- [ ] 13a. Hydration and local ↔ network conversion
  - Per-replica `total_bytes` / `hydrated_bytes` from `replica_status`
    in leader memory, the committed `hydrated` flag, `creating` for
    fast-restored volumes, `warning` with `InitializationStatusDetails`
    otherwise; a root volume restored from an image boots before
    hydration finishes
  - The `convert_volume` workflow of design "Restores and conversions"
    in both directions: target creation with a new lineage and the
    utility attachment, the hydration wait, `CONVERT_VOLUME`,
    `conversion_progress` to `completed` or `failed`, the record switch
    and deletes, cancellation; admin calls `convert-volume`,
    `describe-conversions` and `cancel-conversion`
  - Property tests on the simulated backend (fake helms that answer
    `CONVERT_VOLUME` and stream `conversion_progress`): leader changes
    and dropped or duplicated reports at every step, `failed` with each
    `ConversionFailure`, server loss mid-copy; each run ends with exactly
    one of the two volumes, no utility attachment, and `hydrated` never
    set before every in-sync replica reported it
  - Snapshot-sourced hydration (`CreateVolume` with `SnapshotId`) follows
    task 12; this task needs only image restores and re-keyed sources
  - _Requirements: 7.4, 9.8, 9.9_

- [ ] 14. Instance metadata and key pairs
  - Draft the metadata record type in antikythera's controller-interface
    spec first; per-instance records keyed by NIC ID, the signed identity
    document, instance profile credentials through Kythira STS
  - Key pair operations; private keys returned once
  - _Requirements: 13.1-13.3_

- [ ] 15. Multicast policy, admission and metering
  - `kythira:multicast:*` tags validated against region bounds;
    `GroupPolicy` versions per VNI applied before an opted-in NIC sends;
    flood-list admission on opt-in and on placement
  - `group_usage` deltas per series, faults on decreasing readings,
    enablement hours, hourly S3 export and Prometheus metrics
  - This is antikythera controller-interface task 12
  - _Requirements: 12.1-12.5_

- [ ] 16. Independent layers
  - `KYTHIRA_EC2_ROLES`; local, remote and hybrid data access; the
    authenticated call; layer identities with `ec2` and per-route role
    checks; outbox streams, report submission and lease forwarding over
    the data-layer API; workers on data-node leaders only; drains for
    every role, the fleet drain's silence grace included
  - _Requirements: 15.1-15.6, 16.1, 16.2_

- [ ] 17. Migration operations and path tests
  - `evacuate` for the data role
  - One test per path in both directions under a launch, attach,
    snapshot and terminate load on the simulated backend: gateway role,
    front-end role, fleet role with reports and lease requests in flight,
    data role with workflows in flight, and the whole co-located to split
    path and back with a stop and reversal midway; each checks
    Requirement 16.4
  - docker-chaos scenario of the full path killing one node per layer,
    Docker and rootless Podman, compose services addressed by name
  - _Requirements: 16.3, 16.4, 17.4_

- [ ] 18. Client suites in CI
  - CLI, boto3, the Java, Go and JavaScript SDKs, Terraform's AWS
    provider, and Kythira's `aws_ec2_quorum_manager` and
    `aws_ec2_peer_discovery` against Kythira EC2 on the simulated
    backend, co-located and split
  - _Requirements: 17.1, 17.3_

- [ ] 19. Interoperability with real Amazon EC2
  - CI (no spend): recorded EC2 responses replayed as differential
    fixtures (shapes, errors, pagination, state sequences)
  - Real-cloud bundle (dispatch-only, repo-variable switch): the client
    and Terraform suites against EC2 and Kythira compared
  - Each run needs Clark's go, reports cost, deletes what it made
  - _Requirements: 17.5_

- [ ] 20. End to end on antikythera
  - AWS CLI `run-instances` against Kythira landing in a harbor server:
    boot from a network volume, attach and detach a second volume, stop,
    start on another server, terminate (antikythera controller-interface
    task 7); harbor runs on tikhov need Clark's go
  - _Requirements: 17.6_

- [ ] 21. Measurement and documentation
  - Launch latency and control-plane throughput rows, co-located and
    split; `services/ec2/doc/`
  - _Requirements: 17.7, 18.1_
