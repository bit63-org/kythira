# Implementation Plan

Depends on IAM (SigV4, authorizer), service colocation (module
interface), KMS (BMC credential encryption), the certificate authority
(issuance, CRL), and the shared core pieces of
`.kiro/specs/kinesis-independent-layers/`. Integrates with the EC2
module (placement exclusion, scheduled events), khold (`evacuate`) and S3
(re-placement). On the antikythera side it pairs with
`.kiro/specs/server-provisioning/` in `bit63-org/antikythera`. Each task
is one PR unless noted.

- [ ] 1. Module skeleton
  - `METAL` Kconfig option, `services/metal/`, module number 13 in
    `module_numbers`, boundary list, `configs/ci_no_metal_defconfig`,
    `metal-module.yml` (Docker and rootless Podman)
  - _Requirements: 15.1_

- [ ] 2. Host registry state machine
  - Host, image, boot-node and unclaimed records; allowed transitions;
    `host_id` allocator that never reuses; event history; tombstones
  - Property tests over every transition with leader changes
  - _Requirements: 1.1-1.6_

- [ ] 3. Admin API, action table and CLI
  - JSON over HTTPS, SigV4, `metal:` actions, client tokens, every call
    of Requirement 2.2 against the registry; `kythira-metal` CLI
  - BMC credentials encrypted with KMS, never returned or logged
  - _Requirements: 2.1-2.5_

- [ ] 4. Workflow engine and simulated driver
  - Committed steps with idempotent side effects and step deadlines;
    the driver interface; the `simulated` driver and simulated hosts
  - Each step replayed twice in tests
  - _Requirements: 1.5, 5.1, 5.6, 5.7, 16.1, 16.3_

- [ ] 5. Boot layer: HTTPS surface and dnsmasq supervision
  - Boot scripts by host state, image cache from S3, discovery and
    report endpoints, provisioning files; dnsmasq in proxy mode with
    TFTP, configured per assigned MAC; outbound mTLS to the data layer;
    last-copy cache for Requirement 14.5; one boot node per host
  - Fuzz targets for the HTTP surface and report decoders
  - _Requirements: 4.1-4.6, 14.5, 15.2, 15.4, 16.2_

- [ ] 6. iPXE build and discovery image
  - iPXE `snponly.efi` with embedded CA and script, built reproducibly;
    a signed discovery UKI that reports hardware and powers off
  - _Requirements: 3.1-3.4, 4.2_

- [ ] 7. Kythira host image
  - Signed read-only UKI on the hull build pipeline that runs one node
    binary (khold or S3 storage) with data on local drives; init
    measures the provisioning file before reading it
  - _Requirements: 4.4, 4.6_

- [ ] 8. TPM enrollment and renewal
  - Credential activation, quote verification against per-image PCR 11
    and pinned PCRs 0, 2, 7; CSR issuance with the CA; 7-day renewal
    with a fresh quote; enrollment windows for hosts without a TPM
  - Fuzz targets for quote and CSR decoding
  - _Requirements: 6.1-6.6, 9.1-9.2, 16.2_

- [ ] 9. Checks before service
  - Self-check report, per-role minimums, `failed` with the list
  - _Requirements: 7.1-7.3_

- [ ] 10. Redfish, IPMI and manual drivers
  - Redfish with a pinned BMC certificate; `ipmitool -I lanplus -C 17`;
    manual operator tasks; recorded-exchange tests
  - _Requirements: 5.1-5.3, 5.5, 5.7, 16.5_

- [ ] 11. Joining services and drains
  - EC2: placement exclusion for non-`in_service` hosts, scheduled
    events with deadlines, stop at the deadline (EC2 module change)
  - khold `evacuate` and S3 re-placement asks with polling; refusals
    and forced drains
  - _Requirements: 8.1-8.4, 10.1-10.6_

- [ ] 12. Wipe image and retirement
  - Revoke first; one-use wipe token; per-drive key destruction, NVMe
    Sanitize / ATA Secure Erase, sanitize log read-back; TPM clear;
    retirement and power off; lost-host retirement
  - _Requirements: 11.1-11.7, 13.1-13.2_

- [ ] 13. Reprovisioning and role changes
  - _Requirements: 12.1-12.3_

- [ ] 14. Layer migrations
  - Each layer co-located to independent and back under load in Docker
    and rootless Podman, checking no lost acknowledged change and no
    repeated power action; boot node handover between two boot nodes
  - _Requirements: 14.4, 15.3_

- [ ] 14a. Seeding a new AZ or region from an existing AZ
  - An existing AZ's control plane runs a new AZ's metal data layer while
    only the boot layer runs locally; the new AZ's control plane is then
    built on its own hosts and the data layer migrated onto it
  - A region to be disconnected: control plane moved onto its own hosts,
    every host renewing against the region's own CA chain, checked
    before the link is cut; tested with two simulated AZs in Docker and
    rootless Podman, cutting the link at every step
  - _Requirements: 14.1-14.4_

- [ ] 15. QEMU end to end
  - OVMF with Secure Boot, `swtpm`, bridge in a network namespace,
    dnsmasq-backed boot node: discover, register, provision, enroll,
    drain, wipe and retire a storage host and a diskless host
  - _Requirements: 16.4_

- [ ] 16. Helm driver and antikythera hosts
  - The `helm` driver over the EC2 fleet link; enrollment through helm;
    end to end in harbor on tikhov on Clark's go
  - _Requirements: 5.4, 6.3_

- [ ] 17. Real hardware run
  - One Redfish host through the whole lifecycle on Clark's go
  - _Requirements: 16.5_
