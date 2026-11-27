# Implementation Plan

Depends on `metal-host-lifecycle` (registry, boot layer, drivers,
enrollment), the EC2 module (servers, signing, placement), khold
(attachments, fencing), the virtual HSM (node unseal), the CA, and
`ec2-controller-scale` Requirement 8 (mass-silence suspension). Pairs with
antikythera's `.kiro/specs/cold-start/`. Each task is one PR unless
noted.

- [ ] 1. Cold-start graph and CI check
  - `config/cold_start_graph.yaml` for the components that exist today
    and the planned ones marked `planned`; `tools/cold_start_graph/`
    checker (cycles, tier inversions, missing module declarations);
    CI job on every PR; rendering for the runbook
  - _Requirements: 1.1-1.5, 14.5_

- [ ] 2. Registry fields for tiers, power domains and slots
  - Tier, power domain, slot, per-domain watt budget and per-host
    inrush in the metal registry; slot assignment that respects the
    budget; policy push to helm and BMCs; settings check for BMC
    power-restore
  - _Requirements: 5.1, 5.2, 5.5, 5.6, 5.7_

- [ ] 3. Delayed power-on in the Redfish and IPMI drivers
  - Power-restore setting plus delayed power-on where the BMC offers it;
    the `simulated` driver applies the same policy
  - _Requirements: 5.3, 5.4_

- [ ] 4. LKG boot for Kythira host image hosts
  - Boot-cache partition, LKG promotion after quote and checks, keep two;
    boot LKG when unchanged or boot layer unreachable for 30 s; amend
    metal Requirement 4 in its spec
  - QEMU test: boot with the boot layer down
  - _Requirements: 4.1-4.4_

- [ ] 5. Pinned instances and standing sets in EC2
  - `PinnedForColdStart`, `ec2:PinInstanceForColdStart`, control-plane
    account list; standing-set builder, generation, signing and outbox;
    set refreshed before a pinned change completes; adoption of
    standing-started instances on reconnect
  - Property tests: generation monotonic across leader changes
  - _Requirements: 2.1-2.3, 2.7, 3.1_

- [ ] 6. Power-domain placement for pinned replicas
  - No power domain with a majority of a group's pinned replicas;
    refusal of placements and retirements that break it, with recorded
    forcing
  - _Requirements: 2.4, 2.6_

- [ ] 7. Standing attachments in khold
  - Attachment flag that survives power loss; reconnect with the same ID
    and generation without the controller; fencing unchanged
  - Sim case: all replicas and the initiator lose power, controller absent
  - _Requirements: 2.5, 6.4_

- [ ] 8. Bootstrap intermediate and identity certificates
  - CA bootstrap intermediate (5 years), 400-day identity certificates
    restricted to the bootstrap tier's Raft, unseal and CA traffic;
    ordinary intermediate rotation; offline root procedure documented
  - _Requirements: 3.4, 9.4_

- [ ] 9. HSM node unseal from instance secrets
  - Shares delivered as instance secrets; operator unseal kept as
    break-glass; test with every pinned HSM replica restarted at once
  - _Requirements: 3.3, 9.5_

- [ ] 10. Re-enrollment of expired hosts in service
  - Attested re-enrollment without a lifecycle change; `trust = window`
    hosts listed for the operator
  - _Requirements: 9.1-9.3_

- [ ] 11. Time floor and time-source checks
  - Commit every 10 minutes; refuse issuing below the floor or more than
    5 minutes ahead; time sources declared in the graph; skew metrics
  - _Requirements: 10.1-10.5_

- [ ] 12. Recovery mode
  - Entry on start-up mass silence or `BeginRecovery`; withheld actions;
    exit at 95 % reported, 30 minutes, or `EndRecovery`; hand-off to the
    rate-limited silence rules; events and metrics. Shared by the EC2
    controller, khold controller library and metal
  - _Requirements: 6.2, 6.3, 7.1-7.5_

- [ ] 13. Customer instance restart after a cold start
  - Restart waves per cell, priority order, instance-store rules,
    `system-reboot` events, hand-off of unreported hosts
  - _Requirements: 8.1-8.5_

- [ ] 14. `DescribeRecovery` and the timeline report
  - _Requirements: 13.1-13.3_

- [ ] 15. Simulated AZ cold-start suite
  - `tests/docker_chaos/az_cold_start/`: the full scenario and every
    fault case; Docker and rootless Podman; runs on PRs that touch the
    graph's components
  - _Requirements: 3.5, 6.1, 6.5, 6.6, 11.1-11.3, 14.1, 14.2_

- [ ] 16. Break-glass snapshots and `kythira-coldstart restore`
  - Hourly encrypted exports off the AZ, 7-day retention; restore onto
    seed machines or a neighbour AZ; loss report; refusal while the
    original quorum is reachable; migration back onto pinned instances
  - _Requirements: 6.3, 12.1-12.4_

- [ ] 17. Weekly QEMU cold-start run
  - Scheduled workflow; phase durations against Requirement 3.6
  - _Requirements: 3.6, 14.3_

- [ ] 18. Runbook and real-hardware drill procedure
  - `doc/runbooks/az-cold-start.md`; the drill runs only on Clark's go
  - _Requirements: 14.4, 14.6_
