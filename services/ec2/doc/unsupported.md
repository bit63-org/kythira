# EC2 operations not implemented

`.kiro/specs/ec2-compatible-api/` Requirement 2.1: every operation in the
pinned model (`../model/service-2.json`, botocore 1.43.126) is either
implemented, and then listed in `../implemented-operations.txt`, or listed
here with its planned task, its reason and the exact error it returns.
`tools/check_coverage.py` (the ctest `ec2_model_coverage`) fails when an
operation is in neither list, so a model upgrade that adds one fails until it
is placed.

The pinned model has 811 operations. Nothing is implemented yet: the gateway
and front end arrive with tasks 2 and 3. Once they do, every operation listed
here is answered with EC2's `UnsupportedOperation` error (HTTP 400, in EC2's
`<Response><Errors><Error>` document), never with an empty success, so a
caller cannot mistake a refusal for an accepted change (Requirement 14.1).
The request is authenticated first, so an unsigned caller gets SigV4's error
instead. Task 19's recorded EC2 responses pin the exact message.

The `Planned` column says which task of the spec takes the operation:

- `task N`: implemented in that task, which moves the row to
  `implemented-operations.txt`.
- `task 13 (refusal)`: a feature Requirement 14.1 refuses until antikythera
  backs it (security groups, Elastic IPs, internet, NAT and transit gateways,
  Spot, placement groups, dedicated hosts, `RebootInstances`). Task 13 makes
  the refusal explicit and checks it; the answer stays `UnsupportedOperation`.
  The internet and NAT gateway rows move when the `vpc-internet-gateways`
  spec is built.
- `task 13 (empty list)`: the read-only call of a refused feature, which
  Requirement 14.2 answers with an empty list from task 13 on, so tools that
  list before they act keep working.
- `task 11 (refusal)`: `DisableEbsEncryptionByDefault`, refused for good
  because every network volume is encrypted (Requirement 10.6).
- `none (out of scope)`: no task in the spec takes it; the reason says why.
  Some of these (`DescribeAccountAttributes`, `DescribeVpcAttribute`,
  `ModifyVpcAttribute`, `DescribeInstanceTypeOfferings`) are calls Terraform's
  AWS provider makes; task 18's client suites decide whether they need a
  task of their own.

| Operation | Planned | Reason | Error |
|---|---|---|---|
| `AcceptAddressTransfer` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AcceptCapacityReservationBillingOwnership` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AcceptReservedInstancesExchangeQuote` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AcceptTransitGatewayClientVpnAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AcceptTransitGatewayMulticastDomainAssociations` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AcceptTransitGatewayPeeringAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AcceptTransitGatewayVpcAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AcceptVpcEndpointConnections` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AcceptVpcPeeringConnection` | none (out of scope) | VPC peering has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `AdvertiseByoipCidr` | none (out of scope) | Bring-your-own IP ranges have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AllocateAddress` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AllocateHosts` | task 13 (refusal) | Dedicated hosts have no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AllocateIpamPoolCidr` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ApplySecurityGroupsToClientVpnTargetNetwork` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssignIpv6Addresses` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `AssignPrivateIpAddresses` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `AssignPrivateNatGatewayAddress` | task 13 (refusal) | NAT gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssociateAddress` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssociateApplicationStatusCheck` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `AssociateCapacityReservationBillingOwner` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AssociateClientVpnTargetNetwork` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AssociateDhcpOptions` | none (out of scope) | DHCP option sets have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `AssociateEnclaveCertificateIamRole` | none (out of scope) | Nitro Enclaves have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AssociateIamInstanceProfile` | none (out of scope) | Instance profiles arrive with instance metadata (task 14) as RunInstances' IamInstanceProfile; association calls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `AssociateInstanceEventWindow` | none (out of scope) | Scheduled-event windows have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AssociateIpamByoasn` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AssociateIpamResourceDiscovery` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AssociateNatGatewayAddress` | task 13 (refusal) | NAT gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssociateRouteServer` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `AssociateRouteTable` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `AssociateSecurityGroupVpc` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssociateSubnetCidrBlock` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `AssociateTransitGatewayMulticastDomain` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssociateTransitGatewayPolicyTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssociateTransitGatewayRouteTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AssociateTrunkInterface` | none (out of scope) | Trunk interfaces have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `AssociateVpcCidrBlock` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `AttachClassicLinkVpc` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AttachImageWatermark` | none (out of scope) | Image watermarks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `AttachInternetGateway` | task 13 (refusal) | Internet gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AttachNetworkInterface` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `AttachVerifiedAccessTrustProvider` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AttachVolume` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `AttachVpnGateway` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AuthorizeClientVpnIngress` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `AuthorizeSecurityGroupEgress` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `AuthorizeSecurityGroupIngress` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `BatchModifyIpamRoutingPolicyRegistrations` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `BundleInstance` | none (out of scope) | Instance bundling is a Windows instance-store feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CancelBundleTask` | none (out of scope) | Instance bundling is a Windows instance-store feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CancelCapacityReservation` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CancelCapacityReservationFleets` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CancelConversionTask` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `CancelDeclarativePoliciesReport` | none (out of scope) | AWS Organizations declarative policies have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CancelExportTask` | none (out of scope) | Export tasks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CancelImageLaunchPermission` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `CancelImportTask` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `CancelReservedInstancesListing` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CancelSpotFleetRequests` | task 13 (refusal) | Spot capacity has no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CancelSpotInstanceRequests` | task 13 (refusal) | Spot capacity has no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ConfirmProductInstance` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `CopyFpgaImage` | none (out of scope) | FPGA images have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CopyImage` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `CopySnapshot` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `CopyVolumes` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateApplicationStatusCheck` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateCapacityManagerDataExport` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCapacityReservation` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCapacityReservationBySplitting` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCapacityReservationCancellationQuote` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCapacityReservationDateChangeQuote` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCapacityReservationFleet` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCarrierGateway` | none (out of scope) | Wavelength carrier gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateClientVpnEndpoint` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateClientVpnRoute` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCoipCidr` | none (out of scope) | Outposts customer-owned IP pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCoipPool` | none (out of scope) | Outposts customer-owned IP pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateCustomerGateway` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateDefaultSubnet` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateDefaultVpc` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateDelegateMacVolumeOwnershipTask` | none (out of scope) | Mac instances have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateDhcpOptions` | none (out of scope) | DHCP option sets have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateEgressOnlyInternetGateway` | task 13 (refusal) | Egress-only internet gateways have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateFleet` | none (out of scope) | EC2 Fleet has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateFlowLogs` | none (out of scope) | Flow logs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateFpgaImage` | none (out of scope) | FPGA images have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateImage` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateImageUsageReport` | none (out of scope) | Image usage reports are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateInstanceConnectEndpoint` | none (out of scope) | EC2 Instance Connect endpoints have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateInstanceEventWindow` | none (out of scope) | Scheduled-event windows have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateInstanceExportTask` | none (out of scope) | Export tasks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateInternetGateway` | task 13 (refusal) | Internet gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateInterruptibleCapacityReservationAllocation` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpam` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamExternalResourceVerificationToken` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamInternetRegistryAssociation` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamPolicy` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamPool` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamPrefixListResolver` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamPrefixListResolverTarget` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamResourceDiscovery` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamRoutingPolicyRegistration` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateIpamScope` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateKeyPair` | task 14 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateLaunchTemplate` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateLaunchTemplateVersion` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateLocalGatewayRoute` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateLocalGatewayRouteTable` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociation` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateLocalGatewayRouteTableVpcAssociation` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateLocalGatewayVirtualInterface` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateLocalGatewayVirtualInterfaceGroup` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateMacSystemIntegrityProtectionModificationTask` | none (out of scope) | Mac instances have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateManagedPrefixList` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateNatGateway` | task 13 (refusal) | NAT gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateNetworkAcl` | none (out of scope) | Network ACLs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateNetworkAclEntry` | none (out of scope) | Network ACLs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateNetworkInsightsAccessScope` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateNetworkInsightsPath` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateNetworkInterface` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateNetworkInterfacePermission` | none (out of scope) | Cross-account interface permissions are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreatePlacementGroup` | task 13 (refusal) | Placement groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreatePublicIpv4Pool` | none (out of scope) | Public IPv4 pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateReplaceRootVolumeTask` | none (out of scope) | Root volume replacement is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateReservedInstancesListing` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateRestoreImageTask` | none (out of scope) | Storing AMIs in S3 is not in the spec; images are kept in the configured store already. | `UnsupportedOperation`, HTTP 400 |
| `CreateRoute` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateRouteServer` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateRouteServerEndpoint` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateRouteServerPeer` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateRouteTable` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateSecondaryNetwork` | none (out of scope) | Secondary networks have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateSecondarySubnet` | none (out of scope) | Secondary networks have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateSecurityGroup` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateSnapshot` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateSnapshots` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateSpotDatafeedSubscription` | task 13 (refusal) | Spot capacity has no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateStoreImageTask` | none (out of scope) | Storing AMIs in S3 is not in the spec; images are kept in the configured store already. | `UnsupportedOperation`, HTTP 400 |
| `CreateSubnet` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateSubnetCidrReservation` | none (out of scope) | Subnet CIDR reservations are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateTags` | task 4 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateTrafficMirrorFilter` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateTrafficMirrorFilterRule` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateTrafficMirrorSession` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateTrafficMirrorTarget` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGateway` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayConnect` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayConnectPeer` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayMeteringPolicy` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayMeteringPolicyEntry` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayMulticastDomain` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayPeeringAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayPolicyTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayPolicyTableEntry` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayPrefixListReference` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayRoute` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayRouteTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayRouteTableAnnouncement` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateTransitGatewayVpcAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `CreateVerifiedAccessEndpoint` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVerifiedAccessGroup` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVerifiedAccessInstance` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVerifiedAccessTrustProvider` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVolume` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpc` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpcBlockPublicAccessExclusion` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpcEncryptionControl` | none (out of scope) | VPC encryption controls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpcEndpoint` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpcEndpointConnectionNotification` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpcEndpointServiceConfiguration` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpcPeeringConnection` | none (out of scope) | VPC peering has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpnConcentrator` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpnConnection` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpnConnectionRoute` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `CreateVpnGateway` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteApplicationStatusCheck` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeleteCapacityManagerDataExport` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteCarrierGateway` | none (out of scope) | Wavelength carrier gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteClientVpnEndpoint` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteClientVpnEndpointAuthorizationPolicy` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteClientVpnRoute` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteCoipCidr` | none (out of scope) | Outposts customer-owned IP pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteCoipPool` | none (out of scope) | Outposts customer-owned IP pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteCustomerGateway` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteDhcpOptions` | none (out of scope) | DHCP option sets have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteEgressOnlyInternetGateway` | task 13 (refusal) | Egress-only internet gateways have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteFleets` | none (out of scope) | EC2 Fleet has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteFlowLogs` | none (out of scope) | Flow logs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteFpgaImage` | none (out of scope) | FPGA images have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteImageUsageReport` | none (out of scope) | Image usage reports are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeleteInstanceConnectEndpoint` | none (out of scope) | EC2 Instance Connect endpoints have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteInstanceEventWindow` | none (out of scope) | Scheduled-event windows have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteInternetGateway` | task 13 (refusal) | Internet gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpam` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamExternalResourceVerificationToken` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamInternetRegistryAssociation` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamPolicy` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamPool` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamPrefixListResolver` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamPrefixListResolverTarget` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamResourceDiscovery` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamRoutingPolicyRegistration` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteIpamScope` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteKeyPair` | task 14 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLaunchTemplate` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLaunchTemplateVersions` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLocalGatewayRoute` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLocalGatewayRouteTable` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociation` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLocalGatewayRouteTableVpcAssociation` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLocalGatewayVirtualInterface` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteLocalGatewayVirtualInterfaceGroup` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteManagedPrefixList` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNatGateway` | task 13 (refusal) | NAT gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkAcl` | none (out of scope) | Network ACLs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkAclEntry` | none (out of scope) | Network ACLs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkInsightsAccessScope` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkInsightsAccessScopeAnalysis` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkInsightsAnalysis` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkInsightsPath` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkInterface` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteNetworkInterfacePermission` | none (out of scope) | Cross-account interface permissions are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeletePlacementGroup` | task 13 (refusal) | Placement groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeletePublicIpv4Pool` | none (out of scope) | Public IPv4 pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteQueuedReservedInstances` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteRoute` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteRouteServer` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteRouteServerEndpoint` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteRouteServerPeer` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteRouteTable` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteSecondaryNetwork` | none (out of scope) | Secondary networks have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteSecondarySubnet` | none (out of scope) | Secondary networks have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteSecurityGroup` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteSnapshot` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteSpotDatafeedSubscription` | task 13 (refusal) | Spot capacity has no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteSubnet` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteSubnetCidrReservation` | none (out of scope) | Subnet CIDR reservations are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeleteTags` | task 4 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteTrafficMirrorFilter` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteTrafficMirrorFilterRule` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteTrafficMirrorSession` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteTrafficMirrorTarget` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGateway` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayClientVpnAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayConnect` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayConnectPeer` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayMeteringPolicy` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayMeteringPolicyEntry` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayMulticastDomain` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayPeeringAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayPolicyTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayPolicyTableEntry` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayPrefixListReference` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayRoute` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayRouteTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayRouteTableAnnouncement` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteTransitGatewayVpcAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeleteVerifiedAccessEndpoint` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVerifiedAccessGroup` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVerifiedAccessInstance` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVerifiedAccessTrustProvider` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVolume` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpc` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpcBlockPublicAccessExclusion` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpcEncryptionControl` | none (out of scope) | VPC encryption controls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpcEndpointConnectionNotifications` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpcEndpointServiceConfigurations` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpcEndpoints` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpcPeeringConnection` | none (out of scope) | VPC peering has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpnConcentrator` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpnConnection` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpnConnectionRoute` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeleteVpnGateway` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeprovisionByoipCidr` | none (out of scope) | Bring-your-own IP ranges have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeprovisionIpamByoasn` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeprovisionIpamPoolCidr` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeprovisionPublicIpv4PoolCidr` | none (out of scope) | Public IPv4 pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeregisterImage` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DeregisterInstanceEventNotificationAttributes` | none (out of scope) | Scheduled events have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DeregisterTransitGatewayMulticastGroupMembers` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DeregisterTransitGatewayMulticastGroupSources` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DescribeAccountAttributes` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeAccountVpcEncryptionControl` | none (out of scope) | VPC encryption controls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeAddressTransfers` | task 13 (empty list) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeAddresses` | task 13 (empty list) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeAddressesAttribute` | task 13 (empty list) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeAggregateIdFormat` | none (out of scope) | EC2's long-ID opt-in is over; Kythira IDs always have the long form. | `UnsupportedOperation`, HTTP 400 |
| `DescribeApplicationStatus` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeApplicationStatusCheckAssociations` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeApplicationStatusChecks` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeAvailabilityZones` | task 4 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeAwsNetworkPerformanceMetricSubscriptions` | none (out of scope) | AWS network performance metrics have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeBundleTasks` | none (out of scope) | Instance bundling is a Windows instance-store feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeByoipCidrs` | none (out of scope) | Bring-your-own IP ranges have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityBlockExtensionHistory` | none (out of scope) | Capacity blocks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityBlockExtensionOfferings` | none (out of scope) | Capacity blocks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityBlockOfferings` | none (out of scope) | Capacity blocks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityBlockStatus` | none (out of scope) | Capacity blocks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityBlocks` | none (out of scope) | Capacity blocks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityManagerDataExports` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityReservationBillingRequests` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityReservationCancellationQuotes` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityReservationDateChangeQuotes` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityReservationFleets` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityReservationTopology` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCapacityReservations` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCarrierGateways` | none (out of scope) | Wavelength carrier gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeClassicLinkInstances` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeClientVpnAuthorizationRules` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeClientVpnConnections` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeClientVpnEndpoints` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeClientVpnRoutes` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeClientVpnTargetNetworks` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCoipPools` | none (out of scope) | Outposts customer-owned IP pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeConversionTasks` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `DescribeCustomerGateways` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeDeclarativePoliciesReports` | none (out of scope) | AWS Organizations declarative policies have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeDhcpOptions` | none (out of scope) | DHCP option sets have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeEgressOnlyInternetGateways` | task 13 (empty list) | Egress-only internet gateways have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeElasticGpus` | none (out of scope) | Elastic Graphics is retired on AWS. | `UnsupportedOperation`, HTTP 400 |
| `DescribeExportImageTasks` | none (out of scope) | Export tasks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeExportTasks` | none (out of scope) | Export tasks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFastLaunchImages` | none (out of scope) | Windows fast launch has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFastSnapshotRestores` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFleetHistory` | none (out of scope) | EC2 Fleet has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFleetInstances` | none (out of scope) | EC2 Fleet has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFleets` | none (out of scope) | EC2 Fleet has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFlowLogs` | none (out of scope) | Flow logs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFpgaImageAttribute` | none (out of scope) | FPGA images have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeFpgaImages` | none (out of scope) | FPGA images have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeHostReservationOfferings` | task 13 (empty list) | Dedicated hosts have no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeHostReservations` | task 13 (empty list) | Dedicated hosts have no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeHosts` | task 13 (empty list) | Dedicated hosts have no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeIamInstanceProfileAssociations` | none (out of scope) | Instance profiles arrive with instance metadata (task 14) as RunInstances' IamInstanceProfile; association calls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIdFormat` | none (out of scope) | EC2's long-ID opt-in is over; Kythira IDs always have the long form. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIdentityIdFormat` | none (out of scope) | EC2's long-ID opt-in is over; Kythira IDs always have the long form. | `UnsupportedOperation`, HTTP 400 |
| `DescribeImageAttribute` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeImageReferences` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeImageUsageReportEntries` | none (out of scope) | Image usage reports are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeImageUsageReports` | none (out of scope) | Image usage reports are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeImages` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeImportImageTasks` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `DescribeImportSnapshotTasks` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceAttribute` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceConnectEndpoints` | none (out of scope) | EC2 Instance Connect endpoints have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceCreditSpecifications` | none (out of scope) | Burstable credit specifications have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceEventNotificationAttributes` | none (out of scope) | Scheduled events have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceEventWindows` | none (out of scope) | Scheduled-event windows have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceImageMetadata` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceSqlHaHistoryStates` | none (out of scope) | SQL Server HA has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceSqlHaStates` | none (out of scope) | SQL Server HA has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceStatus` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceTopology` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceTypeOfferings` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstanceTypes` | task 4 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInstances` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeInternetGateways` | task 13 (empty list) | Internet gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeIpamByoasn` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamExternalResourceVerificationTokens` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamInternetRegistryAssociations` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamPolicies` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamPoolAllocations` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamPools` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamPrefixListResolverTargets` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamPrefixListResolvers` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamResourceDiscoveries` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamResourceDiscoveryAssociations` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpamScopes` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpams` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeIpv6Pools` | none (out of scope) | Bring-your-own IPv6 pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeKeyPairs` | task 14 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLaunchTemplateVersions` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLaunchTemplates` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLocalGatewayRouteTableVpcAssociations` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLocalGatewayRouteTables` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLocalGatewayVirtualInterfaceGroups` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLocalGatewayVirtualInterfaces` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLocalGateways` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeLockedSnapshots` | none (out of scope) | Snapshot locks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeMacHosts` | task 13 (empty list) | Dedicated hosts have no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeMacModificationTasks` | none (out of scope) | Mac instances have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeManagedPrefixLists` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeMovingAddresses` | task 13 (empty list) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeNatGateways` | task 13 (empty list) | NAT gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeNetworkAcls` | none (out of scope) | Network ACLs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeNetworkInsightsAccessScopeAnalyses` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeNetworkInsightsAccessScopes` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeNetworkInsightsAnalyses` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeNetworkInsightsPaths` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeNetworkInterfaceAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeNetworkInterfacePermissions` | none (out of scope) | Cross-account interface permissions are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeNetworkInterfaces` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeOutpostLags` | none (out of scope) | Outposts have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribePlacementGroups` | task 13 (empty list) | Placement groups have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribePrefixLists` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribePrincipalIdFormat` | none (out of scope) | EC2's long-ID opt-in is over; Kythira IDs always have the long form. | `UnsupportedOperation`, HTTP 400 |
| `DescribePublicIpv4Pools` | none (out of scope) | Public IPv4 pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeRegions` | task 4 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeReplaceRootVolumeTasks` | none (out of scope) | Root volume replacement is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeReservedInstances` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeReservedInstancesListings` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeReservedInstancesModifications` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeReservedInstancesOfferings` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeRouteServerEndpoints` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeRouteServerPeers` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeRouteServers` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeRouteTables` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeScheduledInstanceAvailability` | none (out of scope) | Scheduled Instances have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeScheduledInstances` | none (out of scope) | Scheduled Instances have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSecondaryInterfaces` | none (out of scope) | Secondary networks have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSecondaryNetworks` | none (out of scope) | Secondary networks have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSecondarySubnets` | none (out of scope) | Secondary networks have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSecurityGroupReferences` | task 13 (empty list) | Security groups have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSecurityGroupRules` | task 13 (empty list) | Security groups have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSecurityGroupVpcAssociations` | task 13 (empty list) | Security groups have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSecurityGroups` | task 13 (empty list) | Security groups have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeServiceLinkVirtualInterfaces` | none (out of scope) | Outposts have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSnapshotAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSnapshotTierStatus` | none (out of scope) | Snapshot archive tiers have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSnapshots` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSpotDatafeedSubscription` | task 13 (empty list) | Spot capacity has no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSpotFleetInstances` | task 13 (empty list) | Spot capacity has no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSpotFleetRequestHistory` | task 13 (empty list) | Spot capacity has no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSpotFleetRequests` | task 13 (empty list) | Spot capacity has no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSpotInstanceRequests` | task 13 (empty list) | Spot capacity has no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeSpotPriceHistory` | task 13 (empty list) | Spot capacity has no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeStaleSecurityGroups` | task 13 (empty list) | Security groups have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeStoreImageTasks` | none (out of scope) | Storing AMIs in S3 is not in the spec; images are kept in the configured store already. | `UnsupportedOperation`, HTTP 400 |
| `DescribeSubnets` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeTags` | task 4 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeTrafficMirrorFilterRules` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeTrafficMirrorFilters` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeTrafficMirrorSessions` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeTrafficMirrorTargets` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeTransitGatewayAttachments` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayConnectPeers` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayConnects` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayMeteringPolicies` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayMulticastDomains` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayPeeringAttachments` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayPolicyTables` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayRouteTableAnnouncements` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayRouteTables` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGatewayVpcAttachments` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTransitGateways` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `DescribeTrunkInterfaceAssociations` | none (out of scope) | Trunk interfaces have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVerifiedAccessEndpoints` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVerifiedAccessGroups` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVerifiedAccessInstanceLoggingConfigurations` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVerifiedAccessInstances` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVerifiedAccessTrustProviders` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVolumeAttribute` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVolumeStatus` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVolumes` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVolumesModifications` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcBlockPublicAccessExclusions` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcBlockPublicAccessOptions` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcClassicLink` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcClassicLinkDnsSupport` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEncryptionControls` | none (out of scope) | VPC encryption controls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEndpointAssociations` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEndpointConnectionNotifications` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEndpointConnections` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEndpointServiceConfigurations` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEndpointServicePermissions` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEndpointServices` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcEndpoints` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcPeeringConnections` | none (out of scope) | VPC peering has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpcs` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpnConcentrators` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpnConnections` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DescribeVpnGateways` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DetachClassicLinkVpc` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DetachImageWatermark` | none (out of scope) | Image watermarks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DetachInternetGateway` | task 13 (refusal) | Internet gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DetachNetworkInterface` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DetachVerifiedAccessTrustProvider` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DetachVolume` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DetachVpnGateway` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableAddressTransfer` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisableAllowedImagesSettings` | none (out of scope) | Allowed-images settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisableApplicationStatusCheckSuppression` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisableAwsNetworkPerformanceMetricSubscription` | none (out of scope) | AWS network performance metrics have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableCapacityManager` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableEbsEncryptionByDefault` | task 11 (refusal) | Every network volume is encrypted, so encryption by default cannot be turned off (Requirement 10.6). | `UnsupportedOperation`, HTTP 400 |
| `DisableFastLaunch` | none (out of scope) | Windows fast launch has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableFastSnapshotRestores` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DisableImage` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `DisableImageBlockPublicAccess` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisableImageDeprecation` | none (out of scope) | Image deprecation is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisableImageDeregistrationProtection` | none (out of scope) | Image deregistration protection is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisableInstanceSqlHaStandbyDetections` | none (out of scope) | SQL Server HA has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableIpamOrganizationAdminAccount` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableIpamPolicy` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableRouteServerPropagation` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DisableSerialConsoleAccess` | none (out of scope) | The serial console is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisableSnapshotBlockPublicAccess` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisableTransitGatewayRouteTablePropagation` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisableVgwRoutePropagation` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableVpcClassicLink` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisableVpcClassicLinkDnsSupport` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateAddress` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisassociateApplicationStatusCheck` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateCapacityReservationBillingOwner` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateClientVpnTargetNetwork` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateEnclaveCertificateIamRole` | none (out of scope) | Nitro Enclaves have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateIamInstanceProfile` | none (out of scope) | Instance profiles arrive with instance metadata (task 14) as RunInstances' IamInstanceProfile; association calls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateInstanceEventWindow` | none (out of scope) | Scheduled-event windows have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateIpamByoasn` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateIpamResourceDiscovery` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateNatGatewayAddress` | task 13 (refusal) | NAT gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisassociateRouteServer` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateRouteTable` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateSecurityGroupVpc` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisassociateSubnetCidrBlock` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateTransitGatewayMulticastDomain` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisassociateTransitGatewayPolicyTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisassociateTransitGatewayRouteTable` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `DisassociateTrunkInterface` | none (out of scope) | Trunk interfaces have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `DisassociateVpcCidrBlock` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `EnableAddressTransfer` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `EnableAllowedImagesSettings` | none (out of scope) | Allowed-images settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `EnableApplicationStatusCheckSuppression` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `EnableAwsNetworkPerformanceMetricSubscription` | none (out of scope) | AWS network performance metrics have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableCapacityManager` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableEbsEncryptionByDefault` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `EnableFastLaunch` | none (out of scope) | Windows fast launch has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableFastSnapshotRestores` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `EnableImage` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `EnableImageBlockPublicAccess` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `EnableImageDeprecation` | none (out of scope) | Image deprecation is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `EnableImageDeregistrationProtection` | none (out of scope) | Image deregistration protection is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `EnableInstanceSqlHaStandbyDetections` | none (out of scope) | SQL Server HA has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableIpamInternetRegistryAssociation` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableIpamOrganizationAdminAccount` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableIpamPolicy` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableReachabilityAnalyzerOrganizationSharing` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableRouteServerPropagation` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `EnableSerialConsoleAccess` | none (out of scope) | The serial console is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `EnableSnapshotBlockPublicAccess` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `EnableTransitGatewayRouteTablePropagation` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `EnableVgwRoutePropagation` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableVolumeIO` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `EnableVpcClassicLink` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `EnableVpcClassicLinkDnsSupport` | none (out of scope) | EC2-Classic is retired on AWS and has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ExportClientVpnClientCertificateRevocationList` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ExportClientVpnClientConfiguration` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ExportImage` | none (out of scope) | Export tasks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ExportTransitGatewayRoutes` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ExportVerifiedAccessInstanceClientConfiguration` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetActiveVpnTunnelStatus` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetAllowedImagesSettings` | none (out of scope) | Allowed-images settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetAssociatedEnclaveCertificateIamRoles` | none (out of scope) | Nitro Enclaves have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetAssociatedIpv6PoolCidrs` | none (out of scope) | Bring-your-own IPv6 pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetAwsNetworkPerformanceData` | none (out of scope) | AWS network performance metrics have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetCapacityManagerAttributes` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetCapacityManagerMetricData` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetCapacityManagerMetricDimensions` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetCapacityManagerMonitoredTagKeys` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetCapacityManagerSupportabilityScores` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetCapacityReservationUsage` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetClientVpnEndpointAuthorizationPolicy` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetCoipPoolUsage` | none (out of scope) | Outposts customer-owned IP pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetConsoleOutput` | none (out of scope) | Console output and screenshots are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetConsoleScreenshot` | none (out of scope) | Console output and screenshots are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetDeclarativePoliciesReportSummary` | none (out of scope) | AWS Organizations declarative policies have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetDefaultCreditSpecification` | none (out of scope) | Burstable credit specifications have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetEbsDefaultKmsKeyId` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `GetEbsEncryptionByDefault` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `GetEnabledIpamPolicy` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetFlowLogsIntegrationTemplate` | none (out of scope) | Flow logs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `GetGroupsForCapacityReservation` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetHostReservationPurchasePreview` | task 13 (empty list) | Dedicated hosts have no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetImageAncestry` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetImageBlockPublicAccessState` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetImageFindings` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetInstanceMetadataDefaults` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetInstanceTpmEkPub` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetInstanceTypesFromInstanceRequirements` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetInstanceUefiData` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamAddressHistory` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamDiscoveredAccounts` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamDiscoveredPublicAddresses` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamDiscoveredResourceCidrs` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamDiscoveredRoutes` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamInternetRegistryAssociationAsns` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamInternetRegistryAssociationCidrs` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamPolicyAllocationRules` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamPolicyOrganizationTargets` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamPoolAllocations` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamPoolCidrs` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamPrefixListResolverRules` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamPrefixListResolverVersionEntries` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamPrefixListResolverVersions` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamResourceCidrs` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamRouteOriginAuthorizations` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamRouteProtectionFindings` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamRoutingPolicyRegistrationDeltas` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetIpamRoutingPolicyRegistrations` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetLaunchTemplateData` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetManagedPrefixListAssociations` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `GetManagedPrefixListEntries` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `GetManagedResourceVisibility` | none (out of scope) | Managed resources have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetNetworkInsightsAccessScopeAnalysisFindings` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetNetworkInsightsAccessScopeContent` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetPasswordData` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetReservedInstancesExchangeQuote` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetRouteServerAssociations` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `GetRouteServerPropagations` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `GetRouteServerRoutingDatabase` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `GetSecurityGroupsForVpc` | task 13 (empty list) | Security groups have no antikythera backing yet (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetSerialConsoleAccessStatus` | none (out of scope) | The serial console is not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetSnapshotBlockPublicAccessState` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetSpotPlacementScores` | task 13 (empty list) | Spot capacity has no Kythira counterpart (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetSubnetCidrReservations` | none (out of scope) | Subnet CIDR reservations are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `GetTransitGatewayAttachmentNatConfiguration` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayAttachmentPropagations` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayMeteringPolicyEntries` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayMulticastDomainAssociations` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayPolicyTableAssociations` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayPolicyTableEntries` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayPrefixListReferences` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayRouteTableAssociations` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetTransitGatewayRouteTablePropagations` | task 13 (empty list) | Transit gateways have no antikythera backing (Requirement 14.1); the describe answers an empty list so tools that list before they act keep working (Requirement 14.2). | none once task 13 lands (empty list); `UnsupportedOperation`, HTTP 400 until then |
| `GetVerifiedAccessEndpointPolicy` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetVerifiedAccessEndpointTargets` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetVerifiedAccessGroupPolicy` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetVpcResourcesBlockingEncryptionEnforcement` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `GetVpnConnectionDeviceSampleConfiguration` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetVpnConnectionDeviceTypes` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `GetVpnTunnelReplacementStatus` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ImportClientVpnClientCertificateRevocationList` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ImportImage` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `ImportInstance` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `ImportKeyPair` | task 14 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ImportSnapshot` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `ImportVolume` | none (out of scope) | VM import has no Kythira counterpart; images come from RegisterImage. | `UnsupportedOperation`, HTTP 400 |
| `ListImagesInRecycleBin` | none (out of scope) | The Recycle Bin has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ListSnapshotsInRecycleBin` | none (out of scope) | The Recycle Bin has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ListVolumesInRecycleBin` | none (out of scope) | The Recycle Bin has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `LockSnapshot` | none (out of scope) | Snapshot locks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ModifyAccountVpcEncryptionControl` | none (out of scope) | VPC encryption controls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ModifyAddressAttribute` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyApplicationStatusCheck` | none (out of scope) | Application status checks are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ModifyAvailabilityZoneGroup` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyCapacityReservation` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyCapacityReservationFleet` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyClientVpnEndpoint` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyClientVpnEndpointAuthorizationPolicy` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyDefaultCreditSpecification` | none (out of scope) | Burstable credit specifications have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyEbsDefaultKmsKeyId` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ModifyFleet` | none (out of scope) | EC2 Fleet has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyFpgaImageAttribute` | none (out of scope) | FPGA images have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyHosts` | task 13 (refusal) | Dedicated hosts have no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyIdFormat` | none (out of scope) | EC2's long-ID opt-in is over; Kythira IDs always have the long form. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIdentityIdFormat` | none (out of scope) | EC2's long-ID opt-in is over; Kythira IDs always have the long form. | `UnsupportedOperation`, HTTP 400 |
| `ModifyImageAttribute` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceAttribute` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceCapacityReservationAttributes` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceConnectEndpoint` | none (out of scope) | EC2 Instance Connect endpoints have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceCpuOptions` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceCreditSpecification` | none (out of scope) | Burstable credit specifications have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceEventStartTime` | none (out of scope) | Scheduled events have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceEventWindow` | none (out of scope) | Scheduled-event windows have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceMaintenanceOptions` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceMetadataDefaults` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceMetadataOptions` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstanceNetworkPerformanceOptions` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyInstancePlacement` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpam` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamPolicyAllocationRules` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamPool` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamPoolAllocation` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamPrefixListResolver` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamPrefixListResolverTarget` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamResourceCidr` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamResourceDiscovery` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamRoutingPolicyRegistration` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyIpamScope` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyLaunchTemplate` | none (out of scope) | Launch templates are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ModifyLocalGatewayRoute` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyManagedPrefixList` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ModifyManagedResourceVisibility` | none (out of scope) | Managed resources have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyNetworkInterfaceAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyPrivateDnsNameOptions` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyPublicIpDnsNameOptions` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyReservedInstances` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyRouteServer` | none (out of scope) | VPC Route Server has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ModifySecurityGroupRules` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifySnapshotAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifySnapshotTier` | none (out of scope) | Snapshot archive tiers have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifySpotFleetRequest` | task 13 (refusal) | Spot capacity has no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifySubnetAttribute` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ModifyTrafficMirrorFilterNetworkServices` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ModifyTrafficMirrorFilterRule` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ModifyTrafficMirrorSession` | none (out of scope) | Traffic mirroring has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ModifyTransitGateway` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyTransitGatewayAttachmentNatConfiguration` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyTransitGatewayMeteringPolicy` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyTransitGatewayPolicyTableEntry` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyTransitGatewayPrefixListReference` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyTransitGatewayVpcAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ModifyVerifiedAccessEndpoint` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVerifiedAccessEndpointPolicy` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVerifiedAccessGroup` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVerifiedAccessGroupPolicy` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVerifiedAccessInstance` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVerifiedAccessInstanceLoggingConfiguration` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVerifiedAccessTrustProvider` | none (out of scope) | Verified Access has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVolume` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVolumeAttribute` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcBlockPublicAccessExclusion` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcBlockPublicAccessOptions` | none (out of scope) | Block public access settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcEncryptionControl` | none (out of scope) | VPC encryption controls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcEndpoint` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcEndpointConnectionNotification` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcEndpointPayerResponsibility` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcEndpointServiceConfiguration` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcEndpointServicePayerResponsibility` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcEndpointServicePermissions` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcPeeringConnectionOptions` | none (out of scope) | VPC peering has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpcTenancy` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpnConnection` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpnConnectionOptions` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpnTunnelCertificate` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ModifyVpnTunnelOptions` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `MonitorInstances` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `MoveAddressToVpc` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `MoveByoipCidrToIpam` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `MoveCapacityReservationInstances` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ProvisionByoipCidr` | none (out of scope) | Bring-your-own IP ranges have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ProvisionIpamByoasn` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ProvisionIpamPoolCidr` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ProvisionPublicIpv4PoolCidr` | none (out of scope) | Public IPv4 pools have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `PurchaseCapacityBlock` | none (out of scope) | Capacity blocks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `PurchaseCapacityBlockExtension` | none (out of scope) | Capacity blocks have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `PurchaseHostReservation` | task 13 (refusal) | Dedicated hosts have no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `PurchaseReservedInstancesOffering` | none (out of scope) | Reserved Instances are a billing feature with no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `PurchaseScheduledInstances` | none (out of scope) | Scheduled Instances have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RebootInstances` | task 13 (refusal) | Hull has no reset command yet (Requirement 14.1, design open question 2). | `UnsupportedOperation`, HTTP 400 |
| `RegisterImage` | task 12 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `RegisterInstanceEventNotificationAttributes` | none (out of scope) | Scheduled events have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RegisterTransitGatewayMulticastGroupMembers` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RegisterTransitGatewayMulticastGroupSources` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RejectCapacityReservationBillingOwnership` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RejectTransitGatewayClientVpnAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RejectTransitGatewayMulticastDomainAssociations` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RejectTransitGatewayPeeringAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RejectTransitGatewayVpcAttachment` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RejectVpcEndpointConnections` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RejectVpcPeeringConnection` | none (out of scope) | VPC peering has no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ReleaseAddress` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ReleaseHosts` | task 13 (refusal) | Dedicated hosts have no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ReleaseIpamPoolAllocation` | none (out of scope) | IPAM has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceIamInstanceProfileAssociation` | none (out of scope) | Instance profiles arrive with instance metadata (task 14) as RunInstances' IamInstanceProfile; association calls are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceImageCriteriaInAllowedImagesSettings` | none (out of scope) | Allowed-images settings are not in the spec. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceImageInstanceTypeSpecification` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceNetworkAclAssociation` | none (out of scope) | Network ACLs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceNetworkAclEntry` | none (out of scope) | Network ACLs have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceRoute` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceRouteTableAssociation` | task 10 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ReplaceTransitGatewayRoute` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ReplaceVpnTunnel` | none (out of scope) | Site-to-site VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ReportInstanceStatus` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `RequestSpotFleet` | task 13 (refusal) | Spot capacity has no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RequestSpotInstances` | task 13 (refusal) | Spot capacity has no Kythira counterpart (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ResetAddressAttribute` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ResetEbsDefaultKmsKeyId` | task 11 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `ResetFpgaImageAttribute` | none (out of scope) | FPGA images have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `ResetImageAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ResetInstanceAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ResetNetworkInterfaceAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `ResetSnapshotAttribute` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `RestoreAddressToClassic` | task 13 (refusal) | Elastic IP addresses have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RestoreImageFromRecycleBin` | none (out of scope) | The Recycle Bin has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RestoreManagedPrefixListVersion` | none (out of scope) | Managed prefix lists have no antikythera backing. | `UnsupportedOperation`, HTTP 400 |
| `RestoreSnapshotFromRecycleBin` | none (out of scope) | The Recycle Bin has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RestoreSnapshotTier` | none (out of scope) | Snapshot archive tiers have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RestoreVolumeFromRecycleBin` | none (out of scope) | The Recycle Bin has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RevokeClientVpnIngress` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `RevokeSecurityGroupEgress` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RevokeSecurityGroupIngress` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `RunInstances` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `RunScheduledInstances` | none (out of scope) | Scheduled Instances have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `SearchLocalGatewayRoutes` | none (out of scope) | Outposts local gateways have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `SearchTransitGatewayMulticastGroups` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `SearchTransitGatewayRoutes` | task 13 (refusal) | Transit gateways have no antikythera backing (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `SendDiagnosticInterrupt` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `StartDeclarativePoliciesReport` | none (out of scope) | AWS Organizations declarative policies have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `StartInstances` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `StartNetworkInsightsAccessScopeAnalysis` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `StartNetworkInsightsAnalysis` | none (out of scope) | Reachability Analyzer has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `StartVpcEndpointServicePrivateDnsVerification` | none (out of scope) | VPC endpoints and PrivateLink have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `StopInstances` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `TerminateClientVpnConnections` | none (out of scope) | Client VPN has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `TerminateInstances` | task 13 | Planned; answered as unsupported until that task lands. | `UnsupportedOperation`, HTTP 400 |
| `UnassignIpv6Addresses` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `UnassignPrivateIpAddresses` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `UnassignPrivateNatGatewayAddress` | task 13 (refusal) | NAT gateways wait for the vpc-internet-gateways spec's build (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `UnlockSnapshot` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `UnmonitorInstances` | none (out of scope) | Not in the spec: no antikythera backing or Kythira counterpart yet. | `UnsupportedOperation`, HTTP 400 |
| `UpdateCapacityManagerMonitoredTagKeys` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `UpdateCapacityManagerOrganizationsAccess` | none (out of scope) | Capacity Manager has no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `UpdateInterruptibleCapacityReservationAllocation` | none (out of scope) | Capacity reservations have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
| `UpdateSecurityGroupRuleDescriptionsEgress` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `UpdateSecurityGroupRuleDescriptionsIngress` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `ValidateSecurityGroupQuotasForInterface` | task 13 (refusal) | Security groups have no antikythera backing yet (Requirement 14.1). | `UnsupportedOperation`, HTTP 400 |
| `WithdrawByoipCidr` | none (out of scope) | Bring-your-own IP ranges have no Kythira counterpart. | `UnsupportedOperation`, HTTP 400 |
