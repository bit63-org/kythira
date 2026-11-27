// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The evidence scenario through the AWS SDK for JavaScript v3 (README.md).
// Usage: node client.mjs ENDPOINT

import assert from "node:assert/strict";
import * as ec2 from "@aws-sdk/client-ec2";

// The SDK sends UserData as given, so it is base64 here (boto3 and the CLI
// encode it themselves).
const USER_DATA = "IyEvYmluL3NoCmVjaG8gaGVsbG8K";
const ZONE = "us-east-1a";

const c = new ec2.EC2Client({ endpoint: process.argv[2], region: "us-east-1" });
const send = (Cmd, input) => c.send(new Cmd(input));
const expectError = async (code, promise) => {
  await assert.rejects(promise, (e) => e.name === code || e.Code === code);
};
const filter = (Name, ...Values) => ({ Name, Values });

await send(ec2.DescribeRegionsCommand, { RegionNames: ["us-east-1"] });
await send(ec2.DescribeAvailabilityZonesCommand, { Filters: [filter("state", "available")] });
const { Vpc: { VpcId: vpc } } = await send(ec2.CreateVpcCommand, {
  CidrBlock: "10.0.0.0/16",
  TagSpecifications: [{ ResourceType: "vpc",
    Tags: [{ Key: "Name", Value: "evidence" }, { Key: "team", Value: "kythira" }] }],
});
const { Subnet: { SubnetId: subnet } } = await send(ec2.CreateSubnetCommand, {
  VpcId: vpc, CidrBlock: "10.0.1.0/24", AvailabilityZone: ZONE,
});
await send(ec2.DescribeVpcsCommand, { VpcIds: [vpc], Filters: [filter("tag:Name", "evidence")] });
const { VolumeId: vol1 } = await send(ec2.CreateVolumeCommand, {
  AvailabilityZone: ZONE, Size: 8, VolumeType: "gp3", Encrypted: true,
  ClientToken: "evidence-volume-1",
  TagSpecifications: [{ ResourceType: "volume", Tags: [{ Key: "Name", Value: "evidence-data" }] }],
});
const { VolumeId: vol2 } = await send(ec2.CreateVolumeCommand, {
  AvailabilityZone: ZONE, Size: 16, VolumeType: "gp3", Iops: 3000, Throughput: 125,
});
const zoneFilter = [filter("availability-zone", ZONE)];
const page = await send(ec2.DescribeVolumesCommand, { Filters: zoneFilter, MaxResults: 5 });
await send(ec2.DescribeVolumesCommand, {
  Filters: zoneFilter, MaxResults: 5, NextToken: page.NextToken,
});
const run = {
  ImageId: "ami-0000000000000a001", InstanceType: "t3.micro", MinCount: 1, MaxCount: 2,
  SubnetId: subnet, UserData: USER_DATA,
  BlockDeviceMappings: [
    { DeviceName: "/dev/xvda", Ebs: { VolumeSize: 8, VolumeType: "gp3", DeleteOnTermination: true } },
    { DeviceName: "/dev/sdb", VirtualName: "ephemeral0" },
  ],
  TagSpecifications: [
    { ResourceType: "instance", Tags: [{ Key: "Name", Value: "evidence" }] },
    { ResourceType: "volume", Tags: [{ Key: "Name", Value: "evidence-root" }] },
  ],
};
const { Instances } = await send(ec2.RunInstancesCommand, { ClientToken: "evidence-run-1", ...run });
const ids = Instances.map((i) => i.InstanceId);
await expectError("DryRunOperation", send(ec2.RunInstancesCommand, { DryRun: true, ...run }));
await send(ec2.DescribeInstancesCommand, {
  InstanceIds: ids, Filters: [filter("instance-state-name", "pending", "running")],
});
await send(ec2.CreateTagsCommand, {
  Resources: [ids[0], vol1], Tags: [{ Key: "stage", Value: "evidence" }, { Key: "flag" }],
});
await send(ec2.DescribeTagsCommand, {
  Filters: [filter("resource-id", ids[0]), filter("key", "stage")],
});
await send(ec2.DeleteTagsCommand, { Resources: [vol1], Tags: [{ Key: "flag" }] });
await send(ec2.AttachVolumeCommand, { VolumeId: vol1, InstanceId: ids[0], Device: "/dev/sdf" });
await send(ec2.DetachVolumeCommand, { VolumeId: vol1 });
await send(ec2.StopInstancesCommand, { InstanceIds: [ids[0]] });
await send(ec2.StartInstancesCommand, { InstanceIds: [ids[0]] });
await send(ec2.TerminateInstancesCommand, { InstanceIds: ids });
await expectError("UnsupportedOperation", send(ec2.CreateSecurityGroupCommand, {
  GroupName: "evidence", Description: "evidence group", VpcId: vpc,
}));
await send(ec2.DeleteVolumeCommand, { VolumeId: vol1 });
await send(ec2.DeleteVolumeCommand, { VolumeId: vol2 });
await send(ec2.DeleteSubnetCommand, { SubnetId: subnet });
await send(ec2.DeleteVpcCommand, { VpcId: vpc });
