#!/usr/bin/env python3
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

"""The evidence scenario through boto3. README.md lists the steps; every
client runs the same ones. Usage: boto3_client.py ENDPOINT"""

import sys

import boto3
import botocore.exceptions

USER_DATA = "#!/bin/sh\necho hello\n"  # boto3 base64-encodes it for RunInstances


def expect_error(code, call, **kwargs):
    try:
        call(**kwargs)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != code:
            raise
        return
    raise SystemExit(f"{call.__name__} succeeded; expected {code}")


def main():
    ec2 = boto3.client("ec2", endpoint_url=sys.argv[1], region_name="us-east-1")
    zone = "us-east-1a"
    ec2.describe_regions(RegionNames=["us-east-1"])
    ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=[{
        "ResourceType": "vpc",
        "Tags": [{"Key": "Name", "Value": "evidence"}, {"Key": "team", "Value": "kythira"}]}])
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24",
                                  AvailabilityZone=zone)["Subnet"]["SubnetId"]
    ec2.describe_vpcs(VpcIds=[vpc_id], Filters=[{"Name": "tag:Name", "Values": ["evidence"]}])
    vol1 = ec2.create_volume(AvailabilityZone=zone, Size=8, VolumeType="gp3", Encrypted=True,
                             ClientToken="evidence-volume-1", TagSpecifications=[{
                                 "ResourceType": "volume",
                                 "Tags": [{"Key": "Name", "Value": "evidence-data"}]}])["VolumeId"]
    vol2 = ec2.create_volume(AvailabilityZone=zone, Size=16, VolumeType="gp3", Iops=3000,
                             Throughput=125)["VolumeId"]
    zone_filter = [{"Name": "availability-zone", "Values": [zone]}]
    page = ec2.describe_volumes(Filters=zone_filter, MaxResults=5)
    ec2.describe_volumes(Filters=zone_filter, MaxResults=5, NextToken=page["NextToken"])
    run = dict(
        ImageId="ami-0000000000000a001", InstanceType="t3.micro", MinCount=1, MaxCount=2,
        SubnetId=subnet_id, UserData=USER_DATA,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/xvda",
             "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}},
            {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"}],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "evidence"}]},
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": "evidence-root"}]}])
    ids = [i["InstanceId"] for i in ec2.run_instances(ClientToken="evidence-run-1",
                                                       **run)["Instances"]]
    expect_error("DryRunOperation", ec2.run_instances, DryRun=True, **run)
    ec2.describe_instances(InstanceIds=ids, Filters=[
        {"Name": "instance-state-name", "Values": ["pending", "running"]}])
    ec2.create_tags(Resources=[ids[0], vol1],
                    Tags=[{"Key": "stage", "Value": "evidence"}, {"Key": "flag"}])
    ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [ids[0]]},
                               {"Name": "key", "Values": ["stage"]}])
    ec2.delete_tags(Resources=[vol1], Tags=[{"Key": "flag"}])
    ec2.attach_volume(VolumeId=vol1, InstanceId=ids[0], Device="/dev/sdf")
    ec2.detach_volume(VolumeId=vol1)
    ec2.stop_instances(InstanceIds=[ids[0]])
    ec2.start_instances(InstanceIds=[ids[0]])
    ec2.terminate_instances(InstanceIds=ids)
    expect_error("UnsupportedOperation", ec2.create_security_group, GroupName="evidence",
                 Description="evidence group", VpcId=vpc_id)
    ec2.delete_volume(VolumeId=vol1)
    ec2.delete_volume(VolumeId=vol2)
    ec2.delete_subnet(SubnetId=subnet_id)
    ec2.delete_vpc(VpcId=vpc_id)


if __name__ == "__main__":
    main()
