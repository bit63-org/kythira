// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The evidence scenario through the AWS SDK for Go v2 (README.md).
// Usage: go run . ENDPOINT
package main

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// The SDK sends UserData as given, so it is base64 here (boto3 and the CLI
// encode it themselves).
const userData = "IyEvYmluL3NoCmVjaG8gaGVsbG8K"

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func expectError(code string, err error) {
	var api smithy.APIError
	if !errors.As(err, &api) || api.ErrorCode() != code {
		log.Fatalf("expected %s, got %v", code, err)
	}
}

func tag(k, v string) types.Tag { return types.Tag{Key: aws.String(k), Value: aws.String(v)} }

func filter(name string, values ...string) types.Filter {
	return types.Filter{Name: aws.String(name), Values: values}
}

func main() {
	ctx := context.Background()
	zone := "us-east-1a"
	cfg := must(config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1")))
	c := ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.BaseEndpoint = aws.String(os.Args[1]) })

	must(c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{RegionNames: []string{"us-east-1"}}))
	must(c.DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{
		Filters: []types.Filter{filter("state", "available")}}))
	vpc := must(c.CreateVpc(ctx, &ec2.CreateVpcInput{
		CidrBlock: aws.String("10.0.0.0/16"),
		TagSpecifications: []types.TagSpecification{{ResourceType: types.ResourceTypeVpc,
			Tags: []types.Tag{tag("Name", "evidence"), tag("team", "kythira")}}},
	})).Vpc.VpcId
	subnet := must(c.CreateSubnet(ctx, &ec2.CreateSubnetInput{VpcId: vpc,
		CidrBlock: aws.String("10.0.1.0/24"), AvailabilityZone: aws.String(zone)})).Subnet.SubnetId
	must(c.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{*vpc},
		Filters: []types.Filter{filter("tag:Name", "evidence")}}))
	vol1 := must(c.CreateVolume(ctx, &ec2.CreateVolumeInput{AvailabilityZone: aws.String(zone),
		Size: aws.Int32(8), VolumeType: types.VolumeTypeGp3, Encrypted: aws.Bool(true),
		ClientToken: aws.String("evidence-volume-1"),
		TagSpecifications: []types.TagSpecification{{ResourceType: types.ResourceTypeVolume,
			Tags: []types.Tag{tag("Name", "evidence-data")}}},
	})).VolumeId
	vol2 := must(c.CreateVolume(ctx, &ec2.CreateVolumeInput{AvailabilityZone: aws.String(zone),
		Size: aws.Int32(16), VolumeType: types.VolumeTypeGp3, Iops: aws.Int32(3000),
		Throughput: aws.Int32(125)})).VolumeId
	zoneFilter := []types.Filter{filter("availability-zone", zone)}
	page := must(c.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{Filters: zoneFilter,
		MaxResults: aws.Int32(5)}))
	must(c.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{Filters: zoneFilter,
		MaxResults: aws.Int32(5), NextToken: page.NextToken}))
	run := func(token *string, dryRun *bool) (*ec2.RunInstancesOutput, error) {
		return c.RunInstances(ctx, &ec2.RunInstancesInput{
			ImageId: aws.String("ami-0000000000000a001"), InstanceType: types.InstanceTypeT3Micro,
			MinCount: aws.Int32(1), MaxCount: aws.Int32(2), SubnetId: subnet,
			ClientToken: token, DryRun: dryRun, UserData: aws.String(userData),
			BlockDeviceMappings: []types.BlockDeviceMapping{
				{DeviceName: aws.String("/dev/xvda"), Ebs: &types.EbsBlockDevice{
					VolumeSize: aws.Int32(8), VolumeType: types.VolumeTypeGp3,
					DeleteOnTermination: aws.Bool(true)}},
				{DeviceName: aws.String("/dev/sdb"), VirtualName: aws.String("ephemeral0")}},
			TagSpecifications: []types.TagSpecification{
				{ResourceType: types.ResourceTypeInstance, Tags: []types.Tag{tag("Name", "evidence")}},
				{ResourceType: types.ResourceTypeVolume, Tags: []types.Tag{tag("Name", "evidence-root")}}},
		})
	}
	var ids []string
	for _, i := range must(run(aws.String("evidence-run-1"), nil)).Instances {
		ids = append(ids, *i.InstanceId)
	}
	_, err := run(nil, aws.Bool(true))
	expectError("DryRunOperation", err)
	must(c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: ids,
		Filters: []types.Filter{filter("instance-state-name", "pending", "running")}}))
	must(c.CreateTags(ctx, &ec2.CreateTagsInput{Resources: []string{ids[0], *vol1},
		Tags: []types.Tag{tag("stage", "evidence"), {Key: aws.String("flag")}}}))
	must(c.DescribeTags(ctx, &ec2.DescribeTagsInput{Filters: []types.Filter{
		filter("resource-id", ids[0]), filter("key", "stage")}}))
	must(c.DeleteTags(ctx, &ec2.DeleteTagsInput{Resources: []string{*vol1},
		Tags: []types.Tag{{Key: aws.String("flag")}}}))
	must(c.AttachVolume(ctx, &ec2.AttachVolumeInput{VolumeId: vol1, InstanceId: aws.String(ids[0]),
		Device: aws.String("/dev/sdf")}))
	must(c.DetachVolume(ctx, &ec2.DetachVolumeInput{VolumeId: vol1}))
	must(c.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: ids[:1]}))
	must(c.StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: ids[:1]}))
	must(c.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: ids}))
	_, err = c.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{GroupName: aws.String("evidence"),
		Description: aws.String("evidence group"), VpcId: vpc})
	expectError("UnsupportedOperation", err)
	must(c.DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: vol1}))
	must(c.DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: vol2}))
	must(c.DeleteSubnet(ctx, &ec2.DeleteSubnetInput{SubnetId: subnet}))
	must(c.DeleteVpc(ctx, &ec2.DeleteVpcInput{VpcId: vpc}))
}
