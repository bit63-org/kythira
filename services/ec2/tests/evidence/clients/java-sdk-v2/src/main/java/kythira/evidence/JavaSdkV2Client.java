// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

package kythira.evidence;

import java.net.URI;
import java.util.List;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.BlockDeviceMapping;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.ResourceType;
import software.amazon.awssdk.services.ec2.model.RunInstancesRequest;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.model.TagSpecification;
import software.amazon.awssdk.services.ec2.model.VolumeType;

/** The evidence scenario through aws-sdk-java-v2 (README.md). Usage: JavaSdkV2Client ENDPOINT */
public final class JavaSdkV2Client {
    /** The SDK sends UserData as given, so it is base64 here (boto3 and the CLI encode it). */
    private static final String USER_DATA = "IyEvYmluL3NoCmVjaG8gaGVsbG8K";
    private static final String ZONE = "us-east-1a";

    private JavaSdkV2Client() {}

    private static Tag tag(String k, String v) {
        return Tag.builder().key(k).value(v).build();
    }

    private static Filter filter(String name, String... values) {
        return Filter.builder().name(name).values(values).build();
    }

    private static TagSpecification spec(ResourceType type, Tag... tags) {
        return TagSpecification.builder().resourceType(type).tags(tags).build();
    }

    private static void expectError(String code, Runnable call) {
        try {
            call.run();
        } catch (Ec2Exception e) {
            if (!code.equals(e.awsErrorDetails().errorCode())) {
                throw e;
            }
            return;
        }
        throw new IllegalStateException("expected " + code);
    }

    public static void main(String[] args) {
        try (Ec2Client c = Ec2Client.builder()
                .endpointOverride(URI.create(args[0]))
                .region(Region.US_EAST_1)
                .httpClient(UrlConnectionHttpClient.create())
                .build()) {
            c.describeRegions(b -> b.regionNames("us-east-1"));
            c.describeAvailabilityZones(b -> b.filters(filter("state", "available")));
            String vpc = c.createVpc(b -> b.cidrBlock("10.0.0.0/16").tagSpecifications(
                    spec(ResourceType.VPC, tag("Name", "evidence"), tag("team", "kythira"))))
                    .vpc().vpcId();
            String subnet = c.createSubnet(b -> b.vpcId(vpc).cidrBlock("10.0.1.0/24")
                    .availabilityZone(ZONE)).subnet().subnetId();
            c.describeVpcs(b -> b.vpcIds(vpc).filters(filter("tag:Name", "evidence")));
            String vol1 = c.createVolume(b -> b.availabilityZone(ZONE).size(8)
                    .volumeType(VolumeType.GP3).encrypted(true).clientToken("evidence-volume-1")
                    .tagSpecifications(spec(ResourceType.VOLUME, tag("Name", "evidence-data"))))
                    .volumeId();
            String vol2 = c.createVolume(b -> b.availabilityZone(ZONE).size(16)
                    .volumeType(VolumeType.GP3).iops(3000).throughput(125)).volumeId();
            Filter zone = filter("availability-zone", ZONE);
            String token = c.describeVolumes(b -> b.filters(zone).maxResults(5)).nextToken();
            c.describeVolumes(b -> b.filters(zone).maxResults(5).nextToken(token));
            RunInstancesRequest.Builder run = RunInstancesRequest.builder()
                    .imageId("ami-0000000000000a001").instanceType("t3.micro").minCount(1)
                    .maxCount(2).subnetId(subnet).userData(USER_DATA)
                    .blockDeviceMappings(
                            BlockDeviceMapping.builder().deviceName("/dev/xvda").ebs(e -> e
                                    .volumeSize(8).volumeType(VolumeType.GP3)
                                    .deleteOnTermination(true)).build(),
                            BlockDeviceMapping.builder().deviceName("/dev/sdb")
                                    .virtualName("ephemeral0").build())
                    .tagSpecifications(spec(ResourceType.INSTANCE, tag("Name", "evidence")),
                            spec(ResourceType.VOLUME, tag("Name", "evidence-root")));
            List<String> ids = c.runInstances(run.copy().clientToken("evidence-run-1").build())
                    .instances().stream().map(Instance::instanceId).toList();
            expectError("DryRunOperation", () -> c.runInstances(run.copy().dryRun(true).build()));
            c.describeInstances(b -> b.instanceIds(ids)
                    .filters(filter("instance-state-name", "pending", "running")));
            c.createTags(b -> b.resources(ids.get(0), vol1)
                    .tags(tag("stage", "evidence"), Tag.builder().key("flag").build()));
            c.describeTags(b -> b.filters(filter("resource-id", ids.get(0)), filter("key", "stage")));
            c.deleteTags(b -> b.resources(vol1).tags(Tag.builder().key("flag").build()));
            c.attachVolume(b -> b.volumeId(vol1).instanceId(ids.get(0)).device("/dev/sdf"));
            c.detachVolume(b -> b.volumeId(vol1));
            c.stopInstances(b -> b.instanceIds(ids.get(0)));
            c.startInstances(b -> b.instanceIds(ids.get(0)));
            c.terminateInstances(b -> b.instanceIds(ids));
            expectError("UnsupportedOperation", () -> c.createSecurityGroup(b -> b
                    .groupName("evidence").description("evidence group").vpcId(vpc)));
            c.deleteVolume(b -> b.volumeId(vol1));
            c.deleteVolume(b -> b.volumeId(vol2));
            c.deleteSubnet(b -> b.subnetId(subnet));
            c.deleteVpc(b -> b.vpcId(vpc));
        }
    }
}
