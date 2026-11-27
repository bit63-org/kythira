#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The evidence scenario through the AWS CLI v2 (`aws` on PATH, or $AWS_CLI).
# README.md lists the steps; every client runs the same ones.
# Usage: awscli_v2.sh ENDPOINT
set -euo pipefail
endpoint=$1
aws=${AWS_CLI:-aws}
e() { "$aws" --endpoint-url "$endpoint" --no-cli-pager --output json ec2 "$@"; }
q() { e "$@" >/dev/null; }
t() { e "$@" --output text; }
# Runs a call that must fail with the error code $1.
expect_error() {
    local code=$1 err
    shift
    if err=$(e "$@" 2>&1 >/dev/null); then
        echo "$* succeeded; expected $code" >&2
        exit 1
    fi
    grep -q "($code)" <<<"$err" || { echo "$err" >&2; exit 1; }
}
zone=us-east-1a
# The CLI base64-encodes --user-data itself.
user_data=$'#!/bin/sh\necho hello\n'
bdm='[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":8,"VolumeType":"gp3","DeleteOnTermination":true}},
      {"DeviceName":"/dev/sdb","VirtualName":"ephemeral0"}]'
run_tags='ResourceType=instance,Tags=[{Key=Name,Value=evidence}]'
root_tags='ResourceType=volume,Tags=[{Key=Name,Value=evidence-root}]'

q describe-regions --region-names us-east-1
q describe-availability-zones --filters Name=state,Values=available
vpc=$(t create-vpc --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=evidence},{Key=team,Value=kythira}]' \
  --query Vpc.VpcId)
subnet=$(t create-subnet --vpc-id "$vpc" --cidr-block 10.0.1.0/24 --availability-zone "$zone" \
  --query Subnet.SubnetId)
q describe-vpcs --vpc-ids "$vpc" --filters Name=tag:Name,Values=evidence
vol1=$(t create-volume --availability-zone "$zone" --size 8 --volume-type gp3 --encrypted \
  --client-token evidence-volume-1 \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=evidence-data}]' \
  --query VolumeId)
vol2=$(t create-volume --availability-zone "$zone" --size 16 --volume-type gp3 --iops 3000 \
  --throughput 125 --query VolumeId)
token=$(t describe-volumes --filters "Name=availability-zone,Values=$zone" --max-results 5 \
  --no-paginate --query NextToken)
q describe-volumes --filters "Name=availability-zone,Values=$zone" --max-results 5 \
  --next-token "$token" --no-paginate
# shellcheck disable=SC2207 # instance ids have no spaces or globs
ids=($(t run-instances --image-id ami-0000000000000a001 --instance-type t3.micro \
  --count 1:2 --subnet-id "$subnet" --client-token evidence-run-1 \
  --user-data "$user_data" --block-device-mappings "$bdm" \
  --tag-specifications "$run_tags" "$root_tags" --query 'Instances[].InstanceId'))
expect_error DryRunOperation run-instances --image-id ami-0000000000000a001 \
  --instance-type t3.micro --count 1:2 --subnet-id "$subnet" \
  --user-data "$user_data" --block-device-mappings "$bdm" \
  --tag-specifications "$run_tags" "$root_tags" --dry-run
q describe-instances --instance-ids "${ids[@]}" \
  --filters Name=instance-state-name,Values=pending,running
q create-tags --resources "${ids[0]}" "$vol1" --tags Key=stage,Value=evidence Key=flag
q describe-tags --filters "Name=resource-id,Values=${ids[0]}" Name=key,Values=stage
q delete-tags --resources "$vol1" --tags Key=flag
q attach-volume --volume-id "$vol1" --instance-id "${ids[0]}" --device /dev/sdf
q detach-volume --volume-id "$vol1"
q stop-instances --instance-ids "${ids[0]}"
q start-instances --instance-ids "${ids[0]}"
q terminate-instances --instance-ids "${ids[@]}"
expect_error UnsupportedOperation create-security-group --group-name evidence \
  --description "evidence group" --vpc-id "$vpc"
q delete-volume --volume-id "$vol1"
q delete-volume --volume-id "$vol2"
q delete-subnet --subnet-id "$subnet"
q delete-vpc --vpc-id "$vpc"
