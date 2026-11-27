#!/bin/bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The AWS interop bundle (.kiro/specs/redis-general-data-types/
# Requirement 25.2), run by .github/workflows/redis-aws-interop.yml with the
# role scripts/ci-cloud-credentials/aws/redis-interop/ provisions. It
# creates the smallest ElastiCache Serverless caches (Valkey and Redis OSS)
# and MemoryDB cluster (Valkey, one db.t4g.small node), then a runner
# instance in the same VPC (both services are VPC-only) that records the
# differential streams, runs the client library suites and checks an IAM
# auth token (runner-job.sh). It compares the suites with Kythira's run,
# estimates the cost, and deletes everything it made, including on failure
# or cancellation. A resource it could not delete fails the run and is
# listed in $OUT/leftovers.txt.
#
# Every run needs Clark's go in his own words (the workflow's environment
# asks for a reviewer as well).
#
# Environment:
#   AWS_REGION              where to run (the role's credentials come from
#                           the workflow)
#   RUN_TAG                 unique, lowercase, short (the workflow's run id)
#   IMAGES_TAR              docker save of kythira-redis-clients:interop and
#                           kythira-redis-recorder:interop, gzip
#   KYTHIRA_CLIENT_REPORTS  directory of Kythira's client suite reports
#                           (redis-module.yml's artifact), may be empty
#   OUT                     output directory
#   RUNNER_MINUTES          how long to wait for the runner (default 75)

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
region=${AWS_REGION:?}
tag=${RUN_TAG:?}
out=${OUT:?}
images=${IMAGES_TAR:?}
reports=${KYTHIRA_CLIENT_REPORTS:-}
runner_minutes=${RUNNER_MINUTES:-75}
prefix="kyt-ri-$tag"
tags="Key=kythira:redis-interop,Value=$tag"
mkdir -p "$out"
started=$(date +%s)

account=$(aws sts get-caller-identity --query Account --output text)
bucket="$prefix-$account"
password=$(openssl rand -hex 24)
instance=""
sg=""

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ── teardown: everything named after this run, whatever state it got to ─────
# shellcheck disable=SC2329  # run by the EXIT trap
teardown() {
    set +e
    log "teardown"
    [ -n "$instance" ] && aws ec2 terminate-instances --instance-ids "$instance" >/dev/null
    for engine in valkey redis; do
        aws elasticache delete-serverless-cache --serverless-cache-name "$prefix-$engine" \
            >/dev/null 2>&1
    done
    aws memorydb delete-cluster --cluster-name "$prefix" >/dev/null 2>&1
    # Users and groups go once nothing uses them.
    local deadline=$(($(date +%s) + 1800))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local busy=0
        for engine in valkey redis; do
            aws elasticache describe-serverless-caches --serverless-cache-name "$prefix-$engine" \
                >/dev/null 2>&1 && busy=1
        done
        aws memorydb describe-clusters --cluster-name "$prefix" >/dev/null 2>&1 && busy=1
        [ "$busy" = 0 ] && break
        sleep 20
    done
    for engine in valkey redis; do
        aws elasticache delete-user-group --user-group-id "$prefix-$engine" >/dev/null 2>&1
    done
    sleep 30
    for u in "$prefix-valkey-app" "$prefix-valkey-iam" "$prefix-redis-app" "$prefix-redis-iam" \
        "$prefix-redis-default"; do
        aws elasticache delete-user --user-id "$u" >/dev/null 2>&1
    done
    aws memorydb delete-acl --acl-name "$prefix" >/dev/null 2>&1
    aws memorydb delete-user --user-name "$prefix-app" >/dev/null 2>&1
    aws memorydb delete-subnet-group --subnet-group-name "$prefix" >/dev/null 2>&1
    if [ -n "$instance" ]; then
        aws ec2 wait instance-terminated --instance-ids "$instance"
    fi
    if [ -n "$sg" ]; then
        # Interfaces of deleted caches linger for a few minutes.
        for _ in $(seq 1 30); do
            aws ec2 delete-security-group --group-id "$sg" >/dev/null 2>&1 && break
            sleep 20
        done
    fi
    aws s3 rb "s3://$bucket" --force >/dev/null 2>&1

    # What is still there fails the run.
    : >"$out/leftovers.txt"
    for engine in valkey redis; do
        aws elasticache describe-serverless-caches --serverless-cache-name "$prefix-$engine" \
            >/dev/null 2>&1 && echo "serverless cache $prefix-$engine" >>"$out/leftovers.txt"
        aws elasticache describe-user-groups --user-group-id "$prefix-$engine" >/dev/null 2>&1 &&
            echo "user group $prefix-$engine" >>"$out/leftovers.txt"
    done
    aws elasticache describe-users --query "Users[?starts_with(UserId, '$prefix')].UserId" \
        --output text | tr '\t' '\n' | sed '/^$/d; s/^/elasticache user /' >>"$out/leftovers.txt"
    aws memorydb describe-clusters --cluster-name "$prefix" >/dev/null 2>&1 &&
        echo "memorydb cluster $prefix" >>"$out/leftovers.txt"
    aws memorydb describe-acls --acl-name "$prefix" >/dev/null 2>&1 &&
        echo "memorydb acl $prefix" >>"$out/leftovers.txt"
    aws memorydb describe-users --user-name "$prefix-app" >/dev/null 2>&1 &&
        echo "memorydb user $prefix-app" >>"$out/leftovers.txt"
    aws memorydb describe-subnet-groups --subnet-group-name "$prefix" >/dev/null 2>&1 &&
        echo "memorydb subnet group $prefix" >>"$out/leftovers.txt"
    if [ -n "$sg" ] && aws ec2 describe-security-groups --group-ids "$sg" >/dev/null 2>&1; then
        echo "security group $sg" >>"$out/leftovers.txt"
    fi
    aws s3api head-bucket --bucket "$bucket" >/dev/null 2>&1 &&
        echo "bucket $bucket" >>"$out/leftovers.txt"

    python3 "$here/aws_helpers.py" cost --started "$started" --ended "$(date +%s)" \
        >"$out/cost.md"
    cat "$out/cost.md"
    if [ -s "$out/leftovers.txt" ]; then
        echo "::error::resources left behind (delete them by hand):"
        cat "$out/leftovers.txt"
        exit 1
    fi
    log "everything deleted"
}
trap teardown EXIT

# ── network ─────────────────────────────────────────────────────────────────
vpc=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
    --query 'Vpcs[0].VpcId' --output text)
read -r -a subnets <<<"$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$vpc" Name=default-for-az,Values=true \
    --query 'Subnets[].SubnetId' --output text)"
# The runner goes in a subnet whose zone offers its instance type.
runner_subnet=""
for z in $(aws ec2 describe-instance-type-offerings --location-type availability-zone     --filters Name=instance-type,Values=t3.small --query 'InstanceTypeOfferings[].Location'     --output text); do
    runner_subnet=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc"         Name=default-for-az,Values=true "Name=availability-zone,Values=$z"         --query 'Subnets[0].SubnetId' --output text)
    [ "$runner_subnet" != None ] && break
done
log "default VPC $vpc, subnets ${subnets[*]}, runner in $runner_subnet"
sg=$(aws ec2 create-security-group --group-name "$prefix" --vpc-id "$vpc" \
    --description "Kythira Redis interop run $tag" \
    --tag-specifications "ResourceType=security-group,Tags=[{$tags}]" \
    --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$sg" \
    --ip-permissions "IpProtocol=tcp,FromPort=6379,ToPort=6380,UserIdGroupPairs=[{GroupId=$sg}]" \
    >/dev/null

# ── ElastiCache Serverless, both engines ────────────────────────────────────
for engine in valkey redis; do
    aws elasticache create-user --user-id "$prefix-$engine-app" --user-name app \
        --engine "$engine" --passwords "$password" --access-string "on ~* &* +@all" \
        --tags "$tags" >/dev/null
    # IAM users' names equal their ids.
    aws elasticache create-user --user-id "$prefix-$engine-iam" --user-name "$prefix-$engine-iam" \
        --engine "$engine" --authentication-mode Type=iam --access-string "on ~* &* +@all" \
        --tags "$tags" >/dev/null
done
# A Redis OSS user group needs a user named default.
aws elasticache create-user --user-id "$prefix-redis-default" --user-name default \
    --engine redis --no-password-required --access-string "off ~* -@all" --tags "$tags" >/dev/null
aws elasticache create-user-group --user-group-id "$prefix-valkey" --engine valkey \
    --user-ids "$prefix-valkey-app" "$prefix-valkey-iam" --tags "$tags" >/dev/null
aws elasticache create-user-group --user-group-id "$prefix-redis" --engine redis \
    --user-ids "$prefix-redis-default" "$prefix-redis-app" "$prefix-redis-iam" \
    --tags "$tags" >/dev/null
for engine in valkey redis; do
    aws elasticache wait user-group-active --user-group-id "$prefix-$engine" 2>/dev/null ||
        sleep 60
done
aws elasticache create-serverless-cache --serverless-cache-name "$prefix-valkey" \
    --engine valkey --major-engine-version 8 --subnet-ids "${subnets[@]:0:3}" \
    --security-group-ids "$sg" --user-group-id "$prefix-valkey" \
    --cache-usage-limits 'DataStorage={Maximum=1,Unit=GB},ECPUPerSecond={Maximum=5000}' \
    --tags "$tags" >/dev/null
aws elasticache create-serverless-cache --serverless-cache-name "$prefix-redis" \
    --engine redis --major-engine-version 7 --subnet-ids "${subnets[@]:0:3}" \
    --security-group-ids "$sg" --user-group-id "$prefix-redis" \
    --cache-usage-limits 'DataStorage={Maximum=1,Unit=GB},ECPUPerSecond={Maximum=5000}' \
    --tags "$tags" >/dev/null
log "ElastiCache Serverless caches requested"

# ── MemoryDB, Valkey, one node ──────────────────────────────────────────────
aws memorydb create-user --user-name "$prefix-app" --access-string "on ~* &* +@all" \
    --authentication-mode "Type=password,Passwords=$password" --tags "$tags" >/dev/null
aws memorydb create-acl --acl-name "$prefix" --user-names "$prefix-app" --tags "$tags" >/dev/null
aws memorydb create-subnet-group --subnet-group-name "$prefix" --subnet-ids "${subnets[@]}" \
    --tags "$tags" >/dev/null
aws memorydb create-cluster --cluster-name "$prefix" --node-type db.t4g.small --engine valkey \
    --acl-name "$prefix" --num-shards 1 --num-replicas-per-shard 0 \
    --subnet-group-name "$prefix" --security-group-ids "$sg" --tls-enabled \
    --tags "$tags" >/dev/null
log "MemoryDB cluster requested"

# ── the images, where the runner can fetch them ─────────────────────────────
aws s3 mb "s3://$bucket" >/dev/null
aws s3api put-bucket-tagging --bucket "$bucket" \
    --tagging "TagSet=[{Key=kythira:redis-interop,Value=$tag}]"
aws s3 cp --only-show-errors "$images" "s3://$bucket/images.tar.gz"
images_url=$(aws s3 presign "s3://$bucket/images.tar.gz" --expires-in 10800)
results_url=$(python3 "$here/aws_helpers.py" presign-put --bucket "$bucket" \
    --key results.tar.gz)

# ── wait for the three endpoints ────────────────────────────────────────────
wait_for() {  # description, command printing the status
    local what=$1
    shift
    for _ in $(seq 1 120); do
        local status
        status=$("$@" 2>/dev/null || echo "?")
        [ "$status" = available ] && return 0
        sleep 20
    done
    echo "::error::$what never became available"
    return 1
}
for engine in valkey redis; do
    wait_for "$prefix-$engine" aws elasticache describe-serverless-caches \
        --serverless-cache-name "$prefix-$engine" --query 'ServerlessCaches[0].Status' \
        --output text
done
wait_for "$prefix (MemoryDB)" aws memorydb describe-clusters --cluster-name "$prefix" \
    --query 'Clusters[0].Status' --output text
log "all three endpoints available"

targets=""
iam_targets=""
iam_vars=""
for engine in valkey redis; do
    read -r host port version <<<"$(aws elasticache describe-serverless-caches \
        --serverless-cache-name "$prefix-$engine" \
        --query 'ServerlessCaches[0].[Endpoint.Address,Endpoint.Port,FullEngineVersion]' \
        --output text)"
    targets="$targets elasticache-$engine:$host:$port:app:${engine}_$version"
    token=$(python3 "$here/aws_helpers.py" iam-token --cache "$prefix-$engine" \
        --user "$prefix-$engine-iam" --region "$region" --serverless)
    iam_targets="$iam_targets elasticache-$engine:$host:$port:$prefix-$engine-iam:TOKEN_${engine^^}"
    iam_vars="${iam_vars}TOKEN_${engine^^}='$token'"$'\n'
done
read -r host port version <<<"$(aws memorydb describe-clusters --cluster-name "$prefix" \
    --query 'Clusters[0].[ClusterEndpoint.Address,ClusterEndpoint.Port,EngineVersion]' \
    --output text)"
targets="$targets memorydb:$host:$port:$prefix-app:valkey_$version"

# ── the runner ──────────────────────────────────────────────────────────────
userdata=$(mktemp)
{
    echo '#!/bin/bash'
    echo "IMAGES_URL='$images_url'"
    echo "RESULTS_URL='$results_url'"
    echo "TARGETS='${targets# }'"
    echo "IAM_TARGETS='${iam_targets# }'"
    echo "PASSWORD='$password'"
    echo "export PASSWORD"
    printf '%s' "$iam_vars"
    tail -n +2 "$here/runner-job.sh"
} >"$userdata"
ami=$(aws ssm get-parameter \
    --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
    --query Parameter.Value --output text)
instance=$(aws ec2 run-instances --image-id "$ami" --instance-type t3.small \
    --subnet-id "$runner_subnet" --security-group-ids "$sg" --associate-public-ip-address \
    --instance-initiated-shutdown-behavior terminate \
    --metadata-options HttpTokens=required \
    --user-data "file://$userdata" \
    --tag-specifications "ResourceType=instance,Tags=[{$tags},{Key=Name,Value=$prefix}]" \
    --query 'Instances[0].InstanceId' --output text)
rm -f "$userdata"
log "runner $instance launched; waiting up to $runner_minutes minutes for its results"

deadline=$(($(date +%s) + runner_minutes * 60))
until aws s3api head-object --bucket "$bucket" --key results.tar.gz >/dev/null 2>&1; do
    if [ "$(date +%s)" -gt "$deadline" ]; then
        aws ec2 get-console-output --instance-id "$instance" --latest --output text \
            >"$out/runner-console.txt" 2>&1 || true
        echo "::error::the runner sent no results in $runner_minutes minutes"
        exit 1
    fi
    sleep 30
done
aws s3 cp --only-show-errors "s3://$bucket/results.tar.gz" "$out/results.tar.gz"
tar xzf "$out/results.tar.gz" -C "$out"
log "results in $out"

# ── report ──────────────────────────────────────────────────────────────────
{
    echo "# Redis AWS interop run $tag"
    echo
    echo "Targets: ${targets# }" | sed 's/:[^ ]*:[0-9]*:[^ :]*:/ /g'
    echo
    echo "## IAM auth tokens"
    for f in "$out"/iam/*.txt; do
        [ -e "$f" ] && echo "- $(basename "$f" .txt): $(tail -1 "$f")"
    done
    echo
    [ -s "$out/failures.txt" ] && { echo "## Failures"; sed 's/^/- /' "$out/failures.txt"; echo; }
    for d in "$out"/clients/*/; do
        name=$(basename "$d")
        if [ -n "$reports" ] && [ -d "$reports" ]; then
            python3 "$here/aws_helpers.py" compare-junit "$reports" "$d" "$name"
        fi
        echo "ioredis on $name: $(grep -E 'passing|failing' "$d/output.txt" | tr '\n' ' ')"
        echo
    done
} >"$out/report.md"
cat "$out/report.md"
grep -q FAILED "$out"/iam/*.txt && {
    echo "::error::an IAM auth token was refused"
    exit 1
}
[ -s "$out/failures.txt" ] && exit 1
exit 0
