#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Provisions the IAM role .github/workflows/redis-aws-interop.yml assumes
# (.kiro/specs/redis-general-data-types/ Requirement 25.2): trusted only by
# GitHub's OIDC provider for jobs that declare the `redis-aws-interop`
# environment, with policy.json's permissions (ElastiCache Serverless,
# MemoryDB, one runner instance, a bucket, all named kyt-ri-*). It is a role
# of its own, not a bundle of the real-cloud-tests role, whose inline policy
# is within a few characters of IAM's 10,240-character limit.
#
# Run locally, once, with IAM-admin credentials. Then:
#   gh variable set AWS_REDIS_INTEROP_ROLE_ARN --body <the ARN printed>
#   gh variable set REDIS_AWS_INTEROP_ENABLED --body true
# and create the `redis-aws-interop` environment with Clark as its required
# reviewer, so that every run waits for his approval.
#
# Usage: provision-role.sh --github-org ORG --github-repo REPO [--role-name N] [--dry-run]

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OIDC_PROVIDER_URL="token.actions.githubusercontent.com"
ROLE_NAME="kythira-ci-redis-aws-interop"
ENVIRONMENT="redis-aws-interop"
GITHUB_ORG=""
GITHUB_REPO=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --github-org) GITHUB_ORG="$2"; shift 2 ;;
        --github-repo) GITHUB_REPO="$2"; shift 2 ;;
        --role-name) ROLE_NAME="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) sed -n '4,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done
if [[ -z "${GITHUB_ORG}" || -z "${GITHUB_REPO}" ]]; then
    echo "ERROR: --github-org and --github-repo are required" >&2
    exit 1
fi

run() {
    if [[ "${DRY_RUN}" == 1 ]]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER_URL}"
if ! aws iam get-open-id-connect-provider --open-id-connect-provider-arn "${PROVIDER_ARN}" \
    >/dev/null 2>&1; then
    echo "ERROR: no GitHub OIDC provider in ${ACCOUNT_ID}; run ../provision-oidc-role.sh first" >&2
    exit 1
fi

SUBJECT="repo:${GITHUB_ORG}/${GITHUB_REPO}:environment:${ENVIRONMENT}"
TRUST=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": "${PROVIDER_ARN}"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {
            "${OIDC_PROVIDER_URL}:aud": "sts.amazonaws.com",
            "${OIDC_PROVIDER_URL}:sub": "${SUBJECT}"
        }}
    }]
}
EOF
)
POLICY=$(sed "s/{{ACCOUNT_ID}}/${ACCOUNT_ID}/g" "${HERE}/policy.json")

echo "role ${ROLE_NAME}, trusted subject ${SUBJECT}"
if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    run aws iam update-assume-role-policy --role-name "${ROLE_NAME}" --policy-document "${TRUST}"
else
    # Three hours: MemoryDB alone takes about 20 minutes each way.
    run aws iam create-role --role-name "${ROLE_NAME}" --assume-role-policy-document "${TRUST}" \
        --max-session-duration 10800 \
        --description "Kythira Redis AWS interop bundle (redis-general-data-types Requirement 25)"
fi
run aws iam put-role-policy --role-name "${ROLE_NAME}" --policy-name "${ROLE_NAME}-policy" \
    --policy-document "${POLICY}"
[[ "${DRY_RUN}" == 1 ]] && exit 0
echo "role ARN: $(aws iam get-role --role-name "${ROLE_NAME}" --query Role.Arn --output text)"
