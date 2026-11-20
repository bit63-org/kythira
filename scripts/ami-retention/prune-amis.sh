#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Retention for the ca_cluster_node AMIs the `ami-build` bundle registers
# (.kiro/specs/ca-cluster-node-ami-retention/).
#
# Every `ami-build` run registers a new AMI and EBS snapshot per architecture
# and nothing removed them. This script computes a Plan from three read-only
# queries (the candidate images, the instances launched from them, and the
# launch templates naming them), prints it, and with --apply carries it out.
#
# Candidates are AMIs owned by this account and tagged BOTH
# kythira:component=ca-cluster-node and kythira:built-by=packer; nothing else
# is ever considered. They are grouped into classes by (kythira:arch,
# kythira:chaos-node), an image with no chaos-node tag counting as "false".
# Within each class, newest first, an image is KEPT when any of these hold:
#
#   newest-N             it is one of the newest KEEP images of its class
#   younger-than-D-days  it is younger than MIN_AGE days
#   pinned               it is tagged kythira:retain=true
#   in-use               an instance not yet terminated was launched from it,
#                        or the $Latest or $Default version of a launch
#                        template in the region names it
#
# and REMOVED otherwise. Removing deregisters the image, then deletes those of
# its snapshots that are themselves tagged kythira:component=ca-cluster-node;
# any other snapshot in its mappings is listed and left alone.
#
# Failure rules, which are the point of the structure below:
#
#   * Every read goes through aws_json(), which treats a non-zero exit OR
#     output jq cannot parse as a failure. Any failed read aborts the run
#     before anything is mutated: an unknown "in use" set means keep
#     everything. A CLI that exits 0 with a banner on stdout, or an auth
#     failure that prints nothing, must never read as "no instances".
#   * With --apply, every deregister and delete is attempted even after one
#     fails, and the script exits 1 at the end if any did.
#
# Usage:
#   prune-amis.sh [--arch amd64|arm64] [--keep N] [--min-age-days D] [--apply]
#
# The region is the aws CLI's own (AWS_REGION / AWS_DEFAULT_REGION / profile).
# PRUNE_AMIS_NOW (epoch seconds) overrides the clock; the stub test uses it.

set -euo pipefail

ARCH=""
KEEP=2
MIN_AGE_DAYS=7
APPLY=0

usage() {
    cat <<'USAGE'
Usage: prune-amis.sh [--arch amd64|arm64] [--keep N] [--min-age-days D] [--apply]

Prints a retention plan for this account's ca_cluster_node AMIs and, with
--apply, deregisters the images it removes and deletes their snapshots.

  --arch A           only consider images tagged kythira:arch=A (amd64|arm64).
                     Default: every architecture.
  --keep N           newest images kept per class, N >= 1. Default: 2
  --min-age-days D   images younger than D days are always kept. Default: 7
  --apply            act on the plan. Without it, print the plan and exit 0.
  -h, --help         show this help

Images tagged kythira:retain=true are always kept, as are images an instance
or a launch template ($Latest/$Default version) still uses.
USAGE
}

die_usage() {
    echo "prune-amis.sh: $1" >&2
    usage >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) [[ $# -ge 2 ]] || die_usage "--arch needs a value"; ARCH="$2"; shift 2 ;;
        --keep) [[ $# -ge 2 ]] || die_usage "--keep needs a value"; KEEP="$2"; shift 2 ;;
        --min-age-days) [[ $# -ge 2 ]] || die_usage "--min-age-days needs a value"; MIN_AGE_DAYS="$2"; shift 2 ;;
        --apply) APPLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die_usage "unknown argument: $1" ;;
    esac
done

case "${ARCH}" in
    ""|amd64|arm64) ;;
    *) die_usage "--arch must be amd64 or arm64, not '${ARCH}'" ;;
esac
# KEEP >= 1 is what guarantees the real-EC2 bundles' "Resolve ca_cluster_node
# AMI ID" steps always still find an image of their class.
[[ "${KEEP}" =~ ^[0-9]+$ && "${KEEP}" -ge 1 ]] || die_usage "--keep must be an integer >= 1, not '${KEEP}'"
[[ "${MIN_AGE_DAYS}" =~ ^[0-9]+$ ]] || die_usage "--min-age-days must be an integer >= 0, not '${MIN_AGE_DAYS}'"

NOW="${PRUNE_AMIS_NOW:-$(date -u +%s)}"
[[ "${NOW}" =~ ^[0-9]+$ ]] || die_usage "PRUNE_AMIS_NOW must be epoch seconds, not '${NOW}'"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/prune-amis-XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# Runs one read-only aws call and prints its JSON. Aborts the whole run on a
# non-zero exit or on output jq cannot parse. `jq -e .` alone is not used as
# the parse check because it also fails on a literal `null`/`false`; `type`
# succeeds for every valid JSON document and nothing else.
aws_json() {
    local out err rc=0
    err="${WORK}/stderr"
    out=$(aws "$@" --output json 2>"${err}") || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        echo "::error::aws $1 $2 failed (exit ${rc}); nothing was changed:" >&2
        sed 's/^/    /' "${err}" >&2
        exit 1
    fi
    if ! printf '%s' "${out}" | jq -e 'type' >/dev/null 2>&1; then
        echo "::error::aws $1 $2 returned output jq could not read; nothing was changed:" >&2
        printf '%s\n' "${out}" | head -20 | sed 's/^/    /' >&2
        exit 1
    fi
    printf '%s' "${out}"
}

# ── Query 1: the candidates ──────────────────────────────────────────────────
filters=(
    "Name=tag:kythira:component,Values=ca-cluster-node"
    "Name=tag:kythira:built-by,Values=packer"
)
[[ -n "${ARCH}" ]] && filters+=("Name=tag:kythira:arch,Values=${ARCH}")

aws_json ec2 describe-images --owners self --filters "${filters[@]}" > "${WORK}/images.json"

# Re-check the candidate rule locally as well as in the filter. The filter is
# what limits the query, but a stub, a CLI quirk or a typo in the filter must
# never widen what this script may delete.
jq --arg arch "${ARCH}" '
    def tag($k): (.Tags // []) | map(select(.Key == $k)) | (.[0].Value // null);
    [ .Images[]?
      | select(tag("kythira:component") == "ca-cluster-node"
               and tag("kythira:built-by") == "packer"
               and ($arch == "" or tag("kythira:arch") == $arch)) ]
' "${WORK}/images.json" > "${WORK}/candidates.json"

mapfile -t CANDIDATE_IDS < <(jq -r '.[].ImageId' "${WORK}/candidates.json")

echo "ca_cluster_node AMI retention plan (arch=${ARCH:-all}, keep=${KEEP} per class, min-age=${MIN_AGE_DAYS}d, $([[ ${APPLY} -eq 1 ]] && echo apply || echo dry-run))"

if [[ ${#CANDIDATE_IDS[@]} -eq 0 ]]; then
    echo "No candidate images."
    exit 0
fi

# ── Query 2: instances launched from a candidate ─────────────────────────────
# Every state but `terminated`. The image-id filter is chunked because EC2
# caps the number of values one filter may carry.
: > "${WORK}/in-use.tsv"
for ((i = 0; i < ${#CANDIDATE_IDS[@]}; i += 100)); do
    chunk=("${CANDIDATE_IDS[@]:i:100}")
    ids_csv=$(IFS=,; echo "${chunk[*]}")
    aws_json ec2 describe-instances --filters \
        "Name=image-id,Values=${ids_csv}" \
        "Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped" \
        | jq -r '.Reservations[]?.Instances[]? | [.ImageId, .InstanceId] | @tsv' \
        >> "${WORK}/in-use.tsv"
done

# ── Query 3: launch templates naming a candidate ─────────────────────────────
# Only the $Latest and $Default versions: an ASG or fleet launches from one of
# those unless pinned to a numbered version, and reading every version of
# every template is unbounded. A template pinned to an old numbered version
# needs kythira:retain=true on its image (packer/ca_cluster_node/README.md).
aws_json ec2 describe-launch-templates > "${WORK}/lts.json"
mapfile -t LT_IDS < <(jq -r '.LaunchTemplates[]?.LaunchTemplateId' "${WORK}/lts.json")
for lt in "${LT_IDS[@]}"; do
    # shellcheck disable=SC2016  # $Latest / $Default are literal EC2 version names
    aws_json ec2 describe-launch-template-versions --launch-template-id "${lt}" \
        --versions '$Latest' '$Default' \
        | jq -r '.LaunchTemplateVersions[]?
                 | select(.LaunchTemplateData.ImageId != null)
                 | [.LaunchTemplateData.ImageId, "\(.LaunchTemplateId):v\(.VersionNumber)"] | @tsv' \
        >> "${WORK}/in-use.tsv"
done

# ── The plan ─────────────────────────────────────────────────────────────────
# One jq program decides every image, so the rule order lives in one place.
# Any keep rule wins; the order only chooses which reason is printed.
jq -R -s 'split("\n") | map(select(length > 0) | split("\t"))
          | reduce .[] as [$img, $user] ({}; .[$img] += [$user])' \
    "${WORK}/in-use.tsv" > "${WORK}/in-use.json"

jq --slurpfile inuse "${WORK}/in-use.json" \
   --argjson now "${NOW}" --argjson keep "${KEEP}" --argjson min_age_days "${MIN_AGE_DAYS}" '
    def tag($k): (.Tags // []) | map(select(.Key == $k)) | (.[0].Value // null);
    def epoch: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
    ($inuse[0]) as $users
    | map(. + { arch: (tag("kythira:arch") // "unknown"),
                chaos: (if tag("kythira:chaos-node") == "true" then "true" else "false" end) })
    | group_by([.arch, .chaos])
    | map(sort_by(.CreationDate) | reverse | to_entries | map(
        .key as $rank | .value as $img
        | ($now - ($img.CreationDate | epoch)) as $age
        | (if $rank < $keep then "newest-\($keep)"
           elif $age < $min_age_days * 86400 then "younger-than-\($min_age_days)-days"
           elif ($img | tag("kythira:retain")) == "true" then "pinned"
           elif $users[$img.ImageId] then "in-use: \($users[$img.ImageId] | unique | join(" "))"
           else null end) as $why
        | { id: $img.ImageId, arch: $img.arch, chaos: $img.chaos,
            created: $img.CreationDate,
            action: (if $why then "keep" else "remove" end),
            reason: ($why // "older than the newest \($keep) and \($min_age_days) days, unpinned, unused"),
            snapshots: [ $img.BlockDeviceMappings[]?.Ebs.SnapshotId // empty ] }))
    | flatten
' "${WORK}/candidates.json" > "${WORK}/plan.json"

# ── Snapshots of the removed images ──────────────────────────────────────────
mapfile -t REMOVE_SNAPS < <(jq -r '.[] | select(.action == "remove") | .snapshots[]' "${WORK}/plan.json" | sort -u)
echo '{"Snapshots":[]}' > "${WORK}/snapshots.json"
if [[ ${#REMOVE_SNAPS[@]} -gt 0 ]]; then
    aws_json ec2 describe-snapshots --snapshot-ids "${REMOVE_SNAPS[@]}" > "${WORK}/snapshots.json"
fi
# A snapshot is deleted only if it carries kythira:component=ca-cluster-node
# itself (Requirement 1.2). Packer stamps that on every snapshot it makes;
# this only bites for an image someone registered over a shared snapshot.
jq '[ .Snapshots[]?
      | select((.Tags // []) | any(.Key == "kythira:component" and .Value == "ca-cluster-node"))
      | .SnapshotId ]' "${WORK}/snapshots.json" > "${WORK}/owned-snaps.json"

# ── Print the plan ───────────────────────────────────────────────────────────
jq -r --slurpfile owned "${WORK}/owned-snaps.json" '
    ($owned[0]) as $own
    | .[]
    | "\(.action | if . == "keep" then "keep  " else "REMOVE" end)  \(.id)  \(.arch)/chaos-node=\(.chaos)  \(.created)  \(.reason)",
      (select(.action == "remove") | .snapshots[]
       | if (. as $s | $own | any(. == $s)) then "          delete snapshot \(.)"
         else "          leave snapshot \(.) (not tagged kythira:component=ca-cluster-node)" end)
' "${WORK}/plan.json"

n_keep=$(jq '[.[] | select(.action == "keep")] | length' "${WORK}/plan.json")
n_remove=$(jq '[.[] | select(.action == "remove")] | length' "${WORK}/plan.json")
echo "Summary: keep ${n_keep}, remove ${n_remove}."

if [[ ${APPLY} -eq 0 ]]; then
    [[ ${n_remove} -gt 0 ]] && echo "Dry run: nothing changed. Re-run with --apply to remove ${n_remove} image(s)."
    exit 0
fi

# ── Act ──────────────────────────────────────────────────────────────────────
# Deregister every removed image first: EC2 refuses to delete a snapshot a
# registered image still uses. A snapshot is attempted only if its image was
# deregistered; otherwise the delete is certain to fail and the image's own
# failure is already counted. Every call is attempted; failures fail the run
# at the end.
failures=0
declare -A DEREGISTERED=()
mapfile -t REMOVE_IDS < <(jq -r '.[] | select(.action == "remove") | .id' "${WORK}/plan.json")
for img in "${REMOVE_IDS[@]}"; do
    if aws ec2 deregister-image --image-id "${img}" >/dev/null 2>"${WORK}/stderr"; then
        echo "deregistered ${img}"
        DEREGISTERED["${img}"]=1
    else
        echo "::error::deregister-image ${img} failed:" >&2
        sed 's/^/    /' "${WORK}/stderr" >&2
        failures=$((failures + 1))
    fi
done

while IFS=$'\t' read -r img snap; do
    if [[ -z "${DEREGISTERED[${img}]:-}" ]]; then
        echo "::warning::skipping snapshot ${snap}: its image ${img} was not deregistered" >&2
        continue
    fi
    if aws ec2 delete-snapshot --snapshot-id "${snap}" >/dev/null 2>"${WORK}/stderr"; then
        echo "deleted ${snap}"
    else
        echo "::error::delete-snapshot ${snap} failed:" >&2
        sed 's/^/    /' "${WORK}/stderr" >&2
        failures=$((failures + 1))
    fi
done < <(jq -r --slurpfile owned "${WORK}/owned-snaps.json" '
    ($owned[0]) as $own
    | .[] | select(.action == "remove") | .id as $img
    | .snapshots[] | select(. as $s | $own | any(. == $s)) | [$img, .] | @tsv
' "${WORK}/plan.json")

if [[ ${failures} -gt 0 ]]; then
    echo "::error::${failures} deregister/delete call(s) failed; see above." >&2
    exit 1
fi
echo "Done: removed ${n_remove} image(s)."
