#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Stub-mode test for prune-amis.sh
# (.kiro/specs/ca-cluster-node-ami-retention/ task 2, Requirement 5.1).
#
# A fake `aws` earlier on PATH answers every read from a per-case fixture
# directory and appends each invocation to a call log, so a case can assert
# both what the pruner printed and which mutating calls it made. No AWS
# account and no network: it runs in CI on every pull request.
#
# There is deliberately no live mode. A live test would have to build an AMI
# in order to delete one, which is a whole `ami-build` run; the first real
# dry-run plan in that job's summary is the live check, read by a person
# before REAL_CLOUD_TESTS_AWS_AMI_PRUNE_ENABLED is turned on.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRUNER="${REPO_ROOT}/scripts/ami-retention/prune-amis.sh"

# Fixed clock: 2026-11-20T00:00:00Z. "Old" images below are from October.
NOW=1795132800
OLD="2026-10-01T00:00:00.000Z"

passed=0
failed=0
pass() { echo "  PASS: $1"; passed=$((passed + 1)); }
fail() { echo "  FAIL: $1" >&2; failed=$((failed + 1)); }

TOP=$(mktemp -d "${TMPDIR:-/tmp}/kythira-prune-amis-test-XXXXXX")
trap 'rm -rf "${TOP}"' EXIT

# ── The fake aws ─────────────────────────────────────────────────────────────
#
# Reads STUB_FIXTURES (a directory) and three failure knobs:
#   STUB_FAIL           -- subcommand that exits 255, as an AccessDenied would
#   STUB_GARBAGE        -- subcommand that prints non-JSON and exits 0
#   STUB_FAIL_SNAPSHOT  -- snapshot id whose delete-snapshot fails
# Keyed on the subcommand, not a call counter, so the pruner may reorder its
# queries without the stub silently answering the wrong one.
mkdir -p "${TOP}/bin"
cat > "${TOP}/bin/aws" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${STUB_FIXTURES}/calls.log"
[[ "$1" == "ec2" ]] || { echo "stub aws: unexpected service: $*" >&2; exit 90; }
sub="$2"
if [[ "${sub}" == "${STUB_FAIL:-}" ]]; then
    echo "An error occurred (UnauthorizedOperation) when calling the ${sub} operation: stubbed" >&2
    exit 255
fi
if [[ "${sub}" == "${STUB_GARBAGE:-}" ]]; then
    echo "<html>login required</html>"
    exit 0
fi
arg_after() {
    local want="$1"; shift
    while [[ $# -gt 0 ]]; do
        [[ "$1" == "${want}" ]] && { echo "$2"; return; }
        shift
    done
}
case "${sub}" in
    describe-images)    cat "${STUB_FIXTURES}/images.json" ;;
    describe-instances) cat "${STUB_FIXTURES}/instances.json" 2>/dev/null || echo '{"Reservations":[]}' ;;
    describe-launch-templates)
        cat "${STUB_FIXTURES}/lts.json" 2>/dev/null || echo '{"LaunchTemplates":[]}' ;;
    describe-launch-template-versions)
        lt=$(arg_after --launch-template-id "$@")
        cat "${STUB_FIXTURES}/ltv-${lt}.json" ;;
    describe-snapshots) cat "${STUB_FIXTURES}/snapshots.json" ;;
    deregister-image)   echo '{"Return": true}' ;;
    delete-snapshot)
        snap=$(arg_after --snapshot-id "$@")
        if [[ "${snap}" == "${STUB_FAIL_SNAPSHOT:-}" ]]; then
            echo "An error occurred (InvalidSnapshot.InUse) when calling the DeleteSnapshot operation: stubbed" >&2
            exit 255
        fi ;;
    *) echo "stub aws: unexpected subcommand: $*" >&2; exit 90 ;;
esac
STUB
chmod +x "${TOP}/bin/aws"

# ── Fixture builders ─────────────────────────────────────────────────────────
#
# image <id> <arch> <chaos|-> <created> <snap> [retain]
#   chaos "-" leaves the kythira:chaos-node tag off (a pre-tag image).
image() {
    jq -n --arg id "$1" --arg arch "$2" --arg chaos "$3" --arg created "$4" \
          --arg snap "$5" --arg retain "${6:-}" '
        { ImageId: $id, CreationDate: $created,
          BlockDeviceMappings: [ { DeviceName: "/dev/sda1", Ebs: { SnapshotId: $snap } } ],
          Tags: ([ {Key: "kythira:component", Value: "ca-cluster-node"},
                   {Key: "kythira:built-by",  Value: "packer"},
                   {Key: "kythira:arch",      Value: $arch} ]
                 + (if $chaos == "-" then [] else [{Key: "kythira:chaos-node", Value: $chaos}] end)
                 + (if $retain == "" then [] else [{Key: "kythira:retain", Value: $retain}] end)) }'
}

# owned_snapshots <id>... : every id tagged kythira:component=ca-cluster-node
owned_snapshots() {
    printf '%s\n' "$@" | jq -R . | jq -s '{ Snapshots: map({ SnapshotId: ., Tags: [ {Key: "kythira:component", Value: "ca-cluster-node"} ] }) }'
}

# new_case <name>, then write fixtures into ${FX}.
new_case() {
    FX="${TOP}/$1"
    mkdir -p "${FX}"
    : > "${FX}/calls.log"
}

# images_fixture <image json>... : wrap images into describe-images output
images_fixture() {
    printf '%s\n' "$@" | jq -s '{ Images: . }' > "${FX}/images.json"
}

# run_pruner <extra env and args...> : sets OUT and RC
run_pruner() {
    local envs=()
    while [[ $# -gt 0 && "$1" == *=* ]]; do envs+=("$1"); shift; done
    RC=0
    OUT=$(env "${envs[@]}" PATH="${TOP}/bin:${PATH}" STUB_FIXTURES="${FX}" \
              PRUNE_AMIS_NOW="${NOW}" bash "${PRUNER}" "$@" 2>&1) || RC=$?
}

expect_rc() {
    if [[ "${RC}" -eq "$2" ]]; then pass "$1 (exit ${RC})"
    else fail "$1: wanted exit $2, got ${RC}"; printf '%s\n' "${OUT}" | sed 's/^/        /' >&2; fi
}

# expect_line <what> <regex> : the output has a line matching regex
expect_line() {
    if printf '%s\n' "${OUT}" | grep -qE -- "$2"; then pass "$1"
    else fail "$1: no line matching /$2/"; printf '%s\n' "${OUT}" | sed 's/^/        /' >&2; fi
}

# expect_call <what> <regex> / expect_no_call : the call log does (not) match
expect_call() {
    if grep -qE -- "$2" "${FX}/calls.log"; then pass "$1"
    else fail "$1: no call matching /$2/"; sed 's/^/        /' "${FX}/calls.log" >&2; fi
}
expect_no_call() {
    if ! grep -qE -- "$2" "${FX}/calls.log"; then pass "$1"
    else fail "$1: unexpected call matching /$2/"; sed 's/^/        /' "${FX}/calls.log" >&2; fi
}

# ── Cases ────────────────────────────────────────────────────────────────────

echo "[1] three old images of one class: newest two kept, third removed with its snapshot"
new_case c1
images_fixture \
    "$(image ami-1old amd64 true 2026-09-01T00:00:00.000Z snap-1old)" \
    "$(image ami-1mid amd64 true 2026-09-15T00:00:00.000Z snap-1mid)" \
    "$(image ami-1new amd64 true "${OLD}" snap-1new)"
owned_snapshots snap-1old > "${FX}/snapshots.json"
run_pruner --arch amd64 --apply
expect_rc "apply succeeds" 0
expect_line "newest kept" '^keep +ami-1new .*newest-2'
expect_line "second newest kept" '^keep +ami-1mid .*newest-2'
expect_line "oldest removed" '^REMOVE +ami-1old '
expect_call "oldest deregistered" '^ec2 deregister-image --image-id ami-1old$'
expect_call "its snapshot deleted" '^ec2 delete-snapshot --snapshot-id snap-1old$'
expect_no_call "kept images not deregistered" 'deregister-image --image-id ami-1(mid|new)'
expect_call "query restricted to the arch" 'describe-images --owners self --filters Name=tag:kythira:component,Values=ca-cluster-node Name=tag:kythira:built-by,Values=packer Name=tag:kythira:arch,Values=amd64'
# Deregister before delete: the first delete-snapshot line comes after the
# last deregister-image line.
last_dereg=$(grep -n 'deregister-image' "${FX}/calls.log" | tail -1 | cut -d: -f1)
first_del=$(grep -n 'delete-snapshot' "${FX}/calls.log" | head -1 | cut -d: -f1)
if [[ -n "${last_dereg}" && -n "${first_del}" && "${last_dereg}" -lt "${first_del}" ]]; then
    pass "images deregistered before snapshots are deleted"
else
    fail "images deregistered before snapshots are deleted"
fi

echo "[2] two classes (chaos-node true and false): each keeps its own newest two"
new_case c2
images_fixture \
    "$(image ami-t1 amd64 true  2026-09-01T00:00:00.000Z snap-t1)" \
    "$(image ami-t2 amd64 true  2026-09-02T00:00:00.000Z snap-t2)" \
    "$(image ami-t3 amd64 true  2026-09-03T00:00:00.000Z snap-t3)" \
    "$(image ami-f1 amd64 false 2026-08-01T00:00:00.000Z snap-f1)" \
    "$(image ami-f2 amd64 -     2026-08-02T00:00:00.000Z snap-f2)" \
    "$(image ami-f3 amd64 false 2026-08-03T00:00:00.000Z snap-f3)"
owned_snapshots snap-t1 snap-f1 > "${FX}/snapshots.json"
run_pruner
expect_rc "dry run exits 0" 0
expect_line "chaos class keeps t3" '^keep +ami-t3 +amd64/chaos-node=true .*newest-2'
expect_line "chaos class keeps t2" '^keep +ami-t2 +amd64/chaos-node=true .*newest-2'
expect_line "chaos class removes t1" '^REMOVE +ami-t1 '
expect_line "plain class keeps f3" '^keep +ami-f3 +amd64/chaos-node=false .*newest-2'
expect_line "untagged image counts as chaos-node=false" '^keep +ami-f2 +amd64/chaos-node=false .*newest-2'
expect_line "plain class removes f1" '^REMOVE +ami-f1 '
expect_no_call "no arch filter without --arch" 'Name=tag:kythira:arch'

echo "[3] an old image younger than MIN_AGE is kept"
new_case c3
images_fixture \
    "$(image ami-3a arm64 true 2026-11-17T00:00:00.000Z snap-3a)" \
    "$(image ami-3b arm64 true 2026-11-18T00:00:00.000Z snap-3b)" \
    "$(image ami-3c arm64 true 2026-11-19T00:00:00.000Z snap-3c)"
owned_snapshots > "${FX}/snapshots.json"
run_pruner --arch arm64 --keep 1 --min-age-days 7 --apply
expect_rc "apply succeeds" 0
expect_line "3-day-old image kept for age" '^keep +ami-3a .*younger-than-7-days'
expect_line "2-day-old image kept for age" '^keep +ami-3b .*younger-than-7-days'
expect_no_call "nothing deregistered" 'deregister-image'

echo "[4] a pinned image is kept"
new_case c4
images_fixture \
    "$(image ami-4pin amd64 true 2026-08-01T00:00:00.000Z snap-4pin true)" \
    "$(image ami-4b amd64 true 2026-09-01T00:00:00.000Z snap-4b)" \
    "$(image ami-4c amd64 true "${OLD}" snap-4c)"
owned_snapshots > "${FX}/snapshots.json"
run_pruner --apply
expect_rc "apply succeeds" 0
expect_line "pinned image kept" '^keep +ami-4pin .*pinned'
expect_no_call "pinned image not deregistered" 'deregister-image'

echo "[5] an image an instance runs, and one a launch template names: both kept"
new_case c5
images_fixture \
    "$(image ami-5inst amd64 true 2026-07-01T00:00:00.000Z snap-5inst)" \
    "$(image ami-5lt   amd64 true 2026-07-02T00:00:00.000Z snap-5lt)" \
    "$(image ami-5gone amd64 true 2026-07-03T00:00:00.000Z snap-5gone)" \
    "$(image ami-5b    amd64 true 2026-09-01T00:00:00.000Z snap-5b)" \
    "$(image ami-5c    amd64 true "${OLD}" snap-5c)"
jq -n '{Reservations: [{Instances: [{InstanceId: "i-0stopped", ImageId: "ami-5inst"}]}]}' > "${FX}/instances.json"
jq -n '{LaunchTemplates: [{LaunchTemplateId: "lt-0aaa"}, {LaunchTemplateId: "lt-0bbb"}]}' > "${FX}/lts.json"
jq -n '{LaunchTemplateVersions: [
          {LaunchTemplateId: "lt-0aaa", VersionNumber: 3, LaunchTemplateData: {ImageId: "ami-5lt"}},
          {LaunchTemplateId: "lt-0aaa", VersionNumber: 1, LaunchTemplateData: {ImageId: "ami-unrelated"}}]}' \
    > "${FX}/ltv-lt-0aaa.json"
jq -n '{LaunchTemplateVersions: [{LaunchTemplateId: "lt-0bbb", VersionNumber: 1, LaunchTemplateData: {}}]}' \
    > "${FX}/ltv-lt-0bbb.json"
owned_snapshots snap-5gone > "${FX}/snapshots.json"
run_pruner --apply
expect_rc "apply succeeds" 0
expect_line "instance's image kept" '^keep +ami-5inst .*in-use: i-0stopped'
expect_line "launch template's image kept" '^keep +ami-5lt .*in-use: lt-0aaa:v3'
expect_line "unused old image removed" '^REMOVE +ami-5gone '
expect_call "instances queried for non-terminated states" 'describe-instances --filters Name=image-id,Values=.*ami-5inst.* Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped'
# shellcheck disable=SC2016  # literal EC2 version names in the regex
expect_call "only \$Latest and \$Default versions read" 'describe-launch-template-versions --launch-template-id lt-0aaa --versions \$Latest \$Default'
expect_no_call "in-use images not deregistered" 'deregister-image --image-id ami-5(inst|lt)'
expect_call "unused image deregistered" 'deregister-image --image-id ami-5gone'

echo "[6] an untagged snapshot in a removed image's mappings is listed, not deleted"
new_case c6
jq -n --argjson img "$(image ami-6old amd64 true 2026-08-01T00:00:00.000Z snap-6own)" \
    '$img | .BlockDeviceMappings += [{DeviceName: "/dev/sdb", Ebs: {SnapshotId: "snap-6shared"}}]' \
    > "${FX}/old.json"
images_fixture \
    "$(cat "${FX}/old.json")" \
    "$(image ami-6b amd64 true 2026-09-01T00:00:00.000Z snap-6b)" \
    "$(image ami-6c amd64 true "${OLD}" snap-6c)"
jq -n '{Snapshots: [
          {SnapshotId: "snap-6own", Tags: [{Key: "kythira:component", Value: "ca-cluster-node"}]},
          {SnapshotId: "snap-6shared", Tags: [{Key: "team", Value: "someone-else"}]}]}' > "${FX}/snapshots.json"
run_pruner --apply
expect_rc "apply succeeds" 0
expect_line "own snapshot planned for deletion" 'delete snapshot snap-6own'
expect_line "foreign snapshot listed and left" 'leave snapshot snap-6shared \(not tagged'
expect_call "own snapshot deleted" 'delete-snapshot --snapshot-id snap-6own'
expect_no_call "foreign snapshot not deleted" 'delete-snapshot --snapshot-id snap-6shared'

# Shared by cases 7-10: three old images, the oldest removable.
three_old() {
    images_fixture \
        "$(image ami-xold amd64 true 2026-08-01T00:00:00.000Z snap-xold)" \
        "$(image ami-xb amd64 true 2026-09-01T00:00:00.000Z snap-xb)" \
        "$(image ami-xc amd64 true "${OLD}" snap-xc)"
    owned_snapshots snap-xold > "${FX}/snapshots.json"
}

echo "[7] describe-instances exits 255: nothing removed, exit non-zero"
new_case c7
three_old
run_pruner STUB_FAIL=describe-instances --apply
expect_rc "failed in-use query fails the run" 1
expect_line "says nothing was changed" 'describe-instances failed .*nothing was changed'
expect_no_call "no deregister" 'deregister-image'
expect_no_call "no delete" 'delete-snapshot'

echo "[7b] describe-launch-template-versions exits 255: nothing removed, exit non-zero"
new_case c7b
three_old
jq -n '{LaunchTemplates: [{LaunchTemplateId: "lt-0ccc"}]}' > "${FX}/lts.json"
run_pruner STUB_FAIL=describe-launch-template-versions --apply
expect_rc "failed launch template query fails the run" 1
expect_no_call "no deregister" 'deregister-image'

echo "[8] describe-images prints non-JSON: nothing removed, exit non-zero"
new_case c8
three_old
run_pruner STUB_GARBAGE=describe-images --apply
expect_rc "unreadable output fails the run" 1
expect_line "says jq could not read it" 'jq could not read'
expect_no_call "no deregister" 'deregister-image'

echo "[8b] describe-snapshots prints non-JSON: nothing removed, exit non-zero"
new_case c8b
three_old
run_pruner STUB_GARBAGE=describe-snapshots --apply
expect_rc "unreadable snapshot output fails the run" 1
expect_no_call "no deregister" 'deregister-image'

echo "[9] dry run: no mutating call"
new_case c9
three_old
run_pruner
expect_rc "dry run exits 0" 0
expect_line "plan still shows the removal" '^REMOVE +ami-xold '
expect_line "says it was a dry run" '^Dry run: nothing changed'
expect_no_call "no deregister" 'deregister-image'
expect_no_call "no delete" 'delete-snapshot'

echo "[10] --apply with one failing delete-snapshot: the rest still run, exit 1"
new_case c10
images_fixture \
    "$(image ami-ya amd64 true 2026-07-01T00:00:00.000Z snap-ya)" \
    "$(image ami-yb amd64 true 2026-07-02T00:00:00.000Z snap-yb)" \
    "$(image ami-yc amd64 true 2026-09-01T00:00:00.000Z snap-yc)" \
    "$(image ami-yd amd64 true "${OLD}" snap-yd)"
owned_snapshots snap-ya snap-yb > "${FX}/snapshots.json"
run_pruner STUB_FAIL_SNAPSHOT=snap-yb --apply
expect_rc "a failed delete fails the run" 1
expect_call "first image deregistered" 'deregister-image --image-id ami-ya'
expect_call "second image deregistered" 'deregister-image --image-id ami-yb'
expect_call "the failing delete was attempted" 'delete-snapshot --snapshot-id snap-yb'
expect_call "the other delete still ran" 'delete-snapshot --snapshot-id snap-ya'
expect_line "names the failure" 'delete-snapshot snap-yb failed'

echo "[11] argument validation"
new_case c11
three_old
run_pruner --keep 0
expect_rc "--keep 0 refused" 2
run_pruner --arch x86_64
expect_rc "unknown arch refused" 2
expect_no_call "no aws call on bad arguments" '.'

echo "[12] no candidates: nothing else queried"
new_case c12
echo '{"Images":[]}' > "${FX}/images.json"
run_pruner --apply
expect_rc "empty account exits 0" 0
expect_line "says so" '^No candidate images'
expect_no_call "no further queries" 'describe-(instances|launch|snapshots)'

echo ""
echo "${passed} passed, ${failed} failed"
[[ ${failed} -eq 0 ]]
