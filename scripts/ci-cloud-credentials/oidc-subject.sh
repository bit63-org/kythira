# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Sourced, not run: works out the `sub` claim prefix GitHub puts in this
# repository's Actions OIDC tokens, so the provisioning scripts trust the
# subject GitHub actually issues.
#
# Why this is not just "repo:ORG/REPO": a repository can opt into
# immutable subjects, where GitHub qualifies both names with their numeric
# ids (repo:bit63-org@359328292/kythira@1148357760:...). kythira has them
# since its move to bit63-org, and a trust written with the plain names
# then matches nothing. The ids survive renames and transfers, and nobody
# who later re-creates the old name can mint a matching token.
#
# oidc_sub_prefix ORG REPO [OVERRIDE]
#   Prints the prefix (everything before ":environment:..."). OVERRIDE, when
#   non-empty, wins outright (the scripts' --subject-prefix). Otherwise it
#   asks GitHub; a custom claim template (use_default false) changes more
#   than the prefix, so that is refused rather than guessed. When GitHub
#   cannot be asked, it falls back to the plain form with a warning.
oidc_sub_prefix() {
    local org="$1" repo="$2" override="${3:-}"
    if [[ -n "${override}" ]]; then
        printf '%s\n' "${override}"
        return 0
    fi
    local json=""
    if command -v gh >/dev/null 2>&1; then
        json=$(gh api "repos/${org}/${repo}/actions/oidc/customization/sub" 2>/dev/null) || json=""
    fi
    if [[ -z "${json}" ]]; then
        echo "WARNING: could not read ${org}/${repo}'s OIDC subject settings; assuming plain repo:${org}/${repo}." >&2
        echo "         Pass --subject-prefix if the repository uses immutable subjects." >&2
        printf 'repo:%s/%s\n' "${org}" "${repo}"
        return 0
    fi
    if [[ "$(jq -r '.use_default' <<<"${json}")" != "true" ]]; then
        echo "ERROR: ${org}/${repo} uses a custom OIDC claim template; its subject is not repo:...:environment:NAME." >&2
        echo "       Pass --subject-prefix only if you have checked the full subject format." >&2
        return 1
    fi
    local prefix
    prefix=$(jq -r 'if .use_immutable_subject == true then (.sub_claim_prefix // empty) else empty end' <<<"${json}")
    if [[ -z "${prefix}" ]]; then
        prefix="repo:${org}/${repo}"
    fi
    printf '%s\n' "${prefix}"
}
