#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: rulesets.sh OWNER/REPO CHECK..." >&2
	exit 2
fi
repo=$1
shift
checks=$(printf '%s\n' "$@" | jq -R '{context: .}' | jq -s .)

main_ruleset=$(jq -n --argjson checks "$checks" '{
	name: "Protect main",
	target: "branch",
	enforcement: "active",
	conditions: {ref_name: {include: ["~DEFAULT_BRANCH"], exclude: []}},
	rules: [
		{type: "deletion"},
		{type: "non_fast_forward"},
		{type: "pull_request", parameters: {
			allowed_merge_methods: ["squash"],
			required_approving_review_count: 0,
			require_last_push_approval: false,
			dismiss_stale_reviews_on_push: false,
			require_code_owner_review: false,
			required_review_thread_resolution: false
		}},
		{type: "required_status_checks", parameters: {
			strict_required_status_checks_policy: false,
			required_status_checks: $checks
		}}
	]
}')

upsert() {
	local name=$1 body=$2 id
	id=$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id")
	if [[ -n "$id" ]]; then
		gh api --method PUT "repos/$repo/rulesets/$id" --input - <<<"$body" >/dev/null
	else
		gh api --method POST "repos/$repo/rulesets" --input - <<<"$body" >/dev/null
	fi
	echo "applied ruleset \"$name\" to $repo"
}

gh repo edit "$repo" \
	--enable-squash-merge \
	--enable-merge-commit=false \
	--enable-rebase-merge=false \
	--delete-branch-on-merge
gh api --method PATCH "repos/$repo" \
	-f 'security_and_analysis[secret_scanning][status]=enabled' \
	-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' >/dev/null
gh api --method PUT "repos/$repo/vulnerability-alerts" >/dev/null
gh api --method PUT "repos/$repo/automated-security-fixes" >/dev/null
gh api --method PUT "repos/$repo/actions/permissions/workflow" \
	-f default_workflow_permissions=read \
	-F can_approve_pull_request_reviews=false >/dev/null
gh api --method PUT "repos/$repo/actions/permissions" \
	-F enabled=true \
	-f allowed_actions=all \
	-F sha_pinning_required=true >/dev/null
upsert "Protect main" "$main_ruleset"
