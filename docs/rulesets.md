# Repository Rules

`scripts/rulesets.sh OWNER/REPO CHECK...` sets a repo's merge settings and its `main` ruleset, and is safe to run again. It needs `gh` logged in as Taylor and `jq`.

It sets:

- Squash merges only, and branches deleted after merge.
- Secret scanning and push protection on.
- Dependabot alerts and security updates on.
- Default workflow token read-only, workflows cannot approve PRs, and actions must be pinned to full commit SHAs.
- Ruleset "Protect main" on the default branch: no deletion, no force push, changes only through PRs merged by squash, and the named CI checks must pass.

Required approving reviews and the `v*` tag ruleset are off until the GitHub App exists, so that Taylor can merge the PRs Taylor authors.

Checks for this repo: `scripts/rulesets.sh tahardi/xena lint test vuln secrets shellcheck`.
