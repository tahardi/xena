# Xena

Xena moves agentic coding into a disposable, encrypted VM behind a network wall the desktop enforces. Maple drives sessions in the VM over SSH, and a guardrail suite, a log watcher, and an audit prove every wall.

## Commands

| Command | What it does |
|---|---|
| `xena version` | Prints the installed version. |
| `xena secrets put\|list\|verify\|delete` | Store and check secrets in the YubiKey-encrypted secrets store. |

## Development

Requires Go 1.27 and shellcheck. `make pre-pr` runs tidy, fix, lint, unit tests, govulncheck, gitleaks, and shellcheck, the same checks CI runs. See `docs/rulesets.md` for the branch rules on `main`.
