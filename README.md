# Xena

Xena moves agentic coding into a disposable, encrypted VM behind a network wall the desktop enforces. Maple drives sessions in the VM over SSH, and a guardrail suite, a log watcher, and an audit prove every wall.

## Commands

| Command | What it does |
|---|---|
| `xena version` | Prints the installed version. |
| `xena secrets put\|list\|verify\|delete` | Store and check secrets in the YubiKey-encrypted secrets store. |
| `xena audit [--json]` | Checks the desktop against the spec and lists every drift with its fix. Exits non-zero on drift. Runs daily at 04:00. Settings live in `~/.config/xena/audit.yaml`; copy `config/audit.example.yaml` to start. |

## Talking to the VM

Desktop programs reach the VM through `internal/vmexec`, which runs `ssh` with the automation key and sends one short command such as `health` or `secret-put jira-token`.

`xena-agent` (`cmd/xena-agent`) runs inside the VM. The VM's SSH server starts it for every login with the automation key, so that key can only run the commands the agent allows. It never runs on the desktop.

## Development

Requires Go 1.27 and shellcheck. `make pre-pr` runs tidy, fix, lint, unit tests, govulncheck, gitleaks, and shellcheck, the same checks CI runs. See `docs/rulesets.md` for the branch rules on `main`.
