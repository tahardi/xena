# Xena

Xena moves agentic coding into a disposable, encrypted VM behind a network wall the desktop enforces. Maple drives sessions in the VM over SSH, and a guardrail suite, a log watcher, and an audit prove every wall.

## Commands

| Command | What it does |
|---|---|
| `xena version` | Prints the installed version. |
| `xena secrets put\|list\|verify\|delete` | Store and check secrets in the YubiKey-encrypted secrets store. |
| `xena audit [--json]` | Checks the desktop against the spec and lists every drift with its fix. Exits non-zero on drift. Runs daily at 04:00. Settings live in `~/.config/xena/audit.yaml`; copy `config/audit.example.yaml` to start. |
| `xena firewall cut\|resume\|reapply` | Cut or restore the VM's network at the desktop firewall, or re-apply a recorded cut after the table reloads. Root only, normally run by `xena-cut.service`, `xena-resume.service`, and `xena-nftables.service`. |
| `xena inventory check [--file-cards]` | Check the token inventory and file rotation cards. |
| `xena rotate NAME [--file PEM]` | Rotate one token and confirm the old value is rejected; `github-app-key` takes the new key's `.pem` with `--file`. |
| `xena grant aws\|gcp [--hours N]` | Mint short-lived sandbox credentials into the VM (one touch; GCP re-mints hourly). |
| `xena grant clear aws\|gcp` | Remove them from the VM. |
| `xena health` | Check every Xena service, timer, and the VM. |
| `xena status [--json]` | Health, cut state, alerts, and last guard and audit for Maple. |
| `xena vm build` | Build the work VM from the pinned image with an encrypted disk, pin its host key, and boot it. Refuses when the VM exists; run `xena vm destroy` first. |
| `xena vm start` | Start the VM (one touch to unlock its disk) and wait until it accepts SSH logins. Refuses while the network is cut. |
| `xena vm stop` | Shut the VM down, forcing it off after five minutes. |
| `xena vm destroy` | Remove the VM, its disk, and its pinned host key. |
| `xena vm snapshot NAME` | Take a disk snapshot while the VM is off (one touch). `make vm-snapshot` names it by date. |
| `xena vm restore NAME` | Revert the disk to a snapshot while the VM is off, then rotate the VM's tokens. Two touches: one for the disk, one for the restarted `xena-tokend`. `make vm-restore NAME=...` |
| `xena guard [--case NAME]` | Run the guardrail attack suite and write `~/.local/state/xena/guard/last.json`. Exits non-zero when any case fails. `--case` runs only print their results and leave the report alone. |
| `xena memory sync [--force]` | Pull Claude memory and claude-mem history out of the VM, redact every secret gitleaks finds, and keep the copy in `~/.local/state/xena/memory/current`. Runs hourly and before `xena vm stop`; skips when the VM is down. `--force` accepts an empty export. |
| `xena memory diff` | Show what changed in memory since the last review, ending with a `digest:` line. |
| `xena memory reviewed DIGEST` | Mark the copy shown by `xena memory diff` as reviewed; refuses if memory changed since. |
| `xena memory restore [--reviewed]` | Load the desktop copy (or the reviewed one, after an incident) into a fresh VM. Refuses when the VM already has memory. |

## Talking to the VM

Desktop programs reach the VM through `internal/vmexec`, which runs `ssh` with the automation key and sends one short command such as `health` or `secret-put jira-token`.

`xena-agent` (`cmd/xena-agent`) runs inside the VM. The VM's SSH server starts it for every login with the automation key, so that key can only run the commands the agent allows. It never runs on the desktop.

The VM attaches to the `xena` libvirt network on the `xena0` bridge. The bridge name, bridge address and prefix come from `config/vm.yaml`, and installing writes them into the installed copy of `deploy/libvirt/xena-net.xml`. `make install` defines the network from that copy, marks it to start at boot, and starts it; `make uninstall` removes it. An edited `deploy/libvirt/xena-net.xml`, or a changed bridge, bridge address or prefix in `config/vm.yaml`, reaches the running network only after you install again, stop the VM, and run `sudo virsh -c qemu:///system net-destroy xena` then `sudo virsh -c qemu:///system net-start xena`.

## Desktop hardening

Review `deploy/desktop/harden.sh`, then run `sudo deploy/desktop/harden.sh` for the system steps, `deploy/desktop/harden.sh --user` for gh, Claude settings, and the Claude version, and `deploy/desktop/harden.sh --check` to see each item's state. Reboot after the first system run.

## Development

Requires Go 1.27, shellcheck, jq, and python3-yaml. Run `make agent` once before using Go commands directly, and again after changing `cmd/xena-agent`, because the `xena` binary embeds the agent it builds. `make pre-pr` runs tidy, fix, lint, unit tests, govulncheck, gitleaks, and shellcheck, the same checks CI runs. See `docs/rulesets.md` for the branch rules on `main`.
