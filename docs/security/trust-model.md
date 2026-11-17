# Trust Model

Xena moves agentic coding off Taylor's desktop into a disposable, encrypted VM behind a network wall the desktop enforces. Taylor is its only user, on their own desktop. Claude sessions in the VM run with no permission prompts, so the walls around them, not the sessions, carry the protection.

## Assets

- `desktop`: Taylor's desktop account and everything it reaches, including sudo, mail, Slack, browser cookies, and claude.ai connectors. If lost, a session acts as Taylor, up to root.
- `taylor-logins`: Taylor's own gh, Jira, Google, cloud root, and claude.ai logins in the desktop keyring. If lost, accounts are taken over, including approving and merging PRs.
- `secrets-store`: the YubiKey-encrypted store with the GitHub App private key, cloud grant-issuing credentials, the VM disk key, and the Jira bot token. If lost, anyone can mint repo tokens and cloud credentials.
- `vm-tokens`: the one-hour GitHub App token, Jira bot token, VM Claude login, and cloud grants in the VM. If lost, repos or Jira can be tampered with and cloud money spent until they expire or are revoked.
- `automation-key`: the SSH key desktop services use for the VM agent's fixed commands. If lost, anyone can push secrets into or pull memory out of the VM.
- `main-branch`: reviewed code on `main` and signed `v*` tags, which `make install` runs as root. If lost, unreviewed code becomes root on the desktop.
- `private-vault`: vault notes outside the project, ideas, and security lesson folders, such as the journal and contacts. If lost, private data leaks to the VM and Anthropic.
- `project-notes`: vault notes the VM may read and write. If lost, forged reports or notes steer desktop Claude.
- `project-data`: sensitive personal data in the projects Xena is used to build, such as Halo and Little Things. If lost, health data or notes about real people leak. Real data is meant to stay on each project's host, and Xena does not enforce that.
- `money`: cloud sandbox, API, and Actions billing. If lost, a large bill.
- `walls`: firewall rules, proxy allowlist and overlay, VM managed Claude settings, and the cut state. If lost, guardrails are off without anyone noticing.
- `logs`: proxy, firewall, and gateway logs, alerts, and guard results on the desktop. If tampered with, they give a false all-clear.
- `memory`: Claude memory and claude-mem history, and the desktop copy. If poisoned, bad instructions carry into future sessions.

## Who Might Attack

- `prompt-injector`: anyone who can put text in front of a VM session, such as issue, PR, or card text, a web page, or a dependency README. Reaches the VM session.
- `hijacked-session`: a misled or hijacked VM session, or any code it runs. Taylor assumes this happens at some point. Reaches the proxy, firewall, vault gateway, VM agent replies, GitHub App, VM settings, VM SSH server, cloud sandboxes, Maple through VM output, and the guard.
- `malicious-package`: the author of a dependency, image package, or plugin, or someone who took over a registry account. Reaches the VM session and CI.
- `pr-author`: anyone who can open a PR or comment on the public repo. Reaches CI.
- `lan-device`: any device on the home network. Reaches the firewall only; `xena expose` is not built.
- `thief`: someone who steals the desktop, its disk, or a backup drive. Reaches the encrypted secrets store and VM disk.
- `third-party`: Anthropic, GitHub, and Atlassian, which see session content, code, and card text.

## Trust Boundaries

The desktop is trusted and the VM is not. `xena-cli`, `tokend`, `prompt`, and `watch` are reached by no attacker directly.

- `xena-cli`: the `xena` command Taylor runs.
- `secrets-store`: age files encrypted to both YubiKeys.
- `tokend`: the user service that mints GitHub App tokens.
- `proxy`: the system service that is the VM's only way out.
- `prompt`: the user service that shows host questions and alerts.
- `firewall`: the `inet xena` nftables table and its cut, resume, and reapply services.
- `guard`: the attack suite.
- `vault-gateway`: planned, not built.
- `watch`: planned, not built.
- `maple`: the desktop app, in its own repo, that drives VM sessions.
- `vm-session`: everything running as `dev` in the VM.
- `vm-settings`: root-owned managed Claude settings in the VM.
- `vm-sshd`: the VM's SSH server.
- `xena-agent`: the forced command for automation-key logins.
- `github-app`: the App the VM uses on GitHub.
- `cloud-sandbox`: the AWS and GCP sandbox accounts.
- `ci`: GitHub Actions.
- `vm-to-desktop-net`: all VM packets. Only new TCP to the proxy port passes; everything else is dropped and logged.
- `vm-to-proxy`: VM web requests. Host and port checked against the allowlist, resolved only after, private and metadata ranges refused, exact address dialed.
- `proxy-to-prompt`: questions about unknown hosts. Group-only socket and deny after 60 seconds. The prompt service asks for a touch before allow always; the proxy does not check it.
- `desktop-to-vm-ssh`: commands and secrets into the VM. Pinned host key, root-owned keys file, only remote Unix socket forwarding, automation key forced to the agent.
- `vm-to-desktop-data`: agent replies, hook events, transcripts, findings, and memory. Treated as untrusted; memory gets a secret scan.
- `vm-to-xena-cli`: the SSH host key and cloud-init result, read through the VM's qemu guest agent. Read only at build and start; the host key is pinned at first boot before repo code runs, and a VM root compromise controls later replies.
- `tokend-to-github`: token requests. Only `api.github.com` through the proxy socket, fenced by nftables and AppArmor.
- `vm-to-github`: pushes and PRs with the App token. No admin and required CI checks; the `main` ruleset requires no approval today.
- `vm-to-cloud`: cloud API calls during a grant. A touch per grant, expiry, and account caps.
- `vm-to-vault`: MCP calls to the planned gateway. Path policy, socket ownership, size and rate caps.
- `pr-to-ci`: PR code in Actions. Read-only token and no secrets.

## What We Trust

Any part that runs Claude can be misled, so its trust is a best effort and its limits carry the weight.

- `xena-cli`: trusted with Taylor's intent and the secrets store, one touch per decrypt. Nothing limits it; it is the trusted base. Firewall cut and resume need admin authentication.
- `secrets-store`: trusted with every long-lived secret. Limited by encryption to both YubiKeys and a touch per decrypt.
- `tokend`: trusted with the GitHub App key after a daily touch, and minting one-hour tokens. Limited by an nftables fence to VM port 22, GitHub only through the proxy socket, AppArmor, and the App's permissions.
- `proxy`: trusted with deciding every VM connection and writing the proxy log. Limited by its own user, systemd hardening, address rules allowing only the VM and the local resolver, and no write to the allowlist. It trusts any answer on the prompt socket from the xena-prompt group, which includes every process running as Taylor.
- `prompt`: trusted with showing host questions and alerts and returning Taylor's answer. Limited by Unix sockets only, asking for a touch before it answers allow always, and deny on timeout.
- `firewall`: trusted with dropping all VM traffic but the proxy port, logging drops at up to 10 a second, and cutting the VM. Drops from a cut address and broadcast or multicast drops are not logged. Limited by root only, loading at boot before libvirt, and the audit.
- `guard`: trusted with proving each wall holds. Limited by judging from desktop logs and counters, never the VM's answer; persistence cases still trust the VM until the libguestfs check exists.
- `vault-gateway`: trusted with VM reads and writes in the project, ideas, and lesson notes, except Xena reports. Limited by the path policy, a socket only Taylor can open, size and rate caps, and a log of every call.
- `watch`: trusted with spotting misbehavior and cutting the network on high alerts. Limited by its own user, read-only logs, and only the cut hook as write power.
- `maple`: trusted with Taylor's gh login and the merge decision. Limited by its own trust model treating VM content as untrusted, and merges pinned to the head commit.
- `vm-session`: trusted with a best-effort try at the card's task, never an honest report on its own work. Limited by the VM with no sudo, the managed sandbox and write list, the deny list, the proxy allowlist, and no desktop tokens. Its GitHub token lasts an hour and cloud grants end with the grant, but its Jira bot token rotates every 90 days and its Claude login lasts until rebuild.
- `vm-settings`: trusted with keeping the sandbox, deny list, hooks, no connectors, and proxy settings in force. Limited by root ownership, changes only by merged dotclaude PR, and the guard; deny rules match text only.
- `vm-sshd`: trusted with letting in only the desktop's keys. Limited by the pinned host key, root-owned keys file, no forwarding except remote Unix sockets, and the firewall; a VM root compromise gets past it.
- `xena-agent`: trusted with running its fixed automation commands. Limited by the forced command and fixed verb and name checks; its replies are untrusted.
- `github-app`: trusted with pushing branches and opening PRs. Limited by no admin permission, one-hour tokens, required CI checks, and only Taylor's signed tags installing; the `main` ruleset requires no approval today, so the App could merge.
- `cloud-sandbox`: trusted with whatever cloud work a grant allows. Limited by touch-gated expiring grants, the AWS SCP and GCP deny policy, quotas, and a GCP budget that cuts billing.
- `ci`: trusted with running checks on every PR. Limited by a read-only token, no persisted credentials, SHA-pinned actions, and no secrets.

## Users and Access

- `taylor`: owner, can do everything. Desktop login with Xena's groups, YubiKey touches, polkit admin for libvirt and firewall cuts, YubiKey second factor on every account, and a touch-required key into the VM.
- `dev`: the VM user sessions run as. Writes sandbox paths, pushes and opens PRs, uses Jira as the bot and cloud grants. Locked password, no sudo.
- `automation`: desktop services with the automation key. Only the agent's commands, by forced command.
- `jira-bot`: the Atlassian bot. Works cards in Taylor's projects, no admin, token rotated every 90 days.
- `github-app`: the App on xena, dotclaude, and maple. Contents, pull requests, checks, and workflows, no administration, one-hour tokens.
- `service-users`: `xena-proxy` and `xena-watch` system users with no login.

## Build, Deploy, and Monitor

Built with `make pre-pr` locally and the same jobs in GitHub Actions on PRs, pushes to `main`, and nightly, with Dependabot weekly. Taylor signs a `v*` tag on `main`, and `make install` builds only from a verified signed tag reachable from `main`; `make rollback` reinstalls an earlier one. The VM image, dotclaude, and Claude Code are pinned. Watched through proxy logs and journald kept 90 days, firewall drop logs, a daily audit, `xena health` and `xena status`, and `xena guard` by hand. Nightly guard, weekly report, backups, memory sync, and the watch service are not built yet.

## Accepted Risks

None recorded yet. The design spec accepts these, and they come back as findings to decide: exfiltration to allowed hosts, an unencrypted desktop home folder, an infostealer taking browser cookies, a VM session deleting or rewriting its own findings, a VM session writing a wrong lesson, and approve and merge not being testable in the VM.

## Severity Overrides

None yet.
