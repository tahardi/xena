#!/usr/bin/env bash
set -euo pipefail

root=${XENA_ROOT:-}
user=${XENA_USER:-${SUDO_USER:-$(id -un)}}
home=${XENA_HOME:-$HOME}
dotclaude=${DOTCLAUDE_DIR:-$home/Documents/code/dotclaude}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
vm_config=${XENA_VM_CONFIG:-$here/../../config/vm.yaml}
claude_version=$(
	python3 -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["claude_code_version"])' "$vm_config"
)
polkit_rules=$here/../polkit/50-xena.rules
docker_packages=(
	containerd.io
	docker-buildx-plugin
	docker-ce
	docker-ce-cli
	docker-ce-rootless-extras
	docker-compose-plugin
	docker-compose-v2
	docker-model-plugin
	docker.io
	podman-docker
)
docker_sources=(
	etc/apt/sources.list.d/docker.list
	etc/apt/sources.list.d/docker.sources
)
settings_rule='.sandbox.enabled == true
	and .sandbox.allowUnsandboxedCommands == false
	and (.permissions.defaultMode // "default") == "default"
	and (.skipDangerousModePermissionPrompt // false) == false
	and .env.DISABLE_UPDATES == "1"'
failed=0

nftables_conf() {
	cat <<'CONF'
#!/usr/sbin/nft -f

table inet host_filter
delete table inet host_filter

table inet host_filter {
	chain input {
		type filter hook input priority filter + 10; policy drop;
		iifname "lo" accept
		ct state established,related accept
		ct state invalid drop
		iifname "xena0" ip saddr 192.168.150.10 tcp dport 3128 accept
		meta l4proto ipv6-icmp icmpv6 type {
			destination-unreachable,
			packet-too-big,
			time-exceeded,
			parameter-problem,
			nd-router-advert,
			nd-neighbor-solicit,
			nd-neighbor-advert
		} accept
		meta l4proto icmp icmp type {
			destination-unreachable,
			time-exceeded,
			parameter-problem
		} accept
		ip6 saddr fe80::/10 udp dport 546 accept
	}
}

include "/etc/nftables.d/*.nft"
CONF
}

auto_upgrades_conf() {
	cat <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
}

installed() {
	# dpkg-query expands ${Status} itself.
	# shellcheck disable=SC2016
	dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

enabled() {
	[[ $(systemctl is-enabled "$1" 2>/dev/null) == enabled ]]
}

in_group() {
	awk -F: -v g="$1" -v u="$user" '
		$1 == g { n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] == u) found = 1 }
		END { exit !found }
	' "$root/etc/group"
}

not_in_group() {
	! in_group "$1"
}

not_enabled() {
	! enabled "$1"
}

same() {
	cmp -s - "$1"
}

write_file() {
	local path=$1 mode=$2 tmp

	tmp=$(mktemp)
	cat >"$tmp"

	changed=0
	if ! cmp -s "$tmp" "$path"; then
		install -D -m "$mode" "$tmp" "$path"
		changed=1
	fi

	rm -f "$tmp"
}

no_docker_packages() {
	local p

	for p in "${docker_packages[@]}"; do
		if installed "$p"; then
			return 1
		fi
	done
}

no_docker_sources() {
	local s

	for s in "${docker_sources[@]}"; do
		if [[ -e "$root/$s" ]]; then
			return 1
		fi
	done
}

gh_plaintext() {
	grep -qs 'oauth_token:' "$home/.config/gh/hosts.yml"
}

gh_in_keyring() {
	[[ -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]] && ! gh_plaintext && gh auth status --hostname github.com >/dev/null 2>&1
}

settings_linked() {
	[[ -L "$home/.claude/settings.json" ]] &&
		[[ "$(readlink -f "$home/.claude/settings.json")" == "$(readlink -f "$dotclaude/settings/desktop.json")" ]]
}

settings_safe() {
	settings_linked && jq -e "$settings_rule" "$home/.claude/settings.json" >/dev/null
}

claude_pinned() {
	[[ "$(claude --version 2>/dev/null | awk '{print $1}')" == "$claude_version" ]]
}

system_steps() {
	if [[ -z "$root" && $(id -u) -ne 0 ]]; then
		echo "running system steps: run with sudo" >&2
		exit 1
	fi

	local purge=() p g

	for p in "${docker_packages[@]}"; do
		if installed "$p"; then
			purge+=("$p")
		fi
	done

	if [[ ${#purge[@]} -gt 0 ]]; then
		apt-get purge -y "${purge[@]}"
	fi

	for p in "${docker_sources[@]}"; do
		rm -f "$root/$p"
	done

	for g in docker libvirt; do
		if in_group "$g"; then
			gpasswd -d "$user" "$g"
		fi
	done

	mkdir -p "$root/etc/nftables.d"
	if ! same "$root/etc/nftables.conf" < <(nftables_conf); then
		nft -c -f <(nftables_conf)
	fi

	write_file "$root/etc/nftables.conf" 0755 < <(nftables_conf)
	if [[ $changed -eq 1 ]]; then
		nft -f "$root/etc/nftables.conf"
	fi

	if ! enabled nftables; then
		systemctl enable nftables
	fi

	if enabled ufw; then
		systemctl disable --now ufw
	fi

	if ! installed unattended-upgrades; then
		apt-get install -y unattended-upgrades
	fi

	write_file "$root/etc/apt/apt.conf.d/20auto-upgrades" 0644 < <(auto_upgrades_conf)
	if ! enabled unattended-upgrades; then
		systemctl enable --now unattended-upgrades
	fi

	write_file "$root/etc/polkit-1/rules.d/50-xena.rules" 0644 <"$polkit_rules"
}

user_steps() {
	if [[ -z "$root" && $(id -u) -eq 0 ]]; then
		echo "running user steps: run without sudo" >&2
		exit 1
	fi

	if [[ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
		echo "moving gh login to the keyring: remove GH_TOKEN and GITHUB_TOKEN from shell startup files, then rerun" >&2
		exit 1
	fi

	if gh_plaintext; then
		gh auth logout --hostname github.com
	fi

	if ! gh auth status --hostname github.com >/dev/null 2>&1; then
		gh auth login --hostname github.com --git-protocol https --web
	fi

	if ! settings_linked; then
		"$dotclaude/install.sh" desktop
	fi

	if ! claude_pinned; then
		claude install --force "$claude_version"
	fi
}

result() {
	local name=$1

	shift

	if "$@"; then
		echo "ok: $name"
	else
		echo "fail: $name"
		failed=1
	fi
}

check_steps() {
	if [[ -z "$root" && $(id -u) -eq 0 ]]; then
		echo "running checks: run without sudo" >&2
		exit 1
	fi

	result docker-packages no_docker_packages
	result docker-sources no_docker_sources
	result docker-group not_in_group docker
	result libvirt-group not_in_group libvirt
	result nftables-conf same "$root/etc/nftables.conf" < <(nftables_conf)
	result nftables-enabled enabled nftables
	result ufw-disabled not_enabled ufw
	result unattended-upgrades-installed installed unattended-upgrades
	result unattended-upgrades-conf same "$root/etc/apt/apt.conf.d/20auto-upgrades" < <(auto_upgrades_conf)
	result unattended-upgrades-enabled enabled unattended-upgrades
	result polkit-rules same "$root/etc/polkit-1/rules.d/50-xena.rules" <"$polkit_rules"
	result gh-keyring gh_in_keyring
	result claude-settings settings_safe
	result claude-version claude_pinned
	exit "$failed"
}

case "${1:-}" in
	"") system_steps ;;
	--user) user_steps ;;
	--check) check_steps ;;
	*)
		echo "usage: harden.sh [--user|--check]" >&2
		exit 2
		;;
esac
