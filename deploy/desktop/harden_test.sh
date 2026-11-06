#!/usr/bin/env bash
# Stub bodies stay single-quoted so they expand when each stub runs.
# shellcheck disable=SC2016
set -euo pipefail

if [[ $(id -u) -eq 0 ]]; then
	echo "running tests: run without sudo" >&2
	exit 1
fi

script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/harden.sh
failures=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

setup() {
	root=$(mktemp -d -p "$work")
	fake=$root/.fake
	mkdir -p "$fake/bin" "$fake/installed" "$fake/enabled" "$root/etc" "$root/home/taylor/.claude"
	mkdir -p "$root/etc/apt/sources.list.d" "$root/dotclaude/settings"

	printf 'docker:x:999:taylor\nlibvirt:x:998:other,taylor\nsudo:x:27:taylor\n' >"$root/etc/group"
	printf 'flush ruleset\n' >"$root/etc/nftables.conf"
	touch "$root/etc/apt/sources.list.d/docker.list" "$root/etc/apt/sources.list.d/docker.sources"
	touch "$fake/installed/docker-ce" "$fake/installed/containerd.io"
	touch "$fake/enabled/ufw"
	printf '2.1.200\n' >"$fake/claude-version"
	printf 'version: 1\nclaude_code_version: "2.1.310"\n' >"$root/vm.yaml"

	cat >"$root/dotclaude/settings/desktop.json" <<'JSON'
{"env": {"DISABLE_UPDATES": "1"}, "permissions": {"defaultMode": "default"},
 "sandbox": {"enabled": true, "allowUnsandboxedCommands": false}}
JSON

	cat >"$root/dotclaude/install.sh" <<'STUB'
#!/usr/bin/env bash
echo "install.sh $*" >>"$FAKE/calls"
ln -sf "$DOTCLAUDE_DIR/settings/desktop.json" "$XENA_HOME/.claude/settings.json"
STUB

	stub apt-get 'case $1 in purge) shift 2; for p in "$@"; do rm -f "$FAKE/installed/$p"; done ;;
		install) touch "$FAKE/installed/$3" ;; esac'
	stub dpkg-query '[[ -e "$FAKE/installed/${@: -1}" ]] && printf "install ok installed"'
	stub gpasswd 'sed -i -E "/^$3:/{s/([:,])$2(,|$)/\1/;s/,$//}" "$XENA_ROOT/etc/group"'
	stub systemctl 'case $1 in is-enabled) [[ -e "$FAKE/enabled/$2" ]] && echo enabled || { echo disabled; exit 1; } ;;
		enable) touch "$FAKE/enabled/${@: -1}" ;; disable) rm -f "$FAKE/enabled/${@: -1}" ;; esac'
	stub nft ':'
	stub gh 'case $2 in status) [[ -e "$FAKE/gh-ok" ]] ;; login) touch "$FAKE/gh-ok" ;; esac'
	stub claude 'case $1 in --version) echo "$(cat "$FAKE/claude-version") (Claude Code)" ;;
		install) echo "$3" >"$FAKE/claude-version" ;; esac'

	chmod +x "$root/dotclaude/install.sh"
}

stub() {
	printf '#!/usr/bin/env bash\necho "%s $*" >>"$FAKE/calls"\n%s\n' "$1" "$2" >"$fake/bin/$1"
	chmod +x "$fake/bin/$1"
}

harden() {
	env -u GH_TOKEN -u GITHUB_TOKEN \
		PATH="$fake/bin:$PATH" \
		FAKE="$fake" \
		XENA_ROOT="$root" \
		XENA_USER=taylor \
		XENA_HOME="$root/home/taylor" \
		XENA_VM_CONFIG="$root/vm.yaml" \
		DOTCLAUDE_DIR="$root/dotclaude" \
		"$script" "$@"
}

calls() {
	cat "$fake/calls" 2>/dev/null || true
}

pass() {
	echo "PASS $1"
}

fail() {
	echo "FAIL $1: $2"
	failures=$((failures + 1))
}

test_system_applies_every_step() {
	setup

	harden >/dev/null

	local c

	c=$(calls)
	grep -qx 'apt-get purge -y containerd.io docker-ce' <<<"$c" || { fail "${FUNCNAME[0]}" "no docker purge"; return; }
	grep -qx 'gpasswd -d taylor docker' <<<"$c" || { fail "${FUNCNAME[0]}" "no docker group removal"; return; }
	grep -qx 'gpasswd -d taylor libvirt' <<<"$c" || { fail "${FUNCNAME[0]}" "no libvirt group removal"; return; }
	grep -qx "nft -f $root/etc/nftables.conf" <<<"$c" || { fail "${FUNCNAME[0]}" "no nft load"; return; }
	grep -qx 'systemctl enable nftables' <<<"$c" || { fail "${FUNCNAME[0]}" "nftables not enabled"; return; }
	grep -qx 'systemctl disable --now ufw' <<<"$c" || { fail "${FUNCNAME[0]}" "ufw not disabled"; return; }
	grep -qx 'apt-get install -y unattended-upgrades' <<<"$c" ||
		{ fail "${FUNCNAME[0]}" "no unattended-upgrades"; return; }
	grep -qx 'systemctl enable --now unattended-upgrades' <<<"$c" ||
		{ fail "${FUNCNAME[0]}" "unattended-upgrades not enabled"; return; }
	[[ ! -e "$root/etc/apt/sources.list.d/docker.list" ]] || { fail "${FUNCNAME[0]}" "docker source kept"; return; }
	[[ ! -e "$root/etc/apt/sources.list.d/docker.sources" ]] || { fail "${FUNCNAME[0]}" "docker.sources kept"; return; }
	[[ $(stat -c %a "$root/etc/nftables.conf") == 755 ]] || { fail "${FUNCNAME[0]}" "wrong nftables.conf mode"; return; }
	grep -q 'policy drop' "$root/etc/nftables.conf" || { fail "${FUNCNAME[0]}" "no drop policy"; return; }
	grep -q 'APT::Periodic::Unattended-Upgrade "1";' "$root/etc/apt/apt.conf.d/20auto-upgrades" ||
		{ fail "${FUNCNAME[0]}" "no auto-upgrades"; return; }
	[[ -f "$root/etc/polkit-1/rules.d/50-xena.rules" ]] || { fail "${FUNCNAME[0]}" "no polkit rules"; return; }
	[[ $(stat -c %a "$root/etc/polkit-1/rules.d/50-xena.rules") == 644 ]] ||
		{ fail "${FUNCNAME[0]}" "wrong polkit mode"; return; }
	pass "${FUNCNAME[0]}"
}

test_system_is_idempotent() {
	setup

	harden >/dev/null
	rm -f "$fake/calls"
	harden >/dev/null
	if grep -qE '^(apt-get|gpasswd|nft|systemctl (enable|disable)) ' <<<"$(calls)"; then
		fail "${FUNCNAME[0]}" "second run changed state: $(calls)"
		return
	fi

	pass "${FUNCNAME[0]}"
}

test_system_keeps_xena_table() {
	setup

	mkdir -p "$root/etc/nftables.d"
	printf 'table inet xena {}\n' >"$root/etc/nftables.d/xena.nft"
	harden >/dev/null
	if grep -q 'flush ruleset' "$root/etc/nftables.conf" || grep -q 'inet xena' "$root/etc/nftables.conf"; then
		fail "${FUNCNAME[0]}" "nftables.conf touches the xena table"
		return
	fi

	grep -qx 'include "/etc/nftables.d/\*.nft"' "$root/etc/nftables.conf" ||
		{ fail "${FUNCNAME[0]}" "no include"; return; }
	[[ "$(cat "$root/etc/nftables.d/xena.nft")" == 'table inet xena {}' ]] ||
		{ fail "${FUNCNAME[0]}" "xena.nft changed"; return; }
	pass "${FUNCNAME[0]}"
}

test_system_requires_root() {
	setup

	local out

	if out=$(env XENA_ROOT= PATH="$fake/bin:$PATH" FAKE="$fake" "$script" 2>&1); then
		fail "${FUNCNAME[0]}" "ran without root"
		return
	fi

	grep -q 'running system steps: run with sudo' <<<"$out" || { fail "${FUNCNAME[0]}" "wrong error: $out"; return; }
	pass "${FUNCNAME[0]}"
}

test_user_refuses_gh_token() {
	setup

	local out var

	for var in GH_TOKEN GITHUB_TOKEN; do
		if out=$(env "$var=made-up" PATH="$fake/bin:$PATH" FAKE="$fake" XENA_ROOT="$root" "$script" --user 2>&1); then
			fail "${FUNCNAME[0]}" "ran with $var set"
			return
		fi

		grep -q 'moving gh login to the keyring' <<<"$out" || { fail "${FUNCNAME[0]}" "wrong error: $out"; return; }
	done

	pass "${FUNCNAME[0]}"
}

test_user_applies_every_step() {
	setup

	mkdir -p "$root/home/taylor/.config/gh"
	printf 'github.com:\n    oauth_token: made-up\n' >"$root/home/taylor/.config/gh/hosts.yml"
	harden --user >/dev/null

	local c

	c=$(calls)
	grep -qx 'gh auth logout --hostname github.com' <<<"$c" || { fail "${FUNCNAME[0]}" "no logout"; return; }
	grep -qx 'gh auth login --hostname github.com --git-protocol https --web' <<<"$c" ||
		{ fail "${FUNCNAME[0]}" "no login"; return; }
	grep -qx 'install.sh desktop' <<<"$c" || { fail "${FUNCNAME[0]}" "no dotclaude install"; return; }
	grep -qx 'claude install --force 2.1.310' <<<"$c" || { fail "${FUNCNAME[0]}" "no claude pin"; return; }
	pass "${FUNCNAME[0]}"
}

test_check_fails_before_apply() {
	setup

	local out

	if out=$(harden --check); then
		fail "${FUNCNAME[0]}" "check passed on a fresh root"
		return
	fi

	for item in docker-packages docker-sources docker-group libvirt-group nftables-conf ufw-disabled claude-version; do
		grep -qx "fail: $item" <<<"$out" || { fail "${FUNCNAME[0]}" "missing fail: $item"; return; }
	done

	pass "${FUNCNAME[0]}"
}

test_check_passes_after_apply() {
	setup

	harden >/dev/null
	harden --user >/dev/null

	local out

	if ! out=$(harden --check); then
		fail "${FUNCNAME[0]}" "check failed: $out"
		return
	fi

	if grep -qv '^ok: ' <<<"$out"; then
		fail "${FUNCNAME[0]}" "non-ok line: $out"
		return
	fi

	pass "${FUNCNAME[0]}"
}

test_system_validates_nftables_first() {
	setup
	stub nft 'exit 1'

	if harden >/dev/null 2>&1; then
		fail "${FUNCNAME[0]}" "ran past rules nft rejected"
		return
	fi

	grep -q 'flush ruleset' "$root/etc/nftables.conf" || { fail "${FUNCNAME[0]}" "wrote rejected rules"; return; }

	stub nft ':'
	harden >/dev/null
	grep -qx "nft -f $root/etc/nftables.conf" <<<"$(calls)" || { fail "${FUNCNAME[0]}" "rerun did not load"; return; }
	pass "${FUNCNAME[0]}"
}

test_system_matches_whole_user_name() {
	setup
	printf 'docker:x:999:taylor2\nlibvirt:x:998:\n' >"$root/etc/group"

	harden >/dev/null

	if grep -q '^gpasswd ' <<<"$(calls)"; then
		fail "${FUNCNAME[0]}" "removed another user: $(calls)"
		return
	fi

	pass "${FUNCNAME[0]}"
}

test_user_and_check_refuse_root() {
	setup
	stub id 'echo 0'

	local out

	if out=$(env XENA_ROOT= PATH="$fake/bin:$PATH" FAKE="$fake" "$script" --user 2>&1); then
		fail "${FUNCNAME[0]}" "--user ran as root"
		return
	fi

	grep -q 'running user steps: run without sudo' <<<"$out" || { fail "${FUNCNAME[0]}" "wrong error: $out"; return; }

	if out=$(env XENA_ROOT= PATH="$fake/bin:$PATH" FAKE="$fake" "$script" --check 2>&1); then
		fail "${FUNCNAME[0]}" "--check ran as root"
		return
	fi

	grep -q 'running checks: run without sudo' <<<"$out" || { fail "${FUNCNAME[0]}" "wrong error: $out"; return; }
	pass "${FUNCNAME[0]}"
}

test_user_is_idempotent() {
	setup
	harden --user >/dev/null
	rm -f "$fake/calls"

	harden --user >/dev/null

	if grep -qE '^(gh auth log|install\.sh|claude install)' <<<"$(calls)"; then
		fail "${FUNCNAME[0]}" "second run changed state: $(calls)"
		return
	fi

	pass "${FUNCNAME[0]}"
}

test_check_changes_nothing() {
	setup

	harden --check >/dev/null || true

	local changes='^(apt-get|gpasswd|nft|systemctl (enable|disable)|gh auth log|install\.sh|claude install)'

	if grep -qE "$changes" <<<"$(calls)"; then
		fail "${FUNCNAME[0]}" "check changed state: $(calls)"
		return
	fi

	grep -qx 'flush ruleset' "$root/etc/nftables.conf" || { fail "${FUNCNAME[0]}" "check wrote nftables.conf"; return; }
	pass "${FUNCNAME[0]}"
}

test_check_fails_unsafe_settings() {
	local settings good filter

	for filter in \
		'.skipDangerousModePermissionPrompt = true' \
		'del(.env.DISABLE_UPDATES)' \
		'.sandbox.enabled = false' \
		'.sandbox.allowUnsandboxedCommands = true' \
		'.permissions.defaultMode = "bypassPermissions"'; do
		setup
		harden --user >/dev/null
		settings=$root/dotclaude/settings/desktop.json
		good=$(cat "$settings")
		jq "$filter" <<<"$good" >"$settings"

		if harden --check | grep -qx 'ok: claude-settings'; then
			fail "${FUNCNAME[0]}" "passed with $filter"
			return
		fi
	done

	pass "${FUNCNAME[0]}"
}

test_check_fails_unlinked_settings() {
	setup
	harden --user >/dev/null
	rm "$root/home/taylor/.claude/settings.json"
	cp "$root/dotclaude/settings/desktop.json" "$root/home/taylor/.claude/settings.json"

	if harden --check | grep -qx 'ok: claude-settings'; then
		fail "${FUNCNAME[0]}" "passed with a copied settings file"
		return
	fi

	pass "${FUNCNAME[0]}"
}

test_check_fails_plaintext_gh_token() {
	setup
	harden --user >/dev/null
	mkdir -p "$root/home/taylor/.config/gh"
	printf 'github.com:\n    oauth_token: made-up\n' >"$root/home/taylor/.config/gh/hosts.yml"

	if harden --check | grep -qx 'ok: gh-keyring'; then
		fail "${FUNCNAME[0]}" "passed with a plaintext token"
		return
	fi

	pass "${FUNCNAME[0]}"
}

test_rejects_unknown_flag() {
	setup

	local code=0

	harden --bad >/dev/null 2>&1 || code=$?
	[[ $code -eq 2 ]] || { fail "${FUNCNAME[0]}" "exit $code"; return; }
	pass "${FUNCNAME[0]}"
}

test_stops_without_vm_config() {
	setup
	rm "$root/vm.yaml"

	if harden >/dev/null 2>&1; then
		fail "${FUNCNAME[0]}" "ran without vm.yaml"
		return
	fi

	[[ -z "$(calls)" ]] || { fail "${FUNCNAME[0]}" "changed state: $(calls)"; return; }
	pass "${FUNCNAME[0]}"
}

test_system_applies_every_step
test_system_is_idempotent
test_system_keeps_xena_table
test_system_requires_root
test_user_refuses_gh_token
test_user_applies_every_step
test_check_fails_before_apply
test_check_passes_after_apply
test_system_validates_nftables_first
test_system_matches_whole_user_name
test_user_and_check_refuse_root
test_user_is_idempotent
test_check_changes_nothing
test_check_fails_unsafe_settings
test_check_fails_unlinked_settings
test_check_fails_plaintext_gh_token
test_rejects_unknown_flag
test_stops_without_vm_config
exit "$((failures > 0))"
