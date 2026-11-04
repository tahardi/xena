#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
install_sh="$script_dir/install.sh"
uninstall_sh="$script_dir/uninstall.sh"
failures=0

write_fake() {
	local name=$1

	cat >"$work/fakebin/$name" <<'EOF'
#!/usr/bin/env bash
echo "$(basename "$0") $*" >>"$FAKE_LOG"
if [[ " ${FAKE_FAIL:-} " == *" $(basename "$0") "* ]]; then
	exit 1
fi
EOF
	cat >>"$work/fakebin/$name"
	chmod +x "$work/fakebin/$name"
}

write_fakes() {
	mkdir -p "$work/fakebin"

	local name
	for name in systemctl systemd-sysusers systemd-tmpfiles usermod userdel groupdel chown nft apparmor_parser; do
		write_fake "$name" </dev/null
	done

	write_fake xena </dev/null

	write_fake getent <<'EOF'
[[ " ${FAKE_GETENT-xena-proxy xena-watch xena-prompt} " == *" $2 "* ]]
EOF

	write_fake virsh <<'EOF'
if [[ -z "${FAKE_VM_STATE:-}" ]]; then
	exit 1
fi
echo "$FAKE_VM_STATE"
EOF

	write_fake go <<'EOF'
echo "go-env GOWORK=${GOWORK-} GOFLAGS=${GOFLAGS-} GOENV=${GOENV-} GOTOOLCHAIN=${GOTOOLCHAIN-}" >>"$FAKE_LOG"
if [[ -n "${FAKE_GO_FAIL:-}" ]]; then
	exit 1
fi
if [[ -n "${FAKE_GO_CUT:-}" ]]; then
	mkdir -p "$(dirname "$FAKE_GO_CUT")"
	touch "$FAKE_GO_CUT"
fi
if [[ "${1:-}" == "build" ]]; then
	while [[ $# -gt 0 ]]; do
		if [[ "$1" == "-o" ]]; then
			out=$2
		fi
		shift
	done
	mkdir -p "$out"
	for bin in xena xena-agent xena-proxy xena-prompt xena-tokend xena-vault xena-watch; do
		touch "$out/$bin"
	done
fi
EOF
}

commit_file() {
	local path=$1 content=$2

	mkdir -p "$clone/$(dirname "$path")"
	printf '%s\n' "$content" >"$clone/$path"
	git -C "$clone" add "$path"
}

signed_tag() {
	local key=$1 tag=$2

	git -C "$clone" -c gpg.format=ssh -c user.signingkey="$key" tag -s "$tag" -m "$tag"
}

setup() {
	work=$(mktemp -d)
	root="$work/root"
	clone="$work/clone"
	export FAKE_LOG="$work/fake.log"
	export GIT_CONFIG_GLOBAL=/dev/null
	export GIT_CONFIG_NOSYSTEM=1
	mkdir -p "$root" "$work/tmp"
	: >"$FAKE_LOG"

	write_fakes

	ssh-keygen -t ed25519 -N '' -q -f "$work/key" -C test@example.com
	ssh-keygen -t ed25519 -N '' -q -f "$work/other_key" -C other@example.com
	signers="$work/allowed_signers"
	echo "test@example.com namespaces=\"git\" $(cat "$work/key.pub")" >"$signers"

	git init -q --bare -b main "$work/origin.git"
	git init -q -b main "$clone"
	git -C "$clone" config user.email test@example.com
	git -C "$clone" config user.name Test
	git -C "$clone" remote add origin "$work/origin.git"

	commit_file go.mod "module example.com/xena"
	commit_file config/watch.yaml "interval: 5s"
	commit_file deploy/nftables/xena.nft "table inet xena {}"
	commit_file deploy/polkit/50-xena.rules "polkit.addRule(function () {});"
	commit_file deploy/sysusers/xena.conf "u xena-proxy -"
	commit_file deploy/libvirt/hooks/qemu "#!/bin/sh"
	commit_file deploy/apparmor/usr.local.bin.xena-tokend "profile xena-tokend {}"
	commit_file deploy/systemd/xena-proxy.service $'[Service]\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target'
	commit_file deploy/systemd/xena-cut.service $'[Service]\nType=oneshot\nExecStart=/bin/true'
	commit_file deploy/systemd/xena-nftables.service $'[Service]\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target'
	commit_file deploy/systemd/xena-report.timer $'[Timer]\nOnCalendar=daily\n\n[Install]\nWantedBy=timers.target'
	git -C "$clone" commit -q -m initial
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.1.0
	git -C "$clone" push -q origin v0.1.0
}

teardown() {
	rm -rf "$work"
}

run_install() {
	XENA_REPO_DIR="$clone" \
		DESTDIR="$root" \
		SUDO="" \
		XENA_ALLOWED_SIGNERS="$signers" \
		PATH="$work/fakebin:$PATH" \
		TMPDIR="$work/tmp" \
		"$install_sh" install "$@"
}

run_uninstall() {
	DESTDIR="$root" \
		SUDO="" \
		PATH="$work/fakebin:$PATH" \
		"$uninstall_sh"
}

fail() {
	echo "  $*" >&2
	return 1
}

assert_file() {
	[[ -f "$1" ]] || fail "missing file $1"
}

assert_dir() {
	[[ -d "$1" ]] || fail "missing directory $1"
}

assert_absent() {
	[[ ! -e "$1" ]] || fail "unexpected $1"
}

assert_mode() {
	local want=$1 path=$2 got

	got=$(stat -c %a "$path")
	[[ "$got" == "$want" ]] || fail "$path has mode $got, want $want"
}

assert_log() {
	grep -qxF -- "$1" "$FAKE_LOG" || fail "log missing line: $1"
}

assert_log_match() {
	grep -qE -- "$1" "$FAKE_LOG" || fail "log missing match: $1"
}

assert_no_log_match() {
	! grep -qE -- "$1" "$FAKE_LOG" || fail "log has unexpected match: $1"
}

assert_refused() {
	local want=$1 err
	shift

	if err=$(run_install "$@" 2>&1 >/dev/null); then
		fail "install succeeded, want refusal"
	fi
	[[ "$err" == *"$want"* ]] || fail "stderr '$err' does not contain '$want'"

	assert_absent "$root/usr"
	assert_absent "$root/etc"
	assert_no_log_match '^(systemctl|systemd-sysusers|systemd-tmpfiles|chown)'
}

test_install_happy_path() {
	run_install v0.1.0 >/dev/null

	assert_file "$root/usr/local/bin/xena-watch"
	assert_mode 755 "$root/usr/local/bin/xena-watch"
	assert_file "$root/usr/local/share/xena/config/watch.yaml"
	assert_file "$root/etc/systemd/system/xena-proxy.service"
	assert_file "$root/etc/systemd/user/xena-report.timer"
	assert_file "$root/etc/polkit-1/rules.d/50-xena.rules"
	assert_file "$root/etc/nftables.d/xena.nft"
	assert_file "$root/etc/sysusers.d/xena.conf"
	assert_file "$root/etc/libvirt/hooks/qemu"
	assert_mode 755 "$root/etc/libvirt/hooks/qemu"
	assert_dir "$root/var/lib/xena-vm"
	assert_dir "$root/var/lib/xena-desktop"
	assert_mode 2750 "$root/var/lib/xena-desktop"
	assert_mode 711 "$root/var/lib/xena-vm"
	assert_mode 755 "$root/var/lib/xena-expose"
	assert_mode 755 "$root/var/lib/xena"
	assert_absent "$root/usr/local/bin/xena-agent"
	grep -qxF "d /run/xena-guard 0750 $(id -un) xena-watch -" "$root/etc/tmpfiles.d/xena-guard.conf" ||
		fail "tmpfiles entry missing"
	assert_log_match '^systemd-sysusers .*xena\.conf'
	assert_log_match '^systemd-tmpfiles --create'
	assert_log "chown $(id -un) $root/var/lib/xena-vm"
	assert_log "chown $(id -un):xena-watch $root/var/lib/xena-desktop"
	assert_log "systemctl daemon-reload"
	assert_log "systemctl --user daemon-reload"
	assert_log "systemctl enable xena-nftables.service xena-proxy.service"
	assert_log "systemctl restart xena-nftables.service xena-proxy.service"
	assert_log "systemctl --user enable xena-report.timer"
	assert_log "systemctl --user restart xena-report.timer"
	assert_log_match '^go build .*-X main\.version=v0\.1\.0 '
	assert_no_log_match 'enable.*xena-cut\.service'
	assert_no_log_match '^usermod'
}

test_install_idempotent() {
	run_install v0.1.0 >/dev/null
	local first
	first=$(find "$root" -printf '%p %m %s\n' | sort)

	: >"$FAKE_LOG"

	run_install v0.1.0 >/dev/null

	[[ "$(find "$root" -printf '%p %m %s\n' | sort)" == "$first" ]] || fail "second install changed the files"
	assert_log "apparmor_parser -r $root/etc/apparmor.d/usr.local.bin.xena-tokend"
}

test_install_loads_apparmor() {
	local profile="$root/etc/apparmor.d/usr.local.bin.xena-tokend" load_line systemctl_line

	run_install v0.1.0 >/dev/null

	assert_file "$profile"
	assert_mode 644 "$profile"
	assert_log "apparmor_parser -r $profile"
	load_line=$(grep -nxF "apparmor_parser -r $profile" "$FAKE_LOG" | cut -d: -f1)
	systemctl_line=$(grep -n '^systemctl' "$FAKE_LOG" | head -1 | cut -d: -f1)
	[[ $load_line -lt $systemctl_line ]] || fail "profile loaded after the first systemctl call"
}

test_install_builds_from_tag() {
	echo "interval: 1s" >"$clone/config/watch.yaml"

	run_install v0.1.0 >/dev/null

	grep -qxF "interval: 5s" "$root/usr/local/share/xena/config/watch.yaml" ||
		fail "installed config is not the tagged copy"
}

test_install_refuses_unsigned_tag() {
	git -C "$clone" tag -a v0.2.0 -m v0.2.0

	assert_refused "refusing tag v0.2.0: signature not valid" v0.2.0
}

test_install_refuses_foreign_signer() {
	signed_tag "$work/other_key" v0.2.0

	assert_refused "refusing tag v0.2.0: signature not valid" v0.2.0
}

test_install_refuses_tag_off_main() {
	git -C "$clone" checkout -q -b other
	commit_file config/other.yaml "other: true"
	git -C "$clone" commit -q -m other
	signed_tag "$work/key" v0.3.0

	assert_refused "refusing tag v0.3.0: not reachable from origin/main" v0.3.0
}

test_install_refuses_non_v_tag() {
	signed_tag "$work/key" release-1

	assert_refused "refusing tag release-1: not a v* tag" release-1
}

test_install_refuses_while_cut() {
	mkdir -p "$root/var/lib/xena"
	touch "$root/var/lib/xena/cut"

	assert_refused "refusing install: vm network is cut, run xena resume first" v0.1.0
}

test_install_refuses_cut_during_build() {
	local err

	if err=$(FAKE_GO_CUT="$root/var/lib/xena/cut" run_install v0.1.0 2>&1 >/dev/null); then
		fail "install succeeded, want refusal"
	fi

	[[ "$err" == *"refusing install: vm network is cut, run xena resume first"* ]] ||
		fail "stderr '$err' does not contain the cut refusal"
	assert_no_log_match '^systemctl'
}

test_install_refuses_copied_tag() {
	git -C "$clone" update-ref refs/tags/v9.9.9 "$(git -C "$clone" rev-parse refs/tags/v0.1.0)"

	assert_refused "refusing tag v9.9.9: signed as a different tag" v9.9.9
}

test_install_refuses_missing_tag() {
	assert_refused "cannot locate tag for version v9.9.9" v9.9.9
}

test_install_refuses_no_tags() {
	git -C "$clone" tag -d v0.1.0 >/dev/null
	git -C "$clone" push -q origin :refs/tags/v0.1.0

	assert_refused "cannot locate tag for version latest"
}

test_install_defaults_to_latest_tag_after_fetch() {
	local other="$work/other"
	git clone -q "$work/origin.git" "$other"
	git -C "$other" config user.email test@example.com
	git -C "$other" config user.name Test
	git -C "$other" commit -q --allow-empty -m next
	git -C "$other" push -q origin main
	git -C "$other" -c gpg.format=ssh -c user.signingkey="$work/key" tag -s v0.1.1 -m v0.1.1
	git -C "$other" push -q origin v0.1.1

	run_install >/dev/null

	assert_log_match '^go build .*-X main\.version=v0\.1\.1 '
}

test_install_removes_stale_units() {
	run_install v0.1.0 >/dev/null
	git -C "$clone" rm -q deploy/systemd/xena-report.timer deploy/systemd/xena-cut.service
	git -C "$clone" commit -q -m drop
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.2.0

	run_install v0.2.0 >/dev/null

	assert_absent "$root/etc/systemd/user/xena-report.timer"
	assert_absent "$root/etc/systemd/system/xena-cut.service"
	assert_file "$root/etc/systemd/system/xena-proxy.service"
	assert_log "systemctl --user disable --now xena-report.timer"
	assert_log "systemctl disable --now xena-cut.service"
}

test_install_backs_up_foreign_hook() {
	mkdir -p "$root/etc/libvirt/hooks"
	echo other >"$root/etc/libvirt/hooks/qemu"

	run_install v0.1.0 >/dev/null
	run_install v0.1.0 >/dev/null

	grep -qxF other "$root/etc/libvirt/hooks/qemu.pre-xena" || fail "foreign hook not backed up"
	grep -qxF "#!/bin/sh" "$root/etc/libvirt/hooks/qemu" || fail "xena hook not installed"

	run_uninstall >/dev/null

	grep -qxF other "$root/etc/libvirt/hooks/qemu" || fail "foreign hook not restored"
	assert_absent "$root/etc/libvirt/hooks/qemu.pre-xena"
}

test_install_prints_progress() {
	local out

	out=$(run_install v0.1.0)

	[[ "$out" == *"building xena v0.1.0"* ]] || fail "missing build line in '$out'"
	[[ "$out" == *"installing xena v0.1.0 system files (sudo may ask for your password)"* ]] ||
		fail "missing sudo line in '$out'"
}

test_install_refuses_lightweight_tag() {
	git -C "$clone" tag v0.4.0

	assert_refused "refusing tag v0.4.0: signature not valid" v0.4.0
}

test_install_refuses_missing_signers_file() {
	signers="$work/missing_signers"

	assert_refused "refusing tag v0.1.0: signature not valid" v0.1.0
}

test_install_refuses_unpushed_main_tag() {
	commit_file config/new.yaml "new: true"
	git -C "$clone" commit -q -m new
	signed_tag "$work/key" v0.5.0

	assert_refused "refusing tag v0.5.0: not reachable from origin/main" v0.5.0
}

test_install_build_failure_cleans_up() {
	if FAKE_GO_FAIL=1 run_install v0.1.0 >/dev/null 2>&1; then
		fail "install succeeded, want failure"
	fi

	assert_absent "$root/usr"
	[[ -z "$(ls -A "$work/tmp")" ]] || fail "build directory left behind"
}

test_install_clears_go_environment() {
	GOFLAGS=-toolexec=/bin/false GOWORK=/tmp/go.work run_install v0.1.0 >/dev/null

	assert_log "go-env GOWORK=off GOFLAGS= GOENV=off GOTOOLCHAIN=local"
}

test_install_usage() {
	local status=0

	"$install_sh" >/dev/null 2>&1 || status=$?

	[[ $status -eq 2 ]] || fail "exit $status, want 2"
}

test_rollback_needs_version() {
	local err

	if err=$(env -u VERSION make -s -C "$script_dir/.." rollback 2>&1); then
		fail "rollback succeeded, want refusal"
	fi

	[[ "$err" == *"rollback needs VERSION=vX.Y.Z"* ]] || fail "output '$err' does not contain the rollback message"
}

test_services_skip_without_vm_config() {
	local unit
	for unit in xena-proxy.service xena-tokend.service; do
		grep -qxF "ConditionPathExists=/usr/local/share/xena/config/vm.yaml" "$script_dir/../deploy/systemd/$unit" ||
			fail "$unit does not skip a missing vm config"
	done
}

test_nftables_unit_skips_without_table() {
	grep -qxF "ConditionPathExists=/etc/nftables.d/xena.nft" "$script_dir/../deploy/systemd/xena-nftables.service" ||
		fail "xena-nftables.service does not skip a missing table file"
}

test_uninstall_keeps_state() {
	run_install v0.1.0 >/dev/null
	mkdir -p "$root/var/lib/xena-proxy"
	touch "$root/var/lib/xena-proxy/keep.txt"
	local out

	out=$(run_uninstall 2>&1)

	[[ "$out" == *"uninstalled xena" ]] || fail "output '$out' does not end with 'uninstalled xena'"
	assert_absent "$root/usr/local/bin/xena-watch"
	assert_absent "$root/etc/systemd/system/xena-proxy.service"
	assert_absent "$root/etc/systemd/user/xena-report.timer"
	assert_absent "$root/usr/local/share/xena"
	assert_absent "$root/etc/polkit-1/rules.d/50-xena.rules"
	assert_file "$root/var/lib/xena-proxy/keep.txt"
	assert_log "nft destroy table inet xena"
	assert_no_log_match '^userdel'
}

test_uninstall_stops_running_vm() {
	run_install v0.1.0 >/dev/null

	FAKE_VM_STATE=running run_uninstall >/dev/null

	assert_log "xena vm stop"
	local stop_line destroy_line
	stop_line=$(grep -n '^xena vm stop' "$FAKE_LOG" | cut -d: -f1)
	destroy_line=$(grep -n '^nft destroy' "$FAKE_LOG" | cut -d: -f1)
	[[ $stop_line -lt $destroy_line ]] ||
		fail "vm stopped after the nftables table was deleted"
}

test_uninstall_refuses_when_vm_stop_fails() {
	run_install v0.1.0 >/dev/null
	local err

	if err=$(FAKE_VM_STATE=running FAKE_FAIL=xena run_uninstall 2>&1 >/dev/null); then
		fail "uninstall succeeded, want refusal"
	fi

	[[ "$err" == *"refusing uninstall: could not stop vm xena-dev, run xena vm stop first"* ]] ||
		fail "stderr '$err' does not contain the vm refusal"
	assert_file "$root/usr/local/bin/xena-watch"
	assert_no_log_match '^nft destroy'
}

test_uninstall_skips_stopped_vm() {
	run_install v0.1.0 >/dev/null

	FAKE_VM_STATE="shut off" run_uninstall >/dev/null

	assert_no_log_match '^xena vm stop'
}

test_uninstall_warns_on_failures() {
	run_install v0.1.0 >/dev/null
	local out err="$work/err"

	out=$(PURGE=1 FAKE_FAIL="nft userdel groupdel" run_uninstall 2>"$err")

	[[ "$out" == *"uninstalled xena with 4 warnings"* ]] || fail "stdout '$out' does not count 4 warnings"
	grep -qF "warning: deleting nftables table inet xena failed" "$err" || fail "missing nft warning"
	grep -qF "warning: removing user xena-proxy failed" "$err" || fail "missing userdel warning"
	grep -qF "warning: removing group xena-prompt failed" "$err" || fail "missing groupdel warning"
}

test_install_skips_missing_apparmor() {
	git -C "$clone" rm -q -r deploy/apparmor
	git -C "$clone" commit -q -m drop
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.2.0

	run_install v0.2.0 >/dev/null

	assert_absent "$root/etc/apparmor.d"
	assert_no_log_match '^apparmor_parser'
}

test_install_stops_when_apparmor_fails() {
	if FAKE_FAIL=apparmor_parser run_install v0.1.0 >/dev/null 2>&1; then
		fail "install succeeded, want failure"
	fi

	assert_no_log_match '^systemctl'
}

test_uninstall_removes_apparmor_when_unload_fails() {
	local profile="$root/etc/apparmor.d/usr.local.bin.xena-tokend"

	run_install v0.1.0 >/dev/null

	FAKE_FAIL=apparmor_parser run_uninstall >/dev/null 2>&1 || fail "uninstall failed"

	assert_absent "$profile"
}

test_uninstall_unloads_apparmor() {
	local profile="$root/etc/apparmor.d/usr.local.bin.xena-tokend"

	run_install v0.1.0 >/dev/null

	run_uninstall >/dev/null

	assert_absent "$profile"
	assert_log "apparmor_parser -R $profile"
	run_uninstall >/dev/null
}

test_uninstall_idempotent() {
	run_install v0.1.0 >/dev/null
	run_uninstall >/dev/null

	run_uninstall >/dev/null
}

test_uninstall_removes_drop_ins() {
	run_install v0.1.0 >/dev/null
	mkdir -p "$root/etc/systemd/system/xena-proxy.service.d"
	touch "$root/etc/systemd/system/xena-proxy.service.d/override.conf"

	run_uninstall >/dev/null

	assert_absent "$root/etc/systemd/system/xena-proxy.service.d"
}

test_uninstall_keeps_other_binaries() {
	run_install v0.1.0 >/dev/null
	touch "$root/usr/local/bin/other-tool" "$root/usr/local/bin/xena-unrelated"

	run_uninstall >/dev/null

	assert_file "$root/usr/local/bin/other-tool"
	assert_file "$root/usr/local/bin/xena-unrelated"
}

test_uninstall_purge() {
	run_install v0.1.0 >/dev/null
	mkdir -p "$root/var/lib/xena-proxy" "$root/var/lib/xena-watch"

	PURGE=1 run_uninstall >/dev/null

	local dir
	for dir in xena-proxy xena-watch xena-desktop xena-expose xena-vm xena; do
		assert_absent "$root/var/lib/$dir"
	done
	assert_log "userdel xena-proxy"
	assert_log "userdel xena-watch"
	assert_log "groupdel xena-prompt"
}

test_uninstall_purge_skips_missing_accounts() {
	run_install v0.1.0 >/dev/null
	local out

	out=$(PURGE=1 FAKE_GETENT="" run_uninstall 2>&1)

	[[ "$out" == *"uninstalled xena" ]] || fail "output '$out' does not end with 'uninstalled xena'"
	assert_no_log_match '^userdel'
	assert_no_log_match '^groupdel'
}

run_test() {
	local name=$1

	setup

	local status=0
	set +e
	(
		set -e
		"$name"
	)
	status=$?
	set -e

	if [[ $status -eq 0 ]]; then
		echo "PASS $name"
	else
		echo "FAIL $name"
		failures=$((failures + 1))
	fi
	teardown
}

tests=(
	test_install_happy_path
	test_install_idempotent
	test_install_loads_apparmor
	test_install_skips_missing_apparmor
	test_install_stops_when_apparmor_fails
	test_install_builds_from_tag
	test_install_refuses_unsigned_tag
	test_install_refuses_foreign_signer
	test_install_refuses_tag_off_main
	test_install_refuses_non_v_tag
	test_install_refuses_while_cut
	test_install_refuses_cut_during_build
	test_install_refuses_copied_tag
	test_install_refuses_missing_tag
	test_install_refuses_no_tags
	test_install_defaults_to_latest_tag_after_fetch
	test_install_removes_stale_units
	test_install_backs_up_foreign_hook
	test_install_prints_progress
	test_install_refuses_lightweight_tag
	test_install_refuses_missing_signers_file
	test_install_refuses_unpushed_main_tag
	test_install_build_failure_cleans_up
	test_install_clears_go_environment
	test_install_usage
	test_rollback_needs_version
	test_nftables_unit_skips_without_table
	test_services_skip_without_vm_config
	test_uninstall_keeps_state
	test_uninstall_stops_running_vm
	test_uninstall_refuses_when_vm_stop_fails
	test_uninstall_skips_stopped_vm
	test_uninstall_warns_on_failures
	test_uninstall_unloads_apparmor
	test_uninstall_removes_apparmor_when_unload_fails
	test_uninstall_idempotent
	test_uninstall_removes_drop_ins
	test_uninstall_keeps_other_binaries
	test_uninstall_purge
	test_uninstall_purge_skips_missing_accounts
)

for t in "${tests[@]}"; do
	run_test "$t"
done

if [[ $failures -gt 0 ]]; then
	echo "$failures test(s) failed"
	exit 1
fi
