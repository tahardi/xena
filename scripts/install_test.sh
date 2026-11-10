#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
install_sh="$script_dir/install.sh"
uninstall_sh="$script_dir/uninstall.sh"
release_sh="$script_dir/release.sh"
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
for sub in ${FAKE_VIRSH_FAIL:-}; do
	if [[ " $* " == *" $sub "* ]]; then
		exit 1
	fi
done
case " $* " in
*" domstate "*)
	if [[ -z "${FAKE_VM_STATE:-}" ]]; then
		exit 1
	fi
	echo "$FAKE_VM_STATE"
	;;
*" net-list "*)
	printf '%s\n' "${FAKE_NETS:-}"
	;;
esac
EOF

	write_fake go <<'EOF'
echo "go-env GOWORK=${GOWORK-} GOFLAGS=${GOFLAGS-} GOENV=${GOENV-} GOTOOLCHAIN=${GOTOOLCHAIN-}" >>"$FAKE_LOG"
echo "go-target GOOS=${GOOS-} GOARCH=${GOARCH-} $*" >>"$FAKE_LOG"
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
	git -C "$clone" config user.signingkey "$work/key"
	git -C "$clone" remote add origin "$work/origin.git"

	commit_file go.mod "module example.com/xena"
	commit_file config/watch.yaml "interval: 5s"
	commit_file deploy/nftables/xena.nft "table inet xena {}"
	commit_file deploy/polkit/50-xena.rules "polkit.addRule(function () {});"
	commit_file deploy/sysusers/xena.conf "u xena-proxy -"
	commit_file deploy/libvirt/hooks/qemu "#!/bin/sh"
	commit_file deploy/libvirt/xena-net.xml "<network><name>xena</name></network>"
	commit_file deploy/apparmor/usr.local.bin.xena-tokend "profile xena-tokend {}"
	commit_file deploy/apparmor/usr.local.bin.xena-vault "profile xena-vault {}"
	commit_file deploy/journald/xena.conf $'[Journal]\nMaxRetentionSec=90day'
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

run_release() {
	XENA_REPO_DIR="$clone" \
		XENA_ALLOWED_SIGNERS="$signers" \
		PATH="$work/fakebin:$PATH" \
		TMPDIR="$work/tmp" \
		"$release_sh" "$@"
}

push_commit() {
	local name=$1

	commit_file "$name" "$name"
	git -C "$clone" commit -q -m "$name"
	git -C "$clone" push -q origin main
}

push_tag() {
	local tag=$1

	signed_tag "$work/key" "$tag"
	git -C "$clone" push -q origin "$tag"
}

setup_release() {
	push_commit one
	push_tag v0.1.1
	push_commit two
}

push_side_tag() {
	local tag=$1

	git -C "$clone" checkout -q -b side
	commit_file side "side"
	git -C "$clone" commit -q -m side
	push_tag "$tag"
	git -C "$clone" checkout -q main
	git -C "$clone" branch -q -D side
	git -C "$clone" tag -d "$tag" >/dev/null
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

assert_origin_tag() {
	local tag=$1

	[[ -n "$(git -C "$work/origin.git" tag -l "$tag")" ]] || fail "origin missing tag $tag"
}

assert_release_refused() {
	local want=$1 before err
	shift

	before=$(git -C "$work/origin.git" tag -l)

	if err=$(run_release "$@" 2>&1 >/dev/null); then
		fail "release succeeded, want refusal"
	fi

	[[ "$err" == *"$want"* ]] || fail "stderr '$err' does not contain '$want'"

	[[ "$(git -C "$work/origin.git" tag -l)" == "$before" ]] || fail "origin tags changed"
	[[ "$(git -C "$clone" tag -l)" == "$before" ]] || fail "clone tags differ from origin"
}

test_install_happy_path() {
	run_install v0.1.0 >/dev/null

	assert_file "$root/usr/local/bin/xena-watch"
	assert_mode 755 "$root/usr/local/bin/xena-watch"
	assert_file "$root/usr/local/share/xena/config/watch.yaml"
	assert_file "$root/etc/systemd/system/xena-proxy.service"
	assert_file "$root/etc/systemd/user/xena-report.timer"
	assert_file "$root/usr/share/polkit-1/rules.d/50-xena.rules"
	assert_file "$root/etc/nftables.d/xena.nft"
	assert_file "$root/etc/sysusers.d/xena.conf"
	assert_file "$root/etc/systemd/journald.conf.d/xena.conf"
	assert_mode 644 "$root/etc/systemd/journald.conf.d/xena.conf"
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
	assert_log "systemctl restart systemd-journald"
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
	local profile name load_line systemctl_line

	run_install v0.1.0 >/dev/null

	systemctl_line=$(grep -n '^systemctl' "$FAKE_LOG" | head -1 | cut -d: -f1)
	for name in usr.local.bin.xena-tokend usr.local.bin.xena-vault; do
		profile="$root/etc/apparmor.d/$name"
		assert_file "$profile"
		assert_mode 644 "$profile"
		assert_log "apparmor_parser -r $profile"
		load_line=$(grep -nxF "apparmor_parser -r $profile" "$FAKE_LOG" | cut -d: -f1)
		[[ $load_line -lt $systemctl_line ]] || fail "$name loaded after the first systemctl call"
	done
}

test_install_defines_network() {
	local xml="$root/usr/local/share/xena/libvirt/xena-net.xml" define_line restart_line

	run_install v0.1.0 >/dev/null

	assert_file "$xml"
	assert_mode 644 "$xml"
	assert_log_match '^virsh -c qemu:///system net-define .*/xena-net\.xml$'
	assert_log "virsh -c qemu:///system net-autostart xena"
	assert_log "virsh -c qemu:///system net-start xena"
	define_line=$(grep -n '^virsh -c qemu:///system net-define ' "$FAKE_LOG" | head -1 | cut -d: -f1)
	restart_line=$(grep -nxF "systemctl restart xena-nftables.service xena-proxy.service" "$FAKE_LOG" | cut -d: -f1)
	[[ $define_line -gt $restart_line ]] || fail "network defined before the nftables table was loaded"
}

test_install_starts_network_once() {
	FAKE_NETS=xena run_install v0.1.0 >/dev/null

	assert_log_match '^virsh -c qemu:///system net-define '
	assert_log "virsh -c qemu:///system net-autostart xena"
	assert_no_log_match '^virsh .*net-start'
}

test_install_skips_missing_network() {
	git -C "$clone" rm -q deploy/libvirt/xena-net.xml
	git -C "$clone" commit -q -m drop
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.2.0

	run_install v0.2.0 >/dev/null

	assert_absent "$root/usr/local/share/xena/libvirt"
	assert_no_log_match '^virsh'
}

test_install_removes_dropped_network() {
	run_install v0.1.0 >/dev/null
	git -C "$clone" rm -q deploy/libvirt/xena-net.xml
	git -C "$clone" commit -q -m drop
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.2.0
	: >"$FAKE_LOG"

	run_install v0.2.0 >/dev/null

	assert_absent "$root/usr/local/share/xena/libvirt"
	assert_log "virsh -c qemu:///system net-destroy xena"
	assert_log "virsh -c qemu:///system net-undefine xena"
	assert_no_log_match '^virsh .*net-define'
}

test_install_warns_when_dropped_network_undefine_fails() {
	local err="$work/err"

	run_install v0.1.0 >/dev/null
	git -C "$clone" rm -q deploy/libvirt/xena-net.xml
	git -C "$clone" commit -q -m drop
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.2.0

	FAKE_VIRSH_FAIL="net-destroy net-undefine" run_install v0.2.0 >/dev/null 2>"$err" || fail "install failed"

	grep -qF "warning: removing libvirt network xena failed" "$err" || fail "missing network warning"
	assert_absent "$root/usr/local/share/xena/libvirt"
}

test_install_stops_when_network_define_fails() {
	if FAKE_VIRSH_FAIL=net-define run_install v0.1.0 >/dev/null 2>&1; then
		fail "install succeeded, want failure"
	fi

	assert_no_log_match '^virsh .*net-autostart'
	assert_no_log_match '^virsh .*net-start'
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

test_install_defaults_to_highest_tag() {
	push_commit one
	push_tag v0.10.0
	push_commit two
	push_tag v0.9.0
	push_commit three

	run_install >/dev/null

	assert_log_match '^go build .*-X main\.version=v0\.10\.0 '
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

test_install_skips_incomplete_vm_config() {
	commit_file config/vm.yaml "version: 1"
	git -C "$clone" commit -q -m partial
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.5.0

	run_install v0.5.0 >/dev/null

	assert_absent "$root/usr/local/share/xena/config/vm.yaml"

	commit_file config/vm.yaml "network:"
	git -C "$clone" commit -q -m complete
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.6.0

	run_install v0.6.0 >/dev/null

	assert_file "$root/usr/local/share/xena/config/vm.yaml"
}

test_install_fills_proxy_port() {
	commit_file config/vm.yaml $'version: 1\nnetwork:\n  vm_address: 192.168.150.10\nproxy_port: 4128'
	commit_file deploy/systemd/xena-tokend.service $'[Service]\nEnvironment=HTTPS_PROXY=http://127.0.0.1:@PROXY_PORT@'
	git -C "$clone" commit -q -m port
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.7.0

	run_install v0.7.0 >/dev/null

	grep -qxF "Environment=HTTPS_PROXY=http://127.0.0.1:4128" "$root/etc/systemd/user/xena-tokend.service" ||
		fail "proxy port not filled in"
}

test_install_builds_agent_first() {
	local agent_line xena_line

	git -C "$clone" commit -q --allow-empty -m agent
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.7.1

	run_install v0.7.1 >/dev/null

	agent_line=$(grep -n '^go-target GOOS=linux GOARCH=amd64 build .*-o vm/agent/xena-agent' "$FAKE_LOG" | cut -d: -f1)
	xena_line=$(grep -n '^go-target .*\./cmd/\.\.\.' "$FAKE_LOG" | cut -d: -f1)
	if [[ -z "$agent_line" || -z "$xena_line" || "$agent_line" -ge "$xena_line" ]]; then
		fail "agent not built for linux before the xena binaries"
	fi
}

test_install_warns_without_proxy_port() {
	local err="$work/err"

	commit_file deploy/systemd/xena-tokend.service $'[Service]\nEnvironment=HTTPS_PROXY=http://127.0.0.1:@PROXY_PORT@'
	git -C "$clone" commit -q -m port
	git -C "$clone" push -q origin main
	signed_tag "$work/key" v0.7.0

	run_install v0.7.0 >/dev/null 2>"$err"

	grep -qF "warning: proxy_port missing from vm.yaml, xena-tokend.service left without it" "$err" ||
		fail "missing proxy port warning"
	assert_file "$root/etc/systemd/user/xena-tokend.service"
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
	assert_absent "$root/usr/share/polkit-1/rules.d/50-xena.rules"
	assert_absent "$root/etc/systemd/journald.conf.d/xena.conf"
	assert_file "$root/var/lib/xena-proxy/keep.txt"
	assert_log "nft destroy table inet xena"
	[[ $(grep -c '^systemctl restart systemd-journald$' "$FAKE_LOG") -eq 2 ]] ||
		fail "uninstall did not restart systemd-journald"
	assert_no_log_match '^userdel'
}

test_uninstall_stops_running_vm() {
	run_install v0.1.0 >/dev/null

	FAKE_VM_STATE=running run_uninstall >/dev/null

	assert_log_match '^virsh -r '
	assert_log "xena vm stop"
	local stop_line destroy_line
	stop_line=$(grep -n '^xena vm stop' "$FAKE_LOG" | cut -d: -f1)
	destroy_line=$(grep -n '^nft destroy' "$FAKE_LOG" | cut -d: -f1)
	[[ $stop_line -lt $destroy_line ]] ||
		fail "vm stopped after the nftables table was deleted"
}

test_uninstall_removes_network() {
	run_install v0.1.0 >/dev/null
	: >"$FAKE_LOG"
	local stop_line destroy_line

	FAKE_NETS=xena FAKE_VM_STATE=running run_uninstall >/dev/null

	assert_log "virsh -c qemu:///system net-destroy xena"
	assert_log "virsh -c qemu:///system net-undefine xena"
	stop_line=$(grep -n '^xena vm stop' "$FAKE_LOG" | cut -d: -f1)
	destroy_line=$(grep -n '^virsh -c qemu:///system net-destroy xena' "$FAKE_LOG" | cut -d: -f1)
	[[ $destroy_line -gt $stop_line ]] || fail "network destroyed before the vm stopped"
	assert_absent "$root/usr/local/share/xena"
}

test_uninstall_skips_missing_network() {
	run_install v0.1.0 >/dev/null
	local out

	out=$(run_uninstall 2>&1)

	[[ "$out" == *"uninstalled xena" ]] || fail "output '$out' does not end with 'uninstalled xena'"
	[[ "$out" != *"warning"* ]] || fail "output '$out' has warnings"
	assert_no_log_match '^virsh .*net-destroy'
	assert_no_log_match '^virsh .*net-undefine'
}

test_uninstall_warns_when_network_undefine_fails() {
	run_install v0.1.0 >/dev/null
	local out err="$work/err"

	out=$(FAKE_NETS=xena FAKE_VIRSH_FAIL=net-undefine run_uninstall 2>"$err")

	[[ "$out" == *"uninstalled xena with 1 warnings"* ]] || fail "stdout '$out' does not count 1 warning"
	grep -qF "warning: removing libvirt network xena failed" "$err" || fail "missing network warning"
}

test_uninstall_undefines_stopped_network() {
	run_install v0.1.0 >/dev/null
	local out

	out=$(FAKE_NETS=xena FAKE_VIRSH_FAIL=net-destroy run_uninstall 2>&1)

	[[ "$out" == *"uninstalled xena" ]] || fail "output '$out' does not end with 'uninstalled xena'"
	[[ "$out" != *"warning"* ]] || fail "output '$out' has warnings"
	assert_log "virsh -c qemu:///system net-undefine xena"
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
	local profile="$root/etc/apparmor.d/usr.local.bin.xena-tokend" out err="$work/err"

	run_install v0.1.0 >/dev/null

	out=$(FAKE_FAIL=apparmor_parser run_uninstall 2>"$err") || fail "uninstall failed"

	assert_absent "$profile"
	[[ "$out" == *"uninstalled xena with 2 warnings"* ]] || fail "stdout '$out' does not count 2 warnings"
	grep -qF "warning: unloading apparmor profile usr.local.bin.xena-tokend failed" "$err" ||
		fail "missing apparmor warning"
}

test_uninstall_unloads_apparmor() {
	local profile name

	run_install v0.1.0 >/dev/null

	run_uninstall >/dev/null

	for name in usr.local.bin.xena-tokend usr.local.bin.xena-vault; do
		profile="$root/etc/apparmor.d/$name"
		assert_absent "$profile"
		assert_log "apparmor_parser -R $profile"
	done
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

test_release_patch_bumps_patch() {
	setup_release

	run_release patch >/dev/null

	assert_origin_tag v0.1.2
}

test_release_minor_bumps_minor() {
	setup_release

	run_release minor >/dev/null

	assert_origin_tag v0.2.0
}

test_release_major_bumps_major() {
	setup_release

	run_release major >/dev/null

	assert_origin_tag v1.0.0
}

test_release_first_tag() {
	git -C "$clone" push -q origin :refs/tags/v0.1.0
	git -C "$clone" tag -d v0.1.0 >/dev/null

	local part
	for part in major minor patch; do
		run_release "$part" >/dev/null

		assert_origin_tag v0.1.0

		git -C "$clone" push -q origin :refs/tags/v0.1.0
		git -C "$clone" tag -d v0.1.0 >/dev/null
	done
}

test_release_patch_passes_nine() {
	push_commit one
	push_tag v0.1.9
	push_commit two

	run_release patch >/dev/null

	assert_origin_tag v0.1.10
}

test_release_uses_highest_tag() {
	push_commit one
	push_tag v0.10.0
	push_commit two
	push_tag v0.9.0
	push_commit three

	run_release patch >/dev/null

	assert_origin_tag v0.10.1
}

test_release_uses_fresh_origin_main() {
	setup_release
	git clone -q "$work/origin.git" "$work/other"
	git -C "$work/other" config user.email test@example.com
	git -C "$work/other" config user.name Test
	git -C "$work/other" commit -q --allow-empty -m other
	git -C "$work/other" push -q origin main

	run_release patch >/dev/null

	local got want
	got=$(git -C "$work/origin.git" rev-parse 'refs/tags/v0.1.2^{commit}')
	want=$(git -C "$work/other" rev-parse HEAD)

	[[ "$got" == "$want" ]] || fail "tag at $got, want fresh origin/main $want"
}

test_release_tags_origin_main() {
	setup_release
	git -C "$clone" checkout -q -b local-work
	commit_file local "local"
	git -C "$clone" commit -q -m local

	local main_before
	main_before=$(git -C "$work/origin.git" rev-parse main)

	run_release patch >/dev/null

	local got want head
	got=$(git -C "$work/origin.git" rev-parse 'refs/tags/v0.1.2^{commit}')
	want=$(git -C "$clone" rev-parse origin/main)
	head=$(git -C "$clone" rev-parse HEAD)

	[[ "$got" == "$want" ]] || fail "tag at $got, want origin/main $want"
	[[ "$got" != "$head" ]] || fail "tag at HEAD"
	[[ "$(git -C "$work/origin.git" rev-parse main)" == "$main_before" ]] || fail "origin main moved"
	[[ -z "$(git -C "$work/origin.git" branch --list local-work)" ]] || fail "branch pushed to origin"
}

test_release_prints_next_step() {
	setup_release

	local out
	out=$(run_release patch)

	[[ "$out" == *"released v0.1.2"* ]] || fail "output '$out' does not name the tag"
	[[ "$out" == *"make install"* ]] || fail "output '$out' does not mention make install"
}

test_release_refuses_bad_part() {
	assert_release_refused "usage: release.sh major|minor|patch"
	assert_release_refused "usage: release.sh major|minor|patch" sideways

	local status=0
	run_release sideways >/dev/null 2>&1 || status=$?

	[[ $status -eq 2 ]] || fail "exit $status, want 2"
}

test_release_refuses_tagged_head() {
	push_commit one
	push_tag v0.1.1

	assert_release_refused "refusing release: origin/main is already v0.1.1" patch
}

test_release_refuses_existing_tag() {
	setup_release
	push_side_tag v0.1.2

	assert_release_refused "refusing release: tag v0.1.2 already exists" patch

	[[ "$(git -C "$work/origin.git" rev-parse 'refs/tags/v0.1.2^{commit}')" != \
		"$(git -C "$clone" rev-parse origin/main)" ]] || fail "origin tag moved to origin/main"
}

test_release_refuses_tag_only_on_origin() {
	setup_release
	push_side_tag v0.1.2

	local real_git
	real_git=$(command -v git)
	write_fake git <<EOF
if [[ "\$3" == "fetch" ]]; then
	exit 0
fi
exec "$real_git" "\$@"
EOF

	local err
	if err=$(run_release patch 2>&1 >/dev/null); then
		fail "release succeeded, want refusal"
	fi

	[[ "$err" == *"refusing release: tag v0.1.2 already exists"* ]] || fail "stderr '$err' lacks the refusal"
	[[ -z "$(git -C "$clone" tag -l v0.1.2)" ]] || fail "local tag left behind"
}

test_release_refuses_unparsable_tag() {
	push_commit one
	push_tag v1.0.0-rc.1
	push_commit two

	assert_release_refused "refusing release: cannot read version from v1.0.0-rc.1" patch
}

test_release_refuses_leading_zero_tag() {
	push_commit one
	push_tag v1.09.0
	push_commit two

	assert_release_refused "refusing release: cannot read version from v1.09.0" patch
}

test_release_refuses_without_signing_key() {
	setup_release
	git -C "$clone" config --unset user.signingkey

	assert_release_refused "refusing release: no ssh signing key configured" patch
}

test_release_refuses_missing_signers_file() {
	setup_release
	signers="$work/missing_signers"

	assert_release_refused "refusing release: allowed signers file not found" patch
}

test_release_refuses_foreign_signer() {
	setup_release
	git -C "$clone" config user.signingkey "$work/other_key"

	assert_release_refused "refusing release: tag v0.1.2 signature not valid" patch
}

test_release_refuses_unsigned_latest_tag() {
	push_commit one
	git -C "$clone" tag -a v0.1.1 -m v0.1.1
	git -C "$clone" push -q origin v0.1.1
	push_commit two

	assert_release_refused "refusing release: tag v0.1.1 signature not valid" patch
}

test_release_refuses_failed_fetch() {
	setup_release
	git -C "$clone" remote set-url origin "$work/missing.git"

	assert_release_refused "refusing release: fetching origin failed" patch
}

test_release_refuses_failed_signing() {
	setup_release
	git -C "$clone" config user.signingkey "$work/missing_key"

	assert_release_refused "refusing release: signing v0.1.2 failed" patch

	local out
	out=$(run_release patch 2>/dev/null) || true

	[[ "$out" == *"signing v0.1.2, touch the YubiKey"* ]] || fail "output '$out' lacks the signing line"
}

test_release_refuses_failed_push() {
	setup_release
	printf '#!/bin/sh\nexit 1\n' >"$work/origin.git/hooks/pre-receive"
	chmod +x "$work/origin.git/hooks/pre-receive"

	assert_release_refused "refusing release: pushing v0.1.2 failed" patch
}

test_release_refuses_as_root() {
	setup_release
	write_fake id <<<'echo 0'

	assert_release_refused "refusing release: run as your user, not root" patch
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
	test_install_defines_network
	test_install_starts_network_once
	test_install_skips_missing_network
	test_install_removes_dropped_network
	test_install_warns_when_dropped_network_undefine_fails
	test_install_stops_when_network_define_fails
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
	test_install_defaults_to_highest_tag
	test_install_removes_stale_units
	test_install_backs_up_foreign_hook
	test_install_prints_progress
	test_install_refuses_lightweight_tag
	test_install_refuses_missing_signers_file
	test_install_refuses_unpushed_main_tag
	test_install_build_failure_cleans_up
	test_install_skips_incomplete_vm_config
	test_install_fills_proxy_port
	test_install_builds_agent_first
	test_install_warns_without_proxy_port
	test_install_clears_go_environment
	test_install_usage
	test_rollback_needs_version
	test_nftables_unit_skips_without_table
	test_services_skip_without_vm_config
	test_uninstall_keeps_state
	test_uninstall_stops_running_vm
	test_uninstall_removes_network
	test_uninstall_skips_missing_network
	test_uninstall_warns_when_network_undefine_fails
	test_uninstall_undefines_stopped_network
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
	test_release_patch_bumps_patch
	test_release_minor_bumps_minor
	test_release_major_bumps_major
	test_release_first_tag
	test_release_patch_passes_nine
	test_release_uses_highest_tag
	test_release_uses_fresh_origin_main
	test_release_tags_origin_main
	test_release_prints_next_step
	test_release_refuses_bad_part
	test_release_refuses_tagged_head
	test_release_refuses_existing_tag
	test_release_refuses_tag_only_on_origin
	test_release_refuses_unparsable_tag
	test_release_refuses_leading_zero_tag
	test_release_refuses_without_signing_key
	test_release_refuses_missing_signers_file
	test_release_refuses_foreign_signer
	test_release_refuses_unsigned_latest_tag
	test_release_refuses_failed_fetch
	test_release_refuses_failed_signing
	test_release_refuses_failed_push
	test_release_refuses_as_root
)

for t in "${tests[@]}"; do
	run_test "$t"
done

if [[ $failures -gt 0 ]]; then
	echo "$failures test(s) failed"
	exit 1
fi
