#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

destdir=${DESTDIR:-}
sudo_cmd=${SUDO-sudo}
purge=${PURGE:-}
vm_name=${XENA_VM_NAME:-xena-dev}
warnings=0

binaries=(
	xena
	xena-proxy
	xena-prompt
	xena-tokend
	xena-vault
	xena-watch
)

state_dirs=(
	/var/lib/xena-proxy
	/var/lib/xena-watch
	/var/lib/xena-desktop
	/var/lib/xena-expose
	/var/lib/xena-vm
	/var/lib/xena
)

as_root() {
	if [[ -n "$sudo_cmd" ]]; then
		"$sudo_cmd" "$@"
	else
		"$@"
	fi
}

warn() {
	echo "warning: $*" >&2
	warnings=$((warnings + 1))
}

stop_vm() {
	local state

	state=$(virsh -r -c qemu:///system domstate "$vm_name" 2>/dev/null) || return 0

	if [[ "$state" == "shut off" ]]; then
		return 0
	fi

	if ! xena vm stop; then
		echo "refusing uninstall: could not stop vm $vm_name, run xena vm stop first" >&2
		exit 1
	fi
}

remove_network() {
	if ! as_root virsh -c qemu:///system net-list --all --name | grep -xF xena >/dev/null; then
		return 0
	fi

	as_root virsh -c qemu:///system net-destroy xena >/dev/null 2>&1 || true

	as_root virsh -c qemu:///system net-undefine xena ||
		warn "removing libvirt network xena failed"
}

disable_units() {
	local unit

	for unit in "$destdir"/etc/systemd/system/xena*; do
		[[ -f "$unit" && "$unit" != *@.service ]] || continue
		as_root systemctl disable --now "$(basename "$unit")" || warn "disabling $(basename "$unit") failed"
	done

	for unit in "$destdir"/etc/systemd/user/xena*; do
		[[ -f "$unit" ]] || continue
		systemctl --user disable --now "$(basename "$unit")" || warn "disabling $(basename "$unit") failed"
	done
}

remove_files() {
	local name files=(
		"$destdir"/etc/systemd/system/xena*
		"$destdir"/etc/systemd/user/xena*
		"$destdir"/etc/nftables.d/xena.nft
		"$destdir"/usr/share/polkit-1/rules.d/50-xena.rules
		"$destdir"/etc/sysusers.d/xena.conf
		"$destdir"/etc/tmpfiles.d/xena-guard.conf
		"$destdir"/etc/systemd/journald.conf.d/xena.conf
	)

	for name in "${binaries[@]}"; do
		files+=("$destdir/usr/local/bin/$name")
	done

	as_root rm -rf "${files[@]}" "$destdir/usr/local/share/xena"
}

remove_apparmor() {
	local profile

	for profile in "$destdir"/etc/apparmor.d/usr.local.bin.xena*; do
		[[ -f "$profile" ]] || continue
		as_root apparmor_parser -R "$profile" ||
			warn "unloading apparmor profile $(basename "$profile") failed"
		as_root rm -f "$profile"
	done
}

remove_hook() {
	local hook="$destdir/etc/libvirt/hooks/qemu"

	if [[ -f "$hook.pre-xena" ]]; then
		as_root mv "$hook.pre-xena" "$hook"
	else
		as_root rm -f "$hook"
	fi
}

purge_state() {
	local dir name

	for dir in "${state_dirs[@]}"; do
		as_root rm -rf "$destdir$dir"
	done

	for name in xena-proxy xena-watch; do
		if getent passwd "$name" >/dev/null; then
			as_root userdel "$name" || warn "removing user $name failed"
		fi
	done

	for name in xena-prompt xena-tokend; do
		if getent group "$name" >/dev/null; then
			as_root groupdel "$name" || warn "removing group $name failed"
		fi
	done
}

stop_vm
remove_network
disable_units
remove_files
remove_apparmor
remove_hook
as_root nft destroy table inet xena || warn "deleting nftables table inet xena failed"
as_root systemctl daemon-reload || warn "reloading systemd failed"
as_root systemctl restart systemd-journald || warn "restarting systemd-journald failed"
systemctl --user daemon-reload || warn "reloading user systemd failed"

if [[ "$purge" == "1" ]]; then
	purge_state
fi

if [[ $warnings -gt 0 ]]; then
	echo "uninstalled xena with $warnings warnings"
else
	echo "uninstalled xena"
fi
