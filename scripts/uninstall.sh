#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

destdir=${DESTDIR:-}
sudo_cmd=${SUDO-sudo}
purge=${PURGE:-}

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

disable_units() {
	local unit

	for unit in "$destdir"/etc/systemd/system/xena*; do
		[[ -f "$unit" ]] || continue
		as_root systemctl disable --now "$(basename "$unit")" || true
	done

	for unit in "$destdir"/etc/systemd/user/xena*; do
		[[ -f "$unit" ]] || continue
		systemctl --user disable --now "$(basename "$unit")" || true
	done
}

remove_files() {
	local name files=(
		"$destdir"/etc/systemd/system/xena*
		"$destdir"/etc/systemd/user/xena*
		"$destdir"/etc/nftables.d/xena.nft
		"$destdir"/etc/polkit-1/rules.d/50-xena.rules
		"$destdir"/etc/sysusers.d/xena.conf
		"$destdir"/etc/libvirt/hooks/qemu
		"$destdir"/etc/tmpfiles.d/xena-guard.conf
	)

	for name in "${binaries[@]}"; do
		files+=("$destdir/usr/local/bin/$name")
	done

	as_root rm -rf "${files[@]}" "$destdir/usr/local/share/xena"
}

purge_state() {
	local dir

	for dir in "${state_dirs[@]}"; do
		as_root rm -rf "$destdir$dir"
	done

	as_root userdel xena-proxy || true
	as_root userdel xena-watch || true
	as_root groupdel xena-prompt || true
}

disable_units
remove_files
as_root nft delete table inet xena 2>/dev/null || true
as_root systemctl daemon-reload
systemctl --user daemon-reload

if [[ "$purge" == "1" ]]; then
	purge_state
fi

echo "uninstalled xena"
