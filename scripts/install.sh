#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=${XENA_REPO_DIR:-$(dirname "$script_dir")}
destdir=${DESTDIR:-}
sudo_cmd=${SUDO-sudo}
signers=${XENA_ALLOWED_SIGNERS:-$HOME/.config/xena/allowed_signers}
user=$(id -un)

binaries=(
	xena
	xena-proxy
	xena-prompt
	xena-tokend
	xena-vault
	xena-watch
)

system_units=(
	xena-nftables.service
	xena-proxy.service
	xena-watch.service
	xena-cut.service
	xena-resume.service
	xena-expose@.service
	xena-unexpose@.service
)
installed_system_units=()
installed_user_units=()

refuse() {
	echo "$*" >&2
	exit 1
}

as_root() {
	if [[ -n "$sudo_cmd" ]]; then
		"$sudo_cmd" "$@"
	else
		"$@"
	fi
}

is_system_unit() {
	local name=$1 unit

	for unit in "${system_units[@]}"; do
		if [[ "$unit" == "$name" ]]; then
			return 0
		fi
	done

	return 1
}

check_not_root() {
	if [[ $EUID -eq 0 ]]; then
		refuse "refusing install: run as your user, not root"
	fi
}

check_not_cut() {
	if [[ -e "$destdir/var/lib/xena/cut" ]]; then
		refuse "refusing install: vm network is cut, run xena resume first"
	fi
}

verify_tag() {
	local tag=$1

	if [[ "$tag" != v* ]]; then
		refuse "refusing tag $tag: not a v* tag"
	fi

	git -C "$repo_dir" fetch -q --tags origin main

	if ! git -C "$repo_dir" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
		refuse "refusing tag $tag: not found"
	fi

	if ! git -C "$repo_dir" \
		-c gpg.format=ssh \
		-c gpg.ssh.allowedSignersFile="$signers" \
		verify-tag "refs/tags/$tag" >/dev/null 2>&1; then
		refuse "refusing tag $tag: signature not valid"
	fi

	if ! git -C "$repo_dir" cat-file tag "refs/tags/$tag" | grep -qxF "tag $tag"; then
		refuse "refusing tag $tag: signed as a different tag"
	fi

	if ! git -C "$repo_dir" merge-base --is-ancestor "refs/tags/$tag^{commit}" origin/main; then
		refuse "refusing tag $tag: not reachable from origin/main"
	fi
}

build() {
	local tag=$1

	git -C "$repo_dir" archive "refs/tags/$tag" | tar -x -C "$build_dir"
	(
		cd "$build_dir"
		export GOWORK=off GOFLAGS="" GOENV=off GOTOOLCHAIN=local
		go mod verify
		CGO_ENABLED=0 go build -trimpath -o "$build_dir/bin/" ./cmd/...
	)
}

install_file() {
	local mode=$1 src=$2 dst=$3

	if [[ -f "$src" ]]; then
		as_root install -D -m "$mode" "$src" "$destdir$dst"
	fi
}

install_files() {
	local src=$build_dir file name

	for name in "${binaries[@]}"; do
		install_file 0755 "$src/bin/$name" "/usr/local/bin/$name"
	done

	for file in "$src"/config/*.yaml; do
		install_file 0644 "$file" "/usr/local/share/xena/config/$(basename "$file")"
	done

	install_file 0644 "$src/deploy/nftables/xena.nft" /etc/nftables.d/xena.nft
	install_file 0644 "$src/deploy/polkit/50-xena.rules" /etc/polkit-1/rules.d/50-xena.rules
	install_file 0644 "$src/deploy/sysusers/xena.conf" /etc/sysusers.d/xena.conf
	install_file 0755 "$src/deploy/libvirt/hooks/qemu" /etc/libvirt/hooks/qemu

	for file in "$src"/deploy/systemd/*; do
		if [[ ! -f "$file" ]]; then
			continue
		fi

		name=$(basename "$file")

		if is_system_unit "$name"; then
			install_file 0644 "$file" "/etc/systemd/system/$name"
			if grep -q '^\[Install\]' "$file"; then
				installed_system_units+=("$name")
			fi
		else
			install_file 0644 "$file" "/etc/systemd/user/$name"
			if grep -q '^\[Install\]' "$file"; then
				installed_user_units+=("$name")
			fi
		fi
	done
}

create_users() {
	if [[ -f "$destdir/etc/sysusers.d/xena.conf" ]]; then
		as_root systemd-sysusers "$destdir/etc/sysusers.d/xena.conf"
	fi
}

make_dir() {
	local mode=$1 owner=$2 path=$3

	as_root install -d -m "$mode" "$destdir$path"
	if [[ "$owner" != "root" ]]; then
		as_root chown "$owner" "$destdir$path"
	fi
}

create_dirs() {
	make_dir 0711 "$user" /var/lib/xena-vm
	make_dir 2750 "$user:xena-watch" /var/lib/xena-desktop
	make_dir 0755 root /var/lib/xena-expose
	make_dir 0755 root /var/lib/xena

	printf 'd /run/xena-guard 0750 %s xena-watch -\n' "$user" >"$build_dir/xena-guard.conf"
	install_file 0644 "$build_dir/xena-guard.conf" /etc/tmpfiles.d/xena-guard.conf
	as_root systemd-tmpfiles --create "$destdir/etc/tmpfiles.d/xena-guard.conf"
}

enable_units() {
	as_root systemctl daemon-reload
	systemctl --user daemon-reload

	if [[ ${#installed_system_units[@]} -gt 0 ]]; then
		as_root systemctl enable "${installed_system_units[@]}"
		as_root systemctl restart "${installed_system_units[@]}"
	fi

	if [[ ${#installed_user_units[@]} -gt 0 ]]; then
		systemctl --user enable "${installed_user_units[@]}"
		systemctl --user restart "${installed_user_units[@]}"
	fi
}

install_tag() {
	local tag=${1:-}

	if [[ -z "$tag" ]]; then
		refuse "missing version: make install VERSION=vX.Y.Z"
	fi

	check_not_root
	check_not_cut
	verify_tag "$tag"

	build_dir=$(mktemp -d)
	trap 'rm -rf "$build_dir"' EXIT

	build "$tag"
	install_files
	create_users
	create_dirs
	check_not_cut
	enable_units

	echo "installed xena $tag"
}

case "${1:-}" in
install)
	shift
	install_tag "$@"
	;;
uninstall)
	exec "$script_dir/uninstall.sh"
	;;
*)
	echo "usage: install.sh install VERSION | uninstall" >&2
	exit 2
	;;
esac
