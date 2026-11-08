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

warn() {
	echo "warning: $*" >&2
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

resolve_tag() {
	local tag=$1

	if [[ -n "$tag" && "$tag" != v* ]]; then
		refuse "refusing tag $tag: not a v* tag"
	fi

	git -C "$repo_dir" fetch -q --tags origin main

	if [[ -z "$tag" ]]; then
		tag=$(git -C "$repo_dir" tag --merged origin/main --list 'v*' --sort=v:refname | tail -n 1)

		if [[ -z "$tag" ]]; then
			refuse "cannot locate tag for version latest"
		fi
	fi

	if ! git -C "$repo_dir" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
		refuse "cannot locate tag for version $tag"
	fi

	echo "$tag"
}

verify_tag() {
	local tag=$1

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
		CGO_ENABLED=0 go build \
			-trimpath \
			-ldflags "-X main.version=$tag" \
			-o "$build_dir/bin/" \
			./cmd/...
	)
}

install_file() {
	local mode=$1 src=$2 dst=$3

	if [[ -f "$src" ]]; then
		as_root install -D -m "$mode" "$src" "$destdir$dst"
	fi
}

install_hook() {
	local src=$1 dst="$destdir/etc/libvirt/hooks/qemu"

	if [[ ! -f "$src" ]]; then
		return
	fi

	if [[ -f "$dst" && ! -e "$dst.pre-xena" ]] && ! cmp -s "$src" "$dst"; then
		as_root cp -p "$dst" "$dst.pre-xena"
	fi

	install_file 0755 "$src" /etc/libvirt/hooks/qemu
}

remove_stale_units() {
	local src=$1 unit name

	for unit in "$destdir"/etc/systemd/system/xena* "$destdir"/etc/systemd/user/xena*; do
		name=$(basename "$unit")

		if [[ ! -f "$unit" || -f "$src/$name" ]]; then
			continue
		fi

		if [[ "$unit" == "$destdir/etc/systemd/system/"* ]]; then
			as_root systemctl disable --now "$name" || warn "disabling $name failed"
		else
			systemctl --user disable --now "$name" || warn "disabling $name failed"
		fi

		as_root rm -rf "$unit" "$unit.d"
	done
}

proxy_port() {
	local vm="$destdir/usr/local/share/xena/config/vm.yaml"

	if [[ -f "$vm" ]]; then
		awk '$1 == "proxy_port:" && $2 ~ /^[0-9]+$/ { print $2; exit }' "$vm"
	fi
}

fill_proxy_port() {
	local file=$1 port

	if ! grep -qF '@PROXY_PORT@' "$file"; then
		return
	fi

	port=$(proxy_port)
	if [[ -z "$port" ]]; then
		warn "proxy_port missing from vm.yaml, $(basename "$file") left without it"
		return
	fi

	sed -i "s/@PROXY_PORT@/$port/g" "$file"
}

install_files() {
	local src=$build_dir file name

	for name in "${binaries[@]}"; do
		install_file 0755 "$src/bin/$name" "/usr/local/bin/$name"
	done

	for file in "$src"/config/*.yaml; do
		if [[ $(basename "$file") == vm.yaml ]] && ! grep -q '^network:' "$file"; then
			continue
		fi

		install_file 0644 "$file" "/usr/local/share/xena/config/$(basename "$file")"
	done

	install_file 0644 "$src/deploy/nftables/xena.nft" /etc/nftables.d/xena.nft
	install_file 0644 "$src/deploy/polkit/50-xena.rules" /usr/share/polkit-1/rules.d/50-xena.rules
	install_file 0644 "$src/deploy/sysusers/xena.conf" /etc/sysusers.d/xena.conf
	install_file 0644 "$src/deploy/journald/xena.conf" /etc/systemd/journald.conf.d/xena.conf
	install_file 0644 "$src/deploy/libvirt/xena-net.xml" /usr/local/share/xena/libvirt/xena-net.xml

	if [[ ! -f "$src/deploy/libvirt/xena-net.xml" ]]; then
		as_root rm -rf "$destdir/usr/local/share/xena/libvirt"
	fi

	install_hook "$src/deploy/libvirt/hooks/qemu"
	remove_stale_units "$src/deploy/systemd"

	for file in "$src"/deploy/systemd/*; do
		if [[ ! -f "$file" ]]; then
			continue
		fi

		name=$(basename "$file")
		fill_proxy_port "$file"

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

install_apparmor() {
	local file profile

	for file in "$build_dir"/deploy/apparmor/*; do
		if [[ ! -f "$file" ]]; then
			continue
		fi

		profile=/etc/apparmor.d/$(basename "$file")
		install_file 0644 "$file" "$profile"
		as_root apparmor_parser -r "$destdir$profile"
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
	as_root systemctl restart systemd-journald

	if [[ ${#installed_system_units[@]} -gt 0 ]]; then
		as_root systemctl enable "${installed_system_units[@]}"
		as_root systemctl restart "${installed_system_units[@]}"
	fi

	if [[ ${#installed_user_units[@]} -gt 0 ]]; then
		systemctl --user enable "${installed_user_units[@]}"
		systemctl --user restart "${installed_user_units[@]}"
	fi
}

define_network() {
	local xml="$destdir/usr/local/share/xena/libvirt/xena-net.xml"

	if [[ ! -f "$xml" ]]; then
		return
	fi

	as_root virsh -c qemu:///system net-define "$xml"
	as_root virsh -c qemu:///system net-autostart xena

	if ! as_root virsh -c qemu:///system net-list --name | grep -xF xena >/dev/null; then
		as_root virsh -c qemu:///system net-start xena
	fi
}

install_tag() {
	local tag

	check_not_root
	check_not_cut
	tag=$(resolve_tag "${1:-}")
	verify_tag "$tag"

	build_dir=$(mktemp -d)
	trap 'rm -rf "$build_dir"' EXIT

	echo "building xena $tag"
	build "$tag"

	echo "installing xena $tag system files (sudo may ask for your password)"
	install_files
	install_apparmor
	create_users
	create_dirs
	check_not_cut
	enable_units
	define_network

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
	echo "usage: install.sh install [VERSION] | uninstall" >&2
	exit 2
	;;
esac
