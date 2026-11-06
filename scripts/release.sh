#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=${XENA_REPO_DIR:-$(dirname "$script_dir")}
signers=${XENA_ALLOWED_SIGNERS:-$HOME/.config/xena/allowed_signers}

refuse() {
	echo "$*" >&2
	exit 1
}

verify_tag() {
	local tag=$1

	git -C "$repo_dir" \
		-c gpg.format=ssh \
		-c gpg.ssh.allowedSignersFile="$signers" \
		verify-tag "refs/tags/$tag" >/dev/null 2>&1
}

release() {
	local part=$1 latest next major minor patch

	if [[ $(id -u) -eq 0 ]]; then
		refuse "refusing release: run as your user, not root"
	fi

	if [[ ! -f "$signers" ]]; then
		refuse "refusing release: allowed signers file not found"
	fi

	if [[ -z "$(git -C "$repo_dir" config --get user.signingkey)" ]]; then
		refuse "refusing release: no ssh signing key configured"
	fi

	if ! git -C "$repo_dir" fetch -q --tags origin main; then
		refuse "refusing release: fetching origin failed"
	fi

	latest=$(git -C "$repo_dir" tag --merged origin/main --list 'v*' --sort=v:refname | tail -n 1)

	if [[ -z "$latest" ]]; then
		next=v0.1.0
	else
		if [[ ! "$latest" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
			refuse "refusing release: cannot read version from $latest"
		fi

		if ! verify_tag "$latest"; then
			refuse "refusing release: tag $latest signature not valid"
		fi

		if [[ "$(git -C "$repo_dir" rev-parse "refs/tags/$latest^{commit}")" == \
			"$(git -C "$repo_dir" rev-parse origin/main)" ]]; then
			refuse "refusing release: origin/main is already $latest"
		fi

		IFS=. read -r major minor patch <<<"${latest#v}"

		case "$part" in
		major) next=v$((major + 1)).0.0 ;;
		minor) next=v$major.$((minor + 1)).0 ;;
		patch) next=v$major.$minor.$((patch + 1)) ;;
		esac
	fi

	if git -C "$repo_dir" rev-parse -q --verify "refs/tags/$next" >/dev/null ||
		[[ -n "$(git -C "$repo_dir" ls-remote --tags origin "refs/tags/$next")" ]]; then
		refuse "refusing release: tag $next already exists"
	fi

	echo "signing $next, touch the YubiKey when it blinks"

	if ! git -C "$repo_dir" -c gpg.format=ssh tag -s "$next" -m "$next" origin/main; then
		refuse "refusing release: signing $next failed"
	fi

	if ! verify_tag "$next"; then
		git -C "$repo_dir" tag -d "$next" >/dev/null
		refuse "refusing release: tag $next signature not valid"
	fi

	if ! git -C "$repo_dir" push -q origin "refs/tags/$next"; then
		git -C "$repo_dir" tag -d "$next" >/dev/null
		refuse "refusing release: pushing $next failed"
	fi

	echo "released $next"
	echo "run make install to install it"
}

case "${1:-}" in
major | minor | patch)
	release "$1"
	;;
*)
	echo "usage: release.sh major|minor|patch" >&2
	exit 2
	;;
esac
