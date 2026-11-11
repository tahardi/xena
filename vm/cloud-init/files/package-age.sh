#!/usr/bin/env bash
set -euo pipefail

dir=/etc/uv
cutoff=$(date -u -d '7 days ago' +%Y-%m-%d)

mkdir -p "$dir"
tmp=$(mktemp "$dir/.uv.toml.XXXXXX")
trap 'rm -f "$tmp"' EXIT

printf 'exclude-newer = "%sT00:00:00Z"\nno-build = true\n' "$cutoff" >"$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$dir/uv.toml"
