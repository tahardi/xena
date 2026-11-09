#!/usr/bin/env bash
set -euo pipefail

proxy=http://192.168.150.1:3128

status=0

probe_proxy() {
	if /usr/bin/curl --silent --fail --output /dev/null --max-time "$2" --noproxy '' --proxy "$proxy" "$1"; then
		echo "connected $1"
		return 1
	fi

	echo "blocked $1"
}

probe_proxy https://github.com:22/ 75 || status=1
exit "$status"
