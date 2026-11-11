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

probe_tcp() {
	if /usr/bin/timeout 5 /bin/bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
		echo "connected $1:$2"
		return 1
	fi

	echo "blocked $1:$2"
}

probe_proxy https://198.51.100.7/ 20 || status=1
probe_proxy http://198.51.100.7/ 20 || status=1
probe_tcp 198.51.100.7 443 || status=1
exit "$status"
