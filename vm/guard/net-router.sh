#!/usr/bin/env bash
set -euo pipefail

status=0

probe_tcp() {
	if /usr/bin/timeout 5 /bin/bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
		echo "connected $1:$2"
		return 1
	fi

	echo "blocked $1:$2"
}

probe_tcp 192.168.0.1 80 || status=1
probe_tcp 192.168.1.1 80 || status=1
probe_tcp 10.0.0.1 80 || status=1
exit "$status"
