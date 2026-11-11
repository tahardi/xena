#!/usr/bin/env bash
set -euo pipefail

bridge=192.168.150.1

status=0

probe_tcp() {
	if /usr/bin/timeout 5 /bin/bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
		echo "connected $1:$2"
		return 1
	fi

	echo "blocked $1:$2"
}

send_udp() {
	/usr/bin/timeout 3 /bin/bash -c "echo guard > /dev/udp/$1/$2" 2>/dev/null || true
	echo "sent $1:$2/udp"
}

probe_tcp "$bridge" 22 || status=1
probe_tcp "$bridge" 80 || status=1
probe_tcp "$bridge" 443 || status=1
probe_tcp "$bridge" 631 || status=1
probe_tcp "$bridge" 8080 || status=1
send_udp "$bridge" 5353
exit "$status"
