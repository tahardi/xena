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

label=$(/usr/bin/head -c 30 /dev/urandom | /usr/bin/od -An -tx1 | /usr/bin/tr -d ' \n')

if /usr/bin/getent hosts "$label.guard-tunnel.invalid" >/dev/null; then
	echo "connected getent"
	status=1
else
	echo "blocked getent"
fi

send_udp "$bridge" 53
send_udp 1.1.1.1 53
send_udp 9.9.9.9 53
probe_tcp 1.1.1.1 53 || status=1
exit "$status"
