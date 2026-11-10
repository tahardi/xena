#!/usr/bin/env bash
set -euo pipefail

proxy="http://{{.BridgeAddress}}:{{.ProxyPort}}"
export HTTP_PROXY="$proxy" HTTPS_PROXY="$proxy" http_proxy="$proxy" https_proxy="$proxy"
export NPM_CONFIG_GLOBALCONFIG=/etc/npmrc
export HOME=/root

systemctl start qemu-guest-agent

systemctl disable --now docker.service docker.socket containerd.service
apt-get purge -y snapd
systemctl disable --now motd-news.timer

sysctl --system
systemctl restart systemd-resolved

npm install --global --ignore-scripts=false "@anthropic-ai/claude-code@{{.ClaudeCodeVersion}}"

git clone https://github.com/tahardi/dotclaude /usr/local/share/dotclaude
git -C /usr/local/share/dotclaude checkout --detach "{{.DotclaudeRef}}"
/usr/local/share/dotclaude/install.sh vm

install -d -o dev -g dev -m 0700 \
	/home/dev/.xena \
	/home/dev/.config \
	/home/dev/.config/xena \
	/home/dev/Documents \
	/home/dev/Documents/code \
	/home/dev/Documents/code/wts
chown -R dev:dev /home/dev/.config

/usr/local/lib/xena/package-age
systemctl daemon-reload
systemctl enable --now xena-package-age.timer

loginctl enable-linger dev

uid=$(id -u dev)
runtime_dir="/run/user/$uid"

for _ in $(seq 1 60); do
	if [[ -S "$runtime_dir/bus" ]]; then
		break
	fi
	sleep 1
done

if [[ ! -S "$runtime_dir/bus" ]]; then
	echo "waiting for dev's user bus: $runtime_dir/bus did not appear in 60 seconds" >&2
	exit 1
fi

runuser -u dev -- env \
	PATH=/usr/share/docker.io/contrib:/usr/sbin:/usr/bin:/sbin:/bin \
	XDG_RUNTIME_DIR="$runtime_dir" \
	DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus" \
	dockerd-rootless-setuptool.sh install

if systemctl cat ssh.socket >/dev/null 2>&1; then
	systemctl restart ssh.socket
fi
systemctl restart ssh
