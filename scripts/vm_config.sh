#!/usr/bin/env bash

read_vm_config() {
	if ! python3 -I - "$1" 2>/dev/null <<'PY'; then
import ipaddress
import re
import sys

import yaml

with open(sys.argv[1]) as f:
    c = yaml.safe_load(f)

bridge = c["network"]["bridge"]
bridge_address = str(ipaddress.IPv4Address(c["network"]["bridge_address"]))
vm_address = str(ipaddress.IPv4Address(c["network"]["vm_address"]))
prefix = c["network"]["prefix"]
port = c["proxy_port"]
version = c["claude_code_version"]

if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge):
    sys.exit(1)

if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]*", version):
    sys.exit(1)

if not (type(port) is int and 1 <= port <= 65535):
    sys.exit(1)

if not (type(prefix) is int and 1 <= prefix <= 32):
    sys.exit(1)

print(version, bridge, vm_address, port, bridge_address, prefix)
PY
		echo "reading vm config from $1: check it sets claude_code_version, network.bridge," \
			"network.bridge_address, network.vm_address, network.prefix, and proxy_port," \
			"and python3-yaml is installed" >&2
		return 1
	fi
}
