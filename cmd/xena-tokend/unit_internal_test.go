package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokendUnit(t *testing.T) {
	// given
	unit, err := os.ReadFile("../../deploy/systemd/xena-tokend.service")
	require.NoError(t, err)
	lines := strings.Split(string(unit), "\n")

	wantLines := []string{
		"ExecStart=/usr/local/bin/xena-tokend",
		"Environment=PATH=%h/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
		"Restart=on-failure",
		"UMask=0077",
		"NoNewPrivileges=yes",
		"KeyringMode=private",
		"LockPersonality=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"RestrictNamespaces=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native",
		"SystemCallFilter=@system-service",
		"SystemCallFilter=~@privileged @resources",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"WantedBy=default.target",
	}
	unsupportedPrefixes := []string{
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"PrivateUsers=",
		"PrivateDevices=",
		"ProtectClock=",
		"ProtectHostname=",
		"ProtectKernelTunables=",
		"ProtectKernelModules=",
		"ProtectKernelLogs=",
		"ProtectControlGroups=",
	}

	// when
	var unsupported []string
	for _, line := range lines {
		for _, prefix := range unsupportedPrefixes {
			if strings.HasPrefix(line, prefix) {
				unsupported = append(unsupported, line)
			}
		}
	}

	// then
	for _, want := range wantLines {
		require.Contains(t, lines, want)
	}

	require.Empty(t, unsupported, "user units cannot drop capabilities on hosts that restrict user namespaces")
}
