package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultUnit(t *testing.T) {
	// given
	unit, err := os.ReadFile("../../deploy/systemd/xena-vault.service")
	require.NoError(t, err)

	wantLines := []string{
		"Description=Xena vault gateway",
		"ExecStart=/usr/local/bin/xena-vault",
		"Restart=on-failure",
		"UMask=0027",
		"Environment=HF_HUB_OFFLINE=1",
		"Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin",
		"Environment=TMPDIR=%C/xena/vault",
		"CacheDirectory=xena/vault",
		"NoNewPrivileges=yes",
		"LockPersonality=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"RestrictNamespaces=yes",
		"SystemCallArchitectures=native",
		"RestrictAddressFamilies=AF_UNIX",
		"WantedBy=default.target",
	}

	// when
	lines := strings.Split(string(unit), "\n")

	// then
	for _, want := range wantLines {
		require.Contains(t, lines, want)
	}

	for _, line := range lines {
		require.False(t, strings.HasPrefix(line, "User="), "user services run as the desktop user")
	}
}
