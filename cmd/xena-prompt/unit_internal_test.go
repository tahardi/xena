package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPromptUnit(t *testing.T) {
	// given
	unit, err := os.ReadFile("../../deploy/systemd/xena-prompt.service")
	require.NoError(t, err)
	lines := strings.Split(string(unit), "\n")

	wantLines := []string{
		"ExecStart=/usr/local/bin/xena-prompt",
		"Environment=PATH=/usr/local/bin:/usr/bin:/bin:%h/.cargo/bin",
		"PartOf=graphical-session.target",
		"WantedBy=graphical-session.target",
		"NoNewPrivileges=yes",
		"LockPersonality=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"SystemCallArchitectures=native",
		"RestrictAddressFamilies=AF_UNIX",
		"UMask=0077",
		"ConditionPathExists=/usr/local/share/xena/config/vm.yaml",
		"MemoryDenyWriteExecute=yes",
		"RestrictNamespaces=yes",
		"KeyringMode=private",
		"SystemCallFilter=@system-service",
		"SystemCallFilter=~@privileged @resources",
		"SystemCallErrorNumber=EPERM",
	}

	// when
	var userLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "User=") {
			userLines = append(userLines, line)
		}
	}

	// then
	for _, want := range wantLines {
		require.Contains(t, lines, want)
	}

	require.Empty(t, userLines, "user services run as the desktop user")
}
