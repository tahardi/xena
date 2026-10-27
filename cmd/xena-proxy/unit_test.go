package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyUnit(t *testing.T) {
	// given
	unit, err := os.ReadFile("../../deploy/systemd/xena-proxy.service")
	require.NoError(t, err)
	unitLines := strings.Split(string(unit), "\n")

	sysusers, err := os.ReadFile("../../deploy/sysusers/xena.conf")
	require.NoError(t, err)
	sysusersLines := strings.Split(string(sysusers), "\n")

	wantLines := []string{
		"User=xena-proxy",
		"Group=xena-proxy",
		"SupplementaryGroups=xena-prompt",
		"ExecStart=/usr/local/bin/xena-proxy",
		"StateDirectory=xena-proxy",
		"StateDirectoryMode=0750",
		"RuntimeDirectory=xena-proxy",
		"RuntimeDirectoryMode=0755",
		"UMask=0027",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"SystemCallFilter=@chown",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"IPAddressAllow=192.168.150.10/32 127.0.0.53/32",
	}
	wantDenied := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	wantPrefixes := []string{
		"u xena-proxy",
		"g xena-prompt",
		"m xena-proxy xena-prompt",
		"m xena-watch xena-proxy",
	}

	// when
	var denied []string
	for _, line := range unitLines {
		if rest, ok := strings.CutPrefix(line, "IPAddressDeny="); ok {
			denied = append(denied, strings.Fields(rest)...)
		}
	}

	// then
	for _, want := range wantLines {
		require.Contains(t, unitLines, want)
	}

	for _, want := range wantDenied {
		require.Contains(t, denied, want)
	}

	for _, want := range wantPrefixes {
		found := false
		for _, line := range sysusersLines {
			found = found || strings.HasPrefix(line, want)
		}
		require.True(t, found, "missing sysusers line starting %q", want)
	}
}
