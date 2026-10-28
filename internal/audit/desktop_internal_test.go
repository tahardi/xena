package audit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDesktopChecks(t *testing.T) {
	// given
	cfg := Config{
		Vault:             "/home/example/Documents/vault",
		ClaudeCodeVersion: "2.0.0",
		GHScopes:          []string{"repo"},
		ExtraListeners:    []string{"192.0.2.10:22"},
	}
	cmd := fakeCommander{}
	paths := Paths{Root: "/", Home: "/home/example", User: "example", ProxyStateDir: "/var/lib/xena-proxy"}

	// when
	checks := DesktopChecks(cfg, cmd, paths, "192.168.150.1:3128")

	// then
	names := make([]string, 0, len(checks))
	for _, check := range checks {
		names = append(names, check.Name())
	}
	require.Equal(t, []string{
		"desktop-docker",
		"desktop-groups",
		"desktop-inbound-firewall",
		"desktop-auto-updates",
		"desktop-listeners",
		"desktop-wayland",
		"desktop-claude-settings",
		"desktop-claude-version",
		"desktop-gh-auth",
		"desktop-obsidian",
		"desktop-overlay",
	}, names)
	require.Contains(t, checks, NewListeners(cmd, []string{"192.168.150.1:3128", "192.0.2.10:22"}))
	require.Contains(t, checks, NewOverlay("/var/lib/xena-proxy/overlay.yaml"))
	require.Contains(t, checks, NewClaudeVersion(cmd, "/home/example", "2.0.0"))
}
