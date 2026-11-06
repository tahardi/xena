package audit

import (
	"path/filepath"
)

type Paths struct {
	Root          string
	Home          string
	User          string
	ProxyStateDir string
}

func DesktopChecks(cfg Config, cmd Commander, p Paths, bridgeListener string) []Check {
	allowed := cfg.ExtraListeners
	if bridgeListener != "" {
		allowed = append([]string{bridgeListener}, cfg.ExtraListeners...)
	}

	return []Check{
		NewDocker(p.Root),
		NewGroups(p.Root, p.User),
		NewFirewall(cmd, p.Root),
		NewAutoUpdates(cmd),
		NewListeners(cmd, allowed),
		NewWayland(cmd, p.Root, p.User, cfg.MinUbuntuVersion),
		NewClaudeSettings(p.Root, p.Home),
		NewClaudeVersion(cmd, p.Root, p.Home, cfg.ClaudeCodeVersion),
		NewGHAuth(cmd, p.Home, cfg.GHScopes),
		NewObsidian(cfg.Vault),
		NewOverlay(filepath.Join(p.ProxyStateDir, "overlay.yaml")),
	}
}
