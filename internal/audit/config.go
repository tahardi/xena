package audit

import (
	"fmt"

	"github.com/tahardi/xena/internal/config"
)

const ConfigVersion = 1

type Config struct {
	Version           int      `yaml:"version"`
	Vault             string   `yaml:"vault"`
	ClaudeCodeVersion string   `yaml:"claude_code_version"`
	GHScopes          []string `yaml:"gh_scopes"`
	ExtraListeners    []string `yaml:"extra_listeners"`
}

func LoadConfig(path string) (Config, error) {
	cfg, err := config.Load[Config](path, ConfigVersion, nil)
	if err != nil {
		return Config{}, fmt.Errorf("loading audit config: %w", err)
	}
	return cfg, nil
}
