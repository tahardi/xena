package audit

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tahardi/xena/internal/config"
)

const (
	ConfigVersion       = 1
	DefaultCheckTimeout = 2 * time.Minute
)

var ErrInvalidConfig = errors.New("invalid audit config")

type Config struct {
	Version           int           `yaml:"version"`
	Vault             string        `yaml:"vault"`
	ClaudeCodeVersion string        `yaml:"claude_code_version"`
	MinUbuntuVersion  string        `yaml:"min_ubuntu_version"`
	GHScopes          []string      `yaml:"gh_scopes"`
	ExtraListeners    []string      `yaml:"extra_listeners"`
	CheckTimeout      time.Duration `yaml:"check_timeout"`
}

func LoadConfig(path string) (Config, error) {
	cfg, err := config.Load[Config](path, ConfigVersion, nil)
	if err != nil {
		return Config{}, fmt.Errorf("loading audit config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("loading audit config %s: %w", path, err)
	}

	if cfg.CheckTimeout == 0 {
		cfg.CheckTimeout = DefaultCheckTimeout
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.Vault == "" {
		return fmt.Errorf("vault is not set; set it to your Obsidian vault folder: %w", ErrInvalidConfig)
	}

	if info, err := os.Stat(c.Vault); err != nil || !info.IsDir() {
		return fmt.Errorf("vault %q is not a folder: %w", c.Vault, ErrInvalidConfig)
	}

	if c.ClaudeCodeVersion == "" {
		return fmt.Errorf("claude_code_version is not set; set it to the version you have reviewed: %w", ErrInvalidConfig)
	}

	if c.MinUbuntuVersion == "" {
		return fmt.Errorf("min_ubuntu_version is not set: %w", ErrInvalidConfig)
	}

	if _, err := parseUbuntuVersion(c.MinUbuntuVersion); err != nil {
		return fmt.Errorf(
			"min_ubuntu_version %q is not a version like \"26.04\": %w",
			c.MinUbuntuVersion,
			ErrInvalidConfig,
		)
	}

	if len(c.GHScopes) == 0 {
		return fmt.Errorf("gh_scopes is not set; list the scopes your gh token may have: %w", ErrInvalidConfig)
	}

	if c.CheckTimeout < 0 {
		return fmt.Errorf("check_timeout %q must be more than zero: %w", c.CheckTimeout, ErrInvalidConfig)
	}
	return nil
}
