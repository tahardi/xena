package github

import (
	"errors"
	"fmt"

	"github.com/tahardi/xena/internal/config"
)

const appConfigVersion = 1

var ErrMissingID = errors.New("app_id and installation_id are required")

type AppConfig struct {
	Version        int      `yaml:"version"`
	AppID          int64    `yaml:"app_id"`
	InstallationID int64    `yaml:"installation_id"`
	Repos          []string `yaml:"repos"`
}

func LoadAppConfig(path string) (AppConfig, error) {
	cfg, err := config.Load[AppConfig](path, appConfigVersion, nil)
	if err != nil {
		return AppConfig{}, fmt.Errorf("loading github app config: %w", err)
	}

	if cfg.AppID == 0 || cfg.InstallationID == 0 {
		return AppConfig{}, fmt.Errorf("loading github app config: %w", ErrMissingID)
	}

	return cfg, nil
}
