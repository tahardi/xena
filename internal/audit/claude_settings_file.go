package audit

import (
	"errors"
	"io/fs"
	"maps"
	"path/filepath"
)

// Claude Code's settings files use camelCase keys.
//
//nolint:tagliatelle
type claudeSettingsFile struct {
	Sandbox struct {
		Enabled                  *bool `json:"enabled"`
		AllowUnsandboxedCommands *bool `json:"allowUnsandboxedCommands"`
	} `json:"sandbox"`
	Permissions struct {
		DefaultMode                  string   `json:"defaultMode"`
		DisableBypassPermissionsMode string   `json:"disableBypassPermissionsMode"`
		Allow                        []string `json:"allow"`
	} `json:"permissions"`
	Env map[string]string `json:"env"`
}

func loadClaudeSettings(home string) (claudeSettingsFile, error) {
	var settings claudeSettingsFile
	if err := readJSON(filepath.Join(home, ".claude", "settings.json"), &settings); err != nil {
		return claudeSettingsFile{}, err
	}

	var local claudeSettingsFile
	err := readJSON(filepath.Join(home, ".claude", "settings.local.json"), &local)
	if errors.Is(err, fs.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return claudeSettingsFile{}, err
	}
	return settings.merge(local), nil
}

func (s claudeSettingsFile) merge(local claudeSettingsFile) claudeSettingsFile {
	if local.Sandbox.Enabled != nil {
		s.Sandbox.Enabled = local.Sandbox.Enabled
	}

	if local.Sandbox.AllowUnsandboxedCommands != nil {
		s.Sandbox.AllowUnsandboxedCommands = local.Sandbox.AllowUnsandboxedCommands
	}

	if local.Permissions.DefaultMode != "" {
		s.Permissions.DefaultMode = local.Permissions.DefaultMode
	}

	if local.Permissions.DisableBypassPermissionsMode != "" {
		s.Permissions.DisableBypassPermissionsMode = local.Permissions.DisableBypassPermissionsMode
	}

	s.Permissions.Allow = append(s.Permissions.Allow, local.Permissions.Allow...)

	env := maps.Clone(s.Env)
	if env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, local.Env)
	s.Env = env
	return s
}
