package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
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

func loadClaudeSettings(root, home string) (claudeSettingsFile, error) {
	dropIns, err := filepath.Glob(filepath.Join(root, "etc", "claude-code", "managed-settings.d", "*.json"))
	if err != nil {
		return claudeSettingsFile{}, fmt.Errorf("listing managed settings: %w", err)
	}
	slices.Sort(dropIns)

	paths := append([]string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(root, "etc", "claude-code", "managed-settings.json"),
	}, dropIns...)

	var merged claudeSettingsFile
	found := false
	for _, path := range paths {
		var layer claudeSettingsFile
		err := readJSON(path, &layer)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return claudeSettingsFile{}, err
		}

		merged = merged.merge(layer)
		found = true
	}

	if !found {
		return claudeSettingsFile{}, fmt.Errorf("reading Claude Code settings: %w", fs.ErrNotExist)
	}
	return merged, nil
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
