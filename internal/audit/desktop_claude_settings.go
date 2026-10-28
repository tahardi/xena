package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

const untrustedSource = "source: xena-vm"

var (
	unsafeDefaultModes = []string{"bypassPermissions", "acceptEdits", "dontAsk"}
	blanketBashAllows  = []string{"Bash", "Bash(*)", "Bash(*:*)"}
)

type ClaudeSettings struct {
	home string
}

func NewClaudeSettings(home string) *ClaudeSettings {
	return &ClaudeSettings{home: home}
}

func (*ClaudeSettings) Name() string {
	return "desktop-claude-settings"
}

func (c *ClaudeSettings) Run(context.Context) ([]Finding, error) {
	var findings []Finding
	settings, err := loadClaudeSettings(c.home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		findings = append(findings, claudeSettingsFinding(
			logs.SeverityHigh,
			"~/.claude/settings.json is missing",
			"Install the dotclaude desktop settings.",
		))
	case err != nil:
		return nil, err
	default:
		findings = append(findings, settingsFindings(settings)...)
	}

	claudeMD, err := os.ReadFile(filepath.Join(c.home, ".claude", "CLAUDE.md"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading CLAUDE.md: %w", err)
	}
	if !strings.Contains(string(claudeMD), untrustedSource) {
		findings = append(findings, claudeSettingsFinding(
			logs.SeverityMedium,
			"~/.claude/CLAUDE.md does not mark `"+untrustedSource+"` notes as untrusted",
			"Add the rule that vault notes with `"+untrustedSource+"` are untrusted input to ~/.claude/CLAUDE.md.",
		))
	}
	return findings, nil
}

func settingsFindings(s claudeSettingsFile) []Finding {
	var findings []Finding
	if s.Sandbox.Enabled == nil || !*s.Sandbox.Enabled {
		findings = append(findings, claudeSettingsFinding(
			logs.SeverityHigh,
			"the Claude Code sandbox is off",
			"Set sandbox.enabled to true.",
		))
	}

	if s.Sandbox.AllowUnsandboxedCommands == nil || *s.Sandbox.AllowUnsandboxedCommands {
		findings = append(findings, claudeSettingsFinding(
			logs.SeverityHigh,
			"Claude Code may retry commands outside the sandbox",
			"Set sandbox.allowUnsandboxedCommands to false.",
		))
	}

	if slices.Contains(unsafeDefaultModes, s.Permissions.DefaultMode) {
		findings = append(findings, claudeSettingsFinding(
			logs.SeverityHigh,
			"Claude Code starts in "+s.Permissions.DefaultMode+" mode instead of asking",
			"Remove permissions.defaultMode.",
		))
	}

	if s.Permissions.DisableBypassPermissionsMode != "disable" {
		findings = append(findings, claudeSettingsFinding(
			logs.SeverityHigh,
			"bypass permissions mode is not disabled",
			`Set permissions.disableBypassPermissionsMode to "disable".`,
		))
	}

	for _, rule := range s.Permissions.Allow {
		if slices.Contains(blanketBashAllows, rule) {
			findings = append(findings, claudeSettingsFinding(
				logs.SeverityHigh,
				"permissions.allow lets every Bash command run without asking ("+rule+")",
				"Replace "+rule+" with rules for specific commands.",
			))
		}
	}
	return findings
}

func claudeSettingsFinding(severity, message, fix string) Finding {
	return Finding{Severity: severity, Message: message, Fix: fix}
}
