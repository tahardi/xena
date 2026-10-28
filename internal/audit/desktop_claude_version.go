package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

type ClaudeVersion struct {
	cmd    Commander
	home   string
	pinned string
}

func NewClaudeVersion(cmd Commander, home, pinned string) *ClaudeVersion {
	return &ClaudeVersion{cmd: cmd, home: home, pinned: pinned}
}

func (*ClaudeVersion) Name() string {
	return "desktop-claude-version"
}

func (c *ClaudeVersion) Run(ctx context.Context) ([]Finding, error) {
	settings, err := loadClaudeSettings(c.home)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	var findings []Finding
	if settings.Env["DISABLE_AUTOUPDATER"] != "1" {
		findings = append(findings, Finding{
			Severity: logs.SeverityMedium,
			Message:  "the Claude Code auto-updater is on",
			Fix:      `Set env.DISABLE_AUTOUPDATER to "1" in ~/.claude/settings.json.`,
		})
	}

	out, err := c.cmd.Output(ctx, "claude", "--version")
	if err != nil {
		return nil, fmt.Errorf("reading claude version: %w", err)
	}

	installed, _, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if installed != c.pinned {
		findings = append(findings, Finding{
			Severity: logs.SeverityMedium,
			Message:  fmt.Sprintf("Claude Code %s is installed, but audit.yaml pins %s", installed, c.pinned),
			Fix:      "Install the pinned version, or update the pin in audit.yaml after reviewing the release notes.",
		})
	}
	return findings, nil
}
