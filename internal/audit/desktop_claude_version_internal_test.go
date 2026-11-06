package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestClaudeVersion_Run(t *testing.T) {
	tests := []struct {
		name    string
		change  func(map[string]any)
		managed string
		version fakeResult
		want    []string
		msg     string
		errText string
	}{
		{
			name:    "happy path - pinned and auto-updater off",
			version: fakeResult{out: "2.0.0 (Claude Code)\n"},
			want:    []string{},
		},
		{
			name:    "happy path - auto-updater on",
			change:  func(s map[string]any) { delete(s, "env") },
			version: fakeResult{out: "2.0.0 (Claude Code)\n"},
			want:    []string{logs.SeverityMedium},
		},
		{
			name:    "happy path - auto-updater off in managed settings",
			change:  func(s map[string]any) { delete(s, "env") },
			managed: `{"env": {"DISABLE_AUTOUPDATER": "1"}}`,
			version: fakeResult{out: "2.0.0 (Claude Code)\n"},
			want:    []string{},
		},
		{
			name:    "happy path - version differs from pin",
			version: fakeResult{out: "2.0.1 (Claude Code)\n"},
			want:    []string{logs.SeverityMedium},
			msg:     "Claude Code 2.0.1 is installed, but audit.yaml pins 2.0.0",
		},
		{
			name:    "error - claude fails",
			version: fakeResult{err: errBroken},
			errText: "reading claude version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := t.TempDir()
			home := t.TempDir()
			writeFiles(t, home, map[string]string{".claude/settings.json": claudeSettingsJSON(t, tt.change)})
			if tt.managed != "" {
				writeFiles(t, root, map[string]string{"etc/claude-code/managed-settings.json": tt.managed})
			}

			check := NewClaudeVersion(fakeCommander{"claude --version": tt.version}, root, home, "2.0.0")

			// when
			got, err := check.Run(t.Context())

			// then
			if tt.errText != "" {
				require.ErrorContains(t, err, tt.errText)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
			if tt.msg != "" {
				require.Equal(t, tt.msg, got[0].Message)
			}
		})
	}
}
