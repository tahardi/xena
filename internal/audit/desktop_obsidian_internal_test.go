package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestObsidian_Run(t *testing.T) {
	const gatewayNote = "---\nsource: xena-vm\n---\n"

	tests := []struct {
		name  string
		files map[string]string
		want  []string
		msg   string
	}{
		{
			name:  "happy path - safe plugin",
			files: map[string]string{".obsidian/community-plugins.json": `["calendar"]`},
			want:  []string{},
		},
		{
			name: "happy path - dataview with JS",
			files: map[string]string{
				".obsidian/community-plugins.json":     `["dataview"]`,
				".obsidian/plugins/dataview/data.json": `{"enableDataviewJs": true}`,
			},
			want: []string{logs.SeverityHigh},
		},
		{
			name: "happy path - dataview without JS",
			files: map[string]string{
				".obsidian/community-plugins.json":     `["dataview"]`,
				".obsidian/plugins/dataview/data.json": `{"enableDataviewJs": false}`,
			},
			want: []string{},
		},
		{
			name:  "happy path - templater",
			files: map[string]string{".obsidian/community-plugins.json": `["templater-obsidian"]`},
			want:  []string{logs.SeverityHigh},
		},
		{
			name:  "happy path - execute code",
			files: map[string]string{".obsidian/community-plugins.json": `["execute-code"]`},
			want:  []string{logs.SeverityHigh},
		},
		{
			name:  "happy path - shell commands",
			files: map[string]string{".obsidian/community-plugins.json": `["obsidian-shellcommands"]`},
			want:  []string{logs.SeverityHigh},
		},
		{
			name:  "happy path - customjs",
			files: map[string]string{".obsidian/community-plugins.json": `["customjs"]`},
			want:  []string{logs.SeverityHigh},
		},
		{
			name:  "happy path - remote image in gateway note",
			files: map[string]string{"Inbox/a.md": gatewayNote + "![x](https://example.com/a.png)\n"},
			want:  []string{logs.SeverityMedium},
			msg:   "Inbox/a.md",
		},
		{
			name:  "happy path - iframe in gateway note",
			files: map[string]string{"Inbox/b.md": gatewayNote + "<iframe src=\"https://example.com\"></iframe>\n"},
			want:  []string{logs.SeverityMedium},
			msg:   "Inbox/b.md",
		},
		{
			name:  "happy path - remote img tag in gateway note",
			files: map[string]string{"Inbox/e.md": gatewayNote + "<img src=\"https://example.com/a.png\">\n"},
			want:  []string{logs.SeverityMedium},
			msg:   "Inbox/e.md",
		},
		{
			name:  "happy path - source line only in body",
			files: map[string]string{"Notes/f.md": "# Title\nsource: xena-vm\n![x](https://example.com/a.png)\n"},
			want:  []string{},
		},
		{
			name:  "happy path - hidden folders skipped",
			files: map[string]string{".trash/g.md": gatewayNote + "![x](https://example.com/a.png)\n"},
			want:  []string{},
		},
		{
			name:  "happy path - remote image in own note",
			files: map[string]string{"Notes/c.md": "---\nsource: me\n---\n![x](https://example.com/a.png)\n"},
			want:  []string{},
		},
		{
			name:  "happy path - no plugins file",
			files: map[string]string{"Notes/d.md": "plain note\n"},
			want:  []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			vault := t.TempDir()
			writeFiles(t, vault, tt.files)

			// when
			got, err := NewObsidian(vault).Run(t.Context())

			// then
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
			if tt.msg != "" {
				require.Contains(t, got[0].Message, tt.msg)
				require.NotContains(t, got[0].Message, "example.com")
			}
		})
	}

	t.Run("error - symlink out of the vault", func(t *testing.T) {
		// given
		vault := t.TempDir()
		outside := t.TempDir()
		writeFiles(t, outside, map[string]string{"h.md": gatewayNote + "![x](https://example.com/a.png)\n"})
		require.NoError(t, os.Symlink(filepath.Join(outside, "h.md"), filepath.Join(vault, "h.md")))

		// when
		_, err := NewObsidian(vault).Run(t.Context())

		// then
		require.ErrorContains(t, err, "reading vault notes")
	})

	t.Run("error - missing vault", func(t *testing.T) {
		// given
		vault := filepath.Join(t.TempDir(), "missing")

		// when
		_, err := NewObsidian(vault).Run(t.Context())

		// then
		require.ErrorContains(t, err, "reading vault notes")
	})
}
