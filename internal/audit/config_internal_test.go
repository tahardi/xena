package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    Config
		wantErr error
		errText string
	}{
		{
			name: "happy path - full file",
			file: `version: 1
vault: /home/example/Documents/vault
claude_code_version: "2.0.0"
gh_scopes: [repo, read:org]
extra_listeners: ["192.0.2.10:22"]
`,
			want: Config{
				Version:           1,
				Vault:             "/home/example/Documents/vault",
				ClaudeCodeVersion: "2.0.0",
				GHScopes:          []string{"repo", "read:org"},
				ExtraListeners:    []string{"192.0.2.10:22"},
			},
		},
		{
			name:    "error - missing file",
			errText: "loading audit config",
		},
		{
			name:    "error - unknown field",
			file:    "version: 1\nvalut: /home/example/Documents/vault\n",
			errText: "loading audit config",
		},
		{
			name:    "error - unknown version",
			file:    "version: 2\n",
			wantErr: config.ErrUnknownVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := filepath.Join(t.TempDir(), "audit.yaml")
			if tt.file != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))
			}

			// when
			got, err := LoadConfig(path)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			if tt.errText != "" {
				require.ErrorContains(t, err, tt.errText)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
