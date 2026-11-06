package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
)

const validConfig = `version: 1
vault: VAULT
claude_code_version: "2.0.0"
min_ubuntu_version: "26.04"
gh_scopes: [repo, read:org]
extra_listeners: ["192.0.2.10:22"]
`

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		noFile  bool
		want    Config
		wantErr error
		errText string
	}{
		{
			name: "happy path - full file",
			file: validConfig,
			want: Config{
				Version:           1,
				ClaudeCodeVersion: "2.0.0",
				MinUbuntuVersion:  "26.04",
				GHScopes:          []string{"repo", "read:org"},
				ExtraListeners:    []string{"192.0.2.10:22"},
			},
		},
		{
			name:    "error - missing file",
			noFile:  true,
			errText: "loading audit config",
		},
		{
			name:    "error - unknown field",
			file:    validConfig + "valut: /home/example/Documents/vault\n",
			errText: "loading audit config",
		},
		{
			name:    "error - unknown version",
			file:    "version: 2\n",
			wantErr: config.ErrUnknownVersion,
		},
		{
			name:    "error - vault not set",
			file:    strings.Replace(validConfig, "vault: VAULT\n", "", 1),
			wantErr: ErrInvalidConfig,
			errText: "vault is not set",
		},
		{
			name:    "error - vault missing",
			file:    strings.Replace(validConfig, "vault: VAULT", "vault: VAULT/missing", 1),
			wantErr: ErrInvalidConfig,
			errText: "is not a folder",
		},
		{
			name:    "error - claude code version not set",
			file:    strings.Replace(validConfig, "claude_code_version: \"2.0.0\"\n", "", 1),
			wantErr: ErrInvalidConfig,
			errText: "claude_code_version is not set",
		},
		{
			name:    "error - min ubuntu version not set",
			file:    strings.Replace(validConfig, "min_ubuntu_version: \"26.04\"\n", "", 1),
			wantErr: ErrInvalidConfig,
			errText: "min_ubuntu_version is not set",
		},
		{
			name:    "error - min ubuntu version malformed",
			file:    strings.Replace(validConfig, `"26.04"`, `"twenty-six"`, 1),
			wantErr: ErrInvalidConfig,
			errText: `min_ubuntu_version "twenty-six" is not a version like "26.04"`,
		},
		{
			name:    "error - gh scopes not set",
			file:    strings.Replace(validConfig, "gh_scopes: [repo, read:org]\n", "", 1),
			wantErr: ErrInvalidConfig,
			errText: "gh_scopes is not set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			vault := t.TempDir()
			path := filepath.Join(t.TempDir(), "audit.yaml")
			if !tt.noFile {
				file := strings.ReplaceAll(tt.file, "VAULT", vault)
				require.NoError(t, os.WriteFile(path, []byte(file), 0o600))
			}

			// when
			got, err := LoadConfig(path)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
			if tt.errText != "" {
				require.ErrorContains(t, err, tt.errText)
			}
			if tt.wantErr != nil || tt.errText != "" {
				return
			}

			require.NoError(t, err)
			tt.want.Vault = vault
			require.Equal(t, tt.want, got)
		})
	}
}
