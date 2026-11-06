package github_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/github"
)

func TestLoadAppConfig(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		noFile        bool
		want          github.AppConfig
		wantErr       error
		wantErrPrefix string
	}{
		{
			name: "happy path - full file",
			yaml: "version: 1\napp_id: 12345\ninstallation_id: 67890\nrepos: [xena, maple]\n",
			want: github.AppConfig{
				Version:        1,
				AppID:          12345,
				InstallationID: 67890,
				Repos:          []string{"xena", "maple"},
			},
		},
		{
			name:    "error - missing app id",
			yaml:    "version: 1\ninstallation_id: 67890\n",
			wantErr: github.ErrMissingID,
		},
		{
			name:    "error - missing installation id",
			yaml:    "version: 1\napp_id: 12345\n",
			wantErr: github.ErrMissingID,
		},
		{
			name:          "error - missing file",
			noFile:        true,
			wantErrPrefix: "loading github app config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := filepath.Join(t.TempDir(), "github-app.yaml")
			if !tt.noFile {
				require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0o600))
			}

			// when
			got, err := github.LoadAppConfig(path)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix))
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
