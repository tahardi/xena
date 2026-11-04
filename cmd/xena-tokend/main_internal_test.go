package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		appConfig     string
		wantErrPrefix string
	}{
		{name: "error - unknown flag", args: []string{"--bogus"}, wantErrPrefix: "parsing flags"},
		{name: "error - missing app config", args: nil, wantErrPrefix: "loading github app config"},
		{
			name:          "error - missing vm config",
			args:          nil,
			appConfig:     "version: 1\napp_id: 12345\ninstallation_id: 67890\n",
			wantErrPrefix: "loading vm config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			configDir := t.TempDir()
			t.Setenv("XENA_CONFIG_DIR", configDir)
			t.Setenv("XENA_REPO_CONFIG_DIR", t.TempDir())

			if tt.appConfig != "" {
				path := filepath.Join(configDir, "github-app.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.appConfig), 0o600))
			}

			logger := slog.New(slog.DiscardHandler)

			// when
			err := run(context.Background(), tt.args, logger)

			// then
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
		})
	}
}
