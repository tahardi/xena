package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		vm         string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:       "unknown flag",
			args:       []string{"--bogus"},
			wantErrMsg: "parsing flags",
		},
		{
			name:       "missing vm config",
			wantErrMsg: "loading vm config",
		},
		{
			name: "zero prompt timeout",
			vm: `version: 1
prompt_timeout_seconds: 0
`,
			wantErr:    errInvalidPromptTimeout,
			wantErrMsg: "checking prompt timeout",
		},
		{
			name: "negative prompt timeout",
			vm: `version: 1
prompt_timeout_seconds: -1
`,
			wantErr:    errInvalidPromptTimeout,
			wantErrMsg: "checking prompt timeout",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			configDir := t.TempDir()
			t.Setenv("XENA_REPO_CONFIG_DIR", configDir)
			t.Setenv("XENA_WATCH_STATE_DIR", t.TempDir())
			t.Setenv("XENA_PROMPT_SOCKET", filepath.Join(t.TempDir(), "prompt.sock"))

			if tt.vm != "" {
				require.NoError(t, os.WriteFile(filepath.Join(configDir, "vm.yaml"), []byte(tt.vm), 0o600))
			}

			// when
			err := run(t.Context(), tt.args, slog.New(slog.DiscardHandler))

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}

			require.ErrorContains(t, err, tt.wantErrMsg)
		})
	}
}
