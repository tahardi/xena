package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunVM(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantErr       error
		wantErrPrefix string
	}{
		{name: "error - no subcommand", args: nil, wantErr: errUnknownCommand},
		{name: "error - unknown subcommand", args: []string{"bogus"}, wantErr: errUnknownCommand},
		{name: "error - snapshot without name", args: []string{"snapshot"}, wantErrPrefix: "checking arguments: "},
		{name: "error - restore without name", args: []string{"restore"}, wantErrPrefix: "checking arguments: "},
		{name: "error - start without vm config", args: []string{"start"}, wantErrPrefix: "loading vm config: "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			t.Setenv("XENA_REPO_CONFIG_DIR", t.TempDir())
			logger := slog.New(slog.DiscardHandler)

			// when
			err := runVM(context.Background(), tt.args, logger)

			// then
			require.Error(t, err)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
			if tt.wantErrPrefix != "" {
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
			}
		})
	}
}
