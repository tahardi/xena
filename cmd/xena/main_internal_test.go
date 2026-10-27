package main

import (
	"context"
	"log/slog"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		noAge   bool
		wantErr error
	}{
		{name: "happy path - version", args: []string{"version"}},
		{name: "error - no command", args: nil, wantErr: errNoCommand},
		{name: "error - unknown command", args: []string{"nope"}, wantErr: errUnknownCommand},
		{name: "error - secrets without age", args: []string{"secrets", "list"}, noAge: true, wantErr: exec.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			logger := slog.New(slog.DiscardHandler)

			if tt.noAge {
				t.Setenv("PATH", t.TempDir())
			}

			// when
			err := run(context.Background(), tt.args, logger)

			// then
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
