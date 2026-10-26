package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr error
	}{
		{name: "happy path - version", args: []string{"version"}},
		{name: "error - no command", args: nil, wantErr: errNoCommand},
		{name: "error - unknown command", args: []string{"nope"}, wantErr: errUnknownCommand},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			logger := slog.New(slog.DiscardHandler)

			// when
			err := run(context.Background(), tt.args, logger)

			// then
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
