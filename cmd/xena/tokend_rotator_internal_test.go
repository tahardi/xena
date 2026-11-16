package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var errRestart = errors.New("restart failed")

func TestTokendRotator_RotateVMTokens(t *testing.T) {
	tests := []struct {
		name       string
		restartErr error
		want       string
		wantErr    error
	}{
		{
			name: "happy path - warns, restarts, then announces the touch",
			want: snapshotWarning + "\n" + manualRotate + "\n" + tokendTouch + "\n",
		},
		{
			name:       "error - restart fails after the warning",
			restartErr: errRestart,
			want:       snapshotWarning + "\n" + manualRotate + "\n",
			wantErr:    errRestart,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var out bytes.Buffer
			restarts := 0
			r := newTokendRotator(&out)
			r.restart = func(context.Context) error {
				restarts++
				return tt.restartErr
			}

			// when
			err := r.RotateVMTokens(context.Background())

			// then
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, 1, restarts)
			require.Equal(t, tt.want, out.String())
		})
	}
}
