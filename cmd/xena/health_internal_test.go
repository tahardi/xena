package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/health"
)

func TestRunHealth(t *testing.T) {
	ok := health.Check{Name: "xena-proxy", Run: func(context.Context) (string, error) { return "active", nil }}
	bad := health.Check{
		Name: "vm-image",
		Run:  func(context.Context) (string, error) { return "rebuild due", health.ErrNotOK },
	}

	tests := []struct {
		name    string
		checks  []health.Check
		want    string
		wantErr error
	}{
		{
			name:   "happy path - all ok",
			checks: []health.Check{ok},
			want:   "xena-proxy  ok  active\n",
		},
		{
			name:    "error - one check fails",
			checks:  []health.Check{ok, bad},
			want:    "xena-proxy  ok    active\nvm-image    FAIL  rebuild due\n",
			wantErr: errChecksFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var out bytes.Buffer

			// when
			err := runHealth(context.Background(), &out, tt.checks)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, out.String())
		})
	}
}
