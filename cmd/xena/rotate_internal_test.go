package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

func TestRunRotate(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		noFile  bool
		want    string
		wantErr error
	}{
		{
			name: "happy path - manual token prints steps",
			args: []string{"a"},
			want: "No scripted rotation for a. Manual steps:\nRotate a by hand.\n",
		},
		{name: "error - not listed", args: []string{"zzz"}, wantErr: inventory.ErrNotListed},
		{name: "error - no name", args: nil, wantErr: errRotateUsage},
		{name: "error - missing inventory", args: []string{"a"}, noFile: true, wantErr: os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			t.Setenv("XENA_CONFIG_DIR", dir)
			t.Setenv("XENA_SECRETS_DIR", t.TempDir())
			if !tt.noFile {
				path := filepath.Join(dir, "inventory.yaml")
				require.NoError(t, os.WriteFile(path, []byte(overdueInventory), 0o600))
			}
			var out bytes.Buffer

			// when
			err := runRotate(context.Background(), tt.args, strings.NewReader(""), &out)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, out.String())
		})
	}
}
