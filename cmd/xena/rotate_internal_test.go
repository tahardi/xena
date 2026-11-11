package main

import (
	"bytes"
	"cmp"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

const githubInventory = `version: 1
entries:
  - name: github-app-key
    service: github
    stored: secrets:github-app-key
    rotated: 2026-07-01
    rotation_days: 180
    can_spend: false
    rotate: Rotate by hand.
`

func TestRunRotate(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		inventory string
		noFile    bool
		want      string
		wantErr   error
	}{
		{
			name: "happy path - manual token prints steps",
			args: []string{"a"},
			want: "No scripted rotation for a. Manual steps:\nRotate a by hand.\n",
		},
		{name: "error - not listed", args: []string{"zzz"}, wantErr: inventory.ErrNotListed},
		{name: "error - no name", args: nil, wantErr: errRotateUsage},
		{name: "error - missing inventory", args: []string{"a"}, noFile: true, wantErr: os.ErrNotExist},
		{name: "error - extra argument", args: []string{"a", "b"}, wantErr: errRotateUsage},
		{
			name:      "error - github app key without file",
			args:      []string{"github-app-key"},
			inventory: githubInventory,
			wantErr:   errMissingKeyFile,
		},
		{
			name:      "error - github app config missing",
			args:      []string{"github-app-key", "--file", "x.pem"},
			inventory: githubInventory,
			wantErr:   os.ErrNotExist,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			t.Setenv("XENA_CONFIG_DIR", dir)
			t.Setenv("XENA_SECRETS_DIR", t.TempDir())
			if !tt.noFile {
				path := filepath.Join(dir, "inventory.yaml")
				require.NoError(t, os.WriteFile(path, []byte(cmp.Or(tt.inventory, overdueInventory)), 0o600))
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
