package guard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/guard"
)

func TestWriteWindow(t *testing.T) {
	start := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	window := guard.Window{
		Start:   start,
		End:     start.Add(15 * time.Minute),
		VMAddr:  "192.168.150.10",
		Targets: []string{"198.51.100.7"},
	}

	tests := []struct {
		name     string
		existing bool
		noDir    bool
		wantErr  string
	}{
		{name: "happy path - writes window"},
		{name: "happy path - overwrites existing window", existing: true},
		{name: "error - dir does not exist", noDir: true, wantErr: "writing guard window"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			if tt.noDir {
				dir = filepath.Join(dir, "missing")
			}

			path := filepath.Join(dir, "window.json")
			if tt.existing {
				require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
			}

			// when
			err := guard.WriteWindow(dir, window)

			// then
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			data, err := os.ReadFile(path)
			require.NoError(t, err)

			var got guard.Window
			require.NoError(t, json.Unmarshal(data, &got))
			assert.Equal(t, window, got)

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
		})
	}
}

func TestRemoveWindow(t *testing.T) {
	tests := []struct {
		name    string
		missing bool
	}{
		{name: "happy path - removes the file"},
		{name: "happy path - missing file returns nil", missing: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			path := filepath.Join(dir, "window.json")
			if !tt.missing {
				require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
			}

			// when
			err := guard.RemoveWindow(dir)

			// then
			require.NoError(t, err)
			assert.NoFileExists(t, path)
		})
	}
}
