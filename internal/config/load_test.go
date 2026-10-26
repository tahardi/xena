package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type sample struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"name"`
	Size    int    `yaml:"size"`
}

var errBadMigration = errors.New("bad migration")

func TestLoad(t *testing.T) {
	migrations := map[int]func(map[string]any) (map[string]any, error){
		1: func(m map[string]any) (map[string]any, error) {
			m["name"] = m["title"]
			delete(m, "title")
			return m, nil
		},
		2: func(m map[string]any) (map[string]any, error) {
			m["size"] = 8
			return m, nil
		},
	}
	tests := []struct {
		name       string
		file       string
		current    int
		migrate    map[int]func(map[string]any) (map[string]any, error)
		mode       os.FileMode
		want       sample
		wantErr    error
		wantBackup string
	}{
		{
			name:    "happy path - current version",
			file:    "version: 3\nname: a\nsize: 2\n",
			current: 3,
			want:    sample{Version: 3, Name: "a", Size: 2},
		},
		{
			name:       "happy path - migrates from version 1",
			file:       "version: 1\ntitle: a\n",
			current:    3,
			migrate:    migrations,
			want:       sample{Version: 3, Name: "a", Size: 8},
			wantBackup: "sample.yaml.v1.bak",
		},
		{
			name:       "happy path - migrates from version 2 keeping mode 0600",
			file:       "version: 2\nname: a\n",
			current:    3,
			mode:       0o600,
			migrate:    migrations,
			want:       sample{Version: 3, Name: "a", Size: 8},
			wantBackup: "sample.yaml.v2.bak",
		},
		{
			name:    "error - version above current",
			file:    "version: 4\n",
			current: 3,
			wantErr: ErrUnknownVersion,
		},
		{
			name:    "error - missing version",
			file:    "name: a\n",
			current: 3,
			wantErr: ErrMissingVersion,
		},
		{
			name:    "error - version not a number",
			file:    "version: \"1\"\n",
			current: 3,
			wantErr: ErrMissingVersion,
		},
		{
			name:    "error - version zero",
			file:    "version: 0\n",
			current: 3,
			wantErr: ErrMissingVersion,
		},
		{
			name:    "error - no migrations given",
			file:    "version: 1\ntitle: a\n",
			current: 2,
			wantErr: ErrMissingMigration,
		},
		{
			name:    "error - missing migration",
			file:    "version: 1\ntitle: a\n",
			current: 3,
			migrate: map[int]func(map[string]any) (map[string]any, error){1: migrations[1]},
			wantErr: ErrMissingMigration,
		},
		{
			name:    "error - migration fails",
			file:    "version: 2\nname: a\n",
			current: 3,
			migrate: map[int]func(map[string]any) (map[string]any, error){
				2: func(map[string]any) (map[string]any, error) { return nil, errBadMigration },
			},
			wantErr: errBadMigration,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			mode := tt.mode
			if mode == 0 {
				mode = 0o640
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "sample.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.file), mode))
			require.NoError(t, os.Chmod(path, mode))

			// when
			got, err := Load[sample](path, tt.current, tt.migrate)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.want, got)

			temps, globErr := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
			require.NoError(t, globErr)
			require.Empty(t, temps)

			if tt.wantBackup == "" {
				backups, globErr := filepath.Glob(filepath.Join(dir, "*.bak"))
				require.NoError(t, globErr)
				require.Empty(t, backups)

				unchanged, readErr := os.ReadFile(path)
				require.NoError(t, readErr)
				require.Equal(t, tt.file, string(unchanged))
				return
			}
			backup, backupErr := os.ReadFile(filepath.Join(dir, tt.wantBackup))
			require.NoError(t, backupErr)
			require.Equal(t, tt.file, string(backup))

			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, mode, info.Mode().Perm())

			again, err := Load[sample](path, tt.current, nil)
			require.NoError(t, err)
			require.Equal(t, tt.want, again)
		})
	}
	t.Run("error - unknown field", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "sample.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: 1\nnmae: a\n"), 0o600))

		// when
		_, err := Load[sample](path, 1, nil)

		// then
		require.ErrorContains(t, err, "decoding")
	})
	t.Run("error - invalid yaml", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "sample.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: [\n"), 0o600))

		// when
		_, err := Load[sample](path, 1, nil)

		// then
		require.ErrorContains(t, err, "parsing")
	})
	t.Run("error - file missing", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "missing.yaml")

		// when
		_, err := Load[sample](path, 1, nil)

		// then
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}
