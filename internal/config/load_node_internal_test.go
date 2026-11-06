package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestLoadNode(t *testing.T) {
	migrations := map[int]func(map[string]any) (map[string]any, error){
		1: func(m map[string]any) (map[string]any, error) {
			m["name"] = m["title"]
			delete(m, "title")
			return m, nil
		},
	}

	tests := []struct {
		name       string
		file       string
		current    int
		want       string
		wantBackup bool
		wantErr    error
	}{
		{
			name: "happy path - current version keeps comments",
			file: "version: 2\n# keep\nname: a\n",
			want: "version: 2\n# keep\nname: a\n",
		},
		{
			name:       "happy path - migrates forward with backup",
			file:       "version: 1\ntitle: a\n",
			want:       "name: a\nversion: 2\n",
			wantBackup: true,
		},
		{
			name:    "error - missing file",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "error - missing version",
			file:    "name: a\n",
			wantErr: ErrMissingVersion,
		},
		{
			name:    "error - missing migration",
			file:    "version: 2\nname: a\n",
			current: 3,
			wantErr: ErrMissingMigration,
		},
		{
			name:    "error - unknown version",
			file:    "version: 3\nname: a\n",
			wantErr: ErrUnknownVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := filepath.Join(t.TempDir(), "sample.yaml")
			if tt.file != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))
			}

			current := tt.current
			if current == 0 {
				current = 2
			}

			// when
			doc, err := LoadNode(path, current, migrations)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			got, err := yaml.Marshal(&doc)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
			_, err = os.Stat(path + ".v1.bak")
			assert.Equal(t, tt.wantBackup, err == nil)
		})
	}
}
