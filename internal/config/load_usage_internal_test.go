package config

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadIsOnlyYAMLReader(t *testing.T) {
	tests := []struct {
		name string
		root fs.FS
		want []string
	}{
		{
			name: "happy path - module has no other yaml readers",
			root: os.DirFS(filepath.Join("..", "..")),
		},
		{
			name: "error - flags yaml readers outside config",
			root: fstest.MapFS{
				"internal/a/a.go":           {Data: []byte("yaml.Unmarshal(data, &v)")},
				"internal/b/b.go":           {Data: []byte("yaml.NewDecoder(r)")},
				"internal/b/b_test.go":      {Data: []byte("yaml.Unmarshal(data, &v)")},
				"internal/config/load.go":   {Data: []byte("yaml.Unmarshal(data, &v)")},
				"modfiles/tool/tool.go":     {Data: []byte("yaml.Unmarshal(data, &v)")},
				"internal/c/c.go":           {Data: []byte("yaml.Marshal(v)")},
				"internal/a/notes.md":       {Data: []byte("yaml.Unmarshal(")},
				".git/hooks/pre-commit.go":  {Data: []byte("yaml.Unmarshal(")},
				"internal/config/vm/vm.go":  {Data: []byte("yaml.Unmarshal(")},
				"cmd/xena/inventory_cfg.go": {Data: []byte("x := 1")},
			},
			want: []string{"internal/a/a.go", "internal/b/b.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := tt.root

			// when
			got, err := yamlReaders(root)

			// then
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "load YAML through config.Load instead")
		})
	}
}

func yamlReaders(root fs.FS) ([]string, error) {
	skipDirs := map[string]bool{"internal/config": true, "modfiles": true, ".git": true}

	var offenders []string
	err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && skipDirs[path] {
			return fs.SkipDir
		}

		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, err := fs.ReadFile(root, path)
		if err != nil {
			return err
		}

		if bytes.Contains(data, []byte("yaml.Unmarshal(")) || bytes.Contains(data, []byte("yaml.NewDecoder(")) {
			offenders = append(offenders, path)
		}

		return nil
	})

	return offenders, err
}
