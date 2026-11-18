package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestParseFrontmatter(t *testing.T) {
	tests := []struct {
		name     string
		fields   string
		wantKeys []string
		wantErr  error
	}{
		{name: "happy path - mapping", fields: "title: x\ntags: [a]\n", wantKeys: []string{"title", "tags"}},
		{name: "happy path - empty", fields: "", wantKeys: []string{}},
		{name: "happy path - blank lines", fields: "\n\n", wantKeys: []string{}},
		{name: "error - list", fields: "- a\n", wantErr: ErrFrontmatterNotMapping},
		{name: "error - scalar", fields: "just text\n", wantErr: ErrFrontmatterNotMapping},
		{name: "error - broken yaml", fields: "kind: \"abc\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, err := ParseFrontmatter(tt.fields)

			// then
			if tt.wantKeys == nil {
				require.Error(t, err)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, yaml.MappingNode, got.Kind)

			keys := []string{}
			for i := 0; i < len(got.Content); i += 2 {
				keys = append(keys, got.Content[i].Value)
			}
			require.Equal(t, tt.wantKeys, keys)
		})
	}
}
