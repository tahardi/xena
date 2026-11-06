package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestDocker_Run(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
		msg   string
	}{
		{
			name: "happy path - no binaries",
			want: []string{},
		},
		{
			name:  "happy path - dockerd present",
			files: map[string]string{"usr/bin/dockerd": ""},
			want:  []string{logs.SeverityHigh},
			msg:   "/usr/bin/dockerd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := t.TempDir()
			writeFiles(t, root, tt.files)

			// when
			got, err := NewDocker(root).Run(t.Context())

			// then
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
			if tt.msg != "" {
				require.Contains(t, got[0].Message, tt.msg)
				require.NotContains(t, got[0].Message, root)
			}
		})
	}
}
