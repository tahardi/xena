package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestAutoUpdates_Run(t *testing.T) {
	const path = "etc/apt/apt.conf.d/20auto-upgrades"

	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name: "happy path - both on",
			files: map[string]string{
				path: "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
			},
			want: []string{},
		},
		{
			name: "happy path - unattended upgrade off",
			files: map[string]string{
				path: "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
			},
			want: []string{logs.SeverityMedium},
		},
		{
			name: "happy path - missing file",
			want: []string{logs.SeverityMedium},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := t.TempDir()
			writeFiles(t, root, tt.files)

			// when
			got, err := NewAutoUpdates(root).Run(t.Context())

			// then
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
		})
	}
}
