package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestGroups_Run(t *testing.T) {
	tests := []struct {
		name    string
		group   string
		want    []string
		errText string
	}{
		{
			name:  "happy path - not in docker or libvirt",
			group: "docker:x:999:\nlibvirt:x:998:other\nsudo:x:27:taylor\n",
			want:  []string{},
		},
		{
			name:  "happy path - in docker",
			group: "docker:x:999:taylor\n",
			want:  []string{logs.SeverityHigh},
		},
		{
			name:  "happy path - in libvirt",
			group: "libvirt:x:998:a,taylor\n",
			want:  []string{logs.SeverityHigh},
		},
		{
			name:  "happy path - similar user name",
			group: "docker:x:999:taylor2\n",
			want:  []string{},
		},
		{
			name:  "happy path - in both groups",
			group: "docker:x:999:taylor\nlibvirt:x:998:taylor\n",
			want:  []string{logs.SeverityHigh, logs.SeverityHigh},
		},
		{
			name:    "error - missing group file",
			errText: "reading /etc/group",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := t.TempDir()
			if tt.group != "" {
				writeFiles(t, root, map[string]string{"etc/group": tt.group})
			}

			// when
			got, err := NewGroups(root, "taylor").Run(t.Context())

			// then
			if tt.errText != "" {
				require.ErrorContains(t, err, tt.errText)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
		})
	}
}
