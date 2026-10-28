package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestUFW_Run(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
		msg   string
	}{
		{
			name: "happy path - enabled with drop",
			files: map[string]string{
				"etc/ufw/ufw.conf": "# comment\nENABLED=yes\nLOGLEVEL=low\n",
				"etc/default/ufw":  "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n",
			},
			want: []string{},
		},
		{
			name: "happy path - enabled with reject",
			files: map[string]string{
				"etc/ufw/ufw.conf": "ENABLED=yes\n",
				"etc/default/ufw":  "DEFAULT_INPUT_POLICY=\"REJECT\"\n",
			},
			want: []string{},
		},
		{
			name: "happy path - disabled",
			files: map[string]string{
				"etc/ufw/ufw.conf": "ENABLED=no\n",
				"etc/default/ufw":  "DEFAULT_INPUT_POLICY=\"DROP\"\n",
			},
			want: []string{logs.SeverityHigh},
		},
		{
			name: "happy path - accept policy",
			files: map[string]string{
				"etc/ufw/ufw.conf": "ENABLED=yes\n",
				"etc/default/ufw":  "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n",
			},
			want: []string{logs.SeverityHigh},
		},
		{
			name: "happy path - missing files",
			want: []string{logs.SeverityHigh},
			msg:  "ufw not configured",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := t.TempDir()
			writeFiles(t, root, tt.files)

			// when
			got, err := NewUFW(root).Run(t.Context())

			// then
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
			if tt.msg != "" {
				require.Equal(t, tt.msg, got[0].Message)
			}
		})
	}
}
