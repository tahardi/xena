package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestOverlay_Run(t *testing.T) {
	tests := []struct {
		name    string
		overlay string
		mode    os.FileMode
		want    []Finding
		errText string
		noFile  bool
	}{
		{
			name:   "happy path - missing overlay",
			noFile: true,
			want:   []Finding{},
		},
		{
			name:    "happy path - two hosts",
			overlay: "version: 1\nhosts:\n  - host: a.example.com\n  - host: b.example.com\n    ports: [443, 8443]\n",
			mode:    0o600,
			want: []Finding{
				{
					Severity: logs.SeverityLow,
					Message:  "overlay allowlist entry a.example.com ports [443]",
					Fix:      "move it into config/allowlist.yaml by PR, or remove it",
				},
				{
					Severity: logs.SeverityLow,
					Message:  "overlay allowlist entry b.example.com ports [443 8443]",
					Fix:      "move it into config/allowlist.yaml by PR, or remove it",
				},
			},
		},
		{
			name:    "error - invalid yaml",
			overlay: "version: 1\nhosts: [\n",
			mode:    0o600,
			errText: "reading overlay allowlist",
		},
		{
			name:    "error - unreadable file",
			overlay: "version: 1\nhosts: []\n",
			mode:    0o000,
			errText: "reading overlay allowlist",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := filepath.Join(t.TempDir(), "overlay.yaml")
			if !tt.noFile {
				require.NoError(t, os.WriteFile(path, []byte(tt.overlay), tt.mode))
			}

			// when
			got, err := NewOverlay(path).Run(t.Context())

			// then
			if tt.errText != "" {
				require.ErrorContains(t, err, tt.errText)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, append([]Finding{}, got...))
		})
	}
}
