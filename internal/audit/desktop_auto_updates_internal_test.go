package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestAutoUpdates_Run(t *testing.T) {
	const key = "apt-config dump APT::Periodic"

	tests := []struct {
		name    string
		dump    fakeResult
		want    []string
		errText string
	}{
		{
			name: "happy path - both on",
			dump: fakeResult{out: "APT::Periodic \"\";\n" +
				"APT::Periodic::Update-Package-Lists \"1\";\n" +
				"APT::Periodic::Unattended-Upgrade \"1\";\n"},
			want: []string{},
		},
		{
			name: "happy path - later file turns unattended upgrade off",
			dump: fakeResult{out: "APT::Periodic::Update-Package-Lists \"1\";\n" +
				"APT::Periodic::Unattended-Upgrade \"0\";\n"},
			want: []string{logs.SeverityMedium},
		},
		{
			name: "happy path - nothing configured",
			dump: fakeResult{out: "APT::Periodic \"\";\n"},
			want: []string{logs.SeverityMedium, logs.SeverityMedium},
		},
		{
			name:    "error - apt-config fails",
			dump:    fakeResult{err: errBroken},
			errText: "reading apt periodic settings",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			check := NewAutoUpdates(fakeCommander{key: tt.dump})

			// when
			got, err := check.Run(t.Context())

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
