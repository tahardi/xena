package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestFirewall_Run(t *testing.T) {
	const hardened = "table inet host_filter {\n" +
		"\tchain input {\n" +
		"\t\ttype filter hook input priority filter + 10; policy drop;\n" +
		"\t\tiifname \"lo\" accept\n" +
		"\t}\n" +
		"}\n"
	const ubuntuDefault = "table inet filter {\n" +
		"\tchain input {\n" +
		"\t\ttype filter hook input priority filter;\n" +
		"\t}\n" +
		"}\n"
	enabled := fakeResult{out: "enabled\n"}

	tests := []struct {
		name    string
		files   map[string]string
		service fakeResult
		want    []string
		msgs    []string
	}{
		{
			name:    "happy path - hardened and enabled",
			files:   map[string]string{"etc/nftables.conf": hardened},
			service: enabled,
			want:    []string{},
		},
		{
			name:    "happy path - default ruleset accepts input",
			files:   map[string]string{"etc/nftables.conf": ubuntuDefault},
			service: enabled,
			want:    []string{logs.SeverityHigh},
			msgs:    []string{"nftables input chain does not drop by default"},
		},
		{
			name:    "happy path - no ruleset",
			service: enabled,
			want:    []string{logs.SeverityHigh},
			msgs:    []string{"nftables not configured"},
		},
		{
			name:    "happy path - service disabled",
			files:   map[string]string{"etc/nftables.conf": hardened},
			service: fakeResult{out: "disabled\n", err: errBroken},
			want:    []string{logs.SeverityHigh},
			msgs:    []string{`nftables service is "disabled", not enabled`},
		},
		{
			name:    "happy path - service missing",
			files:   map[string]string{"etc/nftables.conf": hardened},
			service: fakeResult{err: errBroken},
			want:    []string{logs.SeverityHigh},
			msgs:    []string{`nftables service is "unknown", not enabled`},
		},
		{
			name:    "happy path - nothing set up",
			service: fakeResult{out: "disabled\n", err: errBroken},
			want:    []string{logs.SeverityHigh, logs.SeverityHigh},
			msgs:    []string{"nftables not configured", `nftables service is "disabled", not enabled`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := t.TempDir()
			writeFiles(t, root, tt.files)
			cmd := fakeCommander{"systemctl is-enabled nftables": tt.service}

			// when
			got, err := NewFirewall(cmd, root).Run(t.Context())

			// then
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
			for i, msg := range tt.msgs {
				require.Equal(t, msg, got[i].Message)
			}
		})
	}
}
