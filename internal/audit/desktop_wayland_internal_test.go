package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestWayland_Run(t *testing.T) {
	const sessions = `[{"session":"2","uid":1000,"user":"taylor","seat":"seat0","tty":"tty2"},` +
		`{"session":"5","uid":1001,"user":"other","seat":null,"tty":null}]`

	tests := []struct {
		name    string
		version string
		cmd     fakeCommander
		want    []string
		errText string
	}{
		{
			name:    "happy path - 26.04 on wayland",
			version: `VERSION_ID="26.04"`,
			cmd: fakeCommander{
				"loginctl list-sessions --json=short":     {out: sessions},
				"loginctl show-session 2 -p Type --value": {out: "wayland\n"},
			},
			want: []string{},
		},
		{
			name:    "happy path - x11 session",
			version: `VERSION_ID="26.04"`,
			cmd: fakeCommander{
				"loginctl list-sessions --json=short":     {out: sessions},
				"loginctl show-session 2 -p Type --value": {out: "x11\n"},
			},
			want: []string{logs.SeverityHigh},
		},
		{
			name:    "happy path - older ubuntu",
			version: `VERSION_ID="24.04"`,
			cmd: fakeCommander{
				"loginctl list-sessions --json=short":     {out: sessions},
				"loginctl show-session 2 -p Type --value": {out: "wayland\n"},
			},
			want: []string{logs.SeverityMedium},
		},
		{
			name:    "happy path - no session for the user",
			version: `VERSION_ID="26.04"`,
			cmd:     fakeCommander{"loginctl list-sessions --json=short": {out: "[]"}},
			want:    []string{},
		},
		{
			name:    "error - show-session fails",
			version: `VERSION_ID="26.04"`,
			cmd: fakeCommander{
				"loginctl list-sessions --json=short":     {out: sessions},
				"loginctl show-session 2 -p Type --value": {err: errBroken},
			},
			errText: "reading session 2 type",
		},
		{
			name:    "error - bad session list",
			version: `VERSION_ID="26.04"`,
			cmd:     fakeCommander{"loginctl list-sessions --json=short": {out: "not json"}},
			errText: "parsing loginctl sessions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			root := t.TempDir()
			writeFiles(t, root, map[string]string{"etc/os-release": "NAME=\"Ubuntu\"\n" + tt.version + "\n"})
			check := NewWayland(tt.cmd, root, "taylor")

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
