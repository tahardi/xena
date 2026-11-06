package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestGHAuth_Run(t *testing.T) {
	const keyring = "github.com\n" +
		"  ✓ Logged in to github.com account example (keyring)\n" +
		"  - Active account: true\n" +
		"  - Token: gho_************************************\n" +
		"  - Token scopes: 'repo', 'read:org'\n"
	const plainHosts = "github.com:\n    oauth_token: example-token-value\n    user: example\n"

	tests := []struct {
		name    string
		status  fakeResult
		hosts   string
		want    []string
		msg     string
		errText string
	}{
		{
			name:   "happy path - keyring with allowed scopes",
			status: fakeResult{out: keyring},
			hosts:  "github.com:\n    user: example\n",
			want:   []string{},
		},
		{
			name:   "happy path - plain text token",
			status: fakeResult{out: keyring},
			hosts:  plainHosts,
			want:   []string{logs.SeverityHigh},
			msg:    "gh token stored in plain text",
		},
		{
			name:   "happy path - extra scope",
			status: fakeResult{out: "  ✓ Logged in (keyring)\n  - Token scopes: 'repo', 'read:org', 'delete_repo'\n"},
			want:   []string{logs.SeverityMedium},
			msg:    "gh token has scope delete_repo, which audit.yaml does not allow",
		},
		{
			name:   "happy path - not in keyring",
			status: fakeResult{out: "  ✓ Logged in (GH_TOKEN)\n  - Token scopes: 'repo', 'read:org'\n"},
			want:   []string{logs.SeverityHigh},
		},
		{
			name:   "happy path - no scopes line",
			status: fakeResult{out: "  ✓ Logged in (keyring)\n  - Token: github_pat_****\n"},
			want:   []string{},
		},
		{
			name:   "happy path - plain text token and not in keyring",
			status: fakeResult{out: "  ✓ Logged in (oauth_token)\n"},
			hosts:  plainHosts,
			want:   []string{logs.SeverityHigh, logs.SeverityHigh},
		},
		{
			name:    "error - gh fails",
			status:  fakeResult{out: "  X Failed to log in\n", err: errBroken},
			errText: "reading gh auth status",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			home := t.TempDir()
			if tt.hosts != "" {
				writeFiles(t, home, map[string]string{".config/gh/hosts.yml": tt.hosts})
			}
			check := NewGHAuth(
				fakeCommander{"gh auth status --hostname github.com": tt.status},
				home,
				[]string{"repo", "read:org"},
			)

			// when
			got, err := check.Run(t.Context())

			// then
			if tt.errText != "" {
				require.ErrorContains(t, err, tt.errText)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, severities(got))
			if tt.msg != "" {
				require.Equal(t, tt.msg, got[0].Message)
			}
			for _, f := range got {
				require.NotContains(t, f.Message, "example-token-value")
				require.NotContains(t, f.Fix, "example-token-value")
			}
		})
	}
}
