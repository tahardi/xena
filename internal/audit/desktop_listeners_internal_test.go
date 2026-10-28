package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

func TestListeners_Run(t *testing.T) {
	const allowed = "udp   UNCONN 0      0          127.0.0.53%lo:53         0.0.0.0:*\n" +
		"tcp   LISTEN 0      4096       127.0.0.1:631          0.0.0.0:*\n" +
		"tcp   LISTEN 0      4096           [::1]:631             [::]:*\n" +
		"tcp   LISTEN 0      4096   192.168.150.1:3128         0.0.0.0:*\n"

	tests := []struct {
		name    string
		ss      fakeResult
		extra   []string
		want    []string
		msg     string
		errText string
	}{
		{
			name: "happy path - loopback and bridge only",
			ss:   fakeResult{out: allowed},
			want: []string{},
		},
		{
			name: "happy path - ssh on all addresses",
			ss:   fakeResult{out: allowed + "tcp   LISTEN 0      128          0.0.0.0:22           0.0.0.0:*\n"},
			want: []string{logs.SeverityHigh},
			msg:  "listening on 0.0.0.0:22",
		},
		{
			name: "happy path - wildcard listener",
			ss:   fakeResult{out: allowed + "udp   UNCONN 0      0                  *:5353               *:*\n"},
			want: []string{logs.SeverityHigh},
			msg:  "listening on *:5353",
		},
		{
			name:  "happy path - configured extra",
			ss:    fakeResult{out: allowed + "tcp   LISTEN 0      128       192.0.2.10:22           0.0.0.0:*\n"},
			extra: []string{"192.0.2.10:22"},
			want:  []string{},
		},
		{
			name: "happy path - ipv6 wildcard",
			ss:   fakeResult{out: allowed + "tcp   LISTEN 0      128             [::]:22              [::]:*\n"},
			want: []string{logs.SeverityHigh},
			msg:  "listening on [::]:22",
		},
		{
			name: "happy path - scoped ipv6 link-local",
			ss:   fakeResult{out: allowed + "udp   UNCONN 0      0      [fe80::1]%eth0:546            [::]:*\n"},
			want: []string{logs.SeverityHigh},
			msg:  "listening on [fe80::1%eth0]:546",
		},
		{
			name:  "happy path - interface-bound listener allowed by its scoped address",
			ss:    fakeResult{out: allowed + "udp   UNCONN 0      0      0.0.0.0%xena0:67         0.0.0.0:*\n"},
			extra: []string{"0.0.0.0%xena0:67"},
			want:  []string{},
		},
		{
			name:  "happy path - interface-bound listener not allowed by wildcard entry alone",
			ss:    fakeResult{out: allowed + "tcp   LISTEN 0      128          0.0.0.0:68           0.0.0.0:*\n"},
			extra: []string{"0.0.0.0%xena0:68"},
			want:  []string{logs.SeverityHigh},
		},
		{
			name: "happy path - empty output",
			ss:   fakeResult{out: ""},
			want: []string{},
		},
		{
			name:    "error - unparseable address",
			ss:      fakeResult{out: "tcp   LISTEN 0      128          nonsense           0.0.0.0:*\n"},
			errText: "parsing listener",
		},
		{
			name:    "error - ss fails",
			ss:      fakeResult{err: errBroken},
			errText: "reading listeners",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			cmd := fakeCommander{"ss -tulpnH": tt.ss}
			check := NewListeners(cmd, append([]string{"192.168.150.1:3128"}, tt.extra...))

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
		})
	}
}
