package proxy_test

import (
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/proxy"
)

func TestHostsOnlyResolver_LookupNetIP(t *testing.T) {
	tests := []struct {
		name      string
		hosts     *string
		host      string
		next      map[string][]netip.Addr
		want      []netip.Addr
		nextErr   error
		wantErr   error
		wantCalls []string
	}{
		{
			name:  "happy path - listed special-use name",
			hosts: new("127.0.0.1 xena-guard-rebind.test\n"),
			host:  "xena-guard-rebind.test",
			want:  addrs("127.0.0.1"),
		},
		{
			name:    "error - special-use name not listed",
			hosts:   new("127.0.0.1 localhost\n"),
			host:    "xena-guard-rebind.test",
			wantErr: proxy.ErrSpecialUseName,
		},
		{
			name:  "happy path - mixed case and trailing dot",
			hosts: new("127.0.0.1 xena-guard-rebind.test\n"),
			host:  "XENA-Guard-Rebind.test.",
			want:  addrs("127.0.0.1"),
		},
		{
			name:      "happy path - other names go to next",
			hosts:     new("127.0.0.1 api.github.com\n"),
			host:      "api.github.com",
			next:      map[string][]netip.Addr{"api.github.com": addrs("192.0.2.10")},
			want:      addrs("192.0.2.10"),
			wantCalls: []string{"api.github.com"},
		},
		{
			name:    "error - hosts file missing",
			host:    "xena-guard-rebind.test",
			wantErr: fs.ErrNotExist,
		},
		{
			name: "happy path - comments and several names",
			hosts: new(
				"# 192.0.2.99 xena-guard-rebind.test\n" +
					"127.0.0.1 localhost # xena-guard-rebind.test\n" +
					"::1 other.test XENA-guard-rebind.TEST. third.invalid\n" +
					"not-an-address xena-guard-rebind.test\n" +
					"127.0.0.2\txena-guard-rebind.test\n",
			),
			host: "xena-guard-rebind.test",
			want: addrs("::1", "127.0.0.2"),
		},
		{
			name:  "happy path - bare special-use label",
			hosts: new("127.0.0.1 localhost\n"),
			host:  "localhost",
			want:  addrs("127.0.0.1"),
		},
		{
			name:    "error - example name never reaches next",
			hosts:   new(""),
			host:    "a.b.example",
			next:    map[string][]netip.Addr{"a.b.example": addrs("192.0.2.10")},
			wantErr: proxy.ErrSpecialUseName,
		},
		{
			name:    "error - invalid name never reaches next",
			hosts:   new(""),
			host:    "xena-guard-unlisted.invalid",
			next:    map[string][]netip.Addr{"xena-guard-unlisted.invalid": addrs("192.0.2.10")},
			wantErr: proxy.ErrSpecialUseName,
		},
		{
			name:    "error - localhost subdomain never reaches next",
			hosts:   new(""),
			host:    "app.localhost",
			next:    map[string][]netip.Addr{"app.localhost": addrs("192.0.2.10")},
			wantErr: proxy.ErrSpecialUseName,
		},
		{
			name:      "happy path - names that only contain a special-use label go to next",
			hosts:     new("127.0.0.1 latest api.test.com\n"),
			host:      "api.test.com",
			next:      map[string][]netip.Addr{"api.test.com": addrs("192.0.2.10")},
			want:      addrs("192.0.2.10"),
			wantCalls: []string{"api.test.com"},
		},
		{
			name:      "happy path - label suffix without a dot goes to next",
			hosts:     new(""),
			host:      "latest",
			next:      map[string][]netip.Addr{"latest": addrs("192.0.2.11")},
			want:      addrs("192.0.2.11"),
			wantCalls: []string{"latest"},
		},
		{
			name:      "error - next failure returned unchanged",
			hosts:     new(""),
			host:      "api.github.com",
			nextErr:   errFake,
			wantErr:   errFake,
			wantCalls: []string{"api.github.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := filepath.Join(t.TempDir(), "hosts")
			if tt.hosts != nil {
				require.NoError(t, os.WriteFile(path, []byte(*tt.hosts), 0o600))
			}

			next := &fakeResolver{answers: tt.next, err: tt.nextErr}
			if next.answers == nil {
				next.answers = map[string][]netip.Addr{}
			}
			r := proxy.NewHostsOnlyResolver(next, path)

			// when
			got, err := r.LookupNetIP(t.Context(), "ip", tt.host)

			// then
			require.Equal(t, tt.wantCalls, next.Calls())
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
