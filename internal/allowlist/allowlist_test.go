package allowlist_test

import (
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/allowlist"
	"github.com/tahardi/xena/internal/config"
)

const fixture = `version: 1
hosts:
  - host: example.com
  - host: plain.example.com
    ports: [80]
  - host: "*.example.org"
    ports: [443, 8443]
  - host: example.net
    ports: [443]
  - host: example.net
    ports: [8080]
  - host: both.example.org
    ports: [9443]
`

func writeFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "allowlist.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func loadList(t *testing.T, content string) allowlist.Allowlist {
	t.Helper()

	list, err := allowlist.Load(writeFile(t, content))
	require.NoError(t, err)
	return list
}

func TestNormalize(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)
	label62 := strings.Repeat("a", 62)
	name253 := strings.Join([]string{label62, label62, label62, label62}, ".") + ".a"

	tests := []struct {
		name    string
		host    string
		want    string
		wantErr error
	}{
		{name: "lowercase", host: "Example.COM", want: "example.com"},
		{name: "trailing dot", host: "example.com.", want: "example.com"},
		{name: "punycode", host: "xn--bcher-kva.example", want: "xn--bcher-kva.example"},
		{name: "hyphen inside label", host: "a-b.example.com", want: "a-b.example.com"},
		{name: "63-char label", host: label63 + ".example", want: label63 + ".example"},
		{name: "253-char name", host: name253, want: name253},
		{name: "253-char name with trailing dot", host: name253 + ".", want: name253},
		{name: "single label", host: "localhost", want: "localhost"},
		{name: "non-ASCII", host: "bücher.example", wantErr: allowlist.ErrNonASCIIHost},
		{name: "full-width digits", host: "１２７.0.0.1", wantErr: allowlist.ErrNonASCIIHost},
		{name: "IPv4 literal", host: "192.0.2.10", wantErr: allowlist.ErrIPLiteralHost},
		{name: "short IPv4 literal", host: "127.1", wantErr: allowlist.ErrIPLiteralHost},
		{name: "IPv6 literal", host: "[2001:db8::1]", wantErr: allowlist.ErrIPLiteralHost},
		{name: "empty", host: "", wantErr: allowlist.ErrInvalidHost},
		{name: "two trailing dots", host: "example.com..", wantErr: allowlist.ErrInvalidHost},
		{name: "empty label", host: "a..example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "64-char label", host: label64 + ".example", wantErr: allowlist.ErrInvalidHost},
		{
			name:    "254-char name",
			host:    strings.Join([]string{label62, label62, label62, label62}, ".") + ".ab",
			wantErr: allowlist.ErrInvalidHost,
		},
		{name: "leading hyphen", host: "-a.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "trailing hyphen", host: "a-.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "underscore", host: "a_b.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "space", host: "a b.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "markup", host: "<b>.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "wildcard", host: "*.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "port included", host: "example.com:443", wantErr: allowlist.ErrInvalidHost},
		{name: "newline", host: "a\nb.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "tab", host: "a\tb.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "percent", host: "a%b.example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "userinfo", host: "user@example.com", wantErr: allowlist.ErrInvalidHost},
		{name: "path", host: "example.com/a", wantErr: allowlist.ErrInvalidHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			host := tt.host

			// when
			got, err := allowlist.Normalize(host)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		hosts   string
		want    []allowlist.Rule
		wantErr error
	}{
		{
			name:  "ports default to 443",
			hosts: "  - host: example.com\n",
			want:  []allowlist.Rule{{Host: "example.com", Ports: []int{443}}},
		},
		{
			name:  "explicit ports",
			hosts: "  - host: example.com\n    ports: [80, 443]\n",
			want:  []allowlist.Rule{{Host: "example.com", Ports: []int{80, 443}}},
		},
		{
			name:  "normalized",
			hosts: "  - host: Example.COM.\n",
			want:  []allowlist.Rule{{Host: "example.com", Ports: []int{443}}},
		},
		{
			name:  "wildcard kept",
			hosts: "  - host: \"*.example.org\"\n",
			want:  []allowlist.Rule{{Host: "*.example.org", Ports: []int{443}}},
		},
		{
			name:  "wildcard uppercase",
			hosts: "  - host: \"*.Example.ORG.\"\n",
			want:  []allowlist.Rule{{Host: "*.example.org", Ports: []int{443}}},
		},
		{
			name:  "exact shared host allowed",
			hosts: "  - host: docs.github.io\n",
			want:  []allowlist.Rule{{Host: "docs.github.io", Ports: []int{443}}},
		},
		{
			name:  "empty list",
			hosts: "  []\n",
			want:  []allowlist.Rule{},
		},
		{
			name:    "port zero",
			hosts:   "  - host: example.com\n    ports: [0]\n",
			wantErr: allowlist.ErrInvalidPort,
		},
		{
			name:    "port too high",
			hosts:   "  - host: example.com\n    ports: [65536]\n",
			wantErr: allowlist.ErrInvalidPort,
		},
		{
			name:    "negative port",
			hosts:   "  - host: example.com\n    ports: [-1]\n",
			wantErr: allowlist.ErrInvalidPort,
		},
		{
			name:  "empty ports list",
			hosts: "  - host: example.com\n    ports: []\n",
			want:  []allowlist.Rule{{Host: "example.com", Ports: []int{443}}},
		},
		{name: "wildcard on TLD", hosts: "  - host: \"*.com\"\n", wantErr: allowlist.ErrBroadWildcard},
		{name: "bare star", hosts: "  - host: \"*\"\n", wantErr: allowlist.ErrInvalidHost},
		{name: "star mid-name", hosts: "  - host: \"a.*.example.com\"\n", wantErr: allowlist.ErrInvalidHost},
		{name: "double wildcard", hosts: "  - host: \"*.*.example.com\"\n", wantErr: allowlist.ErrInvalidHost},
		{name: "star suffix", hosts: "  - host: \"example*.com\"\n", wantErr: allowlist.ErrInvalidHost},
		{
			name:    "shared S3",
			hosts:   "  - host: \"*.s3.amazonaws.com\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:    "shared parent of S3",
			hosts:   "  - host: \"*.amazonaws.com\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:    "shared under suffix",
			hosts:   "  - host: \"*.eu.vercel.app\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:    "shared cloudfront",
			hosts:   "  - host: \"*.cloudfront.net\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:    "shared github.io",
			hosts:   "  - host: \"*.github.io\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:    "shared parent of blob storage",
			hosts:   "  - host: \"*.windows.net\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:    "shared parent of GCS",
			hosts:   "  - host: \"*.googleapis.com\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:    "shared ngrok free",
			hosts:   "  - host: \"*.ngrok-free.app\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:  "not shared: lookalike",
			hosts: "  - host: \"*.notvercel.app\"\n",
			want:  []allowlist.Rule{{Host: "*.notvercel.app", Ports: []int{443}}},
		},
		{name: "wildcard with no domain", hosts: "  - host: \"*.\"\n", wantErr: allowlist.ErrInvalidHost},
		{name: "wildcard on IP literal", hosts: "  - host: \"*.192.0.2.10\"\n", wantErr: allowlist.ErrIPLiteralHost},
		{name: "wildcard on non-ASCII", hosts: "  - host: \"*.bücher.example\"\n", wantErr: allowlist.ErrNonASCIIHost},
		{name: "IP literal rule", hosts: "  - host: 192.0.2.10\n", wantErr: allowlist.ErrIPLiteralHost},
		{name: "non-ASCII rule", hosts: "  - host: bücher.example\n", wantErr: allowlist.ErrNonASCIIHost},
		{
			name:    "one bad rule refuses file",
			hosts:   "  - host: example.com\n  - host: \"*.vercel.app\"\n",
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := writeFile(t, "version: 1\nhosts:\n"+tt.hosts)

			// when
			got, err := allowlist.Load(path)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.True(t, strings.HasPrefix(err.Error(), "loading allowlist"), err.Error())
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got.Hosts)
		})
	}
	t.Run("happy path - no hosts key", func(t *testing.T) {
		// given
		path := writeFile(t, "version: 1\n")

		// when
		got, err := allowlist.Load(path)

		// then
		require.NoError(t, err)
		require.Empty(t, got.Hosts)
	})

	t.Run("error - misspelled key", func(t *testing.T) {
		// given
		path := writeFile(t, "version: 1\nhosts:\n  - host: example.com\n    port: 8443\n")

		// when
		_, err := allowlist.Load(path)

		// then
		require.ErrorContains(t, err, "decoding")
		require.True(t, strings.HasPrefix(err.Error(), "loading allowlist"), err.Error())
	})

	t.Run("error - port not a number", func(t *testing.T) {
		// given
		path := writeFile(t, "version: 1\nhosts:\n  - host: example.com\n    ports: [https]\n")

		// when
		_, err := allowlist.Load(path)

		// then
		require.ErrorContains(t, err, "decoding")
	})

	t.Run("error - missing file", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "missing.yaml")

		// when
		_, err := allowlist.Load(path)

		// then
		require.ErrorIs(t, err, fs.ErrNotExist)
		require.True(t, strings.HasPrefix(err.Error(), "loading allowlist"), err.Error())
	})

	t.Run("error - unknown version", func(t *testing.T) {
		// given
		path := writeFile(t, "version: 2\nhosts: []\n")

		// when
		_, err := allowlist.Load(path)

		// then
		require.ErrorIs(t, err, config.ErrUnknownVersion)
		require.True(t, strings.HasPrefix(err.Error(), "loading allowlist"), err.Error())
	})
}

func TestAllowlist_Allows(t *testing.T) {
	list := loadList(t, fixture)
	tests := []struct {
		name string
		host string
		port int
		want bool
	}{
		{name: "exact default port", host: "example.com", port: 443, want: true},
		{name: "exact wrong port", host: "example.com", port: 80, want: false},
		{name: "exact other port", host: "example.com", port: 22, want: false},
		{name: "uppercase and trailing dot", host: "EXAMPLE.com.", port: 443, want: true},
		{name: "subdomain of exact rule", host: "www.example.com", port: 443, want: false},
		{name: "suffix trick", host: "badexample.com", port: 443, want: false},
		{name: "exact port 80 rule", host: "plain.example.com", port: 80, want: true},
		{name: "port 80 rule on 443", host: "plain.example.com", port: 443, want: false},
		{name: "wildcard one label", host: "a.example.org", port: 443, want: true},
		{name: "wildcard two labels", host: "a.b.example.org", port: 8443, want: true},
		{name: "wildcard bare domain", host: "example.org", port: 443, want: false},
		{name: "wildcard wrong port", host: "a.example.org", port: 80, want: false},
		{name: "wildcard suffix trick", host: "aexample.org", port: 443, want: false},
		{name: "duplicate rules union 1", host: "example.net", port: 443, want: true},
		{name: "duplicate rules union 2", host: "example.net", port: 8080, want: true},
		{name: "unlisted", host: "example.edu", port: 443, want: false},
		{name: "literal star input", host: "*.example.org", port: 443, want: false},
		{name: "IP literal input", host: "192.0.2.10", port: 443, want: false},
		{name: "non-ASCII input", host: "exämple.com", port: 443, want: false},
		{name: "empty input", host: "", port: 443, want: false},
		{name: "port zero", host: "example.com", port: 0, want: false},
		{name: "port too high", host: "example.com", port: 65536, want: false},
		{name: "negative port", host: "example.com", port: -1, want: false},
		{name: "port in host", host: "example.com:443", port: 443, want: false},
		{name: "exact and wildcard union 1", host: "both.example.org", port: 8443, want: true},
		{name: "exact and wildcard union 2", host: "both.example.org", port: 9443, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			host, port := tt.host, tt.port

			// when
			got := list.Allows(host, port)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAllowlist_Ports(t *testing.T) {
	list := loadList(t, fixture)
	tests := []struct {
		name string
		host string
		want []int
	}{
		{name: "duplicate exact rules", host: "example.net", want: []int{443, 8080}},
		{name: "wildcard rule", host: "a.example.org", want: []int{443, 8443}},
		{name: "exact and wildcard rules", host: "both.example.org", want: []int{443, 8443, 9443}},
		{name: "unlisted", host: "example.edu", want: nil},
		{name: "invalid host", host: "a_b.example.com", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			host := tt.host

			// when
			got := list.Ports(host)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAllowlist_Merge(t *testing.T) {
	t.Run("happy path - overlay adds hosts", func(t *testing.T) {
		// given
		base := loadList(t, "version: 1\nhosts:\n  - host: example.com\n")
		overlay := loadList(t, "version: 1\nhosts:\n  - host: example.edu\n    ports: [8443]\n")

		// when
		merged := base.Merge(overlay)

		// then
		require.True(t, merged.Allows("example.com", 443))
		require.True(t, merged.Allows("example.edu", 8443))
		require.Equal(t, allowlist.CurrentVersion, merged.Version)
		require.Len(t, base.Hosts, 1)
		require.Len(t, overlay.Hosts, 1)
	})

	t.Run("happy path - empty overlay", func(t *testing.T) {
		// given
		base := loadList(t, "version: 1\nhosts:\n  - host: example.com\n")
		overlay := loadList(t, "version: 1\nhosts: []\n")

		// when
		merged := base.Merge(overlay)

		// then
		require.Equal(t, base.Hosts, merged.Hosts)
		require.True(t, merged.Allows("example.com", 443))
		require.False(t, merged.Allows("example.edu", 443))
	})
}

func TestAllowlist_Add(t *testing.T) {
	original := []allowlist.Rule{{Host: "example.com", Ports: []int{443}}}
	tests := []struct {
		name    string
		host    string
		port    int
		want    []allowlist.Rule
		wantErr error
	}{
		{
			name: "new host",
			host: "example.edu",
			port: 443,
			want: []allowlist.Rule{
				{Host: "example.com", Ports: []int{443}},
				{Host: "example.edu", Ports: []int{443}},
			},
		},
		{
			name: "new port on existing host",
			host: "example.com",
			port: 8443,
			want: []allowlist.Rule{{Host: "example.com", Ports: []int{443, 8443}}},
		},
		{
			name: "existing host and port",
			host: "example.com",
			port: 443,
			want: []allowlist.Rule{{Host: "example.com", Ports: []int{443}}},
		},
		{
			name: "normalized",
			host: "EXAMPLE.edu.",
			port: 443,
			want: []allowlist.Rule{
				{Host: "example.com", Ports: []int{443}},
				{Host: "example.edu", Ports: []int{443}},
			},
		},
		{name: "wildcard refused", host: "*.example.edu", port: 443, wantErr: allowlist.ErrInvalidHost},
		{name: "IP literal refused", host: "192.0.2.10", port: 443, wantErr: allowlist.ErrIPLiteralHost},
		{name: "bad port", host: "example.edu", port: 0, wantErr: allowlist.ErrInvalidPort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			list := loadList(t, "version: 1\nhosts:\n  - host: example.com\n    ports: [443]\n")

			// when
			got, err := list.Add(tt.host, tt.port)

			// then
			require.Equal(t, original, list.Hosts)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got.Hosts)
		})
	}
}

func TestAllowlist_Save(t *testing.T) {
	t.Run("happy path - round trip", func(t *testing.T) {
		// given
		list := loadList(t, fixture)
		dir := t.TempDir()
		path := filepath.Join(dir, "overlay.yaml")

		// when
		err := list.Save(path)

		// then
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o640), info.Mode().Perm())

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(string(data), "version: 1"), string(data))

		again, err := allowlist.Load(path)
		require.NoError(t, err)
		require.Equal(t, list.Hosts, again.Hosts)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
	})

	t.Run("happy path - zero list after add", func(t *testing.T) {
		// given
		list, err := allowlist.Allowlist{}.Add("example.com", 443)
		require.NoError(t, err)

		path := filepath.Join(t.TempDir(), "overlay.yaml")

		// when
		err = list.Save(path)

		// then
		require.NoError(t, err)

		again, err := allowlist.Load(path)
		require.NoError(t, err)
		require.Equal(t, allowlist.CurrentVersion, again.Version)
		require.Equal(t, []allowlist.Rule{{Host: "example.com", Ports: []int{443}}}, again.Hosts)
	})

	t.Run("happy path - overwrites existing file", func(t *testing.T) {
		// given
		path := writeFile(t, fixture)
		list := loadList(t, "version: 1\nhosts:\n  - host: example.edu\n")

		// when
		err := list.Save(path)

		// then
		require.NoError(t, err)

		again, err := allowlist.Load(path)
		require.NoError(t, err)
		require.Equal(t, list.Hosts, again.Hosts)
	})

	t.Run("error - path is a directory", func(t *testing.T) {
		// given
		list := loadList(t, fixture)
		dir := t.TempDir()
		path := filepath.Join(dir, "overlay.yaml")
		require.NoError(t, os.Mkdir(path, 0o750))

		// when
		err := list.Save(path)

		// then
		require.True(t, strings.HasPrefix(err.Error(), "saving allowlist"), err.Error())

		temps, err := filepath.Glob(filepath.Join(dir, ".allowlist-*"))
		require.NoError(t, err)
		require.Empty(t, temps)
	})

	t.Run("error - directory missing", func(t *testing.T) {
		// given
		list := loadList(t, fixture)
		path := filepath.Join(t.TempDir(), "missing", "overlay.yaml")

		// when
		err := list.Save(path)

		// then
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "saving allowlist"), err.Error())
	})
}

func TestSharedHostingList(t *testing.T) {
	for _, suffix := range allowlist.SharedHosting() {
		t.Run(suffix, func(t *testing.T) {
			// given
			host := suffix

			// when
			got, err := allowlist.Normalize(host)

			// then
			require.NoError(t, err)
			require.Equal(t, suffix, got)
		})
	}
}

func TestRepoAllowlist(t *testing.T) {
	list, err := allowlist.Load("../../config/allowlist.yaml")
	require.NoError(t, err)
	tests := []struct {
		host string
		port int
		want bool
	}{
		{host: "api.anthropic.com", port: 443, want: true},
		{host: "github.com", port: 443, want: true},
		{host: "proxy.golang.org", port: 443, want: true},
		{host: "sum.golang.org", port: 443, want: true},
		{host: "registry.npmjs.org", port: 443, want: true},
		{host: "pypi.org", port: 443, want: true},
		{host: "files.pythonhosted.org", port: 443, want: true},
		{host: "index.crates.io", port: 443, want: true},
		{host: "static.crates.io", port: 443, want: true},
		{host: "archive.ubuntu.com", port: 80, want: true},
		{host: "security.ubuntu.com", port: 80, want: true},
		{host: "taylorantoniohardin.atlassian.net", port: 443, want: true},
		{host: "api.github.com", port: 443, want: true},
		{host: "codeload.github.com", port: 443, want: true},
		{host: "raw.githubusercontent.com", port: 443, want: true},
		{host: "vuln.go.dev", port: 443, want: true},
		{host: "crates.io", port: 443, want: true},
		{host: "github.com", port: 22, want: false},
		{host: "other.atlassian.net", port: 443, want: false},
	}
	for _, tt := range tests {
		t.Run(net.JoinHostPort(tt.host, strconv.Itoa(tt.port)), func(t *testing.T) {
			// given
			host, port := tt.host, tt.port

			// when
			got := list.Allows(host, port)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}
