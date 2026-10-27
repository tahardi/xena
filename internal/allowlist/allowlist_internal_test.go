package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		want    Rule
		wantErr error
	}{
		{
			name: "happy path - default port",
			rule: Rule{Host: "Example.COM."},
			want: Rule{Host: "example.com", Ports: []int{443}},
		},
		{
			name: "happy path - explicit ports kept",
			rule: Rule{Host: "example.com", Ports: []int{80, 8443}},
			want: Rule{Host: "example.com", Ports: []int{80, 8443}},
		},
		{
			name: "happy path - wildcard",
			rule: Rule{Host: "*.Example.org"},
			want: Rule{Host: "*.example.org", Ports: []int{443}},
		},
		{
			name:    "error - invalid host",
			rule:    Rule{Host: "a_b.example.com"},
			wantErr: ErrInvalidHost,
		},
		{
			name:    "error - one bad port among good ones",
			rule:    Rule{Host: "example.com", Ports: []int{443, 0}},
			wantErr: ErrInvalidPort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			rule := tt.rule

			// when
			err := validateRule(&rule)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr != nil {
				return
			}

			require.Equal(t, tt.want, rule)
		})
	}
}

func TestNormalizeRuleHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr error
	}{
		{name: "happy path - exact host", host: "Example.COM", want: "example.com"},
		{name: "happy path - wildcard", host: "*.Example.ORG.", want: "*.example.org"},
		{name: "happy path - exact shared host", host: "docs.github.io", want: "docs.github.io"},
		{name: "error - star in exact host", host: "a*.example.com", wantErr: ErrInvalidHost},
		{name: "error - second star", host: "*.*.example.com", wantErr: ErrInvalidHost},
		{name: "error - empty wildcard domain", host: "*.", wantErr: ErrInvalidHost},
		{name: "error - single label wildcard", host: "*.com", wantErr: ErrBroadWildcard},
		{name: "error - shared hosting wildcard", host: "*.vercel.app", wantErr: ErrSharedHostingWildcard},
		{name: "error - wildcard on IP literal", host: "*.192.0.2.10", wantErr: ErrIPLiteralHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			host := tt.host

			// when
			got, err := normalizeRuleHost(host)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestValidLabel(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  bool
	}{
		{name: "letters", label: "example", want: true},
		{name: "digits", label: "123", want: true},
		{name: "inner hyphen", label: "a-b", want: true},
		{name: "punycode", label: "xn--bcher-kva", want: true},
		{name: "single character", label: "a", want: true},
		{name: "63 characters", label: strings.Repeat("a", 63), want: true},
		{name: "64 characters", label: strings.Repeat("a", 64), want: false},
		{name: "empty", label: "", want: false},
		{name: "leading hyphen", label: "-a", want: false},
		{name: "trailing hyphen", label: "a-", want: false},
		{name: "lone hyphen", label: "-", want: false},
		{name: "uppercase", label: "A", want: false},
		{name: "underscore", label: "a_b", want: false},
		{name: "star", label: "*", want: false},
		{name: "dot", label: "a.b", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			label := tt.label

			// when
			got := validLabel(label)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}

func TestValidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
		want bool
	}{
		{name: "lowest", port: 1, want: true},
		{name: "https", port: 443, want: true},
		{name: "highest", port: 65535, want: true},
		{name: "zero", port: 0, want: false},
		{name: "negative", port: -1, want: false},
		{name: "above highest", port: 65536, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			port := tt.port

			// when
			got := validPort(port)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWriteSynced(t *testing.T) {
	t.Run("happy path - writes, sets mode, and closes", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "out.yaml")
		f, err := os.Create(path)
		require.NoError(t, err)

		// when
		err = writeSynced(f, []byte("version: 1\n"))

		// then
		require.NoError(t, err)
		require.ErrorIs(t, f.Close(), os.ErrClosed)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "version: 1\n", string(data))

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(fileMode), info.Mode().Perm())
	})

	t.Run("error - file already closed", func(t *testing.T) {
		// given
		f, err := os.Create(filepath.Join(t.TempDir(), "out.yaml"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		// when
		err = writeSynced(f, []byte("version: 1\n"))

		// then
		require.ErrorIs(t, err, os.ErrClosed)
		require.True(t, strings.HasPrefix(err.Error(), "writing"), err.Error())
	})
}
