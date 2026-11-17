package vault_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/vault"
)

func TestWithSource(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "no frontmatter", in: "body", want: "---\nsource: xena-vm\n---\nbody"},
		{name: "empty", in: "", want: "---\nsource: xena-vm\n---\n"},
		{name: "adds source", in: "---\ntitle: x\n---\nbody", want: "---\ntitle: x\nsource: xena-vm\n---\nbody"},
		{
			name: "replaces source",
			in:   "---\ntitle: x\nsource: desktop\n---\nbody",
			want: "---\ntitle: x\nsource: xena-vm\n---\nbody",
		},
		{name: "keeps one source", in: "---\nsource: a\nsource: b\n---\n", want: "---\nsource: xena-vm\n---\n"},
		{
			name: "no closing line",
			in:   "---\ntitle: x\nbody without closing",
			want: "---\nsource: xena-vm\n---\n---\ntitle: x\nbody without closing",
		},
		{
			name: "crlf line endings",
			in:   "---\r\ntitle: x\r\nsource: desktop\r\n---\r\nbody",
			want: "---\r\ntitle: x\r\nsource: xena-vm\r\n---\r\nbody",
		},
		{name: "double-quoted key", in: "---\n\"source\": desktop\n---\nb", want: "---\nsource: xena-vm\n---\nb"},
		{name: "single-quoted key", in: "---\n'source': desktop\n---\nb", want: "---\nsource: xena-vm\n---\nb"},
		{name: "space before colon", in: "---\nsource : desktop\n---\nb", want: "---\nsource: xena-vm\n---\nb"},
		{name: "other key kept", in: "---\nsources: a\n---\nb", want: "---\nsources: a\nsource: xena-vm\n---\nb"},
		{name: "indented source", in: "---\n  source: a\n---\nbody", want: "---\nsource: xena-vm\n---\nbody"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got := vault.WithSource(tt.in)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}
