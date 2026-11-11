package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGrantArgs(t *testing.T) {
	until := time.Date(2026, 10, 24, 16, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		args    []string
		want    grantArgs
		wantErr error
		anyErr  bool
	}{
		{name: "happy path - aws", args: []string{"aws"}, want: grantArgs{provider: "aws"}},
		{
			name: "happy path - gcp with hours",
			args: []string{"gcp", "--hours", "3"},
			want: grantArgs{provider: "gcp", hours: 3},
		},
		{name: "happy path - clear", args: []string{"clear", "aws"}, want: grantArgs{provider: "aws", clear: true}},
		{
			name: "happy path - refresh",
			args: []string{"refresh", "gcp", "--until", "2026-10-24T16:00:00Z"},
			want: grantArgs{provider: "gcp", refresh: true, until: until},
		},
		{name: "error - refresh without until", args: []string{"refresh", "gcp"}, wantErr: errGrantUsage},
		{name: "error - refresh with bad until", args: []string{"refresh", "gcp", "--until", "soon"}, anyErr: true},
		{name: "error - unknown provider", args: []string{"bogus"}, wantErr: errUnknownProvider},
		{name: "error - no arguments", args: []string{}, wantErr: errGrantUsage},
		{name: "error - clear without provider", args: []string{"clear"}, wantErr: errGrantUsage},
		{name: "error - extra argument", args: []string{"aws", "extra"}, wantErr: errGrantUsage},
		{name: "error - bad hours", args: []string{"aws", "--hours", "x"}, anyErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			args := tt.args

			// when
			got, err := parseGrantArgs(args)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			if tt.anyErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
