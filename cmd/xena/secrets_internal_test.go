package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/secrets"
)

func TestRunSecrets(t *testing.T) {
	type call struct {
		args  []string
		stdin string
	}

	tests := []struct {
		name    string
		setup   []call
		args    []string
		want    string
		wantErr error
	}{
		{
			name:  "happy path - put then list",
			setup: []call{{args: []string{"put", "jira-bot-token"}, stdin: "made-up-value"}},
			args:  []string{"list"},
			want:  "jira-bot-token\n",
		},
		{
			name:  "happy path - verify",
			setup: []call{{args: []string{"put", "jira-bot-token"}, stdin: "made-up-value"}},
			args:  []string{"verify", "jira-bot-token"},
			want:  "ok jira-bot-token\n",
		},
		{
			name: "happy path - delete",
			setup: []call{
				{args: []string{"put", "jira-bot-token"}, stdin: "made-up-value"},
				{args: []string{"delete", "jira-bot-token"}},
			},
			args: []string{"list"},
			want: "",
		},
		{name: "error - no subcommand", args: nil, wantErr: errUsage},
		{name: "error - put without name", args: []string{"put"}, wantErr: errUsage},
		{name: "error - put with extra argument", args: []string{"put", "a", "b"}, wantErr: errUsage},
		{name: "error - list with extra argument", args: []string{"list", "a"}, wantErr: errUsage},
		{name: "error - put invalid name", args: []string{"put", "Upper"}, wantErr: secrets.ErrInvalidName},
		{name: "error - delete missing secret", args: []string{"delete", "x"}, wantErr: secrets.ErrNotFound},
		{name: "error - unknown subcommand", args: []string{"show", "x"}, wantErr: errUnknownCommand},
		{name: "error - verify missing secret", args: []string{"verify", "x"}, wantErr: secrets.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			ctx := context.Background()
			store := newSecretsStore(t)

			for _, c := range tt.setup {
				require.NoError(t, runSecrets(ctx, store, c.args, strings.NewReader(c.stdin), &bytes.Buffer{}))
			}

			var out bytes.Buffer

			// when
			err := runSecrets(ctx, store, tt.args, strings.NewReader(""), &out)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, out.String())
			assert.NotContains(t, out.String(), "made-up-value")
		})
	}
}

func newSecretsStore(t *testing.T) secrets.Store {
	t.Helper()

	configDir := t.TempDir()
	t.Setenv("XENA_SECRETS_DIR", t.TempDir())
	t.Setenv("XENA_CONFIG_DIR", configDir)

	identity := filepath.Join(configDir, "age-identities.txt")
	require.NoError(t, exec.CommandContext(t.Context(), "age-keygen", "-o", identity).Run())

	out, err := exec.CommandContext(t.Context(), "age-keygen", "-y", identity).Output()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "age-recipients.txt"), out, 0o600))

	store, err := secrets.NewDefaultStore()
	require.NoError(t, err)

	return store
}
