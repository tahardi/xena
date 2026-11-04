package inventory_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

var errFake = errors.New("fake failure")

type fakeCreate struct {
	summary     string
	description string
}

type fakeJira struct {
	summaries []string
	listErr   error
	createErr error
	creates   []fakeCreate
}

func (f *fakeJira) Summaries(context.Context) ([]string, error) {
	return f.summaries, f.listErr
}

func (f *fakeJira) Create(_ context.Context, summary, description string) error {
	f.creates = append(f.creates, fakeCreate{summary: summary, description: description})
	return f.createErr
}

func TestFileCards(t *testing.T) {
	inv := inventory.Inventory{Version: 1, Entries: []inventory.Token{
		{Name: "jira-bot-token", Service: "atlassian", Stored: "secrets:jira-bot-token", Rotate: "rotate jira"},
		{Name: "aws-grant", Service: "aws", Stored: "secrets:aws-grant", Rotate: "Run xena rotate aws-grant."},
		{Name: "gcp-grant", Service: "gcp", Stored: "secrets:gcp-grant", Rotate: "rotate gcp"},
	}}
	findings := []inventory.Finding{
		{Kind: inventory.KindNearExpiry, Token: "aws-grant", Detail: "due 2026-11-03"},
		// #nosec G101 -- jira-bot-token is an inventory entry name, not a credential.
		{Kind: inventory.KindOverdue, Token: "jira-bot-token", Detail: "due 2026-09-29"},
		{Kind: inventory.KindUncappedSpend, Token: "gcp-grant"},
		{Kind: inventory.KindUnlistedFound, Detail: "secrets:mystery"},
	}

	tests := []struct {
		name        string
		jira        *fakeJira
		want        []string
		wantCreates int
		wantErr     string
	}{
		{
			name:        "happy path - files only cards not open",
			jira:        &fakeJira{summaries: []string{"Rotate jira-bot-token"}},
			want:        []string{"Rotate aws-grant"},
			wantCreates: 1,
		},
		{
			name:    "error - list fails",
			jira:    &fakeJira{listErr: errFake},
			wantErr: "listing jira cards",
		},
		{
			name:        "error - create fails",
			jira:        &fakeJira{summaries: []string{"Rotate jira-bot-token"}, createErr: errFake},
			wantCreates: 1,
			wantErr:     "creating jira card Rotate aws-grant",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			ctx := context.Background()

			// when
			got, err := inventory.FileCards(ctx, tt.jira, inv, findings)

			// then
			require.Len(t, tt.jira.creates, tt.wantCreates)
			if tt.wantErr != "" {
				require.ErrorIs(t, err, errFake)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantErr), err.Error())
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, "Rotate aws-grant", tt.jira.creates[0].summary)
			assert.Equal(
				t,
				"Finding: near-expiry (due 2026-11-03)\n\nService: aws\nStored: secrets:aws-grant\n\n"+
					"Rotation steps:\nRun xena rotate aws-grant.\n",
				tt.jira.creates[0].description,
			)
		})
	}
}

const fakeJiraScript = `if [ "$1" = list ]; then
  echo 'XENA-12 Task (To Do) epic=XENA-3 Rotate jira-bot-token'
  echo 'XENA-13 Task (In Progress) epic=none Fix the proxy log'
  exit 0
fi
dir=$(dirname "$0")
printf '%s\n' "$@" > "$dir/args.txt"
cat > "$dir/stdin.txt"
echo XENA-14
`

func TestJiraScript(t *testing.T) {
	tests := []struct {
		name      string
		call      func(ctx context.Context, j inventory.JiraScript) ([]string, error)
		want      []string
		wantArgs  string
		wantStdin string
	}{
		{
			name: "happy path - summaries",
			call: func(ctx context.Context, j inventory.JiraScript) ([]string, error) {
				return j.Summaries(ctx)
			},
			want: []string{"Rotate jira-bot-token", "Fix the proxy log"},
		},
		{
			name: "happy path - create",
			call: func(ctx context.Context, j inventory.JiraScript) ([]string, error) {
				return nil, j.Create(ctx, "Rotate aws-grant", "steps")
			},
			wantArgs:  "create\nXENA\nRotate aws-grant\n--labels\nneeds-taylor\n",
			wantStdin: "steps",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			script := filepath.Join(dir, "jira.sh")
			require.NoError(t, os.WriteFile(script, []byte(fakeJiraScript), 0o600))
			j := inventory.JiraScript{Python: "sh", Script: script, Project: "XENA"}

			// when
			got, err := tt.call(context.Background(), j)

			// then
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			if tt.wantArgs == "" {
				return
			}
			args, err := os.ReadFile(filepath.Join(dir, "args.txt"))
			require.NoError(t, err)
			assert.Equal(t, tt.wantArgs, string(args))
			stdin, err := os.ReadFile(filepath.Join(dir, "stdin.txt"))
			require.NoError(t, err)
			assert.Equal(t, tt.wantStdin, string(stdin))
		})
	}
}
