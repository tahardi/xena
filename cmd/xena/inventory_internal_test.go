package main

import (
	"bytes"
	"cmp"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const overdueInventory = `version: 1
entries:
  - name: a
    service: aws
    stored: secrets:a
    rotated: 2026-07-01
    rotation_days: 90
    can_spend: false
    rotate: Rotate a by hand.
`

func TestRunInventory(t *testing.T) {
	tests := []struct {
		name      string
		inventory string
		secrets   []string
		script    string
		scriptAt  string
		args      []string
		want      string
		wantErr   string
	}{
		{
			name:      "happy path - prints findings",
			inventory: overdueInventory,
			args:      []string{"check"},
			want:      "overdue a due 2026-09-29\n",
		},
		{
			name:      "happy path - unlisted secret prints dash for token",
			inventory: overdueInventory,
			secrets:   []string{"a", "mystery"},
			args:      []string{"check"},
			want:      "overdue a due 2026-09-29\nunlisted-found - secrets:mystery\n",
		},
		{
			name:      "happy path - files cards",
			inventory: overdueInventory,
			args:      []string{"check", "--file-cards"},
			script:    "import sys\nif sys.argv[1] != 'list':\n    print('XENA-99')\n",
			want:      "overdue a due 2026-09-29\nfiled Rotate a\n",
		},
		{
			name: "happy path - files cards with configured script and project",
			inventory: strings.Replace(
				overdueInventory,
				"entries:",
				"settings:\n  jira_script: ~/bin/jira.py\n  jira_project: ABC\nentries:",
				1,
			),
			args:     []string{"check", "--file-cards"},
			script:   "import sys\nif sys.argv[2] != 'ABC':\n    sys.exit(1)\n",
			scriptAt: "bin/jira.py",
			want:     "overdue a due 2026-09-29\nfiled Rotate a\n",
		},
		{
			name:      "error - unknown flag",
			inventory: overdueInventory,
			args:      []string{"check", "--bogus"},
			wantErr:   "usage: xena inventory check",
		},
		{
			name:    "error - missing inventory",
			args:    []string{"check"},
			wantErr: "loading inventory",
		},
		{
			name:      "error - unknown subcommand",
			inventory: overdueInventory,
			args:      []string{"show"},
			wantErr:   "usage: xena inventory check",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			store := newSecretsStore(t)
			for _, name := range tt.secrets {
				require.NoError(t, store.Put(name, strings.NewReader("made-up-value")))
			}
			if tt.inventory != "" {
				require.NoError(t, os.WriteFile(inventoryPath(), []byte(tt.inventory), 0o600))
			}
			home := t.TempDir()
			if tt.script != "" {
				script := filepath.Join(home, cmp.Or(tt.scriptAt, ".claude/skills/card/scripts/jira.py"))
				require.NoError(t, os.MkdirAll(filepath.Dir(script), 0o700))
				require.NoError(t, os.WriteFile(script, []byte(tt.script), 0o600))
			}
			var out bytes.Buffer

			// when
			err := runInventory(context.Background(), tt.args, home, &out)

			// then
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantErr), err.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, out.String())
		})
	}
}
