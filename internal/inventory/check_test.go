package inventory_test

import (
	"cmp"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

func TestCheck(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	ninety := 90
	thirty := 30
	zero := 0

	token := func(mod func(*inventory.Token)) []inventory.Token {
		tok := inventory.Token{
			Name:         "a",
			Stored:       "secrets:a",
			Rotated:      day(t, "2026-10-01"),
			RotationDays: &ninety,
		}
		mod(&tok)
		return []inventory.Token{tok}
	}

	tests := []struct {
		name   string
		tokens []inventory.Token
		found  []string
		now    time.Time
		warn   int
		want   []inventory.Finding
	}{
		{
			name:   "happy path - due today is near expiry, not overdue",
			tokens: token(func(tok *inventory.Token) { tok.Expires = day(t, "2026-10-24") }),
			now:    day(t, "2026-10-24"),
			want:   []inventory.Finding{{Kind: inventory.KindNearExpiry, Token: "a", Detail: "due 2026-10-24"}},
		},
		{
			name: "happy path - overdue and uncapped",
			tokens: token(func(tok *inventory.Token) {
				tok.Rotated = day(t, "2026-07-01")
				tok.CanSpend = true
			}),
			want: []inventory.Finding{
				{Kind: inventory.KindOverdue, Token: "a", Detail: "due 2026-09-29"},
				{Kind: inventory.KindUncappedSpend, Token: "a"},
			},
		},
		{
			name:   "happy path - nothing due",
			tokens: token(func(*inventory.Token) {}),
		},
		{
			name: "happy path - near expiry in 10 days",
			tokens: token(func(tok *inventory.Token) {
				tok.Rotated = day(t, "2026-10-04")
				tok.RotationDays = &thirty
			}),
			want: []inventory.Finding{{Kind: inventory.KindNearExpiry, Token: "a", Detail: "due 2026-11-03"}},
		},
		{
			name:   "happy path - near expiry at exactly 14 days",
			tokens: token(func(tok *inventory.Token) { tok.Expires = now.AddDate(0, 0, 14) }),
			want:   []inventory.Finding{{Kind: inventory.KindNearExpiry, Token: "a", Detail: "due 2026-11-07"}},
		},
		{
			name:   "happy path - near expiry in 20 days with a 30-day window",
			tokens: token(func(tok *inventory.Token) { tok.Expires = now.AddDate(0, 0, 20) }),
			warn:   30,
			want:   []inventory.Finding{{Kind: inventory.KindNearExpiry, Token: "a", Detail: "due 2026-11-13"}},
		},
		{
			name:   "happy path - due in 15 days",
			tokens: token(func(tok *inventory.Token) { tok.Expires = now.AddDate(0, 0, 15) }),
		},
		{
			name:   "happy path - overdue rotation",
			tokens: token(func(tok *inventory.Token) { tok.Rotated = day(t, "2026-07-01") }),
			want:   []inventory.Finding{{Kind: inventory.KindOverdue, Token: "a", Detail: "due 2026-09-29"}},
		},
		{
			name:   "happy path - overdue expiry",
			tokens: token(func(tok *inventory.Token) { tok.Expires = day(t, "2026-10-20") }),
			want:   []inventory.Finding{{Kind: inventory.KindOverdue, Token: "a", Detail: "due 2026-10-20"}},
		},
		{
			name: "happy path - rotation 0 never due",
			tokens: token(func(tok *inventory.Token) {
				tok.Rotated = day(t, "2020-01-01")
				tok.RotationDays = &zero
			}),
		},
		{
			name:   "happy path - uncapped spend",
			tokens: token(func(tok *inventory.Token) { tok.CanSpend = true }),
			want:   []inventory.Finding{{Kind: inventory.KindUncappedSpend, Token: "a"}},
		},
		{
			name: "happy path - capped spend",
			tokens: token(func(tok *inventory.Token) {
				tok.CanSpend = true
				tok.SpendCap = "$20 budget"
			}),
		},
		{
			name:   "happy path - unlisted found",
			tokens: token(func(tok *inventory.Token) { tok.Stored = "secrets:aws-grant" }),
			found:  []string{"secrets:aws-grant", "secrets:mystery", "file:~/.aws/credentials"},
			want: []inventory.Finding{
				{Kind: inventory.KindUnlistedFound, Detail: "file:~/.aws/credentials"},
				{Kind: inventory.KindUnlistedFound, Detail: "secrets:mystery"},
			},
		},
		{
			name: "happy path - sorted by kind then token",
			tokens: []inventory.Token{
				{Name: "b", Stored: "yubikey", Rotated: day(t, "2026-07-01"), RotationDays: &ninety, CanSpend: true},
				{Name: "a", Stored: "yubikey", Rotated: day(t, "2026-07-01"), RotationDays: &ninety},
			},
			want: []inventory.Finding{
				{Kind: inventory.KindOverdue, Token: "a", Detail: "due 2026-09-29"},
				{Kind: inventory.KindOverdue, Token: "b", Detail: "due 2026-09-29"},
				{Kind: inventory.KindUncappedSpend, Token: "b"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			inv := inventory.Inventory{Version: 1, Settings: inventory.Settings{WarnDays: cmp.Or(tt.warn, 14)}, Entries: tt.tokens}
			at := now
			if !tt.now.IsZero() {
				at = tt.now
			}

			// when
			got := inventory.Check(inv, tt.found, at)

			// then
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFound(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		locked  string
		secrets []string
		want    []string
		wantErr string
	}{
		{
			name: "happy path - markers present",
			files: map[string]string{
				".config/gh/hosts.yml": "github.com:\n  oauth_token: made-up\n",
				".docker/config.json":  `{"auths":{"example.com":{"auth":"bWFkZS11cA=="}}}`,
				".pypirc":              "[pypi]\npassword = made-up\n",
			},
			want: []string{"file:~/.config/gh/hosts.yml", "file:~/.docker/config.json", "file:~/.pypirc"},
		},
		{
			name:    "error - unreadable file",
			files:   map[string]string{".netrc": "machine example.com"},
			locked:  ".netrc",
			wantErr: "checking ",
		},
		{
			name: "happy path - files and secrets",
			files: map[string]string{
				".aws/credentials":     "any",
				".config/gh/hosts.yml": "github.com:\n  user: someone\n",
				".npmrc":               "//registry.npmjs.org/:_authToken=npm_madeup\n",
				".config/jira/env":     "any",
			},
			secrets: []string{"b", "a"},
			want: []string{
				"file:~/.aws/credentials",
				"file:~/.config/jira/env",
				"file:~/.npmrc",
				"secrets:a",
				"secrets:b",
			},
		},
		{
			name: "happy path - empty home",
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			home := t.TempDir()
			for rel, content := range tt.files {
				path := filepath.Join(home, rel)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			}

			if tt.locked != "" {
				require.NoError(t, os.Chmod(filepath.Join(home, tt.locked), 0o000))
			}

			// when
			got, err := inventory.Found(tt.secrets, home)

			// then
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.NotContains(t, err.Error(), "example.com")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
