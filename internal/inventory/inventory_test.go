package inventory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

const twoEntries = `version: 1
# keep me
entries:
  - name: a
    service: aws
    stored: secrets:a
    rotated: 2026-01-01
    rotate: rotate a
  - name: b
    service: gcp
    stored: secrets:b
    rotated: 2026-01-01
    rotate: rotate b
`

func writeInventory(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "inventory.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func day(t *testing.T, s string) time.Time {
	t.Helper()

	d, err := time.Parse(time.DateOnly, s)
	require.NoError(t, err)

	return d
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		check   func(t *testing.T, inv inventory.Inventory)
		wantErr error
		wantMsg string
	}{
		{
			name: "happy path - example file",
			path: "../../config/inventory.example.yaml",
			check: func(t *testing.T, inv inventory.Inventory) {
				t.Helper()
				require.NotEmpty(t, inv.Entries)
				for _, tok := range inv.Entries {
					assert.NotEmpty(t, tok.Name)
					assert.NotEmpty(t, tok.Service, tok.Name)
					assert.NotEmpty(t, tok.Stored, tok.Name)
				}
			},
		},
		{
			name: "happy path - rotation days default",
			content: `version: 1
entries:
  - name: a
    service: aws
    stored: secrets:a
    rotated: 2026-01-01
    rotate: rotate a
  - name: b
    service: yubikey
    stored: yubikey
    rotated: 2026-01-01
    rotation_days: 0
    rotate: rotate b
`,
			check: func(t *testing.T, inv inventory.Inventory) {
				t.Helper()
				require.Len(t, inv.Entries, 2)
				require.NotNil(t, inv.Entries[0].RotationDays)
				assert.Equal(t, inventory.DefaultRotationDays, *inv.Entries[0].RotationDays)
				require.NotNil(t, inv.Entries[1].RotationDays)
				assert.Equal(t, 0, *inv.Entries[1].RotationDays)
			},
		},
		{
			name: "error - duplicate name",
			content: `version: 1
entries:
  - {name: a, service: aws, stored: "secrets:a", rotated: 2026-01-01, rotate: x}
  - {name: a, service: aws, stored: "secrets:a", rotated: 2026-01-01, rotate: x}
`,
			wantErr: inventory.ErrDuplicateName,
		},
		{
			name: "error - missing field",
			content: `version: 1
entries:
  - {name: a, service: aws, rotated: 2026-01-01, rotate: x}
`,
			wantErr: inventory.ErrMissingField,
			wantMsg: "stored",
		},
		{
			name: "error - missing rotated",
			content: `version: 1
entries:
  - {name: a, service: aws, stored: "secrets:a", rotate: x}
`,
			wantErr: inventory.ErrMissingField,
			wantMsg: "rotated",
		},
		{
			name: "error - unknown field",
			content: `version: 1
entries:
  - {name: a, service: aws, stored: "secrets:a", rotated: 2026-01-01, rotate: x, secret: y}
`,
			wantMsg: "decoding",
		},
		{
			name: "error - bad name",
			content: `version: 1
entries:
  - {name: Bad Name, service: aws, stored: "secrets:a", rotated: 2026-01-01, rotate: x}
`,
			wantErr: inventory.ErrInvalidName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := tt.path
			if path == "" {
				path = writeInventory(t, tt.content)
			}

			// when
			inv, err := inventory.Load(path)

			// then
			if tt.wantErr != nil || tt.wantMsg != "" {
				require.Error(t, err)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}
				assert.Contains(t, err.Error(), tt.wantMsg)
				return
			}
			require.NoError(t, err)
			tt.check(t, inv)
		})
	}
}

func TestToken_Due(t *testing.T) {
	ninety := 90
	zero := 0

	tests := []struct {
		name    string
		token   inventory.Token
		want    string
		wantDue bool
	}{
		{
			name:    "happy path - rotation only",
			token:   inventory.Token{Rotated: day(t, "2026-10-01"), RotationDays: &ninety},
			want:    "2026-12-30",
			wantDue: true,
		},
		{
			name: "happy path - expiry before rotation",
			token: inventory.Token{
				Rotated:      day(t, "2026-10-01"),
				RotationDays: &ninety,
				Expires:      day(t, "2026-11-15"),
			},
			want:    "2026-11-15",
			wantDue: true,
		},
		{
			name:  "happy path - never due",
			token: inventory.Token{Rotated: day(t, "2026-10-01"), RotationDays: &zero},
		},
		{
			name: "happy path - no rotation with expiry",
			token: inventory.Token{
				Rotated:      day(t, "2026-10-01"),
				RotationDays: &zero,
				Expires:      day(t, "2026-11-15"),
			},
			want:    "2026-11-15",
			wantDue: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			tok := tt.token

			// when
			due, ok := tok.Due()

			// then
			require.Equal(t, tt.wantDue, ok)
			if ok {
				assert.Equal(t, tt.want, due.Format(time.DateOnly))
			}
		})
	}
}

func TestSetRotated(t *testing.T) {
	withExpiry := strings.Replace(twoEntries, "rotate: rotate b", "expires: 2026-04-01\n    rotate: rotate b", 1)
	noRotated := strings.Replace(twoEntries, "    rotated: 2026-01-01\n    rotate: rotate b", "    rotate: rotate b", 1)

	tests := []struct {
		name    string
		content string
		token   string
		wantErr error
	}{
		{name: "happy path - updates one token and keeps comments", content: twoEntries, token: "b"},
		{name: "happy path - drops the old expiry", content: withExpiry, token: "b"},
		{name: "happy path - adds missing rotated", content: noRotated, token: "b"},
		{name: "error - not listed", content: twoEntries, token: "c", wantErr: inventory.ErrNotListed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := writeInventory(t, tt.content)
			require.NoError(t, os.Chmod(path, 0o644))

			// when
			err := inventory.SetRotated(path, tt.token, day(t, "2026-10-24"))

			// then
			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, tt.content, string(data))
				return
			}
			require.NoError(t, err)
			assert.Contains(t, string(data), "# keep me")

			inv, err := inventory.Load(path)
			require.NoError(t, err)
			a, err := inv.Find("a")
			require.NoError(t, err)
			assert.Equal(t, "2026-01-01", a.Rotated.Format(time.DateOnly))
			b, err := inv.Find("b")
			require.NoError(t, err)
			assert.Equal(t, "2026-10-24", b.Rotated.Format(time.DateOnly))
			assert.True(t, b.Expires.IsZero())

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}
}
