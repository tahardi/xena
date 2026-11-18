package memory_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/memory"
)

func TestTreeDigest(t *testing.T) {
	write := func(t *testing.T, files map[string]string) string {
		t.Helper()

		dir := t.TempDir()
		for name, body := range files {
			path := filepath.Join(dir, name)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		}

		return dir
	}

	base := map[string]string{"projects/p/memory/a.md": "alpha", "claude-mem/claude-mem.sql": "beta"}

	tests := []struct {
		name      string
		other     map[string]string
		wantEqual bool
	}{
		{
			name:      "happy path - same tree",
			other:     base,
			wantEqual: true,
		},
		{
			name:  "happy path - one byte changed",
			other: map[string]string{"projects/p/memory/a.md": "alphb", "claude-mem/claude-mem.sql": "beta"},
		},
		{
			name:  "happy path - file renamed",
			other: map[string]string{"projects/p/memory/b.md": "alpha", "claude-mem/claude-mem.sql": "beta"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			first := write(t, base)
			second := write(t, tt.other)

			// when
			a, errA := memory.TreeDigest(first)
			b, errB := memory.TreeDigest(second)

			// then
			require.NoError(t, errA)
			require.NoError(t, errB)
			require.Len(t, a, 64)
			require.Equal(t, tt.wantEqual, a == b)
		})
	}
}

func TestMarkReviewed(t *testing.T) {
	now := time.Date(2026, 11, 17, 9, 30, 0, 0, time.UTC)

	tests := []struct {
		name         string
		reviewed     bool
		stale        bool
		wantErr      error
		wantReviewed map[string]string
	}{
		{
			name:         "happy path - digest matches",
			reviewed:     true,
			wantReviewed: map[string]string{"projects/p/memory/MEMORY.md": "new"},
		},
		{
			name:         "happy path - first review",
			wantReviewed: map[string]string{"projects/p/memory/MEMORY.md": "new"},
		},
		{
			name:         "error - stale digest",
			reviewed:     true,
			stale:        true,
			wantErr:      memory.ErrStaleDigest,
			wantReviewed: map[string]string{"projects/p/memory/MEMORY.md": "reviewed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			trees := map[string]string{"current": "new"}
			if tt.reviewed {
				trees["reviewed"] = "reviewed"
			}

			for tree, body := range trees {
				path := filepath.Join(dir, tree, "projects", "p", "memory", "MEMORY.md")
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
			}

			digest, err := memory.TreeDigest(filepath.Join(dir, "current"))
			require.NoError(t, err)

			if tt.stale {
				path := filepath.Join(dir, "current", "projects", "p", "memory", "MEMORY.md")
				require.NoError(t, os.WriteFile(path, []byte("changed after diff"), 0o600))
			}

			// when
			err = memory.MarkReviewed(dir, digest, now)

			// then
			require.Equal(t, tt.wantReviewed, readTree(t, filepath.Join(dir, "reviewed")))

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			at, err := os.ReadFile(filepath.Join(dir, "reviewed-at"))
			require.NoError(t, err)
			require.Equal(t, "2026-11-17T09:30:00Z", string(at))

			requireModes(t, dir)
			requireNoStaging(t, dir)
		})
	}
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name          string
		reviewed      bool
		exit          string
		want          string
		wantChanged   bool
		wantErrPrefix string
	}{
		{
			name:        "happy path - no reviewed copy yet",
			exit:        "1",
			want:        "diff output\n",
			wantChanged: true,
		},
		{
			name:     "happy path - equal trees",
			reviewed: true,
			exit:     "0",
			want:     "",
		},
		{
			name:          "error - diff fails",
			reviewed:      true,
			exit:          "2",
			wantErrPrefix: "diffing memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "current"), 0o700))

			if tt.reviewed {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "reviewed"), 0o700))
			}

			body := `[ "$*" = "-ruN reviewed current" ] || exit 9
[ -d reviewed ] && [ -d current ] || exit 8
[ "` + tt.exit + `" = 0 ] || echo "diff output"
exit ` + tt.exit + "\n"
			diffBin := writeScript(t, t.TempDir(), "diff", body)

			// when
			out, changed, err := memory.Diff(context.Background(), diffBin, dir)

			// then
			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, string(out))
			require.Equal(t, tt.wantChanged, changed)
		})
	}
}
