package memory_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/memory"
)

const (
	syncSecret = "ghp_madeup1234567890"
	memoryPath = ".claude/projects/p/memory/MEMORY.md"
)

var errFakeRunner = errors.New("fake runner failure")

type runCall struct {
	verb  string
	args  []string
	stdin []byte
}

type fakeRunner struct {
	out   map[string][]byte
	err   map[string]error
	calls []runCall
}

func (r *fakeRunner) Run(_ context.Context, verb string, args []string, stdin io.Reader) ([]byte, error) {
	call := runCall{verb: verb, args: args}
	if stdin != nil {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}

		call.stdin = data
	}

	r.calls = append(r.calls, call)

	return r.out[verb], r.err[verb]
}

func fakeSqlite(t *testing.T) string {
	t.Helper()

	body := `[ "$#" -eq 4 ] || exit 9
[ -f "$3" ] || exit 8
printf 'INSERT INTO notes VALUES(%s);\n' "'token ` + syncSecret + `'"
`

	return writeScript(t, t.TempDir(), "sqlite3", body)
}

func fakeSyncGitleaks(t *testing.T, always bool) string {
	t.Helper()

	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	finding := `[{"RuleID": "github-pat", "File": "'"$9"'/claude-mem/claude-mem.sql", "Secret": "` + syncSecret + `"}]`

	body := `count=` + count + `
calls=$(cat "$count" 2>/dev/null || echo 0)
echo $((calls + 1)) > "$count"
if [ ! -f "$9/claude-mem/claude-mem.sql" ]; then
  echo '[]' > "$6"
elif [ "$calls" -eq 0 ] || [ "` + map[bool]string{true: "yes", false: "no"}[always] + `" = yes ]; then
  echo '` + finding + `' > "$6"
else
  echo '[]' > "$6"
fi
`

	return writeScript(t, dir, "gitleaks", body)
}

func exportTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()

	return buildTar(t, entries).Bytes()
}

var fullExport = []tarEntry{
	{name: memoryPath, body: "remember this"},
	{name: ".claude-mem/claude-mem.db", body: "binary db"},
}

func seedCurrent(t *testing.T, dir string) {
	t.Helper()

	path := filepath.Join(dir, "current", "projects", "old", "memory", "OLD.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
}

func requireModes(t *testing.T, dir string) {
	t.Helper()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)

		if path == dir {
			return nil
		}

		info, err := d.Info()
		require.NoError(t, err)

		want := os.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}

		require.Equal(t, want, info.Mode().Perm(), path)

		return nil
	})
	require.NoError(t, err)
}

func requireNoStaging(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".staging-"), e.Name())
		require.False(t, strings.HasPrefix(e.Name(), ".old-"), e.Name())
	}
}

func TestSync_Pull(t *testing.T) {
	now := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		export        []tarEntry
		exportErr     error
		existing      bool
		force         bool
		alwaysLeaks   bool
		want          memory.Result
		wantFiles     map[string]string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name:   "happy path - first pull",
			export: fullExport,
			want:   memory.Result{Time: now, Files: 2, Redactions: 1},
			wantFiles: map[string]string{
				"projects/p/memory/MEMORY.md": "remember this",
				"claude-mem/claude-mem.sql":   "INSERT INTO notes VALUES('token [REDACTED:github-pat]');\n",
			},
		},
		{
			name:     "happy path - replaces existing copy",
			export:   fullExport,
			existing: true,
			want:     memory.Result{Time: now, Files: 2, Redactions: 1},
			wantFiles: map[string]string{
				"projects/p/memory/MEMORY.md": "remember this",
				"claude-mem/claude-mem.sql":   "INSERT INTO notes VALUES('token [REDACTED:github-pat]');\n",
			},
		},
		{
			name:     "error - empty export",
			existing: true,
			wantErr:  memory.ErrEmptyExport,
		},
		{
			name:      "happy path - empty export forced",
			existing:  true,
			force:     true,
			want:      memory.Result{Time: now},
			wantFiles: map[string]string{},
		},
		{
			name:        "error - secrets remain",
			export:      fullExport,
			existing:    true,
			alwaysLeaks: true,
			wantErr:     memory.ErrSecretsRemain,
		},
		{
			name:     "error - unsafe entry",
			export:   []tarEntry{{name: memoryPath, typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
			existing: true,
			wantErr:  memory.ErrUnsafeEntry,
		},
		{
			name:          "error - export fails",
			exportErr:     errFakeRunner,
			existing:      true,
			wantErrPrefix: "exporting memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := filepath.Join(t.TempDir(), "memory")
			require.NoError(t, os.MkdirAll(dir, 0o700))

			if tt.existing {
				seedCurrent(t, dir)
			}

			runner := &fakeRunner{
				out: map[string][]byte{"memory-export": exportTar(t, tt.export...)},
				err: map[string]error{"memory-export": tt.exportErr},
			}
			sync := memory.NewSync(
				runner,
				dir,
				fakeSyncGitleaks(t, tt.alwaysLeaks),
				fakeSqlite(t),
				func() time.Time { return now },
			)

			// when
			got, err := sync.Pull(context.Background(), tt.force)

			// then
			requireNoStaging(t, dir)

			if tt.wantErr != nil || tt.wantErrPrefix != "" {
				require.Error(t, err)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}

				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				require.NotContains(t, err.Error(), syncSecret)
				want := map[string]string{"projects/old/memory/OLD.md": "old"}
				require.Equal(t, want, readTree(t, filepath.Join(dir, "current")))
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantFiles, readTree(t, filepath.Join(dir, "current")))

			data, err := os.ReadFile(filepath.Join(dir, "last-sync.json"))
			require.NoError(t, err)

			var last memory.Result
			require.NoError(t, json.Unmarshal(data, &last))
			require.Equal(t, tt.want, last)

			requireModes(t, dir)
		})
	}
}

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
		stale        bool
		wantErr      error
		wantReviewed map[string]string
	}{
		{
			name:         "happy path - digest matches",
			wantReviewed: map[string]string{"projects/p/memory/MEMORY.md": "new"},
		},
		{
			name:         "error - stale digest",
			stale:        true,
			wantErr:      memory.ErrStaleDigest,
			wantReviewed: map[string]string{"projects/p/memory/MEMORY.md": "reviewed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			for tree, body := range map[string]string{"current": "new", "reviewed": "reviewed"} {
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

func TestSync_Restore(t *testing.T) {
	tests := []struct {
		name          string
		reviewed      bool
		importErr     error
		wantBody      string
		wantErrPrefix string
	}{
		{
			name:     "happy path - current copy",
			wantBody: "current",
		},
		{
			name:     "happy path - reviewed copy",
			reviewed: true,
			wantBody: "reviewed",
		},
		{
			name:          "error - import fails",
			importErr:     errFakeRunner,
			wantErrPrefix: "importing memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			for _, tree := range []string{"current", "reviewed"} {
				for name, body := range map[string]string{
					"projects/p/memory/MEMORY.md": tree,
					"claude-mem/claude-mem.sql":   tree,
				} {
					path := filepath.Join(dir, tree, name)
					require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
					require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
				}
			}

			runner := &fakeRunner{err: map[string]error{"memory-import": tt.importErr}}
			sync := memory.NewSync(runner, dir, "gitleaks", "sqlite3", time.Now)

			// when
			err := sync.Restore(context.Background(), tt.reviewed)

			// then
			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				return
			}

			require.NoError(t, err)
			require.Len(t, runner.calls, 1)
			require.Equal(t, "memory-import", runner.calls[0].verb)
			require.Empty(t, runner.calls[0].args)

			got := map[string]string{}
			tr := tar.NewReader(bytes.NewReader(runner.calls[0].stdin))
			for {
				hdr, err := tr.Next()
				if errors.Is(err, io.EOF) {
					break
				}

				require.NoError(t, err)
				require.Equal(t, byte(tar.TypeReg), hdr.Typeflag)

				data, err := io.ReadAll(tr)
				require.NoError(t, err)

				got[hdr.Name] = string(data)
			}

			require.Equal(t, map[string]string{
				"projects/p/memory/MEMORY.md": tt.wantBody,
				"claude-mem/claude-mem.sql":   tt.wantBody,
			}, got)
		})
	}
}
