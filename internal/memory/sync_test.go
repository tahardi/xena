package memory_test

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
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

func fakeSqlite(t *testing.T, fail bool) string {
	t.Helper()

	body := `[ "$#" -eq 4 ] || exit 9
[ "$1 $2 $4" = "-readonly -safe .dump" ] || exit 9
[ -f "$3" ] || exit 8
[ "` + strconv.FormatBool(fail) + `" = false ] || exit 1
printf 'INSERT INTO notes VALUES(%s);\n' "'token ` + syncSecret + `'"
`

	return writeScript(t, t.TempDir(), "sqlite3", body)
}

func fakeSyncGitleaks(t *testing.T, mode string) string {
	t.Helper()

	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	finding := `[{"RuleID": "github-pat", "File": "'"$file"'", "Secret": "` + syncSecret + `"}]`

	body := `count=` + count + `
mode=` + mode + `
calls=$(cat "$count" 2>/dev/null || echo 0)
echo $((calls + 1)) > "$count"
file="$9/claude-mem/claude-mem.sql"
[ "$mode" != fail ] || exit 1
[ "$mode" != outside ] || file="$9/../outside.sql"
if [ ! -f "$9/claude-mem/claude-mem.sql" ]; then
  echo '[]' > "$6"
elif [ "$calls" -eq 0 ] || [ "$mode" = always ]; then
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
		gitleaksMode  string
		sqliteFails   bool
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
			name:         "error - secrets remain",
			export:       fullExport,
			existing:     true,
			gitleaksMode: "always",
			wantErr:      memory.ErrSecretsRemain,
		},
		{
			name:          "error - dump fails",
			export:        fullExport,
			existing:      true,
			sqliteFails:   true,
			wantErrPrefix: "dumping claude-mem",
		},
		{
			name:          "error - scan fails",
			export:        fullExport,
			existing:      true,
			gitleaksMode:  "fail",
			wantErrPrefix: "scanning memory",
		},
		{
			name:          "error - finding outside staging dir",
			export:        fullExport,
			existing:      true,
			gitleaksMode:  "outside",
			wantErrPrefix: "redacting memory",
		},
		{
			name:      "happy path - memory files only",
			export:    []tarEntry{{name: memoryPath, body: "remember this"}},
			want:      memory.Result{Time: now, Files: 1},
			wantFiles: map[string]string{"projects/p/memory/MEMORY.md": "remember this"},
		},
		{
			name:      "happy path - empty export with no copy yet",
			want:      memory.Result{Time: now},
			wantFiles: map[string]string{},
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
				fakeSyncGitleaks(t, cmp.Or(tt.gitleaksMode, "once")),
				fakeSqlite(t, tt.sqliteFails),
				func() time.Time { return now },
				slog.New(slog.DiscardHandler),
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
			sync := memory.NewSync(runner, dir, "gitleaks", "sqlite3", time.Now, slog.New(slog.DiscardHandler))

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
