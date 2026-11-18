package memory_test

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/memory"
)

const tarHeaderSize = 512

type tarEntry struct {
	name     string
	typeflag byte
	body     string
	linkname string
}

func buildTar(t *testing.T, entries []tarEntry) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}

		hdr := &tar.Header{Name: e.name, Typeflag: typeflag, Mode: 0o644, Linkname: e.linkname}
		if typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		require.NoError(t, tw.WriteHeader(hdr))

		_, err := tw.Write([]byte(e.body))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())

	return &buf
}

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()

	got := map[string]string{}
	tree := os.DirFS(dir)
	err := fs.WalkDir(tree, ".", func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)

		if d.IsDir() {
			return nil
		}

		data, err := fs.ReadFile(tree, path)
		require.NoError(t, err)

		got[path] = string(data)

		return nil
	})
	require.NoError(t, err)

	return got
}

func TestExtract(t *testing.T) {
	memoryFile := ".claude/projects/-home-dev-Documents-code/memory/MEMORY.md"
	keptFile := "projects/-home-dev-Documents-code/memory/MEMORY.md"

	tests := []struct {
		name      string
		entries   []tarEntry
		lim       memory.Limits
		truncate  bool
		wantN     int
		wantFiles map[string]string
		wantErr   error
	}{
		{
			name: "happy path - memory and db",
			entries: []tarEntry{
				{name: ".claude/projects/-home-dev-Documents-code/memory/", typeflag: tar.TypeDir},
				{name: memoryFile, body: "notes"},
				{name: ".claude-mem/claude-mem.db", body: "db"},
			},
			lim:       memory.DefaultLimits,
			wantN:     2,
			wantFiles: map[string]string{keptFile: "notes", "db/claude-mem.db": "db"},
		},
		{
			name: "happy path - wal and shm",
			entries: []tarEntry{
				{name: ".claude-mem/claude-mem.db-wal", body: "wal"},
				{name: ".claude-mem/claude-mem.db-shm", body: "shm"},
			},
			lim:       memory.DefaultLimits,
			wantN:     2,
			wantFiles: map[string]string{"db/claude-mem.db-wal": "wal", "db/claude-mem.db-shm": "shm"},
		},
		{
			name: "happy path - skips others",
			entries: []tarEntry{
				{name: ".claude-mem/chroma/x.bin", body: "vec"},
				{name: ".claude-mem/settings.json", body: "{}"},
				{name: ".claude/projects/p/transcript.jsonl", body: "chat"},
			},
			lim:       memory.DefaultLimits,
			wantN:     0,
			wantFiles: map[string]string{},
		},
		{
			name:      "happy path - nested memory file",
			entries:   []tarEntry{{name: ".claude/projects/p/memory/sub/b.md", body: "deep"}},
			lim:       memory.DefaultLimits,
			wantN:     1,
			wantFiles: map[string]string{"projects/p/memory/sub/b.md": "deep"},
		},
		{
			name:     "error - truncated body",
			entries:  []tarEntry{{name: ".claude/projects/p/memory/a.md", body: "12345678"}},
			lim:      memory.DefaultLimits,
			truncate: true,
			wantErr:  io.ErrUnexpectedEOF,
		},
		{
			name:      "happy path - leading ./",
			entries:   []tarEntry{{name: "./" + memoryFile, body: "notes"}},
			lim:       memory.DefaultLimits,
			wantN:     1,
			wantFiles: map[string]string{keptFile: "notes"},
		},
		{
			name: "happy path - symlink outside kept paths",
			entries: []tarEntry{
				{name: ".claude-mem/chroma/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
			},
			lim:       memory.DefaultLimits,
			wantN:     0,
			wantFiles: map[string]string{},
		},
		{
			name: "error - symlink in kept path",
			entries: []tarEntry{
				{name: ".claude/projects/p/memory/a.md", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
			},
			lim:     memory.DefaultLimits,
			wantErr: memory.ErrUnsafeEntry,
		},
		{
			name: "error - hard link",
			entries: []tarEntry{
				{name: ".claude/projects/p/memory/a.md", typeflag: tar.TypeLink, linkname: "/etc/passwd"},
			},
			lim:     memory.DefaultLimits,
			wantErr: memory.ErrUnsafeEntry,
		},
		{
			name:    "error - fifo",
			entries: []tarEntry{{name: ".claude-mem/claude-mem.db", typeflag: tar.TypeFifo}},
			lim:     memory.DefaultLimits,
			wantErr: memory.ErrUnsafeEntry,
		},
		{
			name:    "error - absolute",
			entries: []tarEntry{{name: "/home/dev/.claude/projects/p/memory/a.md", body: "x"}},
			lim:     memory.DefaultLimits,
			wantErr: memory.ErrUnsafeEntry,
		},
		{
			name:    "error - dotdot",
			entries: []tarEntry{{name: ".claude/projects/p/memory/../../../x", body: "x"}},
			lim:     memory.DefaultLimits,
			wantErr: memory.ErrUnsafeEntry,
		},
		{
			name:    "error - file too large",
			entries: []tarEntry{{name: ".claude/projects/p/memory/a.md", body: "12345"}},
			lim:     memory.Limits{MaxFile: 4, MaxTotal: 100, MaxFiles: 10},
			wantErr: memory.ErrTooLarge,
		},
		{
			name: "error - total too large",
			entries: []tarEntry{
				{name: ".claude/projects/p/memory/a.md", body: "1234"},
				{name: ".claude/projects/p/memory/b.md", body: "1234"},
			},
			lim:     memory.Limits{MaxFile: 4, MaxTotal: 6, MaxFiles: 10},
			wantErr: memory.ErrTooLarge,
		},
		{
			name: "error - too many files",
			entries: []tarEntry{
				{name: ".claude/projects/p/memory/a.md", body: "1"},
				{name: ".claude/projects/p/memory/b.md", body: "2"},
			},
			lim:     memory.Limits{MaxFile: 4, MaxTotal: 100, MaxFiles: 1},
			wantErr: memory.ErrTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dst := t.TempDir()
			archive := buildTar(t, tt.entries)
			if tt.truncate {
				archive.Truncate(tarHeaderSize + 3)
			}

			// when
			n, err := memory.Extract(archive, dst, tt.lim)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantN, n)
			require.Equal(t, tt.wantFiles, readTree(t, dst))
		})
	}
}
