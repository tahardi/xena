package agent

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type member struct {
	name     string
	typeflag byte
	body     string
	linkname string
}

func buildTar(t *testing.T, members ...member) string {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, m := range members {
		h := &tar.Header{Name: m.name, Typeflag: m.typeflag, Mode: 0o644, Linkname: m.linkname}
		if m.typeflag == tar.TypeReg {
			h.Size = int64(len(m.body))
		}

		require.NoError(t, tw.WriteHeader(h))
		_, err := tw.Write([]byte(m.body))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())

	return buf.String()
}

func TestAgent_importMemory(t *testing.T) {
	validTar := []member{
		{name: "projects/", typeflag: tar.TypeDir},
		{name: "projects/p1/", typeflag: tar.TypeDir},
		{name: "projects/p1/memory/", typeflag: tar.TypeDir},
		{name: "projects/p1/memory/m.md", typeflag: tar.TypeReg, body: "memory"},
		{name: "claude-mem/claude-mem.sql", typeflag: tar.TypeReg, body: "CREATE TABLE t(x);\n"},
	}

	tests := []struct {
		name      string
		members   []member
		setup     func(t *testing.T, h harness)
		wantFiles []string
		wantErr   error
		wantFail  bool
		absent    []string
	}{
		{
			name:      "happy path - memory and database",
			members:   validTar,
			wantFiles: []string{".claude/projects/p1/memory/m.md", ".claude-mem/claude-mem.db"},
		},
		{
			name:      "happy path - memory without database",
			members:   validTar[:4],
			wantFiles: []string{".claude/projects/p1/memory/m.md"},
			absent:    []string{".claude-mem/claude-mem.db"},
		},
		{
			name:      "happy path - empty memory dir does not block",
			members:   validTar,
			wantFiles: []string{".claude/projects/p1/memory/m.md"},
			setup: func(t *testing.T, h harness) {
				t.Helper()
				require.NoError(t, os.MkdirAll(filepath.Join(h.agent.home, ".claude", "projects", "p1", "memory"), 0o700))
			},
		},
		{
			name:    "error - database exists",
			members: validTar,
			wantErr: ErrMemoryExists,
			setup: func(t *testing.T, h harness) {
				t.Helper()
				writeFile(t, filepath.Join(h.agent.home, ".claude-mem", "claude-mem.db"), "")
			},
		},
		{
			name:    "error - memory file exists",
			members: validTar,
			wantErr: ErrMemoryExists,
			absent:  []string{".claude-mem/claude-mem.db"},
			setup: func(t *testing.T, h harness) {
				t.Helper()
				writeFile(t, filepath.Join(h.agent.home, ".claude", "projects", "p2", "memory", "m.md"), "")
			},
		},
		{
			name:    "error - parent traversal",
			members: []member{{name: "../outside", typeflag: tar.TypeReg, body: "x"}},
			wantErr: ErrUnsafeArchive,
		},
		{
			name:    "error - absolute path",
			members: []member{{name: "/outside", typeflag: tar.TypeReg, body: "x"}},
			wantErr: ErrUnsafeArchive,
		},
		{
			name: "error - symlink member",
			members: []member{
				{name: "projects/p1/memory/MEMORY.md", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
			},
			wantErr: ErrUnsafeArchive,
			absent:  []string{".claude/projects/p1/memory/MEMORY.md"},
		},
		{
			name: "error - hardlink member",
			members: []member{
				{name: "projects/p1/memory/m.md", typeflag: tar.TypeReg, body: "memory"},
				{name: "projects/p1/memory/h.md", typeflag: tar.TypeLink, linkname: "projects/p1/memory/m.md"},
			},
			wantErr: ErrUnsafeArchive,
			absent:  []string{".claude/projects/p1/memory/m.md"},
		},
		{
			name: "error - sql dot-command does not run",
			members: []member{
				{name: "claude-mem/claude-mem.sql", typeflag: tar.TypeReg, body: ".shell touch PWNED\n"},
			},
			wantFail:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t, buildTar(t, tt.members...))
			if tt.setup != nil {
				tt.setup(t, h)
			}

			// when
			err := h.agent.importMemory(t.Context())

			// then
			switch {
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr)
			case tt.wantFail:
				require.Error(t, err)
			default:
				require.NoError(t, err)
			}

			for _, name := range tt.wantFiles {
				require.FileExists(t, filepath.Join(h.agent.home, name))
			}

			for _, name := range tt.absent {
				require.NoFileExists(t, filepath.Join(h.agent.home, name))
			}

			outside, err := filepath.Glob(filepath.Join(h.tmp, "outside"))
			require.NoError(t, err)
			require.Empty(t, outside)

			pwned, err := filepath.Glob(filepath.Join(h.tmp, "*", "*", "PWNED"))
			require.NoError(t, err)
			require.Empty(t, pwned)
			require.NoFileExists(t, filepath.Join(h.agent.home, "PWNED"))

			leftover, err := filepath.Glob(filepath.Join(h.agent.home, ".xena-import-*"))
			require.NoError(t, err)
			require.Empty(t, leftover)
		})
	}
}
