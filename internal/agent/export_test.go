package agent

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func listMembers(t *testing.T, r io.Reader) map[string]byte {
	t.Helper()

	members := map[string]byte{}
	tr := tar.NewReader(r)

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return members
		}

		require.NoError(t, err)
		members[h.Name] = h.Typeflag
	}
}

func TestAgent_exportMemory(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, home string)
		wantMembers []string
		notMembers  []string
	}{
		{
			name: "happy path - memory and claude-mem",
			setup: func(t *testing.T, home string) {
				t.Helper()
				writeFile(t, filepath.Join(home, ".claude", "projects", "p1", "memory", "m.md"), "memory")
				writeFile(t, filepath.Join(home, ".claude-mem", "db"), "db")
			},
			wantMembers: []string{".claude/projects/p1/memory/m.md", ".claude-mem/db"},
		},
		{
			name:  "happy path - nothing to export",
			setup: func(*testing.T, string) {},
		},
		{
			name: "happy path - skips other home files",
			setup: func(t *testing.T, home string) {
				t.Helper()
				writeFile(t, filepath.Join(home, ".claude", "projects", "p1", "transcript.jsonl"), "chat")
				writeFile(t, filepath.Join(home, ".config", "xena", "github-token"), "tok-fake-1")
			},
			notMembers: []string{".claude/projects/p1/transcript.jsonl", ".config/xena/github-token"},
		},
		{
			name: "happy path - skips symlinks",
			setup: func(t *testing.T, home string) {
				t.Helper()
				token := filepath.Join(home, ".config", "xena", "github-token")
				writeFile(t, token, "tok-fake-1")
				memory := filepath.Join(home, ".claude", "projects", "p1", "memory")
				require.NoError(t, os.MkdirAll(memory, 0o700))
				require.NoError(t, os.Symlink(token, filepath.Join(memory, "link.md")))
				require.NoError(t, os.Symlink(filepath.Join(home, ".config"), filepath.Join(home, ".claude-mem")))
			},
			notMembers: []string{".claude/projects/p1/memory/link.md", ".claude-mem/xena/github-token"},
		},
		{
			name: "happy path - skips symlinked memory dir",
			setup: func(t *testing.T, home string) {
				t.Helper()
				writeFile(t, filepath.Join(home, ".config", "xena", "github-token"), "tok-fake-1")
				project := filepath.Join(home, ".claude", "projects", "p1")
				require.NoError(t, os.MkdirAll(project, 0o700))
				require.NoError(t, os.Symlink(filepath.Join(home, ".config", "xena"), filepath.Join(project, "memory")))
			},
			notMembers: []string{".claude/projects/p1/memory/github-token", ".claude/projects/p1/memory"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t, "")
			tt.setup(t, h.agent.home)

			// when
			err := h.agent.exportMemory()

			// then
			require.NoError(t, err)

			members := listMembers(t, h.stdout)
			for _, name := range tt.wantMembers {
				require.Equal(t, byte(tar.TypeReg), members[name], name)
			}

			for _, name := range tt.notMembers {
				require.NotContains(t, members, name)
			}

			if tt.wantMembers == nil && tt.notMembers == nil {
				require.Empty(t, members)
			}
		})
	}
}
