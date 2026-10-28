package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/vault"
)

func newVault(t *testing.T) string {
	t.Helper()

	root := t.TempDir()

	files := []string{
		"Ideas.md",
		"Projects/Xena/Plan.md",
		"Projects/Xena/Reports/2026-W43.md",
		"Journal/2026-10-01.md",
		"Projects/.obsidian/x.md",
	}
	for _, file := range files {
		full := filepath.Join(root, filepath.FromSlash(file))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
		require.NoError(t, os.WriteFile(full, []byte("note"), 0o600))
	}

	require.NoError(t, os.MkdirAll(filepath.Join(root, "Projects", "Folder.md"), 0o700))
	require.NoError(t, os.Symlink("../Journal/2026-10-01.md", filepath.Join(root, "Projects", "link.md")))
	require.NoError(t, os.Symlink("../Journal", filepath.Join(root, "Projects", "linkdir")))
	require.NoError(t, os.Symlink("Xena/Plan.md", filepath.Join(root, "Projects", "inside.md")))
	require.NoError(t, os.Symlink("missing.md", filepath.Join(root, "Projects", "dangling.md")))
	return root
}

func TestNewPolicy(t *testing.T) {
	// given
	root := newVault(t)

	// when
	policy := vault.NewPolicy(root + "/")

	// then
	require.Equal(t, root, policy.Root())
}

func TestPolicy_CheckRead(t *testing.T) {
	root := newVault(t)
	policy := vault.NewPolicy(root)

	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "ideas", path: "Ideas.md"},
		{name: "project note", path: "Projects/Xena/Plan.md"},
		{name: "report", path: "Projects/Xena/Reports/2026-W43.md"},
		{name: "missing note", path: "Projects/New/Note.md"},
		{name: "non-ASCII letter", path: "Projects/Café.md"},
		{name: "exactly 1024 bytes", path: "Projects/" + strings.Repeat(strings.Repeat("a", 200)+"/", 5) + "aaaaaaa.md"},
		{name: "empty", path: "", want: vault.ErrScope},
		{name: "journal", path: "Journal/2026-10-01.md", want: vault.ErrScope},
		{name: "lowercase ideas", path: "ideas.md", want: vault.ErrScope},
		{name: "ideas without extension", path: "Ideas", want: vault.ErrScope},
		{name: "uppercase extension", path: "Ideas.MD", want: vault.ErrScope},
		{name: "double extension", path: "Ideas.md.md", want: vault.ErrScope},
		{name: "nested ideas", path: "Archive/Ideas.md", want: vault.ErrScope},
		{name: "projects folder", path: "Projects", want: vault.ErrScope},
		{name: "projects trailing slash", path: "Projects/", want: vault.ErrTraversal},
		{name: "note trailing slash", path: "Projects/Xena/Plan.md/", want: vault.ErrTraversal},
		{name: "leading dot segment", path: "./Ideas.md", want: vault.ErrTraversal},
		{name: "traversal before hidden", path: "../.obsidian/x.md", want: vault.ErrTraversal},
		{name: "lowercase projects", path: "projects/Xena/Plan.md", want: vault.ErrScope},
		{name: "uppercase projects", path: "PROJECTS/Xena/Plan.md", want: vault.ErrScope},
		{name: "not markdown", path: "Projects/Xena/Plan.txt", want: vault.ErrScope},
		{name: "hidden segment", path: "Projects/.obsidian/x.md", want: vault.ErrScope},
		{name: "directory", path: "Projects/Folder.md", want: vault.ErrScope},
		{name: "cyrillic letter", path: "Рrojects/Xena/Plan.md", want: vault.ErrScope},
		{name: "too long", path: "Projects/" + strings.Repeat("a", 1013) + ".md", want: vault.ErrScope},
		{name: "leading dot dot", path: "../Journal/2026-10-01.md", want: vault.ErrTraversal},
		{name: "inner dot dot", path: "Projects/../Journal/2026-10-01.md", want: vault.ErrTraversal},
		{name: "dot segment", path: "Projects/./Xena/Plan.md", want: vault.ErrTraversal},
		{name: "double slash", path: "Projects//Xena/Plan.md", want: vault.ErrTraversal},
		{name: "backslash", path: `Projects\..\Journal\x.md`, want: vault.ErrTraversal},
		{name: "division slash", path: "Projects/x\u2215..\u2215y.md", want: vault.ErrTraversal},
		{name: "full-width slash", path: "Projects/Xena\uFF0FPlan.md", want: vault.ErrTraversal},
		{name: "fraction slash", path: "Projects/x\u2044y.md", want: vault.ErrTraversal},
		{name: "big solidus", path: "Projects/x\u29F8y.md", want: vault.ErrTraversal},
		{name: "full-width backslash", path: "Projects/x\uFF3Cy.md", want: vault.ErrTraversal},
		{name: "full-width dot", path: "Projects/x\uFF0E\uFF0E/y.md", want: vault.ErrTraversal},
		{name: "one dot leader", path: "Projects/x\u2024y.md", want: vault.ErrTraversal},
		{name: "small full stop", path: "Projects/x\uFE52y.md", want: vault.ErrTraversal},
		{name: "delete", path: "Projects/a\x7f.md", want: vault.ErrTraversal},
		{name: "zero-width space", path: "Projects/\u200bPlan.md", want: vault.ErrTraversal},
		{name: "bidi override", path: "Projects/\u202eplan.md", want: vault.ErrTraversal},
		{name: "null byte", path: "Projects/a\x00.md", want: vault.ErrTraversal},
		{name: "newline", path: "Projects/a\n.md", want: vault.ErrTraversal},
		{name: "invalid UTF-8", path: "Projects/\xff.md", want: vault.ErrTraversal},
		{name: "leading slash", path: "/Projects/Xena/Plan.md", want: vault.ErrAbsolute},
		{name: "vault absolute path", path: filepath.Join(root, "Ideas.md"), want: vault.ErrAbsolute},
		{name: "home", path: "~/Ideas.md", want: vault.ErrAbsolute},
		{name: "drive letter", path: "C:/Projects/a.md", want: vault.ErrAbsolute},
		{name: "lowercase drive letter", path: "c:/a.md", want: vault.ErrAbsolute},
		{name: "other user home", path: "~user/a.md", want: vault.ErrAbsolute},
		{name: "absolute before traversal", path: "/../x.md", want: vault.ErrAbsolute},
		{name: "symlinked file", path: "Projects/link.md", want: vault.ErrSymlink},
		{name: "symlinked directory", path: "Projects/linkdir/2026-10-01.md", want: vault.ErrSymlink},
		{name: "symlink inside projects", path: "Projects/inside.md", want: vault.ErrSymlink},
		{name: "dangling symlink", path: "Projects/dangling.md", want: vault.ErrSymlink},
		{name: "note as directory", path: "Projects/Xena/Plan.md/x.md", want: syscall.ENOTDIR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			rel := tt.path

			// when
			err := policy.CheckRead(rel)

			// then
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestPolicy_CheckWrite(t *testing.T) {
	policy := vault.NewPolicy(newVault(t))

	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "ideas", path: "Ideas.md"},
		{name: "project note", path: "Projects/Xena/Plan.md"},
		{name: "new note", path: "Projects/New/Note.md"},
		{name: "existing report", path: "Projects/Xena/Reports/2026-W43.md", want: vault.ErrScope},
		{name: "new report", path: "Projects/Xena/Reports/New.md", want: vault.ErrScope},
		{name: "lowercase reports", path: "Projects/xena/reports/New.md", want: vault.ErrScope},
		{name: "uppercase reports", path: "Projects/XENA/REPORTS/a.md", want: vault.ErrScope},
		{name: "nested report", path: "Projects/Xena/Reports/sub/a.md", want: vault.ErrScope},
		{name: "reports note", path: "Projects/Xena/Reports.md"},
		{name: "reports prefix folder", path: "Projects/Xena/ReportsOld/a.md"},
		{name: "traversal", path: "../x.md", want: vault.ErrTraversal},
		{name: "absolute", path: "/x.md", want: vault.ErrAbsolute},
		{name: "symlink", path: "Projects/link.md", want: vault.ErrSymlink},
		{name: "scope", path: "Journal/2026-10-01.md", want: vault.ErrScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			rel := tt.path

			// when
			err := policy.CheckWrite(rel)

			// then
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestFilterResults(t *testing.T) {
	type item struct{ Path string }

	policy := vault.NewPolicy(newVault(t))
	pathOf := func(i item) string { return i.Path }

	tests := []struct {
		name  string
		items []item
		want  []item
	}{
		{
			name: "keeps readable paths in order",
			items: []item{
				{Path: "Projects/Xena/Plan.md"},
				{Path: "Journal/2026-10-01.md"},
				{Path: "Ideas.md"},
				{Path: "Projects/link.md"},
				{Path: "Projects/.obsidian/x.md"},
			},
			want: []item{{Path: "Projects/Xena/Plan.md"}, {Path: "Ideas.md"}},
		},
		{name: "empty input", items: []item{}, want: []item{}},
		{name: "nil input", items: nil, want: []item{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			items := tt.items

			// when
			got := vault.FilterResults(policy, items, pathOf)

			// then
			require.NotNil(t, got)
			require.Equal(t, tt.want, got)
		})
	}
}
