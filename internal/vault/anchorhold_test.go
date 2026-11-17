package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/vault"
)

const fakeAnchorhold = `#!/bin/sh
dir=$(dirname "$0")
printf '%s\n' "$@" > "$dir/args"
cat > "$dir/stdin"
printf '%s' "$FAKE_OUT"
exit "${FAKE_EXIT:-0}"
`

func newFakeAnchorhold(t *testing.T, out string, exit string) (vault.Anchorhold, string) {
	t.Helper()

	dir := t.TempDir()
	bin := filepath.Join(dir, "anchorhold")
	require.NoError(t, os.WriteFile(bin, []byte(fakeAnchorhold), 0o700))

	t.Setenv("FAKE_OUT", out)
	t.Setenv("FAKE_EXIT", exit)
	return vault.Anchorhold{Bin: bin}, dir
}

func readFakeArgs(t *testing.T, dir string) []string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, "args"))
	require.NoError(t, err)
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func readFakeStdin(t *testing.T, dir string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, "stdin"))
	require.NoError(t, err)
	return string(data)
}

func TestAnchorhold_Search(t *testing.T) {
	t.Run("happy path - decodes results", func(t *testing.T) {
		// given
		out := `[{"path":"Projects/a.md","title":"A","heading":"H","score":1.5,"snippet":"s",` +
			`"token_estimate":3,"tags":[],"matched_by":"keyword"},` +
			`{"path":"Ideas.md","title":"Ideas","heading":"","score":1,"snippet":"t"}]`
		notes, dir := newFakeAnchorhold(t, out, "0")

		// when
		got, err := notes.Search(t.Context(), "-q", 7)

		// then
		require.NoError(t, err)
		require.Equal(t, []string{"search", "--json", "-n", "7", "--", "-q"}, readFakeArgs(t, dir))
		require.Equal(t, []vault.SearchResult{
			{Path: "Projects/a.md", Title: "A", Heading: "H", Snippet: "s"},
			{Path: "Ideas.md", Title: "Ideas", Snippet: "t"},
		}, got)
	})

	t.Run("error - bad json", func(t *testing.T) {
		// given
		notes, _ := newFakeAnchorhold(t, "not json secret", "0")

		// when
		_, err := notes.Search(t.Context(), "q", 7)

		// then
		require.True(t, strings.HasPrefix(err.Error(), "searching notes"))
		require.NotContains(t, err.Error(), "secret")
	})

	t.Run("error - non-zero exit", func(t *testing.T) {
		// given
		notes, _ := newFakeAnchorhold(t, "secret stdout", "2")

		// when
		_, err := notes.Search(t.Context(), "q", 7)

		// then
		require.True(t, strings.HasPrefix(err.Error(), "searching notes"))
		require.NotContains(t, err.Error(), "secret stdout")
	})
}

func TestAnchorhold_Get(t *testing.T) {
	t.Run("happy path - decodes note", func(t *testing.T) {
		// given
		out := `{"path":"Projects/a.md","title":"A","tags":["x"],"sections":[{"heading":"H","text":"body"}]}`
		notes, dir := newFakeAnchorhold(t, out, "0")

		// when
		got, err := notes.Get(t.Context(), "Projects/a.md")

		// then
		require.NoError(t, err)
		require.Equal(t, []string{"get", "--json", "--", "Projects/a.md"}, readFakeArgs(t, dir))
		require.Equal(t, vault.Note{
			Path:     "Projects/a.md",
			Title:    "A",
			Tags:     []string{"x"},
			Sections: []vault.Section{{Heading: "H", Text: "body"}},
		}, got)
	})

	t.Run("error - not found", func(t *testing.T) {
		// given
		notes, _ := newFakeAnchorhold(t, "", "1")

		// when
		_, err := notes.Get(t.Context(), "Projects/a.md")

		// then
		require.ErrorIs(t, err, vault.ErrNoteNotFound)
	})

	t.Run("error - bad json", func(t *testing.T) {
		// given
		notes, _ := newFakeAnchorhold(t, "not json secret", "0")

		// when
		_, err := notes.Get(t.Context(), "Projects/a.md")

		// then
		require.True(t, strings.HasPrefix(err.Error(), "getting note"))
		require.NotContains(t, err.Error(), "secret")
	})

	t.Run("error - other exit", func(t *testing.T) {
		// given
		notes, _ := newFakeAnchorhold(t, "", "2")

		// when
		_, err := notes.Get(t.Context(), "Projects/a.md")

		// then
		require.NotErrorIs(t, err, vault.ErrNoteNotFound)
		require.True(t, strings.HasPrefix(err.Error(), "getting note"))
	})
}

func TestAnchorhold_Write(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		exit     string
		wantArgs []string
		wantErr  string
	}{
		{name: "happy path - create", mode: "create", exit: "0", wantArgs: []string{"write", "--", "Projects/a.md"}},
		{
			name:     "happy path - overwrite",
			mode:     "overwrite",
			exit:     "0",
			wantArgs: []string{"write", "--overwrite", "--", "Projects/a.md"},
		},
		{name: "error - append", mode: "append", exit: "0", wantErr: "writing note: unknown mode"},
		{name: "error - non-zero exit", mode: "create", exit: "2", wantErr: "writing note"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			notes, dir := newFakeAnchorhold(t, "", tt.exit)
			content := "---\nsource: xena-vm\n---\nmade-up body\n"

			// when
			err := notes.Write(t.Context(), "Projects/a.md", content, tt.mode)

			// then
			if tt.wantErr != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErr), err.Error())
				require.NotContains(t, err.Error(), "made-up body")
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantArgs, readFakeArgs(t, dir))
			require.Equal(t, content, readFakeStdin(t, dir))
		})
	}
}

func TestAnchorhold_Root(t *testing.T) {
	t.Run("happy path - vault field", func(t *testing.T) {
		// given
		notes, dir := newFakeAnchorhold(t, `{"vault":"/home/me/vault","notes":3}`, "0")

		// when
		got, err := notes.Root(t.Context())

		// then
		require.NoError(t, err)
		require.Equal(t, []string{"status", "--json"}, readFakeArgs(t, dir))
		require.Equal(t, "/home/me/vault", got)
	})

	rootErrors := []struct {
		name string
		out  string
		exit string
	}{
		{name: "error - bad json", out: "not json secret", exit: "0"},
		{name: "error - non-zero exit", out: `{"vault":"/home/me/vault"}`, exit: "2"},
	}
	for _, tt := range rootErrors {
		t.Run(tt.name, func(t *testing.T) {
			// given
			notes, _ := newFakeAnchorhold(t, tt.out, tt.exit)

			// when
			_, err := notes.Root(t.Context())

			// then
			require.True(t, strings.HasPrefix(err.Error(), "reading vault root"))
			require.NotContains(t, err.Error(), "secret")
		})
	}

	t.Run("error - missing vault", func(t *testing.T) {
		// given
		notes, _ := newFakeAnchorhold(t, `{"notes":3}`, "0")

		// when
		_, err := notes.Root(t.Context())

		// then
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "reading vault root"))
	})
}
