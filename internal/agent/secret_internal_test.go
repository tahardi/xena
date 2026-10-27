package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgent_writeSecret(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		stdin    string
		existing string
		want     string
		wantErr  error
	}{
		{name: "happy path - github-token", secret: "github-token", stdin: "tok-fake-1", want: "tok-fake-1"},
		{name: "happy path - jira-token", secret: "jira-token", stdin: "jira-fake", want: "jira-fake"},
		{name: "happy path - aws-credentials", secret: "aws-credentials", stdin: "aws-fake", want: "aws-fake"},
		{name: "happy path - gcp-token", secret: "gcp-token", stdin: "gcp-fake", want: "gcp-fake"},
		{
			name:     "happy path - replaces existing value",
			secret:   "github-token",
			stdin:    "tok-fake-2",
			existing: "tok-fake-1",
			want:     "tok-fake-2",
		},
		{
			name:     "error - empty value keeps existing",
			secret:   "github-token",
			existing: "tok-fake-1",
			want:     "tok-fake-1",
			wantErr:  ErrEmptyValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t, tt.stdin)
			dir := filepath.Join(h.agent.home, ".config", "xena")
			path := filepath.Join(dir, tt.secret)

			if tt.existing != "" {
				writeFile(t, path, tt.existing)
			}

			// when
			err := h.agent.writeSecret(tt.secret)

			// then
			require.ErrorIs(t, err, tt.wantErr)

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, tt.want, string(got))

			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

			dirInfo, err := os.Stat(dir)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

			leftover, err := filepath.Glob(filepath.Join(dir, "."+tt.secret+".*"))
			require.NoError(t, err)
			require.Empty(t, leftover)
		})
	}
}

func TestAgent_clearSecret(t *testing.T) {
	tests := []struct {
		name     string
		existing bool
	}{
		{name: "happy path - removes file", existing: true},
		{name: "happy path - missing file", existing: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t, "")
			path := filepath.Join(h.agent.home, ".config", "xena", "jira-token")

			if tt.existing {
				writeFile(t, path, "jira-fake")
			}

			// when
			err := h.agent.clearSecret("jira-token")

			// then
			require.NoError(t, err)
			require.NoFileExists(t, path)
		})
	}
}
