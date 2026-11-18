package memory_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/memory"
)

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("#!/usr/bin/env bash\nset -euo pipefail\n"+body), 0o700))

	return path
}

func fakeGitleaks(t *testing.T, report string, exit int) string {
	t.Helper()

	body := `[ "$#" -eq 9 ] || exit 9
[ "$1 $2 $3 $4" = "dir --no-banner --report-format json" ] || exit 9
[ "$5" = "--report-path" ] || exit 9
[ "$7 $8" = "--exit-code 0" ] || exit 9
cat > "$6" <<'REPORT'
` + report + `
REPORT
exit ` + strconv.Itoa(exit) + "\n"

	return writeScript(t, t.TempDir(), "gitleaks", body)
}

func TestScan(t *testing.T) {
	report := `[
  {"RuleID": "github-pat", "File": "/x/a.md", "Secret": "s1", "Match": "token=s1", "Line": "ignored"},
  {"RuleID": "generic-api-key", "File": "/x/b.md", "Secret": "", "Match": "key=s2"}
]`

	tests := []struct {
		name          string
		report        string
		exit          int
		want          []memory.Finding
		wantErrPrefix string
	}{
		{
			name:   "happy path - two findings",
			report: report,
			want: []memory.Finding{
				{RuleID: "github-pat", File: "/x/a.md", Secret: "s1", Match: "token=s1"},
				{RuleID: "generic-api-key", File: "/x/b.md", Match: "key=s2"},
			},
		},
		{
			name:   "happy path - empty report",
			report: "[]",
			want:   []memory.Finding{},
		},
		{
			name:          "error - gitleaks fails",
			report:        "[]",
			exit:          1,
			wantErrPrefix: "scanning memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			gitleaks := fakeGitleaks(t, tt.report, tt.exit)
			dir := t.TempDir()

			// when
			got, err := memory.Scan(context.Background(), gitleaks, dir)

			// then
			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestRedact(t *testing.T) {
	secret := "ghp_madeup1234567890"
	content := "token=" + secret + " and " + secret

	tests := []struct {
		name          string
		finding       func(dir string) memory.Finding
		want          int
		wantContent   string
		wantErrPrefix string
	}{
		{
			name: "happy path - every copy of the secret",
			finding: func(dir string) memory.Finding {
				return memory.Finding{RuleID: "github-pat", File: filepath.Join(dir, "a.md"), Secret: secret}
			},
			want:        2,
			wantContent: "token=[REDACTED:github-pat] and [REDACTED:github-pat]",
		},
		{
			name: "happy path - empty secret redacts match",
			finding: func(dir string) memory.Finding {
				return memory.Finding{RuleID: "generic", File: filepath.Join(dir, "a.md"), Match: "token=" + secret}
			},
			want:        1,
			wantContent: "[REDACTED:generic] and " + secret,
		},
		{
			name: "error - finding outside dir",
			finding: func(dir string) memory.Finding {
				return memory.Finding{RuleID: "github-pat", File: filepath.Join(dir, "..", "a.md"), Secret: secret}
			},
			wantContent:   content,
			wantErrPrefix: "redacting: finding outside",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			path := filepath.Join(dir, "a.md")
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

			// when
			got, err := memory.Redact(dir, []memory.Finding{tt.finding(dir)})

			// then
			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			require.Equal(t, tt.wantContent, string(data))

			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				require.NotContains(t, err.Error(), secret)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)

			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}
}
