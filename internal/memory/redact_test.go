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

func fakeGitleaks(t *testing.T, scanDir, report, stderr string, exit int) (string, string) {
	t.Helper()

	binDir := t.TempDir()
	reportPathFile := filepath.Join(binDir, "report-path")

	body := `[ "$#" -eq 9 ] || exit 9
[ "$1 $2 $3 $4" = "dir --no-banner --report-format json" ] || exit 9
[ "$5" = "--report-path" ] || exit 9
[ "$7 $8" = "--exit-code 0" ] || exit 9
[ "$9" = '` + scanDir + `' ] || exit 9
echo "$6" > '` + reportPathFile + `'
cat > "$6" <<'REPORT'
` + report + `
REPORT
printf '%s\n' '` + stderr + `' >&2
exit ` + strconv.Itoa(exit) + "\n"

	return writeScript(t, binDir, "gitleaks", body), reportPathFile
}

func TestScan(t *testing.T) {
	report := `[
  {"RuleID": "github-pat", "File": "/x/a.md", "Secret": "s1", "Match": "token=s1", "Line": "ignored"},
  {"RuleID": "generic-api-key", "File": "/x/b.md", "Secret": "", "Match": "key=s2"}
]`

	tests := []struct {
		name          string
		report        string
		stderr        string
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
			name:   "happy path - stderr ignored on success",
			report: "[]",
			stderr: "WRN something",
			want:   []memory.Finding{},
		},
		{
			name:          "error - gitleaks fails",
			report:        "[]",
			stderr:        "Error: unknown command \"dir\" for \"gitleaks\"",
			exit:          1,
			wantErrPrefix: "scanning memory: exit status 1: Error: unknown command \"dir\" for \"gitleaks\"",
		},
		{
			name:          "error - malformed report",
			report:        "not json",
			wantErrPrefix: "scanning memory: decoding report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			gitleaks, reportPathFile := fakeGitleaks(t, dir, tt.report, tt.stderr, tt.exit)

			// when
			got, err := memory.Scan(context.Background(), gitleaks, dir)

			// then
			reportPath, readErr := os.ReadFile(reportPathFile)
			require.NoError(t, readErr)
			require.NoDirExists(t, filepath.Dir(strings.TrimSpace(string(reportPath))))

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
	other := "ghp_madeup0987654321"
	content := "token=" + secret + " and " + secret + " and " + other

	tests := []struct {
		name          string
		findings      func(dir string) []memory.Finding
		want          int
		wantContent   map[string]string
		wantErrPrefix string
	}{
		{
			name: "happy path - every copy of the secret",
			findings: func(dir string) []memory.Finding {
				return []memory.Finding{{RuleID: "github-pat", File: filepath.Join(dir, "a.md"), Secret: secret}}
			},
			want: 2,
			wantContent: map[string]string{
				"a.md": "token=[REDACTED:github-pat] and [REDACTED:github-pat] and " + other,
				"b.md": content,
			},
		},
		{
			name: "happy path - empty secret redacts match",
			findings: func(dir string) []memory.Finding {
				return []memory.Finding{{RuleID: "generic", File: filepath.Join(dir, "a.md"), Match: "token=" + secret}}
			},
			want: 1,
			wantContent: map[string]string{
				"a.md": "[REDACTED:generic] and " + secret + " and " + other,
				"b.md": content,
			},
		},
		{
			name: "happy path - findings across two files",
			findings: func(dir string) []memory.Finding {
				return []memory.Finding{
					{RuleID: "github-pat", File: filepath.Join(dir, "a.md"), Secret: secret},
					{RuleID: "github-pat", File: filepath.Join(dir, "b.md"), Secret: other},
					{RuleID: "github-pat", File: filepath.Join(dir, "a.md"), Secret: other},
				}
			},
			want: 4,
			wantContent: map[string]string{
				"a.md": "token=[REDACTED:github-pat] and [REDACTED:github-pat] and [REDACTED:github-pat]",
				"b.md": "token=" + secret + " and " + secret + " and [REDACTED:github-pat]",
			},
		},
		{
			name: "error - finding outside dir",
			findings: func(dir string) []memory.Finding {
				return []memory.Finding{{RuleID: "github-pat", File: filepath.Join(dir, "..", "a.md"), Secret: secret}}
			},
			wantContent:   map[string]string{"a.md": content, "b.md": content},
			wantErrPrefix: "redacting: finding outside",
		},
		{
			name: "error - outside finding after inside one changes nothing",
			findings: func(dir string) []memory.Finding {
				return []memory.Finding{
					{RuleID: "github-pat", File: filepath.Join(dir, "a.md"), Secret: secret},
					{RuleID: "github-pat", File: filepath.Join(dir, "..", "a.md"), Secret: secret},
				}
			},
			wantContent:   map[string]string{"a.md": content, "b.md": content},
			wantErrPrefix: "redacting: finding outside",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			for _, name := range []string{"a.md", "b.md"} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
			}

			// when
			got, err := memory.Redact(dir, tt.findings(dir))

			// then
			require.Equal(t, tt.wantContent, readTree(t, dir))

			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				require.NotContains(t, err.Error(), secret)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			requireModes(t, dir)
		})
	}
}
