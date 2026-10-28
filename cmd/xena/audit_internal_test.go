package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/audit"
	"github.com/tahardi/xena/internal/logs"
)

type fakeAuditCheck struct {
	name     string
	findings []audit.Finding
	err      error
}

func (c fakeAuditCheck) Name() string {
	return c.name
}

func (c fakeAuditCheck) Run(context.Context) ([]audit.Finding, error) {
	return c.findings, c.err
}

func TestRunAuditWith(t *testing.T) {
	groups := fakeAuditCheck{
		name: "desktop-groups",
		findings: []audit.Finding{{
			Severity: logs.SeverityHigh,
			Message:  "example is in the docker group, which grants root",
			Fix:      "Run sudo gpasswd -d example docker, then log out and back in.",
		}},
	}
	manual := []string{"Claude extra usage is off (claude.ai, Settings, Usage)"}

	tests := []struct {
		name    string
		args    []string
		checks  []audit.Check
		want    string
		wantErr error
		json    bool
		errText string
	}{
		{
			name:   "happy path - no drift",
			checks: []audit.Check{fakeAuditCheck{name: "desktop-docker"}},
			want:   "audit: no drift\nmanual: Claude extra usage is off (claude.ai, Settings, Usage)\n",
		},
		{
			name:   "error - drift",
			checks: []audit.Check{groups},
			want: "HIGH desktop-groups: example is in the docker group, which grants root\n" +
				"  fix: Run sudo gpasswd -d example docker, then log out and back in.\n" +
				"manual: Claude extra usage is off (claude.ai, Settings, Usage)\n",
			wantErr: audit.ErrDrift,
		},
		{
			name:   "happy path - skipped",
			checks: []audit.Check{fakeAuditCheck{name: "vm", err: audit.ErrSkipped}},
			want: "audit: no drift\n" +
				"skipped: vm\n" +
				"manual: Claude extra usage is off (claude.ai, Settings, Usage)\n",
		},
		{
			name:   "happy path - --json",
			args:   []string{"--json"},
			checks: []audit.Check{fakeAuditCheck{name: "desktop-docker"}},
			json:   true,
		},
		{
			name:    "error - --json with drift",
			args:    []string{"--json"},
			checks:  []audit.Check{groups},
			json:    true,
			wantErr: audit.ErrDrift,
		},
		{
			name:    "error - unknown flag",
			args:    []string{"--nope"},
			errText: "parsing audit flags",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var out bytes.Buffer
			deps := auditDeps{Checks: tt.checks, Manual: manual, Dir: t.TempDir(), Out: &out}

			// when
			err := runAuditWith(t.Context(), tt.args, slog.New(slog.DiscardHandler), deps)

			// then
			if tt.errText != "" {
				require.ErrorContains(t, err, tt.errText)
				return
			}
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if tt.json {
				var report audit.Report
				require.NoError(t, json.Unmarshal(out.Bytes(), &report))
				require.Equal(t, 1, report.Version)
				require.Len(t, report.Findings, report.Drift)
				require.Equal(t, manual, report.Manual)
				return
			}
			require.Equal(t, tt.want, out.String())
		})
	}
}

func TestDefaultAuditDeps(t *testing.T) {
	t.Run("error - missing audit config", func(t *testing.T) {
		// given
		t.Setenv("XENA_CONFIG_DIR", t.TempDir())

		// when
		_, err := defaultAuditDeps(t.Context())

		// then
		require.ErrorContains(t, err, "loading audit config")
	})
}
