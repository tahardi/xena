package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/health"
)

const (
	guardOK    = `{"version":1,"last_run":"2026-10-24T02:00:00Z","passed":true,"cases":[]}`
	auditClean = `{"version":1,"last_run":"2026-10-24T03:00:00Z","drift":2,"findings":[]}`
)

func TestBuildStatus(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	alertLines := `{"time":"2026-10-24T09:00:00Z","rule":"acked","severity":"high","guard":false}
{"time":"2026-10-24T11:00:00Z","rule":"drop","severity":"high","guard":false}
{"time":"2026-10-24T11:01:00Z","rule":"burst","severity":"medium","guard":false}
{"time":"2026-10-24T11:02:00Z","rule":"quiet","severity":"low","guard":false}
`
	oldAlert := `{"time":"2026-07-01T11:00:00Z","rule":"old","severity":"high","guard":false}` + "\n"
	okResult := health.Result{Name: "xena-proxy", OK: true, Detail: "active"}

	tests := []struct {
		name           string
		noResults      bool
		cut            bool
		alerts         string
		oldAlerts      string
		ack            string
		guard          string
		audit          string
		alertsDir      bool
		oldHeartbeat   bool
		noHeartbeatDir bool
		want           statusJSON
		wantErr        string
		wantErrIs      error
		wantLog        string
	}{
		{
			name:  "happy path - cut marker present",
			cut:   true,
			guard: guardOK,
			audit: auditClean,
			want: statusJSON{
				Version: 1,
				Cut:     true,
				Health:  []health.Result{okResult},
				Alerts:  []statusAlert{},
				Guard:   statusGuard{LastRun: "2026-10-24T02:00:00Z", Passed: true},
				Audit:   statusAudit{LastRun: "2026-10-24T03:00:00Z", Drift: 2},
			},
		},
		{
			name:      "happy path - only unacknowledged high and medium alerts within 90 days",
			alerts:    alertLines,
			oldAlerts: oldAlert,
			ack:       "version: 1\nacked_through: 2026-10-24T10:00:00Z\n",
			guard:     guardOK,
			audit:     auditClean,
			want: statusJSON{
				Version: 1,
				Health:  []health.Result{okResult},
				Alerts: []statusAlert{
					{Time: time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC), Rule: "drop", Severity: "high"},
					{Time: time.Date(2026, 10, 24, 11, 1, 0, 0, time.UTC), Rule: "burst", Severity: "medium"},
				},
				Guard: statusGuard{LastRun: "2026-10-24T02:00:00Z", Passed: true},
				Audit: statusAudit{LastRun: "2026-10-24T03:00:00Z", Drift: 2},
			},
		},
		{
			name: "happy path - missing guard and audit never run",
			want: statusJSON{
				Version: 1,
				Health: []health.Result{
					okResult,
					{Name: "guard", Detail: "never run"},
					{Name: "audit", Detail: "never run"},
				},
				Alerts: []statusAlert{},
			},
		},
		{
			name:  "happy path - only audit missing",
			guard: guardOK,
			want: statusJSON{
				Version: 1,
				Health:  []health.Result{okResult, {Name: "audit", Detail: "never run"}},
				Alerts:  []statusAlert{},
				Guard:   statusGuard{LastRun: "2026-10-24T02:00:00Z", Passed: true},
			},
		},
		{
			name:      "happy path - no results gives empty health",
			noResults: true,
			guard:     guardOK,
			audit:     auditClean,
			want: statusJSON{
				Version: 1,
				Health:  []health.Result{},
				Alerts:  []statusAlert{},
				Guard:   statusGuard{LastRun: "2026-10-24T02:00:00Z", Passed: true},
				Audit:   statusAudit{LastRun: "2026-10-24T03:00:00Z", Drift: 2},
			},
		},
		{
			name:         "happy path - old heartbeat updated",
			oldHeartbeat: true,
			guard:        guardOK,
			audit:        auditClean,
			want: statusJSON{
				Version: 1,
				Health:  []health.Result{okResult},
				Alerts:  []statusAlert{},
				Guard:   statusGuard{LastRun: "2026-10-24T02:00:00Z", Passed: true},
				Audit:   statusAudit{LastRun: "2026-10-24T03:00:00Z", Drift: 2},
			},
		},
		{
			name:           "happy path - heartbeat failure is logged, not fatal",
			noHeartbeatDir: true,
			wantLog:        "touching heartbeat",
			guard:          guardOK,
			audit:          auditClean,
			want: statusJSON{
				Version: 1,
				Health:  []health.Result{okResult},
				Alerts:  []statusAlert{},
				Guard:   statusGuard{LastRun: "2026-10-24T02:00:00Z", Passed: true},
				Audit:   statusAudit{LastRun: "2026-10-24T03:00:00Z", Drift: 2},
			},
		},
		{
			name:    "error - malformed guard file",
			guard:   "{",
			audit:   auditClean,
			wantErr: "reading guard result",
		},
		{
			name:    "error - malformed audit file",
			guard:   guardOK,
			audit:   "{",
			wantErr: "reading audit result",
		},
		{
			name:      "error - guard file missing version",
			guard:     `{"last_run":"2026-10-24T02:00:00Z","passed":true}`,
			audit:     auditClean,
			wantErr:   "reading guard result",
			wantErrIs: config.ErrMissingVersion,
		},
		{
			name:      "error - audit file unknown version",
			guard:     guardOK,
			audit:     `{"version":2,"last_run":"2026-10-24T03:00:00Z","drift":0}`,
			wantErr:   "reading audit result",
			wantErrIs: config.ErrUnknownVersion,
		},
		{
			name:      "error - unreadable alert file",
			alertsDir: true,
			wantErr:   "reading alerts",
		},
		{
			name:    "error - unknown ack version",
			ack:     "version: 2\nacked_through: 2026-10-24T10:00:00Z\n",
			wantErr: "reading alerts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			stateDir := t.TempDir()
			watchDir := t.TempDir()
			gatewayDir := t.TempDir()
			t.Setenv("XENA_STATE_DIR", stateDir)
			t.Setenv("XENA_WATCH_STATE_DIR", watchDir)
			t.Setenv("XENA_GATEWAY_LOG_DIR", gatewayDir)

			cutMarker := filepath.Join(t.TempDir(), "cut")
			if tt.cut {
				require.NoError(t, os.WriteFile(cutMarker, nil, 0o600))
			}

			writeIfSet(t, filepath.Join(watchDir, "alerts-2026-10-24.jsonl"), tt.alerts)
			if tt.alertsDir {
				require.NoError(t, os.Mkdir(filepath.Join(watchDir, "alerts-2026-10-23.jsonl"), 0o700))
			}
			writeIfSet(t, filepath.Join(watchDir, "alerts-2026-07-01.jsonl"), tt.oldAlerts)
			writeIfSet(t, filepath.Join(stateDir, "alerts-ack.yaml"), tt.ack)
			writeIfSet(t, filepath.Join(stateDir, "guard", "last.json"), tt.guard)
			writeIfSet(t, filepath.Join(stateDir, "audit", "last.json"), tt.audit)

			heartbeat := filepath.Join(gatewayDir, "maple-session")
			if tt.noHeartbeatDir {
				heartbeat = filepath.Join(gatewayDir, "absent", "maple-session")
			}
			if tt.oldHeartbeat {
				require.NoError(t, os.WriteFile(heartbeat, nil, 0o600))
				require.NoError(t, os.Chtimes(heartbeat, now.Add(-time.Hour), now.Add(-time.Hour)))
			}

			results := []health.Result{okResult}
			if tt.noResults {
				results = nil
			}

			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))

			// when
			got, err := buildStatus(context.Background(), logger, results, cutMarker, heartbeat, now)

			// then
			if tt.wantErrIs != nil {
				require.ErrorIs(t, err, tt.wantErrIs)
			}

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), tt.wantErr+": "+tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Contains(t, logs.String(), tt.wantLog)

			info, err := os.Stat(heartbeat)
			if tt.noHeartbeatDir {
				require.ErrorIs(t, err, fs.ErrNotExist)
				return
			}

			require.NoError(t, err)
			assert.True(t, now.Equal(info.ModTime()), "heartbeat mtime %s", info.ModTime())
		})
	}
}

func TestRunStatus(t *testing.T) {
	checks := []health.Check{{Name: "vm", Run: func(context.Context) (string, error) { return "shut off", nil }}}

	tests := []struct {
		name    string
		args    []string
		guard   string
		audit   string
		want    []string
		wantErr string
	}{
		{
			name: "happy path - json",
			args: []string{"--json"},
			want: []string{`{"version":1,"cut":false,"health":[{"name":"vm","ok":true,"detail":"shut off"}`},
		},
		{
			name: "happy path - text",
			want: []string{
				"vm     ok    shut off\n",
				"cut: false\n",
				"guard: never run\n",
				"audit: never run\n",
			},
		},
		{
			name:  "happy path - text with guard and audit results",
			guard: guardOK,
			audit: auditClean,
			want: []string{
				"guard: last run 2026-10-24T02:00:00Z, passed true\n",
				"audit: last run 2026-10-24T03:00:00Z, drift 2\n",
			},
		},
		{
			name:    "error - unknown flag",
			args:    []string{"--bogus"},
			wantErr: "parsing status flags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			stateDir := t.TempDir()
			t.Setenv("XENA_STATE_DIR", stateDir)
			t.Setenv("XENA_WATCH_STATE_DIR", t.TempDir())
			t.Setenv("XENA_GATEWAY_LOG_DIR", t.TempDir())
			t.Setenv("XENA_CUT_MARKER", filepath.Join(t.TempDir(), "cut"))
			writeIfSet(t, filepath.Join(stateDir, "guard", "last.json"), tt.guard)
			writeIfSet(t, filepath.Join(stateDir, "audit", "last.json"), tt.audit)
			var out bytes.Buffer

			// when
			err := runStatus(context.Background(), slog.New(slog.DiscardHandler), tt.args, &out, checks)

			// then
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			for _, want := range tt.want {
				assert.Contains(t, out.String(), want)
			}
		})
	}
}

func TestStatusJSON(t *testing.T) {
	// given
	status := statusJSON{
		Version: 1,
		Cut:     false,
		Health:  []health.Result{{Name: "vm", OK: true, Detail: "shut off"}},
		Alerts: []statusAlert{
			{Time: time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC), Rule: "drop", Severity: "high"},
		},
		Guard: statusGuard{LastRun: "2026-10-24T02:00:00Z", Passed: true},
		Audit: statusAudit{LastRun: "2026-10-24T03:00:00Z", Drift: 0},
	}
	want := `{"version":1,"cut":false,"health":[{"name":"vm","ok":true,"detail":"shut off"}],` +
		`"alerts":[{"time":"2026-10-24T11:00:00Z","rule":"drop","severity":"high"}],` +
		`"guard":{"last_run":"2026-10-24T02:00:00Z","passed":true},` +
		`"audit":{"last_run":"2026-10-24T03:00:00Z","drift":0}}`

	// when
	got, err := json.Marshal(status)

	// then
	require.NoError(t, err)
	assert.Equal(t, want, string(got))
}

func writeIfSet(t *testing.T, path, content string) {
	t.Helper()

	if content == "" {
		return
	}

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
