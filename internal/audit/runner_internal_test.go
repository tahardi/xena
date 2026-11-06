package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
)

type fakeCheck struct {
	name     string
	findings []Finding
	err      error
}

func (c fakeCheck) Name() string {
	return c.name
}

func (c fakeCheck) Run(context.Context) ([]Finding, error) {
	return c.findings, c.err
}

type hangingCheck struct {
	release chan struct{}
}

func (hangingCheck) Name() string {
	return "desktop-hang"
}

func (c hangingCheck) Run(context.Context) ([]Finding, error) {
	<-c.release
	return nil, nil
}

func TestRunner_Run(t *testing.T) {
	discard := slog.New(slog.DiscardHandler)
	started := time.Date(2026, 10, 28, 4, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	manual := []string{"Claude extra usage is off (claude.ai, Settings, Usage)"}
	finding := Finding{Severity: logs.SeverityHigh, Message: "docker found", Fix: "remove docker"}

	tests := []struct {
		name        string
		checks      []Check
		readOnly    bool
		wantErr     error
		errText     string
		wantDrift   int
		wantFinding []Finding
		wantSkipped []string
	}{
		{
			name:        "happy path - no drift",
			checks:      []Check{fakeCheck{name: "a"}, fakeCheck{name: "b"}},
			wantFinding: []Finding{},
			wantSkipped: []string{},
		},
		{
			name:      "error - drift",
			checks:    []Check{fakeCheck{name: "desktop-docker", findings: []Finding{finding, finding}}},
			wantErr:   ErrDrift,
			wantDrift: 2,
			wantFinding: []Finding{
				{Check: "desktop-docker", Severity: logs.SeverityHigh, Message: "docker found", Fix: "remove docker"},
				{Check: "desktop-docker", Severity: logs.SeverityHigh, Message: "docker found", Fix: "remove docker"},
			},
			wantSkipped: []string{},
		},
		{
			name:      "error - check error becomes finding",
			checks:    []Check{fakeCheck{name: "desktop-ufw", err: errBroken}},
			wantErr:   ErrDrift,
			wantDrift: 1,
			wantFinding: []Finding{
				{
					Check:    "desktop-ufw",
					Severity: logs.SeverityHigh,
					Message:  "check failed: broken",
					Fix:      "Fix whatever stops the check from running, then run xena audit again.",
				},
			},
			wantSkipped: []string{},
		},
		{
			name:        "happy path - skipped",
			checks:      []Check{fakeCheck{name: "vm", err: ErrSkipped}},
			wantFinding: []Finding{},
			wantSkipped: []string{"vm"},
		},
		{
			name:        "happy path - wrapped skip",
			checks:      []Check{fakeCheck{name: "vm", err: fmt.Errorf("vm down: %w", ErrSkipped)}},
			wantFinding: []Finding{},
			wantSkipped: []string{"vm"},
		},
		{
			name: "error - findings keep check order",
			checks: []Check{
				fakeCheck{name: "first", findings: []Finding{{Severity: logs.SeverityLow, Message: "one"}}},
				fakeCheck{name: "second", findings: []Finding{{Severity: logs.SeverityLow, Message: "two"}}},
			},
			wantErr:   ErrDrift,
			wantDrift: 2,
			wantFinding: []Finding{
				{Check: "first", Severity: logs.SeverityLow, Message: "one"},
				{Check: "second", Severity: logs.SeverityLow, Message: "two"},
			},
			wantSkipped: []string{},
		},
		{
			name:      "happy path - skipped with findings",
			checks:    []Check{fakeCheck{name: "plugins", findings: []Finding{finding}, err: ErrSkipped}},
			wantErr:   ErrDrift,
			wantDrift: 1,
			wantFinding: []Finding{
				{Check: "plugins", Severity: logs.SeverityHigh, Message: "docker found", Fix: "remove docker"},
			},
			wantSkipped: []string{"plugins"},
		},
		{
			name:     "error - dir not writable",
			checks:   []Check{fakeCheck{name: "a"}},
			readOnly: true,
			errText:  "writing audit report",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			if tt.readOnly {
				require.NoError(t, os.Chmod(dir, 0o500))
			}
			times := []time.Time{started, finished}
			runner := NewRunner(tt.checks, manual, dir, clock(times), time.Minute, discard)

			// when
			report, err := runner.Run(t.Context())

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

			want := Report{
				Version:  1,
				Started:  started,
				LastRun:  finished,
				Drift:    tt.wantDrift,
				Findings: tt.wantFinding,
				Skipped:  tt.wantSkipped,
				Manual:   manual,
			}
			require.Equal(t, want, report)

			data, err := os.ReadFile(filepath.Join(dir, "last.json"))
			require.NoError(t, err)
			var got Report
			require.NoError(t, json.Unmarshal(data, &got))
			require.Equal(t, want, got)

			info, err := os.Stat(filepath.Join(dir, "last.json"))
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}

	t.Run("happy path - history", func(t *testing.T) {
		// given
		dir := t.TempDir()
		times := []time.Time{started, finished}
		checks := []Check{fakeCheck{name: "desktop-docker", findings: []Finding{finding}}}
		runner := NewRunner(checks, manual, dir, clock(times), time.Minute, discard)

		// when
		_, err := runner.Run(t.Context())
		require.ErrorIs(t, err, ErrDrift)

		_, err = NewRunner(checks, manual, dir, clock([]time.Time{started, finished}), time.Minute, discard).Run(t.Context())

		// then
		require.ErrorIs(t, err, ErrDrift)

		f, err := os.Open(filepath.Join(dir, "audit-2026-10-28.jsonl"))
		require.NoError(t, err)
		defer f.Close()

		var lines []map[string]any
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var line map[string]any
			require.NoError(t, json.Unmarshal(scanner.Bytes(), &line))
			lines = append(lines, line)
		}
		require.NoError(t, scanner.Err())
		require.Len(t, lines, 2)
		require.Equal(t, "INFO", lines[0]["level"])
		require.Equal(t, "audit", lines[0]["msg"])
		require.Equal(t, "2026-10-28T04:01:00Z", lines[0]["time"])
		require.InDelta(t, 1, lines[0]["drift"], 0)
		require.Len(t, lines[0]["findings"], 1)
	})

	t.Run("error - history not writable", func(t *testing.T) {
		// given
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, "audit-2026-10-28.jsonl"), 0o700))
		checks := []Check{fakeCheck{name: "a"}}
		runner := NewRunner(checks, manual, dir, clock([]time.Time{started, finished}), time.Minute, discard)

		// when
		_, err := runner.Run(t.Context())

		// then
		require.ErrorContains(t, err, "appending audit history")
	})

	t.Run("error - check timeout becomes finding", func(t *testing.T) {
		// given
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		checks := []Check{hangingCheck{release: release}, fakeCheck{name: "after"}}
		runner := NewRunner(
			checks,
			manual,
			t.TempDir(),
			clock([]time.Time{started, finished}),
			time.Millisecond,
			discard,
		)

		// when
		report, err := runner.Run(t.Context())

		// then
		require.ErrorIs(t, err, ErrDrift)
		require.Equal(t, []Finding{{
			Check:    "desktop-hang",
			Severity: logs.SeverityHigh,
			Message:  "check timed out after 1ms",
			Fix:      "Find the command or file the check waits on, then run xena audit again.",
		}}, report.Findings)
	})

	t.Run("error - check failures are logged", func(t *testing.T) {
		// given
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		var out strings.Builder
		logger := slog.New(slog.NewJSONHandler(&out, nil))
		checks := []Check{
			fakeCheck{name: "desktop-ufw", err: errBroken},
			hangingCheck{release: release},
			fakeCheck{name: "desktop-docker", findings: []Finding{finding}},
			fakeCheck{name: "vm", err: ErrSkipped},
		}
		runner := NewRunner(
			checks,
			manual,
			t.TempDir(),
			clock([]time.Time{started, finished}),
			time.Millisecond,
			logger,
		)

		// when
		_, err := runner.Run(t.Context())

		// then
		require.ErrorIs(t, err, ErrDrift)

		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		require.Len(t, lines, 2)

		got := make([]map[string]any, 0, len(lines))
		for _, line := range lines {
			var entry map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &entry))
			got = append(got, entry)
		}
		require.Equal(t, "ERROR", got[0]["level"])
		require.Equal(t, "audit check failed", got[0]["msg"])
		require.Equal(t, "desktop-ufw", got[0]["check"])
		require.Equal(t, "broken", got[0]["error"])
		require.Equal(t, "audit check failed", got[1]["msg"])
		require.Equal(t, "desktop-hang", got[1]["check"])
		require.Equal(t, "check timed out after 1ms", got[1]["error"])
	})
}
