package notify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/notify"
)

const (
	alertFile     = "alerts-2026-10-01.jsonl"
	secretEntry   = "secret.example.com"
	firewallTitle = "Xena alert: firewall-drop"
)

func alertLine(t *testing.T, severity string, guard bool) string {
	t.Helper()

	line, err := json.Marshal(logs.Alert{
		Time:     time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC),
		Rule:     "firewall-drop",
		Severity: severity,
		Guard:    guard,
		Entries:  []json.RawMessage{json.RawMessage(`{"host":"` + secretEntry + `"}`)},
	})
	require.NoError(t, err)
	return string(line) + "\n"
}

func writeAlerts(t *testing.T, path string, content string) {
	t.Helper()

	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func appendAlerts(t *testing.T, path string, content string) {
	t.Helper()

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = file.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, file.Close())
}

func TestAlertFollower_Poll(t *testing.T) {
	highShow := showCall{title: firewallTitle, body: "high at 2026-10-01T10:00:00Z", critical: true}

	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		actions    []func(t *testing.T, dir string)
		showErrs   []error
		wantShows  []showCall
		wantErrMsg string
	}{
		{
			name: "existing lines skipped",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				writeAlerts(t, filepath.Join(dir, alertFile), alertLine(t, logs.SeverityHigh, false))
			},
			actions: []func(t *testing.T, dir string){nil},
		},
		{
			name: "appended high",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				writeAlerts(t, filepath.Join(dir, alertFile), alertLine(t, logs.SeverityHigh, false))
			},
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					appendAlerts(t, filepath.Join(dir, alertFile), alertLine(t, logs.SeverityHigh, false))
				},
			},
			wantShows: []showCall{highShow},
		},
		{
			name:  "appended medium",
			setup: emptyAlerts,
			actions: []func(t *testing.T, dir string){
				appendTo(alertFile, logs.SeverityMedium, false),
			},
			wantShows: []showCall{{title: firewallTitle, body: "medium at 2026-10-01T10:00:00Z"}},
		},
		{
			name:    "low skipped",
			setup:   emptyAlerts,
			actions: []func(t *testing.T, dir string){appendTo(alertFile, logs.SeverityLow, false)},
		},
		{
			name:    "unknown severity skipped",
			setup:   emptyAlerts,
			actions: []func(t *testing.T, dir string){appendTo(alertFile, "critical", false)},
		},
		{
			name:    "guard alert skipped",
			setup:   emptyAlerts,
			actions: []func(t *testing.T, dir string){appendTo(alertFile, logs.SeverityHigh, true)},
		},
		{
			name:  "partial line waits",
			setup: emptyAlerts,
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					line := alertLine(t, logs.SeverityHigh, false)
					appendAlerts(t, filepath.Join(dir, alertFile), line[:len(line)-1])
				},
				func(t *testing.T, dir string) {
					t.Helper()
					appendAlerts(t, filepath.Join(dir, alertFile), "\n")
				},
			},
			wantShows: []showCall{highShow},
		},
		{
			name: "new file read from start",
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					line := alertLine(t, logs.SeverityHigh, false)
					writeAlerts(t, filepath.Join(dir, "alerts-2026-10-02.jsonl"), line+line)
				},
			},
			wantShows: []showCall{highShow, highShow},
		},
		{
			name:  "malformed line skipped",
			setup: emptyAlerts,
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					appendAlerts(t, filepath.Join(dir, alertFile), "not json\n"+alertLine(t, logs.SeverityHigh, false))
				},
			},
			wantShows: []showCall{highShow},
		},
		{
			name: "other files ignored",
			actions: []func(t *testing.T, dir string){
				appendTo("proxy-2026-10-01.jsonl", logs.SeverityHigh, false),
				appendTo("notes.jsonl", logs.SeverityHigh, false),
			},
		},
		{
			name: "truncated file resets",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				line := alertLine(t, logs.SeverityHigh, false)
				writeAlerts(t, filepath.Join(dir, alertFile), line+line)
			},
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					writeAlerts(t, filepath.Join(dir, alertFile), alertLine(t, logs.SeverityHigh, false))
				},
			},
			wantShows: []showCall{highShow},
		},
		{
			name:      "entries never shown",
			setup:     emptyAlerts,
			actions:   []func(t *testing.T, dir string){appendTo(alertFile, logs.SeverityHigh, false)},
			wantShows: []showCall{highShow},
		},
		{
			name:  "show error continues",
			setup: emptyAlerts,
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					line := alertLine(t, logs.SeverityHigh, false)
					appendAlerts(t, filepath.Join(dir, alertFile), line+line)
				},
			},
			showErrs:   []error{errShow},
			wantShows:  []showCall{highShow, highShow},
			wantErrMsg: "showing alert",
		},
		{
			name: "directory with alert name reports error",
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					require.NoError(t, os.Mkdir(filepath.Join(dir, "alerts-x.jsonl"), 0o700))
				},
				appendTo(alertFile, logs.SeverityHigh, false),
			},
			wantShows:  []showCall{highShow},
			wantErrMsg: "reading alerts",
		},
		{
			name:  "time shown in UTC",
			setup: emptyAlerts,
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					line := `{"time":"2026-10-01T05:00:00-05:00","rule":"firewall-drop","severity":"high"}` + "\n"
					appendAlerts(t, filepath.Join(dir, alertFile), line)
				},
			},
			wantShows: []showCall{highShow},
		},
		{
			name: "recreated file read from start",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				line := alertLine(t, logs.SeverityHigh, false)
				writeAlerts(t, filepath.Join(dir, alertFile), line+line+line)
			},
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					require.NoError(t, os.Remove(filepath.Join(dir, alertFile)))
				},
				func(t *testing.T, dir string) {
					t.Helper()
					line := alertLine(t, logs.SeverityHigh, false)
					writeAlerts(t, filepath.Join(dir, alertFile), line+line+line+line)
				},
			},
			wantShows: []showCall{highShow, highShow, highShow, highShow},
		},
		{
			name: "missing directory",
			actions: []func(t *testing.T, dir string){
				func(t *testing.T, dir string) {
					t.Helper()
					require.NoError(t, os.RemoveAll(dir))
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			asker := &fakeAsker{showErrs: tt.showErrs}
			follower, err := notify.NewAlertFollower(dir, asker)
			require.NoError(t, err)

			// when
			var pollErr error
			for i, action := range tt.actions {
				if action != nil {
					action(t, dir)
				}

				pollErr = follower.Poll(t.Context())

				if i < len(tt.actions)-1 {
					require.Empty(t, asker.showCalls())
				}
			}

			// then
			if tt.wantErrMsg != "" {
				require.ErrorContains(t, pollErr, tt.wantErrMsg)
				require.Regexp(t, "^"+tt.wantErrMsg, pollErr.Error())
			} else {
				require.NoError(t, pollErr)
			}

			shows := asker.showCalls()
			require.Equal(t, tt.wantShows, shows)

			for _, show := range shows {
				require.NotContains(t, show.title, secretEntry)
				require.NotContains(t, show.body, secretEntry)
			}
		})
	}

	t.Run("happy path - missing directory at start", func(t *testing.T) {
		// given
		dir := filepath.Join(t.TempDir(), "missing")
		asker := &fakeAsker{}

		// when
		follower, err := notify.NewAlertFollower(dir, asker)

		// then
		require.NoError(t, err)
		require.NoError(t, follower.Poll(t.Context()))
		require.Empty(t, asker.showCalls())
	})
}

func emptyAlerts(t *testing.T, dir string) {
	t.Helper()

	writeAlerts(t, filepath.Join(dir, alertFile), "")
}

func appendTo(name string, severity string, guard bool) func(t *testing.T, dir string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		appendAlerts(t, filepath.Join(dir, name), alertLine(t, severity, guard))
	}
}
