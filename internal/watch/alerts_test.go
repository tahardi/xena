package watch_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/watch"
)

func TestReadAlerts(t *testing.T) {
	since := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	late := `{"time":"2026-10-24T11:00:00Z","rule":"drop","severity":"high","guard":false}`
	early := `{"time":"2026-10-24T09:00:00Z","rule":"burst","severity":"medium","guard":false}`
	old := `{"time":"2026-10-20T09:00:00Z","rule":"old","severity":"high","guard":false}`

	tests := []struct {
		name    string
		files   map[string]string
		dirs    []string
		missing bool
		want    []string
		wantErr string
	}{
		{
			name: "happy path - only files on or after since in time order",
			files: map[string]string{
				"alerts-2026-10-20.jsonl": old + "\n",
				"alerts-2026-10-24.jsonl": late + "\n" + early + "\n",
			},
			want: []string{"burst", "drop"},
		},
		{
			name:  "happy path - garbage line skipped",
			files: map[string]string{"alerts-2026-10-24.jsonl": "not json\n" + late + "\n"},
			want:  []string{"drop"},
		},
		{
			name:  "happy path - other files ignored",
			files: map[string]string{"proxy-2026-10-24.jsonl": late + "\n", "alerts-bogus.jsonl": late + "\n"},
		},
		{
			name:  "happy path - file dated on since included",
			files: map[string]string{"alerts-2026-10-22.jsonl": late + "\n", "alerts-2026-10-21.jsonl": early + "\n"},
			want:  []string{"drop"},
		},
		{
			name:    "happy path - missing directory",
			missing: true,
		},
		{
			name:    "error - unreadable file",
			dirs:    []string{"alerts-2026-10-24.jsonl"},
			wantErr: "reading alerts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			for name, content := range tt.files {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
			}

			for _, name := range tt.dirs {
				require.NoError(t, os.Mkdir(filepath.Join(dir, name), 0o700))
			}
			if tt.missing {
				dir = filepath.Join(dir, "absent")
			}

			// when
			got, err := watch.ReadAlerts(dir, since)

			// then
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			rules := make([]string, 0, len(got))
			for _, a := range got {
				rules = append(rules, a.Rule)
			}
			if tt.want == nil {
				tt.want = []string{}
			}
			assert.Equal(t, tt.want, rules)
		})
	}
}

func TestAlertFiles(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		missing bool
		want    []string
	}{
		{
			name:  "happy path - dated alert files in name order",
			files: []string{"alerts-2026-10-02.jsonl", "alerts-2026-10-01.jsonl"},
			want:  []string{"alerts-2026-10-01.jsonl", "alerts-2026-10-02.jsonl"},
		},
		{
			name:  "happy path - other files ignored",
			files: []string{"alerts-bogus.jsonl", "proxy-2026-10-01.jsonl", "notes.jsonl"},
		},
		{
			name:    "happy path - missing directory",
			missing: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			for _, name := range tt.files {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
			}

			if tt.missing {
				dir = filepath.Join(dir, "absent")
			}

			// when
			got, err := watch.AlertFiles(dir)

			// then
			require.NoError(t, err)

			names := make([]string, 0, len(got))
			for _, path := range got {
				names = append(names, filepath.Base(path))
			}

			if tt.want == nil {
				tt.want = []string{}
			}

			assert.Equal(t, tt.want, names)
		})
	}
}

func TestLoadAck(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    time.Time
		wantErr error
	}{
		{
			name: "happy path - missing file is zero",
		},
		{
			name:    "happy path - acked through",
			content: "version: 1\nacked_through: 2026-10-24T10:00:00Z\n",
			want:    time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC),
		},
		{
			name:    "error - unknown version",
			content: "version: 2\nacked_through: 2026-10-24T10:00:00Z\n",
			wantErr: config.ErrUnknownVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := filepath.Join(t.TempDir(), "alerts-ack.yaml")
			if tt.content != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))
			}

			// when
			got, err := watch.LoadAck(path)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.ErrorContains(t, err, "loading alert ack")
				return
			}
			require.NoError(t, err)
			assert.True(t, tt.want.Equal(got.AckedThrough), "got %s", got.AckedThrough)
		})
	}
}

func TestUnacknowledged(t *testing.T) {
	ack := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	after := ack.Add(5 * time.Minute)

	tests := []struct {
		name  string
		alert logs.Alert
		want  bool
	}{
		{name: "happy path - high after ack", alert: logs.Alert{Time: after, Severity: logs.SeverityHigh}, want: true},
		{
			name:  "happy path - medium after ack",
			alert: logs.Alert{Time: after, Severity: logs.SeverityMedium},
			want:  true,
		},
		{name: "happy path - low after ack", alert: logs.Alert{Time: after, Severity: logs.SeverityLow}},
		{
			name:  "happy path - high before ack",
			alert: logs.Alert{Time: ack.Add(-5 * time.Minute), Severity: logs.SeverityHigh},
		},
		{name: "happy path - high at ack", alert: logs.Alert{Time: ack, Severity: logs.SeverityHigh}},
		{
			name:  "happy path - guard high after ack",
			alert: logs.Alert{Time: after, Severity: logs.SeverityHigh, Guard: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			alerts := []logs.Alert{tt.alert}

			// when
			got := watch.Unacknowledged(alerts, ack)

			// then
			assert.Equal(t, tt.want, len(got) == 1)
		})
	}
}
