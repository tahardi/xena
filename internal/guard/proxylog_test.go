package guard_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/guard"
	"github.com/tahardi/xena/internal/logs"
)

func writeProxyEntries(t *testing.T, dir string, entries ...logs.ProxyEntry) {
	t.Helper()

	for _, entry := range entries {
		writer := logs.Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return entry.Time }}
		require.NoError(t, writer.Write(entry))
	}
}

func TestProxyLog_Entries(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	first := logs.ProxyEntry{Time: now.Add(-3 * time.Minute), Host: "a.invalid", Port: 443, Decision: logs.DecisionDeny}
	second := logs.ProxyEntry{Time: now.Add(-2 * time.Minute), Host: "b.invalid", Port: 443, Decision: logs.DecisionDeny}
	third := logs.ProxyEntry{Time: now.Add(-time.Minute), Host: "c.invalid", Port: 80, Decision: logs.DecisionTimeout}
	yesterday := logs.ProxyEntry{Time: now.Add(-6 * time.Hour), Host: "d.invalid", Port: 443, Decision: logs.DecisionDeny}

	tests := []struct {
		name    string
		entries []logs.ProxyEntry
		badFile bool
		since   time.Time
		want    []logs.ProxyEntry
		wantErr string
	}{
		{
			name:    "happy path - one day",
			entries: []logs.ProxyEntry{first, second, third},
			since:   now.Add(-150 * time.Second),
			want:    []logs.ProxyEntry{second, third},
		},
		{
			name:    "happy path - spans midnight",
			entries: []logs.ProxyEntry{yesterday, third},
			since:   now.Add(-24 * time.Hour),
			want:    []logs.ProxyEntry{yesterday, third},
		},
		{
			name:    "happy path - entry at since is kept",
			entries: []logs.ProxyEntry{second},
			since:   second.Time,
			want:    []logs.ProxyEntry{second},
		},
		{
			name:  "happy path - no files",
			since: now.Add(-time.Hour),
			want:  []logs.ProxyEntry{},
		},
		{
			name:    "error - bad line",
			badFile: true,
			since:   now.Add(-time.Hour),
			wantErr: "decoding proxy log line",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			writeProxyEntries(t, dir, tt.entries...)

			if tt.badFile {
				path := filepath.Join(dir, "proxy-2026-10-25.jsonl")
				require.NoError(t, os.WriteFile(path, []byte("{not json\n"), 0o600))
			}

			log := guard.NewProxyLog(dir, func() time.Time { return now })

			// when
			got, err := log.Entries(tt.since)

			// then
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, got, len(tt.want))
			for i := range tt.want {
				assert.True(t, tt.want[i].Time.Equal(got[i].Time))
				assert.Equal(t, tt.want[i].Host, got[i].Host)
				assert.Equal(t, tt.want[i].Port, got[i].Port)
				assert.Equal(t, tt.want[i].Decision, got[i].Decision)
			}
		})
	}

	t.Run("error - unreadable file", func(t *testing.T) {
		// given
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, "proxy-2026-10-25.jsonl"), 0o700))
		log := guard.NewProxyLog(dir, func() time.Time { return now })

		// when
		_, err := log.Entries(now.Add(-time.Hour))

		// then
		require.ErrorContains(t, err, "reading proxy log")
	})
}
