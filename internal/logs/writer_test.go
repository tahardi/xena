package logs

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriter_Write(t *testing.T) {
	day := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	entry := ProxyEntry{Time: day, Host: "example.com", Port: 443, Decision: DecisionAllow, BytesOut: 10, BytesIn: 20}
	want := `{"time":"2026-10-24T12:00:00Z","level":"INFO","msg":"proxy","host":"example.com","port":443,` +
		`"decision":"allow","bytes_out":10,"bytes_in":20}` + "\n"

	t.Run("happy path - appends slog lines to the daily file", func(t *testing.T) {
		// given
		dir := t.TempDir()
		w := &Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return day }}

		// when
		require.NoError(t, w.Write(entry))
		require.NoError(t, w.Write(entry))

		// then
		path := filepath.Join(dir, "proxy-2026-10-24.jsonl")
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, want+want, string(got))

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o640), info.Mode().Perm())
	})

	t.Run("happy path - lines decode back into each record type", func(t *testing.T) {
		tests := []struct {
			name   string
			record Record
			decode func([]byte) (Record, error)
		}{
			{
				name:   "proxy entry",
				record: entry,
				decode: decodeAs[ProxyEntry],
			},
			{
				name:   "gateway entry",
				record: GatewayEntry{Time: day, Tool: ToolGetNote, Path: "Notes/example.md", Decision: DecisionAllow},
				decode: decodeAs[GatewayEntry],
			},
			{
				name: "alert",
				record: Alert{
					Time:     day,
					Rule:     "example-rule",
					Severity: SeverityHigh,
					Guard:    true,
					Entries:  []json.RawMessage{json.RawMessage(`{"host":"example.com"}`)},
				},
				decode: decodeAs[Alert],
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// given
				dir := t.TempDir()
				w := &Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return day }}

				// when
				require.NoError(t, w.Write(tt.record))

				// then
				line, err := os.ReadFile(filepath.Join(dir, "proxy-2026-10-24.jsonl"))
				require.NoError(t, err)

				got, err := tt.decode(line)
				require.NoError(t, err)
				require.Equal(t, tt.record, got)
			})
		}
	})

	t.Run("happy path - starts a new file each day", func(t *testing.T) {
		// given
		dir := t.TempDir()
		now := day
		w := &Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return now }}
		require.NoError(t, w.Write(entry))
		now = day.AddDate(0, 0, 1)

		// when
		require.NoError(t, w.Write(entry))

		// then
		require.FileExists(t, filepath.Join(dir, "proxy-2026-10-24.jsonl"))
		require.FileExists(t, filepath.Join(dir, "proxy-2026-10-25.jsonl"))
	})

	t.Run("happy path - prunes files older than 90 days", func(t *testing.T) {
		// given
		dir := t.TempDir()
		for _, name := range []string{
			"proxy-2026-07-25.jsonl",
			"proxy-2026-07-26.jsonl",
			"proxy-notes.jsonl",
			"vault-2026-01-01.jsonl",
		} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o640))
		}
		w := &Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return day }}

		// when
		require.NoError(t, w.Write(entry))

		// then
		require.NoFileExists(t, filepath.Join(dir, "proxy-2026-07-25.jsonl"))
		require.FileExists(t, filepath.Join(dir, "proxy-2026-07-26.jsonl"))
		require.FileExists(t, filepath.Join(dir, "proxy-notes.jsonl"))
		require.FileExists(t, filepath.Join(dir, "vault-2026-01-01.jsonl"))
	})

	t.Run("happy path - prunes once per day", func(t *testing.T) {
		// given
		dir := t.TempDir()
		w := &Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return day }}
		require.NoError(t, w.Write(entry))

		old := filepath.Join(dir, "proxy-2026-07-25.jsonl")
		require.NoError(t, os.WriteFile(old, nil, 0o640))

		// when
		require.NoError(t, w.Write(entry))

		// then
		require.FileExists(t, old)
	})

	t.Run("happy path - names files by UTC date", func(t *testing.T) {
		// given
		dir := t.TempDir()
		local := time.Date(2026, 10, 24, 23, 30, 0, 0, time.FixedZone("UTC-5", -5*60*60))
		w := &Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return local }}

		// when
		require.NoError(t, w.Write(entry))

		// then
		require.FileExists(t, filepath.Join(dir, "proxy-2026-10-25.jsonl"))
	})

	t.Run("happy path - concurrent writes keep whole lines", func(t *testing.T) {
		// given
		dir := t.TempDir()
		w := &Writer{Dir: dir, Name: "proxy", Now: func() time.Time { return day }}
		const writers = 20
		var wg sync.WaitGroup

		// when
		for range writers {
			wg.Go(func() { assert.NoError(t, w.Write(entry)) })
		}
		wg.Wait()

		// then
		got, err := os.ReadFile(filepath.Join(dir, "proxy-2026-10-24.jsonl"))
		require.NoError(t, err)
		require.Equal(t, strings.Repeat(want, writers), string(got))
	})

	t.Run("error - directory missing", func(t *testing.T) {
		// given
		w := &Writer{Dir: filepath.Join(t.TempDir(), "missing"), Name: "proxy", Now: func() time.Time { return day }}

		// when
		err := w.Write(entry)

		// then
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}

func decodeAs[T Record](line []byte) (Record, error) {
	var record T
	err := json.Unmarshal(line, &record)
	return record, err
}
