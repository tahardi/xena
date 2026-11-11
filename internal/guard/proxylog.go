package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/logs"
)

type ProxyLog struct {
	dir string
	now func() time.Time
}

func NewProxyLog(dir string, now func() time.Time) *ProxyLog {
	return &ProxyLog{dir: dir, now: now}
}

func (p *ProxyLog) Entries(since time.Time) ([]logs.ProxyEntry, error) {
	entries := []logs.ProxyEntry{}
	last := p.now().UTC().Format(time.DateOnly)

	for day := since.UTC().AddDate(0, 0, -1); day.Format(time.DateOnly) <= last; day = day.AddDate(0, 0, 1) {
		found, err := readProxyDay(filepath.Join(p.dir, "proxy-"+day.Format(time.DateOnly)+".jsonl"), since)
		if err != nil {
			return nil, err
		}

		entries = append(entries, found...)
	}

	return entries, nil
}

func readProxyDay(path string, since time.Time) ([]logs.ProxyEntry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("reading proxy log: %w", err)
	}

	var entries []logs.ProxyEntry
	for line := range bytes.Lines(data) {
		var entry logs.ProxyEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("decoding proxy log line: %w", err)
		}

		if !entry.Time.Before(since) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}
