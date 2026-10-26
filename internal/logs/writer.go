package logs

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	retentionDays = 90
	fileMode      = 0o640
)

type Writer struct {
	Dir  string
	Name string
	Now  func() time.Time

	mu       sync.Mutex
	prunedOn string
}

func (w *Writer) Write(record Record) error {
	var line bytes.Buffer
	entry := slog.NewRecord(record.LogTime(), slog.LevelInfo, w.Name, 0)
	entry.AddAttrs(slog.Any("", record))
	if err := slog.NewJSONHandler(&line, nil).Handle(context.Background(), entry); err != nil {
		return fmt.Errorf("encoding %s log record: %w", w.Name, err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.now()
	day := now.Format(time.DateOnly)
	if day != w.prunedOn {
		if err := w.prune(now); err != nil {
			return err
		}
		w.prunedOn = day
	}

	path := filepath.Join(w.Dir, w.Name+"-"+day+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	if _, err := f.Write(line.Bytes()); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", path, err)
	}
	return nil
}

func (w *Writer) now() time.Time {
	if w.Now == nil {
		return time.Now().UTC()
	}
	return w.Now().UTC()
}

func (w *Writer) prune(now time.Time) error {
	paths, err := filepath.Glob(filepath.Join(w.Dir, w.Name+"-*.jsonl"))
	if err != nil {
		return fmt.Errorf("listing %s logs: %w", w.Name, err)
	}

	cutoff := now.AddDate(0, 0, -retentionDays).Format(time.DateOnly)
	for _, path := range paths {
		day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), w.Name+"-"), ".jsonl")
		if _, err := time.Parse(time.DateOnly, day); err != nil {
			continue
		}
		if day < cutoff {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("removing %s: %w", path, err)
			}
		}
	}
	return nil
}
