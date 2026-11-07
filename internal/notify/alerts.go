package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/logs"
)

const alertPattern = "alerts-*.jsonl"

type AlertFollower struct {
	Dir     string
	Desktop Asker
	offsets map[string]int64
}

func NewAlertFollower(dir string, desktop Asker) (*AlertFollower, error) {
	// ponytail: alerts written while the service is down are not replayed; Maple's red status and the weekly
	// report still show them.
	paths, err := filepath.Glob(filepath.Join(dir, alertPattern))
	if err != nil {
		return nil, fmt.Errorf("listing alerts: %w", err)
	}

	offsets := make(map[string]int64, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		offsets[path] = info.Size()
	}

	return &AlertFollower{Dir: dir, Desktop: desktop, offsets: offsets}, nil
}

func (f *AlertFollower) Poll(ctx context.Context) error {
	paths, err := filepath.Glob(filepath.Join(f.Dir, alertPattern))
	if err != nil {
		return fmt.Errorf("listing alerts: %w", err)
	}

	offsets := make(map[string]int64, len(paths))
	var readErrs, showErrs []error
	for _, path := range paths {
		alerts, offset, err := readAlerts(path, f.offsets[path])
		offsets[path] = offset
		if err != nil {
			readErrs = append(readErrs, fmt.Errorf("reading alerts %s: %w", path, err))
		}

		for _, alert := range alerts {
			if err := f.show(ctx, alert); err != nil {
				showErrs = append(showErrs, err)
			}
		}
	}

	f.offsets = offsets

	if len(showErrs) > 0 {
		readErrs = append(readErrs, fmt.Errorf("showing alert: %w", errors.Join(showErrs...)))
	}

	return errors.Join(readErrs...)
}

func (f *AlertFollower) show(ctx context.Context, alert logs.Alert) error {
	if alert.Guard {
		return nil
	}

	var critical bool
	switch alert.Severity {
	case logs.SeverityHigh:
		critical = true
	case logs.SeverityMedium:
	default:
		return nil
	}

	title := "Xena alert: " + alert.Rule
	body := alert.Severity + " at " + alert.Time.UTC().Format(time.RFC3339)
	return f.Desktop.Show(ctx, title, body, critical)
}

func readAlerts(path string, offset int64) ([]logs.Alert, int64, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, offset, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, offset, err
	}

	if info.Size() < offset {
		offset = 0
	}

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, offset, err
	}

	end := bytes.LastIndexByte(data, '\n') + 1
	var alerts []logs.Alert
	for line := range bytes.SplitSeq(data[:end], []byte("\n")) {
		var alert logs.Alert
		if json.Unmarshal(line, &alert) == nil {
			alerts = append(alerts, alert)
		}
	}

	return alerts, offset + int64(end), nil
}
