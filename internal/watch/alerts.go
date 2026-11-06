package watch

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
)

const (
	ackVersion   = 1
	maxAlertLine = 1 << 20
)

type Ack struct {
	Version      int       `yaml:"version"`
	AckedThrough time.Time `yaml:"acked_through"`
}

func ReadAlerts(dir string, since time.Time) ([]logs.Alert, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "alerts-*.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("reading alerts: %w", err)
	}

	first := since.UTC().Format(time.DateOnly)
	out := []logs.Alert{}
	for _, path := range paths {
		day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "alerts-"), ".jsonl")
		if _, err := time.Parse(time.DateOnly, day); err != nil || day < first {
			continue
		}

		alerts, err := readAlertFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading alerts: %w", err)
		}
		out = append(out, alerts...)
	}

	slices.SortStableFunc(out, func(a, b logs.Alert) int { return a.Time.Compare(b.Time) })

	return out, nil
}

func LoadAck(path string) (Ack, error) {
	ack, err := config.Load[Ack](path, ackVersion, nil)
	if errors.Is(err, fs.ErrNotExist) {
		return Ack{Version: ackVersion}, nil
	}
	if err != nil {
		return Ack{}, fmt.Errorf("loading alert ack: %w", err)
	}

	return ack, nil
}

func Unacknowledged(alerts []logs.Alert, ackedThrough time.Time) []logs.Alert {
	out := []logs.Alert{}
	for _, a := range alerts {
		serious := a.Severity == logs.SeverityHigh || a.Severity == logs.SeverityMedium
		if serious && !a.Guard && a.Time.After(ackedThrough) {
			out = append(out, a)
		}
	}

	return out
}

func readAlertFile(path string) ([]logs.Alert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []logs.Alert
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, maxAlertLine)
	for scanner.Scan() {
		var a logs.Alert
		if json.Unmarshal(scanner.Bytes(), &a) == nil {
			out = append(out, a)
		}
	}

	return out, scanner.Err()
}
