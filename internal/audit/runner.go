package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
)

const (
	ReportVersion = 1

	dirMode    = 0o700
	reportMode = 0o600
	checkFix   = "Fix whatever stops the check from running, then run xena audit again."
)

var ErrDrift = errors.New("audit found drift")

type Report struct {
	Version  int       `json:"version"`
	Started  time.Time `json:"started"`
	LastRun  time.Time `json:"last_run"`
	Drift    int       `json:"drift"`
	Findings []Finding `json:"findings"`
	Skipped  []string  `json:"skipped"`
	Manual   []string  `json:"manual"`
}

func (r Report) LogTime() time.Time {
	return r.LastRun
}

func (r Report) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Time("started", r.Started),
		slog.Int("drift", r.Drift),
		slog.Any("findings", r.Findings),
		slog.Any("skipped", r.Skipped),
		slog.Any("manual", r.Manual),
	)
}

type Runner struct {
	checks []Check
	manual []string
	dir    string
	now    func() time.Time
}

func NewRunner(checks []Check, manual []string, dir string, now func() time.Time) *Runner {
	return &Runner{checks: checks, manual: manual, dir: dir, now: now}
}

func (r *Runner) Run(ctx context.Context) (Report, error) {
	report := Report{
		Version:  ReportVersion,
		Started:  r.now(),
		Findings: []Finding{},
		Skipped:  []string{},
		Manual:   append([]string{}, r.manual...),
	}

	for _, check := range r.checks {
		report.Findings = append(report.Findings, runCheck(ctx, check, &report)...)
	}

	report.LastRun = r.now()
	report.Drift = len(report.Findings)

	// logs.Writer.Write takes no context.
	if err := r.write(report); err != nil { //nolint:contextcheck
		return report, err
	}

	if report.Drift > 0 {
		return report, ErrDrift
	}
	return report, nil
}

func (r *Runner) write(report Report) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("writing audit report: %w", err)
	}

	if err := os.MkdirAll(r.dir, dirMode); err != nil {
		return fmt.Errorf("writing audit report: %w", err)
	}
	if err := config.WriteAtomic(filepath.Join(r.dir, "last.json"), data, reportMode); err != nil {
		return fmt.Errorf("writing audit report: %w", err)
	}

	history := &logs.Writer{Dir: r.dir, Name: "audit", Now: report.LogTime}
	if err := history.Write(report); err != nil {
		return fmt.Errorf("appending audit history: %w", err)
	}
	return nil
}

func runCheck(ctx context.Context, check Check, report *Report) []Finding {
	findings, err := check.Run(ctx)
	if errors.Is(err, ErrSkipped) {
		report.Skipped = append(report.Skipped, check.Name())
		err = nil
	}

	if err != nil {
		findings = append(findings, Finding{
			Severity: logs.SeverityHigh,
			Message:  fmt.Sprintf("check failed: %v", err),
			Fix:      checkFix,
		})
	}

	for i := range findings {
		findings[i].Check = check.Name()
	}
	return findings
}
