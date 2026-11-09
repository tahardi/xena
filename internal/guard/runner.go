package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
)

const (
	reportVersion = 1
	reportFile    = "last.json"
	reportMode    = 0o600
	reportDirMode = 0o700
	windowLength  = 15 * time.Minute
)

var (
	ErrFailed      = errors.New("guard cases failed")
	ErrUnknownCase = errors.New("unknown guard case")
)

type Report struct {
	Version int       `json:"version"`
	Started time.Time `json:"started"`
	LastRun time.Time `json:"last_run"`
	Passed  bool      `json:"passed"`
	Cases   []Result  `json:"cases"`
}

func (r Report) LogTime() time.Time {
	return r.LastRun
}

func (r Report) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("version", r.Version),
		slog.Time("started", r.Started),
		slog.Time("last_run", r.LastRun),
		slog.Bool("passed", r.Passed),
		slog.Any("cases", r.Cases),
	)
}

type Runner struct {
	cases     []Case
	env       Env
	reportDir string
	windowDir string
}

func NewRunner(cases []Case, env Env, reportDir, windowDir string) *Runner {
	return &Runner{cases: cases, env: env, reportDir: reportDir, windowDir: windowDir}
}

func (r *Runner) Run(ctx context.Context) (report Report, err error) {
	env := r.env
	env.RunStarted = env.Now()

	if targets := r.targets(); len(targets) > 0 {
		window := Window{
			Start:   env.RunStarted,
			End:     env.RunStarted.Add(windowLength),
			VMAddr:  env.VMAddr,
			Targets: targets,
		}
		if err := WriteWindow(r.windowDir, window); err != nil {
			failed := Report{
				Version: reportVersion,
				Started: env.RunStarted,
				LastRun: env.Now(),
				Cases:   []Result{Fail("guard-window", err.Error())},
			}

			// The report must be saved even after the run's context ends, and logs.Writer.Write takes no context.
			return failed, errors.Join(err, r.save(failed)) //nolint:contextcheck
		}

		defer func() {
			err = errors.Join(err, RemoveWindow(r.windowDir))
		}()
	}

	report = Report{
		Version: reportVersion,
		Started: env.RunStarted,
		Passed:  true,
		Cases:   make([]Result, 0, len(r.cases)),
	}

	for _, c := range r.cases {
		result := c.Run(ctx, env)
		report.Cases = append(report.Cases, result)
		report.Passed = report.Passed && result.Passed
	}

	report.LastRun = env.Now()

	// The report must be saved even after the run's context ends, and logs.Writer.Write takes no context.
	if err := r.save(report); err != nil { //nolint:contextcheck
		return report, err
	}

	if !report.Passed {
		return report, ErrFailed
	}

	return report, nil
}

func (r *Runner) targets() []string {
	var targets []string
	for _, c := range r.cases {
		if t, ok := c.(Targeter); ok {
			targets = append(targets, t.Targets()...)
		}
	}

	slices.Sort(targets)

	return slices.Compact(targets)
}

func (r *Runner) save(report Report) error {
	if r.reportDir == "" {
		return nil
	}

	if err := os.MkdirAll(r.reportDir, reportDirMode); err != nil {
		return fmt.Errorf("writing guard report: %w", err)
	}

	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("writing guard report: %w", err)
	}

	if err := config.WriteAtomic(filepath.Join(r.reportDir, reportFile), data, reportMode); err != nil {
		return fmt.Errorf("writing guard report: %w", err)
	}

	history := logs.Writer{Dir: r.reportDir, Name: "guard", Now: r.env.Now}
	if err := history.Write(report); err != nil {
		return fmt.Errorf("appending guard history: %w", err)
	}

	return nil
}

func Select(cases []Case, names []string) ([]Case, error) {
	if len(names) == 0 {
		return cases, nil
	}

	selected := make([]Case, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(cases, func(c Case) bool { return c.Name() == name })
		if i < 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnknownCase, name)
		}

		selected = append(selected, cases[i])
	}

	return selected, nil
}
