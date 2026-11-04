package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/health"
	"github.com/tahardi/xena/internal/watch"
)

const (
	statusVersion = 1
	alertDays     = 90
	heartbeatMode = 0o640
)

type statusJSON struct {
	Version int             `json:"version"`
	Cut     bool            `json:"cut"`
	Health  []health.Result `json:"health"`
	Alerts  []statusAlert   `json:"alerts"`
	Guard   statusGuard     `json:"guard"`
	Audit   statusAudit     `json:"audit"`
}

type statusAlert struct {
	Time     time.Time `json:"time"`
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
}

type statusGuard struct {
	LastRun string `json:"last_run"`
	Passed  bool   `json:"passed"`
}

type statusAudit struct {
	LastRun string `json:"last_run"`
	Drift   int    `json:"drift"`
}

func runStatus(ctx context.Context, args []string, out io.Writer, checks []health.Check) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	asJSON := flags.Bool("json", false, "print JSON")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing status flags: %w", err)
	}

	status, err := buildStatus(
		ctx,
		health.Run(ctx, checks),
		config.CutMarker(),
		filepath.Join(config.GatewayLogDir(), "maple-session"),
		time.Now(),
	)
	if err != nil {
		return err
	}

	if *asJSON {
		return json.NewEncoder(out).Encode(status)
	}

	return printStatus(out, status)
}

func buildStatus(
	_ context.Context,
	results []health.Result,
	cutMarker string,
	heartbeat string,
	now time.Time,
) (statusJSON, error) {
	touchHeartbeat(heartbeat, now)

	status := statusJSON{
		Version: statusVersion,
		Health:  append([]health.Result{}, results...),
		Alerts:  []statusAlert{},
	}

	if _, err := os.Stat(cutMarker); err == nil {
		status.Cut = true
	}

	alerts, err := watch.ReadAlerts(config.WatchStateDir(), now.AddDate(0, 0, -alertDays))
	if err != nil {
		return statusJSON{}, err
	}

	ack, err := watch.LoadAck(filepath.Join(config.StateDir(), "alerts-ack.yaml"))
	if err != nil {
		return statusJSON{}, fmt.Errorf("reading alerts: %w", err)
	}

	for _, a := range watch.Unacknowledged(alerts, ack.AckedThrough) {
		status.Alerts = append(status.Alerts, statusAlert{Time: a.Time, Rule: a.Rule, Severity: a.Severity})
	}

	found, err := readLast(filepath.Join(config.StateDir(), "guard", "last.json"), &status.Guard)
	if err != nil {
		return statusJSON{}, fmt.Errorf("reading guard result: %w", err)
	}

	if !found {
		status.Health = append(status.Health, health.Result{Name: "guard", Detail: "never run"})
	}

	found, err = readLast(filepath.Join(config.StateDir(), "audit", "last.json"), &status.Audit)
	if err != nil {
		return statusJSON{}, fmt.Errorf("reading audit result: %w", err)
	}

	if !found {
		status.Health = append(status.Health, health.Result{Name: "audit", Detail: "never run"})
	}

	return status, nil
}

func touchHeartbeat(path string, now time.Time) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, heartbeatMode)
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = os.Chtimes(path, now, now)
	}
	if err != nil {
		slog.Warn("touching heartbeat", "path", path, "error", err)
	}
}

func readLast(path string, into any) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, json.Unmarshal(data, into)
}

func printStatus(out io.Writer, s statusJSON) error {
	if err := printResults(out, s.Health); err != nil {
		return err
	}

	lines := []string{fmt.Sprintf("cut: %t", s.Cut)}
	for _, a := range s.Alerts {
		lines = append(lines, fmt.Sprintf("alert: %s %s %s", a.Time.Format(time.RFC3339), a.Rule, a.Severity))
	}
	lines = append(
		lines,
		fmt.Sprintf("guard: last run %q, passed %t", s.Guard.LastRun, s.Guard.Passed),
		fmt.Sprintf("audit: last run %q, drift %d", s.Audit.LastRun, s.Audit.Drift),
	)

	for _, line := range lines {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}

	return nil
}
