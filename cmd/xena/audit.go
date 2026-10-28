package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/audit"
	"github.com/tahardi/xena/internal/config"
)

type auditDeps struct {
	Checks []audit.Check
	Manual []string
	Dir    string
	Out    io.Writer
}

func runAudit(ctx context.Context, args []string, logger *slog.Logger) error {
	deps, err := defaultAuditDeps(ctx)
	if err != nil {
		return err
	}
	return runAuditWith(ctx, args, logger, deps)
}

func runAuditWith(ctx context.Context, args []string, logger *slog.Logger, deps auditDeps) error {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	asJSON := flags.Bool("json", false, "print the report as JSON")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing audit flags: %w", err)
	}

	report, err := audit.NewRunner(deps.Checks, deps.Manual, deps.Dir, time.Now).Run(ctx)
	if err != nil && !errors.Is(err, audit.ErrDrift) {
		return err
	}

	logger.Info("audit finished", "drift", report.Drift, "skipped", len(report.Skipped))

	if *asJSON {
		enc := json.NewEncoder(deps.Out)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(report); encErr != nil {
			return fmt.Errorf("printing audit report: %w", encErr)
		}
		return err
	}

	if printErr := printAuditReport(deps.Out, report); printErr != nil {
		return fmt.Errorf("printing audit report: %w", printErr)
	}
	return err
}

func printAuditReport(out io.Writer, report audit.Report) error {
	var b strings.Builder
	if report.Drift == 0 {
		b.WriteString("audit: no drift\n")
	}

	for _, f := range report.Findings {
		fmt.Fprintf(&b, "%s %s: %s\n  fix: %s\n", strings.ToUpper(f.Severity), f.Check, f.Message, f.Fix)
	}

	for _, name := range report.Skipped {
		fmt.Fprintf(&b, "skipped: %s\n", name)
	}

	for _, line := range report.Manual {
		fmt.Fprintf(&b, "manual: %s\n", line)
	}

	_, err := io.WriteString(out, b.String())
	return err
}

func defaultAuditDeps(_ context.Context) (auditDeps, error) {
	cfg, err := audit.LoadConfig(filepath.Join(config.ConfigDir(), "audit.yaml"))
	if err != nil {
		return auditDeps{}, err
	}

	vm, err := config.LoadVM(filepath.Join(config.ConfigDir(), "vm.yaml"))
	if err != nil {
		return auditDeps{}, err
	}

	current, err := user.Current()
	if err != nil {
		return auditDeps{}, fmt.Errorf("reading current user: %w", err)
	}

	paths := audit.Paths{
		Root:          "/",
		Home:          current.HomeDir,
		User:          current.Username,
		ProxyStateDir: config.ProxyStateDir(),
	}
	bridge := net.JoinHostPort(vm.Network.BridgeAddress, strconv.Itoa(vm.ProxyPort))
	return auditDeps{
		Checks: audit.DesktopChecks(cfg, audit.OSCommander{}, paths, bridge),
		Dir:    filepath.Join(config.StateDir(), "audit"),
		Out:    os.Stdout,
	}, nil
}
