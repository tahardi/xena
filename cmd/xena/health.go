package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/health"
	"github.com/tahardi/xena/internal/vmexec"
)

var errChecksFailed = errors.New("health checks failed")

const tablePadding = 2

func defaultChecks(logger *slog.Logger) []health.Check {
	var vmName string
	vmConfig, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		logger.Warn("loading vm config", "error", err)
	} else {
		vmName = vmConfig.Name
	}

	var runner vmexec.Runner
	vm, err := vmexec.Default()
	if err != nil {
		logger.Warn("building vm runner", "error", err)
	} else {
		runner = vm
	}

	return health.Checks(health.ExecCommand, runner, vmName, time.Now)
}

func runHealth(ctx context.Context, out io.Writer, checks []health.Check) error {
	results := health.Run(ctx, checks)
	if err := printResults(out, results); err != nil {
		return err
	}

	for _, r := range results {
		if !r.OK {
			return errChecksFailed
		}
	}

	return nil
}

func printResults(out io.Writer, results []health.Result) error {
	w := tabwriter.NewWriter(out, 0, 0, tablePadding, ' ', 0)
	for _, r := range results {
		state := "ok"
		if !r.OK {
			state = "FAIL"
		}

		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, state, r.Detail); err != nil {
			return err
		}
	}

	return w.Flush()
}
