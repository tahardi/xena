package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/firewall"
	"github.com/tahardi/xena/internal/guard"
	"github.com/tahardi/xena/internal/vmexec"
)

const guardSettle = 5 * time.Second

type guardDeps struct {
	Env       guard.Env
	Cases     []guard.Case
	ReportDir string
	WindowDir string
	Out       io.Writer
}

func runGuard(ctx context.Context, args []string, logger *slog.Logger) error {
	deps, err := defaultGuardDeps(ctx)
	if err != nil {
		return err
	}

	return runGuardWith(ctx, args, logger, deps)
}

func runGuardWith(ctx context.Context, args []string, logger *slog.Logger, deps guardDeps) error {
	var names []string

	flags := flag.NewFlagSet("guard", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("case", "run only this guard case", func(name string) error {
		names = append(names, name)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing guard flags: %w", err)
	}

	cases, err := guard.Select(deps.Cases, names)
	if err != nil {
		return fmt.Errorf("running guard: %w", err)
	}

	reportDir := deps.ReportDir
	if len(names) > 0 {
		reportDir = ""
	}

	report, runErr := guard.NewRunner(cases, deps.Env, reportDir, deps.WindowDir).Run(ctx)

	if err := printGuardReport(deps.Out, report); err != nil {
		return fmt.Errorf("printing guard report: %w", err)
	}

	if runErr != nil {
		return fmt.Errorf("running guard: %w", runErr)
	}

	logger.Info("finished guard run", "cases", len(report.Cases))

	return nil
}

func printGuardReport(out io.Writer, report guard.Report) error {
	for _, result := range report.Cases {
		if result.Passed {
			if _, err := fmt.Fprintf(out, "PASS %s\n", result.Case); err != nil {
				return err
			}

			continue
		}

		if _, err := fmt.Fprintf(out, "FAIL %s: %s\n", result.Case, result.Error); err != nil {
			return err
		}

		for _, line := range result.Evidence {
			if _, err := fmt.Fprintf(out, "  %s\n", line); err != nil {
				return err
			}
		}
	}

	return nil
}

func defaultGuardDeps(_ context.Context) (guardDeps, error) {
	vm, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return guardDeps{}, fmt.Errorf("loading vm config: %w", err)
	}

	runner, err := vmexec.Default()
	if err != nil {
		return guardDeps{}, fmt.Errorf("loading vm config: %w", err)
	}

	return guardDeps{
		Env: guard.Env{
			VM:       runner,
			Proxy:    guard.NewProxyLog(config.ProxyStateDir(), time.Now),
			Drops:    guard.NewJournalDrops("/usr/bin/journalctl"),
			Firewall: firewall.NewFirewall("/usr/sbin/nft"),
			VMAddr:   vm.Network.VMAddress,
			Now:      time.Now,
			Settle:   guardSettle,
		},
		Cases: guard.NetworkCases(guard.NetConfig{
			BridgeAddr: vm.Network.BridgeAddress,
			ProxyPort:  vm.ProxyPort,
			Lookup:     net.DefaultResolver.LookupHost,
		}),
		ReportDir: filepath.Join(config.StateDir(), "guard"),
		WindowDir: config.GuardRunDir(),
		Out:       os.Stdout,
	}, nil
}
