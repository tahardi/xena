package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/memory"
	"github.com/tahardi/xena/internal/vmexec"
)

const reviewedArgs = 2

var errMissingDigest = errors.New("missing digest")

type memoryDeps struct {
	Runner   vmexec.Runner
	Dir      string
	Gitleaks string
	Sqlite   string
	Diff     string
	Out      io.Writer
	Now      func() time.Time
}

func runMemory(ctx context.Context, args []string) error {
	deps, err := defaultMemoryDeps()
	if err != nil {
		return err
	}

	return runMemoryWith(ctx, args, deps)
}

func defaultMemoryDeps() (memoryDeps, error) {
	runner, err := vmexec.Default()
	if err != nil {
		return memoryDeps{}, fmt.Errorf("building vm runner: %w", err)
	}

	return memoryDeps{
		Runner:   runner,
		Dir:      filepath.Join(config.StateDir(), "memory"),
		Gitleaks: "gitleaks",
		Sqlite:   "sqlite3",
		Diff:     "diff",
		Out:      os.Stdout,
		Now:      time.Now,
	}, nil
}

func newMemorySync(deps memoryDeps) *memory.Sync {
	return memory.NewSync(deps.Runner, deps.Dir, deps.Gitleaks, deps.Sqlite, deps.Now)
}

func runMemoryWith(ctx context.Context, args []string, deps memoryDeps) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: memory", errUnknownCommand)
	}

	switch args[0] {
	case "sync":
		return memorySync(ctx, args[1:], deps)
	case "diff":
		return memoryDiff(ctx, deps)
	case "reviewed":
		if len(args) != reviewedArgs {
			return fmt.Errorf("reading digest: %w", errMissingDigest)
		}

		if err := memory.MarkReviewed(deps.Dir, args[1], deps.Now()); err != nil {
			return err
		}

		_, err := fmt.Fprintln(deps.Out, "marked memory reviewed")
		return err
	case "restore":
		return memoryRestore(ctx, args[1:], deps)
	default:
		return fmt.Errorf("%w: memory %s", errUnknownCommand, args[0])
	}
}

func memorySync(ctx context.Context, args []string, deps memoryDeps) error {
	flags := flag.NewFlagSet("memory sync", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	force := flags.Bool("force", false, "replace the desktop copy even when the export is empty")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing memory sync flags: %w", err)
	}

	if _, err := deps.Runner.Run(ctx, "health", nil, nil); err != nil {
		_, err := fmt.Fprintln(deps.Out, "skipping memory sync: vm unreachable")
		return err
	}

	_, err := newMemorySync(deps).Pull(ctx, *force)
	return err
}

func memoryDiff(ctx context.Context, deps memoryDeps) error {
	unlock, err := memory.Lock(deps.Dir)
	if err != nil {
		return err
	}
	defer unlock()

	out, _, err := memory.Diff(ctx, deps.Diff, deps.Dir)
	if err != nil {
		return err
	}

	digest, err := memory.TreeDigest(filepath.Join(deps.Dir, "current"))
	if err != nil {
		return err
	}

	if _, err := deps.Out.Write(out); err != nil {
		return err
	}

	_, err = fmt.Fprintf(deps.Out, "digest: %s\n", digest)
	return err
}

func memoryRestore(ctx context.Context, args []string, deps memoryDeps) error {
	flags := flag.NewFlagSet("memory restore", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	reviewed := flags.Bool("reviewed", false, "restore the copy as of the last review")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing memory restore flags: %w", err)
	}

	if err := newMemorySync(deps).Restore(ctx, *reviewed); err != nil {
		return err
	}

	_, err := fmt.Fprintln(deps.Out, "restored memory into the vm")
	return err
}

func syncBeforeStop(ctx context.Context, warn io.Writer) {
	deps, err := defaultMemoryDeps()
	if err == nil {
		_, err = newMemorySync(deps).Pull(ctx, false)
	}

	if err != nil {
		_, _ = fmt.Fprintf(warn, "warning: memory sync failed: %v\n", err)
	}
}
