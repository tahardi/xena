package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/grant"
	"github.com/tahardi/xena/internal/secrets"
	"github.com/tahardi/xena/internal/vmexec"
)

var (
	errUnknownProvider = errors.New("unknown provider")
	errGrantUsage      = errors.New(
		"usage: xena grant aws|gcp [--hours N], xena grant clear aws|gcp, or xena grant refresh gcp --until TIME",
	)
)

type grantArgs struct {
	provider string
	hours    int
	clear    bool
	refresh  bool
	until    time.Time
}

func parseGrantArgs(args []string) (grantArgs, error) {
	var a grantArgs
	if len(args) > 0 && (args[0] == "clear" || args[0] == "refresh") {
		a.clear = args[0] == "clear"
		a.refresh = args[0] == "refresh"
		args = args[1:]
	}

	if len(args) == 0 {
		return grantArgs{}, errGrantUsage
	}

	a.provider = args[0]
	if a.provider != "aws" && a.provider != "gcp" {
		return grantArgs{}, fmt.Errorf("%w: %s", errUnknownProvider, a.provider)
	}

	var until string
	flags := flag.NewFlagSet("grant", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.IntVar(&a.hours, "hours", 0, "grant length in hours")
	flags.StringVar(&until, "until", "", "refresh end time in RFC 3339")
	if err := flags.Parse(args[1:]); err != nil {
		return grantArgs{}, fmt.Errorf("parsing grant flags: %w", err)
	}

	if flags.NArg() > 0 {
		return grantArgs{}, errGrantUsage
	}

	if !a.refresh {
		return a, nil
	}

	if until == "" {
		return grantArgs{}, errGrantUsage
	}

	t, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return grantArgs{}, fmt.Errorf("parsing until: %w", err)
	}
	a.until = t

	return a, nil
}

func runGrant(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	a, err := parseGrantArgs(args)
	if err != nil {
		return err
	}

	vm, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return err
	}

	runner, err := vmexec.Default()
	if err != nil {
		return err
	}

	providers := map[string]grant.Provider{
		"aws": grant.AWS{Cmd: grant.Exec{}},
		"gcp": grant.GCP{Cmd: grant.Exec{}},
	}
	p := providers[a.provider]

	g := grant.Granter{
		Runner:       runner,
		Cmd:          grant.Exec{},
		Background:   grant.Exec{},
		Xena:         "/usr/local/bin/xena",
		Now:          time.Now,
		Sleep:        grant.Sleep,
		Log:          slog.New(slog.NewTextHandler(os.Stderr, nil)),
		DefaultHours: vm.Grant.DefaultHours,
		MaxHours:     vm.Grant.MaxHours,
	}

	switch {
	case a.clear:
		if err := g.Clear(ctx, p); err != nil {
			return err
		}

		_, err := fmt.Fprintf(out, "%s grant cleared\n", p.Name())
		return err
	case a.refresh:
		issuing, err := io.ReadAll(in)
		if err != nil {
			return fmt.Errorf("reading issuing secret: %w", err)
		}

		return g.Refresh(ctx, p, issuing, a.until)
	}

	store, err := secrets.NewDefaultStore()
	if err != nil {
		return fmt.Errorf("building secrets store: %w", err)
	}
	g.Secrets = store

	end, err := g.Grant(ctx, p, a.hours)
	if err != nil {
		return err
	}

	msg := fmt.Sprintf("%s grant delivered to the VM, expires %s", p.Name(), end.Local().Format("2006-01-02 15:04 MST"))
	if a.provider == "gcp" {
		msg += ", refreshed hourly"
	}

	_, err = fmt.Fprintln(out, msg)
	return err
}
