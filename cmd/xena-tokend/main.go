package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/github"
	"github.com/tahardi/xena/internal/secrets"
	"github.com/tahardi/xena/internal/tokend"
	"github.com/tahardi/xena/internal/vmexec"
)

const (
	githubAPI   = "https://api.github.com"
	httpTimeout = 30 * time.Second
	appKeyName  = "github-app-key"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], logger)
	stop()

	if err != nil {
		logger.Error("running xena-tokend", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("xena-tokend", flag.ContinueOnError)
	dryRun := flags.Bool("dry-run", false, "mint and revoke one token without touching the VM")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	cfg, err := github.LoadAppConfig(filepath.Join(config.ConfigDir(), "github-app.yaml"))
	if err != nil {
		return err
	}

	if *dryRun {
		return runDry(ctx, cfg)
	}

	runner, err := vmexec.Default()
	if err != nil {
		return err
	}

	loop := &tokend.Loop{
		Unlock: func(ctx context.Context) (tokend.Minter, error) {
			app, err := unlock(ctx, cfg, os.Stderr)
			if err != nil {
				return nil, err
			}
			return app, nil
		},
		Runner: runner,
		Now:    time.Now,
		Logger: logger,
	}

	return loop.Run(ctx)
}

func runDry(ctx context.Context, cfg github.AppConfig) error {
	app, err := unlock(ctx, cfg, os.Stderr)
	if err != nil {
		return err
	}

	tok, err := app.InstallationToken(ctx)
	if err != nil {
		return err
	}

	_, printErr := fmt.Fprintf(os.Stdout, "token expires at %s\n", tok.ExpiresAt.Format(time.RFC3339))

	if err := github.RevokeToken(ctx, app.API, tok.Value, app.HTTP); err != nil {
		return errors.Join(printErr, err)
	}

	if printErr != nil {
		return printErr
	}

	_, err = fmt.Fprintln(os.Stdout, "token revoked")
	return err
}

func unlock(ctx context.Context, cfg github.AppConfig, out io.Writer) (github.App, error) {
	_, _ = fmt.Fprintln(out, "touch your YubiKey to unlock the GitHub token service")

	_ = exec.CommandContext(ctx, "notify-send", "Xena", "Touch your YubiKey to unlock the GitHub token service").Run()

	store, err := secrets.NewDefaultStore()
	if err != nil {
		return github.App{}, fmt.Errorf("building secrets store: %w", err)
	}

	pemKey, err := store.Get(ctx, appKeyName)
	if err != nil {
		return github.App{}, err
	}

	key, err := github.ParseKey(pemKey)
	if err != nil {
		return github.App{}, err
	}

	return github.App{
		ID:             cfg.AppID,
		InstallationID: cfg.InstallationID,
		Key:            key,
		API:            githubAPI,
		HTTP:           &http.Client{Timeout: httpTimeout},
	}, nil
}
