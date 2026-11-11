package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/notify"
	"github.com/tahardi/xena/internal/secrets"
)

const pollInterval = 2 * time.Second

var errInvalidPromptTimeout = errors.New("must be positive")

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], logger)
	stop()

	if err != nil {
		logger.Error("running xena-prompt", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("xena-prompt", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	socket := flags.String("socket", config.PromptSocket(), "path of the proxy's prompt socket")
	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	vm, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return err
	}

	if vm.PromptTimeoutSeconds <= 0 {
		return fmt.Errorf("checking prompt timeout: %w", errInvalidPromptTimeout)
	}

	store, err := secrets.NewDefaultStore()
	if err != nil {
		return fmt.Errorf("building secrets store: %w", err)
	}

	store.KillGroup = !term.IsTerminal(int(os.Stdin.Fd()))

	desktop := notify.Desktop{Run: notify.ExecRun}
	client := notify.PromptClient{
		Desktop: desktop,
		Touch:   store,
		Timeout: time.Duration(vm.PromptTimeoutSeconds) * time.Second,
		Logger:  logger,
	}

	follower, err := notify.NewAlertFollower(config.WatchStateDir(), desktop)
	if err != nil {
		return err
	}

	go func() { _ = client.Run(ctx, *socket) }()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := follower.Poll(ctx); err != nil {
				logger.Warn("polling alerts", "error", err)
			}
		}
	}
}
