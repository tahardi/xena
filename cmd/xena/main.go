package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tahardi/xena/internal/secrets"
)

var (
	errNoCommand      = errors.New("no command")
	errUnknownCommand = errors.New("unknown command")
	version           = "dev"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], logger)
	stop()
	if err != nil {
		logger.Error("running xena", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, _ *slog.Logger) error {
	if len(args) == 0 {
		return errNoCommand
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintln(os.Stdout, version)
		return err
	case "secrets":
		store, err := secrets.Default()
		if err != nil {
			return fmt.Errorf("building secrets store: %w", err)
		}

		return runSecrets(ctx, store, args[1:], os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("%w: %s", errUnknownCommand, args[0])
	}
}
