package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/notify"
	"github.com/tahardi/xena/internal/secrets"
	"github.com/tahardi/xena/internal/vm"
)

const (
	vmPollEvery  = 5 * time.Second
	snapshotArgs = 2
)

var errMissingSnapshotName = errors.New("missing snapshot name")

func runVM(ctx context.Context, args []string, logger *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: vm", errUnknownCommand)
	}

	sub := args[0]
	switch sub {
	case "build", "start", "stop", "destroy":
	case "snapshot", "restore":
		if len(args) != snapshotArgs {
			return fmt.Errorf("checking arguments: %w", errMissingSnapshotName)
		}
	default:
		return fmt.Errorf("%w: vm %s", errUnknownCommand, sub)
	}

	m, err := newMachine(logger)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	switch sub {
	case "build":
		err = m.Build(ctx, &http.Client{}, time.Now())
	case "start":
		err = m.Start(ctx)
	case "stop":
		err = m.Stop(ctx)
	case "destroy":
		err = m.Destroy(ctx)
	case "snapshot":
		err = m.Snapshot(ctx, args[1])
	case "restore":
		err = m.Restore(ctx, args[1])
	}
	if err != nil {
		return err
	}

	logger.Info("vm command finished", "command", sub)
	return nil
}

func newMachine(logger *slog.Logger) (*vm.Machine, error) {
	cfg, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return nil, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("finding home directory: %w", err)
	}

	store, err := newDiskKeyStore(logger)
	if err != nil {
		return nil, err
	}

	return vm.NewMachine(
		cfg,
		config.VMDir(),
		filepath.Join(config.ConfigDir(), "known_hosts"),
		filepath.Join(home, ".ssh", "id_ed25519_sk.pub"),
		filepath.Join(home, ".ssh", "id_ed25519_sk_backup.pub"),
		filepath.Join(home, ".ssh", "id_ed25519_sk_carry.pub"),
		store,
		newTokendRotator(os.Stderr),
		vmPollEvery,
		logger,
	), nil
}

func newDiskKeyStore(logger *slog.Logger) (*touchStore, error) {
	store, err := secrets.NewDefaultStore()
	if err != nil {
		return nil, fmt.Errorf("building secrets store: %w", err)
	}

	store.Prompt = nil

	return newTouchStore(store, notify.Desktop{Run: notify.ExecRun}, "unlock the VM disk", os.Stderr, logger), nil
}
