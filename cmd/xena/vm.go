package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/notify"
	"github.com/tahardi/xena/internal/secrets"
	"github.com/tahardi/xena/internal/vm"
	"github.com/tahardi/xena/internal/vmexec"
)

const (
	vmPollEvery  = 5 * time.Second
	snapshotArgs = 2
)

var (
	errMissingSnapshotName = errors.New("missing snapshot name")
	errUnexpectedArgument  = errors.New("unexpected argument")
)

func runVM(ctx context.Context, args []string, logger *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: vm", errUnknownCommand)
	}

	sub := args[0]
	switch sub {
	case "build", "start", "stop", "destroy":
	case "provision":
		if len(args) != 1 {
			return fmt.Errorf("checking arguments: %w: %s", errUnexpectedArgument, args[1])
		}
	case "snapshot", "restore":
		if len(args) != snapshotArgs {
			return fmt.Errorf("checking arguments: %w", errMissingSnapshotName)
		}
	default:
		return fmt.Errorf("%w: vm %s", errUnknownCommand, sub)
	}

	cfg, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return err
	}

	m, err := newMachine(cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	switch sub {
	case "build":
		err = buildVM(ctx, m, cfg, logger)
	case "provision":
		err = provisionVM(ctx, m, cfg, logger)
	case "start":
		err = m.Start(ctx)
	case "stop":
		syncBeforeStop(ctx, m, newStopPuller(logger), os.Stderr, stopSyncTimeout)
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

func newMachine(cfg config.VM, logger *slog.Logger) (*vm.Machine, error) {
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

func buildVM(ctx context.Context, m *vm.Machine, cfg config.VM, logger *slog.Logger) error {
	start := time.Now()

	if err := m.Build(ctx, &http.Client{}, start); err != nil {
		return err
	}

	if err := provisionVM(ctx, m, cfg, logger); err != nil {
		return err
	}

	_, err := fmt.Fprintf(os.Stdout, "vm ready in %s\n", time.Since(start).Round(time.Second))
	return err
}

func provisionVM(ctx context.Context, m *vm.Machine, cfg config.VM, logger *slog.Logger) error {
	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("provisioning vm: %w", err)
	}

	if state != vm.StateRunning {
		return fmt.Errorf("provisioning vm: %w", vm.ErrNotRunning)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("finding home directory: %w", err)
	}

	sshConfig := filepath.Join(config.ConfigDir(), "ssh_config")
	err = vm.WriteSSHConfig(
		sshConfig,
		cfg.Network.VMAddress,
		filepath.Join(home, ".ssh", "id_ed25519_sk"),
		filepath.Join(config.ConfigDir(), "known_hosts"),
		config.ConfigDir(),
	)
	if err != nil {
		return err
	}

	agent, err := vmexec.Default()
	if err != nil {
		return fmt.Errorf("building vm runner: %w", err)
	}

	var restorer vm.MemoryRestorer
	if _, err = os.Stat(filepath.Join(config.StateDir(), "memory", "reviewed")); err == nil {
		deps, err := defaultMemoryDeps(logger)
		if err != nil {
			return err
		}

		restorer = newMemorySync(deps)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking reviewed memory: %w", err)
	}

	jira, err := newSecretTouchStore("read the Jira bot token", logger)
	if err != nil {
		return err
	}

	p := vm.NewProvisioner(cfg, sshConfig, agent, jira, restorer, os.Stderr, vmPollEvery, logger)
	return p.Provision(ctx)
}

func newDiskKeyStore(logger *slog.Logger) (*touchStore, error) {
	return newSecretTouchStore("unlock the VM disk", logger)
}

func newSecretTouchStore(reason string, logger *slog.Logger) (*touchStore, error) {
	store, err := secrets.NewDefaultStore()
	if err != nil {
		return nil, fmt.Errorf("building secrets store: %w", err)
	}

	store.Prompt = nil

	return newTouchStore(store, notify.Desktop{Run: notify.ExecRun}, reason, os.Stderr, logger), nil
}
