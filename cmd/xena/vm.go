package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
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
	manualRotate = "Rotate by hand now: the Jira bot token (xena rotate jira-bot-token) and the VM Claude login " +
		"(/logout, then /login in a VM session)."
	snapshotWarning = "A snapshot can hold a compromise. Rebuild with make vm for a clean reset."
)

var errMissingSnapshotName = errors.New("missing snapshot name")

type tokendRotator struct {
	out io.Writer
}

func newTokendRotator(out io.Writer) *tokendRotator {
	return &tokendRotator{out: out}
}

func (r *tokendRotator) RotateVMTokens(ctx context.Context) error {
	if _, err := fmt.Fprintln(r.out, snapshotWarning+"\n"+manualRotate); err != nil {
		return err
	}

	if err := exec.CommandContext(ctx, "systemctl", "--user", "restart", "xena-tokend.service").Run(); err != nil {
		return fmt.Errorf("restarting xena-tokend: %w", err)
	}

	return nil
}

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

	store, err := secrets.NewDefaultStore()
	if err != nil {
		return nil, fmt.Errorf("building secrets store: %w", err)
	}

	return vm.NewMachine(
		cfg,
		config.VMDir(),
		filepath.Join(config.ConfigDir(), "known_hosts"),
		filepath.Join(home, ".ssh", "id_ed25519_sk.pub"),
		filepath.Join(home, ".ssh", "id_ed25519_sk_backup.pub"),
		filepath.Join(home, ".ssh", "id_ed25519_sk_carry.pub"),
		newTouchStore(store, notify.Desktop{Run: notify.ExecRun}, "unlock the VM disk", os.Stderr, logger),
		newTokendRotator(os.Stderr),
		vmPollEvery,
		logger,
	), nil
}
