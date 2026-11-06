package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/firewall"
)

const (
	nftPath        = "/usr/sbin/nft"
	markerMode     = 0o644
	firewallCut    = "cut"
	firewallResume = "resume"
)

func runFirewall(ctx context.Context, args []string, logger *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: firewall", errUnknownCommand)
	}

	if args[0] != firewallCut && args[0] != firewallResume {
		return fmt.Errorf("%w: firewall %s", errUnknownCommand, args[0])
	}

	vm, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return err
	}

	return applyFirewall(ctx, firewall.NewFirewall(nftPath), args[0], vm.Network.VMAddress, logger)
}

func applyFirewall(
	ctx context.Context,
	fw *firewall.Firewall,
	verb string,
	vmAddr string,
	logger *slog.Logger,
) error {
	if verb == firewallCut {
		return cutNetwork(ctx, fw, vmAddr, logger)
	}

	return resumeNetwork(ctx, fw, vmAddr, logger)
}

func cutNetwork(ctx context.Context, fw *firewall.Firewall, vmAddr string, logger *slog.Logger) error {
	if err := fw.Cut(ctx, vmAddr); err != nil {
		return err
	}

	stamp := time.Now().UTC().Format(time.RFC3339) + "\n"
	// The marker holds no secret and must be world-readable so IsCut works without root.
	if err := os.WriteFile(config.CutMarker(), []byte(stamp), markerMode); err != nil { //nolint:gosec
		return fmt.Errorf("writing cut marker: %w", err)
	}

	logger.InfoContext(ctx, "vm network cut")

	return nil
}

func resumeNetwork(ctx context.Context, fw *firewall.Firewall, vmAddr string, logger *slog.Logger) error {
	if err := fw.Resume(ctx, vmAddr); err != nil {
		return err
	}

	if err := os.Remove(config.CutMarker()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing cut marker: %w", err)
	}

	logger.InfoContext(ctx, "vm network resumed")

	return nil
}
