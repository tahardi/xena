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
	nftPath         = "/usr/sbin/nft"
	markerMode      = 0o644
	firewallCut     = "cut"
	firewallResume  = "resume"
	firewallReapply = "reapply"
)

var errFirewallUsage = errors.New("usage: xena firewall cut|resume|reapply")

func runFirewall(ctx context.Context, args []string, logger *slog.Logger) error {
	if len(args) != 1 || (args[0] != firewallCut && args[0] != firewallResume && args[0] != firewallReapply) {
		return errFirewallUsage
	}

	if args[0] == firewallReapply {
		cut, err := markerExists()
		if err != nil || !cut {
			return err
		}
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
	switch verb {
	case firewallCut:
		return cutNetwork(ctx, fw, vmAddr, logger)
	case firewallReapply:
		return reapplyCut(ctx, fw, vmAddr, logger)
	default:
		return resumeNetwork(ctx, fw, vmAddr, logger)
	}
}

func markerExists() (bool, error) {
	_, err := os.Stat(config.CutMarker())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("checking cut marker: %w", err)
	}

	return true, nil
}

func cutNetwork(ctx context.Context, fw *firewall.Firewall, vmAddr string, logger *slog.Logger) error {
	if err := fw.Cut(ctx, vmAddr); err != nil {
		return err
	}

	stamp := time.Now().UTC().Format(time.RFC3339) + "\n"
	// The marker holds no secret and must be world-readable so IsCut works without root.
	if err := os.WriteFile(config.CutMarker(), []byte(stamp), markerMode); err != nil { //nolint:gosec
		logger.ErrorContext(ctx, "vm network cut but cut marker not written", "error", err)
		return fmt.Errorf("writing cut marker: %w", err)
	}

	logger.InfoContext(ctx, "vm network cut")

	return nil
}

func reapplyCut(ctx context.Context, fw *firewall.Firewall, vmAddr string, logger *slog.Logger) error {
	if err := fw.Cut(ctx, vmAddr); err != nil {
		return err
	}

	logger.InfoContext(ctx, "vm network cut reapplied")

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
