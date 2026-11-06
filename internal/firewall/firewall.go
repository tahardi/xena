package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/tahardi/xena/internal/config"
)

const maxPort = 65535

var (
	ErrInvalidAddress = errors.New("invalid address")
	ErrInvalidPort    = errors.New("invalid port")
	ErrInvalidTTL     = errors.New("invalid ttl")
)

type execFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

type Firewall struct {
	nft string
	run execFunc
}

func NewFirewall(nft string) *Firewall {
	return &Firewall{nft: nft, run: runCommand}
}

func (f *Firewall) Cut(ctx context.Context, vmAddr string) error {
	if err := checkAddress(vmAddr); err != nil {
		return err
	}

	element := fmt.Sprintf("{ %s }", vmAddr)
	if _, err := f.run(ctx, f.nft, "add", "element", "inet", "xena", "cut", element); err != nil {
		return fmt.Errorf("cutting vm network: %w", err)
	}

	if err := f.flushExposed(ctx); err != nil {
		return fmt.Errorf("cutting vm network: %w", err)
	}

	return nil
}

func (f *Firewall) Resume(ctx context.Context, vmAddr string) error {
	if err := checkAddress(vmAddr); err != nil {
		return err
	}

	out, err := f.run(ctx, f.nft, "--json", "list", "set", "inet", "xena", "cut")
	if err != nil {
		return fmt.Errorf("listing cut set: %w", err)
	}

	listed, err := parseCutSet(out)
	if err != nil {
		return err
	}

	if !slices.Contains(listed, vmAddr) {
		return nil
	}

	element := fmt.Sprintf("{ %s }", vmAddr)
	if _, err := f.run(ctx, f.nft, "delete", "element", "inet", "xena", "cut", element); err != nil {
		return fmt.Errorf("resuming vm network: %w", err)
	}

	return nil
}

func (f *Firewall) IsCut(_ context.Context, vmAddr string) (bool, error) {
	if err := checkAddress(vmAddr); err != nil {
		return false, err
	}

	_, err := os.Stat(config.CutMarker())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("checking cut marker: %w", err)
	}

	return true, nil
}

func (f *Firewall) Expose(ctx context.Context, port int, from, vmAddr string, ttl time.Duration) error {
	if err := checkPort(port); err != nil {
		return err
	}

	if err := checkAddress(from); err != nil {
		return err
	}

	if err := checkAddress(vmAddr); err != nil {
		return err
	}

	if ttl < time.Second {
		return fmt.Errorf("checking ttl %s: %w", ttl, ErrInvalidTTL)
	}

	seconds := int64(ttl / time.Second)
	element := fmt.Sprintf("{ %s . %d timeout %ds : %s . %d }", from, port, seconds, vmAddr, port)
	if _, err := f.run(ctx, f.nft, "add", "element", "inet", "xena", "exposed", element); err != nil {
		return fmt.Errorf("exposing port %d: %w", port, err)
	}

	return nil
}

func (f *Firewall) Unexpose(ctx context.Context, port int) error {
	if err := checkPort(port); err != nil {
		return err
	}

	out, err := f.run(ctx, f.nft, "--json", "list", "map", "inet", "xena", "exposed")
	if err != nil {
		return fmt.Errorf("unexposing port %d: %w", port, err)
	}

	keys, err := parseExposed(out)
	if err != nil {
		return err
	}

	for _, key := range keys {
		if key.port != port {
			continue
		}

		element := fmt.Sprintf("{ %s . %d }", key.from, key.port)
		if _, err := f.run(ctx, f.nft, "delete", "element", "inet", "xena", "exposed", element); err != nil {
			return fmt.Errorf("unexposing port %d: %w", port, err)
		}
	}

	return nil
}

func (f *Firewall) UnexposeAll(ctx context.Context) error {
	if err := f.flushExposed(ctx); err != nil {
		return fmt.Errorf("unexposing all ports: %w", err)
	}

	return nil
}

func (f *Firewall) flushExposed(ctx context.Context) error {
	_, err := f.run(ctx, f.nft, "flush", "map", "inet", "xena", "exposed")

	return err
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func checkAddress(addr string) error {
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("checking address %q: %w", addr, ErrInvalidAddress)
	}

	return nil
}

func checkPort(port int) error {
	if port < 1 || port > maxPort {
		return fmt.Errorf("checking port %d: %w", port, ErrInvalidPort)
	}

	return nil
}
