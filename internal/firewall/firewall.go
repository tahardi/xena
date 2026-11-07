package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/config"
)

const maxPort = 65535

var flushArgs = []string{
	"flush", "map", "inet", "xena", "exposed", ";",
	"flush", "set", "inet", "xena", "forwarded",
}

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

	args := append(
		[]string{"add", "element", "inet", "xena", "cut", fmt.Sprintf("{ %s }", vmAddr), ";"},
		flushArgs...,
	)
	if _, err := f.run(ctx, f.nft, args...); err != nil {
		return fmt.Errorf("cutting vm network: %w", err)
	}

	return nil
}

func (f *Firewall) Resume(ctx context.Context, vmAddr string) error {
	if err := checkAddress(vmAddr); err != nil {
		return err
	}

	element := fmt.Sprintf("{ %s }", vmAddr)
	if _, err := f.run(ctx, f.nft, "destroy", "element", "inet", "xena", "cut", element); err != nil {
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
	args := []string{
		"add", "element", "inet", "xena", "exposed",
		fmt.Sprintf("{ %s . %d timeout %ds : %s . %d }", from, port, seconds, vmAddr, port), ";",
		"add", "element", "inet", "xena", "forwarded",
		fmt.Sprintf("{ %s . %d timeout %ds }", from, port, seconds),
	}
	if _, err := f.run(ctx, f.nft, args...); err != nil {
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

	var args []string
	for _, key := range keys {
		if key.port != port {
			continue
		}

		element := fmt.Sprintf("{ %s . %d }", key.from, key.port)
		if args != nil {
			args = append(args, ";")
		}

		args = append(
			args,
			"destroy", "element", "inet", "xena", "exposed", element, ";",
			"destroy", "element", "inet", "xena", "forwarded", element,
		)
	}

	if args == nil {
		return nil
	}

	if _, err := f.run(ctx, f.nft, args...); err != nil {
		return fmt.Errorf("unexposing port %d: %w", port, err)
	}

	return nil
}

func (f *Firewall) UnexposeAll(ctx context.Context) error {
	if _, err := f.run(ctx, f.nft, flushArgs...); err != nil {
		return fmt.Errorf("unexposing all ports: %w", err)
	}

	return nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()

	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return out, fmt.Errorf("running %s: %w: %s", name, err, strings.TrimSpace(string(exitErr.Stderr)))
	}

	return out, err
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
