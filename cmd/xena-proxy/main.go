package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tahardi/xena/internal/allowlist"
	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/proxy"
)

const (
	promptGroup = "xena-prompt"
	dialTimeout = 10 * time.Second
	maxPort     = 65535
	servers     = 2
)

var errInvalidProxyPort = errors.New("invalid proxy port")

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, logger)
	stop()

	if err != nil {
		logger.Error("running xena-proxy", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	vm, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return err
	}

	vmAddr, err := netip.ParseAddr(vm.Network.VMAddress)
	if err != nil {
		return fmt.Errorf("parsing vm address: %w", err)
	}

	bridgeAddr, err := netip.ParseAddr(vm.Network.BridgeAddress)
	if err != nil {
		return fmt.Errorf("parsing bridge address: %w", err)
	}

	if vm.ProxyPort < 1 || vm.ProxyPort > maxPort {
		return fmt.Errorf("validating proxy port %d: %w", vm.ProxyPort, errInvalidProxyPort)
	}

	base, err := allowlist.Load(filepath.Join(config.RepoConfigDir(), "allowlist.yaml"))
	if err != nil {
		return err
	}

	prompter := proxy.NewSocketPrompter(time.Duration(vm.PromptTimeoutSeconds)*time.Second, logger)

	server := proxy.NewServer(
		vmAddr,
		base,
		filepath.Join(config.ProxyStateDir(), "overlay.yaml"),
		net.DefaultResolver,
		&net.Dialer{Timeout: dialTimeout},
		prompter,
		&logs.Writer{Dir: config.ProxyStateDir(), Name: "proxy", Now: time.Now},
		logger,
	)

	if err := server.LoadOverlay(); err != nil {
		return err
	}

	promptLn, err := proxy.ListenPromptSocket(ctx, config.PromptSocket(), promptGroup)
	if err != nil {
		return err
	}

	proxyAddr := netip.AddrPortFrom(bridgeAddr, uint16(vm.ProxyPort)).String()
	proxyLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", proxyAddr)
	if err != nil {
		_ = promptLn.Close()
		return fmt.Errorf("listening on %s: %w", proxyAddr, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, servers)
	go func() { errs <- prompter.Serve(ctx, promptLn) }()
	go func() { errs <- server.Serve(ctx, proxyLn) }()

	first := <-errs
	cancel()
	return errors.Join(first, <-errs)
}
