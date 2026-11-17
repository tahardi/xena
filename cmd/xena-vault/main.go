package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/vault"
)

const (
	listenUmask  = 0o077
	runUmask     = 0o027
	stateDirMode = 0o700
	socketMode   = 0o600
	rate         = 10
	burst        = 10
)

var (
	version      = "dev"
	errNonSocket = errors.New("refusing to remove non-socket")
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], logger)
	stop()

	if err != nil {
		logger.Error("running xena-vault", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("xena-vault", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	bin := flags.String("anchorhold", "anchorhold", "anchorhold binary to run")
	socket := flags.String("socket", filepath.Join(config.StateDir(), "vault.sock"), "path of the gateway socket")
	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	notes := vault.Anchorhold{Bin: *bin}
	root, err := notes.Root(ctx)
	if err != nil {
		return err
	}

	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolving vault root: %w", err)
	}

	ln, err := listen(ctx, *socket)
	if err != nil {
		return err
	}

	server := &vault.Server{
		Policy:  vault.NewPolicy(resolved),
		Notes:   notes,
		Log:     &logs.Writer{Dir: config.GatewayLogDir(), Name: "vault"},
		Limit:   vault.NewBucket(rate, burst, time.Now),
		Now:     time.Now,
		Version: version,
		Logger:  logger,
	}

	logger.Info("serving vault gateway", "socket", *socket)
	return server.Serve(ctx, ln)
}

func listen(ctx context.Context, socket string) (net.Listener, error) {
	syscall.Umask(listenUmask)
	defer syscall.Umask(runUmask)

	if err := os.MkdirAll(filepath.Dir(socket), stateDirMode); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}

	info, err := os.Lstat(socket)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("checking socket: %w", err)
	case info.Mode()&fs.ModeSocket == 0:
		return nil, fmt.Errorf("%w at %s", errNonSocket, socket)
	default:
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("removing stale socket: %w", err)
		}
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listening on socket: %w", err)
	}

	if err := os.Chmod(socket, socketMode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("setting socket mode: %w", err)
	}
	return ln, nil
}
