package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/tahardi/xena/internal/vm"
)

type touchShower interface {
	Show(ctx context.Context, title, body string, critical bool) error
}

type touchStore struct {
	store   vm.SecretStore
	desktop touchShower
	out     io.Writer
	logger  *slog.Logger
}

func newTouchStore(store vm.SecretStore, desktop touchShower, out io.Writer, logger *slog.Logger) *touchStore {
	return &touchStore{store: store, desktop: desktop, out: out, logger: logger}
}

func (s *touchStore) Get(ctx context.Context, name string) ([]byte, error) {
	_, _ = fmt.Fprintln(s.out, "touch your YubiKey to unlock the VM disk")

	if err := s.desktop.Show(ctx, "Touch your YubiKey", "to unlock the VM disk", true); err != nil {
		s.logger.Warn("sending desktop notification", "error", err)
	}

	return s.store.Get(ctx, name)
}

func (s *touchStore) Put(name string, value io.Reader) error {
	return s.store.Put(name, value)
}
