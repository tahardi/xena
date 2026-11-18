package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/tahardi/xena/internal/memory"
)

type memoryPuller interface {
	Pull(ctx context.Context, force bool) (memory.Result, error)
}

type vmStater interface {
	State(ctx context.Context) (string, error)
}

func syncBeforeStop(
	ctx context.Context,
	vm vmStater,
	newPuller func() (memoryPuller, error),
	warn io.Writer,
) {
	state, err := vm.State(ctx)
	if err == nil && state != "running" {
		return
	}

	puller, err := newPuller()
	if err == nil {
		_, err = puller.Pull(ctx, false)
	}

	if err != nil {
		_, _ = fmt.Fprintf(warn, "warning: memory sync failed: %v\n", err)
	}
}

func newStopPuller(logger *slog.Logger) func() (memoryPuller, error) {
	return func() (memoryPuller, error) {
		deps, err := defaultMemoryDeps(logger)
		if err != nil {
			return nil, err
		}

		return newMemorySync(deps), nil
	}
}
