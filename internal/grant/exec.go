package grant

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/tahardi/xena/internal/inventory"
)

type Exec struct {
	inventory.Exec
}

func (Exec) Start(ctx context.Context, stdin []byte, name string, args ...string) error {
	// #nosec G204 -- name and args are fixed by Granter and never hold secret values.
	cmd := exec.CommandContext(context.WithoutCancel(ctx), name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	w, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("opening stdin for %s: %w", name, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", name, err)
	}

	_, writeErr := w.Write(stdin)
	closeErr := w.Close()
	releaseErr := cmd.Process.Release()

	return errors.Join(writeErr, closeErr, releaseErr)
}
