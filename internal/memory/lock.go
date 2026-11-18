package memory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const lockRetry = 50 * time.Millisecond

func Lock(ctx context.Context, dir string) (func(), error) {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("locking memory dir: %w", err)
	}

	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("locking memory dir: %w", err)
	}

	if err := waitForLock(ctx, f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("locking memory dir: %w", err)
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func waitForLock(ctx context.Context, f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockRetry):
		}
	}
}
