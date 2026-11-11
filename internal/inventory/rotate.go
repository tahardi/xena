package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

var ErrOldStillValid = errors.New("old credential still accepted")

type Rotator interface {
	Create(ctx context.Context, old []byte) ([]byte, error)
	Revoke(ctx context.Context, old, current []byte) error
	Rejected(ctx context.Context, old []byte) (bool, error)
}

type Store interface {
	Get(ctx context.Context, name string) ([]byte, error)
	Put(name string, value io.Reader) error
}

type Command interface {
	Output(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
}

type Exec struct{}

func (Exec) Output(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- name is a fixed CLI chosen by a rotator and args never hold secret values.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(baseEnv(env), env...)
	cmd.Stderr = os.Stderr

	return cmd.Output()
}

func baseEnv(env []string) []string {
	if len(env) == 0 {
		return os.Environ()
	}

	return slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "AWS_") || strings.HasPrefix(kv, "CLOUDSDK_")
	})
}

type Rotation struct {
	Store     Store
	Inventory string
	Now       func() time.Time
	Sleep     func(context.Context, time.Duration) error
	Attempts  int
	Wait      time.Duration
}

func (r Rotation) Run(ctx context.Context, name string, rot Rotator) error {
	inv, err := Load(r.Inventory)
	if err != nil {
		return err
	}
	if _, err := inv.Find(name); err != nil {
		return err
	}

	old, err := r.Store.Get(ctx, name)
	if err != nil {
		return fmt.Errorf("reading old %s: %w", name, err)
	}

	current, err := rot.Create(ctx, old)
	if err != nil {
		return fmt.Errorf("creating new %s: %w", name, err)
	}

	if err := r.Store.Put(name, bytes.NewReader(current)); err != nil {
		return fmt.Errorf("storing new %s: %w", name, err)
	}

	if err := r.revoke(ctx, old, current, rot); err != nil {
		return fmt.Errorf("revoking old %s, new value is stored: %w", name, err)
	}

	if err := r.waitRejected(ctx, old, rot); err != nil {
		return fmt.Errorf("verifying old %s, new value is stored: %w", name, err)
	}

	return SetRotated(r.Inventory, name, r.Now())
}

func Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting to retry: %w", ctx.Err())
	}
}

func (r Rotation) revoke(ctx context.Context, old, current []byte, rot Rotator) error {
	var err error
	for i := range r.Attempts {
		if i > 0 {
			if sleepErr := r.Sleep(ctx, r.Wait); sleepErr != nil {
				return sleepErr
			}
		}

		if err = rot.Revoke(ctx, old, current); err == nil {
			return nil
		}
	}

	return err
}

func (r Rotation) waitRejected(ctx context.Context, old []byte, rot Rotator) error {
	for i := range r.Attempts {
		if i > 0 {
			if err := r.Sleep(ctx, r.Wait); err != nil {
				return err
			}
		}

		rejected, err := rot.Rejected(ctx, old)
		if err != nil {
			return err
		}
		if rejected {
			return nil
		}
	}

	return ErrOldStillValid
}
