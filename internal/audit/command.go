package audit

import (
	"context"
	"fmt"
	"os/exec"
)

type Commander interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type OSCommander struct{}

func (OSCommander) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("running %s: %w", name, err)
	}
	return out, nil
}
