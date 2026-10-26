package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func (a Agent) runGuard(ctx context.Context, name string) (int, error) {
	script := filepath.Join(a.GuardDir, name+".sh")

	info, err := os.Stat(script)
	if err != nil || !info.Mode().IsRegular() {
		return result(ErrRefusedVerb)
	}

	// #nosec G204 -- a.Bash is fixed in main, and name matched ^[a-z0-9-]+$ and names an existing file in GuardDir.
	cmd := exec.CommandContext(ctx, a.Bash, "--noprofile", "--norc", script)
	cmd.Dir = a.Home
	cmd.Env = []string{"HOME=" + a.Home, cleanPath}
	cmd.Stdin = a.Stdin
	cmd.Stdout = a.Stdout
	cmd.Stderr = a.Stderr

	err = cmd.Run()

	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode(), nil
	}

	if err != nil {
		return result(fmt.Errorf("running guard %s: %w", name, err))
	}

	return codeOK, nil
}
