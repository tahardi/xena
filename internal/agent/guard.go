package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func (a *Agent) runGuard(ctx context.Context, name string) (int, error) {
	script := filepath.Join(a.guardDir, name+".sh")

	info, err := os.Stat(script)
	if err != nil || !info.Mode().IsRegular() {
		return result(ErrRefusedVerb)
	}

	// #nosec G204 -- a.bash is fixed in main, and name matched ^[a-z0-9-]+$ and names an existing file in guardDir.
	cmd := exec.CommandContext(ctx, a.bash, "--noprofile", "--norc", script)
	cmd.Dir = a.home
	cmd.Env = []string{"HOME=" + a.home, cleanPath}
	cmd.Stdin = a.stdin
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr

	err = cmd.Run()

	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode(), nil
	}

	if err != nil {
		return result(fmt.Errorf("running guard %s: %w", name, err))
	}

	return codeOK, nil
}
