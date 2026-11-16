package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

const (
	manualRotate = "Rotate by hand now: the Jira bot token (xena rotate jira-bot-token) and the VM Claude login " +
		"(/logout, then /login in a VM session)."
	snapshotWarning = "A snapshot can hold a compromise. Rebuild with make vm for a clean reset."
	tokendTouch     = "xena-tokend restarted and asks for its own touch now (to unlock the GitHub token service). " +
		"Touch for it before you start the VM."
)

type tokendRotator struct {
	out     io.Writer
	restart func(ctx context.Context) error
}

func newTokendRotator(out io.Writer) *tokendRotator {
	return &tokendRotator{out: out, restart: restartTokend}
}

func restartTokend(ctx context.Context) error {
	return exec.CommandContext(ctx, "systemctl", "--user", "restart", "xena-tokend.service").Run()
}

func (r *tokendRotator) RotateVMTokens(ctx context.Context) error {
	if _, err := fmt.Fprintln(r.out, snapshotWarning+"\n"+manualRotate); err != nil {
		return err
	}

	if err := r.restart(ctx); err != nil {
		return fmt.Errorf("restarting xena-tokend: %w", err)
	}

	_, err := fmt.Fprintln(r.out, tokendTouch)

	return err
}
