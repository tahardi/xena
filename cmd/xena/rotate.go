package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/tahardi/xena/internal/inventory"
	"github.com/tahardi/xena/internal/secrets"
)

const (
	rotateAttempts = 6
	rotateWait     = 10 * time.Second
	jiraTimeout    = 30 * time.Second
)

var errRotateUsage = errors.New("usage: xena rotate NAME")

func runRotate(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) != 1 {
		return errRotateUsage
	}
	name := args[0]

	inv, err := inventory.Load(inventoryPath())
	if err != nil {
		return fmt.Errorf("loading inventory: %w", err)
	}

	tok, err := inv.Find(name)
	if err != nil {
		return err
	}

	jira := inventory.JiraToken{
		In:   bufio.NewReader(in),
		Out:  out,
		HTTP: &http.Client{Timeout: jiraTimeout},
	}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		jira.ReadHidden = func() ([]byte, error) { return term.ReadPassword(int(f.Fd())) }
	}

	rotators := map[string]inventory.Rotator{
		"aws-grant":      inventory.AWSKey{Cmd: inventory.Exec{}},
		"gcp-grant":      inventory.GCPKey{Cmd: inventory.Exec{}},
		"jira-bot-token": jira,
	}
	rot, ok := rotators[name]
	if !ok {
		_, err := fmt.Fprintf(out, "No scripted rotation for %s. Manual steps:\n%s\n", name, tok.Rotate)
		return err
	}

	store, err := secrets.NewDefaultStore()
	if err != nil {
		return fmt.Errorf("building secrets store: %w", err)
	}

	rotation := inventory.Rotation{
		Store:     store,
		Inventory: inventoryPath(),
		Now:       time.Now,
		Sleep:     inventory.Sleep,
		Attempts:  rotateAttempts,
		Wait:      rotateWait,
	}
	if err := rotation.Run(ctx, name, rot); err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, "rotated", name)
	return err
}
