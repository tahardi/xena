package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/github"
	"github.com/tahardi/xena/internal/inventory"
	"github.com/tahardi/xena/internal/secrets"
)

const (
	httpTimeout  = 30 * time.Second
	githubAPI    = "https://api.github.com"
	githubKeyRef = "github-app-key"
)

var (
	errRotateUsage    = errors.New("usage: xena rotate NAME [--file PEM]")
	errMissingKeyFile = errors.New("missing --file PEM for github-app-key")
)

func runRotate(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errRotateUsage
	}
	name := args[0]

	flags := flag.NewFlagSet("rotate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("file", "", "new GitHub App private key PEM")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}
	if flags.NArg() > 0 || (*file != "" && name != githubKeyRef) {
		return errRotateUsage
	}

	inv, err := inventory.Load(inventoryPath())
	if err != nil {
		return fmt.Errorf("loading inventory: %w", err)
	}

	tok, err := inv.Find(name)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(in)

	jira := inventory.JiraToken{
		In:         reader,
		Out:        out,
		HTTP:       &http.Client{Timeout: httpTimeout},
		ExpiryDays: cmp.Or(*tok.RotationDays, inventory.DefaultRotationDays),
	}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		jira.ReadHidden = func() ([]byte, error) { return term.ReadPassword(int(f.Fd())) }
	}

	rotators := map[string]inventory.Rotator{
		"aws-grant":      inventory.AWSKey{Cmd: inventory.Exec{}},
		"gcp-grant":      inventory.GCPKey{Cmd: inventory.Exec{}},
		"jira-bot-token": jira,
	}
	if name == githubKeyRef {
		key, err := githubAppKey(*file, reader, out)
		if err != nil {
			return err
		}
		rotators[githubKeyRef] = key
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
		Attempts:  inv.Settings.RetryAttempts,
		Wait:      inv.Settings.RetryWait(),
	}
	if err := rotation.Run(ctx, name, rot); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(out, "rotated", name); err != nil {
		return err
	}

	if name == githubKeyRef {
		_, err = fmt.Fprintf(out, "Run shred -u %s; it holds the key in plain text.\n", *file)
	}

	return err
}

func githubAppKey(file string, in *bufio.Reader, out io.Writer) (inventory.GitHubAppKey, error) {
	if file == "" {
		return inventory.GitHubAppKey{}, errMissingKeyFile
	}

	cfg, err := github.LoadAppConfig(filepath.Join(config.ConfigDir(), "github-app.yaml"))
	if err != nil {
		return inventory.GitHubAppKey{}, err
	}

	return inventory.GitHubAppKey{
		File:           file,
		AppID:          cfg.AppID,
		InstallationID: cfg.InstallationID,
		API:            githubAPI,
		HTTP:           &http.Client{Timeout: httpTimeout},
		Cmd:            inventory.Exec{},
		In:             in,
		Out:            out,
	}, nil
}
