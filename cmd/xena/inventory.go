package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/inventory"
	"github.com/tahardi/xena/internal/secrets"
)

var errInventoryUsage = errors.New("usage: xena inventory check [--file-cards]")

func inventoryPath() string {
	return filepath.Join(config.ConfigDir(), "inventory.yaml")
}

func runInventory(ctx context.Context, args []string, home string, out io.Writer) error {
	if len(args) == 0 || args[0] != "check" || len(args) > 2 || (len(args) == 2 && args[1] != "--file-cards") {
		return errInventoryUsage
	}

	inv, err := inventory.Load(inventoryPath())
	if err != nil {
		return fmt.Errorf("loading inventory: %w", err)
	}

	store, err := secrets.NewDefaultStore()
	if err != nil {
		return fmt.Errorf("building secrets store: %w", err)
	}

	names, err := store.List()
	if err != nil {
		return err
	}

	found, err := inventory.Found(names, home)
	if err != nil {
		return err
	}

	findings := inventory.Check(inv, found, today())
	for _, f := range findings {
		if err := printFinding(out, f); err != nil {
			return err
		}
	}

	if len(args) == 1 {
		return nil
	}

	jira := inventory.JiraScript{
		Python:  "python3",
		Script:  expandHome(inv.Settings.JiraScript, home),
		Project: inv.Settings.JiraProject,
	}
	filed, err := inventory.FileCards(ctx, jira, inv, findings)
	for _, summary := range filed {
		if _, printErr := fmt.Fprintln(out, "filed", summary); printErr != nil {
			return printErr
		}
	}

	return err
}

func expandHome(path, home string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return filepath.Join(home, rest)
	}

	return path
}

func today() time.Time {
	y, m, d := time.Now().Date()

	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func printFinding(out io.Writer, f inventory.Finding) error {
	token := f.Token
	if token == "" {
		token = "-"
	}

	_, err := fmt.Fprintln(out, strings.TrimSpace(f.Kind+" "+token+" "+f.Detail))
	return err
}
