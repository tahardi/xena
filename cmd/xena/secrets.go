package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/tahardi/xena/internal/secrets"
)

const nameArgs = 2

var errUsage = errors.New("usage: xena secrets put|verify|delete NAME, or xena secrets list")

func runSecrets(ctx context.Context, store secrets.Store, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}

	if args[0] == "list" {
		return listSecrets(store, args[1:], out)
	}

	if len(args) != nameArgs {
		return errUsage
	}

	name := args[1]
	switch args[0] {
	case "put":
		// Put keeps the card's Shared Contracts signature, which takes no context.
		return store.Put(name, in) //nolint:contextcheck
	case "verify":
		if _, err := store.Get(ctx, name); err != nil {
			return err
		}

		_, err := fmt.Fprintln(out, "ok", name)
		return err
	case "delete":
		return store.Delete(name)
	default:
		return fmt.Errorf("%w: secrets %s", errUnknownCommand, args[0])
	}
}

func listSecrets(store secrets.Store, args []string, out io.Writer) error {
	if len(args) != 0 {
		return errUsage
	}

	names, err := store.List()
	if err != nil {
		return err
	}

	for _, name := range names {
		if _, err := fmt.Fprintln(out, name); err != nil {
			return err
		}
	}

	return nil
}
