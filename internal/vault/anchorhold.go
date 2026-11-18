package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	callTimeout   = 60 * time.Second
	modeCreate    = "create"
	modeOverwrite = "overwrite"
	modeAppend    = "append"
)

var (
	ErrNoteNotFound = errors.New("note not found")
	errUnknownMode  = errors.New("unknown mode")
	errMissingVault = errors.New("missing vault field")
)

type Anchorhold struct {
	Bin   string
	Slots chan struct{}
}

func (a Anchorhold) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	out, err := a.run(ctx, "", "search", "--json", "-n", strconv.Itoa(limit), "--", query)
	if err != nil {
		return nil, fmt.Errorf("searching notes: %w", err)
	}

	var results []SearchResult
	if err := json.Unmarshal(out, &results); err != nil {
		return nil, fmt.Errorf("searching notes: %w", err)
	}
	return results, nil
}

func (a Anchorhold) Get(ctx context.Context, rel string) (Note, error) {
	out, err := a.run(ctx, "", "get", "--json", "--", rel)
	if exitCode(err) == 1 {
		return Note{}, ErrNoteNotFound
	}

	if err != nil {
		return Note{}, fmt.Errorf("getting note: %w", err)
	}

	var note Note
	if err := json.Unmarshal(out, &note); err != nil {
		return Note{}, fmt.Errorf("getting note: %w", err)
	}
	return note, nil
}

func (a Anchorhold) Write(ctx context.Context, rel, content, mode string) error {
	args := []string{"write"}
	switch mode {
	case modeCreate:
	case modeOverwrite:
		args = append(args, "--overwrite")
	default:
		return fmt.Errorf("writing note: %w", errUnknownMode)
	}

	if _, err := a.run(ctx, content, append(args, "--", rel)...); err != nil {
		return fmt.Errorf("writing note: %w", err)
	}
	return nil
}

func (a Anchorhold) Root(ctx context.Context) (string, error) {
	out, err := a.run(ctx, "", "status", "--json")
	if err != nil {
		return "", fmt.Errorf("reading vault root: %w", err)
	}

	var status struct {
		Vault string `json:"vault"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return "", fmt.Errorf("reading vault root: %w", err)
	}

	if status.Vault == "" {
		return "", fmt.Errorf("reading vault root: %w", errMissingVault)
	}
	return status.Vault, nil
}

func (a Anchorhold) run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	if a.Slots != nil {
		select {
		case a.Slots <- struct{}{}:
			defer func() { <-a.Slots }()
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for anchorhold: %w", ctx.Err())
		}
	}

	// The binary comes from the service's own flag, and arguments are passed without a shell.
	cmd := exec.CommandContext(ctx, a.Bin, args...) //nolint:gosec
	cmd.Stdin = strings.NewReader(stdin)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("running anchorhold: %w", err)
	}
	return stdout.Bytes(), nil
}

func exitCode(err error) int {
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode()
	}
	return 0
}
