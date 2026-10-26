package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	codeOK      = 0
	codeFailed  = 1
	codeRefused = 2
	codeExists  = 3
)

var (
	ErrRefusedVerb   = errors.New("refusing verb")
	ErrEmptyValue    = errors.New("refusing empty value")
	ErrMemoryExists  = errors.New("refusing import: memory exists")
	ErrUnsafeArchive = errors.New("refusing import: archive holds links, special files, or paths outside it")

	validCommand = regexp.MustCompile(`^[a-z0-9 -]+$`)
)

type Agent struct {
	Home     string
	GuardDir string
	Bash     string
	SQLite   string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
}

func (a Agent) Run(ctx context.Context, command string) int {
	code, err := a.dispatch(ctx, command)
	if err != nil {
		_, _ = fmt.Fprintln(a.Stderr, err)
	}

	return code
}

func (a Agent) dispatch(ctx context.Context, command string) (int, error) {
	words := strings.Fields(command)
	if !validCommand.MatchString(command) || len(words) == 0 {
		return result(ErrRefusedVerb)
	}

	verb, args := words[0], words[1:]

	switch {
	case verb == "health" && len(args) == 0:
		_, err := fmt.Fprintln(a.Stdout, "ok")
		return result(err)
	case verb == "token-put" && len(args) == 0:
		return result(a.writeSecret("github-token"))
	case verb == "secret-put" && len(args) == 1 && isSecretName(args[0]):
		return result(a.writeSecret(args[0]))
	case verb == "secret-clear" && len(args) == 1 && isSecretName(args[0]):
		return result(a.clearSecret(args[0]))
	case verb == "memory-export" && len(args) == 0:
		return result(a.exportMemory())
	case verb == "memory-import" && len(args) == 0:
		return result(a.importMemory(ctx))
	case verb == "guard" && len(args) == 1:
		return a.runGuard(ctx, args[0])
	default:
		return result(ErrRefusedVerb)
	}
}

func result(err error) (int, error) {
	switch {
	case err == nil:
		return codeOK, nil
	case errors.Is(err, ErrRefusedVerb):
		return codeRefused, err
	case errors.Is(err, ErrMemoryExists):
		return codeExists, err
	default:
		return codeFailed, err
	}
}
