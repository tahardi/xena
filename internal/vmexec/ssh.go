package vmexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
)

var ErrInvalidArgument = errors.New("invalid argument")

var validWord = regexp.MustCompile(`^[a-z0-9-]+$`)

var _ Runner = SSH{}

type execFunc func(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error)

type SSH struct {
	Key        string
	KnownHosts string
	User       string
	Addr       string
	run        execFunc
}

func (s SSH) Run(ctx context.Context, verb string, args []string, stdin io.Reader) ([]byte, error) {
	for _, a := range append([]string{verb}, args...) {
		if !validWord.MatchString(a) {
			return nil, fmt.Errorf("checking argument %q: %w", a, ErrInvalidArgument)
		}
	}

	argv := append([]string{
		"-T",
		"-F", "/dev/null",
		"-i", s.Key,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=" + s.KnownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ForwardX11=no",
		"-o", "ForwardAgent=no",
		s.User + "@" + s.Addr,
		verb,
	}, args...)

	run := s.run
	if run == nil {
		run = runCommand
	}

	out, err := run(ctx, stdin, "ssh", argv...)
	if err != nil {
		return nil, fmt.Errorf("running %s in vm: %w", verb, err)
	}

	return out, nil
}

func runCommand(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stderr = io.Discard

	return cmd.Output()
}
