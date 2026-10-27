package vmexec

import (
	"context"
	"io"
)

type Runner interface {
	Run(ctx context.Context, verb string, args []string, stdin io.Reader) ([]byte, error)
}
