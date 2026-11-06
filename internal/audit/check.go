package audit

import (
	"context"
	"errors"
)

var ErrSkipped = errors.New("check skipped")

type Finding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

type Check interface {
	Name() string
	Run(ctx context.Context) ([]Finding, error)
}
