package guard

import (
	"context"
	"time"

	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/vmexec"
)

type Result struct {
	Case     string   `json:"case"`
	Passed   bool     `json:"passed"`
	Evidence []string `json:"evidence"`
	Error    string   `json:"error,omitempty"`
}

type Case interface {
	Name() string
	Run(ctx context.Context, env Env) Result
}

type Targeter interface {
	Targets() []string
}

type ProxyLogReader interface {
	Entries(since time.Time) ([]logs.ProxyEntry, error)
}

type DropReader interface {
	Drops(ctx context.Context, since time.Time) ([]Drop, error)
}

type CutChecker interface {
	IsCut(ctx context.Context, vmAddr string) (bool, error)
}

type Env struct {
	VM         vmexec.Runner
	Proxy      ProxyLogReader
	Drops      DropReader
	Firewall   CutChecker
	VMAddr     string
	Now        func() time.Time
	Settle     time.Duration
	RunStarted time.Time
}

func Pass(name string, evidence ...string) Result {
	return Result{Case: name, Passed: true, Evidence: append([]string{}, evidence...)}
}

func Fail(name, reason string, evidence ...string) Result {
	return Result{Case: name, Error: reason, Evidence: append([]string{}, evidence...)}
}
