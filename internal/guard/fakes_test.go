package guard_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tahardi/xena/internal/guard"
	"github.com/tahardi/xena/internal/logs"
)

type fakeCase struct {
	name      string
	result    guard.Result
	windowDir string
	sawWindow *bool
	gotEnv    guard.Env
	ran       bool
}

func (c *fakeCase) Name() string {
	return c.name
}

func (c *fakeCase) Run(_ context.Context, env guard.Env) guard.Result {
	c.ran = true
	c.gotEnv = env

	if c.sawWindow != nil {
		_, err := os.Stat(filepath.Join(c.windowDir, "window.json"))
		*c.sawWindow = err == nil
	}

	return c.result
}

type fakeTargetCase struct {
	*fakeCase

	targets []string
}

func (c *fakeTargetCase) Targets() []string {
	return c.targets
}

type windowReadingCase struct {
	*fakeCase

	dir string
	got *guard.Window
}

func (c *windowReadingCase) Targets() []string {
	return []string{"198.51.100.7"}
}

func (c *windowReadingCase) Run(_ context.Context, _ guard.Env) guard.Result {
	data, err := os.ReadFile(filepath.Join(c.dir, "window.json"))
	if err != nil {
		return guard.Fail(c.name, err.Error())
	}

	if err := json.Unmarshal(data, c.got); err != nil {
		return guard.Fail(c.name, err.Error())
	}

	return c.result
}

type windowBlockingCase struct {
	*fakeCase

	dir string
}

func (c *windowBlockingCase) Targets() []string {
	return []string{"198.51.100.7"}
}

func (c *windowBlockingCase) Run(_ context.Context, _ guard.Env) guard.Result {
	path := filepath.Join(c.dir, "window.json")
	if err := os.Remove(path); err != nil {
		return guard.Fail(c.name, err.Error())
	}

	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		return guard.Fail(c.name, err.Error())
	}

	return c.result
}

type fakeVM struct {
	mu     sync.Mutex
	output map[string]string
	err    error
	calls  []string
}

func (f *fakeVM) Run(_ context.Context, verb string, args []string, _ io.Reader) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, verb+" "+args[0])

	return []byte(f.output[args[0]]), f.err
}

type fakeProxy struct {
	entries    []logs.ProxyEntry
	err        error
	emptyCalls int
}

func (f *fakeProxy) Entries(time.Time) ([]logs.ProxyEntry, error) {
	if f.emptyCalls > 0 {
		f.emptyCalls--
		return nil, nil
	}

	return f.entries, f.err
}

type fakeDrops struct {
	drops []guard.Drop
	err   error
}

func (f *fakeDrops) Drops(context.Context, time.Time) ([]guard.Drop, error) {
	return f.drops, f.err
}

type fakeCut struct {
	cut bool
	err error
}

func (f *fakeCut) IsCut(context.Context, string) (bool, error) {
	return f.cut, f.err
}
