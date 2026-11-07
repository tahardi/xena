package notify_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
)

const touchValue = "s3cr3t-touch"

var errShow = errors.New("made-up show failure")

type showCall struct {
	title    string
	body     string
	critical bool
}

type askCall struct {
	host     string
	port     int
	at       time.Time
	deadline time.Time
	hasDL    bool
}

type fakeAsker struct {
	answers  map[string]string
	errs     map[string]error
	block    map[string]chan struct{}
	blockCtx bool
	showErrs []error

	mu    sync.Mutex
	asks  []askCall
	shows []showCall
}

func (f *fakeAsker) Ask(ctx context.Context, host string, port int) (string, error) {
	deadline, ok := ctx.Deadline()

	f.mu.Lock()
	f.asks = append(f.asks, askCall{host: host, port: port, at: time.Now(), deadline: deadline, hasDL: ok})
	f.mu.Unlock()

	if f.blockCtx {
		<-ctx.Done()
		return "", ctx.Err()
	}

	if ch, ok := f.block[host]; ok {
		<-ch
	}

	return f.answers[host], f.errs[host]
}

func (f *fakeAsker) Show(_ context.Context, title, body string, critical bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.shows = append(f.shows, showCall{title: title, body: body, critical: critical})

	if len(f.showErrs) > 0 {
		err := f.showErrs[0]
		f.showErrs = f.showErrs[1:]
		return err
	}

	return nil
}

func (f *fakeAsker) askCalls() []askCall {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]askCall(nil), f.asks...)
}

func (f *fakeAsker) showCalls() []showCall {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]showCall(nil), f.shows...)
}

type fakeTouch struct {
	err   error
	asker *fakeAsker

	mu        sync.Mutex
	names     []string
	deadlines []bool
	shows     []int
}

func (f *fakeTouch) Get(ctx context.Context, name string) ([]byte, error) {
	_, hasDeadline := ctx.Deadline()

	shown := 0
	if f.asker != nil {
		shown = len(f.asker.showCalls())
	}

	f.mu.Lock()
	f.shows = append(f.shows, shown)
	f.names = append(f.names, name)
	f.deadlines = append(f.deadlines, hasDeadline)
	f.mu.Unlock()

	if f.err != nil {
		return nil, f.err
	}

	return []byte(touchValue), nil
}

func (f *fakeTouch) showsAtGet() []int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]int(nil), f.shows...)
}

func (f *fakeTouch) deadlineCalls() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]bool(nil), f.deadlines...)
}

func (f *fakeTouch) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.names...)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
