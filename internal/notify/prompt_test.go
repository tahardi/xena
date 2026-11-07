package notify_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/notify"
)

const (
	noReplyWait = 200 * time.Millisecond
	replyWait   = 2 * time.Second
	onceLine    = `{"id":"a1","host":"example.com","port":443}`
	touchValue  = "s3cr3t-touch"
)

var (
	errAsk   = errors.New("made-up ask failure")
	errTouch = errors.New("made-up touch failure")
	errShow  = errors.New("made-up show failure")
)

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
	err error

	mu    sync.Mutex
	names []string
}

func (f *fakeTouch) Get(_ context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	f.names = append(f.names, name)
	f.mu.Unlock()

	if f.err != nil {
		return nil, f.err
	}

	return []byte(touchValue), nil
}

func (f *fakeTouch) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.names...)
}

type session struct {
	conn    net.Conn
	replies chan string
	done    chan error
}

func startSession(t *testing.T, client notify.PromptClient) *session {
	t.Helper()

	ours, theirs := net.Pipe()
	s := &session{conn: ours, replies: make(chan string, 10), done: make(chan error, 1)}

	go func() {
		s.done <- client.Handle(t.Context(), theirs)
		_ = theirs.Close()
	}()

	go func() {
		reader := bufio.NewReader(ours)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				close(s.replies)
				return
			}
			s.replies <- line
		}
	}()

	t.Cleanup(func() { _ = ours.Close() })
	return s
}

func (s *session) send(t *testing.T, line string) {
	t.Helper()

	_, err := io.WriteString(s.conn, line+"\n")
	require.NoError(t, err)
}

func (s *session) reply(t *testing.T) string {
	t.Helper()

	select {
	case line := <-s.replies:
		return line
	case <-time.After(replyWait):
		require.FailNow(t, "no reply")
		return ""
	}
}

func (s *session) noReply(t *testing.T) {
	t.Helper()

	select {
	case line := <-s.replies:
		require.FailNow(t, "unexpected reply", line)
	case <-time.After(noReplyWait):
	}
}

func newClient(asker *fakeAsker, touch *fakeTouch, timeout time.Duration) notify.PromptClient {
	return notify.PromptClient{
		Desktop: asker,
		Touch:   touch,
		Timeout: timeout,
		Logger:  slog.New(slog.DiscardHandler),
	}
}

func TestPromptClient_Handle(t *testing.T) {
	tests := []struct {
		name       string
		lines      []string
		answer     string
		askErr     error
		touchErr   error
		blockCtx   bool
		timeout    time.Duration
		wantReply  string
		wantTouch  []string
		wantShows  []showCall
		wantNoAsk  bool
		wantDLWith time.Duration
	}{
		{
			name:      "once",
			lines:     []string{onceLine},
			answer:    "once",
			wantReply: `{"id":"a1","answer":"once"}` + "\n",
		},
		{
			name:      "always with touch",
			lines:     []string{onceLine},
			answer:    "always",
			wantReply: `{"id":"a1","answer":"always"}` + "\n",
			wantTouch: []string{"touch-check"},
		},
		{
			name:      "always without touch",
			lines:     []string{onceLine},
			answer:    "always",
			touchErr:  errTouch,
			wantReply: `{"id":"a1","answer":"once"}` + "\n",
			wantTouch: []string{"touch-check"},
			wantShows: []showCall{{title: "Touch not confirmed", body: "example.com:443 allowed once"}},
		},
		{
			name:      "deny",
			lines:     []string{onceLine},
			answer:    "deny",
			wantReply: `{"id":"a1","answer":"deny"}` + "\n",
		},
		{name: "dismissed", lines: []string{onceLine}, answer: ""},
		{name: "unknown output", lines: []string{onceLine}, answer: "maybe"},
		{name: "asker error", lines: []string{onceLine}, askErr: errAsk},
		{
			name:      "unsafe host",
			lines:     []string{`{"id":"a2","host":"exa mple.com","port":443}`},
			wantReply: `{"id":"a2","answer":"deny"}` + "\n",
			wantNoAsk: true,
		},
		{
			name:      "port zero",
			lines:     []string{`{"id":"a3","host":"example.com","port":0}`},
			wantReply: `{"id":"a3","answer":"deny"}` + "\n",
			wantNoAsk: true,
		},
		{
			name:      "missing id",
			lines:     []string{`{"host":"example.com","port":443}`},
			answer:    "once",
			wantNoAsk: true,
		},
		{
			name:      "malformed then valid",
			lines:     []string{"not json", onceLine},
			answer:    "once",
			wantReply: `{"id":"a1","answer":"once"}` + "\n",
		},
		{
			name:       "deadline",
			lines:      []string{onceLine},
			blockCtx:   true,
			timeout:    50 * time.Millisecond,
			wantDLWith: 50 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			asker := &fakeAsker{
				answers:  map[string]string{"example.com": tt.answer},
				errs:     map[string]error{"example.com": tt.askErr},
				blockCtx: tt.blockCtx,
			}
			touch := &fakeTouch{err: tt.touchErr}
			timeout := time.Second
			if tt.timeout != 0 {
				timeout = tt.timeout
			}
			s := startSession(t, newClient(asker, touch, timeout))

			// when
			for _, line := range tt.lines {
				s.send(t, line)
			}

			// then
			if tt.wantReply != "" {
				require.Equal(t, tt.wantReply, s.reply(t))
			}
			s.noReply(t)

			require.Equal(t, tt.wantTouch, touch.calls())
			require.Equal(t, tt.wantShows, asker.showCalls())

			if tt.wantNoAsk {
				require.Empty(t, asker.askCalls())
			}

			if tt.wantDLWith != 0 {
				calls := asker.askCalls()
				require.Len(t, calls, 1)
				require.True(t, calls[0].hasDL)
				require.LessOrEqual(t, calls[0].deadline.Sub(calls[0].at), tt.wantDLWith)
			}
		})
	}

	t.Run("happy path - touch value never sent", func(t *testing.T) {
		// given
		asker := &fakeAsker{answers: map[string]string{"example.com": "always"}}
		s := startSession(t, newClient(asker, &fakeTouch{}, time.Second))

		// when
		s.send(t, onceLine)

		// then
		require.NotContains(t, s.reply(t), touchValue)
	})

	t.Run("happy path - concurrent prompts", func(t *testing.T) {
		// given
		release := make(chan struct{})
		asker := &fakeAsker{
			answers: map[string]string{"one.example.com": "once", "two.example.com": "deny"},
			block:   map[string]chan struct{}{"one.example.com": release},
		}
		s := startSession(t, newClient(asker, &fakeTouch{}, time.Second))

		// when
		s.send(t, `{"id":"a1","host":"one.example.com","port":443}`)
		s.send(t, `{"id":"a2","host":"two.example.com","port":443}`)
		first := s.reply(t)
		close(release)
		second := s.reply(t)

		// then
		require.JSONEq(t, `{"id":"a2","answer":"deny"}`, first)
		require.JSONEq(t, `{"id":"a1","answer":"once"}`, second)
	})

	t.Run("happy path - returns on EOF", func(t *testing.T) {
		// given
		s := startSession(t, newClient(&fakeAsker{}, &fakeTouch{}, time.Second))

		// when
		require.NoError(t, s.conn.Close())

		// then
		select {
		case err := <-s.done:
			require.NoError(t, err)
		case <-time.After(replyWait):
			require.FailNow(t, "Handle did not return")
		}
	})
}
