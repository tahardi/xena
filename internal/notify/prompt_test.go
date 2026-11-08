package notify_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
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
)

var (
	errAsk   = errors.New("made-up ask failure")
	errTouch = errors.New("made-up touch failure")
	errDial  = errors.New("made-up dial failure")
)

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
		wantLog    string
	}{
		{
			name:      "once",
			lines:     []string{onceLine},
			answer:    "once",
			wantReply: `{"id":"a1","answer":"once"}` + "\n",
			wantLog:   `"msg":"answering prompt"`,
		},
		{
			name:      "always with touch",
			lines:     []string{onceLine},
			answer:    "always",
			wantReply: `{"id":"a1","answer":"always"}` + "\n",
			wantTouch: []string{"touch-check"},
			wantShows: []showCall{{title: "Touch your YubiKey", body: "to allow example.com:443 always", critical: true}},
		},
		{
			name:      "always without touch",
			lines:     []string{onceLine},
			answer:    "always",
			touchErr:  errTouch,
			wantReply: `{"id":"a1","answer":"once"}` + "\n",
			wantTouch: []string{"touch-check"},
			wantShows: []showCall{
				{title: "Touch your YubiKey", body: "to allow example.com:443 always", critical: true},
				{title: "Touch not confirmed", body: "example.com:443 allowed once"},
			},
		},
		{
			name:      "deny",
			lines:     []string{onceLine},
			answer:    "deny",
			wantReply: `{"id":"a1","answer":"deny"}` + "\n",
		},
		{name: "dismissed", lines: []string{onceLine}, answer: "", wantLog: `"msg":"prompt unanswered"`},
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
			touch := &fakeTouch{err: tt.touchErr, asker: asker}
			timeout := time.Second
			if tt.timeout != 0 {
				timeout = tt.timeout
			}
			logs := &syncBuffer{}
			client := newClient(asker, touch, timeout)
			client.Logger = slog.New(slog.NewJSONHandler(logs, nil))
			s := startSession(t, client)

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
			for _, hasDeadline := range touch.deadlineCalls() {
				require.True(t, hasDeadline)
			}

			for _, shown := range touch.showsAtGet() {
				require.Equal(t, 1, shown, "touch hint must show before the touch")
			}

			require.Contains(t, logs.String(), tt.wantLog)
			require.Equal(t, tt.wantShows, asker.showCalls())

			if tt.wantNoAsk {
				require.Empty(t, asker.askCalls())
			}

			if tt.wantDLWith != 0 {
				calls := asker.askCalls()
				require.Len(t, calls, 1)
				require.True(t, calls[0].hasDL)
				require.LessOrEqual(t, calls[0].deadline.Sub(calls[0].at), tt.wantDLWith)
				require.Greater(t, calls[0].deadline.Sub(calls[0].at), tt.wantDLWith/2)
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

	t.Run("happy path - EOF cancels open prompts", func(t *testing.T) {
		// given
		asker := &fakeAsker{blockCtx: true}
		s := startSession(t, newClient(asker, &fakeTouch{}, time.Minute))
		s.send(t, onceLine)
		require.Eventually(t, func() bool { return len(asker.askCalls()) == 1 }, replyWait, 10*time.Millisecond)

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

	t.Run("error - oversized prompt line", func(t *testing.T) {
		// given
		s := startSession(t, newClient(&fakeAsker{}, &fakeTouch{}, time.Second))

		// when
		go func() { _, _ = io.WriteString(s.conn, strings.Repeat("a", 5000)+"\n") }()

		// then
		select {
		case err := <-s.done:
			require.ErrorContains(t, err, "reading prompts")
		case <-time.After(replyWait):
			require.FailNow(t, "Handle did not return")
		}
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

type dialStep struct {
	conn net.Conn
	err  error
}

type fakeDialer struct {
	mu    sync.Mutex
	steps []dialStep
	count int
}

func (d *fakeDialer) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.count++
	if len(d.steps) == 0 {
		return nil, errDial
	}

	step := d.steps[0]
	d.steps = d.steps[1:]
	return step.conn, step.err
}

func (d *fakeDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.count
}

func startRun(t *testing.T, dialer *fakeDialer, asker *fakeAsker) (context.CancelFunc, chan error, *syncBuffer) {
	t.Helper()

	logs := &syncBuffer{}
	client := newClient(asker, &fakeTouch{}, time.Second)
	client.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	client.Dial = dialer.Dial
	client.Retry = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx, "prompt.sock") }()

	t.Cleanup(cancel)
	return cancel, done, logs
}

func waitDone(t *testing.T, done chan error) {
	t.Helper()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(replyWait):
		require.FailNow(t, "Run did not return")
	}
}

func TestPromptClient_Run(t *testing.T) {
	t.Run("happy path - repeated failures logged once", func(t *testing.T) {
		// given
		dialer := &fakeDialer{}
		cancel, done, logs := startRun(t, dialer, &fakeAsker{})

		// when
		require.Eventually(t, func() bool { return dialer.calls() >= 5 }, replyWait, time.Millisecond)
		cancel()

		// then
		waitDone(t, done)
		require.Equal(t, 1, strings.Count(logs.String(), `"msg":"connecting to prompt socket"`))
	})

	t.Run("happy path - failure logged again after recovery", func(t *testing.T) {
		// given
		ours, theirs := net.Pipe()
		require.NoError(t, ours.Close())
		dialer := &fakeDialer{steps: []dialStep{{err: errDial}, {err: errDial}, {conn: theirs}}}
		cancel, done, logs := startRun(t, dialer, &fakeAsker{})

		// when
		require.Eventually(t, func() bool { return dialer.calls() >= 6 }, replyWait, time.Millisecond)
		cancel()

		// then
		waitDone(t, done)
		require.Equal(t, 2, strings.Count(logs.String(), `"msg":"connecting to prompt socket"`))
		require.Equal(t, 1, strings.Count(logs.String(), `"msg":"connected to prompt socket"`))
		require.Equal(t, 1, strings.Count(logs.String(), `"msg":"prompt socket disconnected"`))
	})

	t.Run("happy path - reconnects after disconnect", func(t *testing.T) {
		// given
		firstOurs, firstTheirs := net.Pipe()
		require.NoError(t, firstOurs.Close())
		ours, theirs := net.Pipe()
		t.Cleanup(func() { _ = ours.Close() })
		dialer := &fakeDialer{steps: []dialStep{{conn: firstTheirs}, {conn: theirs}}}
		asker := &fakeAsker{answers: map[string]string{"example.com": "once"}}
		cancel, done, _ := startRun(t, dialer, asker)

		// when
		_, err := io.WriteString(ours, onceLine+"\n")
		require.NoError(t, err)
		line, err := bufio.NewReader(ours).ReadString('\n')
		require.NoError(t, err)
		cancel()

		// then
		require.JSONEq(t, `{"id":"a1","answer":"once"}`, line)
		waitDone(t, done)
	})

	t.Run("happy path - returns when cancelled while connected", func(t *testing.T) {
		// given
		ours, theirs := net.Pipe()
		t.Cleanup(func() { _ = ours.Close() })
		dialer := &fakeDialer{steps: []dialStep{{conn: theirs}}}
		cancel, done, logs := startRun(t, dialer, &fakeAsker{})
		require.Eventually(t, func() bool {
			return strings.Contains(logs.String(), `"msg":"connected to prompt socket"`)
		}, replyWait, time.Millisecond)

		// when
		cancel()

		// then
		waitDone(t, done)
	})
}
