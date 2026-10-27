package proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/proxy"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const promptTimeout = 200 * time.Millisecond

type promptLine struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type promptClient struct {
	conn     net.Conn
	lines    chan string
	readErr  chan error
	received []string
	missed   int
	closeErr error
}

type askResult struct {
	answer proxy.Answer
	err    error
}

func startPrompter(t *testing.T, timeout time.Duration) (*proxy.SocketPrompter, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "p.sock")
	ln, err := proxy.ListenPromptSocket(t.Context(), path, "")
	require.NoError(t, err)

	p := proxy.NewSocketPrompter(timeout, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	return p, path
}

func connectClient(t *testing.T, p *proxy.SocketPrompter, path string) *promptClient {
	t.Helper()

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	c := &promptClient{conn: conn, lines: make(chan string, 16), readErr: make(chan error, 1)}
	go func() {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				c.readErr <- err
				return
			}
			c.lines <- strings.TrimSuffix(line, "\n")
		}
	}()

	require.Eventually(t, p.HasClient, time.Second, 5*time.Millisecond)
	return c
}

func askAsync(ctx context.Context, wg *sync.WaitGroup, p *proxy.SocketPrompter, host string, port int) *askResult {
	result := &askResult{}
	wg.Go(func() { result.answer, result.err = p.Ask(ctx, host, port) })
	return result
}

func (c *promptClient) next() promptLine {
	select {
	case line := <-c.lines:
		c.received = append(c.received, line)

		var got promptLine
		if json.Unmarshal([]byte(line), &got) != nil {
			return promptLine{}
		}
		return got
	case <-time.After(time.Second):
		c.missed++
		return promptLine{}
	}
}

func (c *promptClient) reply(id, answer string) {
	_, _ = fmt.Fprintf(c.conn, "{\"id\":%q,\"answer\":%q}\n", id, answer)
}

func (c *promptClient) replySized(id, answer string, size int) {
	line := fmt.Sprintf("{\"id\":%q,\"answer\":%q", id, answer)
	_, _ = io.WriteString(c.conn, line+strings.Repeat(" ", size-len(line)-1)+"}\n")
}

func (c *promptClient) waitClosed() {
	select {
	case c.closeErr = <-c.readErr:
	case <-time.After(time.Second):
	}
}

func (c *promptClient) quiet(t *testing.T, d time.Duration) {
	t.Helper()

	select {
	case line := <-c.lines:
		require.FailNow(t, "unexpected prompt line", line)
	case <-time.After(d):
	}
}

func TestSocketPrompter_Ask(t *testing.T) {
	tests := []struct {
		name       string
		noClient   bool
		cancel     bool
		client     func(c *promptClient)
		want       proxy.Answer
		wantErr    error
		wantClosed bool
		checkLine  bool
		minElapsed time.Duration
		maxElapsed time.Duration
	}{
		{
			name:   "once",
			client: func(c *promptClient) { c.reply(c.next().ID, "once") },
			want:   proxy.AnswerOnce,
		},
		{
			name:   "always",
			client: func(c *promptClient) { c.reply(c.next().ID, "always") },
			want:   proxy.AnswerAlways,
		},
		{
			name:   "deny",
			client: func(c *promptClient) { c.reply(c.next().ID, "deny") },
			want:   proxy.AnswerDeny,
		},
		{
			name:      "prompt line shape",
			client:    func(c *promptClient) { c.reply(c.next().ID, "once") },
			want:      proxy.AnswerOnce,
			checkLine: true,
		},
		{
			name:       "timeout",
			client:     func(c *promptClient) { c.next() },
			want:       proxy.AnswerTimeout,
			minElapsed: promptTimeout,
		},
		{
			name:       "no client",
			noClient:   true,
			want:       proxy.AnswerDeny,
			maxElapsed: 50 * time.Millisecond,
		},
		{
			name: "unknown id ignored",
			client: func(c *promptClient) {
				c.next()
				c.reply("other", "once")
			},
			want: proxy.AnswerTimeout,
		},
		{
			name:   "bad answer ignored",
			client: func(c *promptClient) { c.reply(c.next().ID, "yes") },
			want:   proxy.AnswerTimeout,
		},
		{
			name:   "timeout answer ignored",
			client: func(c *promptClient) { c.reply(c.next().ID, "timeout") },
			want:   proxy.AnswerTimeout,
		},
		{
			name:   "4096-byte reply accepted",
			client: func(c *promptClient) { c.replySized(c.next().ID, "once", 4096) },
			want:   proxy.AnswerOnce,
		},
		{
			name:   "4097-byte reply ignored",
			client: func(c *promptClient) { c.replySized(c.next().ID, "once", 4097) },
			want:   proxy.AnswerTimeout,
		},
		{
			name: "malformed reply ignored",
			client: func(c *promptClient) {
				id := c.next().ID
				_, _ = io.WriteString(c.conn, "not json\n")
				c.reply(id, "once")
			},
			want: proxy.AnswerOnce,
		},
		{
			name: "oversized line closes client",
			client: func(c *promptClient) {
				c.next()
				_, _ = io.WriteString(c.conn, strings.Repeat("a", 5000))
				c.waitClosed()
			},
			want:       proxy.AnswerTimeout,
			wantClosed: true,
		},
		{
			name:    "context canceled",
			cancel:  true,
			client:  func(c *promptClient) { c.next() },
			wantErr: context.Canceled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			p, path := startPrompter(t, promptTimeout)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			var c *promptClient
			var wg sync.WaitGroup
			if !tt.noClient {
				c = connectClient(t, p, path)
				wg.Go(func() {
					tt.client(c)
					if tt.cancel {
						cancel()
					}
				})
			}

			// when
			start := time.Now()
			got, err := p.Ask(ctx, "example.com", 443)
			elapsed := time.Since(start)
			wg.Wait()

			// then
			if c != nil {
				require.Zero(t, c.missed)
			}

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)

			if tt.minElapsed > 0 {
				require.GreaterOrEqual(t, elapsed, tt.minElapsed)
			}
			if tt.maxElapsed > 0 {
				require.Less(t, elapsed, tt.maxElapsed)
			}

			if tt.wantClosed {
				require.ErrorIs(t, c.closeErr, io.EOF)
			}

			if tt.checkLine {
				require.Len(t, c.received, 1)

				var keys map[string]any
				require.NoError(t, json.Unmarshal([]byte(c.received[0]), &keys))
				require.Len(t, keys, 3)
				require.Equal(t, "example.com", keys["host"])
				require.InDelta(t, 443, keys["port"], 0)
				require.Regexp(t, uuidV4, keys["id"])
			}
		})
	}

	t.Run("happy path - same host and port share one prompt", func(t *testing.T) {
		// given
		p, path := startPrompter(t, time.Second)
		c := connectClient(t, p, path)
		var wg sync.WaitGroup

		// when
		results := []*askResult{
			askAsync(t.Context(), &wg, p, "example.com", 443),
			askAsync(t.Context(), &wg, p, "example.com", 443),
			askAsync(t.Context(), &wg, p, "example.com", 443),
		}

		line := c.next()
		c.quiet(t, 100*time.Millisecond)
		c.reply(line.ID, "once")
		wg.Wait()

		// then
		for _, result := range results {
			require.NoError(t, result.err)
			require.Equal(t, proxy.AnswerOnce, result.answer)
		}
	})

	t.Run("happy path - same host other port waits", func(t *testing.T) {
		// given
		p, path := startPrompter(t, time.Second)
		c := connectClient(t, p, path)
		var wg sync.WaitGroup

		// when
		first := askAsync(t.Context(), &wg, p, "example.com", 443)
		line443 := c.next()

		second := askAsync(t.Context(), &wg, p, "example.com", 8443)
		c.quiet(t, 100*time.Millisecond)
		c.reply(line443.ID, "deny")

		line8443 := c.next()
		c.reply(line8443.ID, "once")
		wg.Wait()

		// then
		require.Equal(t, 443, line443.Port)
		require.Equal(t, 8443, line8443.Port)
		require.NoError(t, first.err)
		require.NoError(t, second.err)
		require.Equal(t, proxy.AnswerDeny, first.answer)
		require.Equal(t, proxy.AnswerOnce, second.answer)
	})

	t.Run("happy path - different hosts prompt in parallel", func(t *testing.T) {
		// given
		p, path := startPrompter(t, time.Second)
		c := connectClient(t, p, path)
		var wg sync.WaitGroup

		// when
		results := []*askResult{
			askAsync(t.Context(), &wg, p, "a.example.com", 443),
			askAsync(t.Context(), &wg, p, "b.example.com", 443),
		}
		lines := []promptLine{c.next(), c.next()}

		for _, line := range lines {
			c.reply(line.ID, "once")
		}
		wg.Wait()

		// then
		require.ElementsMatch(t, []string{"a.example.com", "b.example.com"}, []string{lines[0].Host, lines[1].Host})
		for _, result := range results {
			require.NoError(t, result.err)
			require.Equal(t, proxy.AnswerOnce, result.answer)
		}
	})

	t.Run("happy path - late reply ignored", func(t *testing.T) {
		// given
		p, path := startPrompter(t, promptTimeout)
		c := connectClient(t, p, path)
		var wg sync.WaitGroup

		first := askAsync(t.Context(), &wg, p, "example.com", 443)
		old := c.next()
		wg.Wait()

		// when
		c.reply(old.ID, "once")

		second := askAsync(t.Context(), &wg, p, "example.com", 443)
		line := c.next()
		c.reply(line.ID, "deny")
		wg.Wait()

		// then
		require.NoError(t, first.err)
		require.Equal(t, proxy.AnswerTimeout, first.answer)
		require.NotEqual(t, old.ID, line.ID)
		require.NoError(t, second.err)
		require.Equal(t, proxy.AnswerDeny, second.answer)
	})

	t.Run("happy path - disconnected client means deny", func(t *testing.T) {
		// given
		p, path := startPrompter(t, time.Second)
		c := connectClient(t, p, path)
		require.NoError(t, c.conn.Close())
		require.Eventually(t, func() bool { return !p.HasClient() }, time.Second, 5*time.Millisecond)

		// when
		start := time.Now()
		got, err := p.Ask(t.Context(), "example.com", 443)

		// then
		require.NoError(t, err)
		require.Equal(t, proxy.AnswerDeny, got)
		require.Less(t, time.Since(start), 50*time.Millisecond)
	})

	t.Run("happy path - canceled opener lets waiter prompt", func(t *testing.T) {
		// given
		p, path := startPrompter(t, time.Second)
		c := connectClient(t, p, path)
		openerCtx, cancelOpener := context.WithCancel(t.Context())
		var wg sync.WaitGroup

		opener := askAsync(openerCtx, &wg, p, "example.com", 443)
		first := c.next()
		waiter := askAsync(t.Context(), &wg, p, "example.com", 443)
		c.quiet(t, 50*time.Millisecond)

		// when
		cancelOpener()
		second := c.next()
		c.reply(second.ID, "once")
		wg.Wait()

		// then
		require.Zero(t, c.missed)
		require.ErrorIs(t, opener.err, context.Canceled)
		require.NotEqual(t, first.ID, second.ID)
		require.NoError(t, waiter.err)
		require.Equal(t, proxy.AnswerOnce, waiter.answer)
	})

	t.Run("happy path - shutdown closes client", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")
		ln, err := proxy.ListenPromptSocket(t.Context(), path, "")
		require.NoError(t, err)

		p := proxy.NewSocketPrompter(time.Second, slog.New(slog.DiscardHandler))
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- p.Serve(ctx, ln) }()
		c := connectClient(t, p, path)

		// when
		cancel()

		// then
		require.NoError(t, <-done)
		c.waitClosed()
		require.ErrorIs(t, c.closeErr, io.EOF)
	})

	t.Run("happy path - new client replaces old", func(t *testing.T) {
		// given
		p, path := startPrompter(t, time.Second)
		oldClient := connectClient(t, p, path)

		// when
		newClient := connectClient(t, p, path)

		// then
		oldClient.waitClosed()
		require.ErrorIs(t, oldClient.closeErr, io.EOF)

		var wg sync.WaitGroup
		result := askAsync(t.Context(), &wg, p, "example.com", 443)
		newClient.reply(newClient.next().ID, "once")
		wg.Wait()

		require.NoError(t, result.err)
		require.Equal(t, proxy.AnswerOnce, result.answer)
	})
}

func TestListenPromptSocket(t *testing.T) {
	t.Run("happy path - mode 0660", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")

		// when
		ln, err := proxy.ListenPromptSocket(t.Context(), path, "")

		// then
		require.NoError(t, err)
		defer ln.Close()

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o660)|os.ModeSocket, info.Mode())
	})

	t.Run("happy path - removes stale socket", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")
		require.NoError(t, os.WriteFile(path, []byte("stale"), 0o600))

		// when
		ln, err := proxy.ListenPromptSocket(t.Context(), path, "")

		// then
		require.NoError(t, err)
		require.NoError(t, ln.Close())
	})

	t.Run("happy path - sets group", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")
		group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
		require.NoError(t, err)

		// when
		ln, err := proxy.ListenPromptSocket(t.Context(), path, group.Name)

		// then
		require.NoError(t, err)
		defer ln.Close()

		info, err := os.Stat(path)
		require.NoError(t, err)

		stat, ok := info.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		require.Equal(t, group.Gid, strconv.FormatUint(uint64(stat.Gid), 10))
	})

	t.Run("error - missing directory", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "missing", "p.sock")

		// when
		_, err := proxy.ListenPromptSocket(t.Context(), path, "")

		// then
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "listening on prompt socket"), err.Error())
	})

	t.Run("error - unknown group", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")

		// when
		_, err := proxy.ListenPromptSocket(t.Context(), path, "xena-no-such-group")

		// then
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "listening on prompt socket"), err.Error())
	})
}

func TestNewID(t *testing.T) {
	// given
	seen := make(map[string]bool)

	// when
	for range 100 {
		seen[proxy.NewID()] = true
	}

	// then
	require.Len(t, seen, 100)
	for id := range seen {
		require.Regexp(t, uuidV4, id)
	}
}
