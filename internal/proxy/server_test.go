package proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/allowlist"
	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/proxy"
)

const baseAllowlist = `version: 1
hosts:
  - host: example.com
  - host: plain.example.com
    ports: [80]
  - host: "*.example.org"
`

var (
	errFake        = errors.New("fake error")
	errConnRefused = errors.New("connection refused")
	errNotTCPConn  = errors.New("not a TCP connection")
)

type fakeResolver struct {
	mu       sync.Mutex
	answers  map[string][]netip.Addr
	sequence [][]netip.Addr
	err      error
	calls    []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, host)
	if r.err != nil {
		return nil, r.err
	}

	if len(r.sequence) > 0 {
		answer := r.sequence[0]
		if len(r.sequence) > 1 {
			r.sequence = r.sequence[1:]
		}
		return answer, nil
	}
	return r.answers[host], nil
}

func (r *fakeResolver) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.calls...)
}

type fakeDialer struct {
	mu     sync.Mutex
	routes map[string]string
	fail   map[string]bool
	calls  []string
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, address)
	route, ok := d.routes[address]
	failed := d.fail[address]
	d.mu.Unlock()

	if failed || !ok {
		return nil, errConnRefused
	}

	var dialer net.Dialer
	return dialer.DialContext(ctx, network, route)
}

func (d *fakeDialer) Calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]string(nil), d.calls...)
}

type promptCall struct {
	host string
	port int
}

type fakePrompter struct {
	mu     sync.Mutex
	answer proxy.Answer
	err    error
	calls  []promptCall
}

func (p *fakePrompter) Ask(_ context.Context, host string, port int) (proxy.Answer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls = append(p.calls, promptCall{host: host, port: port})
	if p.err != nil {
		return "", p.err
	}

	if p.answer == "" {
		return proxy.AnswerDeny, nil
	}
	return p.answer, nil
}

func (p *fakePrompter) Calls() []promptCall {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]promptCall(nil), p.calls...)
}

type fakeLog struct {
	mu      sync.Mutex
	records []logs.Record
	err     error
}

func (l *fakeLog) Write(record logs.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.records = append(l.records, record)
	return l.err
}

func (l *fakeLog) Entries() []logs.ProxyEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries := make([]logs.ProxyEntry, 0, len(l.records))
	for _, record := range l.records {
		entry, _ := record.(logs.ProxyEntry)
		entries = append(entries, entry)
	}
	return entries
}

type upstreamRequest struct {
	host    string
	path    string
	headers http.Header
}

type proxyFixture struct {
	addr     string
	stateDir string
	resolver *fakeResolver
	dialer   *fakeDialer
	prompter *fakePrompter
	log      *fakeLog
	upstream chan upstreamRequest
}

func startEcho(t *testing.T, extra int) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()

				_, _ = conn.Write([]byte(strings.Repeat("x", extra)))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func newProxyFixture(t *testing.T, extra int) *proxyFixture {
	t.Helper()

	f := &proxyFixture{
		stateDir: t.TempDir(),
		resolver: &fakeResolver{answers: map[string][]netip.Addr{}},
		prompter: &fakePrompter{},
		log:      &fakeLog{},
		upstream: make(chan upstreamRequest, 1),
	}

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.upstream <- upstreamRequest{host: r.Host, path: r.URL.Path, headers: r.Header.Clone()}
		_, _ = io.WriteString(w, "upstream body")
	}))
	t.Cleanup(web.Close)

	echo := startEcho(t, extra)
	f.dialer = &fakeDialer{
		routes: map[string]string{
			"192.0.2.10:443": echo,
			"192.0.2.20:443": echo,
			"192.0.2.10:80":  web.Listener.Addr().String(),
		},
		fail: map[string]bool{},
	}
	return f
}

func (f *proxyFixture) start(t *testing.T) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "allowlist.yaml")
	require.NoError(t, os.WriteFile(path, []byte(baseAllowlist), 0o600))

	base, err := allowlist.Load(path)
	require.NoError(t, err)

	s := proxy.NewServer(
		netip.MustParseAddr("127.0.0.1"),
		base,
		filepath.Join(f.stateDir, "overlay.yaml"),
		f.resolver,
		f.dialer,
		f.prompter,
		f.log,
		slog.New(slog.DiscardHandler),
	)
	require.NoError(t, s.LoadOverlay())

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f.addr = ln.Addr().String()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}

func (f *proxyFixture) connect(t *testing.T, target string, payload []byte) (int, []byte) {
	t.Helper()

	return f.connectWithHost(t, target, target, payload)
}

func (f *proxyFixture) connectWithHost(t *testing.T, target, host string, payload []byte) (int, []byte) {
	t.Helper()

	return f.raw(t, "CONNECT "+target+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n", http.MethodConnect, payload)
}

func (f *proxyFixture) raw(t *testing.T, request, method string, payload []byte) (int, []byte) {
	t.Helper()

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", f.addr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = io.WriteString(conn, request)
	require.NoError(t, err)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: method})
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || method != http.MethodConnect {
		return resp.StatusCode, nil
	}

	_, err = conn.Write(payload)
	require.NoError(t, err)
	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok, errNotTCPConn)
	require.NoError(t, tcp.CloseWrite())

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	return resp.StatusCode, got
}

func (f *proxyFixture) get(t *testing.T, target string, headers map[string]string) (int, string) {
	t.Helper()

	proxyURL, err := url.Parse("http://" + f.addr)
	require.NoError(t, err)

	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)
	req.Header.Set("Proxy-Authorization", "Basic Zm9v")
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func (f *proxyFixture) entry(t *testing.T) logs.ProxyEntry {
	t.Helper()

	require.Eventually(t, func() bool { return len(f.log.Entries()) == 1 }, time.Second, 5*time.Millisecond)
	return f.log.Entries()[0]
}

func addrs(values ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

func TestServer_ServeHTTP(t *testing.T) {
	ping := []byte("ping")

	tests := []struct {
		name       string
		connect    string
		hostHeader string
		get        string
		headers    map[string]string
		raw        string
		payload    []byte
		extra      int
		resolve    []netip.Addr
		sequence   [][]netip.Addr
		resolveErr error
		fail       []string
		answer     proxy.Answer
		promptErr  error
		wantStatus int
		wantEcho   string
		noEntry    bool
		want       logs.ProxyEntry
		anyBytes   bool
		check      func(r *require.Assertions, f *proxyFixture)
	}{
		{
			name:       "allowlisted connect",
			connect:    "example.com:443",
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionAllow, BytesOut: 4, BytesIn: 4},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Equal([]string{"192.0.2.10:443"}, f.dialer.Calls())
				r.Empty(f.prompter.Calls())
			},
		},
		{
			name:       "normalized host",
			connect:    "EXAMPLE.com.:443",
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionAllow, BytesOut: 4, BytesIn: 4},
		},
		{
			name:       "wildcard subdomain",
			connect:    "a.b.example.org:443",
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want: logs.ProxyEntry{
				Host:     "a.b.example.org",
				Port:     443,
				Decision: logs.DecisionAllow,
				BytesOut: 4,
				BytesIn:  4,
			},
		},
		{
			name:       "wildcard bare domain prompts",
			connect:    "example.org:443",
			resolve:    addrs("192.0.2.10"),
			answer:     proxy.AnswerOnce,
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want: logs.ProxyEntry{
				Host:     "example.org",
				Port:     443,
				Decision: logs.DecisionAllowOnce,
				BytesOut: 4,
				BytesIn:  4,
			},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Equal([]promptCall{{host: "example.org", port: 443}}, f.prompter.Calls())
			},
		},
		{
			name:       "IPv4 literal",
			connect:    "192.0.2.10:443",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "192.0.2.10", Port: 443, Decision: logs.DecisionRefuseIPLiteral},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.resolver.Calls())
				r.Empty(f.dialer.Calls())
			},
		},
		{
			name:       "IPv6 literal",
			connect:    "[2001:db8::1]:443",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "2001:db8::1", Port: 443, Decision: logs.DecisionRefuseIPLiteral},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.resolver.Calls())
			},
		},
		{
			name:       "short IPv4 literal",
			connect:    "127.1:443",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "127.1", Port: 443, Decision: logs.DecisionRefuseIPLiteral},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.resolver.Calls())
			},
		},
		{
			name:       "decimal IPv4 literal",
			connect:    "2130706433:443",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "2130706433", Port: 443, Decision: logs.DecisionRefuseIPLiteral},
		},
		{
			name:       "non-ASCII host",
			raw:        "CONNECT bücher.example:443 HTTP/1.1\r\n\r\n",
			wantStatus: http.StatusBadRequest,
			want:       logs.ProxyEntry{Host: "bücher.example", Port: 443, Decision: logs.DecisionDeny},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.prompter.Calls())
			},
		},
		{
			name:       "odd port on allowed host",
			connect:    "example.com:22",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 22, Decision: logs.DecisionRefusePort},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.prompter.Calls())
				r.Empty(f.resolver.Calls())
			},
		},
		{
			name:       "port zero",
			connect:    "example.com:0",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 0, Decision: logs.DecisionRefusePort},
		},
		{
			name:       "port too high",
			connect:    "example.com:70000",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 70000, Decision: logs.DecisionRefusePort},
		},
		{
			name:       "missing port",
			connect:    "example.com",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 0, Decision: logs.DecisionRefusePort},
		},
		{
			name:       "unlisted once",
			connect:    "new.example.net:443",
			resolve:    addrs("192.0.2.10"),
			answer:     proxy.AnswerOnce,
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want: logs.ProxyEntry{
				Host:     "new.example.net",
				Port:     443,
				Decision: logs.DecisionAllowOnce,
				BytesOut: 4,
				BytesIn:  4,
			},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.NoFileExists(filepath.Join(f.stateDir, "overlay.yaml"))
			},
		},
		{
			name:       "unlisted deny",
			connect:    "new.example.net:443",
			resolve:    addrs("192.0.2.10"),
			answer:     proxy.AnswerDeny,
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "new.example.net", Port: 443, Decision: logs.DecisionDeny},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.resolver.Calls())
			},
		},
		{
			name:       "unlisted timeout",
			connect:    "new.example.net:443",
			resolve:    addrs("192.0.2.10"),
			answer:     proxy.AnswerTimeout,
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "new.example.net", Port: 443, Decision: logs.DecisionTimeout},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.resolver.Calls())
			},
		},
		{
			name:       "resolves private",
			connect:    "example.com:443",
			resolve:    addrs("10.0.0.5"),
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionRefuseAddress},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.dialer.Calls())
			},
		},
		{
			name:       "resolves loopback",
			connect:    "example.com:443",
			resolve:    addrs("127.0.0.1"),
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionRefuseAddress},
		},
		{
			name:       "resolves metadata",
			connect:    "example.com:443",
			resolve:    addrs("169.254.169.254"),
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionRefuseAddress},
		},
		{
			name:       "resolves mapped loopback",
			connect:    "example.com:443",
			resolve:    addrs("::ffff:127.0.0.1"),
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionRefuseAddress},
		},
		{
			name:       "resolves IPv6 ULA",
			connect:    "example.com:443",
			resolve:    addrs("fd00::1"),
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionRefuseAddress},
		},
		{
			name:       "any refused address refuses",
			connect:    "example.com:443",
			resolve:    addrs("192.0.2.10", "10.0.0.5"),
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionRefuseAddress},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.dialer.Calls())
			},
		},
		{
			name:       "DNS rebinding",
			connect:    "example.com:443",
			sequence:   [][]netip.Addr{addrs("192.0.2.10"), addrs("127.0.0.1")},
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionAllow, BytesOut: 4, BytesIn: 4},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Len(f.resolver.Calls(), 1)
				r.Equal([]string{"192.0.2.10:443"}, f.dialer.Calls())
			},
		},
		{
			name:       "first address fails",
			connect:    "example.com:443",
			resolve:    addrs("192.0.2.30", "192.0.2.20"),
			fail:       []string{"192.0.2.30:443"},
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionAllow, BytesOut: 4, BytesIn: 4},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Equal([]string{"192.0.2.30:443", "192.0.2.20:443"}, f.dialer.Calls())
			},
		},
		{
			name:       "resolver error",
			connect:    "example.com:443",
			resolveErr: errFake,
			wantStatus: http.StatusBadGateway,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionErrorResolve},
		},
		{
			name:       "no addresses",
			connect:    "example.com:443",
			resolve:    addrs(),
			wantStatus: http.StatusBadGateway,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionErrorResolve},
		},
		{
			name:       "dial error",
			connect:    "example.com:443",
			resolve:    addrs("192.0.2.30"),
			fail:       []string{"192.0.2.30:443"},
			wantStatus: http.StatusBadGateway,
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionErrorDial},
		},
		{
			name:       "byte counts",
			connect:    "example.com:443",
			payload:    []byte("0123456789"),
			extra:      1000,
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			wantEcho:   strings.Repeat("x", 1000) + "0123456789",
			want: logs.ProxyEntry{
				Host:     "example.com",
				Port:     443,
				Decision: logs.DecisionAllow,
				BytesOut: 10,
				BytesIn:  1010,
			},
		},
		{
			name:       "plain HTTP",
			get:        "http://plain.example.com/x?token=s3cr3t",
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			wantEcho:   "upstream body",
			want:       logs.ProxyEntry{Host: "plain.example.com", Port: 80, Decision: logs.DecisionAllow},
			anyBytes:   true,
			check: func(r *require.Assertions, f *proxyFixture) {
				got := <-f.upstream
				r.Equal("/x", got.path)
				r.Empty(got.headers.Values("Proxy-Authorization"))
				r.Empty(got.headers.Values("Proxy-Connection"))

				for _, entry := range f.log.Entries() {
					line, err := json.Marshal(entry)
					r.NoError(err)
					r.NotContains(string(line), "s3cr3t")
					r.NotContains(string(line), "/x")
					r.NotContains(string(line), "Zm9v")
				}
			},
		},
		{
			name:       "plain HTTP odd port",
			get:        "http://plain.example.com:8080/",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "plain.example.com", Port: 8080, Decision: logs.DecisionRefusePort},
		},
		{
			name:       "plain HTTP IP literal",
			get:        "http://192.0.2.10/",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "192.0.2.10", Port: 80, Decision: logs.DecisionRefuseIPLiteral},
		},
		{
			name:       "IPv6 literal without port",
			connect:    "[2001:db8::1]",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "[2001:db8::1]", Port: 0, Decision: logs.DecisionRefuseIPLiteral},
		},
		{
			name:       "trailing-dot IPv4 literal",
			connect:    "192.0.2.10.:443",
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "192.0.2.10.", Port: 443, Decision: logs.DecisionRefuseIPLiteral},
		},
		{
			name:       "connect ignores host header",
			connect:    "example.com:443",
			hostHeader: "evil.example.net:443",
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			wantEcho:   "ping",
			want:       logs.ProxyEntry{Host: "example.com", Port: 443, Decision: logs.DecisionAllow, BytesOut: 4, BytesIn: 4},
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Empty(f.prompter.Calls())
			},
		},
		{
			name:       "prompter error",
			connect:    "new.example.net:443",
			promptErr:  errFake,
			wantStatus: http.StatusForbidden,
			want:       logs.ProxyEntry{Host: "new.example.net", Port: 443, Decision: logs.DecisionDeny},
		},
		{
			name:       "plain HTTP unlisted prompts",
			get:        "http://new.example.net/",
			resolve:    addrs("192.0.2.10"),
			answer:     proxy.AnswerOnce,
			wantStatus: http.StatusOK,
			wantEcho:   "upstream body",
			want:       logs.ProxyEntry{Host: "new.example.net", Port: 80, Decision: logs.DecisionAllowOnce},
			anyBytes:   true,
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Equal([]promptCall{{host: "new.example.net", port: 80}}, f.prompter.Calls())
			},
		},
		{
			name:       "plain HTTP strips hop-by-hop headers",
			get:        "http://plain.example.com/",
			headers:    map[string]string{"Connection": "keep-alive, X-Hop", "X-Hop": "1", "X-Kept": "1"},
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			wantEcho:   "upstream body",
			want:       logs.ProxyEntry{Host: "plain.example.com", Port: 80, Decision: logs.DecisionAllow},
			anyBytes:   true,
			check: func(r *require.Assertions, f *proxyFixture) {
				got := <-f.upstream
				r.Empty(got.headers.Values("X-Hop"))
				r.Equal("1", got.headers.Get("X-Kept"))
				r.Equal([]string{"close"}, got.headers.Values("Connection"))
			},
		},
		{
			name:       "plain HTTP ignores host header",
			raw:        "GET http://plain.example.com/ HTTP/1.1\r\nHost: evil.example.net\r\n\r\n",
			resolve:    addrs("192.0.2.10"),
			wantStatus: http.StatusOK,
			want:       logs.ProxyEntry{Host: "plain.example.com", Port: 80, Decision: logs.DecisionAllow},
			anyBytes:   true,
			check: func(r *require.Assertions, f *proxyFixture) {
				r.Equal("plain.example.com", (<-f.upstream).host)
			},
		},
		{
			name:       "connect origin-form",
			raw:        "CONNECT /path HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
			wantStatus: http.StatusBadRequest,
			noEntry:    true,
		},
		{
			name:       "absolute https",
			raw:        "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantStatus: http.StatusBadRequest,
			noEntry:    true,
		},
		{
			name:       "origin-form",
			raw:        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantStatus: http.StatusBadRequest,
			noEntry:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			f := newProxyFixture(t, tt.extra)
			f.resolver.answers["example.com"] = tt.resolve
			f.resolver.answers["example.org"] = tt.resolve
			f.resolver.answers["a.b.example.org"] = tt.resolve
			f.resolver.answers["new.example.net"] = tt.resolve
			f.resolver.answers["plain.example.com"] = tt.resolve
			f.resolver.sequence = tt.sequence
			f.resolver.err = tt.resolveErr
			f.prompter.answer = tt.answer
			f.prompter.err = tt.promptErr
			for _, address := range tt.fail {
				f.dialer.fail[address] = true
			}
			f.start(t)

			payload := tt.payload
			if payload == nil {
				payload = ping
			}

			// when
			var status int
			var body string
			switch {
			case tt.connect != "":
				host := tt.hostHeader
				if host == "" {
					host = tt.connect
				}

				var echo []byte
				status, echo = f.connectWithHost(t, tt.connect, host, payload)
				body = string(echo)
			case tt.get != "":
				status, body = f.get(t, tt.get, tt.headers)
			default:
				method := strings.Fields(tt.raw)[0]
				status, _ = f.raw(t, tt.raw, method, nil)
			}

			// then
			require.Equal(t, tt.wantStatus, status)
			if tt.wantStatus == http.StatusOK {
				require.Equal(t, tt.wantEcho, body)
			}

			if tt.noEntry {
				require.Never(t, func() bool { return len(f.log.Entries()) > 0 }, 50*time.Millisecond, 5*time.Millisecond)
				return
			}

			got := f.entry(t)
			require.Equal(t, tt.want.Host, got.Host)
			require.Equal(t, tt.want.Port, got.Port)
			require.Equal(t, tt.want.Decision, got.Decision)
			require.False(t, got.Time.IsZero())
			if tt.anyBytes {
				require.Positive(t, got.BytesOut)
				require.Positive(t, got.BytesIn)
			} else {
				require.Equal(t, tt.want.BytesOut, got.BytesOut)
				require.Equal(t, tt.want.BytesIn, got.BytesIn)
			}

			if tt.check != nil {
				tt.check(require.New(t), f)
			}
		})
	}

	t.Run("happy path - always writes overlay", func(t *testing.T) {
		// given
		f := newProxyFixture(t, 0)
		f.resolver.answers["new.example.net"] = addrs("192.0.2.10")
		f.prompter.answer = proxy.AnswerAlways
		f.start(t)

		// when
		status, _ := f.connect(t, "new.example.net:443", ping)

		// then
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, logs.DecisionAllowAlways, f.entry(t).Decision)

		overlay, err := allowlist.Load(filepath.Join(f.stateDir, "overlay.yaml"))
		require.NoError(t, err)
		require.True(t, overlay.Allows("new.example.net", 443))

		status, _ = f.connect(t, "new.example.net:443", ping)
		require.Equal(t, http.StatusOK, status)

		status, _ = f.connect(t, "new.example.net:8443", ping)
		require.Equal(t, http.StatusForbidden, status)

		require.Eventually(t, func() bool { return len(f.log.Entries()) == 3 }, time.Second, 5*time.Millisecond)
		entries := f.log.Entries()
		require.Equal(t, logs.DecisionAllow, entries[1].Decision)
		require.Equal(t, logs.DecisionRefusePort, entries[2].Decision)
		require.Len(t, f.prompter.Calls(), 1)
	})

	t.Run("happy path - overlay loaded at start", func(t *testing.T) {
		// given
		f := newProxyFixture(t, 0)
		f.resolver.answers["new.example.net"] = addrs("192.0.2.10")

		overlay, err := allowlist.Allowlist{}.Add("new.example.net", 443)
		require.NoError(t, err)
		require.NoError(t, overlay.Save(filepath.Join(f.stateDir, "overlay.yaml")))
		f.start(t)

		// when
		status, _ := f.connect(t, "new.example.net:443", ping)

		// then
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, logs.DecisionAllow, f.entry(t).Decision)
		require.Empty(t, f.prompter.Calls())
	})

	t.Run("error - overlay save fails", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}

		// given
		f := newProxyFixture(t, 0)
		f.resolver.answers["new.example.net"] = addrs("192.0.2.10")
		f.prompter.answer = proxy.AnswerAlways
		f.start(t)

		require.NoError(t, os.Chmod(f.stateDir, 0o500))
		t.Cleanup(func() { _ = os.Chmod(f.stateDir, 0o700) })

		// when
		status, _ := f.connect(t, "new.example.net:443", ping)

		// then
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, logs.DecisionAllowOnce, f.entry(t).Decision)
	})

	t.Run("error - log write fails", func(t *testing.T) {
		// given
		f := newProxyFixture(t, 0)
		f.resolver.answers["example.com"] = addrs("192.0.2.10")
		f.log.err = errFake
		f.start(t)

		// when
		status, echo := f.connect(t, "example.com:443", ping)

		// then
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "ping", string(echo))
	})

	t.Run("happy path - connection closes after refusal", func(t *testing.T) {
		// given
		f := newProxyFixture(t, 0)
		f.resolver.answers["example.com"] = addrs("192.0.2.10")
		f.start(t)

		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", f.addr)
		require.NoError(t, err)
		defer conn.Close()

		_, err = io.WriteString(conn, "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n")
		require.NoError(t, err)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// when
		_, _ = io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		_, err = http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})

		// then
		require.Error(t, err)
		require.Never(t, func() bool { return len(f.log.Entries()) > 1 }, 50*time.Millisecond, 5*time.Millisecond)
		require.Equal(t, logs.DecisionRefusePort, f.log.Entries()[0].Decision)
		require.Empty(t, f.dialer.Calls())
	})

	t.Run("error - wrong source", func(t *testing.T) {
		// given
		f := newProxyFixture(t, 0)
		f.start(t)

		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}

		// when
		conn, err := dialer.DialContext(t.Context(), "tcp", f.addr)
		require.NoError(t, err)
		defer conn.Close()

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
		got, err := io.ReadAll(conn)

		// then
		require.NoError(t, err)
		require.Empty(t, got)
		require.Never(t, func() bool { return len(f.log.Entries()) > 0 }, 50*time.Millisecond, 5*time.Millisecond)
		require.Empty(t, f.prompter.Calls())
	})

	t.Run("happy path - shutdown", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		require.NoError(t, os.WriteFile(path, []byte(baseAllowlist), 0o600))

		base, err := allowlist.Load(path)
		require.NoError(t, err)

		s := proxy.NewServer(
			netip.MustParseAddr("127.0.0.1"),
			base,
			filepath.Join(t.TempDir(), "overlay.yaml"),
			&fakeResolver{},
			&fakeDialer{},
			&fakePrompter{},
			&fakeLog{},
			slog.New(slog.DiscardHandler),
		)

		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- s.Serve(ctx, ln) }()

		// when
		cancel()

		// then
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			require.FailNow(t, "Serve did not return")
		}
	})
}
