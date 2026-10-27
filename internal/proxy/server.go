package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tahardi/xena/internal/allowlist"
	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/netrange"
)

const (
	readHeaderTimeout = 10 * time.Second
	maxHeaderBytes    = 16 << 10
	maxPort           = 65535
	defaultHTTPPort   = "80"
)

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

type Server struct {
	source      netip.Addr
	base        allowlist.Allowlist
	overlayPath string
	resolver    Resolver
	dialer      Dialer
	prompter    Prompter
	log         *logs.Writer
	logger      *slog.Logger

	mu      sync.Mutex
	overlay allowlist.Allowlist
}

func NewServer(
	source netip.Addr,
	base allowlist.Allowlist,
	overlayPath string,
	resolver Resolver,
	dialer Dialer,
	prompter Prompter,
	log *logs.Writer,
	logger *slog.Logger,
) *Server {
	return &Server{
		source:      source,
		base:        base,
		overlayPath: overlayPath,
		resolver:    resolver,
		dialer:      dialer,
		prompter:    prompter,
		log:         log,
		logger:      logger,
	}
}

func (s *Server) LoadOverlay() error {
	overlay, err := allowlist.Load(s.overlayPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("loading overlay: %w", err)
	}

	s.mu.Lock()
	s.overlay = overlay
	s.mu.Unlock()
	return nil
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: readHeaderTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	stop := context.AfterFunc(ctx, func() { _ = srv.Shutdown(context.WithoutCancel(ctx)) })
	defer stop()

	err := srv.Serve(&sourceListener{Listener: ln, source: s.source, logger: s.logger})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serving proxy: %w", err)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	target, ok := egressTarget(r)
	if !ok {
		http.Error(w, "xena-proxy: bad request", http.StatusBadRequest)
		return
	}

	host, port := splitTarget(target)
	entry := logs.ProxyEntry{Time: start, Host: host, Port: port}
	// The entry must be written even after the request context ends, and logs.Writer.Write takes no context.
	defer s.writeEntry(&entry) //nolint:contextcheck

	status := s.decide(r.Context(), &entry)
	if status != 0 {
		http.Error(w, "xena-proxy: "+entry.Decision, status)
		return
	}

	upstream, decision, err := s.dialChecked(r.Context(), entry.Host, entry.Port)
	if err != nil {
		s.logger.Warn("connecting upstream", "host", entry.Host, "port", entry.Port, "error", err)
		entry.Decision = decision

		status := http.StatusBadGateway
		if decision == logs.DecisionRefuseAddress {
			status = http.StatusForbidden
		}
		http.Error(w, "xena-proxy: "+decision, status)
		return
	}
	defer upstream.Close()

	if r.Method == http.MethodConnect {
		s.tunnel(w, upstream)
	} else {
		s.forward(w, r, upstream)
	}

	entry.BytesOut = upstream.out.Load()
	entry.BytesIn = upstream.in.Load()
}

func (s *Server) decide(ctx context.Context, entry *logs.ProxyEntry) int {
	if netrange.IsIPLiteral(entry.Host) {
		entry.Decision = logs.DecisionRefuseIPLiteral
		return http.StatusForbidden
	}

	name, err := allowlist.Normalize(entry.Host)
	if err != nil {
		entry.Decision = logs.DecisionDeny
		return http.StatusBadRequest
	}
	entry.Host = name

	s.mu.Lock()
	ports := s.base.Merge(s.overlay).Ports(name)
	s.mu.Unlock()

	if entry.Port < 1 || entry.Port > maxPort || (len(ports) > 0 && !slices.Contains(ports, entry.Port)) {
		entry.Decision = logs.DecisionRefusePort
		return http.StatusForbidden
	}

	if len(ports) > 0 {
		entry.Decision = logs.DecisionAllow
		return 0
	}

	answer, err := s.prompter.Ask(ctx, name, entry.Port)
	if err != nil {
		entry.Decision = logs.DecisionDeny
		return http.StatusForbidden
	}

	switch answer {
	case AnswerOnce:
		entry.Decision = logs.DecisionAllowOnce
		return 0
	case AnswerAlways:
		entry.Decision = s.saveAlways(name, entry.Port)
		return 0
	case AnswerTimeout:
		entry.Decision = logs.DecisionTimeout
		return http.StatusForbidden
	case AnswerDeny:
		entry.Decision = logs.DecisionDeny
		return http.StatusForbidden
	default:
		entry.Decision = logs.DecisionDeny
		return http.StatusForbidden
	}
}

func (s *Server) saveAlways(host string, port int) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	overlay, err := s.overlay.Add(host, port)
	if err == nil {
		err = overlay.Save(s.overlayPath)
	}
	if err != nil {
		s.logger.Warn("saving overlay", "host", host, "port", port, "error", err)
		return logs.DecisionAllowOnce
	}

	s.overlay = overlay
	return logs.DecisionAllowAlways
}

func (s *Server) tunnel(w http.ResponseWriter, upstream *countingConn) {
	client, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		s.logger.Warn("hijacking connection", "error", err)
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(upstream, buf)
		closeWrite(upstream)
	})
	wg.Go(func() {
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	})
	wg.Wait()
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, upstream *countingConn) {
	out := r.Clone(r.Context())
	for _, value := range r.Header.Values("Connection") {
		for name := range strings.SplitSeq(value, ",") {
			out.Header.Del(strings.TrimSpace(name))
		}
	}

	for _, name := range hopHeaders {
		out.Header.Del(name)
	}

	out.Close = true

	if err := out.Write(upstream); err != nil {
		s.logger.Warn("forwarding request", "host", r.URL.Hostname(), "error", err)
		http.Error(w, "xena-proxy: bad gateway", http.StatusBadGateway)
		return
	}

	client, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		s.logger.Warn("hijacking connection", "error", err)
		return
	}
	defer client.Close()

	_, _ = io.Copy(client, upstream)
}

func (s *Server) writeEntry(entry *logs.ProxyEntry) {
	if err := s.log.Write(*entry); err != nil {
		s.logger.Warn("writing proxy log", "error", err)
	}
}

func egressTarget(r *http.Request) (string, bool) {
	if r.Method == http.MethodConnect {
		return r.URL.Host, r.URL.Host != ""
	}

	if r.URL.Scheme != "http" || r.URL.Host == "" {
		return "", false
	}

	if r.URL.Port() == "" {
		return net.JoinHostPort(r.URL.Hostname(), defaultHTTPPort), true
	}
	return r.URL.Host, true
}

func splitTarget(target string) (string, int) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return target, 0
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0
	}
	return host, port
}
