package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"
)

type Answer string

const (
	AnswerOnce    Answer = "once"
	AnswerAlways  Answer = "always"
	AnswerDeny    Answer = "deny"
	AnswerTimeout Answer = "timeout"
)

const (
	maxReplyBytes = 4096
	socketMode    = 0o660
	drainTimeout  = 100 * time.Millisecond
	versionMask   = 0x0f
	version4      = 0x40
	variantMask   = 0x3f
	variantRFC    = 0x80
)

type Prompter interface {
	Ask(ctx context.Context, host string, port int) (Answer, error)
}

type SocketPrompter struct {
	timeout time.Duration
	logger  *slog.Logger

	mu      sync.Mutex
	client  net.Conn
	replies map[string]chan Answer
	open    map[string]*openPrompt
}

type openPrompt struct {
	port   int
	done   chan struct{}
	answer Answer
}

type promptRequest struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type promptReply struct {
	ID     string `json:"id"`
	Answer Answer `json:"answer"`
}

func NewSocketPrompter(timeout time.Duration, logger *slog.Logger) *SocketPrompter {
	return &SocketPrompter{
		timeout: timeout,
		logger:  logger,
		replies: make(map[string]chan Answer),
		open:    make(map[string]*openPrompt),
	}
}

func (p *SocketPrompter) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			p.replaceClient(nil)
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accepting prompt client: %w", err)
		}

		p.replaceClient(conn)
		go p.readReplies(conn)
	}
}

func (p *SocketPrompter) Ask(ctx context.Context, host string, port int) (Answer, error) {
	for {
		p.mu.Lock()
		if open, ok := p.open[host]; ok {
			p.mu.Unlock()

			select {
			case <-open.done:
			case <-ctx.Done():
				return "", ctx.Err()
			}

			if open.port == port && open.answer != "" {
				return open.answer, nil
			}
			continue
		}

		open := &openPrompt{port: port, done: make(chan struct{})}
		p.open[host] = open
		client := p.client
		p.mu.Unlock()

		answer, err := p.prompt(ctx, client, host, port)

		p.mu.Lock()
		delete(p.open, host)
		open.answer = answer
		p.mu.Unlock()

		close(open.done)
		return answer, err
	}
}

func (p *SocketPrompter) prompt(ctx context.Context, client net.Conn, host string, port int) (Answer, error) {
	if client == nil {
		p.logger.Warn("no prompt client connected", "host", host)
		return AnswerDeny, nil
	}

	id := NewID()
	reply := make(chan Answer, 1)

	p.mu.Lock()
	p.replies[id] = reply
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.replies, id)
		p.mu.Unlock()
	}()

	line, err := json.Marshal(promptRequest{ID: id, Host: host, Port: port})
	if err != nil {
		return "", fmt.Errorf("encoding prompt: %w", err)
	}

	if _, err := client.Write(append(line, '\n')); err != nil {
		p.logger.Warn("no prompt client connected", "host", host)
		return AnswerDeny, nil
	}

	timer := time.NewTimer(p.timeout)
	defer timer.Stop()

	select {
	case answer := <-reply:
		return answer, nil
	case <-timer.C:
		return AnswerTimeout, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (p *SocketPrompter) replaceClient(conn net.Conn) {
	p.mu.Lock()
	old := p.client
	p.client = conn
	p.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
}

func (p *SocketPrompter) readReplies(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, maxReplyBytes+1), maxReplyBytes+1)

	for scanner.Scan() {
		var reply promptReply
		if err := json.Unmarshal(scanner.Bytes(), &reply); err != nil {
			continue
		}

		switch reply.Answer {
		case AnswerOnce, AnswerAlways, AnswerDeny:
		case AnswerTimeout:
			continue
		default:
			continue
		}

		p.mu.Lock()
		ch := p.replies[reply.ID]
		p.mu.Unlock()

		if ch != nil {
			select {
			case ch <- reply.Answer:
			default:
			}
		}
	}

	p.mu.Lock()
	if p.client == conn {
		p.client = nil
	}
	p.mu.Unlock()

	if scanner.Err() != nil {
		_ = conn.SetReadDeadline(time.Now().Add(drainTimeout))
		_, _ = io.Copy(io.Discard, conn)
	}

	_ = conn.Close()
}

func ListenPromptSocket(ctx context.Context, path, group string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("listening on prompt socket: %w", err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on prompt socket: %w", err)
	}

	if err := setSocketOwner(path, group); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("listening on prompt socket: %w", err)
	}
	return ln, nil
}

func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])

	b[6] = b[6]&versionMask | version4
	b[8] = b[8]&variantMask | variantRFC
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func setSocketOwner(path, group string) error {
	if err := os.Chmod(path, socketMode); err != nil {
		return fmt.Errorf("setting mode of %s: %w", path, err)
	}

	if group == "" {
		return nil
	}

	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("looking up group %s: %w", group, err)
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parsing gid of group %s: %w", group, err)
	}

	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("setting group of %s: %w", path, err)
	}
	return nil
}
