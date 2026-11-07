package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	answerOnce     = "once"
	answerAlways   = "always"
	answerDeny     = "deny"
	touchSecret    = "touch-check"
	maxPromptBytes = 4096
	reconnectDelay = 5 * time.Second
)

type Asker interface {
	Ask(ctx context.Context, host string, port int) (string, error)
	Show(ctx context.Context, title, body string, critical bool) error
}

type Toucher interface {
	Get(ctx context.Context, name string) ([]byte, error)
}

type PromptClient struct {
	Desktop Asker
	Touch   Toucher
	Timeout time.Duration
	Logger  *slog.Logger
}

type prompt struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type reply struct {
	ID     string `json:"id"`
	Answer string `json:"answer"`
}

func (c PromptClient) Run(ctx context.Context, socket string) error {
	var dialer net.Dialer
	for ctx.Err() == nil {
		conn, err := dialer.DialContext(ctx, "unix", socket)
		if err != nil {
			c.Logger.Warn("connecting to prompt socket", "error", err)
		} else {
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			if err := c.Handle(ctx, conn); err != nil && ctx.Err() == nil {
				c.Logger.Warn("reading prompts", "error", err)
			}
			stop()
			_ = conn.Close()
		}

		select {
		case <-ctx.Done():
		case <-time.After(reconnectDelay):
		}
	}

	return nil
}

func (c PromptClient) Handle(ctx context.Context, conn io.ReadWriter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg      sync.WaitGroup
		writeMu sync.Mutex
	)

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, maxPromptBytes), maxPromptBytes)

	for scanner.Scan() {
		var p prompt
		if err := json.Unmarshal(scanner.Bytes(), &p); err != nil || p.ID == "" {
			continue
		}

		wg.Go(func() {
			answer := c.answer(ctx, p)
			if answer == "" {
				return
			}

			line, err := json.Marshal(reply{ID: p.ID, Answer: answer})
			if err != nil {
				return
			}

			writeMu.Lock()
			_, err = conn.Write(append(line, '\n'))
			writeMu.Unlock()
			if err != nil {
				c.Logger.Warn("writing reply", "id", p.ID, "error", err)
			}
		})
	}

	cancel()
	wg.Wait()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading prompts: %w", err)
	}

	return nil
}

func (c PromptClient) answer(ctx context.Context, p prompt) string {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	if err := checkHost(p.Host, p.Port); err != nil {
		c.Logger.Warn("refusing unsafe host", "id", p.ID, "port", p.Port, "answer", answerDeny)
		return answerDeny
	}

	choice, err := c.Desktop.Ask(ctx, p.Host, p.Port)
	if err != nil {
		c.Logger.Warn("asking for host", "id", p.ID, "host", p.Host, "port", p.Port, "error", err)
		return ""
	}

	answer := ""
	switch choice {
	case answerOnce, answerDeny:
		answer = choice
	case answerAlways:
		answer = c.confirmAlways(ctx, p)
	}

	c.Logger.Info("answering prompt", "id", p.ID, "host", p.Host, "port", p.Port, "answer", answer)
	return answer
}

func (c PromptClient) confirmAlways(ctx context.Context, p prompt) string {
	if _, err := c.Touch.Get(ctx, touchSecret); err != nil {
		c.Logger.Warn("confirming touch", "id", p.ID, "host", p.Host, "port", p.Port, "error", err)

		body := hostPort(p.Host, p.Port) + " allowed once"
		if err := c.Desktop.Show(context.WithoutCancel(ctx), "Touch not confirmed", body, false); err != nil {
			c.Logger.Warn("showing touch failure", "id", p.ID, "error", err)
		}

		return answerOnce
	}

	return answerAlways
}
