package notify

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os/exec"
	"strconv"
	"strings"

	"github.com/tahardi/xena/internal/allowlist"
)

const (
	appName    = "--app-name=Xena"
	notifySend = "notify-send"
	promptText = "Xena: VM wants a new host"
	maxPort    = 65535
)

var ErrUnsafeHost = errors.New("unsafe host")

type Desktop struct {
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func ExecRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func (d Desktop) Ask(ctx context.Context, host string, port int) (string, error) {
	if err := checkHost(host, port); err != nil {
		return "", err
	}

	out, err := d.Run(
		ctx,
		notifySend,
		appName,
		"--urgency=critical",
		"--action=once=Allow once",
		"--action=always=Allow always",
		"--action=deny=Deny",
		"--wait",
		promptText,
		hostPort(host, port),
	)
	if err != nil {
		return "", fmt.Errorf("running notify-send: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func (d Desktop) Show(ctx context.Context, title, body string, critical bool) error {
	urgency := "--urgency=normal"
	if critical {
		urgency = "--urgency=critical"
	}

	_, err := d.Run(ctx, notifySend, appName, urgency, html.EscapeString(title), html.EscapeString(body))
	if err != nil {
		return fmt.Errorf("running notify-send: %w", err)
	}

	return nil
}

func checkHost(host string, port int) error {
	name, err := allowlist.Normalize(host)
	if err != nil {
		return fmt.Errorf("checking host: %w", err)
	}

	if name != host || port < 1 || port > maxPort {
		return fmt.Errorf("checking host: %w", ErrUnsafeHost)
	}

	return nil
}

func hostPort(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}
