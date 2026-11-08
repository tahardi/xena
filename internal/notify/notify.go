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
	appName      = "--app-name=Xena"
	notifySend   = "notify-send"
	zenity       = "zenity"
	alwaysLabel  = "Allow always"
	maxPort      = 65535
	zenityCancel = 1
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
		zenity,
		"--question",
		"--title=Xena",
		"--text=VM wants a new host:\n"+hostPort(host, port),
		"--no-markup",
		"--ok-label=Allow once",
		"--cancel-label=Deny",
		"--extra-button="+alwaysLabel,
	)
	if err == nil {
		return answerOnce, nil
	}

	var exit interface{ ExitCode() int }
	if !errors.As(err, &exit) || exit.ExitCode() != zenityCancel {
		return "", fmt.Errorf("running zenity: %w", err)
	}

	if strings.TrimSpace(string(out)) == alwaysLabel {
		return answerAlways, nil
	}

	return answerDeny, nil
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
