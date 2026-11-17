package guard

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/audit"
	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
)

const (
	daemonSlice      = "tokend.slice"
	daemonUnit       = "xena-tokend.service"
	unlistedAddr     = "198.51.100.7"
	unlistedHost     = "xena-guard-unlisted.invalid"
	daemonDropPrefix = "xena-tokend-drop: "
)

var (
	ErrTokendInactive  = errors.New("token daemon not active")
	ErrTokendConnected = errors.New("curl exited zero")
	ErrNoTokendDrop    = errors.New("no xena-tokend-drop entry since the case started")
	ErrNoTokendDeny    = errors.New("no deny entry since the case started")
)

type TokendUnlisted struct {
	cmd audit.Commander
}

type TokendProxyUnlisted struct {
	cmd    audit.Commander
	log    ProxyLogReader
	socket string
}

func NewTokendUnlisted(cmd audit.Commander) *TokendUnlisted {
	return &TokendUnlisted{cmd: cmd}
}

func NewTokendProxyUnlisted(cmd audit.Commander, log ProxyLogReader) *TokendProxyUnlisted {
	return &TokendProxyUnlisted{cmd: cmd, log: log, socket: config.TokendSocket()}
}

func (t *TokendUnlisted) Name() string {
	return "tokend-unlisted"
}

func (t *TokendUnlisted) Targets() []string {
	return []string{unlistedAddr}
}

func (t *TokendUnlisted) Run(ctx context.Context, env Env) Result {
	if err := requireTokend(ctx, t.cmd); err != nil {
		return Fail(t.Name(), err.Error())
	}

	start := env.Now().Truncate(time.Second)

	if err := probeTokend(ctx, t.cmd, "https://"+unlistedAddr+"/"); err == nil {
		return Fail(t.Name(), fmt.Errorf("probing %s: %w", unlistedAddr, ErrTokendConnected).Error())
	}

	evidence, err := awaitTokend(ctx, env, func() (string, error) { return t.findDrop(ctx, start) })
	if err != nil {
		return Fail(t.Name(), err.Error())
	}

	if evidence == "" {
		return Fail(t.Name(), fmt.Errorf("finding a drop for %s: %w", unlistedAddr, ErrNoTokendDrop).Error())
	}

	return Pass(t.Name(), "probe: curl exited non-zero", evidence)
}

func (t *TokendUnlisted) findDrop(ctx context.Context, start time.Time) (string, error) {
	out, err := t.cmd.Output(
		ctx,
		"journalctl",
		"-k",
		"-o", "cat",
		"--no-pager",
		"--since", "@"+strconv.FormatInt(start.Unix(), 10),
	)
	if err != nil {
		return "", fmt.Errorf("reading the kernel log: %w", err)
	}

	for line := range strings.Lines(string(out)) {
		if strings.Contains(line, daemonDropPrefix) &&
			strings.Contains(line, "DST="+unlistedAddr+" ") &&
			strings.Contains(line, "DPT="+strconv.Itoa(portHTTPS)+" ") {
			return fmt.Sprintf("drop: %s:%d from the token daemon slice", unlistedAddr, portHTTPS), nil
		}
	}

	return "", nil
}

func (t *TokendProxyUnlisted) Name() string {
	return "tokend-proxy-unlisted"
}

func (t *TokendProxyUnlisted) Targets() []string {
	return []string{unlistedHost}
}

func (t *TokendProxyUnlisted) Run(ctx context.Context, env Env) Result {
	if err := requireTokend(ctx, t.cmd); err != nil {
		return Fail(t.Name(), err.Error())
	}

	start := env.Now().Truncate(time.Second)

	_ = probeTokend(
		ctx,
		t.cmd,
		"--unix-socket", t.socket,
		"-X", "CONNECT",
		"--request-target", fmt.Sprintf("%s:%d", unlistedHost, portHTTPS),
		"http://localhost/",
	)

	evidence, err := awaitTokend(ctx, env, func() (string, error) { return t.findDeny(start) })
	if err != nil {
		return Fail(t.Name(), err.Error())
	}

	if evidence == "" {
		return Fail(t.Name(), fmt.Errorf("finding a deny for %s: %w", unlistedHost, ErrNoTokendDeny).Error())
	}

	return Pass(t.Name(), evidence)
}

func (t *TokendProxyUnlisted) findDeny(start time.Time) (string, error) {
	entries, err := t.log.Entries(start)
	if err != nil {
		return "", fmt.Errorf("reading the proxy-tokend log: %w", err)
	}

	for _, entry := range entries {
		if !entry.Time.Before(start) && entry.Host == unlistedHost && entry.Decision == logs.DecisionDeny {
			return fmt.Sprintf("proxy-tokend: %s:%d deny at %s", entry.Host, entry.Port, clock(entry.Time)), nil
		}
	}

	return "", nil
}

func requireTokend(ctx context.Context, cmd audit.Commander) error {
	out, err := cmd.Output(ctx, "systemctl", "--user", "is-active", daemonUnit)
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return fmt.Errorf("starting xena-tokend before xena guard: %w", ErrTokendInactive)
	}

	return nil
}

func probeTokend(ctx context.Context, cmd audit.Commander, curlArgs ...string) error {
	args := append(
		[]string{
			"--user",
			"--slice=" + daemonSlice,
			"--wait",
			"--pipe",
			"--quiet",
			"curl",
			"-sS",
			"--max-time", "5",
		},
		curlArgs...,
	)

	_, err := cmd.Output(ctx, "systemd-run", args...)

	return err
}

func awaitTokend(ctx context.Context, env Env, find func() (string, error)) (string, error) {
	deadline := env.Now().Add(env.Settle)

	for {
		evidence, err := find()
		if err != nil || evidence != "" || !env.Now().Before(deadline) {
			return evidence, err
		}

		select {
		case <-ctx.Done():
			return "", nil
		case <-time.After(pollInterval):
		}
	}
}
