package grant

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/inventory"
	"github.com/tahardi/xena/internal/vmexec"
)

const (
	RefreshEvery = 50 * time.Minute
	RetryAfter   = time.Minute
)

var (
	ErrHoursOutOfRange      = errors.New("hours out of range")
	ErrInvalidSecret        = errors.New("invalid issuing secret")
	ErrEmptyToken           = errors.New("empty token")
	ErrIncompleteCredential = errors.New("issued credential is missing fields")
	ErrRefreshRunning       = errors.New("refresh still running")
)

type Command = inventory.Command

type Background interface {
	Start(ctx context.Context, stdin []byte, name string, args ...string) error
}

type Secrets interface {
	Get(ctx context.Context, name string) ([]byte, error)
}

type Granter struct {
	Secrets      Secrets
	Runner       vmexec.Runner
	Cmd          Command
	Background   Background
	Xena         string
	Now          func() time.Time
	Sleep        func(ctx context.Context, d time.Duration) error
	Log          *slog.Logger
	DefaultHours int
	MaxHours     int
}

func (g Granter) Grant(ctx context.Context, p Provider, hours int) (time.Time, error) {
	if hours == 0 {
		hours = g.DefaultHours
	}
	if hours < 1 || hours > g.MaxHours {
		return time.Time{}, fmt.Errorf("checking hours: %w: %d not in 1..%d", ErrHoursOutOfRange, hours, g.MaxHours)
	}

	now := g.Now()
	lifetime := time.Duration(hours) * time.Hour
	end := now.Add(lifetime)
	secs := int(lifetime.Seconds())

	_, _ = g.Cmd.Output(ctx, nil, "systemctl", "--user", "stop", clearUnit(p)+".timer")

	if err := g.stopRefresh(ctx, p); err != nil {
		return time.Time{}, err
	}

	issuing, err := g.Secrets.Get(ctx, p.SecretName())
	if err != nil {
		return time.Time{}, fmt.Errorf("reading %s: %w", p.SecretName(), err)
	}

	cred, err := p.Issue(ctx, issuing, lifetime, now)
	if err != nil {
		return time.Time{}, fmt.Errorf("issuing %s grant: %w", p.Name(), err)
	}

	if _, err := g.Runner.Run(ctx, "secret-put", []string{p.VMSecret()}, bytes.NewReader(cred.Value)); err != nil {
		return time.Time{}, fmt.Errorf("delivering %s: %w", p.VMSecret(), err)
	}

	_, err = g.Cmd.Output(
		ctx,
		nil,
		"systemd-run",
		"--user",
		"--collect",
		"--unit="+clearUnit(p),
		fmt.Sprintf("--on-active=%ds", secs),
		g.Xena,
		"grant",
		"clear",
		p.Name(),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf("scheduling clear: %w", err)
	}

	if !cred.ExpiresAt.Before(end) {
		return end, nil
	}

	err = g.Background.Start(
		ctx,
		issuing,
		"systemd-run",
		"--user",
		"--scope",
		"--collect",
		"--unit="+refreshUnit(p),
		fmt.Sprintf("--property=RuntimeMaxSec=%d", secs+int(RetryAfter.Seconds())),
		"systemd-cat",
		"-t",
		"xena-grant",
		g.Xena,
		"grant",
		"refresh",
		p.Name(),
		"--until",
		end.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf("starting refresh: %w", err)
	}

	return end, nil
}

func (g Granter) Clear(ctx context.Context, p Provider) error {
	stopErr := g.stopRefresh(ctx, p)

	if _, err := g.Runner.Run(ctx, "secret-clear", []string{p.VMSecret()}, nil); err != nil {
		return errors.Join(stopErr, fmt.Errorf("clearing %s: %w", p.VMSecret(), err))
	}

	return stopErr
}

func (g Granter) Refresh(ctx context.Context, p Provider, issuing []byte, until time.Time) error {
	if len(bytes.TrimSpace(issuing)) == 0 {
		return fmt.Errorf("checking issuing secret: %w", ErrInvalidSecret)
	}

	next := g.Now().Add(RefreshEvery)

	for {
		wake := next
		if until.Before(wake) {
			wake = until
		}

		if err := g.Sleep(ctx, max(0, wake.Sub(g.Now()))); err != nil {
			return fmt.Errorf("waiting to refresh: %w", err)
		}

		now := g.Now()
		if !now.Before(until) {
			if _, err := g.Runner.Run(ctx, "secret-clear", []string{p.VMSecret()}, nil); err != nil {
				return fmt.Errorf("clearing %s: %w", p.VMSecret(), err)
			}

			return nil
		}

		next = now.Add(g.refreshOnce(ctx, p, issuing, now, until))
	}
}

func (g Granter) stopRefresh(ctx context.Context, p Provider) error {
	unit := refreshUnit(p) + ".scope"
	_, _ = g.Cmd.Output(ctx, nil, "systemctl", "--user", "stop", unit)

	out, _ := g.Cmd.Output(ctx, nil, "systemctl", "--user", "is-active", unit)
	state := strings.TrimSpace(string(out))
	if state != "inactive" && state != "failed" {
		return fmt.Errorf("stopping %s: %w (state %q)", unit, ErrRefreshRunning, state)
	}

	return nil
}

func (g Granter) refreshOnce(ctx context.Context, p Provider, issuing []byte, now, until time.Time) time.Duration {
	cred, err := p.Issue(ctx, issuing, until.Sub(now), now)
	if err == nil {
		_, err = g.Runner.Run(ctx, "secret-put", []string{p.VMSecret()}, bytes.NewReader(cred.Value))
	}

	if err != nil {
		g.Log.ErrorContext(ctx, "refreshing grant", "provider", p.Name(), "error", err)
		return RetryAfter
	}

	g.Log.InfoContext(ctx, "refreshed", "provider", p.Name(), "expires_at", cred.ExpiresAt)

	return RefreshEvery
}

func Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func clearUnit(p Provider) string {
	return "xena-grant-clear-" + p.Name()
}

func refreshUnit(p Provider) string {
	return "xena-grant-refresh-" + p.Name()
}
