package tokend

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/github"
	"github.com/tahardi/xena/internal/vmexec"
)

const (
	refreshLead  = 10 * time.Minute
	minWait      = 30 * time.Second
	unlockRetry  = 5 * time.Minute
	refreshRetry = time.Minute
)

type Minter interface {
	InstallationToken(ctx context.Context) (github.Token, error)
}

type Loop struct {
	Unlock func(ctx context.Context) (Minter, error)
	Runner vmexec.Runner
	Now    func() time.Time
	Logger *slog.Logger
	minter Minter
	until  time.Time
}

func (l *Loop) Step(ctx context.Context) (time.Duration, error) {
	now := l.Now()

	if l.minter == nil || !now.Before(l.until) {
		l.minter = nil

		minter, err := l.Unlock(ctx)
		if err != nil {
			return unlockRetry, fmt.Errorf("unlocking app key: %w", err)
		}

		l.minter = minter
		y, m, d := now.Date()
		l.until = time.Date(y, m, d+1, 0, 0, 0, 0, now.Location())
	}

	tok, err := l.minter.InstallationToken(ctx)
	if err != nil {
		return refreshRetry, fmt.Errorf("minting token: %w", err)
	}

	if _, err := l.Runner.Run(ctx, "token-put", nil, strings.NewReader(tok.Value)); err != nil {
		return refreshRetry, fmt.Errorf("pushing token: %w", err)
	}

	l.Logger.Info("pushed token", "expires_at", tok.ExpiresAt)

	return max(tok.ExpiresAt.Sub(now)-refreshLead, minWait), nil
}

func (l *Loop) Run(ctx context.Context) error {
	for {
		wait, err := l.Step(ctx)
		if err != nil {
			l.Logger.Error("refreshing token", "error", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
