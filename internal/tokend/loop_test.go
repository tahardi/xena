package tokend_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/github"
	"github.com/tahardi/xena/internal/tokend"
)

var (
	errUnlock = errors.New("made-up unlock failure")
	errMint   = errors.New("made-up mint failure")
	errPush   = errors.New("made-up push failure")
)

type fakeMinter struct {
	token github.Token
	err   error
	calls int
}

func (f *fakeMinter) InstallationToken(_ context.Context) (github.Token, error) {
	f.calls++
	return f.token, f.err
}

type runnerCall struct {
	verb  string
	args  []string
	stdin string
}

type fakeRunner struct {
	err    error
	calls  []runnerCall
	onCall func()
}

func (f *fakeRunner) Run(_ context.Context, verb string, args []string, stdin io.Reader) ([]byte, error) {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return nil, err
	}

	f.calls = append(f.calls, runnerCall{verb: verb, args: args, stdin: string(data)})

	if f.onCall != nil {
		f.onCall()
	}

	return nil, f.err
}

type loopStep struct {
	at            time.Time
	expiresAt     time.Time
	unlockErr     error
	mintErr       error
	pushErr       error
	wantWait      time.Duration
	wantErrPrefix string
}

func TestLoop_Step(t *testing.T) {
	loc := time.FixedZone("test", -5*60*60)
	at := func(day, hour, minute int) time.Time {
		return time.Date(2026, 10, day, hour, minute, 0, 0, loc)
	}

	tests := []struct {
		name        string
		steps       []loopStep
		wantUnlocks int
		wantMints   int
		wantPushes  int
	}{
		{
			name: "happy path - first step unlocks, mints, pushes",
			steps: []loopStep{
				{at: at(24, 12, 0), expiresAt: at(24, 13, 0), wantWait: 50 * time.Minute},
			},
			wantUnlocks: 1,
			wantMints:   1,
			wantPushes:  1,
		},
		{
			name: "happy path - same day reuses key",
			steps: []loopStep{
				{at: at(24, 12, 0), expiresAt: at(24, 13, 0), wantWait: 50 * time.Minute},
				{at: at(24, 12, 50), expiresAt: at(24, 13, 50), wantWait: 50 * time.Minute},
			},
			wantUnlocks: 1,
			wantMints:   2,
			wantPushes:  2,
		},
		{
			name: "happy path - after local midnight unlocks again",
			steps: []loopStep{
				{at: at(24, 12, 0), expiresAt: at(24, 13, 0), wantWait: 50 * time.Minute},
				{at: at(25, 0, 5), expiresAt: at(25, 1, 5), wantWait: 50 * time.Minute},
			},
			wantUnlocks: 2,
			wantMints:   2,
			wantPushes:  2,
		},
		{
			name: "happy path - token near expiry waits at least 30s",
			steps: []loopStep{
				{at: at(24, 12, 0), expiresAt: at(24, 12, 5), wantWait: 30 * time.Second},
			},
			wantUnlocks: 1,
			wantMints:   1,
			wantPushes:  1,
		},
		{
			name: "happy path - midnight is the cutoff",
			steps: []loopStep{
				{at: at(24, 12, 0), expiresAt: at(24, 13, 0), wantWait: 50 * time.Minute},
				{at: at(24, 23, 59), expiresAt: at(25, 0, 59), wantWait: 50 * time.Minute},
				{at: at(25, 0, 0), expiresAt: at(25, 1, 0), wantWait: 50 * time.Minute},
			},
			wantUnlocks: 2,
			wantMints:   3,
			wantPushes:  3,
		},
		{
			name: "happy path - unlock failure then success pushes",
			steps: []loopStep{
				{
					at:            at(24, 12, 0),
					unlockErr:     errUnlock,
					wantWait:      5 * time.Minute,
					wantErrPrefix: "unlocking app key",
				},
				{at: at(24, 12, 5), expiresAt: at(24, 13, 5), wantWait: 50 * time.Minute},
			},
			wantUnlocks: 2,
			wantMints:   1,
			wantPushes:  1,
		},
		{
			name: "happy path - push retry mints a fresh token",
			steps: []loopStep{
				{
					at:            at(24, 12, 0),
					expiresAt:     at(24, 13, 0),
					pushErr:       errPush,
					wantWait:      time.Minute,
					wantErrPrefix: "pushing token",
				},
				{at: at(24, 12, 1), expiresAt: at(24, 13, 1), wantWait: 50 * time.Minute},
			},
			wantUnlocks: 1,
			wantMints:   2,
			wantPushes:  2,
		},
		{
			name: "error - unlock fails after midnight drops old key",
			steps: []loopStep{
				{at: at(24, 12, 0), expiresAt: at(24, 13, 0), wantWait: 50 * time.Minute},
				{
					at:            at(25, 0, 5),
					unlockErr:     errUnlock,
					wantWait:      5 * time.Minute,
					wantErrPrefix: "unlocking app key",
				},
				{
					at:            at(25, 0, 10),
					unlockErr:     errUnlock,
					wantWait:      5 * time.Minute,
					wantErrPrefix: "unlocking app key",
				},
			},
			wantUnlocks: 3,
			wantMints:   1,
			wantPushes:  1,
		},
		{
			name: "error - unlock fails",
			steps: []loopStep{
				{
					at:            at(24, 12, 0),
					unlockErr:     errUnlock,
					wantWait:      5 * time.Minute,
					wantErrPrefix: "unlocking app key",
				},
			},
			wantUnlocks: 1,
			wantMints:   0,
			wantPushes:  0,
		},
		{
			name: "error - mint fails",
			steps: []loopStep{
				{at: at(24, 12, 0), mintErr: errMint, wantWait: time.Minute, wantErrPrefix: "minting token"},
				{at: at(24, 12, 0), mintErr: errMint, wantWait: time.Minute, wantErrPrefix: "minting token"},
			},
			wantUnlocks: 1,
			wantMints:   2,
			wantPushes:  0,
		},
		{
			name: "error - push fails",
			steps: []loopStep{
				{
					at:            at(24, 12, 0),
					expiresAt:     at(24, 13, 0),
					pushErr:       errPush,
					wantWait:      time.Minute,
					wantErrPrefix: "pushing token",
				},
			},
			wantUnlocks: 1,
			wantMints:   1,
			wantPushes:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var now time.Time
			var unlockErr error
			unlocks := 0
			minter := &fakeMinter{}
			runner := &fakeRunner{}
			loop := &tokend.Loop{
				Unlock: func(_ context.Context) (tokend.Minter, error) {
					unlocks++
					if unlockErr != nil {
						return nil, unlockErr
					}
					return minter, nil
				},
				Runner: runner,
				Now:    func() time.Time { return now },
				Logger: slog.New(slog.DiscardHandler),
			}

			for _, s := range tt.steps {
				// given
				now = s.at
				unlockErr = s.unlockErr
				minter.token = github.Token{Value: "ghs_madeup", ExpiresAt: s.expiresAt}
				minter.err = s.mintErr
				runner.err = s.pushErr

				// when
				wait, err := loop.Step(context.Background())

				// then
				assert.Equal(t, s.wantWait, wait)
				if s.wantErrPrefix == "" {
					require.NoError(t, err)
					continue
				}

				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), s.wantErrPrefix), err.Error())
				assert.NotContains(t, err.Error(), "ghs_madeup")
			}

			// then
			assert.Equal(t, tt.wantUnlocks, unlocks)
			assert.Equal(t, tt.wantMints, minter.calls)
			require.Len(t, runner.calls, tt.wantPushes)
			for _, c := range runner.calls {
				assert.Equal(t, "token-put", c.verb)
				assert.Empty(t, c.args)
				assert.Equal(t, "ghs_madeup", c.stdin)
			}
		})
	}
}

func TestLoop_Run(t *testing.T) {
	tests := []struct {
		name    string
		pushErr error
	}{
		{name: "happy path - stops on cancel"},
		{name: "happy path - stops on cancel after failed step", pushErr: errPush},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
			minter := &fakeMinter{token: github.Token{Value: "ghs_madeup", ExpiresAt: now.Add(time.Hour)}}
			runner := &fakeRunner{err: tt.pushErr, onCall: cancel}
			loop := &tokend.Loop{
				Unlock: func(_ context.Context) (tokend.Minter, error) { return minter, nil },
				Runner: runner,
				Now:    func() time.Time { return now },
				Logger: slog.New(slog.DiscardHandler),
			}

			// when
			err := loop.Run(ctx)

			// then
			require.NoError(t, err)
			assert.Len(t, runner.calls, 1)
		})
	}
}
