package grant_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/grant"
)

var (
	errFake = errors.New("fake failure")
	now     = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
)

type fakeCall struct {
	env  []string
	name string
	args []string
}

type fakeCommand struct {
	outs   [][]byte
	errs   []error
	onCall func(env []string)
	calls  []fakeCall
}

func (f *fakeCommand) Output(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
	i := len(f.calls)
	f.calls = append(f.calls, fakeCall{env: env, name: name, args: args})

	if f.onCall != nil {
		f.onCall(env)
	}

	var out []byte
	if i < len(f.outs) {
		out = f.outs[i]
	}

	var err error
	if i < len(f.errs) {
		err = f.errs[i]
	}

	return out, err
}

func (f *fakeCommand) lines() []string {
	lines := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		lines = append(lines, c.name+" "+strings.Join(c.args, " "))
	}

	return lines
}

type fakeSecrets struct {
	err   error
	names []string
}

func (f *fakeSecrets) Get(_ context.Context, name string) ([]byte, error) {
	f.names = append(f.names, name)

	if f.err != nil {
		return nil, f.err
	}

	return []byte("made-up-issuing"), nil
}

type runCall struct {
	verb  string
	args  []string
	stdin []byte
}

type fakeRunner struct {
	err   error
	errs  []error
	calls []runCall
}

func (f *fakeRunner) Run(_ context.Context, verb string, args []string, stdin io.Reader) ([]byte, error) {
	var data []byte
	if stdin != nil {
		var err error
		data, err = io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
	}

	i := len(f.calls)
	f.calls = append(f.calls, runCall{verb: verb, args: args, stdin: data})

	if f.err == nil && i < len(f.errs) {
		return nil, f.errs[i]
	}

	return nil, f.err
}

type fakeBackground struct {
	err   error
	stdin []byte
	name  string
	args  []string
	calls int
}

func (f *fakeBackground) Start(_ context.Context, stdin []byte, name string, args ...string) error {
	f.calls++
	f.stdin = stdin
	f.name = name
	f.args = args

	return f.err
}

type fakeProvider struct {
	name        string
	secret      string
	vmSecret    string
	maxLifetime time.Duration
	errs        []error
	lifetimes   []time.Duration
}

func awsProvider() *fakeProvider {
	return &fakeProvider{name: "aws", secret: "aws-grant", vmSecret: "aws-credentials"}
}

func gcpProvider() *fakeProvider {
	return &fakeProvider{name: "gcp", secret: "gcp-grant", vmSecret: "gcp-token", maxLifetime: time.Hour}
}

func (f *fakeProvider) Name() string {
	return f.name
}

func (f *fakeProvider) SecretName() string {
	return f.secret
}

func (f *fakeProvider) VMSecret() string {
	return f.vmSecret
}

func (f *fakeProvider) Issue(
	_ context.Context,
	_ []byte,
	lifetime time.Duration,
	now time.Time,
) (grant.Credential, error) {
	i := len(f.lifetimes)
	f.lifetimes = append(f.lifetimes, lifetime)

	if i < len(f.errs) && f.errs[i] != nil {
		return grant.Credential{}, f.errs[i]
	}

	if f.maxLifetime > 0 {
		lifetime = min(lifetime, f.maxLifetime)
	}

	return grant.Credential{Value: []byte("made-up-credential"), ExpiresAt: now.Add(lifetime)}, nil
}

type fakeClock struct {
	now    time.Time
	err    error
	sleeps []time.Duration
}

func (f *fakeClock) Now() time.Time {
	return f.now
}

func (f *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	if f.err != nil {
		return f.err
	}

	f.sleeps = append(f.sleeps, d)
	f.now = f.now.Add(d)

	return nil
}

type granterFakes struct {
	secrets    *fakeSecrets
	runner     *fakeRunner
	cmd        *fakeCommand
	background *fakeBackground
	clock      *fakeClock
	log        *bytes.Buffer
}

func newGranter() (grant.Granter, granterFakes) {
	f := granterFakes{
		secrets:    &fakeSecrets{},
		runner:     &fakeRunner{},
		cmd:        &fakeCommand{},
		background: &fakeBackground{},
		clock:      &fakeClock{now: now},
		log:        &bytes.Buffer{},
	}

	g := grant.Granter{
		Secrets:      f.secrets,
		Runner:       f.runner,
		Cmd:          f.cmd,
		Background:   f.background,
		Xena:         "/usr/local/bin/xena",
		Now:          f.clock.Now,
		Sleep:        f.clock.Sleep,
		Log:          slog.New(slog.NewTextHandler(f.log, nil)),
		DefaultHours: 4,
		MaxHours:     8,
	}

	return g, f
}

func TestGranter_Grant(t *testing.T) {
	stops := func(name string) []string {
		return []string{
			"systemctl --user stop xena-grant-clear-" + name + ".timer",
			"systemctl --user stop xena-grant-refresh-" + name + ".scope",
		}
	}

	tests := []struct {
		name         string
		provider     *fakeProvider
		hours        int
		secretsErr   error
		runnerErr    error
		cmdErrs      []error
		bgErr        error
		wantLifetime time.Duration
		wantPut      []string
		wantCmd      []string
		wantBg       []string
		want         time.Time
		wantErr      error
		wantPrefix   string
		wantHidden   string
		noSecrets    bool
		noRunner     bool
	}{
		{
			name:         "happy path - default hours",
			provider:     awsProvider(),
			hours:        0,
			wantLifetime: 4 * time.Hour,
			wantPut:      []string{"aws-credentials"},
			wantCmd: append(
				stops("aws"),
				"systemd-run --user --collect --unit=xena-grant-clear-aws --on-active=14400s /usr/local/bin/xena grant clear aws",
			),
			want: now.Add(4 * time.Hour),
		},
		{
			name:         "happy path - max hours",
			provider:     awsProvider(),
			hours:        8,
			wantLifetime: 8 * time.Hour,
			wantPut:      []string{"aws-credentials"},
			wantCmd: append(
				stops("aws"),
				"systemd-run --user --collect --unit=xena-grant-clear-aws --on-active=28800s /usr/local/bin/xena grant clear aws",
			),
			want: now.Add(8 * time.Hour),
		},
		{
			name:         "happy path - stop of a missing timer or scope is ignored",
			provider:     awsProvider(),
			hours:        4,
			cmdErrs:      []error{errFake, errFake},
			wantLifetime: 4 * time.Hour,
			wantPut:      []string{"aws-credentials"},
			wantCmd: append(
				stops("aws"),
				"systemd-run --user --collect --unit=xena-grant-clear-aws --on-active=14400s /usr/local/bin/xena grant clear aws",
			),
			want: now.Add(4 * time.Hour),
		},
		{
			name:         "happy path - short-lived credential starts refresh",
			provider:     gcpProvider(),
			hours:        4,
			wantLifetime: 4 * time.Hour,
			wantPut:      []string{"gcp-token"},
			wantCmd: append(
				stops("gcp"),
				"systemd-run --user --collect --unit=xena-grant-clear-gcp --on-active=14400s /usr/local/bin/xena grant clear gcp",
			),
			wantBg: []string{
				"--user",
				"--scope",
				"--collect",
				"--unit=xena-grant-refresh-gcp",
				"--property=RuntimeMaxSec=14460",
				"systemd-cat",
				"-t",
				"xena-grant",
				"/usr/local/bin/xena",
				"grant",
				"refresh",
				"gcp",
				"--until",
				"2026-10-24T16:00:00Z",
			},
			want: now.Add(4 * time.Hour),
		},
		{
			name:      "error - hours above max",
			provider:  awsProvider(),
			hours:     9,
			wantErr:   grant.ErrHoursOutOfRange,
			noSecrets: true,
			noRunner:  true,
		},
		{
			name:      "error - negative hours",
			provider:  awsProvider(),
			hours:     -1,
			wantErr:   grant.ErrHoursOutOfRange,
			noSecrets: true,
			noRunner:  true,
		},
		{
			name: "error - issue fails",
			provider: func() *fakeProvider {
				p := awsProvider()
				p.errs = []error{errFake}
				return p
			}(),
			hours:      4,
			wantCmd:    stops("aws"),
			wantPrefix: "issuing aws grant",
			wantHidden: "made-up-issuing",
			noRunner:   true,
		},
		{
			name:       "error - secrets fail",
			provider:   awsProvider(),
			hours:      4,
			secretsErr: errFake,
			wantPrefix: "reading aws-grant",
			noRunner:   true,
		},
		{
			name:         "error - delivery fails",
			provider:     awsProvider(),
			hours:        4,
			runnerErr:    errFake,
			wantLifetime: 4 * time.Hour,
			wantPut:      []string{"aws-credentials"},
			wantCmd:      stops("aws"),
			wantPrefix:   "delivering aws-credentials",
			wantHidden:   "made-up-credential",
		},
		{
			name:         "error - schedule fails",
			provider:     awsProvider(),
			hours:        4,
			cmdErrs:      []error{nil, nil, errFake},
			wantLifetime: 4 * time.Hour,
			wantPut:      []string{"aws-credentials"},
			wantCmd: append(
				stops("aws"),
				"systemd-run --user --collect --unit=xena-grant-clear-aws --on-active=14400s /usr/local/bin/xena grant clear aws",
			),
			wantPrefix: "scheduling clear",
		},
		{
			name:         "error - refresh start fails",
			provider:     gcpProvider(),
			hours:        4,
			bgErr:        errFake,
			wantLifetime: 4 * time.Hour,
			wantPut:      []string{"gcp-token"},
			wantCmd: append(
				stops("gcp"),
				"systemd-run --user --collect --unit=xena-grant-clear-gcp --on-active=14400s /usr/local/bin/xena grant clear gcp",
			),
			wantPrefix: "starting refresh",
			wantHidden: "made-up-issuing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			g, f := newGranter()
			f.secrets.err = tt.secretsErr
			f.runner.err = tt.runnerErr
			f.cmd.errs = tt.cmdErrs
			f.background.err = tt.bgErr

			// when
			got, err := g.Grant(context.Background(), tt.provider, tt.hours)

			// then
			if tt.noSecrets {
				assert.Empty(t, f.secrets.names)
			}

			if tt.noRunner {
				assert.Empty(t, f.runner.calls)
			}

			if tt.wantErr != nil || tt.wantPrefix != "" {
				require.Error(t, err)

				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}

				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())

				if tt.wantHidden != "" {
					assert.NotContains(t, err.Error(), tt.wantHidden)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
				assert.Equal(t, []string{tt.provider.secret}, f.secrets.names)
			}

			if tt.wantPut != nil {
				require.Len(t, f.runner.calls, 1)
				assert.Equal(t, "secret-put", f.runner.calls[0].verb)
				assert.Equal(t, tt.wantPut, f.runner.calls[0].args)
				assert.Equal(t, "made-up-credential", string(f.runner.calls[0].stdin))
				assert.Equal(t, []time.Duration{tt.wantLifetime}, tt.provider.lifetimes)
			}

			if tt.wantCmd != nil {
				assert.Equal(t, tt.wantCmd, f.cmd.lines())
			}

			if tt.wantBg != nil {
				assert.Equal(t, "made-up-issuing", string(f.background.stdin))
				assert.Equal(t, "systemd-run", f.background.name)
				assert.Equal(t, tt.wantBg, f.background.args)
			}

			if tt.wantBg == nil && tt.bgErr == nil {
				assert.Zero(t, f.background.calls)
			}
		})
	}
}

func TestGranter_Clear(t *testing.T) {
	tests := []struct {
		name       string
		runnerErr  error
		wantPrefix string
	}{
		{name: "happy path - clears"},
		{name: "error - runner fails", runnerErr: errFake, wantPrefix: "clearing aws-credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			g, f := newGranter()
			f.cmd.errs = []error{errFake}
			f.runner.err = tt.runnerErr

			// when
			err := g.Clear(context.Background(), awsProvider())

			// then
			assert.Equal(t, []string{"systemctl --user stop xena-grant-refresh-aws.scope"}, f.cmd.lines())
			require.Len(t, f.runner.calls, 1)
			assert.Equal(t, runCall{verb: "secret-clear", args: []string{"aws-credentials"}}, f.runner.calls[0])

			if tt.wantPrefix != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestGranter_Refresh(t *testing.T) {
	end := now.Add(4 * time.Hour)
	put := runCall{verb: "secret-put", args: []string{"gcp-token"}, stdin: []byte("made-up-credential")}
	clearCall := runCall{verb: "secret-clear", args: []string{"gcp-token"}}

	tests := []struct {
		name          string
		issuing       string
		until         time.Time
		issueErrs     []error
		runnerErrs    []error
		sleepErr      error
		wantSleeps    []time.Duration
		wantLifetimes []time.Duration
		noMint        bool
		wantRuns      []runCall
		wantLog       string
		wantErr       error
		wantPrefix    string
	}{
		{
			name: "happy path - re-mints until the end",
			wantSleeps: []time.Duration{
				50 * time.Minute,
				50 * time.Minute,
				50 * time.Minute,
				50 * time.Minute,
				40 * time.Minute,
			},
			wantLifetimes: []time.Duration{
				3*time.Hour + 10*time.Minute,
				2*time.Hour + 20*time.Minute,
				time.Hour + 30*time.Minute,
				40 * time.Minute,
			},
			wantRuns: []runCall{put, put, put, put, clearCall},
			wantLog:  "refreshed",
		},
		{
			name:       "happy path - failed mint retries after a minute",
			issueErrs:  []error{errFake},
			wantSleeps: []time.Duration{50 * time.Minute, time.Minute, 50 * time.Minute},
			wantLog:    "refreshing grant",
		},
		{
			name:       "happy path - failed delivery retries after a minute",
			runnerErrs: []error{errFake},
			wantSleeps: []time.Duration{50 * time.Minute, time.Minute, 50 * time.Minute},
			wantLog:    "refreshing grant",
		},
		{
			name:       "happy path - end already passed clears without minting",
			until:      now,
			wantSleeps: []time.Duration{0},
			noMint:     true,
			wantRuns:   []runCall{clearCall},
		},
		{
			name:       "error - final clear fails",
			until:      now,
			runnerErrs: []error{errFake},
			wantRuns:   []runCall{clearCall},
			wantPrefix: "clearing gcp-token",
		},
		{
			name:     "error - context cancelled",
			sleepErr: context.Canceled,
			wantRuns: []runCall{},
			wantErr:  context.Canceled,
		},
		{
			name:     "error - empty issuing secret",
			issuing:  " ",
			wantRuns: []runCall{},
			wantErr:  grant.ErrInvalidSecret,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			g, f := newGranter()
			f.clock.err = tt.sleepErr
			f.runner.errs = tt.runnerErrs
			p := gcpProvider()
			p.errs = tt.issueErrs

			issuing := "made-up-issuing"
			if tt.issuing != "" {
				issuing = tt.issuing
			}

			until := end
			if !tt.until.IsZero() {
				until = tt.until
			}

			// when
			err := g.Refresh(context.Background(), p, []byte(issuing), until)

			// then
			assert.NotContains(t, f.log.String(), "made-up-issuing")
			assert.NotContains(t, f.log.String(), "made-up-credential")

			if tt.wantRuns != nil {
				assert.Equal(t, tt.wantRuns, append([]runCall{}, f.runner.calls...))
			}

			if tt.wantErr != nil || tt.wantPrefix != "" {
				require.Error(t, err)

				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}

				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				return
			}

			require.NoError(t, err)
			require.GreaterOrEqual(t, len(f.clock.sleeps), len(tt.wantSleeps))
			assert.Equal(t, tt.wantSleeps, f.clock.sleeps[:len(tt.wantSleeps)])
			assert.Equal(t, clearCall, f.runner.calls[len(f.runner.calls)-1])
			assert.Contains(t, f.log.String(), tt.wantLog)

			if tt.wantLifetimes != nil {
				assert.Equal(t, tt.wantLifetimes, p.lifetimes)
			}

			if tt.noMint {
				assert.Empty(t, p.lifetimes)
			}
		})
	}
}
