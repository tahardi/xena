package inventory_test

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

const oneEntry = `version: 1
# keep me
entries:
  - name: a
    service: aws
    stored: secrets:a
    rotated: 2026-01-01
    rotate: rotate a
`

type fakeStore struct {
	getErr  error
	putErr  error
	gets    []string
	putName string
	putVal  string
}

func (f *fakeStore) Get(_ context.Context, name string) ([]byte, error) {
	f.gets = append(f.gets, name)

	if f.getErr != nil {
		return nil, f.getErr
	}

	return []byte("old-value"), nil
}

func (f *fakeStore) Put(name string, value io.Reader) error {
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}

	f.putName = name
	f.putVal = string(data)

	return f.putErr
}

type fakeRotator struct {
	createErr  error
	revokeErrs []error
	checkErr   error
	rejected   []bool
	createdOld string
	revoked    []string
	revokes    int
	checks     int
}

func (f *fakeRotator) Create(_ context.Context, old []byte) ([]byte, error) {
	f.createdOld = string(old)

	if f.createErr != nil {
		return nil, f.createErr
	}

	return []byte("new-value"), nil
}

func (f *fakeRotator) Revoke(_ context.Context, old, current []byte) error {
	f.revoked = []string{string(old), string(current)}
	f.revokes++

	if len(f.revokeErrs) == 0 {
		return nil
	}

	return f.revokeErrs[min(f.revokes, len(f.revokeErrs))-1]
}

func (f *fakeRotator) Rejected(context.Context, []byte) (bool, error) {
	i := min(f.checks, len(f.rejected)-1)
	f.checks++

	return f.rejected[i], f.checkErr
}

func TestRotation_Run(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		token      string
		store      *fakeStore
		rotator    *fakeRotator
		wantErr    error
		wantPrefix string
		wantText   string
		sleepErr   error
		check      func(t *testing.T, s *fakeStore, r *fakeRotator, sleeps int)
	}{
		{
			name:    "happy path - rotates",
			token:   "a",
			store:   &fakeStore{},
			rotator: &fakeRotator{rejected: []bool{false, true}},
			check: func(t *testing.T, s *fakeStore, r *fakeRotator, sleeps int) {
				t.Helper()
				assert.Equal(t, "old-value", r.createdOld)
				assert.Equal(t, "a", s.putName)
				assert.Equal(t, "new-value", s.putVal)
				assert.Equal(t, []string{"old-value", "new-value"}, r.revoked)
				assert.Equal(t, 2, r.checks)
				assert.Equal(t, 1, sleeps)
			},
		},
		{
			name:    "happy path - rejected at first check",
			token:   "a",
			store:   &fakeStore{},
			rotator: &fakeRotator{rejected: []bool{true}},
			check: func(t *testing.T, _ *fakeStore, r *fakeRotator, sleeps int) {
				t.Helper()
				assert.Equal(t, 1, r.checks)
				assert.Equal(t, 0, sleeps)
			},
		},
		{
			name:       "error - get fails",
			token:      "a",
			store:      &fakeStore{getErr: errFake},
			rotator:    &fakeRotator{rejected: []bool{true}},
			wantErr:    errFake,
			wantPrefix: "reading old a",
			check: func(t *testing.T, _ *fakeStore, r *fakeRotator, _ int) {
				t.Helper()
				assert.Empty(t, r.createdOld)
			},
		},
		{
			name:    "happy path - revoke retried until the new key works",
			token:   "a",
			store:   &fakeStore{},
			rotator: &fakeRotator{revokeErrs: []error{errFake, nil}, rejected: []bool{true}},
			check: func(t *testing.T, _ *fakeStore, r *fakeRotator, sleeps int) {
				t.Helper()
				assert.Equal(t, 2, r.revokes)
				assert.Equal(t, 1, r.checks)
				assert.Equal(t, 1, sleeps)
			},
		},
		{
			name:       "error - revoke fails",
			token:      "a",
			store:      &fakeStore{},
			rotator:    &fakeRotator{revokeErrs: []error{errFake}, rejected: []bool{true}},
			wantErr:    errFake,
			wantPrefix: "revoking old a",
			wantText:   "new value is stored",
			check: func(t *testing.T, s *fakeStore, r *fakeRotator, sleeps int) {
				t.Helper()
				assert.Equal(t, "new-value", s.putVal)
				assert.Equal(t, 3, r.revokes)
				assert.Equal(t, 2, sleeps)
				assert.Equal(t, 0, r.checks)
			},
		},
		{
			name:       "error - canceled while waiting",
			token:      "a",
			store:      &fakeStore{},
			rotator:    &fakeRotator{rejected: []bool{false}},
			sleepErr:   context.Canceled,
			wantErr:    context.Canceled,
			wantPrefix: "verifying old a",
			wantText:   "new value is stored",
			check: func(t *testing.T, _ *fakeStore, r *fakeRotator, sleeps int) {
				t.Helper()
				assert.Equal(t, 1, r.checks)
				assert.Equal(t, 1, sleeps)
			},
		},
		{
			name:       "error - check fails",
			token:      "a",
			store:      &fakeStore{},
			rotator:    &fakeRotator{checkErr: errFake, rejected: []bool{false}},
			wantErr:    errFake,
			wantPrefix: "verifying old a",
			check: func(t *testing.T, _ *fakeStore, r *fakeRotator, _ int) {
				t.Helper()
				assert.Equal(t, 1, r.checks)
			},
		},
		{
			name:    "error - not listed",
			token:   "zzz",
			store:   &fakeStore{},
			rotator: &fakeRotator{rejected: []bool{true}},
			wantErr: inventory.ErrNotListed,
			check: func(t *testing.T, s *fakeStore, _ *fakeRotator, _ int) {
				t.Helper()
				assert.Empty(t, s.gets)
			},
		},
		{
			name:       "error - create fails",
			token:      "a",
			store:      &fakeStore{},
			rotator:    &fakeRotator{createErr: errFake, rejected: []bool{true}},
			wantErr:    errFake,
			wantPrefix: "creating new a",
			check: func(t *testing.T, s *fakeStore, r *fakeRotator, _ int) {
				t.Helper()
				assert.Empty(t, s.putName)
				assert.Nil(t, r.revoked)
			},
		},
		{
			name:       "error - put fails",
			token:      "a",
			store:      &fakeStore{putErr: errFake},
			rotator:    &fakeRotator{rejected: []bool{true}},
			wantErr:    errFake,
			wantPrefix: "storing new a",
			check: func(t *testing.T, _ *fakeStore, r *fakeRotator, _ int) {
				t.Helper()
				assert.Nil(t, r.revoked)
			},
		},
		{
			name:     "error - old still valid",
			token:    "a",
			store:    &fakeStore{},
			rotator:  &fakeRotator{rejected: []bool{false}},
			wantErr:  inventory.ErrOldStillValid,
			wantText: "new value is stored",
			check: func(t *testing.T, _ *fakeStore, r *fakeRotator, sleeps int) {
				t.Helper()
				assert.Equal(t, 3, r.checks)
				assert.Equal(t, 2, sleeps)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := writeInventory(t, oneEntry)
			var sleeps []time.Duration
			rotation := inventory.Rotation{
				Store:     tt.store,
				Inventory: path,
				Now:       func() time.Time { return now },
				Sleep: func(_ context.Context, d time.Duration) error {
					sleeps = append(sleeps, d)
					return tt.sleepErr
				},
				Attempts: 3,
				Wait:     time.Second,
			}

			// when
			err := rotation.Run(context.Background(), tt.token, tt.rotator)

			// then
			tt.check(t, tt.store, tt.rotator, len(sleeps))
			for _, d := range sleeps {
				assert.Equal(t, time.Second, d)
			}

			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				assert.Contains(t, err.Error(), tt.wantText)
				assert.Equal(t, oneEntry, string(data))
				return
			}
			require.NoError(t, err)
			assert.Contains(t, string(data), "# keep me")
			inv, err := inventory.Load(path)
			require.NoError(t, err)
			a, err := inv.Find("a")
			require.NoError(t, err)
			assert.Equal(t, "2026-10-24", a.Rotated.Format(time.DateOnly))
		})
	}
}

type fakeCall struct {
	env  []string
	name string
	args []string
}

type fakeResult struct {
	out []byte
	err error
}

type fakeCommand struct {
	results map[string]fakeResult
	hook    func(c fakeCall)
	calls   []fakeCall
}

func (f *fakeCommand) Output(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
	c := fakeCall{env: env, name: name, args: args}
	f.calls = append(f.calls, c)

	if f.hook != nil {
		f.hook(c)
	}

	r := f.results[strings.Join(args[:min(2, len(args))], " ")]

	return r.out, r.err
}

func TestSleep(t *testing.T) {
	tests := []struct {
		name     string
		canceled bool
		wait     time.Duration
		wantErr  error
	}{
		{name: "happy path - waits", wait: time.Millisecond},
		{name: "error - canceled", canceled: true, wait: time.Hour, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			ctx, cancel := context.WithCancel(context.Background())
			if tt.canceled {
				cancel()
			}
			defer cancel()

			// when
			err := inventory.Sleep(ctx, tt.wait)

			// then
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
