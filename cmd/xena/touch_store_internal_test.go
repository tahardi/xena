package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	errNoDisplay = errors.New("no display")
	errStore     = errors.New("store failed")
)

type fakeDiskStore struct {
	out        *bytes.Buffer
	shower     *fakeShower
	err        error
	gets       []string
	outAtGet   string
	shownAtGet int
	puts       map[string]string
}

func (s *fakeDiskStore) Get(_ context.Context, name string) ([]byte, error) {
	s.gets = append(s.gets, name)
	s.outAtGet = s.out.String()
	s.shownAtGet = len(s.shower.shown)

	if s.err != nil {
		return nil, s.err
	}

	return []byte("value"), nil
}

func (s *fakeDiskStore) Put(name string, value io.Reader) error {
	if s.err != nil {
		return s.err
	}

	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}

	s.puts = map[string]string{name: string(data)}
	return nil
}

type fakeShower struct {
	shown    []string
	critical []bool
	err      error
}

func (s *fakeShower) Show(_ context.Context, title, body string, critical bool) error {
	s.shown = append(s.shown, title+": "+body)
	s.critical = append(s.critical, critical)
	return s.err
}

func TestTouchStore_Get(t *testing.T) {
	tests := []struct {
		name    string
		showErr error
		getErr  error
		want    string
	}{
		{name: "happy path - prompts then reads", want: "value"},
		{name: "happy path - notification fails still reads", showErr: errNoDisplay, want: "value"},
		{name: "error - read fails", getErr: errStore},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var out bytes.Buffer
			shower := &fakeShower{err: tt.showErr}
			inner := &fakeDiskStore{out: &out, shower: shower, err: tt.getErr}
			store := newTouchStore(inner, shower, "unlock the VM disk", &out, slog.New(slog.DiscardHandler))

			// when
			got, err := store.Get(context.Background(), "vm-disk-key")

			// then
			require.ErrorIs(t, err, tt.getErr)
			require.Equal(t, tt.want, string(got))
			require.Equal(t, []string{"vm-disk-key"}, inner.gets)
			require.Equal(t, "touch your YubiKey to unlock the VM disk\n", inner.outAtGet)
			require.Equal(t, 1, inner.shownAtGet)
			require.Equal(t, []string{"Touch your YubiKey: to unlock the VM disk"}, shower.shown)
			require.Equal(t, []bool{true}, shower.critical)
		})
	}
}

func TestTouchStore_Put(t *testing.T) {
	tests := []struct {
		name     string
		putErr   error
		wantPuts map[string]string
	}{
		{name: "happy path - saves without prompt", wantPuts: map[string]string{"vm-disk-key": "value"}},
		{name: "error - save fails", putErr: errStore},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var out bytes.Buffer
			shower := &fakeShower{}
			inner := &fakeDiskStore{out: &out, shower: shower, err: tt.putErr}
			store := newTouchStore(inner, shower, "unlock the VM disk", &out, slog.New(slog.DiscardHandler))

			// when
			err := store.Put("vm-disk-key", strings.NewReader("value"))

			// then
			require.ErrorIs(t, err, tt.putErr)
			require.Equal(t, tt.wantPuts, inner.puts)
			require.Empty(t, shower.shown)
			require.Empty(t, out.String())
		})
	}
}
