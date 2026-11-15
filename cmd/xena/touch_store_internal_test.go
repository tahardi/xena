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

var errNoDisplay = errors.New("no display")

type fakeDiskStore struct {
	gets []string
	puts map[string]string
}

func (s *fakeDiskStore) Get(_ context.Context, name string) ([]byte, error) {
	s.gets = append(s.gets, name)
	return []byte("value"), nil
}

func (s *fakeDiskStore) Put(name string, value io.Reader) error {
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
	}{
		{name: "happy path - prompts then reads"},
		{name: "happy path - notification fails still reads", showErr: errNoDisplay},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			inner := &fakeDiskStore{}
			shower := &fakeShower{err: tt.showErr}
			var out bytes.Buffer
			store := newTouchStore(inner, shower, &out, slog.New(slog.DiscardHandler))

			// when
			got, err := store.Get(context.Background(), "vm-disk-key")

			// then
			require.NoError(t, err)
			require.Equal(t, "value", string(got))
			require.Equal(t, []string{"vm-disk-key"}, inner.gets)
			require.Equal(t, []string{"Touch your YubiKey: to unlock the VM disk"}, shower.shown)
			require.Equal(t, []bool{true}, shower.critical)
			require.Equal(t, "touch your YubiKey to unlock the VM disk\n", out.String())
		})
	}
}

func TestTouchStore_Put(t *testing.T) {
	// given
	inner := &fakeDiskStore{}
	shower := &fakeShower{}
	var out bytes.Buffer
	store := newTouchStore(inner, shower, &out, slog.New(slog.DiscardHandler))

	// when
	err := store.Put("vm-disk-key", strings.NewReader("value"))

	// then
	require.NoError(t, err)
	require.Equal(t, map[string]string{"vm-disk-key": "value"}, inner.puts)
	require.Empty(t, shower.shown)
	require.Empty(t, out.String())
}
