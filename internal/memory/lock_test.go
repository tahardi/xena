package memory_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/memory"
)

func TestLock(t *testing.T) {
	t.Run("happy path - second lock waits for unlock", func(t *testing.T) {
		// given
		dir := t.TempDir()
		unlock, err := memory.Lock(context.Background(), dir)
		require.NoError(t, err)

		acquired := make(chan func())
		go func() {
			second, err := memory.Lock(context.Background(), dir)
			if err != nil {
				close(acquired)
				return
			}

			acquired <- second
		}()

		// when
		select {
		case <-acquired:
			t.Fatal("second lock acquired while the first was held")
		case <-time.After(100 * time.Millisecond):
		}

		unlock()

		// then
		select {
		case second, ok := <-acquired:
			require.True(t, ok)
			second()
		case <-time.After(5 * time.Second):
			t.Fatal("second lock never acquired")
		}

		require.FileExists(t, filepath.Join(dir, ".lock"))
	})

	t.Run("error - lock dir cannot be created", func(t *testing.T) {
		// given
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))

		// when
		unlock, err := memory.Lock(context.Background(), filepath.Join(file, "memory"))

		// then
		require.Error(t, err)
		require.Nil(t, unlock)
		require.True(t, strings.HasPrefix(err.Error(), "locking memory dir"), err.Error())
	})

	t.Run("error - context ends while another holds the lock", func(t *testing.T) {
		// given
		dir := t.TempDir()
		unlock, err := memory.Lock(context.Background(), dir)
		require.NoError(t, err)
		defer unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		// when
		second, err := memory.Lock(ctx, dir)

		// then
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Nil(t, second)
		require.True(t, strings.HasPrefix(err.Error(), "locking memory dir"), err.Error())
	})
}
