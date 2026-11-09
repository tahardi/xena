package proxy_test

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/proxy"
)

func TestListenSocket(t *testing.T) {
	t.Run("happy path - mode 0660", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")

		// when
		ln, err := proxy.ListenSocket(t.Context(), path, "")

		// then
		require.NoError(t, err)
		defer ln.Close()

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o660)|os.ModeSocket, info.Mode())
	})

	t.Run("happy path - removes stale socket", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")
		require.NoError(t, os.WriteFile(path, []byte("stale"), 0o600))

		// when
		ln, err := proxy.ListenSocket(t.Context(), path, "")

		// then
		require.NoError(t, err)
		require.NoError(t, ln.Close())
	})

	t.Run("happy path - sets group", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")
		group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
		require.NoError(t, err)

		// when
		ln, err := proxy.ListenSocket(t.Context(), path, group.Name)

		// then
		require.NoError(t, err)
		defer ln.Close()

		info, err := os.Stat(path)
		require.NoError(t, err)

		stat, ok := info.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		require.Equal(t, group.Gid, strconv.FormatUint(uint64(stat.Gid), 10))
	})

	t.Run("error - missing directory", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "missing", "p.sock")

		// when
		_, err := proxy.ListenSocket(t.Context(), path, "")

		// then
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "listening on socket "), err.Error())
	})

	t.Run("error - unknown group", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")

		// when
		_, err := proxy.ListenSocket(t.Context(), path, "xena-no-such-group")

		// then
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "listening on socket "), err.Error())
		require.NoFileExists(t, path)
	})

	t.Run("error - path cannot be removed", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "p.sock")
		require.NoError(t, os.MkdirAll(filepath.Join(path, "child"), 0o700))

		// when
		_, err := proxy.ListenSocket(t.Context(), path, "")

		// then
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "listening on socket "), err.Error())
	})
}
