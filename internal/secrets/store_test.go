package secrets_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/secrets"
)

var errReadFailed = errors.New("made-up read failure")

func TestStore_Put(t *testing.T) {
	t.Run("happy path - writes encrypted file", func(t *testing.T) {
		// given
		store := newStore(t)

		// when
		err := store.Put("jira-bot-token", strings.NewReader("made-up-value-1"))

		// then
		require.NoError(t, err)

		path := filepath.Join(store.Dir, "jira-bot-token.age")
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())

		dirInfo, err := os.Stat(store.Dir)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o700), dirInfo.Mode().Perm())

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(data), "age-encryption.org/v1"))
		assert.NotContains(t, string(data), "made-up-value-1")
	})

	t.Run("happy path - overwrite replaces value", func(t *testing.T) {
		// given
		store := newStore(t)
		require.NoError(t, store.Put("a", strings.NewReader("one")))

		// when
		err := store.Put("a", strings.NewReader("two"))

		// then
		require.NoError(t, err)

		got, err := store.Get(context.Background(), "a")
		require.NoError(t, err)
		assert.Equal(t, "two", string(got))
	})

	tests := []struct {
		name    string
		secret  string
		wantErr error
	}{
		{name: "error - name with slash", secret: "../escape", wantErr: secrets.ErrInvalidName},
		{name: "error - upper case name", secret: "Upper", wantErr: secrets.ErrInvalidName},
		{name: "error - empty name", secret: "", wantErr: secrets.ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			store := newStore(t)

			// when
			err := store.Put(tt.secret, strings.NewReader("made-up"))

			// then
			require.ErrorIs(t, err, tt.wantErr)

			entries, err := os.ReadDir(filepath.Dir(store.Dir))
			require.NoError(t, err)
			for _, e := range entries {
				assert.NotEqual(t, "escape.age", e.Name())
			}

			_, err = os.Stat(store.Dir)
			assert.ErrorIs(t, err, fs.ErrNotExist)
		})
	}

	t.Run("error - missing recipients file", func(t *testing.T) {
		// given
		store := newStore(t)
		store.RecipientsFile = filepath.Join(t.TempDir(), "missing.txt")

		// when
		err := store.Put("a", strings.NewReader("made-up"))

		// then
		require.Error(t, err)

		entries, err := os.ReadDir(store.Dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("error - value read fails", func(t *testing.T) {
		// given
		store := newStore(t)

		// when
		err := store.Put("a", iotest.ErrReader(errReadFailed))

		// then
		require.Error(t, err)

		entries, err := os.ReadDir(store.Dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("error - failed overwrite keeps old value", func(t *testing.T) {
		// given
		store := newStore(t)
		require.NoError(t, store.Put("a", strings.NewReader("one")))

		broken := store
		broken.RecipientsFile = filepath.Join(t.TempDir(), "missing.txt")

		// when
		err := broken.Put("a", strings.NewReader("two"))

		// then
		require.Error(t, err)

		got, err := store.Get(context.Background(), "a")
		require.NoError(t, err)
		assert.Equal(t, "one", string(got))
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("happy path - round trip", func(t *testing.T) {
		// given
		store := newStore(t)
		require.NoError(t, store.Put("a", strings.NewReader("made-up-value-2")))

		// when
		got, err := store.Get(context.Background(), "a")

		// then
		require.NoError(t, err)
		assert.Equal(t, []byte("made-up-value-2"), got)
	})

	t.Run("error - missing secret", func(t *testing.T) {
		// given
		store := newStore(t)

		// when
		_, err := store.Get(context.Background(), "a")

		// then
		require.ErrorIs(t, err, secrets.ErrNotFound)
	})

	t.Run("error - invalid name", func(t *testing.T) {
		// given
		store := newStore(t)

		// when
		_, err := store.Get(context.Background(), "../a")

		// then
		require.ErrorIs(t, err, secrets.ErrInvalidName)
	})

	t.Run("error - wrong identity", func(t *testing.T) {
		// given
		store := newStore(t)
		require.NoError(t, store.Put("a", strings.NewReader("made-up-value-3")))

		other := newStore(t)
		other.Dir = store.Dir

		// when
		got, err := other.Get(context.Background(), "a")

		// then
		require.Error(t, err)
		require.NotErrorIs(t, err, secrets.ErrNotFound)
		assert.NotContains(t, err.Error(), "made-up-value-3")
		assert.Nil(t, got)
	})

	t.Run("error - missing identity file", func(t *testing.T) {
		// given
		store := newStore(t)
		require.NoError(t, store.Put("a", strings.NewReader("made-up")))

		store.IdentityFile = filepath.Join(t.TempDir(), "missing.txt")

		// when
		_, err := store.Get(context.Background(), "a")

		// then
		require.Error(t, err)
		require.NotErrorIs(t, err, secrets.ErrNotFound)
	})
}

func TestStore_List(t *testing.T) {
	t.Run("happy path - missing dir", func(t *testing.T) {
		// given
		store := newStore(t)

		// when
		got, err := store.List()

		// then
		require.NoError(t, err)
		assert.Equal(t, []string{}, got)
	})

	t.Run("happy path - sorted names", func(t *testing.T) {
		// given
		store := newStore(t)
		require.NoError(t, store.Put("b", strings.NewReader("made-up")))
		require.NoError(t, store.Put("a", strings.NewReader("made-up")))
		require.NoError(t, os.WriteFile(filepath.Join(store.Dir, "notes.txt"), nil, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(store.Dir, ".c.age.tmp-123"), nil, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(store.Dir, ".d.age"), nil, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(store.Dir, "Upper.age"), nil, 0o600))

		// when
		got, err := store.List()

		// then
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, got)
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("happy path - removes file", func(t *testing.T) {
		// given
		store := newStore(t)
		require.NoError(t, store.Put("a", strings.NewReader("made-up")))

		// when
		err := store.Delete("a")

		// then
		require.NoError(t, err)

		_, err = store.Get(context.Background(), "a")
		require.ErrorIs(t, err, secrets.ErrNotFound)
	})

	tests := []struct {
		name    string
		secret  string
		wantErr error
	}{
		{name: "error - missing secret", secret: "a", wantErr: secrets.ErrNotFound},
		{name: "error - invalid name", secret: "../a", wantErr: secrets.ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			store := newStore(t)

			// when
			err := store.Delete(tt.secret)

			// then
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestNewDefaultStore(t *testing.T) {
	t.Run("happy path - builds from paths", func(t *testing.T) {
		// given
		secretsDir := t.TempDir()
		configDir := t.TempDir()
		t.Setenv("XENA_SECRETS_DIR", secretsDir)
		t.Setenv("XENA_CONFIG_DIR", configDir)

		age, err := exec.LookPath("age")
		require.NoError(t, err)

		// when
		got, err := secrets.NewDefaultStore()

		// then
		require.NoError(t, err)
		assert.Equal(t, secrets.Store{
			Dir:            secretsDir,
			RecipientsFile: filepath.Join(configDir, "age-recipients.txt"),
			IdentityFile:   filepath.Join(configDir, "age-identities.txt"),
			Age:            age,
		}, got)
	})

	t.Run("error - age missing", func(t *testing.T) {
		// given
		t.Setenv("PATH", t.TempDir())

		// when
		_, err := secrets.NewDefaultStore()

		// then
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "finding age"))
	})
}

func newStore(t *testing.T) secrets.Store {
	t.Helper()

	dir := t.TempDir()
	identity := filepath.Join(dir, "identity.txt")
	recipients := filepath.Join(dir, "recipients.txt")

	require.NoError(t, exec.CommandContext(t.Context(), "age-keygen", "-o", identity).Run())

	out, err := exec.CommandContext(t.Context(), "age-keygen", "-y", identity).Output()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(recipients, out, 0o600))

	return secrets.Store{
		Dir:            filepath.Join(dir, "secrets"),
		RecipientsFile: recipients,
		IdentityFile:   identity,
		Age:            "age",
	}
}
