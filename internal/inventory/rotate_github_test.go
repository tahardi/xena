package inventory_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/github"
	"github.com/tahardi/xena/internal/inventory"
)

type githubRequest struct {
	method string
	path   string
	auth   string
}

type githubServer struct {
	srv          *httptest.Server
	newKey       *rsa.PrivateKey
	appStatus    int
	revokeStatus int
	mu           sync.Mutex
	requests     []githubRequest
}

func newGitHubServer(t *testing.T, newKey *rsa.PrivateKey, appStatus int) *githubServer {
	t.Helper()

	g := &githubServer{newKey: newKey, appStatus: appStatus, revokeStatus: http.StatusNoContent}
	g.srv = httptest.NewServer(http.HandlerFunc(g.handle))
	t.Cleanup(g.srv.Close)

	return g
}

func (g *githubServer) handle(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	g.mu.Lock()
	g.requests = append(g.requests, githubRequest{method: r.Method, path: r.URL.Path, auth: auth})
	g.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/app/installations/67890/access_tokens":
		if !signedBy(&g.newKey.PublicKey, auth) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_madeup","expires_at":"2026-11-07T13:00:00Z"}`))
	case r.Method == http.MethodDelete && r.URL.Path == "/installation/token" && auth == "Bearer ghs_madeup":
		w.WriteHeader(g.revokeStatus)
	case r.Method == http.MethodGet && r.URL.Path == "/app":
		w.WriteHeader(g.appStatus)
	default:
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func signedBy(pub *rsa.PublicKey, auth string) bool {
	jwt, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		return false
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return key
}

func keyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func githubAppKey(
	t *testing.T,
	srv *githubServer,
	cmd *fakeCommand,
	in string,
	out *bytes.Buffer,
) inventory.GitHubAppKey {
	t.Helper()

	return inventory.GitHubAppKey{
		File:           filepath.Join(t.TempDir(), "new.pem"),
		AppID:          12345,
		InstallationID: 67890,
		API:            srv.srv.URL,
		HTTP:           srv.srv.Client(),
		Cmd:            cmd,
		In:             bufio.NewReader(strings.NewReader(in)),
		Out:            out,
	}
}

func TestGitHubAppKey_Create(t *testing.T) {
	oldKey := rsaKey(t)
	newKey := rsaKey(t)
	otherKey := rsaKey(t)

	tests := []struct {
		name         string
		file         []byte
		old          []byte
		noFile       bool
		revokeStatus int
		wantErr      error
		wantPrefix   string
		wantNoCall   bool
	}{
		{name: "happy path - checks new key and returns it", file: keyPEM(newKey)},
		{name: "error - same key", file: keyPEM(oldKey), wantErr: inventory.ErrSameKey, wantNoCall: true},
		{
			name:       "error - missing file",
			noFile:     true,
			wantErr:    fs.ErrNotExist,
			wantPrefix: "reading new github app key",
			wantNoCall: true,
		},
		{name: "error - not a key", file: []byte("not a pem"), wantErr: github.ErrInvalidKey, wantNoCall: true},
		{
			name:       "error - new key rejected",
			file:       keyPEM(otherKey),
			wantErr:    github.ErrUnexpectedStatus,
			wantPrefix: "checking new github app key",
		},
		{
			name:       "error - stored key invalid",
			file:       keyPEM(newKey),
			old:        []byte("not a pem"),
			wantErr:    github.ErrInvalidKey,
			wantPrefix: "parsing old github app key",
			wantNoCall: true,
		},
		{
			name:         "error - check token revoke fails",
			file:         keyPEM(newKey),
			revokeStatus: http.StatusInternalServerError,
			wantErr:      github.ErrUnexpectedStatus,
			wantPrefix:   "revoking check token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := newGitHubServer(t, newKey, http.StatusOK)
			if tt.revokeStatus != 0 {
				srv.revokeStatus = tt.revokeStatus
			}
			var out bytes.Buffer
			key := githubAppKey(t, srv, &fakeCommand{}, "", &out)
			if !tt.noFile {
				require.NoError(t, os.WriteFile(key.File, tt.file, 0o600))
			}
			old := keyPEM(oldKey)
			if tt.old != nil {
				old = tt.old
			}

			// when
			got, err := key.Create(context.Background(), old)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				assert.NotContains(t, err.Error(), "PRIVATE KEY")
				assert.NotContains(t, out.String(), "PRIVATE KEY")
				assert.NotContains(t, err.Error(), "ghs_madeup")
				assert.NotContains(t, out.String(), "ghs_madeup")
				if tt.wantNoCall {
					assert.Empty(t, srv.requests)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.file, got)
			require.Len(t, srv.requests, 2)
			assert.Equal(t, http.MethodPost, srv.requests[0].method)
			assert.True(t, signedBy(&newKey.PublicKey, srv.requests[0].auth))
			assert.Equal(t, http.MethodDelete, srv.requests[1].method)
			assert.Equal(t, "Bearer ghs_madeup", srv.requests[1].auth)
			assert.NotContains(t, out.String(), "ghs_madeup")
		})
	}
}

func TestGitHubAppKey_Revoke(t *testing.T) {
	oldKey := rsaKey(t)
	newKey := rsaKey(t)

	fp, err := github.Fingerprint(&oldKey.PublicKey)
	require.NoError(t, err)

	tests := []struct {
		name       string
		in         string
		old        []byte
		result     fakeResult
		wantCalls  int
		wantErr    error
		wantPrefix string
	}{
		{name: "happy path - restarts tokend and waits for delete", in: "\n", wantCalls: 1},
		{
			name:       "error - restart fails",
			in:         "\n",
			result:     fakeResult{err: errFake},
			wantCalls:  1,
			wantErr:    errFake,
			wantPrefix: "restarting xena-tokend",
		},
		{name: "error - no input", in: "", wantCalls: 1, wantPrefix: "waiting for old github app key delete"},
		{
			name:       "error - stored key invalid",
			in:         "\n",
			old:        []byte("not a pem"),
			wantErr:    github.ErrInvalidKey,
			wantPrefix: "parsing old github app key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := newGitHubServer(t, newKey, http.StatusOK)
			cmd := &fakeCommand{results: map[string]fakeResult{"--user try-restart": tt.result}}
			var out bytes.Buffer
			key := githubAppKey(t, srv, cmd, tt.in, &out)
			old := keyPEM(oldKey)
			if tt.old != nil {
				old = tt.old
			}

			// when
			err := key.Revoke(context.Background(), old, keyPEM(newKey))

			// then
			require.Len(t, cmd.calls, tt.wantCalls)
			for _, c := range cmd.calls {
				assert.Equal(t, "systemctl", c.name)
				assert.Equal(t, []string{"--user", "try-restart", "xena-tokend.service"}, c.args)
			}
			assert.NotContains(t, out.String(), "PRIVATE KEY")
			assert.Empty(t, srv.requests)

			if tt.wantPrefix != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
					assert.NotContains(t, out.String(), "Delete")
				}
				return
			}

			require.NoError(t, err)
			assert.Contains(t, out.String(), fp)
			assert.Contains(t, out.String(), "https://github.com/settings/apps")
		})
	}
}

func TestGitHubAppKey_Rejected(t *testing.T) {
	oldKey := rsaKey(t)
	newKey := rsaKey(t)

	tests := []struct {
		name       string
		status     int
		old        []byte
		want       bool
		wantErr    error
		wantPrefix string
	}{
		{name: "happy path - old key rejected", status: http.StatusUnauthorized, want: true},
		{name: "happy path - old key still accepted", status: http.StatusOK, want: false},
		{name: "error - unexpected status", status: http.StatusInternalServerError, wantErr: github.ErrUnexpectedStatus},
		{
			name:       "error - stored key invalid",
			status:     http.StatusUnauthorized,
			old:        []byte("not a pem"),
			wantErr:    github.ErrInvalidKey,
			wantPrefix: "parsing old github app key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := newGitHubServer(t, newKey, tt.status)
			var out bytes.Buffer
			key := githubAppKey(t, srv, &fakeCommand{}, "", &out)
			old := keyPEM(oldKey)
			if tt.old != nil {
				old = tt.old
			}

			// when
			got, err := key.Rejected(context.Background(), old)

			// then
			if tt.old != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				assert.Empty(t, srv.requests)
				return
			}

			require.NotEmpty(t, srv.requests)
			for _, r := range srv.requests {
				assert.Equal(t, http.MethodGet, r.method)
				assert.Equal(t, "/app", r.path)
				assert.True(t, signedBy(&oldKey.PublicKey, r.auth))
			}

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
