package github_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/github"
)

type jwtClaims struct {
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return key
}

func verifyJWT(t *testing.T, key *rsa.PrivateKey, jwt string) (string, jwtClaims) {
	t.Helper()

	parts := strings.Split(jwt, ".")
	require.Len(t, parts, 3)

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig))

	var claims jwtClaims
	require.NoError(t, json.Unmarshal(rawClaims, &claims))

	return string(header), claims
}

func newApp(t *testing.T, key *rsa.PrivateKey, handler http.HandlerFunc) github.App {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return github.App{
		ID:             12345,
		InstallationID: 67890,
		Key:            key,
		API:            srv.URL,
		HTTP:           srv.Client(),
	}
}

func requireBearerJWT(t *testing.T, key *rsa.PrivateKey, auth string) {
	t.Helper()

	jwt, ok := strings.CutPrefix(auth, "Bearer ")
	require.True(t, ok)
	verifyJWT(t, key, jwt)
}

func TestApp_JWT(t *testing.T) {
	t.Run("happy path - claims and signature", func(t *testing.T) {
		// given
		key := testKey(t)
		app := github.App{ID: 12345, Key: key}
		now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

		// when
		jwt, err := app.JWT(now)

		// then
		require.NoError(t, err)

		header, claims := verifyJWT(t, key, jwt)
		assert.JSONEq(t, `{"alg":"RS256","typ":"JWT"}`, header)
		assert.Equal(t, now.Add(-60*time.Second).Unix(), claims.IssuedAt)
		assert.Equal(t, now.Add(9*time.Minute).Unix(), claims.ExpiresAt)
		assert.Equal(t, "12345", claims.Issuer)
	})

	t.Run("error - nil key", func(t *testing.T) {
		// given
		app := github.App{ID: 12345}

		// when
		_, err := app.JWT(time.Now())

		// then
		require.ErrorIs(t, err, github.ErrInvalidKey)
	})
}

func TestApp_InstallationToken(t *testing.T) {
	t.Run("happy path - returns token", func(t *testing.T) {
		// given
		key := testKey(t)
		var auth string
		app := newApp(t, key, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/app/installations/67890/access_tokens", r.URL.Path)
			assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
			assert.Equal(t, "2022-11-28", r.Header.Get("X-Github-Api-Version"))
			auth = r.Header.Get("Authorization")

			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"ghs_madeup","expires_at":"2026-10-24T13:00:00Z"}`))
		})

		// when
		tok, err := app.InstallationToken(context.Background())

		// then
		require.NoError(t, err)
		requireBearerJWT(t, key, auth)
		assert.Equal(t, "ghs_madeup", tok.Value)
		assert.True(t, tok.ExpiresAt.Equal(time.Date(2026, 10, 24, 13, 0, 0, 0, time.UTC)))
	})

	t.Run("error - unexpected status", func(t *testing.T) {
		// given
		app := newApp(t, testKey(t), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("made-up-body"))
		})

		// when
		_, err := app.InstallationToken(context.Background())

		// then
		require.ErrorIs(t, err, github.ErrUnexpectedStatus)
		assert.Contains(t, err.Error(), "401")
		assert.NotContains(t, err.Error(), "made-up-body")
	})

	t.Run("error - empty token", func(t *testing.T) {
		// given
		app := newApp(t, testKey(t), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"","expires_at":"2026-10-24T13:00:00Z"}`))
		})

		// when
		_, err := app.InstallationToken(context.Background())

		// then
		require.ErrorIs(t, err, github.ErrInvalidToken)
	})

	t.Run("error - missing expiry", func(t *testing.T) {
		// given
		app := newApp(t, testKey(t), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"ghs_madeup"}`))
		})

		// when
		_, err := app.InstallationToken(context.Background())

		// then
		require.ErrorIs(t, err, github.ErrInvalidToken)
		assert.NotContains(t, err.Error(), "ghs_madeup")
	})

	t.Run("error - server unreachable", func(t *testing.T) {
		// given
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		app := github.App{ID: 12345, InstallationID: 67890, Key: testKey(t), API: srv.URL, HTTP: srv.Client()}

		// when
		_, err := app.InstallationToken(context.Background())

		// then
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "requesting installation token"), err.Error())
	})

	t.Run("error - nil key sends nothing", func(t *testing.T) {
		// given
		called := false
		app := newApp(t, nil, func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusCreated)
		})

		// when
		_, err := app.InstallationToken(context.Background())

		// then
		require.ErrorIs(t, err, github.ErrInvalidKey)
		assert.False(t, called)
	})

	t.Run("error - bad json", func(t *testing.T) {
		// given
		app := newApp(t, testKey(t), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{"))
		})

		// when
		_, err := app.InstallationToken(context.Background())

		// then
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "decoding installation token"))
	})
}

func TestApp_Suspend(t *testing.T) {
	t.Run("happy path - suspends", func(t *testing.T) {
		// given
		key := testKey(t)
		var auth string
		app := newApp(t, key, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "/app/installations/67890/suspended", r.URL.Path)
			auth = r.Header.Get("Authorization")

			w.WriteHeader(http.StatusNoContent)
		})

		// when
		err := app.Suspend(context.Background())

		// then
		require.NoError(t, err)
		requireBearerJWT(t, key, auth)
	})

	t.Run("error - unexpected status", func(t *testing.T) {
		// given
		app := newApp(t, testKey(t), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		// when
		err := app.Suspend(context.Background())

		// then
		require.ErrorIs(t, err, github.ErrUnexpectedStatus)
	})
}

func TestParseKey(t *testing.T) {
	key := testKey(t)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	tests := []struct {
		name    string
		data    []byte
		want    *rsa.PrivateKey
		wantErr error
	}{
		{
			name: "happy path - pkcs1 pem",
			data: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
			want: key,
		},
		{
			name: "happy path - pkcs8 pem",
			data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
			want: key,
		},
		{
			name:    "error - not pem",
			data:    []byte("made-up"),
			wantErr: github.ErrInvalidKey,
		},
		{
			name:    "error - garbage in pem block",
			data:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("made-up")}),
			wantErr: github.ErrInvalidKey,
		},
		{
			name:    "error - ec key in pkcs8",
			data:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8}),
			wantErr: github.ErrInvalidKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, err := github.ParseKey(tt.data)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.True(t, tt.want.Equal(got))
		})
	}
}
