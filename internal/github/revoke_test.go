package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/github"
)

func TestRevokeToken(t *testing.T) {
	t.Run("happy path - revokes", func(t *testing.T) {
		// given
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/installation/token", r.URL.Path)
			assert.Equal(t, "Bearer ghs_madeup", r.Header.Get("Authorization"))
			assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
			assert.Equal(t, "2022-11-28", r.Header.Get("X-Github-Api-Version"))

			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)

		// when
		err := github.RevokeToken(context.Background(), srv.URL, "ghs_madeup", srv.Client())

		// then
		require.NoError(t, err)
	})

	t.Run("error - unexpected status", func(t *testing.T) {
		// given
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)

		// when
		err := github.RevokeToken(context.Background(), srv.URL, "ghs_madeup", srv.Client())

		// then
		require.ErrorIs(t, err, github.ErrUnexpectedStatus)
		assert.NotContains(t, err.Error(), "ghs_madeup")
	})
}
