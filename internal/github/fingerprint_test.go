package github_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/github"
)

func fixtureKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	data, err := os.ReadFile("testdata/fingerprint.pub.pem")
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	pub, ok := parsed.(*rsa.PublicKey)
	require.True(t, ok)

	return pub
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		key   *rsa.PublicKey
		other *rsa.PublicKey
		want  string
	}{
		{
			name: "happy path - matches openssl",
			key:  fixtureKey(t),
			want: "SHA256:sZx62yDYIdroeHfzC4He5E3O6jIlBypyTS95DH9myqw=",
		},
		{
			name:  "happy path - differs per key",
			key:   &testKey(t).PublicKey,
			other: &testKey(t).PublicKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, err := github.Fingerprint(tt.key)

			// then
			require.NoError(t, err)

			if tt.other == nil {
				assert.Equal(t, tt.want, got)
				return
			}

			other, err := github.Fingerprint(tt.other)
			require.NoError(t, err)
			assert.NotEqual(t, got, other)
		})
	}
}
