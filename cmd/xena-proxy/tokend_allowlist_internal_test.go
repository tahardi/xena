package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/allowlist"
)

func TestTokendAllowlist(t *testing.T) {
	// given
	path := "../../config/tokend-allowlist.yaml"

	// when
	list, err := allowlist.Load(path)

	// then
	require.NoError(t, err)
	require.Equal(t, []allowlist.Rule{{Host: "api.github.com", Ports: []int{443}}}, list.Hosts)
}
