package proxy_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/proxy"
)

func TestDenyPrompter_Ask(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
	}{
		{name: "happy path - unlisted host", host: "example.com", port: 443},
		{name: "happy path - any port", host: "api.github.com", port: 22},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			prompter := proxy.DenyPrompter{}

			// when
			answer, err := prompter.Ask(t.Context(), tt.host, tt.port)

			// then
			require.NoError(t, err)
			require.Equal(t, proxy.AnswerDeny, answer)
		})
	}
}
