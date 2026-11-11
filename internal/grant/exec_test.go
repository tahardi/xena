package grant_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/grant"
)

func TestExec_Start(t *testing.T) {
	tests := []struct {
		name       string
		bin        string
		wantPrefix string
	}{
		{name: "happy path - child reads all of stdin", bin: "sh"},
		{name: "error - missing binary", bin: "xena-no-such-binary", wantPrefix: "starting xena-no-such-binary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			out := filepath.Join(t.TempDir(), "out")

			// when
			err := grant.Exec{}.Start(
				context.Background(),
				[]byte("made-up-issuing"),
				tt.bin,
				"-c",
				`cat > "$1.tmp" && mv "$1.tmp" "$1"`,
				"sh",
				out,
			)

			// then
			if tt.wantPrefix != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				return
			}

			require.NoError(t, err)
			require.Eventually(t, func() bool {
				data, readErr := os.ReadFile(out)
				return readErr == nil && string(data) == "made-up-issuing"
			}, 5*time.Second, 10*time.Millisecond)
		})
	}
}
