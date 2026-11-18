package vault_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/vault"
)

func TestBucket_Allow(t *testing.T) {
	// given
	now := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	bucket := vault.NewBucket(10, 10, func() time.Time { return now })

	steps := []struct {
		name        string
		advance     time.Duration
		calls       int
		wantAllowed int
	}{
		{name: "start full", calls: 11, wantAllowed: 10},
		{name: "after 100ms", advance: 100 * time.Millisecond, calls: 2, wantAllowed: 1},
		{name: "after 1s", advance: time.Second, calls: 15, wantAllowed: 10},
		{name: "idle caps at burst", advance: 10 * time.Second, calls: 10, wantAllowed: 10},
	}

	for _, step := range steps {
		now = now.Add(step.advance)

		// when
		allowed := 0
		for range step.calls {
			if bucket.Allow() {
				allowed++
			}
		}

		// then
		require.Equal(t, step.wantAllowed, allowed, step.name)
	}
}
