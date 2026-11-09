package guard_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tahardi/xena/internal/guard"
)

func TestPass(t *testing.T) {
	tests := []struct {
		name     string
		evidence []string
		want     []string
	}{
		{name: "happy path - evidence", evidence: []string{"drop: a", "drop: b"}, want: []string{"drop: a", "drop: b"}},
		{name: "happy path - no evidence is an empty slice", want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			want := guard.Result{Case: "net-lan", Passed: true, Evidence: tt.want}

			// when
			got := guard.Pass("net-lan", tt.evidence...)

			// then
			assert.Equal(t, want, got)
		})
	}
}

func TestFail(t *testing.T) {
	tests := []struct {
		name     string
		evidence []string
		want     []string
	}{
		{
			name:     "happy path - evidence",
			evidence: []string{"vm: blocked 10.0.0.10:22"},
			want:     []string{"vm: blocked 10.0.0.10:22"},
		},
		{name: "happy path - no evidence is an empty slice", want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			want := guard.Result{Case: "net-lan", Error: "no drop for 10.0.0.10:22", Evidence: tt.want}

			// when
			got := guard.Fail("net-lan", "no drop for 10.0.0.10:22", tt.evidence...)

			// then
			assert.Equal(t, want, got)
		})
	}
}
