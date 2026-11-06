package audit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseUbuntuVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    ubuntuVersion
		wantErr bool
	}{
		{name: "happy path - lts", version: "26.04", want: ubuntuVersion{major: 26, minor: 4}},
		{name: "happy path - interim", version: "26.10", want: ubuntuVersion{major: 26, minor: 10}},
		{name: "error - empty", version: "", wantErr: true},
		{name: "error - no minor", version: "26", wantErr: true},
		{name: "error - words", version: "twenty-six", wantErr: true},
		{name: "error - extra part", version: "26.04.1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, err := parseUbuntuVersion(tt.version)

			// then
			if tt.wantErr {
				require.ErrorIs(t, err, errBadUbuntuVersion)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestUbuntuVersion_AtLeast(t *testing.T) {
	tests := []struct {
		name    string
		version ubuntuVersion
		min     ubuntuVersion
		want    bool
	}{
		{name: "happy path - equal", version: ubuntuVersion{26, 4}, min: ubuntuVersion{26, 4}, want: true},
		{name: "happy path - newer minor", version: ubuntuVersion{26, 10}, min: ubuntuVersion{26, 4}, want: true},
		{name: "happy path - newer major", version: ubuntuVersion{28, 4}, min: ubuntuVersion{26, 10}, want: true},
		{name: "happy path - older minor", version: ubuntuVersion{26, 4}, min: ubuntuVersion{26, 10}, want: false},
		{name: "happy path - older major", version: ubuntuVersion{24, 10}, min: ubuntuVersion{26, 4}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got := tt.version.atLeast(tt.min)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}
