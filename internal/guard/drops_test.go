package guard_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/guard"
)

func TestParseDrop(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    guard.Drop
		wantOK  bool
	}{
		{
			name: "happy path - tcp input",
			message: "xena-drop: IN=xena0 OUT= MAC=52:54:00:00:00:01 SRC=192.168.150.10 DST=192.168.150.1 " +
				"LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN",
			want: guard.Drop{
				In:      "xena0",
				Src:     "192.168.150.10",
				Dst:     "192.168.150.1",
				Proto:   "TCP",
				DstPort: 22,
				SYN:     true,
			},
			wantOK: true,
		},
		{
			name: "happy path - tcp flags without syn",
			message: "xena-drop: IN=xena0 OUT= SRC=192.168.150.10 DST=192.168.150.1 " +
				"PROTO=TCP SPT=40000 DPT=22 WINDOW=0 RES=0x00 ACK FIN URGP=0",
			want: guard.Drop{
				In:      "xena0",
				Src:     "192.168.150.10",
				Dst:     "192.168.150.1",
				Proto:   "TCP",
				DstPort: 22,
				ACK:     true,
			},
			wantOK: true,
		},
		{
			name:    "happy path - forwarded udp",
			message: "xena-drop: IN=xena0 OUT=enp5s0 SRC=192.168.150.10 DST=198.51.100.53 LEN=30 PROTO=UDP SPT=40000 DPT=53",
			want: guard.Drop{
				In:      "xena0",
				Out:     "enp5s0",
				Src:     "192.168.150.10",
				Dst:     "198.51.100.53",
				Proto:   "UDP",
				DstPort: 53,
			},
			wantOK: true,
		},
		{
			name:    "happy path - icmpv6 without port",
			message: "xena-drop: IN=xena0 OUT= SRC=fe80::5054:ff:fe00:1 DST=ff02::1 PROTO=ICMPv6",
			want:    guard.Drop{In: "xena0", Src: "fe80::5054:ff:fe00:1", Dst: "ff02::1", Proto: "ICMPv6"},
			wantOK:  true,
		},
		{
			name:    "happy path - prefix inside the message",
			message: "[ 12.5] xena-drop: IN=xena0 OUT= SRC=192.168.150.10 DST=192.168.150.1 PROTO=TCP DPT=80",
			want:    guard.Drop{In: "xena0", Src: "192.168.150.10", Dst: "192.168.150.1", Proto: "TCP", DstPort: 80},
			wantOK:  true,
		},
		{
			name:    "happy path - tokend drop is not a drop",
			message: "xena-tokend-drop: IN=xena0 OUT= SRC=192.168.150.10 DST=192.168.150.1 PROTO=TCP DPT=22",
		},
		{
			name:    "happy path - non-numeric port is zero",
			message: "xena-drop: IN=xena0 OUT= SRC=192.168.150.10 DST=192.168.150.1 PROTO=TCP DPT=abc",
			want:    guard.Drop{In: "xena0", Src: "192.168.150.10", Dst: "192.168.150.1", Proto: "TCP"},
			wantOK:  true,
		},
		{
			name:    "happy path - not a drop",
			message: "usb 1-1: new high-speed USB device",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, ok := guard.ParseDrop(tt.message)

			// then
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJournalDrops_Drops(t *testing.T) {
	drop := `{"__REALTIME_TIMESTAMP":"1792000000000000",` +
		`"MESSAGE":"xena-drop: IN=xena0 OUT= SRC=192.168.150.10 DST=192.168.150.1 PROTO=TCP DPT=22"}`
	other := `{"__REALTIME_TIMESTAMP":"1792000000000001","MESSAGE":"usb 1-1: new device"}`
	binary := `{"__REALTIME_TIMESTAMP":"1792000000000002","MESSAGE":[120,101,110,97]}`
	since := time.Unix(1792000000, 0)

	tests := []struct {
		name     string
		output   string
		exitCode int
		want     []guard.Drop
		wantErr  string
	}{
		{
			name:   "happy path - parses drops and skips others",
			output: drop + "\n" + other + "\n" + binary + "\n",
			want: []guard.Drop{{
				Time:    time.UnixMicro(1792000000000000),
				In:      "xena0",
				Src:     "192.168.150.10",
				Dst:     "192.168.150.1",
				Proto:   "TCP",
				DstPort: 22,
			}},
		},
		{name: "happy path - passes since", output: "", want: []guard.Drop{}},
		{name: "error - command fails", exitCode: 1, wantErr: "running journalctl"},
		{name: "error - bad json", output: "{not json\n", wantErr: "decoding journal entry"},
		{
			name:    "error - bad timestamp",
			output:  `{"__REALTIME_TIMESTAMP":"soon","MESSAGE":"xena-drop: PROTO=TCP"}` + "\n",
			wantErr: "decoding journal entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			argsPath := filepath.Join(dir, "args")
			outputPath := filepath.Join(dir, "output")
			require.NoError(t, os.WriteFile(outputPath, []byte(tt.output), 0o600))

			script := filepath.Join(dir, "journalctl")
			body := fmt.Sprintf(
				"#!/usr/bin/env bash\necho \"$*\" > %q\ncat %q\nexit %d\n",
				argsPath,
				outputPath,
				tt.exitCode,
			)
			require.NoError(t, os.WriteFile(script, []byte(body), 0o700))

			// when
			got, err := guard.NewJournalDrops(script).Drops(context.Background(), since)

			// then
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			args, err := os.ReadFile(argsPath)
			require.NoError(t, err)
			assert.Equal(t, "-k -o json --no-pager --since @1792000000\n", string(args))
		})
	}
}
