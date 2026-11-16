package vm

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var errFake = errors.New("exit status 1")

func objectArg() string {
	return "--object secret,id=sec0,file=/dev/stdin"
}

func imageOpts(disk string) string {
	return "--image-opts driver=qcow2,file.filename=" + disk + ",encrypt.key-secret=sec0"
}

func convertCall(disk string) string {
	return "qemu-img convert -f qcow2 -O qcow2 " + objectArg() +
		" -o encrypt.format=luks,encrypt.key-secret=sec0 /img/base.img " + disk
}

func resizeCall(disk string) string {
	return "qemu-img resize " + objectArg() + " " + imageOpts(disk) + " 120G"
}

func snapshotCall(flag, name, disk string) string {
	return "qemu-img snapshot " + flag + " " + name + " " + objectArg() + " " + imageOpts(disk)
}

func createEmpty(t *testing.T) func(args []string) {
	t.Helper()

	return func(args []string) {
		require.NoError(t, os.WriteFile(args[len(args)-1], nil, 0o644))
	}
}

func TestMachine_CreateDisk(t *testing.T) {
	tests := []struct {
		name          string
		existing      bool
		convertErr    error
		resizeErr     error
		wantCalls     func(disk string) []string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name: "happy path - convert and resize",
			wantCalls: func(disk string) []string {
				return []string{convertCall(disk), resizeCall(disk)}
			},
		},
		{
			name:      "error - disk already exists",
			existing:  true,
			wantCalls: func(string) []string { return nil },
			wantErr:   ErrDiskExists,
		},
		{
			name:          "error - convert fails",
			convertErr:    errFake,
			wantCalls:     func(disk string) []string { return []string{convertCall(disk)} },
			wantErrPrefix: "creating disk: ",
		},
		{
			name:          "error - resize fails",
			resizeErr:     errFake,
			wantCalls:     func(disk string) []string { return []string{convertCall(disk), resizeCall(disk)} },
			wantErrPrefix: "creating disk: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, []response{
				{Match: "qemu-img convert", Err: tt.convertErr, Effect: createEmpty(t)},
				{Match: "qemu-img resize", Err: tt.resizeErr},
			})
			m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})
			disk := m.DiskPath()

			if tt.existing {
				require.NoError(t, os.WriteFile(disk, nil, 0o600))
			}

			// when
			err := m.CreateDisk(context.Background(), "/img/base.img", []byte(testKey))

			// then
			requireErr(t, err, tt.wantErr, tt.wantErrPrefix)
			require.Equal(t, tt.wantCalls(disk), fake.lines())
			fake.requireKeyNotInArgs(t)

			for _, stdin := range fake.stdinOf("qemu-img") {
				require.Equal(t, testKey, stdin)
			}

			if tt.wantErr == nil && tt.wantErrPrefix == "" {
				info, statErr := os.Stat(disk)
				require.NoError(t, statErr)
				require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			}

			if tt.convertErr != nil || tt.resizeErr != nil {
				require.NoFileExists(t, disk)
			}
		})
	}
}

func TestMachine_Snapshot(t *testing.T) {
	tests := []struct {
		name          string
		snapshot      string
		state         string
		getErr        error
		wantCalls     func(disk string) []string
		wantGets      []string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name:     "happy path - take snapshot",
			snapshot: "before-upgrade",
			state:    "shut off",
			wantCalls: func(disk string) []string {
				return []string{stateCall, snapshotCall("-c", "before-upgrade", disk)}
			},
			wantGets: []string{"vm-disk-key"},
		},
		{
			name:     "happy path - domain undefined",
			snapshot: "before-upgrade",
			state:    "undefined",
			wantCalls: func(disk string) []string {
				return []string{stateCall, snapshotCall("-c", "before-upgrade", disk)}
			},
			wantGets: []string{"vm-disk-key"},
		},
		{
			name:          "error - disk key unreadable",
			snapshot:      "before-upgrade",
			state:         "shut off",
			getErr:        errFake,
			wantCalls:     func(string) []string { return []string{stateCall} },
			wantGets:      []string{"vm-disk-key"},
			wantErrPrefix: "taking snapshot before-upgrade: reading disk key: ",
		},
		{
			name:      "error - vm running",
			snapshot:  "before-upgrade",
			state:     "running",
			wantCalls: func(string) []string { return []string{stateCall} },
			wantErr:   ErrRunning,
		},
		{
			name:      "error - uppercase name",
			snapshot:  "Before",
			wantCalls: func(string) []string { return nil },
			wantErr:   ErrInvalidSnapshotName,
		},
		{
			name:      "error - name with space",
			snapshot:  "a b",
			wantCalls: func(string) []string { return nil },
			wantErr:   ErrInvalidSnapshotName,
		},
		{
			name:      "error - path name",
			snapshot:  "../x",
			wantCalls: func(string) []string { return nil },
			wantErr:   ErrInvalidSnapshotName,
		},
		{
			name:      "error - empty name",
			snapshot:  "",
			wantCalls: func(string) []string { return nil },
			wantErr:   ErrInvalidSnapshotName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, []response{
				{Match: stateCall, Out: tt.state + "\n\n"},
				{Match: "qemu-img snapshot"},
			})
			store := &fakeSecrets{key: testKey, getErr: tt.getErr}
			m := newTestMachine(t, fake, store, &fakeRotator{})

			// when
			err := m.Snapshot(context.Background(), tt.snapshot)

			// then
			requireErr(t, err, tt.wantErr, tt.wantErrPrefix)
			require.Equal(t, tt.wantCalls(m.DiskPath()), fake.lines())
			require.Equal(t, tt.wantGets, store.gets)
			fake.requireKeyNotInArgs(t)

			for _, stdin := range fake.stdinOf("qemu-img") {
				require.Equal(t, testKey, stdin)
			}
		})
	}
}

func TestMachine_Restore(t *testing.T) {
	tests := []struct {
		name          string
		qemuErr       error
		rotateErr     error
		wantRotations int
		wantErrPrefix string
	}{
		{
			name:          "happy path - revert and rotate",
			wantRotations: 1,
		},
		{
			name:          "error - rotator fails",
			rotateErr:     errFake,
			wantRotations: 1,
			wantErrPrefix: "rotating vm tokens: ",
		},
		{
			name:          "error - qemu-img fails",
			qemuErr:       errFake,
			wantRotations: 0,
			wantErrPrefix: "restoring snapshot before-upgrade: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, []response{
				{Match: stateCall, Out: "shut off\n"},
				{Match: "qemu-img snapshot", Err: tt.qemuErr},
			})
			store := &fakeSecrets{key: testKey}
			rotator := &fakeRotator{err: tt.rotateErr}
			m := newTestMachine(t, fake, store, rotator)

			// when
			err := m.Restore(context.Background(), "before-upgrade")

			// then
			requireErr(t, err, nil, tt.wantErrPrefix)
			require.Equal(
				t,
				[]string{stateCall, snapshotCall("-a", "before-upgrade", m.DiskPath())},
				fake.lines(),
			)
			require.Equal(t, []string{"vm-disk-key"}, store.gets)
			require.Equal(t, []string{testKey}, fake.stdinOf("qemu-img"))
			require.Equal(t, tt.wantRotations, rotator.calls)
			fake.requireKeyNotInArgs(t)
		})
	}
}
