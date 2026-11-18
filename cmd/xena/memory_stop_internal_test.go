package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/memory"
)

var (
	errMemoryFakePull    = errors.New("exporting memory: vm gone")
	errMemoryFakeState   = errors.New("reading vm state: no libvirt")
	errMemoryFakeBuilder = errors.New("vm unreachable")
)

type memoryFakePuller struct {
	err    error
	hang   bool
	pulled bool
}

func (p *memoryFakePuller) Pull(ctx context.Context, _ bool) (memory.Result, error) {
	p.pulled = true
	if p.hang {
		<-ctx.Done()
		return memory.Result{}, ctx.Err()
	}

	return memory.Result{}, p.err
}

type memoryFakeVM struct {
	state string
	err   error
}

func (v memoryFakeVM) State(context.Context) (string, error) {
	return v.state, v.err
}

func TestSyncBeforeStop(t *testing.T) {
	tests := []struct {
		name       string
		vm         memoryFakeVM
		pullErr    error
		builderErr error
		hang       bool
		wantPulled bool
		wantWarn   string
	}{
		{
			name:       "happy path - running vm pulls",
			vm:         memoryFakeVM{state: "running"},
			wantPulled: true,
		},
		{
			name:       "error - pull fails warns",
			vm:         memoryFakeVM{state: "running"},
			pullErr:    errMemoryFakePull,
			wantPulled: true,
			wantWarn:   "warning: memory sync failed: exporting memory: vm gone\n",
		},
		{
			name: "happy path - shut off vm skips",
			vm:   memoryFakeVM{state: "shut off"},
		},
		{
			name:       "happy path - unknown state still pulls",
			vm:         memoryFakeVM{err: errMemoryFakeState},
			wantPulled: true,
		},
		{
			name:       "error - stalled pull times out and warns",
			vm:         memoryFakeVM{state: "running"},
			hang:       true,
			wantPulled: true,
			wantWarn:   "warning: memory sync failed: context deadline exceeded\n",
		},
		{
			name:       "error - building puller fails warns",
			vm:         memoryFakeVM{state: "running"},
			builderErr: errMemoryFakeBuilder,
			wantWarn:   "warning: memory sync failed: vm unreachable\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			puller := &memoryFakePuller{err: tt.pullErr, hang: tt.hang}
			newPuller := func() (memoryPuller, error) {
				if tt.builderErr != nil {
					return nil, tt.builderErr
				}

				return puller, nil
			}
			var warn bytes.Buffer

			// when
			syncBeforeStop(context.Background(), tt.vm, newPuller, &warn, 10*time.Millisecond)

			// then
			require.Equal(t, tt.wantPulled, puller.pulled)
			require.Equal(t, tt.wantWarn, warn.String())
		})
	}
}
