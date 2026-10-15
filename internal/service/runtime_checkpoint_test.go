package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"os"
	"testing"
	"time"
)

func TestRuntimeCheckpointClosesBeforeMeterPersistsSignedTailWithoutHTTP(t *testing.T) {
	p := &authorityTestPlane{reportErr: errors.New("must not call HTTP")}
	s := authorityService(t, p)
	k := &fakeKernel{running: true}
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	s.tracker.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "original-period"}})
	s.tracker.Process(map[int][2]int64{7: {17, 23}}, nil, 0)
	if err := s.stopForRuntimeCheckpoint(); err != nil {
		t.Fatal(err)
	}
	if k.running {
		t.Fatal("kernel still running")
	}
	p.mu.Lock()
	requests := len(p.reports)
	p.mu.Unlock()
	if requests != 0 {
		t.Fatal("checkpoint sent HTTP")
	}
	body, err := os.ReadFile(s.legacyPendingPath + ".terminal.json")
	if err != nil {
		t.Fatal(err)
	}
	var batch reporting.Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.Payload.Traffic[7] != [2]int64{17, 23} || batch.Payload.BatchID == "" || len(batch.Payload.TrafficSegments) != 1 || batch.Payload.TrafficSegments[0].Period != "original-period" {
		t.Fatal("original counters/identity lost")
	}
}
func TestRuntimeCheckpointPersistenceFailureCannotBecomeSuccess(t *testing.T) {
	p := &authorityTestPlane{}
	s := authorityService(t, p)
	k := &fakeKernel{running: true}
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	s.tracker.Process(map[int][2]int64{7: {1, 2}}, nil, 0)
	if err := os.Mkdir(s.legacyPendingPath+".terminal.json", 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.stopForRuntimeCheckpoint(); err == nil {
		t.Fatal("failed checkpoint certified")
	}
	if k.running {
		t.Fatal("failed checkpoint left I/O running")
	}
}
func TestRuntimeCheckpointCauseRunsThroughServiceAndReturnsCleanly(t *testing.T) {
	port := authorityPort(t)
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	s := authorityService(t, p)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	authorityWaitListener(t, port)
	cancel(controlerror.RuntimeCheckpoint)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime checkpoint did not join")
	}
	p.mu.Lock()
	requests := len(p.reports)
	p.mu.Unlock()
	if requests != 0 {
		t.Fatal("local checkpoint attempted report HTTP")
	}
}

type checkpointMeterKernel struct {
	*fakeKernel
	sampledRunning bool
	meterErr       error
}

func (k *checkpointMeterKernel) GetUserTraffic(context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	k.sampledRunning = k.running
	return nil, nil, 0, k.meterErr
}
func TestRuntimeCheckpointMetersOnlyClosedKernelAndRefusesMeterFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		p := &authorityTestPlane{}
		s := authorityService(t, p)
		k := &checkpointMeterKernel{fakeKernel: &fakeKernel{running: true}}
		if fail {
			k.meterErr = errors.New("meter failed")
		}
		s.kernel = k
		s.kernelLife = kernellifecycle.New(k)
		err := s.stopForRuntimeCheckpoint()
		if k.sampledRunning || k.running {
			t.Fatal("sample preceded kernel close")
		}
		if (err != nil) != fail {
			t.Fatal("meter failure became success", err)
		}
	}
}
