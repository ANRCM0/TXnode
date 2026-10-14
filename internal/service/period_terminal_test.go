package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	"os"
	"testing"
)

func TestPeriodDifferentUIDModeSwitchDrainsOldCohortAndFailedDeliveryKeepsStopped(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprint(upgrade), func(t *testing.T) {
			p := &authorityTestPlane{}
			s := authorityService(t, p)
			k := &fakeKernel{}
			s.kernel = k
			s.kernelLife = kernellifecycle.New(k)
			s.lastConfig = &model.NodeSpec{Protocol: "vless"}
			s.lastConfigHash = computeConfigHash(s.lastConfig)
			old, newPeriod := "signed-old", ""
			if upgrade {
				old, newPeriod = "", "signed-current"
			}
			users := []model.UserSpec{{ID: 7, UUID: "old", TrafficPeriod: old}}
			s.updateUserState(users, srcBootstrap)
			if !s.startKernel(s.lastConfig, users) {
				t.Fatal("first cohort")
			}
			s.tracker.Process(map[int][2]int64{7: {5, 8}}, nil, 0)
			p.reportErr = errors.New("lost ack")
			current := []model.UserSpec{{ID: 8, UUID: "new", TrafficPeriod: newPeriod}}
			s.applyUserUpdate(context.Background(), current, computeUserHash(current), srcWSFull)
			if k.running || !s.desiredDirty || !s.reporter.HasRecoveryBatch() {
				t.Fatal("differentUID mode switch admitted despite unresolved old cohort")
			}
			p.mu.Lock()
			p.reportErr = nil
			p.mu.Unlock()
			s.applyUserUpdate(context.Background(), current, computeUserHash(current), srcWSFull)
			if !k.running || s.desiredDirty {
				t.Fatal("drained current cohort did not recover")
			}
			s.tracker.Process(map[int][2]int64{8: {3, 4}}, nil, 0)
			batch := s.prepareReportBatch()
			if batch.Payload.Traffic[8] != [2]int64{3, 4} || s.tracker.HasTraffic() {
				t.Fatal("current cohort lost")
			}
			if upgrade && (len(batch.Payload.TrafficSegments) != 1 || batch.Payload.TrafficSegments[0].Period != newPeriod) {
				t.Fatal("fresh signed segment missing")
			}
			if !upgrade && batch.Payload.TrafficSegments != nil {
				t.Fatal("legacy downgrade relabelled signed")
			}
		})
	}
}
func TestPeriodTerminalQueueCapturesMoreThanTenThousandSegmentsAndPublicationFailureRestoresLabels(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			p := &authorityTestPlane{}
			s := authorityService(t, p)
			k := &terminalPublicationKernel{fakeKernel: &fakeKernel{running: true}}
			s.kernel = k
			s.kernelLife = kernellifecycle.New(k)
			for i := 0; i < 10001; i++ {
				s.tracker.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: fmt.Sprintf("opaque-%05d", i)}})
				s.tracker.Process(map[int][2]int64{7: {int64(i + 1), int64(i + 1)}}, nil, 0)
			}
			if fail {
				k.beforeStop = func() { _ = os.Mkdir(s.legacyPendingPath+".terminal.json", 0700) }
			}
			cause := &controlerror.NodeMembershipWithdrawal{NodeID: 42, MachineID: 16}
			err := s.stopForAuthorityDenial(cause)
			if got, ok := controlerror.AsMembershipWithdrawal(err); !ok || got != cause || k.running {
				t.Fatal("terminal scope/listener incorrect", err)
			}
			if fail {
				if err == cause || !s.tracker.HasTraffic() {
					t.Fatal("publication failure falsely certified persistence")
				}
				total, first := s.tracker.FlushBatch()
				last, second := s.tracker.FlushBatch()
				if len(first) == 0 || len(first) > 10000 || len(second) == 0 || len(second) > 10000 || total[7][0]+last[7][0] != 10001 || second[len(second)-1].Period != "opaque-10000" {
					t.Fatal("publication failure lost period chunk labels")
				}
				return
			}
			if s.tracker.HasTraffic() {
				t.Fatal("checkpoint success left volatile segment remainder")
			}
			body, e := os.ReadFile(s.legacyPendingPath + ".terminal.json")
			if e != nil {
				t.Fatal(e)
			}
			var bundle reporting.Batch
			if e := json.Unmarshal(body, &bundle); e != nil {
				t.Fatal(e)
			}
			if len(bundle.Payload.TrafficSegments) == 0 || len(bundle.Payload.TrafficSegments) > 10000 || len(bundle.RecoveryTail) != 1 || len(bundle.RecoveryTail[0].Payload.TrafficSegments) == 0 || len(bundle.Payload.TrafficSegments)+len(bundle.RecoveryTail[0].Payload.TrafficSegments) != 10001 || bundle.Payload.BatchID == bundle.RecoveryTail[0].Payload.BatchID {
				t.Fatal("terminal independent bounded IDs missing")
			}
		})
	}
}

type terminalPublicationKernel struct {
	*fakeKernel
	beforeStop func()
}

func (k *terminalPublicationKernel) Stop() {
	if k.beforeStop != nil {
		k.beforeStop()
		k.beforeStop = nil
	}
	k.fakeKernel.Stop()
}

func TestSignedGracefulShutdownFailurePersistsAllRemainingSegmentChunks(t *testing.T) {
	p := &authorityTestPlane{reportErr: errors.New("offline")}
	s := authorityService(t, p)
	k := &fakeKernel{}
	s.kernel = k
	s.kernelLife = kernellifecycle.New(k)
	for i := 0; i < 10001; i++ {
		s.tracker.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: fmt.Sprintf("opaque-%05d", i)}})
		s.tracker.Process(map[int][2]int64{7: {int64(i + 1), int64(i + 1)}}, nil, 0)
	}
	if err := s.pushReportSync(); err != nil {
		t.Fatal("durably checkpointed graceful shutdown", err)
	}
	if s.tracker.HasTraffic() || !s.reporter.HasRecoveryBatch() {
		t.Fatal("graceful exit left volatile remainder")
	}
	pending, e := os.ReadFile(s.legacyPendingPath)
	if e != nil {
		t.Fatal(e)
	}
	tail, e := os.ReadFile(s.legacyPendingPath + ".terminal.json")
	if e != nil {
		t.Fatal(e)
	}
	var first, last reporting.Batch
	if json.Unmarshal(pending, &first) != nil || json.Unmarshal(tail, &last) != nil || len(first.Payload.TrafficSegments) == 0 || len(last.Payload.TrafficSegments) == 0 || len(first.Payload.TrafficSegments)+len(last.Payload.TrafficSegments) != 10001 || first.Payload.Traffic[7][0]+last.Payload.Traffic[7][0] != 10001 {
		t.Fatal("graceful pending/tail did not retain all original periods")
	}
}

func TestSignedSynchronousPublicationRefusalRestoresPeriodBeforeTerminalFallback(t *testing.T) {
	for _, terminalBlocked := range []bool{false, true} {
		t.Run(fmt.Sprint(terminalBlocked), func(t *testing.T) {
			p := &authorityTestPlane{}
			s := authorityService(t, p)
			k := &fakeKernel{}
			s.kernel = k
			s.kernelLife = kernellifecycle.New(k)
			s.tracker.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "signed-original"}})
			s.tracker.Process(map[int][2]int64{7: {13, 17}}, nil, 0)
			if e := os.Mkdir(s.legacyPendingPath, 0700); e != nil {
				t.Fatal(e)
			} // pending exclusive publication fails after prepare/flush
			if terminalBlocked {
				if e := os.Mkdir(s.legacyPendingPath+".terminal.json", 0700); e != nil {
					t.Fatal(e)
				}
			}
			err := s.pushReportSync()
			p.mu.Lock()
			attempts := len(p.reports)
			p.mu.Unlock()
			if attempts != 0 {
				t.Fatal("unpersisted bytes delivered")
			}
			if terminalBlocked {
				if err == nil {
					t.Fatal("failed pending+tail persistence falsely successful")
				}
				raw, segments := s.tracker.FlushBatch()
				if raw[7] != [2]int64{13, 17} || len(segments) != 1 || segments[0].Period != "signed-original" {
					t.Fatal("publication refusal lost period", raw, segments)
				}
				return
			}
			if err != nil || s.tracker.HasTraffic() {
				t.Fatal("safe terminal fallback incomplete", err)
			}
			body, e := os.ReadFile(s.legacyPendingPath + ".terminal.json")
			if e != nil {
				t.Fatal(e)
			}
			var tail reporting.Batch
			if json.Unmarshal(body, &tail) != nil || tail.Payload.Traffic[7] != [2]int64{13, 17} || len(tail.Payload.TrafficSegments) != 1 || tail.Payload.TrafficSegments[0].Period != "signed-original" {
				t.Fatal("fallback did not preserve original signed period")
			}
		})
	}
}
