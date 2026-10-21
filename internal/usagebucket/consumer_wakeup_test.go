package usagebucket

import (
	"testing"
	"time"
)

func TestSealedWorkWakesConsumerWithoutCoordinatorLockOrDisk(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "already-pending"}[pending], func(t *testing.T) {
			at := Stamp{100, 10}
			meter := testMeter(t, Options{Clock: func() Stamp { return at }, Window: time.Hour, MaxEvents: 1, MaxSealed: 2})
			consumer, err := makeCoordinator(CoordinatorOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := consumer.Add(meter); err != nil {
				t.Fatal(err)
			}
			if !pending {
				<-consumer.wake // Discard the initial registration notification.
			}
			session := meter.Bind(7, "wake-test", "tcp")
			session.Complete(session.Begin(), TCPRead, Upload, Upload, 3, false, true)
			// The consumer has no worker/store and holds its own mutex. Sealing
			// must still return, leaving work retained for its eventual ACK.
			consumer.mu.Lock()
			done := make(chan struct{})
			go func() {
				session.Complete(session.Begin(), TCPRead, Upload, Upload, 5, false, true)
				close(done)
			}()
			select {
			case <-done:
				consumer.mu.Unlock()
			case <-time.After(time.Second):
				consumer.mu.Unlock()
				t.Fatal("sealed work waited for the coordinator or its pending signal")
			}
			select {
			case <-consumer.wake:
			default:
				t.Fatal("newly sealed work did not wake the consumer")
			}
			snapshot := meter.Snapshot()
			if snapshot.Status.Degraded || snapshot.Status.DroppedEvents != 0 || snapshot.Status.PersistedBuckets != 0 || len(snapshot.Sealed) != 1 || snapshot.Sealed[0].PhysicalTotals != [2]int64{3, 0} || snapshot.Open.PhysicalTotals != [2]int64{5, 0} {
				t.Fatalf("notification changed retained evidence or acknowledged without persistence: %+v", snapshot)
			}
		})
	}
}
