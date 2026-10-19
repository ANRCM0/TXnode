package txnode

import (
	"errors"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
)

func newTestMeter(t *testing.T) (*nativeMeter, *usagebucket.Meter) {
	t.Helper()
	meter, err := usagebucket.New(usagebucket.Options{Enabled: true, Window: time.Second, MaxEvents: 64, MaxSealed: 4})
	if err != nil {
		t.Fatal(err)
	}
	m := &nativeMeter{}
	m.setEventMeter(meter)
	return m, meter
}

func TestNativeMeterRecordsBucketEvents(t *testing.T) {
	m, meter := newTestMeter(t)
	chunk := core.Chunk{ConnID: 7, UserID: 3, Dir: core.DirUpload, Path: "conn"}
	token, err := m.Begin(chunk)
	if err != nil {
		t.Fatal(err)
	}
	chunk.N = 1024
	m.Complete(chunk, token)
	m.Close(chunk)

	snap := meter.Snapshot()
	total := len(snap.Open.Events)
	for _, b := range snap.Sealed {
		total += len(b.Events)
	}
	if total == 0 {
		t.Fatal("no accounting event recorded")
	}
}

func TestNativeMeterRefusesWhenCollectorUnknown(t *testing.T) {
	m := &nativeMeter{collector: &usageinterval.NativeCollector{}}
	if !m.EnableEnforcingBounded() {
		t.Fatal("enforcing not enabled")
	}
	if _, err := m.Begin(core.Chunk{ConnID: 1, UserID: 2, Dir: core.DirUpload, Path: "conn", N: 32}); !errors.Is(err, usageinterval.ErrUnknown) {
		t.Fatalf("err = %v, want ErrUnknown", err)
	}
	m.StopBoundedUsageTraffic()
	if _, err := m.Begin(core.Chunk{ConnID: 1, UserID: 2}); err != nil {
		t.Fatalf("stopped meter still refuses: %v", err)
	}
}
