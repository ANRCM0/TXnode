package reporting

import (
	"bytes"
	"errors"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/model"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type bundleSink struct {
	mu     sync.Mutex
	ids    []string
	failAt int
}

func (s *bundleSink) Report(payload controlplane.ReportPayload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids = append(s.ids, payload.BatchID)
	if len(s.ids) == s.failAt {
		return errors.New("lost ack")
	}
	return nil
}
func (s *bundleSink) ReportDevices(controlplane.PushClient, map[int][]string) {}
func (s *bundleSink) SupportsReporting() bool                                 { return true }
func (s *bundleSink) SupportsDeviceReports() bool                             { return false }
func TestPeriodTerminalBundleKeepsOriginalFileAndFIFOThroughPartialAckRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.json")
	sink := &bundleSink{failAt: 1}
	controller, e := NewDurable(sink, path)
	if e != nil {
		t.Fatal(e)
	}
	pending := Batch{Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {3, 4}}}}
	if e := controller.PushSync(func() Batch { return pending }); e == nil {
		t.Fatal("lost pending ack")
	}
	index := 0
	parts := []Batch{{MoreTraffic: true, Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {5, 8}}}}, {MoreTraffic: true, Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{8: {13, 17}}, TrafficSegments: []model.TrafficSegment{{UserID: 8, Period: "old-signed", Upload: 13, Download: 17}}}}, {Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{8: {19, 23}}, TrafficSegments: []model.TrafficSegment{{UserID: 8, Period: "new-signed", Upload: 19, Download: 23}}}}}
	if e := controller.CheckpointTerminal(func() Batch { value := parts[index]; index++; return value }, nil); e != nil || index != 3 {
		t.Fatal("terminal queue not fully captured", e, index)
	}
	original, e := os.ReadFile(path + ".terminal.json")
	if e != nil {
		t.Fatal(e)
	}
	sink.mu.Lock()
	sink.ids = nil
	sink.failAt = 3
	sink.mu.Unlock()
	if e := controller.ReplayRecovery(); e == nil {
		t.Fatal("third chunk lost ack accepted")
	}
	retained, e := os.ReadFile(path + ".terminal.json")
	if e != nil || !bytes.Equal(original, retained) {
		t.Fatal("partial ACK rewrote immutable terminal bundle")
	}
	sink.mu.Lock()
	attempts := append([]string(nil), sink.ids...)
	sink.ids = nil
	sink.failAt = 0
	sink.mu.Unlock()
	restarted, e := NewDurable(sink, path)
	if e != nil {
		t.Fatal(e)
	}
	if e := restarted.ReplayRecovery(); e != nil {
		t.Fatal(e)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(attempts) != 3 || len(sink.ids) != 3 || attempts[1] != sink.ids[0] || attempts[2] != sink.ids[1] || sink.ids[0] == sink.ids[1] || sink.ids[1] == sink.ids[2] {
		t.Fatal("bundle FIFO/original IDs changed", attempts, sink.ids)
	}
	if _, e := os.Stat(path + ".terminal.json"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("fully acked bundle not cleared", e)
	}
}
func TestPeriodTerminalBundlePublicationFailureRestoresEveryAttributionChunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.json")
	controller, e := NewDurable(&bundleSink{}, path)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(path+".terminal.json", 0700); e != nil {
		t.Fatal(e)
	}
	// Reservation fails before prepare: no consumed data or false durability.
	called := false
	if e := controller.CheckpointTerminal(func() Batch { called = true; return Batch{} }, nil); e == nil || called {
		t.Fatal("invalid target consumed data")
	}
}
