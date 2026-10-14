package reporting

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/controlplane"
)

func terminalBatch(up, down int64) Batch {
	return Batch{Payload: controlplane.ReportPayload{Traffic: map[int][2]int64{7: {up, down}}}, TrafficCount: 1}
}

func terminalController(t *testing.T, sink *fakeSink) (*Controller, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "traffic.pending.json")
	c, err := NewDurable(sink, path)
	if err != nil {
		t.Fatal(err)
	}
	return c, path
}

func readTerminalFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTerminalCheckpointPreservesPendingAndClosesAdmissionBeforePrepare(t *testing.T) {
	sink := &fakeSink{supported: true}
	c, path := terminalController(t, sink)
	old, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	original := readTerminalFile(t, path)
	prepared := 0
	err = c.CheckpointTerminal(func() Batch {
		prepared++
		if c.PushAsync(func() Batch { t.Error("closed admission flushed traffic"); return Batch{} }, nil, nil) {
			t.Error("closed admission accepted an async report")
		}
		return terminalBatch(5, 9)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prepared != 1 || sink.callCount() != 0 || !c.HasTerminalTail() || c.EmptyForUsageHandoff() {
		t.Fatalf("checkpoint state: prepared=%d calls=%d tail=%v", prepared, sink.callCount(), c.HasTerminalTail())
	}
	if !bytes.Equal(original, readTerminalFile(t, path)) {
		t.Fatal("checkpoint overwrote old pending")
	}
	if c.terminal.Payload.BatchID == old.Payload.BatchID || c.terminal.Payload.BatchID == "" {
		t.Fatal("tail identity not distinct")
	}
	if err := c.CheckpointTerminal(func() Batch { t.Error("duplicate checkpoint flushed"); return terminalBatch(99, 99) }, nil); !errors.Is(err, ErrTerminalCheckpointExists) {
		t.Fatalf("duplicate checkpoint: %v", err)
	}
	info, err := os.Stat(path + ".terminal.json")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("tail permissions: %v %v", info, err)
	}
	if err := c.PushSync(func() Batch { t.Error("closed sync flushed"); return Batch{} }); !errors.Is(err, ErrReportingClosed) {
		t.Fatal(err)
	}
}

func TestTerminalRecoveryLostACKReplaysOriginalIDsFIFOAfterRestart(t *testing.T) {
	sink := &fakeSink{supported: true, err: errors.New("lost ACK")}
	first, path := terminalController(t, sink)
	old, err := first.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
		t.Fatal(err)
	}
	tailID := first.terminal.Payload.BatchID
	pendingBytes, tailBytes := readTerminalFile(t, path), readTerminalFile(t, path+".terminal.json")
	restarted, err := NewDurable(sink, path)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.PushAsync(func() Batch { t.Error("restart flushed before recovery"); return Batch{} }, nil, nil) {
		t.Fatal("restart admission open")
	}
	if err := restarted.ReplayRecovery(); !errors.Is(err, ErrRecoveryFailed) {
		t.Fatal(err)
	}
	if !bytes.Equal(pendingBytes, readTerminalFile(t, path)) || !bytes.Equal(tailBytes, readTerminalFile(t, path+".terminal.json")) {
		t.Fatal("lost ACK changed slots")
	}
	sink.mu.Lock()
	sink.err = nil
	sink.mu.Unlock()
	restarted, err = NewDurable(sink, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ReplayRecovery(); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	ids := append([]string(nil), sink.batchIDs...)
	sink.mu.Unlock()
	if !reflect.DeepEqual(ids, []string{old.Payload.BatchID, old.Payload.BatchID, tailID}) {
		t.Fatalf("recovery IDs: %v", ids)
	}
	if restarted.HasTerminalTail() || !restarted.EmptyForUsageHandoff() {
		t.Fatal("recovery did not drain both slots")
	}
	for _, name := range []string{path, path + ".terminal.json"} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery slot remained: %v", err)
		}
	}
}

func TestTerminalInFlightSenderAcknowledgesOnlyItsPendingSlot(t *testing.T) {
	started, release := make(chan struct{}, 1), make(chan struct{})
	sink := &fakeSink{supported: true, started: started, release: release}
	c, path := terminalController(t, sink)
	if !c.PushAsync(func() Batch { return terminalBatch(12, 34) }, nil, nil) {
		t.Fatal("initial report refused")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sender not started")
	}
	if err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
		t.Fatal(err)
	}
	tail := readTerminalFile(t, path+".terminal.json")
	if err := c.ReplayRecovery(); !errors.Is(err, ErrRecoveryActive) {
		t.Fatalf("recovery raced sender: %v", err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for c.Active() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Active() {
		t.Fatal("sender did not finish")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending not acknowledged")
	}
	if !c.HasTerminalTail() || !bytes.Equal(tail, readTerminalFile(t, path+".terminal.json")) {
		t.Fatal("old sender cleared terminal tail")
	}
	if c.EmptyForUsageHandoff() {
		t.Fatal("tail controller admitted handoff")
	}
}

func TestTerminalCheckpointPersistenceFailureRestoresOnlyUntaggedNewTraffic(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	if _, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) }); err != nil {
		t.Fatal(err)
	}
	old := readTerminalFile(t, path)
	c.terminalSpool.path = filepath.Join(filepath.Dir(path), "missing", "tail.json")
	var restored Batch
	var restoreErr error
	err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, func(batch Batch, err error) { restored, restoreErr = batch, err })
	if !errors.Is(err, ErrTerminalCheckpointFailed) || !errors.Is(restoreErr, ErrTerminalCheckpointFailed) {
		t.Fatalf("persistence failure: %v/%v", err, restoreErr)
	}
	if restored.Payload.BatchID != "" || restored.Payload.Traffic[7] != [2]int64{5, 9} {
		t.Fatalf("restored wrong traffic: %#v", restored)
	}
	if !bytes.Equal(old, readTerminalFile(t, path)) || c.HasTerminalTail() {
		t.Fatal("failed checkpoint changed original slot")
	}
	if c.PushAsync(func() Batch { t.Error("failure reopened admission"); return Batch{} }, nil, nil) {
		t.Fatal("failure reopened admission")
	}
}

func TestTerminalEmptyCheckpointClosesAdmissionAndCannotBeRepeated(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	if err := c.CheckpointTerminal(func() Batch { return Batch{} }, nil); err != nil {
		t.Fatal(err)
	}
	if c.HasTerminalTail() || c.EmptyForUsageHandoff() {
		t.Fatal("empty stopped state wrong")
	}
	if _, err := os.Stat(path + ".terminal.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty tail was persisted")
	}
	if err := c.CheckpointTerminal(func() Batch { t.Error("empty checkpoint repeated prepare"); return Batch{} }, nil); !errors.Is(err, ErrTerminalCheckpointExists) {
		t.Fatal(err)
	}
}

func TestTerminalMissingOrCorruptTailFailsClosedWithoutHTTP(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "replaced"} {
		t.Run(mode, func(t *testing.T) {
			sink := &fakeSink{supported: true}
			c, path := terminalController(t, sink)
			if err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
				t.Fatal(err)
			}
			if mode == "missing" {
				if err := os.Remove(path + ".terminal.json"); err != nil {
					t.Fatal(err)
				}
			} else if mode == "corrupt" {
				if err := os.WriteFile(path+".terminal.json", []byte("broken"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				replaced := *c.terminal
				replaced.Payload.BatchID = "different"
				if err := c.terminalSpool.clear(*c.terminal); err != nil {
					t.Fatal(err)
				}
				if err := c.terminalSpool.save(replaced); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.ReplayRecovery(); !errors.Is(err, ErrRecoveryFailed) || sink.callCount() != 0 || !c.HasTerminalTail() {
				t.Fatalf("invalid tail: err=%v calls=%d", err, sink.callCount())
			}
		})
	}
}

func TestTerminalCorruptStartupAndDuplicateIDsRefuseRecovery(t *testing.T) {
	for _, mode := range []string{"corrupt", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			c, path := terminalController(t, &fakeSink{supported: true})
			old, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
			if err != nil {
				t.Fatal(err)
			}
			if mode == "corrupt" {
				err = os.WriteFile(path+".terminal.json", []byte("broken"), 0o600)
			} else {
				err = c.terminalSpool.save(old)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewDurable(&fakeSink{supported: true}, path); err == nil {
				t.Fatal("bad terminal startup accepted")
			}
		})
	}
}

func TestTerminalUnexpectedExistingFileRefusesBeforeFlushing(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	if err := os.WriteFile(path+".terminal.json", []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	var prepared atomic.Int32
	if err := c.CheckpointTerminal(func() Batch { prepared.Add(1); return terminalBatch(5, 9) }, nil); !errors.Is(err, ErrTerminalCheckpointExists) || prepared.Load() != 0 {
		t.Fatalf("existing tail: %v prepares=%d", err, prepared.Load())
	}
}

func TestTerminalACKRefusesMissingFileAndLeavesInMemoryIdentity(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	old, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := c.acknowledge(old); err == nil || c.pending == nil {
		t.Fatal("missing spool treated as successful ACK")
	}
}

func TestTerminalTailOnlyStartupRecoversWithoutFreshPreparation(t *testing.T) {
	sink := &fakeSink{supported: true}
	c, path := terminalController(t, sink)
	old, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
		t.Fatal(err)
	}
	tailID := c.terminal.Payload.BatchID
	if err := c.acknowledge(old); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewDurable(sink, path)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.HasTerminalTail() || restarted.EmptyForUsageHandoff() {
		t.Fatal("tail-only startup became empty")
	}
	if err := restarted.ReplayRecovery(); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	ids := append([]string(nil), sink.batchIDs...)
	sink.mu.Unlock()
	if !reflect.DeepEqual(ids, []string{tailID}) {
		t.Fatalf("tail-only replay: %v", ids)
	}
	if !restarted.EmptyForUsageHandoff() {
		t.Fatal("tail-only recovery did not finish")
	}
}

func TestTerminalDelayedUnrelatedACKCannotClearEitherSlot(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	old, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
		t.Fatal(err)
	}
	pending, tail := readTerminalFile(t, path), readTerminalFile(t, path+".terminal.json")
	old.Payload.BatchID = "unrelated-old-batch"
	if err := c.acknowledge(old); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pending, readTerminalFile(t, path)) || !bytes.Equal(tail, readTerminalFile(t, path+".terminal.json")) {
		t.Fatal("unrelated ACK cleared a slot")
	}
}

func TestTerminalCheckpointRaceAllowsExactlyOnePrepare(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	entered, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- c.CheckpointTerminal(func() Batch { close(entered); <-release; return terminalBatch(5, 9) }, nil)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first prepare did not enter")
	}
	if err := c.CheckpointTerminal(func() Batch { t.Error("overlapping checkpoint prepared"); return terminalBatch(99, 99) }, nil); !errors.Is(err, ErrTerminalCheckpointExists) {
		t.Fatal(err)
	}
	if c.PushAsync(func() Batch { t.Error("closed checkpoint allowed new prepare"); return Batch{} }, nil, nil) {
		t.Fatal("checkpoint admission open")
	}
	close(release)
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("checkpoint did not finish")
	}
	if _, err := os.Stat(path + ".terminal.json"); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalPersistenceKeepsOriginalCountersWhenHTTPFailsConcurrently(t *testing.T) {
	started, release := make(chan struct{}, 1), make(chan struct{})
	sink := &fakeSink{supported: true, started: started, release: release, err: errors.New("lost ACK")}
	c, path := terminalController(t, sink)
	failure := make(chan Batch, 1)
	if !c.PushAsync(func() Batch { return terminalBatch(12, 34) }, func(batch Batch, err error) { failure <- batch }, nil) {
		t.Fatal("report not started")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sender not started")
	}
	pending := readTerminalFile(t, path)
	if err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
		t.Fatal(err)
	}
	tail := readTerminalFile(t, path+".terminal.json")
	close(release)
	select {
	case batch := <-failure:
		if len(batch.Payload.Traffic) != 0 {
			t.Fatal("ambiguous old bytes restored")
		}
	case <-time.After(time.Second):
		t.Fatal("failure not returned")
	}
	deadline := time.Now().Add(time.Second)
	for c.Active() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !bytes.Equal(pending, readTerminalFile(t, path)) || !bytes.Equal(tail, readTerminalFile(t, path+".terminal.json")) {
		t.Fatal("concurrent failure changed either slot")
	}
}

func TestTerminalLegacyPendingWithMetricsKeepsCanonicalPayload(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	batch, err := c.nextBatch(func() Batch {
		batch := terminalBatch(12, 34)
		batch.Payload.Metrics = map[string]interface{}{"large_integer": int64(9007199254740993), "nested": map[string]interface{}{"uptime": 42}}
		return batch
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.spool.matches(batch); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewDurable(&fakeSink{supported: true}, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ReplayRecovery(); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalACKRefusesChangedBodyEvenWhenBatchIDMatches(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	old, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
		t.Fatal(err)
	}
	tail := readTerminalFile(t, path+".terminal.json")
	if err := c.spool.clear(old); err != nil {
		t.Fatal(err)
	}
	changed := terminalBatch(1234, 5678)
	changed.Payload.BatchID = old.Payload.BatchID
	if err := c.spool.save(changed); err != nil {
		t.Fatal(err)
	}
	changedBytes := readTerminalFile(t, path)
	if err := c.acknowledge(old); err == nil || c.pending == nil {
		t.Fatal("ACK cleared a changed body")
	}
	if !bytes.Equal(changedBytes, readTerminalFile(t, path)) || !bytes.Equal(tail, readTerminalFile(t, path+".terminal.json")) {
		t.Fatal("mismatching ACK altered either slot")
	}
}

func TestTerminalMemoryFixtureRetainsTwoSlotsWithoutClaimingDiskPersistence(t *testing.T) {
	sink := &fakeSink{supported: true}
	c := New(sink)
	old, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckpointTerminal(func() Batch { return terminalBatch(5, 9) }, nil); err != nil {
		t.Fatal(err)
	}
	if c.pending.Payload.BatchID != old.Payload.BatchID || !c.HasTerminalTail() || c.spool != nil || c.terminalSpool != nil {
		t.Fatal("in-memory fixture slots changed")
	}
	if sink.callCount() != 0 {
		t.Fatal("checkpoint sent HTTP")
	}
}

func TestTerminalClearFailureRestorationKeepsExactLegacyBytes(t *testing.T) {
	c, path := terminalController(t, &fakeSink{supported: true})
	batch, err := c.nextBatch(func() Batch { return terminalBatch(12, 34) })
	if err != nil {
		t.Fatal(err)
	}
	original := append(readTerminalFile(t, path), '\n')
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := c.spool.restoreAfterClearFailure(original); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, readTerminalFile(t, path)) {
		t.Fatal("restoration altered immutable spool bytes")
	}
	if err := c.spool.matches(batch); err != nil {
		t.Fatal(err)
	}
	if err := c.spool.restoreAfterClearFailure([]byte("different")); err == nil {
		t.Fatal("restoration overwrote existing record")
	}
	if !bytes.Equal(original, readTerminalFile(t, path)) {
		t.Fatal("existing restoration record changed")
	}
}
