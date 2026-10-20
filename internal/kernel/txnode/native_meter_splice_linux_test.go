//go:build linux

package txnode

import (
	"errors"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageinterval"
)

func TestNativeMeterSpliceOnlyPermitsLiveLocalObservation(t *testing.T) {
	var absent *nativeMeter
	if absent.AllowSplice() || (&nativeMeter{}).AllowSplice() {
		t.Fatal("missing observation owner allowed splice")
	}
	local, _ := newTestMeter(t)
	if !local.AllowSplice() {
		t.Fatal("active local observation refused explicit splice contract")
	}
	local.retire()
	if local.AllowSplice() {
		t.Fatal("retired local owner allowed a new splice relay")
	}

	session := nativeCrashSession()
	store, spool := nativeCrashOpen(t, t.TempDir(), session)
	defer spool.Close()
	defer store.Close()
	collector, err := store.NewCollector(session, nativeCrashWindow(session, "1"), map[string]int{"native-splice-test": 7})
	if err != nil {
		t.Fatal(err)
	}
	bounded, _ := newTestMeter(t)
	bounded.collector = collector
	if bounded.AllowSplice() || !bounded.EnableEnforcingBounded() || bounded.AllowSplice() {
		t.Fatal("real authorization collector allowed zero-copy before or after enforcement")
	}
	collector.Fail()
	if bounded.AllowSplice() {
		t.Fatal("unknown authorization collector allowed zero-copy")
	}
	bounded.retire()
	if bounded.AllowSplice() {
		t.Fatal("retired authorization collector allowed zero-copy")
	}
}

func TestNativeMeterSpliceTokensKeepOriginalFenceAndRetiredOwner(t *testing.T) {
	m, events := newTestMeter(t)
	meta := core.Chunk{ConnID: 331, UserID: 29, Path: "conn", N: 32}
	upload, err := m.Begin(meta)
	if err != nil {
		t.Fatal(err)
	}
	downloadMeta := meta
	downloadMeta.Dir = core.DirDownload
	download, err := m.Begin(downloadMeta)
	if err != nil {
		t.Fatal(err)
	}
	if !events.Cut(usagebucket.LifecycleFence, true) {
		t.Fatal("real observation generation fence failed")
	}
	m.Close(meta)
	m.retire()
	if m.AllowSplice() {
		t.Fatal("retired meter opted in")
	}
	if _, err := m.Begin(meta); !errors.Is(err, usageinterval.ErrUnknown) {
		t.Fatalf("retired owner admitted fresh intent: %v", err)
	}
	meta.N = 3
	m.Complete(meta, upload)
	downloadMeta.N, downloadMeta.Err = 5, errors.New("synthetic write failed after progress")
	m.Complete(downloadMeta, download)
	if m.inflight.Load() != 0 {
		t.Fatal("original owner retained completed operations")
	}
	snapshot := events.Snapshot()
	all := append([]usagebucket.Event{}, snapshot.Open.Events...)
	for _, bucket := range snapshot.Sealed {
		all = append(all, bucket.Events...)
	}
	seen := map[usagebucket.Path]usagebucket.Event{}
	closes := 0
	for _, event := range all {
		if event.Kind == "close_fence" {
			closes++
			continue
		}
		if event.Kind != "accounting_completion" {
			continue
		}
		if _, duplicate := seen[event.Path]; duplicate {
			t.Fatalf("duplicate original completion: %s", event.Path)
		}
		seen[event.Path] = event
		if !event.HasIOStart || event.IntervalUnknown || !event.CrossedFence || !event.LateAfterClose || event.StartedAfterClose ||
			event.BindingGeneration != 1 || event.ObservationGeneration != 2 || event.UserID != 29 || event.Attribution != "unattributable" || !event.CountKnown {
			t.Fatalf("original local observation boundary changed: %+v", event)
		}
	}
	up, down := seen[usagebucket.TCPRead], seen[usagebucket.TCPWrite]
	if len(seen) != 2 || closes != 1 || up.RawCount != 3 || up.IOError || up.PhysicalDirection != usagebucket.Upload ||
		down.RawCount != 5 || !down.IOError || down.PhysicalDirection != usagebucket.Download {
		t.Fatalf("original completion evidence: paths=%d closes=%d up=%+v down=%+v", len(seen), closes, up, down)
	}
}
