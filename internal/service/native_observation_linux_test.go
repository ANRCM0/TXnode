//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/ANRCM0/TX-Node/internal/usageobserver"
)

func nativeObservationOrigins(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], from)
		}
	}()
	return tcp, udp
}

func nativeObservationWait(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("native observation did not reach its expected state")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// This client drives the actual RFC1928 packet entry, including authentication.
func nativeObservationUDP(t *testing.T, port int) (net.Conn, *net.UDPConn) {
	t.Helper()
	control, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	_ = control.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := control.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil || reply != [2]byte{5, 2} {
		t.Fatal("packet method negotiation", reply, err)
	}
	auth := append([]byte{1, 1, 'u', byte(len(liveProtocolUUID))}, liveProtocolUUID...)
	if _, err := control.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(control, reply[:]); err != nil || reply != [2]byte{1, 0} {
		t.Fatal("packet authentication", reply, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var bound [10]byte
	if _, err := io.ReadFull(control, bound[:]); err != nil || !bytes.Equal(bound[:4], []byte{5, 0, 0, 1}) {
		t.Fatal("packet association reply", bound, err)
	}
	if int(binary.BigEndian.Uint16(bound[8:])) != port {
		t.Fatal("packet association escaped the Node endpoint")
	}
	packet, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(bound[4:8]), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	_ = control.SetDeadline(time.Time{})
	return control, packet
}

func nativeObservationPacketEcho(t *testing.T, c *net.UDPConn, target net.Addr, n int) {
	t.Helper()
	a := target.(*net.UDPAddr)
	p := append([]byte{0, 0, 0, 1}, a.IP.To4()...)
	p = binary.BigEndian.AppendUint16(p, uint16(a.Port))
	p = append(p, bytes.Repeat([]byte{'p'}, n)...)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(p); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(p)+1)
	if size, err := c.Read(got); err != nil || size != len(p) || !bytes.Equal(got[:size], p) {
		t.Fatalf("real packet response size=%d want=%d err=%v", size, len(p), err)
	}
}

func nativeObservationTCPEcho(t *testing.T, port, n int, target net.Addr) {
	t.Helper()
	raw, c := liveProtocolDial(t, "socks", fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, target)
	defer raw.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	p := bytes.Repeat([]byte{'t'}, n)
	if _, err := c.Write(p); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(p, got) {
		t.Fatal("real stream response", err)
	}
}

func nativeObserverRecords(t *testing.T, dir string) []usageobserver.Record {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var records []usageobserver.Record
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Record usageobserver.Record `json:"record"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(liveProtocolUUID)) {
			t.Fatal("observer persisted a credential")
		}
		records = append(records, envelope.Record)
	}
	return records
}

func TestNativeServiceObservationPersistsExactTCPUDPAndRecoversOriginalEvidence(t *testing.T) {
	tcp, udp := nativeObservationOrigins(t)
	port := authorityPort(t)
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	s := authorityService(t, p)
	s.cfg.Node.TrackInterval = 1
	s.cfg.UsageEventStore.Enabled, s.cfg.UsageObserver.Enabled = true, true
	s.eventOwner = &usagebucket.ProcessOwner{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Error("Service did not stop")
			}
		}
	})
	authorityWaitListener(t, port)
	nativeObservationTCPEcho(t, port, 31, tcp.Addr())
	control, packet := nativeObservationUDP(t, port)
	nativeObservationPacketEcho(t, packet, udp.LocalAddr(), 27)
	control.Close()
	packet.Close()
	nativeObservationWait(t, func() bool {
		traffic, _, active, _ := s.kernel.GetUserTraffic(t.Context())
		if traffic[7] != [2]int64{58, 58} || active != 0 {
			return false
		}
		for _, r := range nativeObserverRecords(t, s.usageObserverDirectory()) {
			for _, c := range r.Counters {
				if c.UserID == "7" && c.Up == "58" && c.Down == "58" {
					return true
				}
			}
		}
		return false
	})
	cancel()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("native Service shutdown blocked")
	}
	c := s.localEventConsumer()
	if c == nil || !c.Status().Closed || c.Status().Degraded {
		t.Fatal("real event consumer did not drain", s.localEventMetrics())
	}
	status, ready := c.StoreSnapshot()
	if !ready || status.Buckets == 0 || !status.Closed || status.Degraded {
		t.Fatal("real event store did not persist", status)
	}
	totals := map[string][2]int64{}
	var original []usagebucket.StoredRecord
	for seq := uint64(1); seq <= status.Sequence; seq++ {
		record, err := c.ReadRecord(seq)
		if err != nil {
			t.Fatal(err)
		}
		original = append(original, record)
		if record.Authorizes || record.Attribution != "unattributable" {
			t.Fatal("local observations became billing authority")
		}
		if record.Bucket == nil {
			continue
		}
		for _, e := range record.Bucket.Events {
			if e.Kind != "accounting_completion" || !e.CountKnown {
				continue
			}
			if e.UserID != 7 || e.PhysicalDirection != e.LegacyDirection {
				t.Fatal("event identity or physical direction changed", e)
			}
			n := totals[e.Transport]
			if e.PhysicalDirection == usagebucket.Upload {
				n[0] += e.RawCount
			} else {
				n[1] += e.RawCount
			}
			totals[e.Transport] = n
		}
	}
	if totals["tcp"] != [2]int64{31, 31} || totals["udp"] != [2]int64{27, 27} {
		t.Fatal("durable original I/O bytes changed", totals)
	}
	for attempt := 0; attempt < 2; attempt++ {
		reopened, err := usagebucket.OpenStore(s.localEventDirectory(), usagebucket.StoreOptions{})
		if err != nil {
			t.Fatal("event store recovery", err)
		}
		for _, before := range original {
			after, err := reopened.Read(before.Sequence)
			if err != nil || after.Digest != before.Digest || after.LocalReceiptID != before.LocalReceiptID || after.BucketDigest != before.BucketDigest {
				t.Fatal("recovery changed original local evidence", before.Sequence, err)
			}
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
	records := nativeObserverRecords(t, s.usageObserverDirectory())
	sampled := false
	for _, r := range records {
		for _, counter := range r.Counters {
			if counter.UserID == "7" && counter.Up == "58" && counter.Down == "58" {
				sampled = true
			}
		}
	}
	if !sampled || records[len(records)-1].Event != "PROCESS_END" {
		t.Fatal("observer did not retain exact original sample and shutdown", records)
	}
	restored, err := usageobserver.Open(s.usageObserverDirectory(), usageobserver.Options{})
	if err != nil {
		t.Fatal("observer recovery", err)
	}
	if restored.Status().Sequence <= records[len(records)-1].Sequence {
		t.Fatal("observer recovery did not preserve its original sequence")
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	for i, before := range records {
		after := nativeObserverRecords(t, s.usageObserverDirectory())[i]
		b, _ := json.Marshal(before)
		a, _ := json.Marshal(after)
		if !bytes.Equal(b, a) {
			t.Fatal("observer recovery rewrote a prior record")
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var reported [2]int64
	for _, report := range p.reports {
		n := report.Traffic[7]
		reported[0], reported[1] = reported[0]+n[0], reported[1]+n[1]
	}
	if reported != [2]int64{58, 58} {
		t.Fatal("local observations consumed or duplicated v1 counters", reported)
	}
}

func TestNativePacketPeriodKeepsUnsampledOldTailAndFreshBytesSeparate(t *testing.T) {
	_, udp := nativeObservationOrigins(t)
	port := authorityPort(t)
	p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
	p.bootstrap.Users[0].TrafficPeriod = "native-packet-old"
	s := authorityService(t, p)
	s.lastConfig = p.bootstrap.Config
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	s.updateUserState(p.bootstrap.Users, srcBootstrap)
	if !s.startKernel(s.lastConfig, p.bootstrap.Users) {
		t.Fatal("packet period admission")
	}
	defer s.kernel.Stop()
	control, packet := nativeObservationUDP(t, port)
	nativeObservationPacketEcho(t, packet, udp.LocalAddr(), 13)
	s.trackAndEnforce(t.Context())
	nativeObservationPacketEcho(t, packet, udp.LocalAddr(), 7)
	current := []model.UserSpec{{ID: 7, UUID: liveProtocolUUID, TrafficPeriod: "native-packet-current"}}
	s.applyUserUpdate(t.Context(), current, computeUserHash(current), srcWSFull)
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := control.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("old packet period retained its control transport")
	}
	control.Close()
	packet.Close()
	newControl, newPacket := nativeObservationUDP(t, port)
	nativeObservationPacketEcho(t, newPacket, udp.LocalAddr(), 57)
	newControl.Close()
	newPacket.Close()
	nativeObservationWait(t, func() bool {
		traffic, _, _, _ := s.kernel.GetUserTraffic(t.Context())
		return traffic[7] == [2]int64{57, 57}
	})
	s.trackAndEnforce(t.Context())
	batch := s.prepareReportBatch()
	parts := map[string][2]int64{}
	for _, segment := range batch.Payload.TrafficSegments {
		parts[segment.Period] = [2]int64{segment.Upload, segment.Download}
	}
	if batch.Payload.Traffic[7] != [2]int64{77, 77} || len(parts) != 2 || parts["native-packet-old"] != [2]int64{20, 20} || parts["native-packet-current"] != [2]int64{57, 57} {
		t.Fatal("packet tail was lost, duplicated or reassigned", batch.Payload.Traffic, parts)
	}
}

func TestNativeObservationStorageFailureKeepsActualTrafficAndStopsRetrying(t *testing.T) {
	for _, mode := range []string{"observer_capacity", "observer_unwritable", "event_capacity", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			tcp, _ := nativeObservationOrigins(t)
			port := authorityPort(t)
			p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
			s := authorityService(t, p)
			s.eventOwner = &usagebucket.ProcessOwner{}
			s.cfg.UsageObserver.Enabled = mode != "disabled"
			s.cfg.UsageEventStore.Enabled = mode == "event_capacity"
			s.cfg.UsageObserver.Directory = filepath.Join(t.TempDir(), "observations")
			s.cfg.UsageEventStore.Directory = filepath.Join(t.TempDir(), "events")
			if mode == "observer_capacity" {
				s.cfg.UsageObserver.MaxBytes = 2048
			}
			if mode == "observer_unwritable" {
				blocked := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(blocked, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				s.cfg.UsageObserver.Directory = blocked
			}
			if mode == "event_capacity" {
				s.cfg.UsageEventStore.MaxBytes = 1
			}
			s.initUsageObserver()
			s.initLocalEventConsumer()
			defer s.closeUsageObserver()
			defer s.closeLocalEventConsumer()
			s.lastConfig = p.bootstrap.Config
			s.updateUserState(p.bootstrap.Users, srcBootstrap)
			if !s.startKernel(s.lastConfig, p.bootstrap.Users) {
				t.Fatal("observation storage prevented native admission")
			}
			defer s.kernel.Stop()
			nativeObservationTCPEcho(t, port, 19, tcp.Addr())
			nativeObservationWait(t, func() bool {
				traffic, _, _, _ := s.kernel.GetUserTraffic(t.Context())
				return traffic[7] == [2]int64{19, 19}
			})
			for i := 0; i < 12; i++ {
				s.trackAndEnforce(t.Context())
			}
			switch mode {
			case "observer_capacity":
				if s.usageObserverMetrics()["state"] != "capacity_reached" {
					t.Fatal("observer capacity failure hidden", s.usageObserverMetrics())
				}
				before := len(nativeObserverRecords(t, s.usageObserverDirectory()))
				s.trackAndEnforce(t.Context())
				if len(nativeObserverRecords(t, s.usageObserverDirectory())) != before {
					t.Fatal("failed observer resumed writing")
				}
			case "observer_unwritable":
				if s.usageObserverMetrics()["state"] != "storage_unavailable" {
					t.Fatal("unwritable observer failure hidden")
				}
			case "event_capacity":
				nativeObservationWait(t, func() bool { return s.localEventConsumer().Status().Closed })
				if s.localEventMetrics()["state"] != "stopped" {
					t.Fatal("event storage failure hidden", s.localEventMetrics())
				}
			case "disabled":
				if s.observer != nil || s.localEventConsumer() != nil {
					t.Fatal("disabled observation attached a consumer")
				}
				if _, err := os.Stat(s.cfg.UsageObserver.Directory); !os.IsNotExist(err) {
					t.Fatal("disabled observation performed I/O", err)
				}
			}
			if got := s.prepareReportBatch().Payload.Traffic[7]; got != [2]int64{19, 19} {
				t.Fatal("observation failure changed actual v1 traffic", got)
			}
		})
	}
}

func TestNativeObservationDirectoriesAndProcessOwnerRemainScoped(t *testing.T) {
	p := &authorityTestPlane{bootstrap: authorityBootstrap(authorityPort(t))}
	s := authorityService(t, p)
	s.cfg.UsageEventStore.Enabled = true
	owner := &usagebucket.ProcessOwner{}
	s.eventOwner = owner
	s.initLocalEventConsumer()
	defer s.closeLocalEventConsumer()
	if s.localEventConsumer() == nil {
		t.Fatal("native local consumer was not attached")
	}
	copyConfig := *s.cfg
	copyConfig.InstanceID += "-second"
	second := NewWithControlPlane(&copyConfig, p)
	second.eventOwner = owner
	second.initLocalEventConsumer()
	if second.localEventConsumer() != nil || second.localEventMetrics()["state"] != "LOCAL_PROCESS_OWNER_EXISTS" {
		t.Fatal("second Service took the permanent process assignment")
	}
	if s.localEventDirectory() == second.localEventDirectory() || s.usageObserverDirectory() == second.usageObserverDirectory() {
		t.Fatal("distinct Service identities shared observation directories")
	}
	dir := s.localEventDirectory()
	s.cfg.Panel.Token = "secret-token-never-in-a-path"
	if s.localEventDirectory() != dir || bytes.Contains([]byte(dir), []byte(s.cfg.Panel.Token)) {
		t.Fatal("credential rotation changed local evidence identity")
	}
}
