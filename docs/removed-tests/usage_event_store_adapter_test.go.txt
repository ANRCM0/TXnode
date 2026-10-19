//go:build linux

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/kernellifecycle"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Service.Run and the production ConnTracker are exercised without a proxy
// listener. This harness supplies the optional lifecycle attachment capability.
type localRuntimeKernel struct {
	observedMeterKernel
	consumer *usagebucket.Coordinator
	users    []model.UserSpec
}

func (k *localRuntimeKernel) SetLocalEventConsumer(c *usagebucket.Coordinator) bool {
	if k.consumer != nil {
		return false
	}
	k.consumer = c
	return true
}

func (k *localRuntimeKernel) Start(spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	tracker, err := singbox.NewConnTrackerWithEventBuckets(usagebucket.Options{Enabled: true, Window: time.Second, MaxEvents: 128, MaxSealed: 8})
	if err != nil {
		return err
	}
	if err := k.consumer.Add(tracker.EventBuckets()); err != nil {
		tracker = singbox.NewConnTracker(0)
	}
	k.meter = tracker
	k.users = users
	mapping := make(map[string]int)
	for _, user := range users {
		mapping[user.UUID] = user.ID
	}
	k.meter.SetUserMap(mapping)
	return k.observedMeterKernel.Start(spec, users, tls)
}

func (k *localRuntimeKernel) Stop() {
	for _, user := range k.users {
		k.meter.CloseByUUID(user.UUID)
	}
	k.fakeKernel.Stop()
	if k.consumer != nil {
		k.consumer.Retire(k.meter.EventBuckets())
	}
}

func eventRuntimeConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{InstanceID: "local-events-run", Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, DeviceReportInterval: 60, PushInterval: 60, PullInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}, UsageEventStore: config.UsageEventStoreConfig{Enabled: true}, Standalone: &config.StandaloneConfig{Enabled: true, Node: config.StandaloneNodeConfig{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 23456}, Users: []config.StandaloneUser{{ID: 7, UUID: "00112233-4455-6677-8899-aabbccddeeff"}}}}
}

func waitEventRuntime(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("local runtime condition timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type localEventPacketReader struct {
	N.PacketConn
	read bool
}

func (r *localEventPacketReader) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	if r.read {
		return M.Socksaddr{}, io.EOF
	}
	r.read = true
	_, _ = b.Write([]byte("packet"))
	return M.Socksaddr{}, nil
}

type localEventPacketWriter struct {
	N.PacketConn
	destination M.Socksaddr
}

func (w *localEventPacketWriter) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	return w.PacketConn.WritePacket(b, w.destination)
}

func localEventUDPCopy(t *testing.T, tracker *singbox.ConnTracker, uuid string) N.PacketConn {
	t.Helper()
	open := func() net.PacketConn {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		return conn
	}
	writer, receiver := open(), open()
	wrapped := tracker.RoutedPacketConnection(context.Background(), &localEventPacketWriter{PacketConn: bufio.NewPacketConn(writer), destination: M.SocksaddrFromNet(receiver.LocalAddr())}, adapter.InboundContext{User: uuid, Source: M.ParseSocksaddr("127.0.0.1:12345")}, nil, nil)
	t.Cleanup(func() { _ = wrapped.Close() })
	if n, err := bufio.CopyPacket(wrapped, &localEventPacketReader{}); n != 6 || !errors.Is(err, io.EOF) {
		t.Fatalf("actual sing packet copy %d %v", n, err)
	}
	if n, _, err := receiver.ReadFrom(make([]byte, 16)); n != 6 || err != nil {
		t.Fatalf("actual UDP delivery %d %v", n, err)
	}
	return wrapped
}

func TestServiceRunLocalEventConsumerPersistsActualTCPUDPAndLeavesV1Counters(t *testing.T) {
	cfg := eventRuntimeConfig(t)
	s := NewWithControlPlane(cfg, controlplane.NewLocalControlPlane(cfg))
	s.eventOwner = &usagebucket.ProcessOwner{}
	k := &localRuntimeKernel{observedMeterKernel: observedMeterKernel{started: make(chan struct{})}}
	s.kernel, s.kernelLife = k, kernellifecycle.New(k)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	completed := false
	t.Cleanup(func() {
		cancel()
		if !completed {
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Error("Service.Run did not terminate")
			}
		}
	})
	select {
	case <-k.started:
	case err := <-done:
		completed = true
		t.Fatalf("runtime startup failed: %v", err)
	case <-time.After(4 * time.Second):
		t.Fatal("runtime startup timed out")
	}
	tcp := pipeTraffic(t, &k.observedMeterKernel, cfg.Standalone.Users[0].UUID, "upload", "down")
	udp := localEventUDPCopy(t, k.meter, cfg.Standalone.Users[0].UUID)
	c := s.localEventConsumer()
	waitEventRuntime(t, func() bool {
		store, ready := c.StoreSnapshot()
		return ready && store.Buckets > 0 && s.tracker.HasTraffic()
	})
	_ = tcp.Close()
	_ = udp.Close()
	cancel()
	select {
	case err := <-done:
		completed = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("runtime shutdown timed out")
	}
	if pending := s.tracker.FlushTraffic(); pending[7] != [2]int64{12, 4} {
		// Original upload=6 plus the unchanged legacy UDP writer upload=6.
		t.Fatalf("local observer consumed v1 traffic: %+v", pending)
	}
	if k.reads != 1 {
		t.Fatalf("event consumer added cumulative polls: %d", k.reads)
	}
	store, _ := c.StoreSnapshot()
	var physical, legacy [2]int64
	var directTCP, callbackUDP bool
	for seq := uint64(1); seq <= store.Sequence; seq++ {
		r, err := c.ReadRecord(seq)
		if err != nil || r.Authorizes || !r.TailUnknown || r.Attribution != "unattributable" {
			t.Fatalf("local-only record: %+v %v", r, err)
		}
		if r.Bucket == nil {
			continue
		}
		for i := range physical {
			physical[i] += r.Bucket.PhysicalTotals[i]
			legacy[i] += r.Bucket.LegacyTotals[i]
		}
		for _, event := range r.Bucket.Events {
			if event.Path == usagebucket.TCPRead && event.HasIOStart && event.RawCount == 6 {
				directTCP = true
			}
			if event.Path == usagebucket.UDPWriteCallback && event.IntervalUnknown && !event.HasIOStart && event.PhysicalDirection == usagebucket.Download && event.LegacyDirection == usagebucket.Upload && event.RawCount == 6 {
				callbackUDP = true
			}
		}
	}
	if physical != [2]int64{6, 10} || legacy != [2]int64{12, 4} || !directTCP || !callbackUDP || !c.Status().Closed || c.Status().Meters != 0 {
		t.Fatalf("actual runtime evidence %v %v TCP=%v UDP=%v state=%+v", physical, legacy, directTCP, callbackUDP, c.Status())
	}
	end, _ := c.ReadRecord(store.Sequence)
	if end.Kind != "PROCESS_END" || !end.TailUnknown {
		t.Fatal("shutdown inferred complete tail")
	}
}

func TestServiceLocalEventLifetimeGateDisabledUnsupportedAndFailurePreserveV1(t *testing.T) {
	owner := &usagebucket.ProcessOwner{}
	first := &Service{cfg: eventRuntimeConfig(t), kernel: singbox.New(config.KernelConfig{}), eventOwner: owner}
	first.cfg.UsageEventStore.Enabled = false
	first.initLocalEventConsumer()
	if first.eventConsumer != nil || first.eventConsumerState != "" {
		t.Fatal("disabled runtime created consumer")
	}
	unsupported := &Service{cfg: eventRuntimeConfig(t), kernel: &fakeKernel{}, eventOwner: owner}
	unsupported.initLocalEventConsumer()
	if unsupported.eventConsumerState != "UNSUPPORTED_KERNEL" || unsupported.eventConsumer != nil {
		t.Fatal("unsupported runtime consumed process ownership")
	}
	first.cfg.UsageEventStore.Enabled = true
	first.cfg.UsageEventStore.MaxBytes = 1
	first.initLocalEventConsumer()
	waitEventRuntime(t, func() bool { return first.eventConsumer.Status().Closed })
	if first.localEventMetrics()["state"] != "stopped" {
		t.Fatal("open failure was hidden")
	}
	second := &Service{cfg: eventRuntimeConfig(t), kernel: singbox.New(config.KernelConfig{}), eventOwner: owner}
	second.initLocalEventConsumer()
	if second.eventConsumerState != "LOCAL_PROCESS_OWNER_EXISTS" || second.eventConsumer != nil {
		t.Fatal("failed/closed owner permitted replacement worker")
	}
	if strings.Contains(first.localEventDirectory(), "fixture") || first.localEventDirectory() == second.localEventDirectory() {
		t.Fatal("directory namespace not independent")
	}
}
