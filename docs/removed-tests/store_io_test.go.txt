//go:build linux

package usagebucket_test

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/usagebucket"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type storeOnePacket struct {
	N.PacketConn
	destination M.Socksaddr
	remaining   int
}

func (c *storeOnePacket) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	if c.remaining == 0 {
		return M.Socksaddr{}, io.EOF
	}
	c.remaining--
	return c.PacketConn.ReadPacket(b)
}
func (c *storeOnePacket) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	if c.destination.IsValid() {
		destination = c.destination
	}
	return c.PacketConn.WritePacket(b, destination)
}

func TestStoreExplicitConsumerPersistsActualTrackerTCPAndUDPCopy(t *testing.T) {
	tracker, err := singbox.NewConnTrackerWithEventBuckets(usagebucket.Options{Enabled: true, Window: time.Hour, MaxEvents: 128, MaxSealed: 8})
	if err != nil {
		t.Fatal(err)
	}
	tracker.SetUserMap(map[string]int{"fixture": 7})
	metadata := adapter.InboundContext{User: "fixture", Source: M.ParseSocksaddr("127.0.0.1:12345")}
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	_ = local.SetDeadline(time.Now().Add(3 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	tcp := tracker.RoutedConnection(context.Background(), local, metadata, nil, nil)
	defer tcp.Close()
	completed := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("upload")); completed <- err }()
	if _, err := io.ReadFull(tcp, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := io.ReadFull(peer, make([]byte, 4)); completed <- err }()
	if _, err := tcp.Write([]byte("down")); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	open := func() net.PacketConn {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		_ = socket.SetDeadline(time.Now().Add(3 * time.Second))
		return socket
	}
	source, sender, writer, receiver := open(), open(), open(), open()
	reader := &storeOnePacket{PacketConn: bufio.NewPacketConn(source), remaining: 1}
	rawWriter := &storeOnePacket{PacketConn: bufio.NewPacketConn(writer), destination: M.SocksaddrFromNet(receiver.LocalAddr())}
	udp := tracker.RoutedPacketConnection(context.Background(), rawWriter, metadata, nil, nil)
	defer udp.Close()
	if _, err := sender.WriteTo([]byte("packet"), source.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if n, err := bufio.CopyPacket(udp, reader); n != 6 || !errors.Is(err, io.EOF) {
		t.Fatalf("packet copy %d %v", n, err)
	}
	if n, _, err := receiver.ReadFrom(make([]byte, 16)); n != 6 || err != nil {
		t.Fatalf("real delivery %d %v", n, err)
	}
	meter := tracker.EventBuckets()
	if !meter.Cut(usagebucket.ManualFence, true) {
		t.Fatal("seal")
	}
	store, err := usagebucket.OpenStore(filepath.Join(t.TempDir(), "evidence"), usagebucket.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := usagebucket.NewCoordinator(store, usagebucket.CoordinatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer consumer.Close(ctx)
	if err := consumer.Add(meter); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for meter.Status().PersistedBuckets == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if meter.Status().PersistedBuckets != 1 || meter.Status().SealedBuckets != 0 {
		t.Fatal("durable receipt did not release RAM")
	}
	record, err := store.Read(2)
	if err != nil {
		t.Fatal(err)
	}
	if record.Bucket == nil || len(record.Bucket.Events) != 3 || record.Authorizes || !record.RestoreUnknown || !record.TailUnknown {
		t.Fatalf("local evidence %+v", record)
	}
	events := record.Bucket.Events
	if !events[0].HasIOStart || events[0].Path != usagebucket.TCPRead || !events[1].HasIOStart || events[1].Path != usagebucket.TCPWrite {
		t.Fatal("exact direct operation ranges lost")
	}
	if events[2].Path != usagebucket.UDPWriteCallback || events[2].HasIOStart || !events[2].IntervalUnknown || events[2].PhysicalDirection != usagebucket.Download || events[2].LegacyDirection != usagebucket.Upload || !events[2].DirectionMismatch {
		t.Fatal("UDP unknown interval/legacy mapping rewritten")
	}
	traffic, _, _ := tracker.GetUserTraffic()
	if traffic[7] != [2]int64{12, 4} {
		t.Fatalf("v1 changed %v", traffic)
	}
	// A late callback remains bound to the same connection after closing, and
	// appends to the new open bucket without modifying durable sealed evidence.
	_, callbacks := N.UnwrapCountPacketWriter(udp, nil)
	_ = udp.Close()
	callbacks[0](2)
	if !meter.Cut(usagebucket.LifecycleFence, true) {
		t.Fatal("late seal")
	}
	deadline = time.Now().Add(2 * time.Second)
	for meter.Status().PersistedBuckets < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	late, err := store.Read(3)
	if err != nil {
		t.Fatal(err)
	}
	if late.Bucket == nil || len(late.Bucket.Events) != 2 || !late.Bucket.Events[1].LateAfterClose || late.Bucket.Events[1].UserID != 7 || !late.Bucket.Events[1].IntervalUnknown {
		t.Fatal("late binding lost")
	}
	again, _ := store.Read(2)
	if len(again.Bucket.Events) != 3 {
		t.Fatal("late callback reopened durable bucket")
	}
	traffic, _, _ = tracker.GetUserTraffic()
	if traffic[7] != [2]int64{14, 4} {
		t.Fatal("late v1 bytes lost")
	}
}
