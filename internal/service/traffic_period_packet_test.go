package service

import (
	"context"
	"github.com/ANRCM0/TX-Node/internal/kernel/singbox"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/tracker"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"testing"
	"time"
)

// Real UDP transport boundary, without claiming a full Hysteria/TUIC/etc auth
// handshake. Both packet directions feed the same cumulative period collector.
func TestObservedPeriodPacketTransportCountersShareBindingAndGeneration(t *testing.T) {
	collected := tracker.New()
	collected.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "old-period"}})
	sample := func(up, down int) *singbox.ConnTracker {
		t.Helper()
		meter := singbox.NewConnTracker(0)
		meter.SetUserMap(map[string]int{"packet-user": 7})
		local, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer local.Close()
		peer, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer peer.Close()
		local.SetDeadline(time.Now().Add(time.Second))
		peer.SetDeadline(time.Now().Add(time.Second))
		packet := meter.RoutedPacketConnection(context.Background(), bufio.NewPacketConn(local), adapter.InboundContext{User: "packet-user", Source: M.SocksaddrFromNet(peer.LocalAddr())}, nil, nil)
		defer packet.Close()
		if _, e := peer.WriteTo(make([]byte, up), local.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		buffer := buf.NewPacket()
		defer buffer.Release()
		if _, e := packet.ReadPacket(buffer); e != nil || buffer.Len() != up {
			t.Fatal("actual UDP read", e)
		}
		if e := packet.WritePacket(buf.As(make([]byte, down)), M.SocksaddrFromNet(peer.LocalAddr())); e != nil {
			t.Fatal("actual UDP write", e)
		}
		received := make([]byte, down+1)
		if n, _, e := peer.ReadFrom(received); e != nil || n != down {
			t.Fatal("actual UDP delivery", n, e)
		}
		traffic, alive, count := meter.GetUserTraffic()
		collected.Process(traffic, alive, count)
		return meter
	}
	old := sample(6, 5)
	traffic, alive, count := old.GetUserTraffic()
	collected.Process(traffic, alive, count)
	collected.BeginCumulativeGeneration()
	collected.BindPeriods([]model.UserSpec{{ID: 7, TrafficPeriod: "current-period"}})
	current := sample(13, 17)
	traffic, alive, count = current.GetUserTraffic()
	collected.Process(traffic, alive, count)
	aggregate, segments := collected.FlushBatch()
	if aggregate[7] != [2]int64{19, 22} || len(segments) != 2 {
		t.Fatal("packet period aggregate invalid", aggregate, segments)
	}
	parts := map[string][2]int64{}
	for _, segment := range segments {
		parts[segment.Period] = [2]int64{segment.Upload, segment.Download}
	}
	if parts["old-period"] != [2]int64{6, 5} || parts["current-period"] != [2]int64{13, 17} {
		t.Fatal("packet writer bypassed observed-period collector", parts)
	}
}
