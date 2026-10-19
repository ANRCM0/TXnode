package service

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/reporting"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"
)

func TestRealObservedPeriodRebuildKeepsUnsampledOldTailAndFreshBytesSeparate(t *testing.T) {
	for _, kernelType := range []string{"singbox", "xray"} {
		for _, kind := range []string{"vless", "vmess"} {
			t.Run(kernelType+"/"+kind, func(t *testing.T) {
				origin, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer origin.Close()
				go func() {
					for {
						c, e := origin.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
					}
				}()
				port := authorityPort(t)
				p := &authorityTestPlane{bootstrap: authorityBootstrap(port)}
				p.bootstrap.Config.Protocol = kind
				p.bootstrap.Users[0].TrafficPeriod = "opaque-observed-old"
				s := authorityService(t, p)
				s.cfg.Kernel.Type = kernelType
				if kernelType == "singbox" {
					s.cfg.Kernel.CustomRoute = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{origin.Addr().(*net.TCPAddr).Port}, "outbound": "direct"}}
				} else {
					s.cfg.Kernel.CustomRoute = []map[string]any{{"type": "field", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprint(origin.Addr().(*net.TCPAddr).Port), "outboundTag": "direct"}}
				}
				s = NewWithControlPlane(s.cfg, p)
				s.lastConfig = p.bootstrap.Config
				s.lastConfigHash = computeConfigHash(s.lastConfig)
				s.updateUserState(p.bootstrap.Users, srcBootstrap)
				if !s.startKernel(s.lastConfig, p.bootstrap.Users) {
					t.Fatal("period original admission")
				}
				defer s.kernel.Stop()
				raw, client := liveProtocolDial(t, kind, fmt.Sprintf("127.0.0.1:%d", port), liveProtocolUUID, M.ParseSocksaddr(origin.Addr().String()))
				defer raw.Close()
				defer client.Close()
				client.SetDeadline(time.Now().Add(15 * time.Second))
				echo := func(n int) {
					t.Helper()
					payload := bytes.Repeat([]byte{'p'}, n)
					if _, e := client.Write(payload); e != nil {
						t.Fatal(e)
					}
					got := make([]byte, n)
					if _, e := io.ReadFull(client, got); e != nil || !bytes.Equal(got, payload) {
						t.Fatal("real old-period response", e)
					}
				}
				echo(13)
				s.trackAndEnforce(context.Background())
				echo(7) // old bytes not yet sampled at reset
				current := []model.UserSpec{{ID: 7, UUID: liveProtocolUUID, TrafficPeriod: "opaque-observed-current"}}
				s.applyUserUpdate(context.Background(), current, computeUserHash(current), srcWSFull)
				if !s.kernel.IsRunning() || s.appliedUserHash != computeUserHash(current) {
					t.Fatal("new observed period not rebuilt")
				}
				client.SetReadDeadline(time.Now().Add(time.Second))
				var one [1]byte
				if n, e := client.Read(one[:]); n != 0 || e == nil {
					t.Fatal("old-period connection survives new admission")
				}
				generationEcho(t, kind, port, liveProtocolUUID, origin, 57)
				s.trackAndEnforce(context.Background())
				batch := s.prepareReportBatch()
				if batch.Payload.Traffic[7] != [2]int64{77, 77} || len(batch.Payload.TrafficSegments) != 2 {
					t.Fatal("old late bytes lost or relabelled", batch.Payload.Traffic, batch.Payload.TrafficSegments)
				}
				parts := map[string][2]int64{}
				for _, segment := range batch.Payload.TrafficSegments {
					parts[segment.Period] = [2]int64{segment.Upload, segment.Download}
				}
				if parts["opaque-observed-old"] != [2]int64{20, 20} || parts["opaque-observed-current"] != [2]int64{57, 57} {
					t.Fatal("period delta attribution wrong", parts)
				}
				s.tracker.RestoreBatch(batch.Payload.Traffic, batch.Payload.TrafficSegments)
				// A queued period-aware report and later snapshot cannot replace its labels.
				p.mu.Lock()
				p.reportErr = nil
				p.mu.Unlock()
				if e := s.reporter.PushSync(s.prepareReportBatch); e != nil {
					t.Fatal(e)
				}
				p.mu.Lock()
				if len(p.reports) != 1 || len(p.reports[0].TrafficSegments) != 2 {
					p.mu.Unlock()
					t.Fatal("segment reporting lost")
				}
				p.mu.Unlock()
			})
		}
	}
}
func TestPeriodAwareReportSpoolKeepsOldBodyAcrossCurrentBindingAndLostAck(t *testing.T) {

	// Reporting Controller serialization is tested with an actual durable spool.
	plane := &authorityTestPlane{reportErr: fmt.Errorf("lost ack")}
	path := t.TempDir() + "/period-pending.json"
	r, e := reporting.NewDurable(plane, path)
	if e != nil {
		t.Fatal(e)
	}
	old := []model.TrafficSegment{{UserID: 7, Period: "opaque-old", Upload: 13, Download: 17}}
	batch := reporting.Batch{}
	batch.Payload.Traffic = map[int][2]int64{7: {13, 17}}
	batch.Payload.TrafficSegments = old
	if e := r.PushSync(func() reporting.Batch { return batch }); e == nil {
		t.Fatal("lost ack accepted")
	}
	plane.mu.Lock()
	plane.reportErr = nil
	original := plane.reports[0]
	plane.mu.Unlock()
	fresh, e := reporting.NewDurable(plane, path)
	if e != nil {
		t.Fatal(e)
	}
	if e := fresh.ReplayRecovery(); e != nil {
		t.Fatal(e)
	}
	plane.mu.Lock()
	defer plane.mu.Unlock()
	if len(plane.reports) != 2 || plane.reports[1].BatchID != original.BatchID || plane.reports[1].TrafficSegments[0] != old[0] {
		t.Fatal("lostAck replay relabelled old period")
	}
}
