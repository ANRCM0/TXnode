package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/tracker"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"
)

func generationEcho(t *testing.T, kind string, port int, uuid string, origin net.Listener, count int) {
	t.Helper()
	raw, client := liveProtocolDial(t, kind, fmt.Sprintf("127.0.0.1:%d", port), uuid, M.ParseSocksaddr(origin.Addr().String()))
	defer raw.Close()
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{'g'}, count)
	if n, e := client.Write(payload); n != len(payload) || e != nil {
		t.Fatal("generation real request", e)
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(client, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatal("generation actual echo", e)
	}
}
func TestRealSingboxReconstructionFirstCumulativeAbovePriorDoesNotLoseBytes(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		t.Run(kind, func(t *testing.T) {
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
			s := authorityService(t, p)
			s.cfg.Kernel.CustomRoute = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{origin.Addr().(*net.TCPAddr).Port}, "outbound": "direct"}}
			s = NewWithControlPlane(s.cfg, p)
			users := p.bootstrap.Users
			s.lastConfig = p.bootstrap.Config
			s.lastConfigHash = computeConfigHash(s.lastConfig)
			s.updateUserState(users, srcBootstrap)
			if !s.startKernel(s.lastConfig, users) {
				t.Fatal("initial native kernel")
			}
			defer s.kernel.Stop()
			generationEcho(t, kind, port, liveProtocolUUID, origin, 13)
			generationTrack(t, s, 7, [2]int64{13, 13})
			first := s.tracker.FlushTraffic()
			if first[7] != [2]int64{13, 13} {
				t.Fatal("first meter", first)
			}
			s.stopUncertainKernel()
			if !s.startKernel(s.lastConfig, users) {
				t.Fatal("same desired reconstruction")
			}
			generationEcho(t, kind, port, liveProtocolUUID, origin, 57)
			generationTrack(t, s, 7, [2]int64{57, 57})
			next := s.tracker.FlushTraffic()
			if next[7] != [2]int64{57, 57} {
				t.Fatal("first rebuilt cumulative above old lost bytes", next)
			}
			s.trackAndEnforce(context.Background())
			if len(s.tracker.FlushTraffic()) != 0 {
				t.Fatal("repeat sample double billed")
			}
			s.applyUserUpdate(context.Background(), []model.UserSpec{{ID: 7, UUID: liveProtocolUUID, SpeedLimit: 8}}, "", srcWSFull)
			generationEcho(t, kind, port, liveProtocolUUID, origin, 7)
			generationTrack(t, s, 7, [2]int64{64, 64})
			if hot := s.tracker.FlushTraffic(); hot[7] != [2]int64{7, 7} {
				t.Fatal("hot users reset cumulative generation", hot)
			}
		})
	}
}

func TestRealXrayPersistentCumulativeRebuildDoesNotDoubleCountOldGeneration(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		t.Run(kind, func(t *testing.T) {
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
			s := authorityService(t, p)
			s.cfg.Kernel.Type = "xray"
			s.cfg.Kernel.CustomRoute = []map[string]any{{"type": "field", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprint(origin.Addr().(*net.TCPAddr).Port), "outboundTag": "direct"}}
			s = NewWithControlPlane(s.cfg, p)
			users := p.bootstrap.Users
			s.lastConfig = p.bootstrap.Config
			s.lastConfigHash = computeConfigHash(s.lastConfig)
			s.updateUserState(users, srcBootstrap)
			if !s.startKernel(s.lastConfig, users) {
				t.Fatal("initial Xray")
			}
			defer s.kernel.Stop()
			generationEcho(t, kind, port, liveProtocolUUID, origin, 13)
			generationTrack(t, s, 7, [2]int64{13, 13})
			if first := s.tracker.FlushTraffic(); first[7] != [2]int64{13, 13} {
				t.Fatal("first actual Xray", first)
			}
			s.stopUncertainKernel()
			if !s.startKernel(s.lastConfig, users) {
				t.Fatal("Xray reconstruction")
			}
			generationEcho(t, kind, port, liveProtocolUUID, origin, 57)
			generationTrack(t, s, 7, [2]int64{70, 70})
			if next := s.tracker.FlushTraffic(); next[7] != [2]int64{57, 57} {
				t.Fatal("persistent Xray baseline reset/double count", next)
			}
			s.trackAndEnforce(context.Background())
			if len(s.tracker.FlushTraffic()) != 0 {
				t.Fatal("repeat Xray sample duplicate")
			}
		})
	}
}

type resetGenerationKernel struct{ *fakeKernel }

func (k *resetGenerationKernel) ResetsCumulativeTrafficOnStart() bool { return true }
func TestFailedFreshProducerStartDoesNotClearBaselineOrPendingBytes(t *testing.T) {
	base := &fakeKernel{startErr: errors.New("synthetic-start-failure")}
	s := snapshotTestService(base)
	s.kernel = &resetGenerationKernel{fakeKernel: base}
	s.tracker = tracker.New()
	s.tracker.Process(map[int][2]int64{7: {13, 17}}, nil, 0)
	if s.startKernel(&model.NodeSpec{Protocol: "vless"}, []model.UserSpec{{ID: 7, UUID: liveProtocolUUID}}) {
		t.Fatal("failed fake start marked success")
	}
	s.tracker.Process(map[int][2]int64{7: {20, 26}}, nil, 0)
	if got := s.tracker.FlushTraffic()[7]; got != [2]int64{20, 26} {
		t.Fatal("failed Start cleared baseline or pending", got)
	}
}

func TestRealSingboxRunningReplacementSamplesOldUnreportedMeterBeforeNewGeneration(t *testing.T) {
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
	first := authorityPort(t)
	second := authorityPort(t)
	for second == first {
		second = authorityPort(t)
	}
	p := &authorityTestPlane{bootstrap: authorityBootstrap(first)}
	s := authorityService(t, p)
	s.cfg.Kernel.CustomRoute = []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{origin.Addr().(*net.TCPAddr).Port}, "outbound": "direct"}}
	s = NewWithControlPlane(s.cfg, p)
	users := p.bootstrap.Users
	s.lastConfig = p.bootstrap.Config
	s.lastConfigHash = computeConfigHash(s.lastConfig)
	s.updateUserState(users, srcBootstrap)
	s.startKernel(s.lastConfig, users)
	defer s.kernel.Stop()
	generationEcho(t, "vless", first, liveProtocolUUID, origin, 13)
	// No ordinary track sample occurs before replacement. Start must retire and
	// collect the old producer itself, instead of discarding these first bytes.
	replacement := *s.lastConfig
	replacement.ServerPort = second
	s.lastConfig = &replacement
	s.lastConfigHash = computeConfigHash(&replacement)
	if !s.startKernel(&replacement, users) {
		t.Fatal("running replacement failed")
	}
	generationEcho(t, "vless", second, liveProtocolUUID, origin, 57)
	generationTrack(t, s, 7, [2]int64{57, 57})
	if got := s.tracker.FlushTraffic()[7]; got != [2]int64{70, 70} {
		t.Fatal("old unsampled traffic lost or new producer subtracted old bytes", got)
	}
	if c, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", first), 50*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("old listener remained open")
	}
}

// A TCP peer can receive Write bytes just before the writer returns and updates
// its cumulative counter. Wait for the exact count-site evidence, not a sleep.
func generationTrack(t *testing.T, s *Service, uid int, expected [2]int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		traffic, _, _, err := s.kernel.GetUserTraffic(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if traffic[uid][0] >= expected[0] && traffic[uid][1] >= expected[1] {
			s.trackAndEnforce(context.Background())
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("actual meter count-site did not observe delivered bytes", traffic, expected)
		}
		time.Sleep(time.Millisecond)
	}
}
