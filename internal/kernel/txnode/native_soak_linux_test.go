//go:build linux

package txnode

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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

type soakCounters struct {
	completed [3]atomic.Int64
	failed    [3]atomic.Int64
	starved   [3]atomic.Int64
	latency   [3][12]atomic.Int64
	active    atomic.Int64
	peak      atomic.Int64
}

type soakSample struct {
	At          time.Time   `json:"at"`
	Phase       int         `json:"phase"`
	Active      int64       `json:"active"`
	Connections int         `json:"connections"`
	Goroutines  int         `json:"goroutines"`
	FDs         int         `json:"fds"`
	Heap        uint64      `json:"heap_bytes"`
	HeapObjects uint64      `json:"heap_objects"`
	RSS         uint64      `json:"rss_bytes"`
	Completed   [3]int64    `json:"completed_tcp_udp_mux"`
	Errors      [3]int64    `json:"errors_tcp_udp_mux"`
	Starved     [3]int64    `json:"under_completed_workers_tcp_udp_mux"`
	Bytes       int64       `json:"business_bytes_round_trip"`
	LatencyMS   [3][3]int64 `json:"latency_upper_bound_ms_p50_p95_p99_tcp_udp_mux"`
}

func soakResource(phase int, c *soakCounters, nodes ...*Kernel) soakSample {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	s := soakSample{At: time.Now().UTC(), Phase: phase, Active: c.active.Load(), Goroutines: runtime.NumGoroutine(), Heap: memory.HeapAlloc, HeapObjects: memory.HeapObjects}
	fds, _ := os.ReadDir("/proc/self/fd")
	s.FDs = len(fds)
	if body, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(body))
		if len(fields) > 1 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			s.RSS = pages * uint64(os.Getpagesize())
		}
	}
	for _, k := range nodes {
		_, _, count, _ := k.GetUserTraffic(context.Background())
		s.Connections += count
	}
	for i := range s.Completed {
		s.Completed[i] = c.completed[i].Load()
		s.Errors[i] = c.failed[i].Load()
		s.Starved[i] = c.starved[i].Load()
		s.Bytes += s.Completed[i] * 2048
		for percentile, p := range []int64{50, 95, 99} {
			threshold := (s.Completed[i]*p + 99) / 100
			var total int64
			for bucket := 0; bucket < 12; bucket++ {
				total += c.latency[i][bucket].Load()
				if total >= threshold && threshold > 0 {
					s.LatencyMS[i][percentile] = int64(1) << bucket
					if bucket == 11 {
						s.LatencyMS[i][percentile] = -1
					}
					break
				}
			}
		}
	}
	return s
}

// TestNativeSessionSoak is deliberately opt-in: normal tests cannot substitute
// a shortened run for the 30 minute acceptance profile.
func TestNativeSessionSoak(t *testing.T) {
	if os.Getenv("TXNODE_NATIVE_SOAK") != "1" {
		t.Skip("30 minute native acceptance is enabled only by the dedicated Actions job")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("native load acceptance requires GitHub Actions")
	}
	if os.Getenv("TXNODE_INTEROP_SINGBOX") == "" {
		t.Fatal("required pinned sing-box client is absent")
	}
	dir := os.Getenv("TXNODE_NATIVE_ARTIFACTS")
	if dir == "" {
		t.Fatal("TXNODE_NATIVE_ARTIFACTS is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(dir, "soak-samples.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	packetEcho := udpEcho(t)
	newNode := func(protocol string) (*Kernel, *model.NodeSpec) {
		k := New(RuntimeConfig{MaxFresh: 4096, HandshakeTimeout: 10 * time.Second, DrainTimeout: time.Second, UDPTimeout: 3 * time.Second})
		spec := &model.NodeSpec{Protocol: protocol, ListenIP: "127.0.0.1", ServerPort: freePortTB(t), Transport: "tcp"}
		if protocol == "shadowsocks" {
			spec.Cipher = "aes-128-gcm"
		}
		if err := k.Start(spec, []model.UserSpec{{ID: 1, UUID: interopUUID}}, kernel.TLSCert{}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(k.Stop)
		return k, spec
	}
	tcpNode, tcpSpec := newNode("vless")
	udpNode, udpSpec := newNode("shadowsocks")
	muxNode, muxSpec := newNode("vless")
	client := func(port int, mux bool) string {
		outbound := map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": port, "uuid": interopUUID}
		if mux {
			outbound["multiplex"] = map[string]any{"enabled": true, "protocol": "smux", "max_streams": 32}
		}
		return startSingBoxClient(t, outbound)
	}
	endpoints := [3]string{client(tcpSpec.ServerPort, false), startSingBoxClient(t, map[string]any{"type": "shadowsocks", "server": "127.0.0.1", "server_port": udpSpec.ServerPort, "method": "aes-128-gcm", "password": interopUUID}), client(muxSpec.ServerPort, true)}
	var counters soakCounters
	runtime.GC()
	baseline := soakResource(0, &counters, tcpNode, udpNode, muxNode)
	if err := encoder.Encode(baseline); err != nil {
		t.Fatal(err)
	}
	// Credential fault traffic is a separate Node instance: its revocation must
	// neither interrupt the stable users nor cross instance ownership.
	fault := New(RuntimeConfig{MaxFresh: 64, DrainTimeout: time.Second, HandshakeTimeout: time.Second})
	faultSpec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePortTB(t)}
	if err := fault.Start(faultSpec, []model.UserSpec{{ID: 7, UUID: "initial"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer fault.Stop()
	started := time.Now()
	var phases []map[string]any
	defer func() {
		body, _ := json.MarshalIndent(map[string]any{"schema": "txnode-native-soak/v1", "elapsed_seconds": time.Since(started).Seconds(), "duration_required_seconds": 1800, "phases": phases, "accepted": !t.Failed() && len(phases) == 4 && time.Since(started) >= 30*time.Minute, "full_S3_accepted": false, "scope": "VLESS TCP, Shadowsocks UDP, smux TCP; independent SOCKS lifecycle faults", "unimplemented_faults": []string{"report-blocking", "slow-disk", "short-write", "certificate-refresh", "usage-v2-lease-refresh", "process-restart-during-load", "load-bearing-node-reload", "persistent-queue-depth"}}, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "soak-summary.json"), body, 0o600)
	}()
	for _, target := range []int{100, 250, 500, 1000} {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		defer func() { cancel(); wg.Wait() }()
		before := soakResource(target, &counters)
		counters.peak.Store(0)
		for worker := 0; worker < target; worker++ {
			wg.Add(1)
			go func(kind int) {
				defer wg.Done()
				soakWorker(ctx, kind, endpoints[kind], echo.Addr().String(), packetEcho, &counters)
			}(worker % 3)
		}
		phaseStart := time.Now()
		ticker := time.NewTicker(5 * time.Second)
		faultTick := time.NewTicker(45 * time.Second)
		phaseEnd := time.NewTimer(450 * time.Second)
		faults := 0
	loop:
		for {
			select {
			case <-phaseEnd.C:
				break loop
			case <-ticker.C:
				if err := encoder.Encode(soakResource(target, &counters, tcpNode, udpNode, muxNode)); err != nil {
					t.Error(err)
					break loop
				}
			case <-faultTick.C:
				soakLifecycle(t, fault, faultSpec, echo.Addr().String(), faults)
				faults++
				// Stable workers also prove that lifecycle mutations remain scoped
				// to the independently owned Node instance.
			}
		}
		cancel()
		ticker.Stop()
		faultTick.Stop()
		phaseEnd.Stop()
		wg.Wait()
		after := soakResource(target, &counters, tcpNode, udpNode, muxNode)
		for kind := range before.Completed {
			if after.Completed[kind]-before.Completed[kind] < int64(target/3)*100 {
				t.Errorf("phase %d kind %d under-completed: %d", target, kind, after.Completed[kind]-before.Completed[kind])
			}
			if after.Errors[kind] != before.Errors[kind] {
				t.Errorf("phase %d kind %d I/O errors: %d", target, kind, after.Errors[kind]-before.Errors[kind])
			}
			if after.Starved[kind] != before.Starved[kind] {
				t.Errorf("phase %d kind %d contains under-completed workers", target, kind)
			}
		}
		if counters.peak.Load() < int64(target) {
			t.Errorf("phase %d capacity incomplete: peak=%d", target, counters.peak.Load())
		}
		phases = append(phases, map[string]any{"sessions_required": target, "peak_active": counters.peak.Load(), "elapsed_seconds": time.Since(phaseStart).Seconds(), "completed": after.Completed, "errors": after.Errors, "lifecycle_cycles": faults})
		t.Logf("phase %d complete: %+v", target, after)
	}
	if time.Since(started) < 30*time.Minute {
		t.Error("30 minute load window incomplete")
	}
	// Close every listener and collect twice after UDP idle expiry before applying
	// fixed resource budgets, rather than comparing peak allocations with idle.
	tcpNode.Stop()
	udpNode.Stop()
	muxNode.Stop()
	fault.Stop()
	time.Sleep(6 * time.Second)
	runtime.GC()
	time.Sleep(time.Second)
	runtime.GC()
	final := soakResource(0, &counters)
	if err := encoder.Encode(final); err != nil {
		t.Error(err)
	}
	if final.Goroutines > baseline.Goroutines+96 || final.FDs > baseline.FDs+32 || final.Heap > baseline.Heap+(128<<20) || final.HeapObjects > baseline.HeapObjects+100000 {
		t.Errorf("post-GC resources exceeded fixed budgets: baseline=%+v final=%+v", baseline, final)
	}
}

func soakWorker(ctx context.Context, kind int, proxy, tcp, udp string, c *soakCounters) {
	payload := bytes.Repeat([]byte{0x37}, 1024)
	var conn net.Conn
	var packet *soakPacket
	var successes int64
	defer func() {
		if successes < 100 {
			c.starved[kind].Add(1)
		}
		if conn != nil {
			_ = conn.Close()
			c.active.Add(-1)
		}
		if packet != nil {
			packet.Close()
			c.active.Add(-1)
		}
	}()
	for ctx.Err() == nil {
		started := time.Now()
		var err error
		if kind == 1 {
			if packet == nil {
				packet, err = newSoakPacket(proxy, udp)
				if err == nil {
					n := c.active.Add(1)
					for n > c.peak.Load() {
						old := c.peak.Load()
						if n <= old || c.peak.CompareAndSwap(old, n) {
							break
						}
					}
				}
			}
			var got []byte
			if err == nil {
				got, err = packet.Exchange(payload)
			}
			if err == nil && !bytes.Equal(got, payload) {
				err = fmt.Errorf("UDP payload mismatch")
			}
		} else {
			if conn == nil {
				conn, err = socksNoAuthConnectE(proxy, tcp)
				if err == nil {
					n := c.active.Add(1)
					for n > c.peak.Load() {
						old := c.peak.Load()
						if n <= old || c.peak.CompareAndSwap(old, n) {
							break
						}
					}
				}
			}
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				_, err = conn.Write(payload)
				if err == nil {
					got := make([]byte, len(payload))
					_, err = io.ReadFull(conn, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = fmt.Errorf("TCP payload mismatch")
					}
				}
			}
		}
		if err != nil {
			if ctx.Err() == nil {
				c.failed[kind].Add(1)
			}
			if conn != nil {
				_ = conn.Close()
				conn = nil
				c.active.Add(-1)
			}
			if packet != nil {
				packet.Close()
				packet = nil
				c.active.Add(-1)
			}
		} else {
			c.completed[kind].Add(1)
			successes++
			elapsed := time.Since(started).Milliseconds()
			bucket := 0
			for bucket < 11 && elapsed > (int64(1)<<bucket) {
				bucket++
			}
			c.latency[kind][bucket].Add(1)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

type soakPacket struct {
	control, data net.Conn
	header        []byte
}

func (p *soakPacket) Close() { _ = p.control.Close(); _ = p.data.Close() }
func newSoakPacket(proxy, dest string) (*soakPacket, error) {
	ctl, err := net.DialTimeout("tcp", proxy, 8*time.Second)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = ctl.Close()
		}
	}()
	_ = ctl.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = ctl.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var method [2]byte
	if _, err = io.ReadFull(ctl, method[:]); err != nil || method != [2]byte{5, 0} {
		return nil, fmt.Errorf("UDP method: %v %v", method, err)
	}
	if _, err = ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var head [4]byte
	if _, err = io.ReadFull(ctl, head[:]); err != nil || head[1] != 0 {
		return nil, fmt.Errorf("UDP associate: %v %v", head, err)
	}
	var host string
	var port uint16
	switch head[3] {
	case 1:
		var b [6]byte
		if _, err = io.ReadFull(ctl, b[:]); err != nil {
			return nil, err
		}
		host = net.IP(b[:4]).String()
		port = binary.BigEndian.Uint16(b[4:])
	case 4:
		var b [18]byte
		if _, err = io.ReadFull(ctl, b[:]); err != nil {
			return nil, err
		}
		host = net.IP(b[:16]).String()
		port = binary.BigEndian.Uint16(b[16:])
	default:
		return nil, fmt.Errorf("unsupported relay address %d", head[3])
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	data, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(int(port))), 8*time.Second)
	if err != nil {
		return nil, err
	}
	destHost, destPort, err := net.SplitHostPort(dest)
	if err != nil {
		_ = data.Close()
		return nil, err
	}
	ip := net.ParseIP(destHost).To4()
	if ip == nil {
		_ = data.Close()
		return nil, fmt.Errorf("IPv4 target required")
	}
	n, _ := strconv.Atoi(destPort)
	header := append([]byte{0, 0, 0, 1}, ip...)
	header = binary.BigEndian.AppendUint16(header, uint16(n))
	_ = ctl.SetDeadline(time.Time{})
	ok = true
	return &soakPacket{control: ctl, data: data, header: header}, nil
}
func (p *soakPacket) Exchange(payload []byte) ([]byte, error) {
	_ = p.data.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := p.data.Write(append(append([]byte(nil), p.header...), payload...)); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := p.data.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 10 || buf[2] != 0 || buf[3] != 1 {
		return nil, fmt.Errorf("malformed UDP response length=%d", n)
	}
	return buf[10:n], nil
}

func soakLifecycle(t *testing.T, k *Kernel, spec *model.NodeSpec, dest string, cycle int) {
	t.Helper()
	old := fmt.Sprintf("cycle-%d", cycle)
	users := []model.UserSpec{{ID: 7, UUID: old}}
	if _, _, err := k.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	if _, err := k.AddUsers([]model.UserSpec{{ID: 8, UUID: "ephemeral"}}); err != nil {
		t.Fatal(err)
	}
	c := socksConnectTB(t, spec.ServerPort, old, dest)
	if _, err := c.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	users[0].UUID = old + "-rotated"
	if _, _, err := k.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := c.Read(one[:]); err == nil {
		t.Error("old authenticated session survived rotation")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Error("revocation did not close old session")
	}
	_ = c.Close()
	if socksCredentialAccepted(t, spec.ServerPort, old) {
		t.Fatal("old credential revived")
	}
	if _, err := k.RemoveUsers(users); err != nil {
		t.Fatal(err)
	}
	if socksCredentialAccepted(t, spec.ServerPort, users[0].UUID) {
		t.Fatal("removed credential accepted")
	}
	if _, err := k.AddUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := k.Reload(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	bad := *spec
	bad.Protocol = "unsupported-soak-rollback"
	if err := k.Reload(&bad, users, kernel.TLSCert{}); err == nil {
		t.Fatal("invalid replacement unexpectedly succeeded")
	}
	if !socksCredentialAccepted(t, spec.ServerPort, users[0].UUID) {
		t.Fatal("failed replacement lost previous listener")
	}
	traffic, _, _, err := k.GetUserTraffic(t.Context())
	if err != nil || traffic[7][0] < 4 || traffic[7][1] < 4 {
		t.Fatalf("revocation tail lost: %v %v", traffic, err)
	}
}
