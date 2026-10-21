//go:build linux

package txnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
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
	retired   atomic.Int64
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
	Retired     int64       `json:"expected_retired_tls_disconnects"`
	Bytes       int64       `json:"business_bytes_round_trip"`
	LatencyMS   [3][3]int64 `json:"latency_upper_bound_ms_p50_p95_p99_tcp_udp_mux"`
}

func soakResource(phase int, c *soakCounters, nodes ...*Kernel) soakSample {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	s := soakSample{At: time.Now().UTC(), Phase: phase, Active: c.active.Load(), Retired: c.retired.Load(), Goroutines: runtime.NumGoroutine(), Heap: memory.HeapAlloc, HeapObjects: memory.HeapObjects}
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
	certs := [2]kernel.TLSCert{selfSignedPEM(t), selfSignedPEM(t)}
	roots := x509.NewCertPool()
	for _, cert := range certs {
		if !roots.AppendCertsFromPEM(cert.CertPEM) {
			t.Fatal("invalid soak TLS root")
		}
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	newNode := func(protocol string, secure bool) (*Kernel, *model.NodeSpec) {
		k := New(RuntimeConfig{MaxFresh: 4096, HandshakeTimeout: 10 * time.Second, DrainTimeout: time.Second, UDPTimeout: 3 * time.Second})
		spec := &model.NodeSpec{Protocol: protocol, ListenIP: "127.0.0.1", ServerPort: freePortTB(t), Transport: "tcp"}
		if protocol == "shadowsocks" {
			spec.Cipher = "aes-128-gcm"
		}
		var cert kernel.TLSCert
		if secure {
			spec.TLS = 1
			cert = certs[0]
		}
		if err := k.Start(spec, []model.UserSpec{{ID: 1, UUID: interopUUID}}, cert); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(k.Stop)
		return k, spec
	}
	tcpNode, tcpSpec := newNode("vless", true)
	udpNode, udpSpec := newNode("shadowsocks", false)
	muxNode, muxSpec := newNode("vless", false)
	var stopClients []func()
	client := func(port int, mux bool) string {
		outbound := map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": port, "uuid": interopUUID}
		if mux {
			outbound["multiplex"] = map[string]any{"enabled": true, "protocol": "smux", "max_streams": 32}
		}
		endpoint, stop := startSoakSingBox(t, outbound, dir, "mux")
		stopClients = append(stopClients, stop)
		return endpoint
	}
	udpEndpoint, stopUDPClient := startSoakSingBox(t, map[string]any{"type": "shadowsocks", "server": "127.0.0.1", "server_port": udpSpec.ServerPort, "method": "aes-128-gcm", "password": interopUUID}, dir, "udp")
	stopClients = append(stopClients, stopUDPClient)
	endpoints := [3]string{"direct-verified-TLS-VLESS", udpEndpoint, client(muxSpec.ServerPort, true)}
	var counters soakCounters
	runtime.GC()
	baseline := soakResource(0, &counters, tcpNode, udpNode, muxNode)
	soakDiagnostics(t, dir, "baseline", tcpNode, udpNode, muxNode)
	if err := encoder.Encode(baseline); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	var phases []map[string]any
	totalLifecycleCycles := 0
	defer func() {
		body, _ := json.MarshalIndent(map[string]any{"schema": "txnode-native-soak/v2", "elapsed_seconds": time.Since(started).Seconds(), "duration_required_seconds": 1800, "phases": phases, "accepted": !t.Failed() && len(phases) == 4 && time.Since(started) >= 30*time.Minute, "scope": "verified TLS VLESS TCP, Shadowsocks UDP, smux TCP; credential rotation, revocation, same-port certificate Reload and invalid replacement retention on the load-bearing TLS Node", "load_bearing_lifecycle_cycles": totalLifecycleCycles, "separate_loaded_fault_job": []string{"report-blocking", "slow-disk", "short-write", "rate-cancellation", "signed-lease-refresh-expiry", "SIGKILL-restart"}}, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "soak-summary.json"), body, 0o600)
	}()
	for _, target := range []int{100, 250, 500, 1000} {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		defer func() { cancel(); wg.Wait() }()
		before := soakResource(target, &counters)
		counters.peak.Store(0)
		loaded := &soakLoadedNode{last: make([]atomic.Uint64, (target+2)/3)}
		loaded.generation.Store(1)
		for worker := 0; worker < target; worker++ {
			wg.Add(1)
			go func(kind, index int) {
				defer wg.Done()
				soakWorker(ctx, kind, index, endpoints[kind], echo.Addr().String(), packetEcho, &counters, loaded, func() (net.Conn, error) {
					return nativeFaultVLESSDial(tcpSpec.ServerPort, interopUUID, echo.Addr().String(), tlsConfig)
				})
			}(worker%3, worker/3)
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
				soakLoadedLifecycle(t, tcpNode, tcpSpec, echo.Addr().String(), tlsConfig, certs, loaded, totalLifecycleCycles)
				faults++
				totalLifecycleCycles++
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
		retired := after.Retired - before.Retired
		if faults < 8 || retired != int64(faults*len(loaded.last)) {
			t.Errorf("phase %d missing loaded TLS lifecycle proof: cycles=%d retired=%d required=%d", target, faults, retired, faults*len(loaded.last))
		}
		phases = append(phases, map[string]any{"sessions_required": target, "peak_active": counters.peak.Load(), "elapsed_seconds": time.Since(phaseStart).Seconds(), "completed": after.Completed, "errors": after.Errors, "lifecycle_cycles": faults, "load_bearing_tls_workers": len(loaded.last), "expected_retired_disconnects": retired, "load_bearing_generations_recovered": loaded.generation.Load()})
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
	for _, stop := range stopClients {
		stop()
	}
	time.Sleep(6 * time.Second)
	runtime.GC()
	time.Sleep(time.Second)
	runtime.GC()
	// Go's net splice pool uses asynchronous runtime.AddCleanup for pipe FDs.
	// Keep the original numeric budgets and allow only bounded cleanup latency.
	cleanupDeadline := time.Now().Add(5 * time.Second)
	for {
		fds, _ := os.ReadDir("/proc/self/fd")
		if len(fds) <= baseline.FDs+32 || time.Now().After(cleanupDeadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	final := soakResource(0, &counters)
	soakDiagnostics(t, dir, "final", tcpNode, udpNode, muxNode)
	if err := encoder.Encode(final); err != nil {
		t.Error(err)
	}
	if final.Goroutines > baseline.Goroutines+96 || final.FDs > baseline.FDs+32 || final.Heap > baseline.Heap+(128<<20) || final.HeapObjects > baseline.HeapObjects+100000 {
		t.Errorf("post-GC resources exceeded fixed budgets: baseline=%+v final=%+v", baseline, final)
	}
}

func startSoakSingBox(t *testing.T, outbound map[string]any, artifacts, name string) (string, func()) {
	t.Helper()
	root := t.TempDir()
	port := freePortTB(t)
	config := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{outbound}}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(artifacts, "client-"+name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(singBoxBinary(t), "run", "-c", path, "-D", root)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = command.Process.Kill(); _ = command.Wait(); _ = log.Close() }) }
	t.Cleanup(stop)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			time.Sleep(100 * time.Millisecond)
			return address, stop
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop()
	t.Fatalf("soak client %s readiness missing; see retained client log", name)
	return "", stop
}

func soakDiagnostics(t *testing.T, dir, stage string, nodes ...*Kernel) {
	t.Helper()
	type descriptor struct {
		FD     string `json:"fd"`
		Target string `json:"target"`
	}
	var descriptors []descriptor
	classes := map[string]int{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err != nil {
			continue
		}
		descriptors = append(descriptors, descriptor{fd.Name(), target})
		kind := "file"
		if strings.HasPrefix(target, "socket:") {
			kind = "socket"
		} else if strings.HasPrefix(target, "pipe:") {
			kind = "pipe"
		} else if strings.HasPrefix(target, "anon_inode:") {
			kind = "anon_inode"
		}
		classes[kind]++
	}
	var diagnostics []map[string]any
	for _, node := range nodes {
		diagnostics = append(diagnostics, node.RuntimeDiagnostics())
	}
	body, _ := json.MarshalIndent(map[string]any{"descriptor_classes": classes, "descriptors": descriptors, "nodes": diagnostics}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, stage+"-descriptors.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"heap", "goroutine"} {
		file, err := os.Create(filepath.Join(dir, stage+"-"+profile+".pprof"))
		if err != nil {
			t.Fatal(err)
		}
		if err := pprof.Lookup(profile).WriteTo(file, 0); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%s descriptor classes: %v", stage, classes)
}

func soakWorker(ctx context.Context, kind, index int, proxy, tcp, udp string, c *soakCounters, loaded *soakLoadedNode, direct func() (net.Conn, error)) {
	var generation uint64
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
				if kind == 0 {
					loaded.mu.RLock()
					generation = loaded.generation.Load()
					conn, err = direct()
					loaded.mu.RUnlock()
				} else {
					conn, err = socksNoAuthConnectE(proxy, tcp)
				}
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
				if kind == 0 && generation < loaded.generation.Load() && nativeFaultDisconnected(err) {
					c.retired.Add(1)
				} else {
					c.failed[kind].Add(1)
				}
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
			if kind == 0 {
				loaded.last[index].Store(generation)
			}
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

type soakLoadedNode struct {
	mu         sync.RWMutex
	generation atomic.Uint64
	last       []atomic.Uint64
}

func (s *soakLoadedNode) wait(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for {
		ready := true
		for i := range s.last {
			if s.last[i].Load() < s.generation.Load() {
				ready = false
			}
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("loaded TLS generation %d did not fully recover", s.generation.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func soakLoadedLifecycle(t *testing.T, k *Kernel, spec *model.NodeSpec, dest string, tlsConfig *tls.Config, certs [2]kernel.TLSCert, load *soakLoadedNode, cycle int) {
	t.Helper()
	load.wait(t)
	stable := model.UserSpec{ID: 1, UUID: interopUUID}
	old := model.UserSpec{ID: 7, UUID: "11223344-5566-7788-9900-aabbccddeeff"}
	fresh := model.UserSpec{ID: 7, UUID: "22334455-6677-8899-aabb-ccddeeff0011"}
	if _, err := k.AddUsers([]model.UserSpec{old}); err != nil {
		t.Fatal(err)
	}
	c, err := nativeFaultVLESSDial(spec.ServerPort, old.UUID, dest, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := nativeFaultEcho(c, []byte("tail")); err != nil {
		t.Fatal(err)
	}
	users := []model.UserSpec{stable, fresh}
	if _, _, err := k.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := c.Read(one[:]); !nativeFaultDisconnected(err) {
		t.Fatalf("rotation did not close old TLS stream: %v", err)
	}
	_ = c.Close()
	reject := func(uuid string) {
		t.Helper()
		c, err := nativeFaultVLESSDial(spec.ServerPort, uuid, dest, tlsConfig)
		if err == nil {
			defer c.Close()
			err = nativeFaultEcho(c, []byte("revoked"))
		}
		if err == nil {
			t.Fatal("revoked TLS credential authenticated")
		}
	}
	reject(old.UUID)
	if _, err := k.RemoveUsers([]model.UserSpec{fresh}); err != nil {
		t.Fatal(err)
	}
	reject(fresh.UUID)
	if _, err := k.AddUsers([]model.UserSpec{fresh}); err != nil {
		t.Fatal(err)
	}
	if err := k.Reload(spec, users, kernel.TLSCert{CertPEM: []byte("invalid"), KeyPEM: []byte("invalid")}); err == nil {
		t.Fatal("invalid TLS replacement unexpectedly succeeded")
	}
	cert := certs[(cycle+1)%2]
	load.mu.Lock()
	load.generation.Add(1)
	err = k.Reload(spec, []model.UserSpec{stable}, cert)
	load.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	load.wait(t)
	identity, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(spec.ServerPort)), tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	actual := sha256.Sum256(identity.ConnectionState().PeerCertificates[0].Raw)
	_ = identity.Close()
	pair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	if err != nil || actual != sha256.Sum256(pair.Certificate[0]) {
		t.Fatal("loaded TLS reload retained wrong certificate", err)
	}
	bad := *spec
	bad.Protocol = "unsupported-soak-rollback"
	if err := k.Reload(&bad, []model.UserSpec{stable}, cert); err == nil {
		t.Fatal("invalid replacement unexpectedly succeeded")
	}
	probe, err := nativeFaultVLESSDial(spec.ServerPort, stable.UUID, dest, tlsConfig)
	if err != nil {
		t.Fatal("failed replacement lost loaded TLS listener", err)
	}
	err = nativeFaultEcho(probe, []byte("rollback-preserved"))
	_ = probe.Close()
	if err != nil {
		t.Fatal("failed replacement lost fresh TLS admission", err)
	}
	traffic, _, _, err := k.GetUserTraffic(t.Context())
	if err != nil || traffic[7][0] < 4 || traffic[7][1] < 4 {
		t.Fatalf("revocation tail lost: %v %v", traffic, err)
	}
}
