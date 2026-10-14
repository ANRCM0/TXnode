package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type revocationFlow struct {
	raw        *net.TCPConn
	client     net.Conn
	originDone chan error
	extra      atomic.Int64
	request    []byte
	response   []byte
}

// The kernel, native controlplane, tickers and collector are production-owned.
// Files are lifecycle barriers only; none provides raw counters or fake grants.
func TestServiceUsageV2LiveRevocation(t *testing.T) {
	dir := os.Getenv("TXBOARD_LIVE_REVOCATION_DIR")
	if dir == "" {
		t.Skip("requires exclusive live revocation Core fixture")
	}
	var fixture liveProtocolFixture
	liveProtocolDecode(t, filepath.Join(dir, "fixture.json"), &fixture)
	id, err := strconv.Atoi(fixture.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	caseName := os.Getenv("TXBOARD_LIVE_REVOCATION_CASE")
	routes := []map[string]any{{"network": "tcp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{fixture.OriginPort}, "outbound": "direct"}}
	if caseName == "udp" || caseName == "xudp" {
		routes = append(routes, map[string]any{"network": "udp", "ip_cidr": []string{"127.0.0.1/32"}, "port": []int{fixture.OriginPort}, "outbound": "direct"})
	}
	cfg := &config.Config{InstanceID: "live-revocation-" + fixture.Protocol, Panel: config.PanelConfig{Provider: "txboard", URL: os.Getenv("TXBOARD_LIVE_REVOCATION_ENDPOINT"), NodeID: id, Token: "live-revocation-local-test-only"}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: filepath.Join(dir, "kernel"), LogLevel: "error", CustomRoute: routes}, Cert: config.CertConfig{CertMode: "none"}, Node: config.NodeConfig{TrackInterval: 1, PushInterval: 5, PullInterval: 1, DeviceReportInterval: 60}, WS: config.WSConfig{DiscoveryInterval: 60}, UsageV2: config.UsageV2Config{Enabled: true, IsolatedCopy: true, Directory: filepath.Join(dir, "mode"), CAFile: filepath.Join(dir, "cert.pem")}}
	if err := os.MkdirAll(cfg.Kernel.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	phase := os.Getenv("TXBOARD_LIVE_REVOCATION_PHASE")
	origin, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: fixture.OriginPort})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	var udpOrigin *net.UDPConn
	if caseName == "udp" || caseName == "xudp" {
		udpOrigin, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: fixture.OriginPort})
		if err != nil {
			t.Fatal(err)
		}
		defer udpOrigin.Close()
	}
	svc, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- svc.Run(ctx) }()
	liveProtocolWait(t, done, 12*time.Second, svc.kernel.IsRunning)
	liveProtocolCheckListener(t, fixture.NodePort)
	var expiry time.Time
	var startupLease time.Duration
	if caseName == "expiry" && phase == "expiry" {
		if svc.usageV2 == nil {
			t.Fatal("finite lease phase did not start bounded usage")
		}
		expiry = svc.usageV2.expires
		startupLease = time.Until(expiry)
		if startupLease <= time.Second || startupLease > 4*time.Second {
			t.Fatal("fixture timing exhausted the Core-issued lease during startup", startupLease)
		}
	}
	nodeAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.NodePort))
	dest := M.ParseSocksaddr(net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))
	if phase == "history" {
		flow := revocationExchange(t, origin, fixture.Protocol, nodeAddr, dest, 43, 79)
		if err := flow.raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		var eof [1]byte
		if n, e := flow.client.Read(eof[:]); n != 0 || e != io.EOF {
			t.Fatal("history real protocol EOF", n, e)
		}
		if err := <-flow.originDone; err != nil {
			t.Fatal(err)
		}
		flow.client.Close()
		flow.raw.Close()
		var record usagev2.Record
		liveProtocolWait(t, done, 8*time.Second, func() bool { return revocationRecord(cfg.UsageV2.Directory, &record) && record.Receipt != nil })
		entry := record.Submission.Payload.Entries[0]
		if entry.RawUpBytes != "43" || entry.RawDownBytes != "79" {
			t.Fatal("real history directions changed")
		}
		var heartbeat json.RawMessage
		liveProtocolWait(t, done, 8*time.Second, func() bool { heartbeat = liveProtocolHeartbeat(t, dir, started); return len(heartbeat) > 0 })
		capture := liveProtocolCapture{Session: record.Session, Submission: record.Submission, Pending: *record.Receipt, Protocol: fixture.Protocol, RequestBytes: 43, ResponseBytes: 79, RequestSHA256: liveProtocolSHA(flow.request), ResponseSHA256: liveProtocolSHA(flow.response), Heartbeat: heartbeat, Listener: nodeAddr, ActualService: true, ActualKernel: true, NativeTrafficAbsent: true}
		liveProtocolWrite(t, filepath.Join(dir, "history-capture.json"), capture)
		liveProtocolWrite(t, filepath.Join(dir, "history-ready.json"), map[string]any{"batch_id": record.Submission.Payload.BatchID, "actual_service_live": true})
		liveProtocolWait(t, done, 12*time.Second, func() bool {
			return revocationRecord(cfg.UsageV2.Directory, &record) && record.Receipt != nil && record.Receipt.SettlementStatus == "settled"
		})
		if caseName == "history" || caseName == "expiry" || caseName == "source-continue" || caseName == "generation-drift" || caseName == "instance-drift" || caseName == "receipt-missing" {
			cancel()
			revocationStopped(t, done, false)
			return
		}
	} else if phase != "tail" && phase != "expiry" && phase != "continuation" {
		t.Fatal("invalid live revocation phase")
	}
	if caseName == "source-continue" {
		if phase != "continuation" {
			t.Fatal("source continuation requires the second Core-issued epoch")
		}
		old, err := revocationRecords(cfg.UsageV2.Directory)
		if err != nil || len(old) != 1 || old[0].Session.SourceEpoch != "1" || old[0].Receipt == nil || old[0].Receipt.SettlementStatus != "settled" {
			t.Fatal("original settled source-epoch record missing", err)
		}
		nodeAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.NodePort))
		dest := M.ParseSocksaddr(net.JoinHostPort("127.0.0.1", strconv.Itoa(fixture.OriginPort)))
		flow := revocationExchange(t, origin, fixture.Protocol, nodeAddr, dest, 37, 19)
		if err := flow.raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		var eof [1]byte
		if n, e := flow.client.Read(eof[:]); n != 0 || e != io.EOF {
			t.Fatal("continued source flow EOF", n, e)
		}
		if err := <-flow.originDone; err != nil {
			t.Fatal("continued source origin completion", err)
		}
		flow.client.Close()
		flow.raw.Close()
		var records []usagev2.Record
		liveProtocolWait(t, done, 12*time.Second, func() bool {
			records, err = revocationRecords(cfg.UsageV2.Directory)
			return err == nil && len(records) == 2 && records[1].Session.SourceEpoch == "2" && records[1].Receipt != nil
		})
		if records[0].Submission.PayloadDigest != old[0].Submission.PayloadDigest || records[0].Receipt == nil || records[0].Receipt.ReceiptID != old[0].Receipt.ReceiptID || records[0].Session.SourceEpoch != "1" {
			t.Fatal("old source record changed while continuing")
		}
		liveProtocolWrite(t, filepath.Join(dir, "continuation-capture.json"), map[string]any{
			"old_batch_id": old[0].Submission.Payload.BatchID, "old_digest": old[0].Submission.PayloadDigest,
			"old_receipt_id": old[0].Receipt.ReceiptID, "old_source_epoch": old[0].Session.SourceEpoch,
			"new_batch_id": records[1].Submission.Payload.BatchID, "new_digest": records[1].Submission.PayloadDigest,
			"new_receipt_id": records[1].Receipt.ReceiptID, "new_source_epoch": records[1].Session.SourceEpoch,
			"new_raw_up_bytes":     records[1].Submission.Payload.Entries[0].RawUpBytes,
			"new_raw_down_bytes":   records[1].Submission.Payload.Entries[0].RawDownBytes,
			"old_receipt_replayed": liveProtocolObservedOldReceipt(dir, old[0], started),
		})
		if !liveProtocolObservedOldReceipt(dir, old[0], started) {
			t.Fatal("new Service did not query the immutable old receipt")
		}
		liveProtocolWrite(t, filepath.Join(dir, "continuation-ready.json"), map[string]any{"new_batch_id": records[1].Submission.Payload.BatchID, "source_epoch": "2"})
		revocationWaitFile(t, done, dir, "continuation-settled.json", 12*time.Second)
		liveProtocolWait(t, done, 12*time.Second, func() bool {
			records, err = revocationRecords(cfg.UsageV2.Directory)
			return err == nil && len(records) == 2 && records[1].Receipt != nil && records[1].Receipt.SettlementStatus == "settled"
		})
		if err != nil || len(records) != 2 || records[1].Receipt == nil || records[1].Receipt.SettlementStatus != "settled" || records[0].Receipt.ReceiptID != old[0].Receipt.ReceiptID || records[0].Submission.PayloadDigest != old[0].Submission.PayloadDigest {
			t.Fatal("source epoch continuation mutated prior history or failed to settle", err)
		}
		cancel()
		revocationStopped(t, done, false)
		liveProtocolWrite(t, filepath.Join(dir, "continuation-result.json"), map[string]any{
			"actual_service_run": true, "protocol": fixture.Protocol, "core_instance_id": records[1].Session.CoreInstanceID,
			"receipt_generation": records[1].Session.ReceiptGeneration, "old_source_epoch": records[0].Session.SourceEpoch,
			"new_source_epoch": records[1].Session.SourceEpoch, "old_batch_id": records[0].Submission.Payload.BatchID,
			"new_batch_id": records[1].Submission.Payload.BatchID, "old_receipt_id": records[0].Receipt.ReceiptID,
			"new_receipt_id": records[1].Receipt.ReceiptID, "old_history_unchanged": true,
			"new_upload_bytes":   records[1].Submission.Payload.Entries[0].RawUpBytes,
			"new_download_bytes": records[1].Submission.Payload.Entries[0].RawDownBytes,
		})
		return
	}
	if caseName == "udp" || caseName == "xudp" {
		if phase != "history" || udpOrigin == nil {
			t.Fatal("packet boundary requires the real history and isolated UDP route")
		}
		packetRaw, packet := revocationPacketDial(t, fixture.Protocol, caseName, nodeAddr, dest)
		defer packetRaw.Close()
		defer packet.Close()
		payload := []byte("synthetic-unsupported-datagram")
		if err := packet.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		written, writeErr := packet.WriteTo(payload, dest.UDPAddr())
		if writeErr != nil && !errors.Is(writeErr, net.ErrClosed) {
			t.Fatal("actual protocol packet write", writeErr)
		}
		if written != 0 && written != len(payload) {
			t.Fatal("partial protocol packet write", written)
		}
		_ = udpOrigin.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		buffer := make([]byte, 256)
		n, _, originErr := udpOrigin.ReadFromUDP(buffer)
		if originErr == nil || n != 0 {
			t.Fatal("unsupported UDP reached exact loopback origin", n, originErr)
		}
		if timeout, ok := originErr.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal("UDP origin refusal observation failed", originErr)
		}
		stopped := false
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("bounded packet failure returned success")
			}
			stopped = true
		case <-time.After(1500 * time.Millisecond):
		}
		if !stopped {
			cancel()
			revocationStopped(t, done, false)
		}
		var historical usagev2.Record
		if !revocationRecord(cfg.UsageV2.Directory, &historical) || historical.Receipt == nil || historical.Receipt.SettlementStatus != "settled" {
			t.Fatal("settled original history missing after unsupported packet")
		}
		liveProtocolWrite(t, filepath.Join(dir, "boundary-result.json"), map[string]any{
			"case": caseName, "protocol": fixture.Protocol,
			"packet_api":         map[bool]string{true: "DialEarlyXUDPPacketConn", false: "DialEarlyPacketConn"}[caseName == "xudp"],
			"actual_service_run": true, "udp_origin_datagrams": 0, "origin_closed": true,
			"service_stopped_on_tracker_detection": stopped, "listener_closed": !svc.kernel.IsRunning(),
			"historical_receipt": historical.Receipt.ReceiptID, "unknown_packet_successful_batch": false,
			"production_authorization": false,
		})
		return
	}
	if caseName == "tcp-mux" {
		if phase != "history" {
			t.Fatal("classic TCP mux boundary requires the real history baseline")
		}
		var historical usagev2.Record
		if !revocationRecord(cfg.UsageV2.Directory, &historical) || historical.Receipt == nil || historical.Receipt.SettlementStatus != "settled" {
			t.Fatal("settled original history missing before classic mux")
		}
		muxRaw, muxConn := revocationTCPMuxDial(t, fixture.Protocol, nodeAddr, dest)
		defer muxRaw.Close()
		defer muxConn.Close()
		payload := []byte("synthetic-classic-tcp-mux")
		frame := new(bytes.Buffer)
		address := new(bytes.Buffer)
		if err := vmess.AddressSerializer.WriteAddrPort(address, dest); err != nil {
			t.Fatal("locked destination serializer", err)
		}
		_ = binary.Write(frame, binary.BigEndian, uint16(5+address.Len()))
		_ = binary.Write(frame, binary.BigEndian, uint16(1))
		_ = frame.WriteByte(vmess.StatusNew)
		_ = frame.WriteByte(vmess.OptionData)
		_ = frame.WriteByte(vmess.NetworkTCP)
		_, _ = frame.Write(address.Bytes())
		_ = binary.Write(frame, binary.BigEndian, uint16(len(payload)))
		_, _ = frame.Write(payload)
		if _, err := muxConn.Write(frame.Bytes()); err != nil {
			t.Fatal("locked classic TCP mux frame write", err)
		}
		_ = origin.SetDeadline(time.Now().Add(1200 * time.Millisecond))
		originConn, originErr := origin.AcceptTCP()
		originReached := originErr == nil
		var originPayload []byte
		if originReached {
			_ = originConn.SetDeadline(time.Now().Add(time.Second))
			originPayload = make([]byte, len(payload))
			_, _ = io.ReadFull(originConn, originPayload)
			_ = originConn.Close()
		} else if timeout, ok := originErr.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal("classic mux origin observation failed", originErr)
		}
		if originReached {
			liveProtocolWrite(t, filepath.Join(dir, "tcp-mux-bypass.json"), map[string]any{
				"case": caseName, "protocol": fixture.Protocol, "outer_command": "CommandMux",
				"inner_network": "TCP", "origin_connection": true,
				"origin_received_payload": string(originPayload) == string(payload),
				"origin_payload_sha256":   liveProtocolSHA(originPayload), "listener_closed": !svc.kernel.IsRunning(),
				"historical_batch": historical.Submission.Payload.BatchID, "historical_receipt": historical.Receipt.ReceiptID,
				"production_authorization": false,
			})
			t.Fatal("LIVE_REVOCATION_CLASSIC_TCP_MUX_REACHED_ORIGIN")
		}
		stopped := false
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("bounded mux failure returned success")
			}
			stopped = true
		case <-time.After(1500 * time.Millisecond):
		}
		if !stopped {
			cancel()
			revocationStopped(t, done, false)
		}
		liveProtocolWrite(t, filepath.Join(dir, "boundary-result.json"), map[string]any{
			"case": caseName, "protocol": fixture.Protocol, "outer_command": "CommandMux",
			"inner_network": "TCP", "origin_connection": false, "actual_service_run": true,
			"service_stopped_on_tracker_detection": stopped, "listener_closed": !svc.kernel.IsRunning(),
			"historical_receipt":           historical.Receipt.ReceiptID,
			"unknown_mux_successful_batch": false, "production_authorization": false,
		})
		return
	}

	// A separate live flow has real measured bytes and an unfinished read. The
	// worker must retain that tail, rather than generating a final successful batch.
	tail := revocationExchange(t, origin, fixture.Protocol, nodeAddr, dest, 17, 41)
	defer tail.client.Close()
	defer tail.raw.Close()
	liveProtocolWrite(t, filepath.Join(dir, "tail-ready.json"), map[string]any{"case": caseName, "upload_bytes": 17, "download_bytes": 41, "request_sha256": liveProtocolSHA(tail.request), "response_sha256": liveProtocolSHA(tail.response), "actual_listener": nodeAddr, "opened_at": time.Now().UnixNano(), "service_live": svc.kernel.IsRunning()})
	if caseName == "shutdown" {
		revocationWaitFile(t, done, dir, "trigger.json", 10*time.Second)
		cancel()
		revocationStopped(t, done, false)
	} else if caseName == "expiry" {
		if phase != "expiry" || expiry.IsZero() {
			t.Fatal("finite lease phase did not start bounded usage")
		}
		tailRemaining := time.Until(expiry)
		if tailRemaining <= 0 {
			t.Fatal("finite lease expired before the actual tail was open")
		}
		revocationStopped(t, done, true)
		stoppedAt := time.Now()
		if stoppedAt.Before(expiry) || stoppedAt.After(expiry.Add(1500*time.Millisecond)) {
			t.Fatal("actual Service shutdown outside lease expiry allowance", stoppedAt.Sub(expiry))
		}
		liveProtocolWrite(t, filepath.Join(dir, "expiry-boundary-result.json"), map[string]any{
			"case": caseName, "protocol": fixture.Protocol, "actual_service_run": true,
			"lease_expires_at": expiry.Unix(), "remaining_at_service_start_ms": startupLease.Milliseconds(),
			"remaining_at_tail_open_ms": tailRemaining.Milliseconds(),
			"actual_close_lag_ms":       stoppedAt.Sub(expiry).Milliseconds(),
			"listener_closed":           !svc.kernel.IsRunning(), "unknown_tail_successful_batch": false,
			"production_authorization": false,
		})
	} else if caseName == "ban-baseline" {
		liveProtocolWait(t, done, 8*time.Second, func() bool { return revocationEmptyPoll(dir) })
		// Wait through further genuine polls after the native sole-user removal.
		deadline := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				t.Fatal("baseline unexpectedly stopped", err)
			case <-time.After(25 * time.Millisecond):
			}
		}
		if !svc.kernel.IsRunning() {
			t.Fatal("baseline listener unexpectedly stopped")
		}
		probe := []byte("after-ban")
		if n, e := tail.client.Write(probe); n != len(probe) || e != nil {
			t.Fatal("baseline continued stream probe", n, e)
		}
		liveProtocolWait(t, done, 2*time.Second, func() bool { return tail.extra.Load() == int64(len(probe)) })
		liveProtocolWrite(t, filepath.Join(dir, "baseline-ignored-empty.json"), map[string]any{"native_users200_empty_observed": true, "service_still_running": true, "postban_origin_bytes": tail.extra.Load(), "postban_probe_sha256": liveProtocolSHA(probe), "case": "ban-baseline", "production_authorization": false})
		cancel()
		revocationStopped(t, done, false)
		t.Fatal("LIVE_REVOCATION_EMPTY_USERS_IGNORED_REAL_PROTOCOL")
	} else {
		revocationStopped(t, done, true)
	}
	if svc.kernel.IsRunning() {
		t.Fatal("actual listener remained after boundary")
	}
	// The origin must observe actual connection termination. Buffered local writes
	// are not accepted as evidence that the origin received post-stop bytes.
	select {
	case err := <-tail.originDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal("tail origin termination", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin live tail not closed")
	}
	if tail.extra.Load() != 0 {
		t.Fatal("unexpected post-trigger origin bytes", tail.extra.Load())
	}
	if svc.tracker.HasTraffic() {
		t.Fatal("unknown v2 tail entered native traffic tracker")
	}
	var historical usagev2.Record
	if !revocationRecord(cfg.UsageV2.Directory, &historical) || historical.Receipt == nil || historical.Receipt.SettlementStatus != "settled" {
		t.Fatal("settled original history missing")
	}
	if historical.Submission.Payload.Entries[0].RawUpBytes != "43" || historical.Submission.Payload.Entries[0].RawDownBytes != "79" {
		t.Fatal("history mutated by tail")
	}
	liveProtocolWrite(t, filepath.Join(dir, "boundary-result.json"), map[string]any{"case": caseName, "protocol": fixture.Protocol, "actual_service_run": true, "actual_kernel": "sing-box", "listener_closed": true, "origin_connection_closed": true, "unknown_tail_upload_bytes": 17, "unknown_tail_download_bytes": 41, "unknown_tail_successful_batch": false, "legacy_traffic_absent": true, "historical_batch": historical.Submission.Payload.BatchID, "historical_receipt": historical.Receipt.ReceiptID, "production_authorization": false})
}

func revocationExchange(t *testing.T, origin *net.TCPListener, protocol, nodeAddr string, dest M.Socksaddr, up, down int) *revocationFlow {
	t.Helper()
	flow := &revocationFlow{originDone: make(chan error, 1), request: bytes.Repeat([]byte("u"), up), response: bytes.Repeat([]byte("D"), down)}
	ready := make(chan error, 1)
	go func() {
		conn, err := origin.AcceptTCP()
		if err != nil {
			ready <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		request := make([]byte, up)
		if _, err := io.ReadFull(conn, request); err != nil {
			ready <- err
			return
		}
		if !bytes.Equal(request, flow.request) {
			ready <- errors.New("origin decoded request mismatch")
			return
		}
		if n, e := conn.Write(flow.response); n != down || e != nil {
			ready <- errors.New("origin response incomplete")
			return
		}
		ready <- nil
		buffer := make([]byte, 128)
		for {
			n, e := conn.Read(buffer)
			if n > 0 {
				flow.extra.Add(int64(n))
			}
			if e != nil {
				if e == io.EOF {
					e = conn.CloseWrite()
				}
				flow.originDone <- e
				return
			}
		}
	}()
	flow.raw, flow.client = liveProtocolDial(t, protocol, nodeAddr, liveProtocolUUID, dest)
	if n, e := flow.client.Write(flow.request); n != up || e != nil {
		t.Fatal("actual request incomplete", n, e)
	}
	got := make([]byte, down)
	if _, e := io.ReadFull(flow.client, got); e != nil || !bytes.Equal(got, flow.response) {
		t.Fatal("actual response mismatch", e)
	}
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin readiness timeout")
	}
	return flow
}

func revocationPacketDial(t *testing.T, protocol, kind, address string, dest M.Socksaddr) (*net.TCPConn, net.PacketConn) {
	t.Helper()
	rawConn, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := rawConn.(*net.TCPConn)
	if !ok {
		rawConn.Close()
		t.Fatal("non-TCP protocol transport")
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	xudp := kind == "xudp"
	if protocol == "vless" {
		client, err := vless.NewClient(liveProtocolUUID, "", logger.NOP())
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		if xudp {
			packet, err := client.DialEarlyXUDPPacketConn(raw, dest)
			if err != nil {
				raw.Close()
				t.Fatal(err)
			}
			return raw, packet
		}
		packet, err := client.DialEarlyPacketConn(raw, dest)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		return raw, packet
	}
	client, err := vmess.NewClient(liveProtocolUUID, "aes-128-gcm", 0)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if xudp {
		return raw, client.DialEarlyXUDPPacketConn(raw, dest)
	}
	return raw, client.DialEarlyPacketConn(raw, dest)
}

func revocationTCPMuxDial(t *testing.T, protocol, address string, dest M.Socksaddr) (*net.TCPConn, net.Conn) {
	t.Helper()
	rawConn, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := rawConn.(*net.TCPConn)
	if !ok {
		rawConn.Close()
		t.Fatal("non-TCP protocol transport")
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if protocol == "vless" {
		id, err := uuid.FromString(liveProtocolUUID)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		conn := vless.NewConn(raw, id, vmess.CommandMux, dest, "")
		if _, err := conn.Write(nil); err != nil {
			raw.Close()
			t.Fatal("VLESS CommandMux handshake", err)
		}
		return raw, conn
	}
	client, err := vmess.NewClient(liveProtocolUUID, "aes-128-gcm", 0)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	packet := client.DialEarlyXUDPPacketConn(raw, dest)
	conn, ok := packet.(*vmess.XUDPConn)
	if !ok {
		raw.Close()
		t.Fatal("locked VMess XUDP client concrete type changed")
	}
	if _, err := conn.Conn.Write(nil); err != nil {
		raw.Close()
		t.Fatal("VMess CommandMux handshake", err)
	}
	return raw, conn.Conn
}

func revocationRecord(modeDir string, record *usagev2.Record) bool {
	records, err := revocationRecords(modeDir)
	if err != nil || len(records) != 1 {
		return false
	}
	*record = records[0]
	return true
}

func revocationRecords(modeDir string) ([]usagev2.Record, error) {
	files, err := filepath.Glob(filepath.Join(modeDir, "spool", "*.usage.json"))
	if err != nil {
		return nil, err
	}
	records := make([]usagev2.Record, 0, len(files))
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var record usagev2.Record
		if err := usagev2.StrictDecode(body, &record, usagev2.MaxPayloadBytes); err != nil {
			return nil, err
		}
		if err := record.Validate(); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i].Session.SourceEpoch, records[j].Session.SourceEpoch
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return a < b
	})
	return records, nil
}

func liveProtocolObservedOldReceipt(dir string, record usagev2.Record, started time.Time) bool {
	body, err := os.ReadFile(filepath.Join(dir, "native-observations.jsonl"))
	if err != nil {
		return false
	}
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		var observation struct {
			Path          string  `json:"path"`
			Status        int     `json:"status"`
			StartedAt     float64 `json:"started_at"`
			SourceEpoch   string  `json:"source_epoch"`
			ReceiptID     string  `json:"receipt_id"`
			BatchID       string  `json:"batch_id"`
			PayloadDigest string  `json:"payload_digest"`
		}
		if json.Unmarshal(line, &observation) == nil && observation.Path == "/txapi/node/v2/usage/batch/get" && observation.Status == 200 &&
			observation.StartedAt >= float64(started.UnixNano())/1e9 && observation.SourceEpoch == record.Session.SourceEpoch &&
			observation.BatchID == record.Submission.Payload.BatchID && observation.PayloadDigest == record.Submission.PayloadDigest &&
			record.Receipt != nil && observation.ReceiptID == record.Receipt.ReceiptID {
			return true
		}
	}
	return false
}
func revocationStopped(t *testing.T, done <-chan error, wantFailure bool) {
	t.Helper()
	select {
	case err := <-done:
		if wantFailure != (err != nil) {
			t.Fatal("unexpected actual Service boundary outcome", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("actual Service failed to stop on boundary")
	}
}
func revocationWaitFile(t *testing.T, done <-chan error, dir, name string, timeout time.Duration) {
	t.Helper()
	liveProtocolWait(t, done, timeout, func() bool { _, e := os.Stat(filepath.Join(dir, name)); return e == nil })
}
func revocationEmptyPoll(dir string) bool {
	body, e := os.ReadFile(filepath.Join(dir, "native-observations.jsonl"))
	if e != nil {
		return false
	}
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		var observation struct {
			Path   string `json:"path"`
			Status int    `json:"status"`
			Count  *int   `json:"user_count"`
		}
		if json.Unmarshal(line, &observation) == nil && observation.Path == "/txapi/node/v1/users" && observation.Status == 200 && observation.Count != nil && *observation.Count == 0 {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
