package mux

// TCP Brutal negotiation.
//
// Evidence:
//   - Serve.func1 @0x774c40 dispatches a stream whose destination host is
//     exactly "_BrutalBwExchange" (17 bytes) to (*Brutal).exchange.
//   - exchange @0x7731c0 sets a 10 s read deadline, reads 8 bytes
//     (io.ReadAtLeast), bswaps them (big-endian rate) and rejects rates below
//     0x10000 B/s.
//   - writeBrutalAnswer @0x772f80 writes 10 bytes: 00 01 followed by the rate as
//     big-endian uint64.
//   - SetBrutal.func1 @0x773840 sets TCP_CONGESTION="brutal" and
//     TCP_BRUTAL_PARAMS (0x5b05 = 23301) with a 12-byte struct
//     {rate uint64, cwndGain uint32=20} (host byte order).
//
// UNVERIFIED: whether the server answer carries its own limit or an echo, and
// the exact gain semantics (20 here, from the immediate 0x14).

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// BrutalExchangeHost is the reserved mux destination for the rate exchange.
const BrutalExchangeHost = "_BrutalBwExchange"

// BrutalMinRate is the smallest rate the sample accepts (0x10000 B/s).
const BrutalMinRate = 0x10000

// tcpBrutalParams is Linux's TCP_BRUTAL_PARAMS (the sample's 0x5b05).
const tcpBrutalParams = 23301

// brutalProfile is the 12-byte setsockopt payload.
type brutalProfile struct {
	Rate     uint64
	CWNDGain uint32
}

// BrutalAvailable reports whether the kernel offers the tcp-brutal congestion
// control (mux.BrutalAvailable @0x773aa0 reads
// /proc/sys/net/ipv4/tcp_available_congestion_control).
func BrutalAvailable() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(b)) {
		if f == "brutal" {
			return true
		}
	}
	return false
}

// SetBrutal installs the congestion control and rate on a TCP connection.
// Non-TCP connections cannot carry the option and get an explicit error.
func SetBrutal(conn net.Conn, rate uint64) error {
	sc, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return errors.New("TCP Brutal is not available on this machine (the tcp-brutal kernel module is not loaded)")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	profile := make([]byte, 12)
	binary.LittleEndian.PutUint64(profile[0:8], rate)
	binary.LittleEndian.PutUint32(profile[8:12], 20)
	err = raw.Control(func(fd uintptr) {
		if e := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal"); e != nil {
			setErr = errors.New("TCP Brutal is not available on this machine (the tcp-brutal kernel module is not loaded)")
			return
		}
		if e := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, tcpBrutalParams, string(profile)); e != nil {
			setErr = e
		}
	})
	if err != nil {
		return err
	}
	if setErr != nil {
		return setErr
	}
	return nil
}

// ServerExchange performs the server side of the rate exchange on a mux stream.
// limit is the server's cap in bytes/s (0 = none); the answer carries the
// accepted rate.
func ServerExchange(conn net.Conn, limit uint64) (uint64, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buf [8]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return 0, err
	}
	rate := binary.BigEndian.Uint64(buf[:])
	if rate < BrutalMinRate {
		return 0, errors.New("TCP Brutal: the client can receive a rate below the minimum this node accepts")
	}
	if limit > 0 && rate > limit {
		rate = limit
	}
	if _, err := conn.Write(answer(rate)); err != nil {
		return 0, err
	}
	return rate, nil
}

// ClientExchange performs the client side: announce the receive rate, read the
// server's answer and apply it to conn.
func ClientExchange(conn net.Conn, recvRate uint64) (uint64, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], recvRate)
	if _, err := conn.Write(buf[:]); err != nil {
		return 0, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ans [10]byte
	if _, err := io.ReadFull(conn, ans[:]); err != nil {
		return 0, err
	}
	rate, ok := parseAnswer(ans[:])
	if !ok {
		return 0, errors.New("TCP Brutal: the server did not answer the rate exchange")
	}
	return rate, nil
}

func answer(rate uint64) []byte {
	b := make([]byte, 10)
	b[1] = 1
	binary.BigEndian.PutUint64(b[2:], rate)
	return b
}

func parseAnswer(b []byte) (uint64, bool) {
	if len(b) < 10 || b[1] != 1 {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[2:10]), true
}
