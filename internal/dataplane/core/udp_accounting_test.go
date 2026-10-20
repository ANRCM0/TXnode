package core

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

type accountingPackets struct {
	write func([]byte, socks.Addr) error
	close func() error
}

func (p accountingPackets) ReadPacket([]byte) (int, socks.Addr, error) {
	return 0, socks.Addr{}, io.EOF
}
func (p accountingPackets) WritePacket(b []byte, a socks.Addr) error { return p.write(b, a) }
func (p accountingPackets) Close() error {
	if p.close != nil {
		return p.close()
	}
	return nil
}

func TestUDPDownloadAccountsPacketDelivery(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failed"}[failed], func(t *testing.T) {
			hook := &recordingHook{}
			var delivered int64
			writeErr := errors.New("packet write failed")
			packets := accountingPackets{write: func([]byte, socks.Addr) error {
				if failed {
					return writeErr
				}
				return nil
			}}
			u := &udpRelay{ctx: context.Background(), sess: &Session{ConnID: 1, Packets: packets},
				opts: ServerOptions{Hooks: hook, OnTraffic: func(_ int, _, down int64) { delivered += down }}, assocs: make(map[socks.Addr]*udpAssoc)}
			a := &udpAssoc{conn: accountingConn{reader: strings.NewReader("hello")}}
			u.readBack(a)
			want := int64(5)
			if failed {
				want = 0
			}
			if len(hook.begins) != 1 || len(hook.completes) != 1 || hook.completes[0].N != want || delivered != want {
				t.Fatalf("hook=%+v delivered=%d want=%d", hook, delivered, want)
			}
			if failed && !errors.Is(hook.completes[0].Err, writeErr) {
				t.Fatal("write failure lost")
			}
		})
	}
}

type countedAccountingPackets struct {
	accountingPackets
	count func([]byte, socks.Addr) (int, error)
}

func (p countedAccountingPackets) WritePacketCount(b []byte, a socks.Addr) (int, error) {
	return p.count(b, a)
}

func TestUDPDownloadPreservesCountedWriteErrorTail(t *testing.T) {
	for _, test := range []struct {
		name string
		n    int
		want int64
	}{{"full", 5, 5}, {"partial", 2, 2}, {"empty", 0, 0}, {"invalid-negative", -1, 0}, {"invalid-large", 6, 0}} {
		t.Run(test.name, func(t *testing.T) {
			hook := &recordingHook{}
			writeErr := errors.New("parent shutdown after write")
			var traffic int64
			packets := countedAccountingPackets{count: func([]byte, socks.Addr) (int, error) { return test.n, writeErr }}
			u := &udpRelay{ctx: context.Background(), sess: &Session{ConnID: 1, Packets: packets},
				opts: ServerOptions{Hooks: hook, OnTraffic: func(_ int, _, down int64) { traffic += down }}, assocs: make(map[socks.Addr]*udpAssoc)}
			a := &udpAssoc{conn: accountingConn{reader: strings.NewReader("hello")}}
			u.readBack(a)
			if len(hook.completes) != 1 || hook.completes[0].N != test.want || traffic != test.want || !errors.Is(hook.completes[0].Err, writeErr) {
				t.Fatalf("completion=%+v traffic=%d want=%d", hook.completes, traffic, test.want)
			}
		})
	}
}

func TestUDPCloseJoinsPacketWriteCompletion(t *testing.T) {
	started := make(chan struct{})
	closed := make(chan struct{})
	var once sync.Once
	packets := accountingPackets{
		write: func([]byte, socks.Addr) error { close(started); <-closed; return io.ErrClosedPipe },
		close: func() error { once.Do(func() { close(closed) }); return nil },
	}
	hook := &recordingHook{}
	u := &udpRelay{ctx: context.Background(), sess: &Session{ConnID: 1, Packets: packets}, opts: ServerOptions{Hooks: hook}, assocs: make(map[socks.Addr]*udpAssoc)}
	a := &udpAssoc{conn: accountingConn{reader: strings.NewReader("hello")}}
	u.readers.Add(1)
	go func() { defer u.readers.Done(); u.readBack(a) }()
	<-started
	u.close()
	if len(hook.completes) != 1 || hook.completes[0].N != 0 || !errors.Is(hook.completes[0].Err, io.ErrClosedPipe) {
		t.Fatalf("close returned before write completion: %+v", hook)
	}
}
