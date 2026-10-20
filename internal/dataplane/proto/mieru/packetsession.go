package mieru

import (
	"errors"
	"sync"
	"time"
)

// PacketSession is the per-peer reliable datagram session used by the UDP
// transport. Evidence: NewPacketSession @0x7e0700 with
// PacketSession.{Input @0x7e2180, step @0x7e3300, acked @0x7e2c00,
// loop @0x7e2f00, Write, Read} and the out-of-order queue arrivals @0xee9b20
// (notes/rev-proto-udp.md §3.4). The report states the state machine was not
// verified instruction by instruction (notes §7 item 3), so the reordering and
// retransmission policy below is the kaze-replication design:
//
//   - inbound segments are delivered in sequence order, out-of-order ones are
//     buffered up to a window;
//   - outbound segments are kept until acknowledged; an ack is a segPacket
//     segment whose flags carry flagAck and whose payload is the acked sequence
//     (4 bytes, big endian);
//   - loop retransmits an unacknowledged segment after retransmitAfter, up to
//     maxRetries times.
const (
	// reorderWindow is the number of out-of-order sequences buffered.
	reorderWindow = 64
	// retransmitAfter is the retransmission delay.
	retransmitAfter = 500 * time.Millisecond
	// maxRetries bounds retransmissions before a segment is dropped.
	maxRetries = 5
	// loopInterval is the timer period of loop.
	loopInterval = 100 * time.Millisecond
	// readyBuffer is the delivery queue size.
	readyBuffer = 128
	// flagAck marks an acknowledgement segment.
	flagAck = 1 << 0
)

// outPacket is one unacknowledged outbound segment.
type outPacket struct {
	seq   uint32
	seg   []byte
	sent  time.Time
	tries int
}

// PacketSession is a reliable, ordered datagram session.
type PacketSession struct {
	send func([]byte) error

	mu      sync.Mutex
	wmu     sync.Mutex
	nextSeq uint32 // next expected inbound sequence
	pending map[uint32][]byte
	ready   chan []byte
	outSeq  uint32
	unacked map[uint32]*outPacket
	closed  chan struct{}
	once    sync.Once
}

// NewPacketSession builds a session whose send function puts one sealed segment
// on the wire.
func NewPacketSession(send func([]byte) error) *PacketSession {
	p := &PacketSession{
		send:    send,
		pending: make(map[uint32][]byte),
		ready:   make(chan []byte, readyBuffer),
		unacked: make(map[uint32]*outPacket),
		closed:  make(chan struct{}),
	}
	go p.loop()
	return p
}

// Input accepts one inbound segment payload with its sequence number, buffering
// out-of-order arrivals.
func (p *PacketSession) Input(seq uint32, payload []byte) {
	p.mu.Lock()
	if seq < p.nextSeq {
		p.mu.Unlock()
		return // duplicate
	}
	if seq > p.nextSeq+reorderWindow {
		p.mu.Unlock()
		return // too far ahead: drop
	}
	if seq != p.nextSeq {
		if _, ok := p.pending[seq]; !ok {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			p.pending[seq] = cp
		}
		p.mu.Unlock()
		return
	}
	p.nextSeq++
	queue := [][]byte{payload}
	for {
		next, ok := p.pending[p.nextSeq]
		if !ok {
			break
		}
		delete(p.pending, p.nextSeq)
		p.nextSeq++
		queue = append(queue, next)
	}
	p.mu.Unlock()
	for _, q := range queue {
		select {
		case p.ready <- q:
		case <-p.closed:
			return
		default:
			// Delivery queue full: dropping is the right UDP behaviour.
		}
	}
}

// setNext initialises the expected inbound sequence, for a session whose first
// datagram does not carry sequence 0.
func (p *PacketSession) setNext(seq uint32) {
	p.mu.Lock()
	if seq > p.nextSeq {
		p.nextSeq = seq
	}
	p.mu.Unlock()
}

// Read pops one delivered datagram.
func (p *PacketSession) Read(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, netErrClosed{}
	case d := <-p.ready:
		return copy(b, d), nil
	}
}

// Write seals nothing itself: the caller supplies the sealed segment for the
// assigned sequence and gets the sequence back for tracking.
func (p *PacketSession) Write(seal func(seq uint32) []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.mu.Lock()
	select {
	case <-p.closed:
		p.mu.Unlock()
		return netErrClosed{}
	default:
	}
	if len(p.unacked) >= reorderWindow || p.outSeq == ^uint32(0) {
		p.mu.Unlock()
		return errors.New("mieru: compatibility packet send window exhausted")
	}
	seq := p.outSeq
	p.outSeq++
	p.mu.Unlock()
	seg := seal(seq)
	p.mu.Lock()
	p.unacked[seq] = &outPacket{seq: seq, seg: seg, sent: time.Now()}
	p.mu.Unlock()
	if err := p.send(seg); err != nil {
		p.mu.Lock()
		delete(p.unacked, seq)
		p.mu.Unlock()
		return err
	}
	return nil
}

// acked removes a sequence from the retransmission set.
func (p *PacketSession) acked(seq uint32) {
	p.mu.Lock()
	delete(p.unacked, seq)
	p.mu.Unlock()
}

// step performs one retransmission pass.
func (p *PacketSession) step(now time.Time) {
	var resend [][]byte
	p.mu.Lock()
	for seq, pkt := range p.unacked {
		if now.Sub(pkt.sent) < retransmitAfter {
			continue
		}
		if pkt.tries >= maxRetries {
			delete(p.unacked, seq)
			continue
		}
		pkt.tries++
		pkt.sent = now
		resend = append(resend, pkt.seg)
	}
	p.mu.Unlock()
	for _, seg := range resend {
		_ = p.send(seg)
	}
}

// loop drives step.
func (p *PacketSession) loop() {
	t := time.NewTicker(loopInterval)
	defer t.Stop()
	for {
		select {
		case <-p.closed:
			return
		case now := <-t.C:
			p.step(now)
		}
	}
}

// Close stops the session.
func (p *PacketSession) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// netErrClosed avoids importing net just for the sentinel.
type netErrClosed struct{}

func (netErrClosed) Error() string   { return "mieru: packet session closed" }
func (netErrClosed) Timeout() bool   { return false }
func (netErrClosed) Temporary() bool { return false }
