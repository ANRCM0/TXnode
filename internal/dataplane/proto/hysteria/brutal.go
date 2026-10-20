package hysteria

import (
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// brutal is Hysteria's fixed-rate congestion controller: the sender paces at a
// configured byte rate and never reacts to loss. In the sample it lives in
// github.com/ANRCM0/TX-Node/internal/dataplane/proto/hysteria (SetRTTStatsProvider @0xaa15c0, budgetAt
// @0xaa1620, TimeUntilSend @0xaa1740, HasPacingBudget @0xaa18e0, OnPacketSent
// @0xaa1a00, CanSend @0xaa1b60, GetCongestionWindow @0xaa1bc0,
// OnCongestionEventEx @0xaa1d80, SetMaxDatagramSize @0xaa2020, OnPacketAcked
// @0xaa20a0) and is installed from ServeHTTP as:
//
//	b = new(brutal); b->tx = rx; b->maxDS = conn->maxDatagramSize;
//	b->gain = 1.0; conn->congestion = b;
//
// so tx is bytes/second, maxDatagramSize is copied from the connection and the
// gain is 1.0 (notes/rev-proto-udp.md §1.3, 0xaa2f08–0xaa2f9d).
const (
	// brutalDefaultGain is +0xa0 = 0x3ff0000000000000 = 1.0.
	brutalDefaultGain = 1.0
	// brutalWindow is what GetCongestionWindow reports: brutal is rate-limited,
	// not window-limited, so the window is effectively unlimited.
	brutalWindow congestion.ByteCount = 1 << 30
)

// brutalSender implements congestion.CongestionControlEx with a fixed rate.
type brutalSender struct {
	tx               congestion.ByteCount // bytes/second (+0x08)
	maxDatagramSize  congestion.ByteCount // +0x20
	gain             float64              // +0xa0
	sentAtLastRefill monotime.Time
	budget           congestion.ByteCount
	rttStats         congestion.RTTStatsProvider
}

var _ congestion.CongestionControlEx = (*brutalSender)(nil)

func newBrutalSender(tx congestion.ByteCount) *brutalSender {
	if tx <= 0 {
		tx = 1
	}
	b := &brutalSender{
		tx:              tx,
		maxDatagramSize: congestion.InitialPacketSize,
		gain:            brutalDefaultGain,
	}
	// Start with a small burst so the first datagrams are not delayed: 10 ms of
	// the configured rate, but never less than two datagrams.
	b.budget = congestion.ByteCount(float64(tx) * 0.01)
	if b.budget < 2*b.maxDatagramSize {
		b.budget = 2 * b.maxDatagramSize
	}
	return b
}

// installBrutal installs the controller on a QUIC connection. The connection's
// own initial packet size seeds maxDatagramSize, as quic-go requires for
// controllers installed with SetCongestionControl.
func installBrutal(conn *quic.Conn, tx int64) *brutalSender {
	b := newBrutalSender(congestion.ByteCount(tx))
	if size := conn.InitialPacketSize(); size > 0 {
		b.SetMaxDatagramSize(size)
	}
	conn.SetCongestionControl(b)
	return b
}

func (b *brutalSender) rate() congestion.ByteCount {
	return congestion.ByteCount(float64(b.tx) * b.gain)
}

// refill banks the tokens accrued since the last call.
func (b *brutalSender) refill(now monotime.Time) {
	if b.sentAtLastRefill.IsZero() {
		b.sentAtLastRefill = now
		return
	}
	elapsed := now.Sub(b.sentAtLastRefill)
	if elapsed <= 0 {
		return
	}
	b.budget += congestion.ByteCount(float64(b.rate()) * elapsed.Seconds())
	if ceiling := b.maxDatagramSize * 10; b.budget > ceiling {
		b.budget = ceiling
	}
	b.sentAtLastRefill = now
}

func (b *brutalSender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	b.rttStats = provider
}

// TimeUntilSend is governed purely by the rate budget.
func (b *brutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	now := monotime.Now()
	b.refill(now)
	if b.budget >= b.maxDatagramSize {
		return now
	}
	need := b.maxDatagramSize - b.budget
	d := time.Duration(float64(need) / float64(b.rate()) * float64(time.Second))
	if d < congestion.MinPacingDelay {
		d = congestion.MinPacingDelay
	}
	return now.Add(d)
}

func (b *brutalSender) HasPacingBudget(now monotime.Time) bool {
	b.refill(now)
	return b.budget >= b.maxDatagramSize
}

func (b *brutalSender) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount, packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool) {
	b.refill(sentTime)
	b.budget -= bytes
	if b.budget < 0 {
		b.budget = 0
	}
}

// CanSend is always true: a brutal sender is rate-limited, never window-limited.
func (b *brutalSender) CanSend(bytesInFlight congestion.ByteCount) bool { return true }

func (b *brutalSender) MaybeExitSlowStart() {}

// OnPacketAcked / OnCongestionEvent / OnRetransmissionTimeout are no-ops: a
// fixed-rate sender ignores the network's feedback by design.
func (b *brutalSender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}

func (b *brutalSender) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}

func (b *brutalSender) OnCongestionEventEx(congestion.ByteCount, monotime.Time, []congestion.AckedPacketInfo, []congestion.LostPacketInfo) {
}

func (b *brutalSender) OnRetransmissionTimeout(bool) {}

func (b *brutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size > 0 {
		b.maxDatagramSize = size
	}
}

func (b *brutalSender) InSlowStart() bool                         { return false }
func (b *brutalSender) InRecovery() bool                          { return false }
func (b *brutalSender) GetCongestionWindow() congestion.ByteCount { return brutalWindow }
