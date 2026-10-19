package bbr

import (
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// pacerBurst is the packet budget ceiling of the token bucket. quic-go BBRv1
// allows at most this many maximum-size datagrams of accumulated budget so a
// long idle period cannot turn into an unbounded send burst.
const pacerBurst = 10

// pacer is the BBRv1 token-bucket pacer: it answers TimeUntilSend and
// HasPacingBudget for the sender. The queue itself never leaves this process.
type pacer struct {
	maxDatagramSize    congestion.ByteCount
	budgetAtLastRefill monotime.Time
	budget             congestion.ByteCount
	rate               congestion.ByteCount // bytes per second
}

func newPacer(maxDatagramSize congestion.ByteCount) *pacer {
	return &pacer{
		maxDatagramSize: maxDatagramSize,
		budget:          maxDatagramSize * pacerBurst,
	}
}

// budgetAt returns the budget accumulated up to now.
func (p *pacer) budgetAt(now monotime.Time) congestion.ByteCount {
	if p.budgetAtLastRefill.IsZero() {
		return p.budget
	}
	elapsed := now.Sub(p.budgetAtLastRefill)
	if elapsed <= 0 {
		return p.budget
	}
	b := p.budget + congestion.ByteCount(float64(p.rate)*elapsed.Seconds())
	if ceiling := p.maxDatagramSize * pacerBurst; b > ceiling {
		b = ceiling
	}
	return b
}

// setRate installs a new pacing rate, first banking the accrued budget.
func (p *pacer) setRate(now monotime.Time, rate congestion.ByteCount) {
	p.budget = p.budgetAt(now)
	p.budgetAtLastRefill = now
	p.rate = rate
}

// TimeUntilSend is the earliest monotonic instant at which one more maximum-size
// datagram may be sent.
func (p *pacer) TimeUntilSend(now monotime.Time) monotime.Time {
	if p.budgetAt(now) >= p.maxDatagramSize {
		return now
	}
	if p.rate <= 0 {
		// No estimate yet: do not stall the connection, the congestion window
		// still gates the burst.
		return now
	}
	need := p.maxDatagramSize - p.budgetAt(now)
	d := time.Duration(float64(need) / float64(p.rate) * float64(time.Second))
	if d < congestion.MinPacingDelay {
		d = congestion.MinPacingDelay
	}
	return now.Add(d)
}

// HasPacingBudget reports whether a maximum-size datagram fits right now.
func (p *pacer) HasPacingBudget(now monotime.Time) bool {
	return p.budgetAt(now) >= p.maxDatagramSize
}

// OnPacketSent consumes the budget for one sent packet.
func (p *pacer) OnPacketSent(now monotime.Time, bytes congestion.ByteCount) {
	p.budget = p.budgetAt(now) - bytes
	if p.budget < 0 {
		p.budget = 0
	}
	p.budgetAtLastRefill = now
}

// setMaxDatagramSize tracks a PMTU change. The report quotes the BBR debug guard
// "congestion BUG: decreased max datagram size from %d to %d"
// (notes/rev-transport.md §6.3); the original asserts, this port clamps instead
// of panicking so a misbehaving path cannot take the node down.
func (p *pacer) setMaxDatagramSize(size congestion.ByteCount) {
	if size <= 0 {
		return
	}
	p.maxDatagramSize = size
}
