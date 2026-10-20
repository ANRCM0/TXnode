package bbr

import (
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// The bandwidth sampler measures delivery rate the way BBRv1 does: it groups
// acknowledgements by round trip and takes (bytes delivered)/(time elapsed) over
// one ack event, then keeps a windowed maximum.
//
// Evidence: notes/rev-transport.md §6.1 lists bandwidthSampler,
// maxAckHeightTracker and the generic WindowedFilter[E,T] / RingBuffer[T]
// instantiations, which is exactly quic-go's BBRv1 sampler. The private
// kaze-specific part is only the named profile (§6.3).
//
// UNVERIFIED: quic-go's sampler also tracks app-limited periods and a
// max-ack-height tracker for the "ack aggregation" correction. Those are
// rate-accuracy refinements; the state machine, gains and cwnd accounting below
// are what the node's behaviour depends on, so the sampler here keeps the round
// grouping and the windowed maximum and omits the app-limited bookkeeping.

// bandwidthSampleWindow is the number of round trips kept by the windowed
// maximum (quic-go BBRv1 uses a 2-round window, noted here as the port keeps a
// slightly wider one to survive sparse ack events).
const bandwidthSampleWindow = 3

// bandwidthSampler turns ack events into delivery-rate samples.
type bandwidthSampler struct {
	// lastAckTime is the monotonic time of the previous ack event that carried
	// data.
	lastAckTime monotime.Time
	// delivered is the running total of acked bytes.
	delivered congestion.ByteCount
	// deliveredAtLastAck is delivered at the previous sample point.
	deliveredAtLastAck congestion.ByteCount
	// round is the current round-trip counter.
	round uint64
	// lastSentTime is the send time of the most recent packet.
	lastSentTime monotime.Time

	// samples is the windowed maximum of observed delivery rates.
	samples ringMax
	// hasSample is set once at least one sample was taken.
	hasSample bool
}

func newBandwidthSampler() *bandwidthSampler {
	return &bandwidthSampler{samples: ringMax{capacity: bandwidthSampleWindow}}
}

// onPacketSent records the newest send time; a new round starts when a packet is
// sent at least one RTT after the previous one.
func (s *bandwidthSampler) onPacketSent(now monotime.Time, rtt float64) {
	if s.lastSentTime.IsZero() {
		s.lastSentTime = now
		return
	}
	if now.Sub(s.lastSentTime).Seconds() >= rtt {
		s.round++
		s.lastSentTime = now
	}
}

// onPacketAcked adds bytes to the delivered total and, when enough time passed
// since the last sample, records a new delivery rate.
func (s *bandwidthSampler) onPacketAcked(now monotime.Time, bytes congestion.ByteCount, minRTT float64) {
	s.delivered += bytes
	if s.lastAckTime.IsZero() {
		s.lastAckTime = now
		s.deliveredAtLastAck = s.delivered - bytes
	}
	dt := now.Sub(s.lastAckTime).Seconds()
	if dt <= 0 {
		return
	}
	// Ignore sub-millisecond buckets: the rate is meaningless and it would let
	// one tight ack loop dominate the estimate.
	rate := congestion.ByteCount(float64(s.delivered-s.deliveredAtLastAck) / dt)
	if rate <= 0 {
		return
	}
	s.samples.add(rate)
	s.hasSample = true
	s.lastAckTime = now
	s.deliveredAtLastAck = s.delivered
}

// onPacketLost subtracts the lost bytes from the delivered total so a lost
// packet never counts as delivered bandwidth.
func (s *bandwidthSampler) onPacketLost(bytes congestion.ByteCount) {
	s.delivered -= bytes
	if s.deliveredAtLastAck > s.delivered {
		s.deliveredAtLastAck = s.delivered
	}
	if s.delivered < 0 {
		s.delivered = 0
		s.deliveredAtLastAck = 0
	}
}

// bandwidthEstimate returns the windowed-maximum sample, or zero when the
// connection has not delivered anything measurable yet.
func (s *bandwidthSampler) bandwidthEstimate() congestion.ByteCount {
	if !s.hasSample {
		return 0
	}
	return s.samples.max()
}

// ringMax is a fixed-window maximum filter over ByteCount samples.
type ringMax struct {
	capacity int
	values   []congestion.ByteCount
	pos      int
	filled   bool
}

func (r *ringMax) add(v congestion.ByteCount) {
	if r.capacity <= 0 {
		return
	}
	if len(r.values) < r.capacity {
		r.values = append(r.values, v)
		if len(r.values) == r.capacity {
			r.filled = true
		}
		return
	}
	r.values[r.pos] = v
	r.pos = (r.pos + 1) % r.capacity
}

func (r *ringMax) max() congestion.ByteCount {
	var best congestion.ByteCount
	for _, v := range r.values {
		if v > best {
			best = v
		}
	}
	return best
}

// minRTTFilter keeps the minimum RTT over a time window: BBRv1 refreshes its
// min-RTT estimate every 10 seconds so a stale low sample cannot pin the cwnd
// target forever.
type minRTTFilter struct {
	window   float64 // seconds
	minRTT   float64
	stamp    monotime.Time
	hasValue bool
}

func newMinRTTFilter(windowSeconds float64) *minRTTFilter {
	return &minRTTFilter{window: windowSeconds}
}

func (f *minRTTFilter) update(now monotime.Time, rttSeconds float64) {
	if rttSeconds <= 0 {
		return
	}
	if !f.hasValue {
		f.minRTT = rttSeconds
		f.stamp = now
		f.hasValue = true
		return
	}
	if rttSeconds < f.minRTT {
		f.minRTT = rttSeconds
		f.stamp = now
		return
	}
	if now.Sub(f.stamp).Seconds() > f.window {
		// Window expired: restart the filter from the current sample.
		f.minRTT = rttSeconds
		f.stamp = now
	}
}

// expired reports whether the min-RTT sample is older than the window, which is
// what pushes BBRv1 into PROBE_RTT for one round trip.
func (f *minRTTFilter) expired(now monotime.Time) bool {
	return f.hasValue && now.Sub(f.stamp).Seconds() > f.window
}
