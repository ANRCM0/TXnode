package bbr

import (
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// BBRv1 constants. The values are the canonical BBRv1 ones; the report proves
// this package is an unmodified quic-go BBRv1 port (notes/rev-transport.md §6.1:
// no BBRv2 markers anywhere in the binary, phases are exactly
// STARTUP/DRAIN/PROBE_BW/PROBE_RTT), so the only kaze-specific values are the
// named profiles in profile.go.
const (
	// initialCongestionWindowPackets is quic-go's BBRv1 initial window.
	initialCongestionWindowPackets = 32
	// maxCongestionWindowPackets mirrors congestion.MaxCongestionWindowPackets.
	maxCongestionWindowPackets = 20000
	// gainCycleLength is the number of PROBE_BW phases in one cycle.
	gainCycleLength = 8
	// lowGain is the PROBE_BW gain right after the cycle's high-gain phase.
	lowGain = 0.25
	// probeRTTDuration is how long PROBE_RTT keeps the window pinned (200 ms,
	// the BBRv1 value quic-go uses).
	probeRTTDuration = 200 * time.Millisecond
	// minRTTWindowSeconds is BBRv1's min-RTT filter window.
	minRTTWindowSeconds = 10.0
	// defaultMinRTTSeconds is used until the RTT provider supplies a sample.
	defaultMinRTTSeconds = 0.1
)

// cycleGains is the canonical BBRv1 PROBE_BW gain cycle.
var cycleGains = [gainCycleLength]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

// Mode is the BBRv1 phase machine. The four names are the strings recovered from
// the binary: "Phase: STARTUP", "Phase: DRAIN", "Phase: PROBE_BW",
// "Phase: PROBE_RTT" (notes/rev-transport.md §6.1).
type Mode int

const (
	// ModeStartup grows the window at the high gain until the pipe is full.
	ModeStartup Mode = iota
	// ModeDrain sheds the STARTUP queue at the inverse high gain.
	ModeDrain
	// ModeProbeBW oscillates around the bandwidth-delay product.
	ModeProbeBW
	// ModeProbeRTT drains the pipe for one round trip to re-measure min RTT.
	ModeProbeRTT
)

// String matches the "[BBRSender] [%s] %s" debug line's phase names.
func (m Mode) String() string {
	switch m {
	case ModeStartup:
		return "STARTUP"
	case ModeDrain:
		return "DRAIN"
	case ModeProbeBW:
		return "PROBE_BW"
	case ModeProbeRTT:
		return "PROBE_RTT"
	}
	return "UNKNOWN"
}

// Sender is the BBRv1 congestion controller. It implements
// congestion.CongestionControlEx, the interface quic.Conn.SetCongestionControl
// accepts, which is how the binary installs it (congestion_bbr.Use @0xa97c00).
type Sender struct {
	rttStats congestion.RTTStatsProvider

	profile    profile
	highGain   float64
	cwndGain   float64
	pacingGain float64

	maxDatagramSize         congestion.ByteCount
	congestionWindow        congestion.ByteCount
	initialCongestionWindow congestion.ByteCount
	maxCongestionWindow     congestion.ByteCount

	mode          Mode
	fullBwReached bool
	fullBwNow     bool
	fullBwRounds  int // profile.numStartupRTTs
	fullBwCount   int
	fullBw        congestion.ByteCount

	roundTripCounter uint64
	nextRoundTrip    uint64
	cycleIndex       int
	probeRTTDoneAt   monotime.Time

	bandwidthEstimate congestion.ByteCount
	minRTT            *minRTTFilter
	pacer             *pacer
	sampler           *bandwidthSampler

	priorInFlight congestion.ByteCount
	inRecovery    bool
}

var _ congestion.CongestionControlEx = (*Sender)(nil)

// New returns a BBRv1 sender with the named profile installed. An empty or
// unknown name is the "standard" profile, exactly like applyProfile @0xa95aa0.
func New(profileName string) *Sender {
	s := &Sender{
		maxDatagramSize: congestion.InitialPacketSize,
		minRTT:          newMinRTTFilter(minRTTWindowSeconds),
		sampler:         newBandwidthSampler(),
		profile:         profileStandard,
		mode:            ModeStartup,
	}
	s.congestionWindow = congestionWindowForPackets(initialCongestionWindowPackets, s.maxDatagramSize)
	s.initialCongestionWindow = s.congestionWindow
	s.maxCongestionWindow = maxCongestionWindowFor(s.maxDatagramSize)
	s.pacer = newPacer(s.maxDatagramSize)
	s.applyProfile(profileName)
	s.pacingGain = s.highGain
	s.cwndGain = s.highGain
	s.pacer.setRate(monotime.Now(), s.pacingRateLocked())
	return s
}

// congestionWindowForPackets converts a packet count into bytes, never below the
// BBRv1 two-datagram floor.
func congestionWindowForPackets(packets int, maxDatagramSize congestion.ByteCount) congestion.ByteCount {
	if packets < 2 {
		packets = 2
	}
	return congestion.ByteCount(packets) * maxDatagramSize
}

// maxCongestionWindowFor is the absolute cwnd ceiling in bytes.
func maxCongestionWindowFor(maxDatagramSize congestion.ByteCount) congestion.ByteCount {
	return maxCongestionWindowPackets * maxDatagramSize
}

// SetRTTStatsProvider installs the RTT source. quic.Conn calls this itself from
// SetCongestionControl before the sender is used.
func (s *Sender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	s.rttStats = provider
}

// GetCongestionWindow returns the current cwnd in bytes.
func (s *Sender) GetCongestionWindow() congestion.ByteCount { return s.congestionWindow }

// InSlowStart is true during STARTUP; the sender's growth is BBR's, not Reno's.
func (s *Sender) InSlowStart() bool { return s.mode == ModeStartup }

// InRecovery is true after a loss episode until the packets in flight at loss
// time have left the network. BBRv1 does not halve the window; it keeps a
// recovery window of inflight+acked so a loss burst cannot collapse the rate.
func (s *Sender) InRecovery() bool { return s.inRecovery }

// Mode returns the current phase.
func (s *Sender) Mode() Mode { return s.mode }

// BandwidthEstimate returns the current delivery-rate estimate in bytes/second.
func (s *Sender) BandwidthEstimate() congestion.ByteCount { return s.bandwidthEstimate }

// SetMaxDatagramSize tracks the path MTU.
func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size <= 0 || size == s.maxDatagramSize {
		return
	}
	s.maxDatagramSize = size
	s.pacer.setMaxDatagramSize(size)
	s.maxCongestionWindow = maxCongestionWindowFor(size)
	if s.congestionWindow < s.minCwnd() {
		s.congestionWindow = s.minCwnd()
	}
}

// CanSend reports whether another maximum-size datagram fits in the window.
func (s *Sender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < s.congestionWindow
}

// HasPacingBudget reports whether the pacer allows a datagram right now.
func (s *Sender) HasPacingBudget(now monotime.Time) bool {
	return s.pacer.HasPacingBudget(now)
}

// TimeUntilSend is the instant the pacer allows the next datagram.
func (s *Sender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	now := monotime.Now()
	if bytesInFlight >= s.congestionWindow {
		// Window-limited: no pacing estimate applies, ask to be called again
		// after a nominal RTT.
		return now.Add(s.nominalRTT())
	}
	return s.pacer.TimeUntilSend(now)
}

// MaybeExitSlowStart is a QUIC-internal hint used by other controllers; BBR
// decides on its own, so it is a no-op apart from the recovery reset.
func (s *Sender) MaybeExitSlowStart() {}

// OnPacketSent records a sent packet for the sampler and the pacer.
func (s *Sender) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount, packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool) {
	s.sampler.onPacketSent(sentTime, s.nominalRTT().Seconds())
	s.pacer.OnPacketSent(sentTime, bytes)
}

// OnPacketAcked feeds one ack into the model.
func (s *Sender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount, priorInFlight congestion.ByteCount, eventTime monotime.Time) {
	s.OnCongestionEventEx(priorInFlight, eventTime,
		[]congestion.AckedPacketInfo{{
			PacketNumber: number,
			BytesAcked:   ackedBytes,
			ReceivedTime: eventTime,
		}}, nil)
}

// OnCongestionEvent feeds one loss episode into the model.
func (s *Sender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount, priorInFlight congestion.ByteCount) {
	s.OnCongestionEventEx(priorInFlight, monotime.Now(), nil,
		[]congestion.LostPacketInfo{{
			PacketNumber: number,
			BytesLost:    lostBytes,
		}})
}

// OnRetransmissionTimeout keeps BBR's window (BBR does not react to RTO with a
// multiplicative decrease) but drops out of recovery so the next ack reopens it.
func (s *Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	s.inRecovery = false
}

// OnCongestionEventEx is the main entry point used by the QUIC ack handler: one
// ack event with all acked and lost packets.
func (s *Sender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	if priorInFlight > 0 {
		s.priorInFlight = priorInFlight
	}
	var ackedBytes, lostBytes congestion.ByteCount
	for _, p := range ackedPackets {
		ackedBytes += p.BytesAcked
	}
	for _, p := range lostPackets {
		lostBytes += p.BytesLost
	}
	if ackedBytes == 0 && lostBytes == 0 {
		return
	}

	s.updateRTT(eventTime)
	for _, p := range ackedPackets {
		s.sampler.onPacketAcked(eventTime, p.BytesAcked, s.nominalRTT().Seconds())
	}
	if lostBytes > 0 {
		s.sampler.onPacketLost(lostBytes)
		s.handleLoss(priorInFlight, ackedBytes)
	}

	s.bandwidthEstimate = s.sampler.bandwidthEstimate()
	s.advanceRound(ackedPackets)
	s.updateModelAndState(ackedBytes)
	s.updatePacingRate(eventTime)
}

// updateRTT refreshes the min-RTT filter from the RTT provider.
func (s *Sender) updateRTT(now monotime.Time) {
	if s.rttStats == nil {
		return
	}
	if minRTT := s.rttStats.MinRTT(); minRTT > 0 {
		s.minRTT.update(now, minRTT.Seconds())
	} else if latest := s.rttStats.LatestRTT(); latest > 0 {
		s.minRTT.update(now, latest.Seconds())
	}
}

// advanceRound bumps the round-trip counter when a packet sent after the last
// round's boundary is acked. This is the clock the gain cycle and the STARTUP
// exit condition run on.
func (s *Sender) advanceRound(acked []congestion.AckedPacketInfo) {
	if len(acked) == 0 {
		return
	}
	highest := acked[0].PacketNumber
	for _, p := range acked[1:] {
		if p.PacketNumber > highest {
			highest = p.PacketNumber
		}
	}
	if s.nextRoundTrip == 0 || uint64(highest) >= s.nextRoundTrip {
		s.roundTripCounter++
		s.nextRoundTrip = uint64(highest) + 1
	}
}

// updateModelAndState runs the BBRv1 state machine after one ack event.
func (s *Sender) updateModelAndState(ackedBytes congestion.ByteCount) {
	s.checkIfFullBandwidthReached()
	s.maybeEnterOrExitProbeRTT()
	s.updateCongestionWindow(ackedBytes)
	s.enterDrainOrProbeBW()
}

// checkIfFullBandwidthReached implements BBR's STARTUP exit test: the estimated
// bandwidth has to grow by 25% within profile.numStartupRTTs round trips.
func (s *Sender) checkIfFullBandwidthReached() {
	if s.fullBwReached {
		return
	}
	if s.bandwidthEstimate <= 0 {
		return
	}
	if s.bandwidthEstimate >= congestion.ByteCount(float64(s.fullBw)*1.25) {
		s.fullBw = s.bandwidthEstimate
		s.fullBwCount = 0
		return
	}
	s.fullBwCount++
	if s.fullBwCount >= s.fullBwRounds {
		s.fullBwReached = true
		s.fullBwNow = true
	}
}

// maybeEnterOrExitProbeRTT drives the 10 s min-RTT refresh.
func (s *Sender) maybeEnterOrExitProbeRTT() {
	now := monotime.Now()
	if s.mode == ModeProbeRTT {
		if now.Sub(s.probeRTTDoneAt) < probeRTTDuration {
			return
		}
		s.mode = ModeProbeBW
		s.pacingGain = cycleGains[s.cycleIndex]
		s.cwndGain = s.profile.cwndGain
		return
	}
	if s.minRTT.expired(now) && s.mode != ModeProbeRTT {
		s.mode = ModeProbeRTT
		s.pacingGain = 1
		s.cwndGain = 1
		s.probeRTTDoneAt = now
		// Forget the stale minimum so the filter restarts as soon as a fresh
		// sample arrives.
		s.minRTT.hasValue = false
	}
}

// enterDrainOrProbeBW performs the STARTUP -> DRAIN -> PROBE_BW transitions.
func (s *Sender) enterDrainOrProbeBW() {
	switch s.mode {
	case ModeStartup:
		s.pacingGain = s.highGain
		s.cwndGain = s.highGain
		if s.fullBwReached {
			s.mode = ModeDrain
			s.pacingGain = 1 / s.highGain
			s.cwndGain = s.highGain
		}
	case ModeDrain:
		s.pacingGain = 1 / s.highGain
		s.cwndGain = s.highGain
		if s.priorInFlight <= s.congestionWindow {
			s.mode = ModeProbeBW
			s.cycleIndex = 0
			s.pacingGain = cycleGains[0]
			s.cwndGain = s.profile.cwndGain
		}
	case ModeProbeBW:
		s.cwndGain = s.profile.cwndGain
		// The gain cycle advances once per round trip.
		if s.fullBwNow {
			s.fullBwNow = false
			s.cycleIndex = (s.cycleIndex + 1) % gainCycleLength
		}
		s.pacingGain = cycleGains[s.cycleIndex]
	case ModeProbeRTT:
		s.pacingGain = 1
		s.cwndGain = 1
	}
}

// updateCongestionWindow grows the window as BBRv1 does per phase. acked is the
// number of bytes acknowledged by this event.
func (s *Sender) updateCongestionWindow(acked congestion.ByteCount) {
	switch s.mode {
	case ModeStartup:
		// Exponential growth: one more byte of window per byte acked.
		s.congestionWindow += acked
	case ModeDrain:
		// No growth; the pacer drains the STARTUP queue.
	case ModeProbeBW:
		target := s.targetCwnd()
		if s.congestionWindow < target {
			s.congestionWindow += acked
			if s.congestionWindow > target {
				s.congestionWindow = target
			}
		}
	case ModeProbeRTT:
		if c := s.minCwnd(); s.congestionWindow > c {
			s.congestionWindow = c
		}
	}
	if s.congestionWindow < s.minCwnd() {
		s.congestionWindow = s.minCwnd()
	}
	if s.congestionWindow > s.maxCongestionWindow {
		s.congestionWindow = s.maxCongestionWindow
	}
}

// handleLoss opens a BBR recovery window: cwnd becomes inflight+acked, never
// below the floor, and stays there until the loss-time flight is accounted for.
func (s *Sender) handleLoss(priorInFlight, acked congestion.ByteCount) {
	if s.inRecovery {
		return
	}
	s.inRecovery = true
	window := priorInFlight + acked
	if min := s.minCwnd(); window < min {
		window = min
	}
	if window < s.congestionWindow {
		s.congestionWindow = window
	}
}

// updatePacingRate recomputes the pacing rate from the bandwidth estimate and
// the current gain.
func (s *Sender) updatePacingRate(now monotime.Time) {
	s.pacer.setRate(now, s.pacingRateLocked())
}

func (s *Sender) pacingRateLocked() congestion.ByteCount {
	minRTT := s.minRTTSeconds()
	if s.bandwidthEstimate <= 0 {
		// Before the first sample, pace at twice the initial window per RTT so
		// STARTUP can double.
		rate := congestion.ByteCount(float64(s.initialCongestionWindow) * 2 / minRTT)
		if rate <= 0 {
			rate = congestion.ByteCount(float64(s.maxDatagramSize) / minRTT)
		}
		return rate
	}
	rate := congestion.ByteCount(float64(s.bandwidthEstimate) * s.pacingGain)
	// Never pace slower than one window per RTT.
	if floor := congestion.ByteCount(float64(s.congestionWindow) / minRTT); rate < floor {
		rate = floor
	}
	return rate
}

// targetCwnd is the PROBE_BW window target: BDP * cwndGain.
func (s *Sender) targetCwnd() congestion.ByteCount {
	if s.bandwidthEstimate <= 0 {
		return s.initialCongestionWindow
	}
	bdp := float64(s.bandwidthEstimate) * s.minRTTSeconds()
	target := congestion.ByteCount(bdp * s.cwndGain)
	if min := s.minCwnd(); target < min {
		target = min
	}
	if target > s.maxCongestionWindow {
		target = s.maxCongestionWindow
	}
	return target
}

func (s *Sender) minCwnd() congestion.ByteCount {
	return 4 * s.maxDatagramSize
}

func (s *Sender) minRTTSeconds() float64 {
	if s.minRTT.hasValue && s.minRTT.minRTT > 0 {
		return s.minRTT.minRTT
	}
	if s.rttStats != nil {
		if rtt := s.rttStats.MinRTT(); rtt > 0 {
			return rtt.Seconds()
		}
		if rtt := s.rttStats.SmoothedRTT(); rtt > 0 {
			return rtt.Seconds()
		}
	}
	return defaultMinRTTSeconds
}

// nominalRTT is the RTT used for the "call me again" hint when the connection is
// window-limited: the current min-RTT estimate.
func (s *Sender) nominalRTT() time.Duration {
	return time.Duration(s.minRTTSeconds() * float64(time.Second))
}
