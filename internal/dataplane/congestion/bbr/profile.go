// Package bbr is the BBRv1 congestion controller recovered from
// github.com/ANRCM0/TX-Node/internal/dataplane/congestion/bbr.
//
// Evidence (all static, from kazecore):
//   - REPORT.md §7.8: 55 functions, BBRv1 (quic-go port) instantiated on
//     apernet/quic-go types, so it only ever acts on QUIC (Hysteria2 / TUIC).
//   - notes/rev-transport.md §6.1: the phase machine has exactly
//     STARTUP / DRAIN / PROBE_BW / PROBE_RTT and BBRv2 markers
//     (PROBE_UP, PROBE_DOWN, inflight_hi) have zero hits.
//   - notes/rev-transport.md §6.3: kaze adds named profiles through
//     applyProfile @0xa95aa0. The profile name is matched with inline 8-byte
//     constants, and a 40-byte parameter block is copied into the sender
//     (3 float64 + uint64 + 8 trailing bytes).
//
// UNVERIFIED: the mapping of the trailing 8 bytes to a semantic field. They are
// kept verbatim in profile.tail so the table below is byte-faithful, but no
// behaviour is derived from them.
package bbr

import "fmt"

// profile is one named parameter block, mirroring the 40 bytes copied at
// sender+0xa8 by applyProfile (notes/rev-transport.md §6.3).
//
// The float64 triple comes straight out of .rodata:
//
//	aggressive   f1=3.0   f2=2.25  f3=2.5   u64=4  tail=00 00 00 00 01 01 02 00
//	conservative f1=2.25  f2=1.75  f3=1.75  u64=2  tail=01 01 00 00 01 01 00 01
//	standard     f1=2.885 f2=2.0   f3=2.0   u64=3  tail=00 00 00 00 00 00 02 00
//
// f1 is the STARTUP high gain: 2.885 = 2/(ln 2)^2 is the BBRv1 spec constant,
// which is what identifies f1 as highGain. f2/f3 are the cwnd and pacing gains
// by position; the report marks that mapping as unresolved (§6.4 item 8), so the
// names are INFERRED from BBRv1's algebra (PROBE_BW target = bw*minRTT*cwndGain,
// pacing = pacingGain*bw) and are the only reading under which the numbers make
// sense (aggressive: both above 2, conservative: both below 2).
type profile struct {
	name string
	// highGain is STARTUP/DRAIN's pacing and cwnd gain (f1).
	highGain float64
	// cwndGain scales the PROBE_BW congestion-window target (f2).
	cwndGain float64
	// pacingGain scales the pacing rate outside STARTUP (f3).
	pacingGain float64
	// numStartupRTTs is the number of full-bandwidth round trips after which
	// STARTUP is left (u64). It matches quic-go's numStartupRTTs = 3 for the
	// default profile (notes/rev-transport.md §6.3).
	numStartupRTTs int
	// tail holds the trailing 8 bytes of the 40-byte block unchanged.
	tail [8]byte

	// initialCwndPackets overrides the initial congestion window. The contract
	// (§ deliverable 5) asks the named profile to override the initial window;
	// the binary's parameter block has no explicit packet count, so these three
	// values are INFERRED (32 is quic-go BBRv1's own initial window, the other
	// two keep the aggressive/conservative ordering of highGain).
	initialCwndPackets int
}

// The three profiles observed in the binary. "standard" is the zero-length name
// branch at 0xa95abc, i.e. the default when no profile is configured.
var (
	profileStandard = profile{
		name:               "standard",
		highGain:           2.885, // 0x4007147ae147ae14, BBRv1 high gain
		cwndGain:           2.0,
		pacingGain:         2.0,
		numStartupRTTs:     3,
		tail:               [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00},
		initialCwndPackets: 32,
	}
	profileAggressive = profile{
		name:               "aggressive",
		highGain:           3.0,
		cwndGain:           2.25,
		pacingGain:         2.5,
		numStartupRTTs:     4,
		tail:               [8]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00},
		initialCwndPackets: 64,
	}
	profileConservative = profile{
		name:               "conservative",
		highGain:           2.25,
		cwndGain:           1.75,
		pacingGain:         1.75,
		numStartupRTTs:     2,
		tail:               [8]byte{0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01},
		initialCwndPackets: 16,
	}
)

// Profiles returns the names accepted by ApplyProfile, in the order the binary
// tests them.
func Profiles() []string { return []string{"standard", "aggressive", "conservative"} }

// lookupProfile resolves a profile name exactly like applyProfile @0xa95aa0:
// an empty name is "standard" (the `len == 0` branch), unknown names fall back
// to "standard" as well — the binary has no error path for a bad name.
func lookupProfile(name string) profile {
	switch name {
	case "", "standard":
		return profileStandard
	case "aggressive":
		return profileAggressive
	case "conservative":
		return profileConservative
	}
	return profileStandard
}

// ApplyProfile installs a named profile: it overwrites the sender's gains, the
// STARTUP round count and the initial congestion window. It mirrors
// applyProfile writing the 40-byte block into sender+0xa8 and the name pointer
// into sender+0x98.
func (s *Sender) ApplyProfile(name string) {
	s.applyProfile(name)
}

func (s *Sender) applyProfile(name string) {
	p := lookupProfile(name)
	s.profile = p
	s.highGain = p.highGain
	s.cwndGain = p.cwndGain
	s.pacingGain = p.pacingGain
	s.fullBwRounds = p.numStartupRTTs
	s.initialCongestionWindow = congestionWindowForPackets(p.initialCwndPackets, s.maxDatagramSize)
	s.maxCongestionWindow = maxCongestionWindowFor(s.maxDatagramSize)
	// applyProfile installs the profile's initial window. The binary calls it
	// from newBbrSender before the first packet, so the window is set rather than
	// only raised; a mid-flight call would reinstall the window, which is the
	// same thing the constructor does.
	s.congestionWindow = s.initialCongestionWindow
}

// ProfileName reports the installed profile, for the "Profile: %s" debug line
// (notes/rev-transport.md §6.3).
func (s *Sender) ProfileName() string { return s.profile.name }

func (s *Sender) String() string {
	return fmt.Sprintf("bbr(%s)", s.profile.name)
}
