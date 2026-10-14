package singbox

// ResetsCumulativeTrafficOnStart declares that a successful complete Start
// owns a fresh ConnTracker. User-only hot updates retain their existing meter.
// It does not attest traffic continuity or trigger a reset on failed starts.
func (s *SingBox) ResetsCumulativeTrafficOnStart() bool { return true }
