package mieru

func scanGatePointer(rate, burst float64) *scanGate {
	g := newScanGate(rate, burst)
	return &g
}

// InheritSecurityState keeps replay protection and scan budgets across user updates.
// Call only on an unpublished replacement handler for the same node configuration.
func (h *Handler) InheritSecurityState(previous *Handler) {
	h.rmu, h.seen, h.scans = previous.rmu, previous.seen, previous.scans
}
