package vmess

// InheritSecurityState keeps the replay map and its lock across user updates.
// Call only on an unpublished replacement handler for the same node configuration.
func (h *Handler) InheritSecurityState(previous *Handler) {
	h.replayMu, h.replay = previous.replayMu, previous.replay
}
