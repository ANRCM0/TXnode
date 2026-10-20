package vless

// InheritSecurityState retains encryption resumption tickets across user updates.
// Call only on an unpublished replacement handler for the same node configuration.
func (h *Handler) InheritSecurityState(previous *Handler) {
	h.enc = previous.enc
}
