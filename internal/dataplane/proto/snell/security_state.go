package snell

// InheritSecurityState retains replay protection across user table updates.
// Call only on an unpublished replacement handler for the same node configuration.
func (h *Handler) InheritSecurityState(previous *Handler) {
	h.salts = previous.salts
}
