package shadowsocks

// InheritSecurityState retains salts seen by old and new handshakes alike.
// Call only on an unpublished replacement handler for the same node configuration.
func (h *Handler) InheritSecurityState(previous *Handler) {
	h.salts = previous.salts
}
