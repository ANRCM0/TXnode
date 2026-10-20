package socks5

// InheritPacketState keeps the listening UDP endpoint available to new
// authenticated TCP associations without replacing the packet receive loop.
func (h *Handler) InheritPacketState(previous *Handler) { h.pkt = previous.pkt }
