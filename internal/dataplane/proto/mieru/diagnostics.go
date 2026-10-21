package mieru

// PacketDiagnostics reports a fixed, bounded label set. It never exposes user
// names, remote addresses, credentials, plaintext, or per-session identifiers.
func (h *Handler) PacketDiagnostics() map[string]uint64 {
	out := map[string]uint64{
		"peers": 0, "pending_segments": 0, "reassembly_bytes": 0,
		"retransmissions": 0, "duplicate_packets": 0, "dropped_packets": 0,
	}
	s := h.packetServer.Load()
	if s == nil {
		return out
	}
	out["retransmissions"] = s.retransmissions.Load()
	out["duplicate_packets"] = s.duplicates.Load()
	out["dropped_packets"] = s.dropped.Load()
	s.mu.Lock()
	peers := make([]*v2DatagramConn, 0, len(s.v2Peers))
	legacy := make([]*udpPeer, 0, len(s.peers))
	for _, peer := range s.v2Peers {
		peers = append(peers, peer)
	}
	for _, peer := range s.peers {
		legacy = append(legacy, peer)
	}
	s.mu.Unlock()
	out["peers"] = uint64(len(peers) + len(legacy))
	for _, peer := range peers {
		peer.mu.Lock()
		out["pending_segments"] += uint64(len(peer.pending))
		out["reassembly_bytes"] += uint64(peer.buffered)
		peer.mu.Unlock()
	}
	for _, peer := range legacy {
		peer.ps.mu.Lock()
		out["pending_segments"] += uint64(len(peer.ps.unacked))
		for _, body := range peer.ps.pending {
			out["reassembly_bytes"] += uint64(len(body))
		}
		peer.ps.mu.Unlock()
	}
	return out
}
