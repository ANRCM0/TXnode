package txnode

// RuntimeDiagnostics returns fixed-cardinality counters. It intentionally omits
// connection IDs, UUIDs, peer/target addresses, authorization grants and errors.
func (k *Kernel) RuntimeDiagnostics() map[string]any {
	k.mu.Lock()
	defer k.mu.Unlock()
	tcp, udp := 0, 0
	for _, srv := range k.liveServersLocked() {
		a, b := srv.ActiveSessionCounts()
		tcp, udp = tcp+a, udp+b
	}
	var pending int64
	meters := make(map[*nativeMeter]struct{}, len(k.retiring)+1)
	if k.meter != nil {
		meters[k.meter] = struct{}{}
	}
	for _, m := range k.retiring {
		if m != nil {
			meters[m] = struct{}{}
		}
	}
	for m := range meters {
		pending += m.inflight.Load()
	}
	revoked, requested := k.tracker.CloseDiagnostics()
	m := map[string]any{
		"running": k.running, "admission_open": k.admitted(),
		"configured_users": len(k.users), "active_tcp_sessions": tcp, "active_udp_sessions": udp,
		"config_generation": k.configGeneration, "credential_generation": k.credentialGeneration,
		"retiring_servers": len(k.retiring), "pending_io": pending,
		"reload_attempts": k.reloadAttempts, "reload_succeeded": k.reloadSucceeded, "reload_failed": k.reloadFailed,
		"credential_revocation_close_requests": revoked, "user_close_requests": requested,
		"connection_close_requests": k.connectionCloseRequests.Load(),
	}
	if k.auth != nil {
		if state := k.auth.state.Load(); state != nil && state.security != nil {
			if p, ok := state.security.(interface{ PacketDiagnostics() map[string]uint64 }); ok {
				m["udp_transport"] = p.PacketDiagnostics()
			}
		}
	}
	return m
}
