package core

import "sort"

const MaxConnectionPage = 128

// ConnectionInfo contains only management identity, never addresses or credentials.
type ConnectionInfo struct {
	ID        uint64 `json:"-"`
	UserID    int    `json:"user_id"`
	Transport string `json:"transport"`
}

type ConnectionPage struct {
	Connections []ConnectionInfo
	Total       int
	More        bool
}

// ConnectionPage returns the lowest IDs after the cursor with bounded allocation.
// Entries may disappear as soon as the snapshot is returned.
func (s *Server) ConnectionPage(after uint64, limit int) ConnectionPage {
	if limit <= 0 || limit > MaxConnectionPage {
		limit = MaxConnectionPage
	}
	page := ConnectionPage{Connections: make([]ConnectionInfo, 0, limit)}
	eligible := 0
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	page.Total = len(s.sessions)
	for sess := range s.sessions {
		if sess.ConnID <= after {
			continue
		}
		eligible++
		i := sort.Search(len(page.Connections), func(i int) bool { return page.Connections[i].ID >= sess.ConnID })
		if i == limit {
			continue
		}
		if len(page.Connections) < limit {
			page.Connections = append(page.Connections, ConnectionInfo{})
		}
		copy(page.Connections[i+1:], page.Connections[i:len(page.Connections)-1])
		transport := "tcp"
		if sess.Packets != nil {
			transport = "udp"
		}
		page.Connections[i] = ConnectionInfo{ID: sess.ConnID, UserID: sess.UserID, Transport: transport}
	}
	page.More = eligible > len(page.Connections)
	return page
}

// CloseSession closes only a session owned by this Server. Session.Close cancels
// limiter waits and closes packet transports; relay teardown still owns the tail.
func (s *Server) CloseSession(id uint64) bool {
	s.connsMu.Lock()
	var found *Session
	for sess := range s.sessions {
		if sess.ConnID == id {
			found = sess
			break
		}
	}
	s.connsMu.Unlock()
	if found == nil {
		return false
	}
	_ = found.Close()
	return true
}

func (s *Server) ActiveSessionCounts() (tcp, udp int) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	for sess := range s.sessions {
		if sess.Packets != nil {
			udp++
		} else {
			tcp++
		}
	}
	return
}
