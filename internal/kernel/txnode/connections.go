package txnode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/kernel"
)

var connectionEpoch = func() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("native connection identity unavailable")
	}
	return hex.EncodeToString(b[:])
}()

func connectionID(id uint64) string {
	return connectionEpoch + ":" + strconv.FormatUint(id, 10)
}

func parseConnectionID(id string) (uint64, error) {
	if len(id) < 34 || len(id) > 53 || id[32] != ':' {
		return 0, kernel.ErrInvalidConnectionID
	}
	if _, err := hex.DecodeString(id[:32]); err != nil || strings.ToLower(id[:32]) != id[:32] {
		return 0, kernel.ErrInvalidConnectionID
	}
	n, err := strconv.ParseUint(id[33:], 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != id[33:] {
		return 0, kernel.ErrInvalidConnectionID
	}
	if id[:32] != connectionEpoch {
		return 0, kernel.ErrConnectionNotFound
	}
	return n, nil
}

// liveServersLocked includes draining generations so a reload does not retarget
// a connection ID onto the replacement Server.
func (k *Kernel) liveServersLocked() []*core.Server {
	servers := make([]*core.Server, 0, len(k.retiring)+1)
	if k.srv != nil {
		servers = append(servers, k.srv)
	}
	for srv := range k.retiring {
		if srv != k.srv {
			servers = append(servers, srv)
		}
	}
	return servers
}

func (k *Kernel) Connections(ctx context.Context, after string, limit int) (kernel.ConnectionPage, error) {
	page := kernel.ConnectionPage{Connections: []kernel.Connection{}}
	if err := ctx.Err(); err != nil {
		return page, err
	}
	var cursor uint64
	if after != "" {
		var err error
		cursor, err = parseConnectionID(after)
		if err != nil {
			return page, err
		}
	}
	if limit <= 0 || limit > core.MaxConnectionPage {
		limit = core.MaxConnectionPage
	}
	k.mu.Lock()
	servers := k.liveServersLocked()
	k.mu.Unlock()
	var entries []core.ConnectionInfo
	more := false
	for _, srv := range servers {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		p := srv.ConnectionPage(cursor, limit)
		page.Total += p.Total
		more = more || p.More
		entries = append(entries, p.Connections...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
		if len(entries) > limit {
			more = true
			entries = entries[:limit]
		}
	}
	for _, entry := range entries {
		page.Connections = append(page.Connections, kernel.Connection{
			ID: connectionID(entry.ID), UserID: entry.UserID, Transport: entry.Transport,
		})
	}
	if more && len(entries) > 0 {
		page.Next = connectionID(entries[len(entries)-1].ID)
	}
	return page, nil
}

// CloseConnection returns ErrConnectionNotFound for exited, restarted or foreign
// IDs. A concurrent duplicate while registered is harmless (Session.Close is once).
func (k *Kernel) CloseConnection(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := parseConnectionID(id)
	if err != nil {
		return err
	}
	k.mu.Lock()
	servers := k.liveServersLocked()
	k.mu.Unlock()
	for _, srv := range servers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if srv.CloseSession(n) {
			k.connectionCloseRequests.Add(1)
			return nil
		}
	}
	return kernel.ErrConnectionNotFound
}
