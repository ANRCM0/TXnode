package txnode

import (
	"io"
	"log/slog"
	"net/netip"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
