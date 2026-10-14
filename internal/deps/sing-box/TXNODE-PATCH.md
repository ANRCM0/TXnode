# TX-Node sing-box patch

This directory is the source for the sing-box module selected by `node/go.mod`.
It is based on `github.com/ANRCM0/sing-box` commit
`20260917154452-6184aa2cd055`.

The TX-Node patch adds an optional `AdmitRoutedConnection` tracker hook before
the router invokes an outbound handler. Bounded usage uses it to refuse virtual
TCP streams that cannot be attached to the socket-backed byte tracker. This
prevents classic VLESS/VMess CommandMux streams from opening an origin
connection before their unsupported transport is rejected.

Upstream source and license notices are retained. Keep this patch narrow and
review it whenever the pinned upstream module changes.

P0 native snapshot application also makes VLESS and VMess inbound authentication
identities immutable across user-list updates. The pinned local sing-vmess module
preserves the VMess replay filter while atomically publishing authentication
indexes. Concurrent handshakes keep one coherent user identity and never index
into a later user list. Keep protocol bytes, cryptographic derivation and replay
windows unchanged; verify real concurrent clients whenever this patch changes.
