# TX-Node control plane and runtime safety

TX-Node runs the Data Plane, not Core business authority. Service and kernels
consume the provider-neutral `ControlPlane` (`Source` + `Sink`), `NodeSpec` and
`UserSpec`. Protocol JSON, credentials, HTTP paths and WebSocket frames belong
in adapters.

## Adapters and ownership

- `TXBoardControlPlane` uses `/txapi/node/v1`, Bearer authentication and explicit
  Node/Machine identity headers. HTTP polling works without optional native WS.
- `XboardControlPlane` and `MachineXboardControlPlane` remain supported product
  adapters for Xboard REST/WS. Xboard support is not TX-Node's runtime identity.
- `LocalControlPlane` reads standalone configuration and performs no remote
  reporting.

Normal services use `controlplane.NewForConfig`; checked factories reject
unsupported providers. Machine orchestration owns the shared transport and
injects each child's control plane through `service.NewWithControlPlane`.
Optional provider features use capability interfaces rather than panel-specific
branches in Service or kernels. Native Provider delivery and signed usage are
specified in [Node authorization](native-provider-node.md) and
[Subscription usage](native-subscription-usage.md).

Agent/MCP and per-node AI `ops.*` executors are retired. They must not reenter
runtime state. Ordinary configuration, user synchronization, reporting and the
separately authenticated Installer-owned machine update remain supported.

## Native authority denial

Only a completed bounded JSON `401 NODE_UNAUTHORIZED` or a node-scoped
`404 NODE_NOT_FOUND` on the supported handshake/config/users/discovery requests
is an authority withdrawal. Supported requests are `POST /handshake`,
`GET /config`, `GET /users` and `GET /machine/nodes`. The 404 requires a configured Node ID and is never
inferred from `/machine/nodes`. Network/TLS failures, redirects, HTML/proxy
responses, other status/code combinations and report refusals are not revocation
proof. They do not extend any finite authorization deadline either.

A Node denial stops that listener. Machine credential denial cancels and joins
all children without a child waiting on itself; a child-scoped 404 stops only
that child. A denied credential is not reused for a final report. Current
credentials must recover original pending/tail records before reopening.

## Desired and applied snapshots

Keep desired configuration/users separate from successfully applied hashes.
Start, Reload and user mutation confirm applied state only after success. A
failed request remains retryable; a partially failed user mutation stops an
uncertain kernel rather than claiming revoked users have disappeared. Empty
desired users close the listener. Configuration and certificate failures stay
visible until the corresponding application succeeds.

A transport 304 can redeliver only complete cached content bound to the same
configured identity. A missing-cache 304 retries once without a conditional
header; it cannot invent empty users. Cache bodies are cloned, and a config
received before a later users failure remains available for retry. An ETag or
cached body never renews signed authority.

Asynchronous polls capture the local event generation. Newer accepted WS state
invalidates older ordinary poll results and schedules a fresh read; terminal
authority denials still apply. Reconnect/drop invalidates transport caches.
This is local ordering, not an atomic Core config/users transaction or a global
applied-revision acknowledgement. Provider policies accept WS changes as refresh
hints, not unsigned credential or authorization updates.

## Kernel application and connection closure

sing-box compares the complete generated construction, independently of its
user list. Routing/outbounds, DNS, protocol, listeners and TLS changes require
stop and full reconstruction. Same-construction user updates retain replay
protection and meters. Invalid route/detour/selector/DNS references fail before
mutation; a failed replacement cannot be marked applied. Trackers and coherent
authentication indexes are installed before listeners open.

sing-box registers tracked TCP/UDP sessions with their authenticated identity.
Admission recheck and insertion share the user-map change lock. Explicit user
close terminates registered sessions but does not itself remove future user
authorization; identity removal/reassignment does both. Closers and canceled
limiter waits run outside the registry lock. Final cumulative counters remain
readable under the original user even after removal.

Xray advertises `ForceCloseUser=false`: it has no individual established-session
termination capability. Subset removal or UUID replacement therefore stops and
reconstructs the whole instance. Full desired users are validated first; partial
manager failure cannot advance applied users/hashes. Restart releases the old
port and retains final meters. This can interrupt unaffected streams, which must
authenticate again under current desired users. Do not describe either backend
as supporting a stronger revocation capability than it actually exposes.

## Machine synchronization

Current authenticated membership governs the shared socket. A valid empty list
is not malformed/missing membership, and transport failure does not withdraw a
child. Removal closes and checkpoints only that child; credential denial closes
the whole Machine. Each child keeps independent runtime, mailbox and durable
state.

Publish committed configuration changes only. Registry replacement installs the
successor Machine and current mappings before closing the old registry entry.
Redis events identify changed domains; Workerman rereads current enabled state,
ownership and credentials before producing snapshots. Delayed hints cannot
restore revoked access or disclose reassigned credentials. Empty device maps
retain object encoding.

## Durable reporting

Persist immutable counters and a stable `traffic_batch_id` before sending.
Timeouts/restarts replay the same ID, body, identity and period attribution, not
current users or a new epoch. The writable `kernel.config_dir` must survive
container replacement; Installer owns host data mounts and any migration.
TX-Node never depends on Core database table names.

Recovery sends pending batches first and terminal-tail records second, before
new listeners open. Partial acknowledgement leaves original bundle bytes intact;
only acknowledged records can clear their slots. Corrupt, missing, changed,
unwritable or capacity-exhausted storage fails closed, not by dropping a slot or
falling back to another billing path. One process owns each identity/state
directory. Final unsealed RAM bytes after an abrupt crash remain unknown, not
reconstructed usage.

An HTTP 202 or `queued` response is not settlement. Native
`receipt_status=persisted` proves durable reception only; queue wakeups, ledger
settlement and deduplication remain Core responsibilities. The signed native
Subscription path has stricter receipt/retention rules in
[native-subscription-usage.md](native-subscription-usage.md); ordinary cumulative
reporting cannot substitute for it or charge the same bytes twice.

## UDP accounting boundary

The generic sing packet unwrap must not bypass `trackedPacketConn`:
`WriterReplaceable()` is false. Counter-aware `UnwrapPacketWriter` returns the
underlying writer and exactly one callback, never the same wrapper. Cached
packet traversal must not add another counter owner. The original counter is
invoked only for a successful write, not attempted bytes on failure.

| Meter site | Physical direction | Existing cumulative counter |
| --- | --- | --- |
| Direct `ReadPacket` | upload | upload |
| Direct `WritePacket` | download | download |
| sing reader callback | upload | download |
| sing writer callback | download | upload |

These callback mappings are intentional existing behavior. Optional observers
retain physical/counter directions and `DirectionMismatch`; a callback supplies
completion time but no proven I/O start. Counter-aware writer limiting happens
after writing and is canceled by close, not a strict pre-write lease gate.
Generic traversal retains the tracked direct writer and its pre-write limiter.
Explicit raw `Upstream()` access is not an authorization-safe bypass; signed
bounded TCP uses a private nonreplaceable I/O view instead. UDP observations do
not establish native Subscription billing coverage.

## Machine runtime updates

`ops.machine.runtime.update` delegates only `{request_id,target:"latest"}` to
the fixed `/run/txnode-update` bridge supplied by TXBoard-Deploy. Without the
Installer capability marker, reject without writing an update request. No
Docker socket, arbitrary command, SSH or host management authority is granted.
Machine status includes bounded runtime/updater state through its own adapter.
An update can briefly disconnect every child on that Machine.
