# Isolated Service usage-v2 mode

Status: verified isolated Service integration. Production v2 admission and authority
handoff remain closed. The ordinary absent/disabled `usage_v2` configuration uses
existing v1 behavior; no v2 worker, observer, clock or spool path is created.

The explicit mode requires `usage_v2.enabled=true`, `isolated_copy=true`, an absolute
durable directory, TXBoard provider, loopback HTTPS, one sing-box Service and an
explicit kernel persistent directory. A bounded regular CA file can provide the
local fixture trust. Machine/multi-node/standalone/xray/WS-bootstrap and simultaneous
local observers are rejected. Instance expansion never inherits the flag; enabling
it only at a root with child instances is refused rather than silently ignored.
Only one permanent process owner is allowed, including after open failure/timeout.

Service prepares native TLS trust before initial handshake, then receives the real
Core usage-v2 Session and transport alongside native config/users. It checks the
exact original durable v1 pending path is absent, Controller has no RAM pending or
active batch, Service Tracker has no last/pending bytes, and actual kernel is not
running with no cumulative bytes/connections. Existing CheckHandoff is called with
these observations; it never drains uncertain legacy history. No in-place switch
from an already-running kernel is supported.

Before actual sing-box listeners start, Service freezes the Core grants against
actual users, attaches the enforcing bounded producer and selects one usage worker.
The explicit mode's private direct TCP view cannot unwrap raw I/O; unknown binding,
UDP, expired or closed/unknown collector refuses new bytes. The existing v1 totals
remain available as metrics, but Tracker builds no second pending billing queue.
Native heartbeat/online reports keep their existing path with Traffic omitted.

One worker handles integer-boundary Flush, immutable journal/spool commit and the
existing HTTPS Reporter. File work runs outside user/connection/collector short
locks. Unknown interval, fsync/store/receipt/recovery errors fail-stop this mode:
active connections close and Service returns a fixed error, never v1 billing fallback.
A main-loop finite lease timer stops traffic independently of a stalled worker;
Begin/Complete also check UTC/monotonic collector budget. Config/users/credential
change and disruptive restart refuse continuation of the frozen binding. Source
regeneration and production lease refresh are not guessed or performed automatically.

Stop marks unknown unsealed tail and closes connections. Already sealed original
claims/payloads may still commit/export; nothing is deleted or reconstructed.
Shutdown joins its single worker for two seconds. A blocked syscall/transport keeps
original FD/flock until completion; the permanent owner is not reassigned. Same Core
source epoch cannot restart a live collector after normal close or SIGKILL. Only a
separately authorized newer Core source epoch can begin another process timeline.
Old receipt/payload/session identities remain immutable and queryable.

The [fixture runner](../../scripts/tests/node-service-usage/README.md) executes actual
Service.Run with native Core handshake/config/users, memory TCP through the production
enforcing ConnTracker, existing Reporter HTTPTransport and real Laravel/MariaDB.
Its kernel lifecycle is injected to avoid a live proxy listener. Actual full
sing-box Start separately verifies prepared tracker installation before listeners
and full-restart refusal. The fixture proves11 upload/7 download, Core persisted
ACK then frozen3/2 billing16/10 (26 total), settled query/replay, one batch/one ledger
entry and legacy User u/d0/0. It does not claim live VLESS/VMESS protocol interop.

Nine complete affected packages passed239 main tests/152 subtests under Linux race;
one opt-in actual Core case skipped there was separately run twice and passed.
Vet passed. Real Service process SIGKILL retains sealed payload/receipt and rejects
same-epoch resume. Blocked worker expiry/shutdown preserves owner and payload.
Existing bounded journal fsync/SIGKILL, original v1 and disabled-path regressions
also ran. Source/locks/artifact hashes, fixed snapshots and corrected failed fixtures
are recorded in [verification evidence](service-usage-v2-verification.json).

No production Core source-opening route, credential delivery, Provider proof
admission, distributed revocation/ACK, trusted clock/restore, multi-Service coverage
or automatic authority publication is added. Core usage still requires isolated
local/testing policy. Only one production settlement path may be selected after
all separate Provider/authority/handoff/recovery gates; this slice does not open them.
