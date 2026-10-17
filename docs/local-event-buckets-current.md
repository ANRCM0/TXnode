# Local accounting-event buckets: first slice

Status: explicit constructor opt-in, default off, in-memory evidence only. The
ordinary ConnTracker constructor and production Service continue on the existing
v1 path. This slice adds no Service drain, disk writer, grant gate or v2 submit.

`NewConnTrackerWithEventBuckets(usagebucket.Options{Enabled: true})` creates a local
meter on the actual sing-box tracker. Disabled construction returns a nil meter;
the ordinary direct/callback path does not read an observer clock, allocate an
observer session, record events or acquire a meter mutex. Existing v1 atomics,
returned I/O values, limiter cancellation and user-close behavior remain intact.

Meter hooks sit at the existing counter sites. TCP Read/Write records actual
returned counts, including n > 0 with an error. Direct operation ranges refer to
the underlying I/O call; limiter waiting before Write or after Read is excluded.
UDP retains its existing successful-datagram count semantics. The attempted buffer
length is captured before WritePacket can consume/release it. UDP errors record
an unknown delivered count with zero observed bytes; they do not assert that an
attempted packet was delivered or that its actual partial delivery was zero.

Each event contains its numeric user, local connection reference, transport,
registration generation, observation generation, clock era, accounting sequence,
physical direction, legacy counter direction, raw count and completion stamp.
Stamps include wall Unix nanoseconds and process-relative monotonic nanoseconds.
Records have `attribution: unattributable`; they contain no UUID, token, source IP,
Core subject, Terms, period or tariff identifiers.

Direct paths have an actual captured operation start. A CountFunc callback has
only completion time and `IntervalUnknown`; it cannot prove when every byte was
read or delivered. No interpolation, proportional split or current-grant lookup
occurs. A `WriteBuffer` wrapper delegates to the tracked Write and gets one count;
actual sing Copy unwraps to the underlying connection and uses the corresponding
single CountFunc. A per-connection reentry flag is not used because concurrent
read/write would make that suppression ambiguous.

The existing UDP zero-copy counters differ from direct methods: reader callbacks
increment the legacy download atomic although the physical method reads upload;
writer callbacks increment the legacy upload atomic for physical download. Events
retain both directions and mark `DirectionMismatch`, leaving v1 behavior intact.

The initial slice recorded a pinned sing 0.8.2 writer coverage gap:
`UnwrapCountPacketWriter` first unwraps replaceable writers, which bypassed the
trackedPacketConn counter. Its historical report proves a delivered UDP packet
with zero writer totals and events. The separate
[UDP accounting boundary](controlplane.md#udp-accounting-boundary) now keeps that boundary
and restores ordinary `CopyPacket` counting in the existing legacy upload
direction. Current tests assert one writer callback per successful packet. The
initial verification report remains the evidence for the original slice; this
fix has its own report. These observations still form no billing-ready stream.

One mutex per meter serializes clock observations, append, checked bucket totals,
local cuts, generation changes and close fences. It performs no network I/O,
limiter wait or persistence. Each bucket has a random tracker nonce, bucket number,
local generation, clock era and a half-open sequence range. Sequence is the
authoritative local order. Equal-resolution timestamps can occur on either side
of a cut, and time bounds alone do not prove event ownership at a remote boundary.
A manual cut is a local observation fence, not a Core Terms transition.

Binding is captured once on the connection wrapper and never re-resolved against
today's user map. Closing records a fence before canceling/closing I/O outside the
meter lock. An operation already in progress may return bytes after that fence;
saved callbacks can arrive even when ActiveCount is zero. These events retain the
original user/connection/generation and `LateAfterClose` with the close sequence.
They append to a new open bucket after a cut and never reopen a sealed bucket.
Direct operations spanning a cut are marked `CrossedFence`; callbacks retain an
unknown interval. Snapshot returns copies so callers cannot mutate retained data.

Monotonic elapsed time controls windows; wall rollback seals the previous clock
era and begins another. Monotonic rollback stops the meter and exposes a gap.
Negative counts, sequence/generation overflow and aggregate counter overflow
degrade observation before invalid bucket mutation. The first rejected event's
signed count and binding are retained when available, with a saturating dropped
event counter. The original v1 counter still follows its original behavior; its
own signed wrap/reset behavior is not changed by this observation slice.

Defaults are a one-second window, 1024 events per bucket and 32 sealed buckets.
Options cap each bucket at 4096 events, sealed retention at 1024 and total event
capacity at 65536. No history is deleted or automatically acknowledged. Capacity
exhaustion leaves retained open/sealed records intact, marks a gap and stops new
observations while v1 continues. An empty cut also consumes bounded bucket space.
Snapshot copies may allocate proportional to retained evidence; enabled append and
cut operations add local lock overhead. This is a bounded observation exercise.

All buckets expose `VolatileTailUnknown`, including sealed buckets: nothing is
durable yet. Abrupt termination loses this in-memory stream. Restart creates a new
random tracker identity; local generation is not a Core source epoch or a
restore-safe identity. Full Start's old asynchronous tracker drain and production
Service persistence require the next slice. There is no current sink retaining old
tracker buckets through recycle, and no completion claim based on ActiveCount.

Finite lease enforcement also remains separate. Future strict admission requires
verified Provider binding, finite grants, skew rules, restore-safe identities,
revocation ordering, a local monotonic lease deadline, admission fences and closing
existing TCP/UDP sessions. It must prevent zero-copy upstream bypass and classify
late bytes conservatively. Core manual changes need advance boundary/fence ACK or
honoring outstanding finite coverage. Missing proofs cannot be replaced by fixture
IDs or by callback timestamps. No authorization gating is activated in this slice.

[Verification report](local-event-buckets-verification.json) records Linux race/vet
results and source hashes. Tests exercise real net.Pipe TCP I/O, loopback UDP,
pinned sing Copy/CopyPacket and WriteBuffer delegation, partial TCP errors,
concurrent cuts, held callbacks, close/reassignment races, limiter waits, clock
rollback, numeric bounds and observation capacity failure with unchanged v1 totals.
