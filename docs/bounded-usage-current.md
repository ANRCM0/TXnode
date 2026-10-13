# Explicit direct TCP usage interval bridge

Status: verified isolated prototype. This joins actual sing-box ConnTracker
Read/Write ranges to frozen Core grant metadata, an independent immutable local
journal, the existing Usage v2 spool and its existing Reporter. Ordinary Service
construction does not call it, and production usage-v2 remains disabled.

The explicit constructor is `NewConnTrackerWithBoundedUsage(session, users,
journal)`. Its Session must have passed the existing authenticated Core protocol
and production authorization gates before a future runtime may use it. The
constructor checks shape/finite local time only and does not establish those
upstream gates. The present tests use synthetic Sessions and credentials.
`FlushBoundedUsage` owns the actual producer claim; it cannot accept a caller's
arbitrary counter map or old unattributable event bucket.

A private net.Conn view exposes direct Read/Write without raw Upstream or
CountReader/CountWriter interfaces. Pinned sing Copy and extended writer therefore
reach the same original tracker methods. The ordinary nil path keeps v1 atomic
counting, limiting, zero-copy callbacks and event observation behavior. Unknown
User/UDP/local mapping updates, clock/lease errors or capacity loss permanently
stop this collector's exports; v1 traffic processing continues. This constructor
is specific to sing-box TCP; it does not claim xray or UDP interval coverage.

Integer UTC end boundaries never overlap. An unfinished or boundary-crossing I/O
keeps its real counters in the same unsealed interval until a later integer end
can contain it. Start/completion nanoseconds and process-relative monotonic stamps
remain in evidence. File synchronization occurs outside the short collector lock,
so I/O during Flush is retained for the next interval. Bytes returned with errors
stay counted. Counters use physical upload/download; original v1 mappings stay
independent. Idle ranges advance without synthetic zero-byte billing batches.

The bounded journal commits original random batch identity, frozen Session and
actual complete I/O evidence before writing the existing spool. Its files are
0600, single-owner flock protected, immutable and published after file fsync;
directory edges are synchronized. Existing spool confirmation rechecks file and
directory durability under its owner lock and preserves Core receipts. Failed
persistence retries the same claim; histories are retained rather than pruned.
At most 128 journal records/128 grants/1024 pending operations/1MiB per record
are accepted. Capacity stops export rather than losing known counts.

The durable source marker always says tail unknown. A crashed/closed collector
cannot restart the same source epoch, including a source with no sealed batch.
A fresh Core-issued greater epoch can begin a new timeline. Old sealed evidence
re-exports original epoch/Session/batch IDs, never current grant identities. Hash
consistency is not independent attestation of complete history; same-OS invention
of evidence with a new hash is outside this trusted prototype boundary. File and
DB restore, unobserved rollback and authoritative epoch allocation are not solved.

Actual memory TCP verified 11 upload/7 download, partial-error 7/2, pinned sing
read/write copy 13/0 and 0/13, extended writer and delayed in-flight boundaries.
Reporter's in-process fake transport verifies the actual TCP batch's persisted
receipt response loss, query-before-replay and receipt preservation. No production
panel, authorization service or live VLESS listener was contacted. Actual Core
TLS receipt/settlement interoperation is a next gate, not a completed claim.

Linux race over all five affected packages passed 185 main tests and 152 subtests,
without filters/skips/failures; vet passed. Six real helper SIGKILL gates cover
before seal, after file fsync, publication, directory fsync, before spool and after
spool. Eight fault edges plus new spool file/directory reconfirmation reject false
durability. Original event-store SIGKILL/fsync and default Service/v1 regressions
also ran in the complete packages. See [frozen hashes and logs](bounded-usage-verification.json)
and [contract](../../contracts/v2/node-usage/bounded-tcp-collector-v1.md).

This prototype does not open admission, install or revoke credentials, grant
permissions from Provider proofs, run an automatic Reporter or select production
billing authority. V1 cumulative reporting still counts the same traffic; tests
cannot justify charging it again via v2. Production v2 handoff must separately
prove v1 pending/cumulative counters empty and select exactly one settlement path.
Unsealed/unknown tail is retained as a failure boundary, never interpolated.
