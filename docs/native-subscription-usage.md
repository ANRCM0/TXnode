# Native Subscription usage

Linux capability `node_native_subscription_usage_v1` identifies the explicit
`native-provider-authorization/v2` consumer. The bounded C2 scope is sing-box
VLESS/VMess direct TCP. UDP, multiplexing, Xray and local observer evidence are
not native Subscription usage support. Xboard remains a supported independent
adapter, not a fallback source of native billing authority.

Keep [Provider authorization](native-provider-node.md) trust/identity settings
and explicitly select:

```yaml
authorization:
  policy_version: native-provider-authorization/v2
usage_v2:
  enabled: true
  directory: /var/lib/tx-node/usage
  ca_file: /etc/tx-node/core-ca.pem
  max_bytes: 67108864
```

## Signed session and I/O ownership

The complete UsageV2 Session, grants, Provider binding, users and finite lease
share the same Core signature. There is no unsigned usage-handshake authority.
Every I/O is preceded by a durable intent; actual completion retains that
original grant and physical direction, including bytes returned with an error.
Completed operations may share bounded per-user/direction evidence with exact
summed bytes, request bounds, operation count and first-start/last-completion
times. Pending calls retain individual intents.

The enforcing direct TCP view cannot expose raw Upstream or replaceable
reader/writer shortcuts around accounting. Pinned copy/extended-write paths must
reach the same tracked I/O. Unknown identity, unsupported transport, stale lease,
clock regression, overflow or persistence/capacity failure stops admission; do
not continue through cumulative v1 billing. Cumulative metrics are not a second
billable queue. Callback completion times or locally unattributable event buckets
cannot establish grant/Terms ownership or reconstruct an unknown interval.

Refresh closes old I/O and drains its original Session before the next revision
is admitted. Already-started work retains its old grant even if completion
arrives after close. Restart recovers completed old evidence and requires a
higher signed revision; it never resumes a crashed timeline, guesses unsealed
bytes or relabels them under the new grant. Provider/Core outages cannot renew
the independent finite deadline.

## Durable submission and receipt

`POST /txapi/node/v2/usage/submit` sends `{payload,payload_digest}`;
`POST /txapi/node/v2/usage/batch/get` queries the original Node/source/batch/digest.
Both use native Bearer and Node/Machine headers, verified HTTPS and no redirects.
Wire schemas and canonical encoding remain in the
[Node usage contract](../../contracts/v2/node-usage/README.md); payloads do not
pre-multiply rates or guess a subscription. Immutable batches keep original
Core instance, receipt generation, source epoch, Session, grants and IDs.

The private durable directory has one process owner. Journal/spool publication
uses owner-only files, file synchronization, atomic publication and directory
synchronization. A failed durability edge is not permission to send or choose a
new batch ID. Damaged files fail closed and stay available for recovery. Machine
children use separate per-node directories and keep their Node/Machine identity.

A typed `receipt_status="persisted"` must match every original receipt identity
field. HTTP 202, `queued`, or untyped 2xx alone is not that acknowledgement and
never proves settlement. After a lost response, query first and replay the exact
original submission only if no receipt was previously confirmed. Once persisted,
query settlement rather than changing the payload. Conflicting digest, instance
or generation, or a missing previously confirmed receipt, stops normal replay
and preserves explicit recovery evidence. Later authorization expiry cannot
rewrite historical accepted bytes.

## Cutoff and quarantine

A proved later revocation boundary can produce a real Core receipt with
`receipt_status="persisted"`, `settlement_status="quarantined"` and
`reason_code="USAGE_NATIVE_AUTHORIZATION_CUTOFF"`. Save that actual receipt with
the complete original Session/Submission. Core reserves the validated original
Period bytes while settlement is pending/quarantined; credential rotation does
not restore consumed available quota.

An authenticated `422 USAGE_NATIVE_AUTHORIZATION_CUTOFF` instead retains the
complete original record as `local_quarantine`, binding a SHA-256 digest of its
schema, Session and Submission. It is not an invented receipt: `receipt` stays
absent until a query finds a real Core receipt. Neither response authorizes
splitting, dropping, relabeling or automatically resubmitting under another
Session/key.

If the rejected grant is currently applied, immediately close its I/O and request
a higher signed revision. A historical grant refusal must not stop a different
legal current grant. Authentication, scope, ownership, signature, digest and
receipt-generation failures still stop runtime; broader ownership/coverage
failure is not a quarantine exception.

## Recovery and validation

Retain unknown evidence and rejected payloads for explicit recovery. Capacity
exhaustion stops admission. Age alone never acknowledges/deletes records.
Persisted and quarantined payloads stay available; settled payload reclamation
requires both negotiated retention windows and a durable settled tombstone
before removal. Pending/tail replay and default cumulative modes retain their
[control-plane safety boundaries](controlplane.md#durable-reporting).

Real protocol, database, process/crash, TLS and race validation runs in
CI/Actions. Local formatting/static review is not runtime or billing acceptance.
The bounded Linux sing-box direct-TCP result does not imply UDP/mux/Xray,
production PKI, HA, coordinated restore or global billing authority readiness.
