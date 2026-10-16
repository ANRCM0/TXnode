# Native Subscription Usage

Linux capability `node_native_subscription_usage_v1` identifies the explicit
`native-provider-authorization/v2` consumer. This mode supports sing-box VLESS
and VMess direct TCP. It does not use legacy User billing, an unsigned usage
handshake, UDP, multiplexing, Xray or local observer evidence.

Keep the pinned Provider authorization configuration and select:

```yaml
authorization:
  policy_version: native-provider-authorization/v2
usage_v2:
  enabled: true
  isolated_copy: false
  directory: /var/lib/tx-node/usage
  ca_file: /etc/tx-node/core-ca.pem
  max_bytes: 67108864
```

The complete UsageV2 Session is inside the same Core signature as the users,
Provider binding and finite lease. Every I/O is preceded by a durable intent.
Its actual completion retains the original grant. Completed operations may
share bounded per-user/direction evidence with exact summed bytes and request
bounds, operation count, earliest start and latest completion. Pending calls
remain individual intents. A refresh stops old I/O and drains the old Session
before admitting the next revision. A restart recovers completed old evidence
and requires a higher signed revision; it never resumes the crashed timeline.

A proved later revocation boundary can produce a real Core receipt with
`receipt_status="persisted"`, `settlement_status="quarantined"` and
`reason_code="USAGE_NATIVE_AUTHORIZATION_CUTOFF"`. Node saves that receipt
with the complete original Session and Submission. Core reserves the original
Period's validated bytes even while settlement is pending or quarantined;
credential rotation does not restore that available quota.

Older authenticated `422 USAGE_NATIVE_AUTHORIZATION_CUTOFF` responses remain
supported. Node preserves that complete original record with
`local_quarantine`, binding a SHA-256 digest of its schema, Session and
Submission. Until a query discovers a real Core receipt, `receipt` remains
absent. Neither response authorizes dropping, splitting or relabeling the
bytes. Automatic resubmission under another key or Session is forbidden.

If that rejection identifies the currently applied grant, Node immediately
closes its I/O and requests a higher signed revision. A rejected historical
grant cannot stop a different legal current grant. Authentication, scope,
ownership, signature, digest and receipt-generation failures still stop the
runtime; the broader ownership/coverage error is not a quarantine exception.

Local unknown evidence and rejected payloads are retained for explicit recovery.
Capacity exhaustion stops admission; age alone never acknowledges or deletes
them. Settled payloads may be reclaimed only after both negotiated retention
windows, with a durable settled tombstone before removal. Machine children use
independent per-node directories and retain their own Node/Machine identity.

All executable validation for this change runs in CI/Actions. Local formatting
and static review do not establish runtime or billing acceptance.
