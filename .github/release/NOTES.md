# TX-Node v2.3.0

This delivery is the v2.3.0-rc.1 candidate. It is a GitHub prerelease and uses
the `preview` image channel. It does not promote the stable `latest` channel.

## Included

- Strict pinned-client interop gates, including native smux/yamux packet
  forwarding, Mieru UDP, packet faults and explicit traffic patterns.
- Mieru `seed` and `unlockAll` deterministic generation using the pinned
  v3.38.1 mapping. Explicit zero/false values retain precedence; empty settings
  retain existing behavior. Invalid or ambiguous settings fail validation.
- Scoped native connection list/close commands for the Core administrator
  panel. Commands delegate to the original Node Service/kernel/session owner;
  pagination, process-scoped IDs, deadlines and original workflow receipts
  preserve node and reload ownership. Closure is confirmed only by a matching
  Node result; an unknown outcome is not automatically retried.
- The exact supported Core revision and protocol set are recorded in
  `compatibility/core.v1.json`. Core adoption, physical connection close,
  continued sibling traffic, native authorization and original usage replay
  have separate Actions evidence. Release artifacts retain their source SHA
  and immutable image digests.

## Acceptance Limits

Complete S3 v3 performance acceptance remains open. The retained formal run
`40121606962` has 120 measured samples, two CPU investigation outcomes and one
unresolved p99 comparison under the predeclared budgets. Subsequent finite
diagnostics and the separate nightly v2 run do not replace that rejection.
Budgets, synchronization, capacity, durable receipts and private ACK semantics
are unchanged.

The user has no fixed performance runner or physical test host available for
this delivery. Actual rollout, production PKI, physical multi-host behavior and
an executed deployment rollback remain unverified. The arm64 image capability
check runs under QEMU. Candidate delivery does not close those acceptance items.

## Artifacts And Rollback

The release includes `tx-node-linux-amd64`, `tx-node-linux-arm64`, `SHA256SUMS`
and `release-manifest.json`. The manifest binds binary checksums, the source
commit, supported Core and both published image architectures. Deploy by the
recorded immutable image digest after checking that manifest.

Before upgrading, retain the current Node/Core versions, image digests,
configuration and state ownership. Keep original usage journals, spools and
receipts. Older Nodes reject the new implicit traffic-pattern fields; remove
those opt-in settings before rolling back configuration. Do not let an older
reader overwrite state that it has not been verified to read. The candidate
rollout and rollback procedure is in `docs/NATIVE-OPERATIONS.zh.md`.
