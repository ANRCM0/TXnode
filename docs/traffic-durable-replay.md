# Durable traffic reporting and replay

TX-Node persists one unacknowledged traffic batch before sending it. The batch contains the immutable counters and a stable `traffic_batch_id`. Timeouts and retries reuse the **same** batch ID and payload; restarting the runtime replays pending data before sending newly accumulated counters.

The pending file lives beneath `kernel.config_dir` (default: the directory containing `config.yml`). This directory **must be writable and persistent across container replacement**. New Installer-managed Compose layouts bind-mount the host `$INSTALL_DIR/data` onto `/etc/txnode` and mount the YAML file read-only inside it. Existing deployments need explicit data migration before adding the new directory mount; otherwise an empty host directory can hide pending traffic in the old container layer.

A successful HTTP acknowledgement clears the local pending spool. For native TXBoard this is **HTTP 202 / queued**, not proof of database settlement. TXBoard must process the queue and deduplicate traffic using the stable batch identity; verify the queue and billing ledger before declaring an end-to-end no-loss/no-double-charge result. The database may use legacy or native table names according to TXBoard's configured schema cutover: **TX-Node must never hard-code database table names**.

Startup fails closed if the spool is corrupt, unreadable or cannot be written. Spool files have owner-only permissions. Do not run two active agents with the same node identity and the same state directory.

Limitations: bytes tracked in memory but not yet flushed to a durable batch may be lost in an abrupt crash. A panel that acknowledges queuing and later fails permanently to settle a batch also requires operator-side queue recovery and reconciliation. Pending-batch replay alone cannot resolve those cases.

Regression acceptance includes: retries after timeout, repeated IDs with identical payloads, rejecting mismatched duplicate payloads, successful reboot/recreation with the data mount, queue failure recovery, and user/server statistics reconciliation. See [Installer's durable data guidance](https://github.com/ANRCM0/TXBoard-Deploy/blob/main/node/README.md#durable-runtime-data-s8).
