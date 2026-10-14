# Control Plane Providers

TX-Node has three supported control-plane implementations: `txboard` (native), `xboard` (compatibility) and `local` (standalone). The runtime and kernel consume provider-neutral `NodeSpec` and `UserSpec` models; protocol-specific HTTP and WebSocket handling stays in the adapters.

## Selecting a remote provider

| `panel.provider` | Protocol | Node | Machine | Notes |
| --- | --- | --- | --- | --- |
| `txboard` | TXBoard `/txapi/node/v1/*` | Yes | Yes | Bearer + node/machine identity headers; optional native WebSocket |
| `xboard` (default) | Xboard V1/V2 | Yes | Yes | Preserves deployed Xboard protocol compatibility |
| Other | Unsupported | — | — | Startup validation rejects unknown values |

Standalone mode uses the local control plane, configured through `standalone`; it does not contact a panel.

Example for a native TXBoard Node:

```yaml
panel:
  provider: txboard
  url: "https://panel.example.com"
  token: "REPLACE_WITH_NODE_TOKEN"
  node_id: 1
kernel:
  type: singbox
audit:
  enabled: false
```

Example for a native TXBoard Machine:

```yaml
panel:
  provider: txboard
  url: "https://panel.example.com"
machine:
  machine_id: 2
  token: "REPLACE_WITH_MACHINE_TOKEN"
kernel:
  type: singbox
```

For Xboard, change `provider` to `xboard` and provide the compatible panel token/node identity. See the root [config example](../config.yml.example) for multiple instances.

## Protocol behavior and boundaries

- **TXBoard HTTP:** `/txapi/node/v1` with `Authorization: Bearer`, `X-TX-Node-ID` and/or `X-TX-Machine-ID`. No credentials in query parameters. Versioned `data` response envelope; config and user snapshots can return HTTP 304 based on separate ETags.
- **TXBoard WebSocket:** versioned event frames and machine-scoped multiplexing; availability depends on the panel-side Workerman/native-WS configuration. HTTP polling operates without native WS.
- **Traffic:** Native Core defaults to SQL reception before nonempty HTTP202. `receipt_status=persisted` attests that durable acceptance; `settlement=queued` does not attest billing. Exact replay freezes the original rate/day and post-hook input. Explicit legacy mode reports `queued_only`; period-aware reports require durable mode. Native Node persists the original ID/body and drains pending/terminal records before restart admission.
- **Observed periods:** Core supplies signed `traffic_period` values in native user snapshots. Node reports canonical `traffic_segments`; current epochs consume current quota, while older observed epochs retain historical accounting. This is not a finite offline authorization lease. See the [traffic boundary](../../contracts/node-protocol/native-traffic-quota-v1.md) and [period boundary](../../contracts/node-protocol/native-traffic-period-v1.md).
- **AccessAudit:** An optional shared sing-box collector uses provider-specific transports. Xboard preserves the legacy `/api/v1/plugin/access-audit/*` plugin API. TXBoard uses native `/txapi/node/v1/audit/*` bearer Node/Machine identity with stable per-event dedup IDs, and the TXBoard admin manages rules/logs. Audit defaults off; enable only once the corresponding panel endpoints are deployed. Xray has no equivalent embedded collector.
- **Compatibility:** Preserve the Xboard adapter and the Installer migration boundaries. Deprecated executable names and legacy configuration paths are *migration inputs*, not active release targets.
- **Factories:** `controlplane.NewForConfigChecked`, `service.NewChecked`, and `machine.NewChecked` report unsupported provider errors. Multi-instance settings inherit `panel.provider` when omitted.

## Completed isolated acceptance

P0.5 proves actual Core/Workerman shared Machine scope and credential rotation; P0.6 proves actual VLESS/VMess bytes, durable acceptance, Redis worker settlement, lost ACK/queue recovery, actual process restart and observed reset epochs. Reports: [Machine](native-machine-control-verification.json), [traffic/quota](native-traffic-quota-verification.json). These do not activate isolated Usage v2 or global migration authority.

## Production acceptance

Before rolling out a new native runtime, verify real TXBoard + TX-Node + Installer connectivity for Node and Machine, credentials and token rotation, HTTP 304 handling, optional native WebSocket, kernel protocols, traffic retry/idempotency, durable replay after restart and queue/ledger settlement. Passing unit tests or publishing an image is not production acceptance.
