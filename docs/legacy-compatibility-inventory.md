# TX-Node compatibility and migration boundary

This is the active compatibility inventory for TX-Node. **Protocol interoperability is not deployment legacy.** Do not remove working integrations merely because historical binaries have been retired.

## Canonical targets

| Surface | Canonical owner or location |
| --- | --- |
| Runtime agent | `ANRCM0/TXBoard/node` (planned repository name `tx-core`), stable Go module `github.com/ANRCM0/TX-Node`, executable `tx-node` |
| Container registry | `ghcr.io/anrcm0/txboard-node` |
| Container config | `/etc/txnode/config.yml` |
| Persistent node state | `kernel.config_dir`; Installer mounts `/etc/txnode` from host persistent storage |
| Docker installation, upgrade and rollback | `ANRCM0/TXBoard-Deploy/node`, `txnode` command |
| TXBoard control-plane protocol | `panel.provider: txboard` / `/txapi/node/v1/*` |
| Xboard compatibility protocol | `panel.provider: xboard` / Xboard V1/V2 |

## Current classifications

| Surface | Status | Removal rule |
| --- | --- | --- |
| TXBoard native Node and Machine | Product runtime | Keep and test |
| Xboard-compatible Node and Machine | Supported protocol adapter | Keep; any removal requires a deliberate protocol-breaking release |
| Local / Standalone | Supported, feature-frozen mode | Keep unless a replacement and migration plan are approved |
| Remote single-node | Supported runtime mode | Keep; Machine is preferred for new TXBoard management |
| `xboard-node` and `xbctl` built artifacts | Retired from current v2+ source/build workflow | Do not restore or ship them in new Release assets |
| Historical native/systemd `xboard-node.service`, `/usr/local/bin/xboard-node`, `/usr/local/bin/xbctl` | Installer migration/cleanup input | Retain detection/import/cleanup until a safe retirement decision |
| Host `/etc/xboard-node` | Historical deployment data | Installer may read it during migration; new deployments use `/etc/txnode` |
| Container `/etc/xboard-node/config.yml` | Narrow startup fallback for old Compose mounts | Remove only after an explicit migration window; custom `-c` paths must not invoke fallback |
| Optional legacy AccessAudit reporter | Xboard plugin compatibility only | Keep isolated; TXBoard native does not implement its API |

The retirement gate matches Docker image tokens, including quoted and registry-qualified references. It accepts `txboard-node:latest` and rejects the retired `xboard-node:latest` alias. [Node CI for `f9b2714`](https://github.com/ANRCM0/TXBoard/actions/runs/38300575454) passed Go tests, `vet` and runtime stability, then exposed a substring check that incorrectly treated the new image name as the retired alias. The token boundary check corrects that gate.

## Migration and rollback safeguards

The Installer is the single authority for moving a legacy native/systemd deployment into canonical Docker Compose. Before retirement or migration of a compatibility surface, ensure:

1. Equivalent operations exist in the new runtime or Installer, and credentials are transferred without logging them.
2. Node/Machine identity, config, kernel type and TLS state survive migration.
3. **Unacknowledged traffic batches remain durable:** preserve the old container's `kernel.config_dir` including hidden pending JSON files before creating new writable mounts or replacing a container.
4. Health and binding checks are verified, and rollback restores the earlier working container/image/config if the new one fails.
5. Existing non-native/Xboard users are not silently routed to the native TXBoard API; `panel.provider` is an explicit compatibility boundary.
6. A breaking removal has a named supported-version window, operator notice and tested recovery path.

Do not infer zero legacy usage solely because telemetry is absent. A historical GitHub Release can retain retired artifacts for reproducibility; that does **not** mean the current CI should publish them.

See [runtime boundaries](./runtime-boundary.md), [control-plane adapters](./control-plane-providers.md) and the public [Installer](https://github.com/ANRCM0/TXBoard-Deploy/tree/main/node).
