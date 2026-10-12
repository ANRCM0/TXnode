# TX-Node control-plane architecture

TX-Node core code is intentionally independent from any single panel protocol. Remote and local management systems connect to the node through the `internal/controlplane` abstraction.

## Boundary

The core service consumes only the `ControlPlane` contract (`Source` + `Sink`) and TX-native models such as `model.NodeSpec` and `model.UserSpec`.

```text
                         TX-Node core
                             |
                        ControlPlane
                 +-----------+-----------+
                 |                       |
          LocalControlPlane        remote adapters
                                         |
                              +----------+----------+
                              |                     |
                     XboardControlPlane      TXBoardControlPlane
                                               (future adapters separately)
```

Protocol-specific JSON, authentication fields, REST paths and websocket event formats must be translated inside their adapter before data reaches service or kernel code.

## Current adapters

### LocalControlPlane

Local standalone mode is panel-free. Node configuration and users are read from the local TX-Node configuration and no remote reporting is performed.

### TXBoardControlPlane

`TXBoardControlPlane` handles native `/txapi/node/v1` Bearer + identity headers, HTTP handshake/config/users/report and optional versioned WebSocket. Machine mode uses an independent transport with per-node adapters and the existing mailbox/mux. Successful traffic HTTP 202 means queued, not SQL committed; the durable retry spool and TXBoard ledger must be verified together in staging.

### XboardControlPlane

`XboardControlPlane` is the canonical name for the existing Xboard-compatible adapter. It preserves compatibility with Xboard REST/WebSocket APIs and translates panel objects into TX-native `NodeSpec` / `UserSpec` values.

Machine mode uses `MachineXboardControlPlane`, with the shared websocket owned by the machine orchestrator.

The historical Go names `PanelControlPlane` and `MachinePanelControlPlane` remain implementation/source-compatibility names during the migration window; new TX-Node code should use the Xboard-specific constructors.

## Factory rule

Normal node services obtain their control plane through `controlplane.NewForConfig`. Service and kernel packages should not instantiate a concrete remote adapter directly.

Machine orchestration is the exception because it owns the shared transport and therefore injects a per-node `ControlPlane` explicitly through `service.NewWithControlPlane`.

## Typed Node Ops isolation

Typed Node Ops remain a core data-plane capability, but operation dispatch no longer belongs directly in the top-level Service orchestrator.

The runtime boundary is:

```text
ControlPlane EventOpsRequest
        |
        v
internal/nodeops.Executor
        |
        v
serviceOpsRuntime adapter
        |
        v
Service / Kernel
```

`nodeops.Executor` owns the fixed operation allow-list, bounded argument parsing, replay protection and bounded log/network diagnostics. The Service adapter exposes only current runtime validation, restart/reload, status, system metrics and application-log location.

This prevents a new typed operation from automatically gaining access to unrelated Service state. The protocol contract is unchanged.

See [Runtime Boundary](./runtime-boundary.md) for current runtime ownership and the feature-admission rules; consult [compatibility inventory](./legacy-compatibility-inventory.md) before removing migration paths.

## Optional capabilities

Protocol-specific extensions that are not universal control-plane operations must be exposed as optional capability interfaces rather than by teaching core service code about a concrete panel.

The first capability is `AuditTargetProvider`. Xboard adapters implement it to expose the remote identity required by the embedded access-audit reporter; `LocalControlPlane` intentionally does not. The service resolves the capability through `controlplane.AuditTargetOf` and therefore never reads Xboard panel credentials directly.

The TXBoard native adapter currently omits the legacy audit capability: its API does not implement Xboard plugin audit routes. Keep `audit.enabled: false` in native deployments. Future adapters may implement audit only after defining their own supported audit API and authentication. New protocol-specific features should follow the same pattern when they do not belong in the base `ControlPlane` contract.

## Extending with another control plane

Additional panel protocols should be implemented as independent adapters, not by adding panel-specific branches throughout Service or kernel code. The intended path is:

```text
New panel API / WS
      |
NewPanelControlPlane
      |
TX NodeSpec / UserSpec / Event / ReportPayload
      |
TX-Node service
```

Before enabling another provider, define its authentication, bootstrap, configuration/user synchronization, reporting and push-event semantics, then add provider selection in the ControlPlane factory/config layer. Provider-specific extensions should use optional capability interfaces where possible.

## Compatibility principle

Xboard support is a protocol compatibility feature, not the identity of TX-Node. Removing Xboard compatibility is not required for TX-Node to evolve independently; keeping that compatibility isolated behind an adapter is the goal.


## Machine Runtime Update v1

Machine-mode deployments can optionally expose a bounded runtime update bridge installed by **TXBoard-Deploy's Node installer**.

The control flow is:

```text
TXBoard Machine Admin
  -> machine-scoped WebSocket event
  -> TX-Node runtimeupdate.Manager
  -> fixed /run/txnode-update request
  -> Installer-owned host bridge
  -> Installer upgrade / verification / rollback
```

TX-Node does not receive the Docker socket and does not execute a control-plane supplied command. The only v1 target is `latest`.

The machine WebSocket event is:

```text
ops.machine.runtime.update
```

with:

```json
{
  "request_id": "mup_...",
  "target": "latest"
}
```

When the Installer capability marker is absent, TX-Node reports `updater_available=false` and rejects the request without writing an update file.

Machine status reports runtime-derived metadata additively via native `POST /txapi/node/v1/machine/status` (or the Xboard compatibility endpoint in xboard mode), including current build version, updater availability, and the bounded last Installer update status.

This is separate from per-node Node Ops. A machine runtime update restarts the TX-Node deployment and can briefly disconnect every node hosted by that machine.
